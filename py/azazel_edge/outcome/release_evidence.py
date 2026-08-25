from __future__ import annotations

import math
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

from .contracts import (
    SCHEMA_VERSION,
    ActionExecutionReceipt,
    ActionLifecycle,
    AppliedMechanism,
    ExecutionStatus,
    MechanismStatus,
)
from .ownership import expected_ownership


class ReleaseEvidenceStatus(str, Enum):
    RELEASED = "released"
    RETRY_PENDING = "retry_pending"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class ReleaseEvidenceRecord:
    release_task_id: str
    decision_id: str
    action_kind: str
    resource_key: str
    owner_token: str
    tc_handle: str
    due_epoch: float
    attempted_at_epoch: float
    status: ReleaseEvidenceStatus
    result: str
    command_count: int
    failed_count: int
    errors: Sequence[str]
    postcondition: Mapping[str, Any]
    evidence_refs: Sequence[str]
    observed_at: str
    producer: str = "azazel_edge.outcome.release_adapter"
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


def from_rust_release_event(event: Mapping[str, Any]) -> ReleaseEvidenceRecord:
    """Normalize one Rust release-engine event without granting it new authority."""

    if str(event.get("pipeline") or "") != "rust_release_engine_v1":
        raise ValueError("release evidence requires rust_release_engine_v1 pipeline")
    release = event.get("release")
    if not isinstance(release, Mapping):
        raise ValueError("release event requires release object")

    task_id = _required_text(release, "release_task_id")
    decision_id = _required_text(release, "trace_id")
    action = _required_text(release, "action").lower()
    resource_key = _required_text(release, "resource_key")
    owner_token = _required_text(release, "owner_token")
    result = _required_text(release, "result")
    if action not in {"throttle", "redirect", "isolate"}:
        raise ValueError("unsupported release action")
    if not owner_token.startswith("azazel-edge:release-"):
        raise ValueError("release evidence has invalid owner token")

    try:
        status = ReleaseEvidenceStatus(str(release.get("status") or ""))
    except ValueError as exc:
        raise ValueError("unsupported release evidence status") from exc

    due_epoch = _epoch(release.get("due_epoch"), "due_epoch")
    attempted_at_epoch = _epoch(release.get("attempted_at_epoch"), "attempted_at_epoch")
    if attempted_at_epoch < due_epoch and status is not ReleaseEvidenceStatus.SUPERSEDED:
        raise ValueError("release attempt predates due time")

    postcondition = release.get("postcondition")
    if not isinstance(postcondition, Mapping):
        raise ValueError("release evidence requires postcondition object")
    if status is ReleaseEvidenceStatus.RELEASED and postcondition.get("verified") is not True:
        raise ValueError("released evidence requires verified absence postcondition")

    tc_handle = str(release.get("tc_handle") or "")
    if action == "throttle" and not _valid_tc_handle(tc_handle):
        raise ValueError("throttle release evidence requires valid tc handle")
    if action != "throttle" and tc_handle:
        raise ValueError("nft release evidence must not claim tc handle")

    command_count = _nonnegative_int(release.get("command_count"), "command_count")
    failed_count = _nonnegative_int(release.get("failed_count"), "failed_count")
    raw_errors = release.get("errors")
    if not isinstance(raw_errors, Sequence) or isinstance(raw_errors, (str, bytes)):
        raise ValueError("release evidence errors must be a sequence")
    errors = tuple(str(value)[:512] for value in raw_errors)

    evidence_ref = f"rust_release_engine_v1:{task_id}:{attempted_at_epoch:.6f}"
    return ReleaseEvidenceRecord(
        release_task_id=task_id,
        decision_id=decision_id,
        action_kind=action,
        resource_key=resource_key,
        owner_token=owner_token,
        tc_handle=tc_handle,
        due_epoch=due_epoch,
        attempted_at_epoch=attempted_at_epoch,
        status=status,
        result=result,
        command_count=command_count,
        failed_count=failed_count,
        errors=errors,
        postcondition=dict(postcondition),
        evidence_refs=(evidence_ref,),
        observed_at=datetime.fromtimestamp(attempted_at_epoch, tz=timezone.utc).isoformat(),
    )


def reconcile_release_evidence(
    *,
    execution: ActionExecutionReceipt,
    mechanism: AppliedMechanism,
    release: ReleaseEvidenceRecord,
) -> tuple[ActionExecutionReceipt, AppliedMechanism]:
    """Apply a verified release fact to already-observed correlated shadow evidence.

    This function cannot execute a rollback. It only changes evidence lifecycle after
    the Rust release engine has independently verified that its owned mechanism is no
    longer present.
    """

    if execution.decision_id != release.decision_id or mechanism.decision_id != release.decision_id:
        raise ValueError("release evidence decision correlation mismatch")
    if execution.execution_id != mechanism.execution_id:
        raise ValueError("release evidence execution/mechanism correlation mismatch")
    if execution.action_kind.lower() != release.action_kind:
        raise ValueError("release evidence action correlation mismatch")

    expected = expected_ownership(execution)
    if expected is None:
        # Legacy unowned actions cannot be retrospectively attributed to a release task.
        return execution, mechanism
    release_owner = _release_ownership(release)
    if expected != release_owner:
        raise ValueError("release evidence ownership mismatch")

    probe = mechanism.observed_parameters.get("postcondition_probe")
    if not isinstance(probe, Mapping):
        return execution, mechanism
    observed_owner = probe.get("ownership")
    if not isinstance(observed_owner, Mapping):
        return execution, mechanism
    normalized_observed_owner = {
        "kind": str(observed_owner.get("kind") or ""),
        "value": str(observed_owner.get("value") or ""),
    }
    if normalized_observed_owner != expected:
        raise ValueError("release evidence does not match observed mechanism owner")

    if release.status is not ReleaseEvidenceStatus.RELEASED:
        return execution, mechanism
    if release.postcondition.get("verified") is not True:
        return execution, mechanism
    if execution.status is not ExecutionStatus.APPLIED or execution.lifecycle is not ActionLifecycle.ACTIVE:
        return execution, mechanism
    if mechanism.status is not MechanismStatus.OBSERVED:
        return execution, mechanism

    refs = tuple(dict.fromkeys((*execution.provider_evidence_refs, *release.evidence_refs)))
    mechanism_refs = tuple(dict.fromkeys((*mechanism.evidence_refs, *release.evidence_refs)))
    release_summary = {
        "release_task_id": release.release_task_id,
        "status": release.status.value,
        "result": release.result,
        "observed_at": release.observed_at,
        "ownership": expected,
        "postcondition": dict(release.postcondition),
    }
    observed = dict(mechanism.observed_parameters)
    observed["release_evidence"] = release_summary
    return (
        replace(
            execution,
            status=ExecutionStatus.RELEASED,
            lifecycle=ActionLifecycle.RELEASED,
            completed_at=release.observed_at,
            release_ref=release.release_task_id,
            provider_evidence_refs=refs,
        ),
        replace(
            mechanism,
            status=MechanismStatus.RELEASED,
            observed_parameters=observed,
            observed_at=release.observed_at,
            evidence_refs=mechanism_refs,
            producer="azazel_edge.outcome.release_reconciliation",
        ),
    )


def _release_ownership(release: ReleaseEvidenceRecord) -> dict[str, str]:
    if release.action_kind == "throttle":
        return {"kind": "tc_handle", "value": release.tc_handle}
    return {"kind": "nft_comment", "value": release.owner_token}


def _required_text(mapping: Mapping[str, Any], key: str) -> str:
    value = str(mapping.get(key) or "").strip()
    if not value:
        raise ValueError(f"release evidence requires {key}")
    return value


def _epoch(value: Any, name: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be numeric")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not math.isfinite(parsed) or parsed < 0.0:
        raise ValueError(f"{name} must be finite and non-negative")
    return parsed


def _nonnegative_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return parsed


def _valid_tc_handle(value: str) -> bool:
    if not value.endswith(":"):
        return False
    raw = value[:-1]
    if not raw or len(raw) > 4:
        return False
    try:
        return int(raw, 16) > 0
    except ValueError:
        return False
