from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .contracts import (
    ActionExecutionReceipt,
    ActionLifecycle,
    AppliedMechanism,
    Correlation,
    ExecutionStatus,
    MechanismKind,
    MechanismStatus,
    ShadowRecordBundle,
)


RUST_PROVIDER = "rust_event_engine_v1"
_DISRUPTIVE_ACTIONS = {"throttle", "redirect", "isolate"}


def _stable_id(prefix: str, *parts: object) -> str:
    raw = "\x1f".join(str(part) for part in parts).encode("utf-8", errors="replace")
    return f"{prefix}-{hashlib.sha256(raw).hexdigest()[:24]}"


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _action_kind(event: Mapping[str, Any]) -> str:
    enforcement = _as_mapping(event.get("enforcement"))
    defense = _as_mapping(event.get("defense"))
    return str(enforcement.get("selected_action") or defense.get("action") or "unknown").lower()


def _execution_status(enforcement: Mapping[str, Any], action: str) -> ExecutionStatus:
    mode = str(enforcement.get("mode", "")).lower()
    result = str(enforcement.get("result", "")).lower()
    failed_count = int(enforcement.get("failed_count") or 0)
    executed_count = int(enforcement.get("executed_count") or 0)

    if mode == "policy_gated":
        return ExecutionStatus.REJECTED
    if mode == "dry_run":
        return ExecutionStatus.UNVERIFIED
    if failed_count > 0 and executed_count == 0:
        return ExecutionStatus.FAILED
    if failed_count > 0 and executed_count > 0:
        return ExecutionStatus.PARTIAL
    if result == "partial_failure":
        return ExecutionStatus.UNVERIFIED
    if mode == "enforced" and result == "applied" and failed_count == 0:
        # A disruptive provider cannot truthfully be marked applied if it reports
        # that it executed zero commands. Current Rust normally cannot emit this
        # combination, but the normalization boundary remains fail-closed for
        # malformed/legacy/provider records.
        if action in _DISRUPTIVE_ACTIONS and executed_count <= 0:
            return ExecutionStatus.UNVERIFIED
        return ExecutionStatus.APPLIED
    # observe is an intentional no-runtime-change action. It is complete by definition.
    if action == "observe" and result == "no_disruptive_action":
        return ExecutionStatus.APPLIED
    # The Rust core currently selects notify but does not prove delivery to an external notifier.
    if action == "notify":
        return ExecutionStatus.UNVERIFIED
    return ExecutionStatus.UNVERIFIED


def _action_lifecycle(status: ExecutionStatus) -> ActionLifecycle:
    return {
        ExecutionStatus.APPLIED: ActionLifecycle.ACTIVE,
        ExecutionStatus.PARTIAL: ActionLifecycle.UNVERIFIED,
        ExecutionStatus.REJECTED: ActionLifecycle.REJECTED,
        ExecutionStatus.FAILED: ActionLifecycle.FAILED,
        ExecutionStatus.EXPIRED: ActionLifecycle.EXPIRED,
        ExecutionStatus.RELEASED: ActionLifecycle.RELEASED,
        ExecutionStatus.UNVERIFIED: ActionLifecycle.UNVERIFIED,
    }[status]


def _mechanism_kind(action: str) -> MechanismKind:
    return {
        "throttle": MechanismKind.TRAFFIC_SHAPING,
        "redirect": MechanismKind.REDIRECTION,
        "isolate": MechanismKind.ISOLATION,
        "notify": MechanismKind.NOTIFICATION,
        "observe": MechanismKind.OBSERVATION_ONLY,
    }.get(action, MechanismKind.UNKNOWN)


def _mechanism_status(status: ExecutionStatus, action: str) -> MechanismStatus:
    if status is ExecutionStatus.APPLIED and action == "observe":
        return MechanismStatus.OBSERVED
    if status is ExecutionStatus.APPLIED:
        # A zero exit status proves provider command completion, not postcondition state.
        return MechanismStatus.UNVERIFIED
    if status is ExecutionStatus.PARTIAL:
        return MechanismStatus.DISPUTED
    if status in {ExecutionStatus.REJECTED, ExecutionStatus.FAILED}:
        return MechanismStatus.NOT_OBSERVED
    if status is ExecutionStatus.RELEASED:
        return MechanismStatus.RELEASED
    return MechanismStatus.UNVERIFIED


def _extract_iface(command_plan: list[str]) -> str:
    for command in command_plan:
        parts = command.split()
        if parts[:3] == ["tc", "qdisc", "replace"] and "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    return ""


def _scope(event: Mapping[str, Any], action: str, command_plan: list[str]) -> dict[str, Any]:
    normalized = _as_mapping(event.get("normalized"))
    src_ip = str(normalized.get("src_ip") or "")
    target_port = normalized.get("target_port")
    if action == "throttle":
        # Current Rust plan installs a root qdisc on the configured interface.
        # Do not mislabel this as attacker-scoped simply because the decision target is an IP.
        return {
            "scope_kind": "interface_root_qdisc",
            "interface": _extract_iface(command_plan),
            "decision_subject_ip": src_ip,
        }
    if action == "redirect":
        return {
            "scope_kind": "source_ip_and_destination_port",
            "source_ip": src_ip,
            "destination_port": target_port,
        }
    if action == "isolate":
        return {"scope_kind": "source_ip", "source_ip": src_ip}
    return {"scope_kind": "logical_action", "subject_ip": src_ip}


def _provider_execution_summary(enforcement: Mapping[str, Any]) -> dict[str, Any]:
    """Return only execution facts the current provider actually reports.

    The Rust record exposes aggregate success/failure counts, not a per-command receipt.
    Consequently a partial result cannot truthfully identify which requested command
    was applied. Keep the complete plan on the requested side and record only the
    provider's aggregate execution report here.
    """

    return {
        "executed_count": int(enforcement.get("executed_count") or 0),
        "failed_count": int(enforcement.get("failed_count") or 0),
        "result": str(enforcement.get("result") or ""),
        "mode": str(enforcement.get("mode") or ""),
        "metadata": dict(_as_mapping(enforcement.get("metadata"))),
        "individual_command_mapping_verified": False,
    }


def _mechanism_observation_parameters(
    action: str,
    status: MechanismStatus,
    provider_summary: Mapping[str, Any],
) -> dict[str, Any]:
    if action == "observe" and status is MechanismStatus.OBSERVED:
        return {
            "verification_basis": "no_runtime_change_action",
            "provider_report": dict(provider_summary),
        }
    if status is MechanismStatus.NOT_OBSERVED:
        return {
            "verification_basis": "provider_report_no_successful_postcondition",
            "provider_report": dict(provider_summary),
        }
    return {
        "verification_basis": "provider_command_exit_status_only",
        "provider_report": dict(provider_summary),
    }


def from_rust_event(event: Mapping[str, Any]) -> ShadowRecordBundle:
    """Normalize an existing Rust event-engine record into shadow evidence contracts.

    This function never executes, retries, releases, or authorizes an action. The Rust
    event engine remains the source of execution facts. Missing facts are represented
    as ``unverified`` rather than inferred.
    """

    normalized = _as_mapping(event.get("normalized"))
    defense = _as_mapping(event.get("defense"))
    enforcement = _as_mapping(event.get("enforcement"))

    if not normalized or not defense or not enforcement:
        raise ValueError("rust event must contain normalized, defense and enforcement objects")

    trace_id = str(enforcement.get("trace_id") or "")
    ts = str(normalized.get("ts") or "")
    src_ip = str(normalized.get("src_ip") or "")
    dst_ip = str(normalized.get("dst_ip") or "")
    sid = str(normalized.get("sid") or "0")
    action = _action_kind(event)
    if not ts:
        raise ValueError("normalized.ts is required for canonical shadow evidence")

    decision_id = trace_id or _stable_id("decision", ts, src_ip, dst_ip, sid, action)
    # No authoritative incident/session identity is proven by the Rust record today.
    # Use a per-decision synthetic incident id rather than guessing cross-event grouping.
    incident_id = _stable_id("incident", decision_id)
    action_id = _stable_id("action", decision_id, action)
    execution_id = _stable_id("execution", decision_id, enforcement.get("mode"), enforcement.get("result"))
    mechanism_id = _stable_id("mechanism", execution_id, action)

    command_plan = [str(v) for v in enforcement.get("command_plan", []) if isinstance(v, str)]
    rollback_plan = [str(v) for v in enforcement.get("rollback_plan", []) if isinstance(v, str)]
    status = _execution_status(enforcement, action)
    lifecycle = _action_lifecycle(status)
    mechanism_status = _mechanism_status(status, action)
    scope = _scope(event, action, command_plan)
    provider_summary = _provider_execution_summary(enforcement)

    provider = str(event.get("pipeline") or RUST_PROVIDER)
    evidence_ref = f"{provider}:{decision_id}"
    error_code = ""
    errors = enforcement.get("errors")
    if isinstance(errors, list) and errors:
        error_code = "provider_command_failure"

    receipt = ActionExecutionReceipt(
        incident_id=incident_id,
        decision_id=decision_id,
        action_id=action_id,
        execution_id=execution_id,
        action_kind=action,
        provider=provider,
        scope=scope,
        requested_parameters={
            "target": enforcement.get("target") or defense.get("target"),
            "policy_reason": enforcement.get("policy_reason") or defense.get("policy_reason"),
            "command_plan": command_plan,
            "rollback_plan": rollback_plan,
        },
        applied_parameters=provider_summary if status in {ExecutionStatus.APPLIED, ExecutionStatus.PARTIAL} else {},
        status=status,
        requested_at=ts,
        started_at="",
        completed_at="",
        reversible=bool(rollback_plan),
        release_ref="rollback_plan" if rollback_plan else "",
        error_code=error_code,
        provider_evidence_refs=(evidence_ref,),
        producer="azazel_edge.outcome.rust_adapter",
        lifecycle=lifecycle,
        idempotency_key=execution_id,
    )
    mechanism = AppliedMechanism(
        mechanism_id=mechanism_id,
        execution_id=execution_id,
        decision_id=decision_id,
        mechanism_kind=_mechanism_kind(action),
        scope=scope,
        observed_parameters=_mechanism_observation_parameters(action, mechanism_status, provider_summary),
        status=mechanism_status,
        observed_at=ts,
        reversible=bool(rollback_plan),
        evidence_refs=(evidence_ref,),
        producer="azazel_edge.outcome.rust_adapter",
    )
    correlation = Correlation(
        incident_id=incident_id,
        decision_id=decision_id,
        action_id=action_id,
        execution_id=execution_id,
        mechanism_id=mechanism_id,
        reasoning_trace_id=trace_id,
    )
    return ShadowRecordBundle(correlation=correlation, execution=receipt, mechanism=mechanism)
