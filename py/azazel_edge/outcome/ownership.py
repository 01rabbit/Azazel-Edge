from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Mapping, Sequence

from .contracts import ActionExecutionReceipt, AppliedMechanism
from .postcondition import (
    ReadOnlyCommandResult,
    ReadOnlyRunner,
    verify_mechanism_postcondition as _verify_legacy_postcondition,
)

_OWNER_PREFIX = "azazel-edge:release-"


def expected_ownership(execution: ActionExecutionReceipt) -> dict[str, str] | None:
    """Extract the single ownership marker grounded in a provider command plan.

    G1b-owned disruptive plans use either a qdisc handle (throttle) or an nft rule
    comment (redirect/isolate). Legacy plans have no marker and intentionally return
    ``None`` so the already-merged G1a behavior remains available for old evidence.
    Conflicting markers are rejected rather than guessed.
    """

    owners: list[dict[str, str]] = []
    for command in _requested_commands(execution):
        parts = command.split()
        if parts[:3] == ["tc", "qdisc", "replace"] and "root" in parts and "tbf" in parts:
            try:
                root_idx = parts.index("root")
                if parts[root_idx + 1] == "handle":
                    handle = parts[root_idx + 2]
                    if not _valid_tc_handle(handle):
                        raise ValueError("invalid tc ownership handle")
                    owners.append({"kind": "tc_handle", "value": handle})
            except (IndexError, ValueError) as exc:
                if isinstance(exc, ValueError) and str(exc) == "invalid tc ownership handle":
                    raise
        if parts and parts[0] == "nft" and "comment" in parts:
            try:
                comment_idx = parts.index("comment")
                token = parts[comment_idx + 1]
            except IndexError as exc:
                raise ValueError("nft ownership comment is missing its token") from exc
            if not _valid_owner_token(token):
                raise ValueError("invalid nft ownership token")
            owners.append({"kind": "nft_comment", "value": token})

    if not owners:
        return None
    first = owners[0]
    if any(owner != first for owner in owners[1:]):
        raise ValueError("conflicting ownership markers in execution command plan")
    return first


def verify_mechanism_postcondition(
    *,
    execution: ActionExecutionReceipt,
    mechanism: AppliedMechanism,
    runner: ReadOnlyRunner,
    timeout_seconds: float = 2.0,
) -> AppliedMechanism:
    """Run G1a verification, restricted to the G1b-owned mechanism when present."""

    ownership = expected_ownership(execution)
    if ownership is None:
        return _verify_legacy_postcondition(
            execution=execution,
            mechanism=mechanism,
            runner=runner,
            timeout_seconds=timeout_seconds,
        )

    normalized_execution = replace(
        execution,
        requested_parameters={
            **dict(execution.requested_parameters),
            "command_plan": list(_normalized_commands(execution)),
        },
    )
    filtered_runner = _OwnershipFilteringRunner(runner, ownership)
    verified = _verify_legacy_postcondition(
        execution=normalized_execution,
        mechanism=mechanism,
        runner=filtered_runner,
        timeout_seconds=timeout_seconds,
    )

    probe = verified.observed_parameters.get("postcondition_probe")
    if not isinstance(probe, Mapping):
        return verified
    enriched_probe = dict(probe)
    enriched_probe["ownership"] = dict(ownership)
    observed = dict(verified.observed_parameters)
    observed["postcondition_probe"] = enriched_probe
    digest_payload = json.dumps(
        {"ownership": ownership, "basis": probe.get("basis"), "observed_at": probe.get("observed_at")},
        sort_keys=True,
        separators=(",", ":"),
    )
    ownership_ref = f"postcondition-ownership:{hashlib.sha256(digest_payload.encode('utf-8')).hexdigest()[:24]}"
    refs = tuple(dict.fromkeys((*verified.evidence_refs, ownership_ref)))
    return replace(
        verified,
        observed_parameters=observed,
        evidence_refs=refs,
        producer="azazel_edge.outcome.ownership_postcondition",
    )


class _OwnershipFilteringRunner:
    def __init__(self, delegate: ReadOnlyRunner, ownership: Mapping[str, str]) -> None:
        self._delegate = delegate
        self._ownership = dict(ownership)

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult:
        result = self._delegate.run(argv, timeout_seconds=timeout_seconds)
        if result.returncode != 0:
            return result
        args = tuple(str(value) for value in argv)
        if self._ownership["kind"] == "tc_handle" and args[:4] == ("tc", "-j", "qdisc", "show"):
            payload = json.loads(result.stdout or "[]")
            if not isinstance(payload, list):
                raise ValueError("tc JSON must be a list")
            payload = [
                item
                for item in payload
                if isinstance(item, Mapping) and str(item.get("handle") or "") == self._ownership["value"]
            ]
            return replace(result, stdout=json.dumps(payload, separators=(",", ":")))
        if self._ownership["kind"] == "nft_comment" and args[:4] == ("nft", "-j", "list", "chain"):
            payload = json.loads(result.stdout or "{}")
            if not isinstance(payload, Mapping):
                raise ValueError("nft JSON must be an object")
            entries = payload.get("nftables")
            if not isinstance(entries, list):
                raise ValueError("nft JSON must contain nftables list")
            filtered: list[Mapping[str, Any]] = []
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                rule = entry.get("rule")
                if not isinstance(rule, Mapping):
                    continue
                if str(rule.get("comment") or "") == self._ownership["value"]:
                    filtered.append(entry)
            return replace(result, stdout=json.dumps({"nftables": filtered}, separators=(",", ":")))
        return result


def _requested_commands(execution: ActionExecutionReceipt) -> tuple[str, ...]:
    raw = execution.requested_parameters.get("command_plan")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    return tuple(str(value) for value in raw if isinstance(value, str))


def _normalized_commands(execution: ActionExecutionReceipt) -> tuple[str, ...]:
    normalized: list[str] = []
    for command in _requested_commands(execution):
        parts = command.split()
        if parts[:3] == ["tc", "qdisc", "replace"] and "root" in parts:
            root_idx = parts.index("root")
            if root_idx + 2 < len(parts) and parts[root_idx + 1] == "handle":
                del parts[root_idx + 1 : root_idx + 3]
        if parts and parts[0] == "nft" and "comment" in parts:
            comment_idx = parts.index("comment")
            if comment_idx + 1 >= len(parts):
                raise ValueError("nft ownership comment is missing its token")
            del parts[comment_idx : comment_idx + 2]
        normalized.append(" ".join(parts))
    return tuple(normalized)


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


def _valid_owner_token(value: str) -> bool:
    return (
        value.startswith(_OWNER_PREFIX)
        and len(value) <= 96
        and all(character.isalnum() or character in ":-" for character in value)
    )
