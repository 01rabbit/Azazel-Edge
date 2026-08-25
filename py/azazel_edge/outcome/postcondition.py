from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
from dataclasses import dataclass, replace
from typing import Any, Mapping, Protocol, Sequence

from .contracts import (
    ActionExecutionReceipt,
    AppliedMechanism,
    ExecutionStatus,
    MechanismKind,
    MechanismStatus,
    utc_now,
)


_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


class ReadOnlyCommandRejected(ValueError):
    """Raised when a caller attempts to use the probe runner for a mutating command."""


@dataclass(frozen=True)
class ReadOnlyCommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class ReadOnlyRunner(Protocol):
    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult: ...


class SubprocessReadOnlyRunner:
    """Minimal subprocess runner restricted to exact read-only tc/nft query shapes.

    This runner is deliberately unsuitable for enforcement. It never invokes a shell,
    accepts no arbitrary subcommands, and rejects every argv shape outside the small
    G1a query allowlist.
    """

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult:
        args = tuple(str(v) for v in argv)
        if not _is_allowed_read_only_query(args):
            raise ReadOnlyCommandRejected(f"command is outside read-only probe allowlist: {args!r}")
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        completed = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=max(0.1, float(timeout_seconds)),
            check=False,
            env=env,
        )
        return ReadOnlyCommandResult(
            argv=args,
            returncode=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


def verify_mechanism_postcondition(
    *,
    execution: ActionExecutionReceipt,
    mechanism: AppliedMechanism,
    runner: ReadOnlyRunner,
    timeout_seconds: float = 2.0,
) -> AppliedMechanism:
    """Independently verify a current Edge mechanism with read-only host queries.

    G1a does not execute, retry, release, repair, or authorize anything. It only
    upgrades an existing disruptive ``AppliedMechanism`` from ``unverified`` to
    ``observed`` when a narrowly-scoped postcondition can be read back from the host.

    A provider receipt must already be ``applied``. Partial/rejected/failed/dry-run
    receipts are never upgraded by this function even if a similar host state exists.
    """

    _validate_correlation(execution, mechanism)

    if execution.status is not ExecutionStatus.APPLIED:
        return _with_probe_result(
            mechanism,
            status=mechanism.status,
            basis="execution_not_applied",
            probe={"execution_status": execution.status.value},
        )

    try:
        if mechanism.mechanism_kind is MechanismKind.TRAFFIC_SHAPING:
            return _verify_traffic_shaping(execution, mechanism, runner, timeout_seconds)
        if mechanism.mechanism_kind is MechanismKind.REDIRECTION:
            return _verify_redirection(execution, mechanism, runner, timeout_seconds)
        if mechanism.mechanism_kind is MechanismKind.ISOLATION:
            return _verify_isolation(execution, mechanism, runner, timeout_seconds)
    except (ReadOnlyCommandRejected, ValueError, TypeError, json.JSONDecodeError) as exc:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="probe_input_or_parse_error",
            probe={"error": type(exc).__name__},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="probe_runtime_error",
            probe={"error": type(exc).__name__},
        )

    # Notification delivery and other future provider types need their own evidence
    # source. G1a must not use tc/nft state to infer them.
    return _with_probe_result(
        mechanism,
        status=mechanism.status,
        basis="no_postcondition_probe_for_mechanism",
        probe={"mechanism_kind": mechanism.mechanism_kind.value},
    )


def _verify_traffic_shaping(
    execution: ActionExecutionReceipt,
    mechanism: AppliedMechanism,
    runner: ReadOnlyRunner,
    timeout_seconds: float,
) -> AppliedMechanism:
    scope = mechanism.scope
    if scope.get("scope_kind") != "interface_root_qdisc":
        raise ValueError("traffic shaping requires interface_root_qdisc scope")
    interface = _validated_interface(scope.get("interface"))
    if not _requested_plan_has_tbf(execution, interface):
        raise ValueError("requested plan does not contain the expected root tbf qdisc")

    result = runner.run(("tc", "-j", "qdisc", "show", "dev", interface), timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="tc_query_failed",
            probe=_result_summary(result),
        )
    payload = json.loads(result.stdout or "[]")
    if not isinstance(payload, list):
        raise ValueError("tc JSON must be a list")
    matched = any(
        isinstance(item, Mapping)
        and str(item.get("kind") or "").lower() == "tbf"
        and item.get("root") is True
        for item in payload
    )
    return _with_probe_result(
        mechanism,
        status=MechanismStatus.OBSERVED if matched else MechanismStatus.NOT_OBSERVED,
        basis="tc_root_tbf_readback_match" if matched else "tc_root_tbf_not_found",
        probe=_result_summary(result),
    )


def _verify_redirection(
    execution: ActionExecutionReceipt,
    mechanism: AppliedMechanism,
    runner: ReadOnlyRunner,
    timeout_seconds: float,
) -> AppliedMechanism:
    scope = mechanism.scope
    if scope.get("scope_kind") != "source_ip_and_destination_port":
        raise ValueError("redirection requires source_ip_and_destination_port scope")
    source_ip = _validated_ip(scope.get("source_ip"))
    destination_port = _validated_port(scope.get("destination_port"))
    redirect_port = _requested_redirect_port(execution, source_ip, destination_port)
    if redirect_port is None:
        raise ValueError("requested redirect target port is not grounded")

    result = runner.run(
        ("nft", "-j", "list", "chain", "inet", "azazel_edge", "prerouting"),
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="nft_prerouting_query_failed",
            probe=_result_summary(result),
        )
    payload = json.loads(result.stdout or "{}")
    matched = _nft_has_redirect_rule(payload, source_ip, destination_port, redirect_port)
    return _with_probe_result(
        mechanism,
        status=MechanismStatus.OBSERVED if matched else MechanismStatus.NOT_OBSERVED,
        basis="nft_redirect_rule_readback_match" if matched else "nft_redirect_rule_not_found",
        probe=_result_summary(result),
    )


def _verify_isolation(
    execution: ActionExecutionReceipt,
    mechanism: AppliedMechanism,
    runner: ReadOnlyRunner,
    timeout_seconds: float,
) -> AppliedMechanism:
    scope = mechanism.scope
    if scope.get("scope_kind") != "source_ip":
        raise ValueError("isolation requires source_ip scope")
    source_ip = _validated_ip(scope.get("source_ip"))
    if not _requested_plan_has_isolation(execution, source_ip):
        raise ValueError("requested plan does not contain expected source-IP drop rule")

    result = runner.run(
        ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input"),
        timeout_seconds=timeout_seconds,
    )
    if result.returncode != 0:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="nft_input_query_failed",
            probe=_result_summary(result),
        )
    payload = json.loads(result.stdout or "{}")
    matched = _nft_has_source_drop_rule(payload, source_ip)
    return _with_probe_result(
        mechanism,
        status=MechanismStatus.OBSERVED if matched else MechanismStatus.NOT_OBSERVED,
        basis="nft_isolation_rule_readback_match" if matched else "nft_isolation_rule_not_found",
        probe=_result_summary(result),
    )


def _validate_correlation(execution: ActionExecutionReceipt, mechanism: AppliedMechanism) -> None:
    if execution.decision_id != mechanism.decision_id:
        raise ValueError("execution/mechanism decision mismatch")
    if execution.execution_id != mechanism.execution_id:
        raise ValueError("execution/mechanism execution mismatch")


def _validated_interface(value: Any) -> str:
    interface = str(value or "")
    if not _INTERFACE_RE.fullmatch(interface):
        raise ValueError("invalid interface name")
    return interface


def _validated_ip(value: Any) -> str:
    return str(ipaddress.ip_address(str(value or "")))


def _validated_port(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("invalid port")
    port = int(value)
    if port < 1 or port > 65535:
        raise ValueError("invalid port")
    return port


def _requested_commands(execution: ActionExecutionReceipt) -> tuple[str, ...]:
    raw = execution.requested_parameters.get("command_plan")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    return tuple(str(v) for v in raw if isinstance(v, str))


def _requested_plan_has_tbf(execution: ActionExecutionReceipt, interface: str) -> bool:
    expected = ("tc", "qdisc", "replace", "dev", interface, "root", "tbf")
    for command in _requested_commands(execution):
        parts = tuple(command.split())
        if parts[: len(expected)] == expected:
            return True
    return False


def _requested_redirect_port(
    execution: ActionExecutionReceipt,
    source_ip: str,
    destination_port: int,
) -> int | None:
    for command in _requested_commands(execution):
        parts = command.split()
        try:
            if parts[:7] != ["nft", "insert", "rule", "inet", "azazel_edge", "prerouting", "ip"]:
                continue
            saddr_idx = parts.index("saddr")
            dport_idx = parts.index("dport")
            redirect_idx = parts.index("redirect")
            to_idx = parts.index("to", redirect_idx)
            if parts[saddr_idx + 1] != source_ip:
                continue
            if int(parts[dport_idx + 1]) != destination_port:
                continue
            return _validated_port(parts[to_idx + 1])
        except (ValueError, IndexError):
            continue
    return None


def _requested_plan_has_isolation(execution: ActionExecutionReceipt, source_ip: str) -> bool:
    for command in _requested_commands(execution):
        parts = command.split()
        expected_prefix = ["nft", "insert", "rule", "inet", "azazel_edge", "input", "ip", "saddr"]
        if parts[: len(expected_prefix)] != expected_prefix:
            continue
        if len(parts) > len(expected_prefix) + 1 and parts[len(expected_prefix)] == source_ip and parts[-1] == "drop":
            return True
    return False


def _nftables(payload: Any) -> list[Mapping[str, Any]]:
    if not isinstance(payload, Mapping):
        return []
    entries = payload.get("nftables")
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, Mapping)]


def _rule_exprs(payload: Any, *, chain: str) -> list[list[Mapping[str, Any]]]:
    result: list[list[Mapping[str, Any]]] = []
    for entry in _nftables(payload):
        rule = entry.get("rule")
        if not isinstance(rule, Mapping) or rule.get("chain") != chain:
            continue
        expr = rule.get("expr")
        if isinstance(expr, list):
            result.append([item for item in expr if isinstance(item, Mapping)])
    return result


def _match_value(exprs: list[Mapping[str, Any]], protocol: str, field: str) -> Any:
    for expr in exprs:
        match = expr.get("match")
        if not isinstance(match, Mapping) or match.get("op") != "==":
            continue
        left = match.get("left")
        if not isinstance(left, Mapping):
            continue
        payload = left.get("payload")
        if not isinstance(payload, Mapping):
            continue
        if payload.get("protocol") == protocol and payload.get("field") == field:
            return match.get("right")
    return None


def _nft_has_redirect_rule(payload: Any, source_ip: str, destination_port: int, redirect_port: int) -> bool:
    for exprs in _rule_exprs(payload, chain="prerouting"):
        if str(_match_value(exprs, "ip", "saddr") or "") != source_ip:
            continue
        try:
            if int(_match_value(exprs, "tcp", "dport")) != destination_port:
                continue
        except (TypeError, ValueError):
            continue
        for expr in exprs:
            redirect = expr.get("redirect")
            if not isinstance(redirect, Mapping):
                continue
            try:
                if int(redirect.get("port")) == redirect_port:
                    return True
            except (TypeError, ValueError):
                continue
    return False


def _nft_has_source_drop_rule(payload: Any, source_ip: str) -> bool:
    for exprs in _rule_exprs(payload, chain="input"):
        if str(_match_value(exprs, "ip", "saddr") or "") != source_ip:
            continue
        for expr in exprs:
            verdict = expr.get("drop")
            if verdict is not None:
                return True
    return False


def _result_summary(result: ReadOnlyCommandResult) -> dict[str, Any]:
    # Do not copy arbitrary provider stdout into durable evidence. The parsed
    # postcondition and small error summary are sufficient for this v1 record.
    return {
        "argv": list(result.argv),
        "returncode": result.returncode,
        "stderr": result.stderr[:512],
    }


def _with_probe_result(
    mechanism: AppliedMechanism,
    *,
    status: MechanismStatus,
    basis: str,
    probe: Mapping[str, Any],
) -> AppliedMechanism:
    observed = dict(mechanism.observed_parameters)
    observed["postcondition_probe"] = {
        "basis": basis,
        "observed_at": utc_now(),
        **dict(probe),
    }
    return replace(
        mechanism,
        status=status,
        observed_parameters=observed,
        observed_at=utc_now(),
        producer="azazel_edge.outcome.postcondition",
    )


def _is_allowed_read_only_query(argv: tuple[str, ...]) -> bool:
    if len(argv) == 6 and argv[:4] == ("tc", "-j", "qdisc", "show") and argv[4] == "dev":
        return bool(_INTERFACE_RE.fullmatch(argv[5]))
    if len(argv) == 8 and argv[:4] == ("nft", "-j", "list", "chain"):
        return argv[4:7] == ("inet", "azazel_edge", "prerouting") and argv[7] == ""  # unreachable guard
    if argv == ("nft", "-j", "list", "chain", "inet", "azazel_edge", "prerouting"):
        return True
    if argv == ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input"):
        return True
    return False
