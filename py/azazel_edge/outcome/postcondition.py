from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
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
_NUMBER_UNIT_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([A-Za-z]+)?$")
_TRUSTED_BINARY_SEARCH_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


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
    """Subprocess runner restricted to exact read-only tc/nft query shapes.

    It never invokes a shell, accepts no caller-controlled subcommand shape, ignores
    the process PATH when resolving tc/nft, and is deliberately unsuitable for
    enforcement, rollback, repair, or release.
    """

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult:
        args = tuple(str(value) for value in argv)
        if not _is_allowed_read_only_query(args):
            raise ReadOnlyCommandRejected(f"command is outside read-only probe allowlist: {args!r}")
        binary = shutil.which(args[0], path=_TRUSTED_BINARY_SEARCH_PATH)
        if not binary:
            raise OSError(f"read-only probe binary not found in trusted path: {args[0]}")
        env = dict(os.environ)
        env["LC_ALL"] = "C"
        env["PATH"] = _TRUSTED_BINARY_SEARCH_PATH
        completed = subprocess.run(
            (binary, *args[1:]),
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
    """Verify a mechanism postcondition using read-only host state.

    G1a never executes, retries, repairs, releases, or authorizes an action. A
    disruptive mechanism is promoted to ``observed`` only when an already-applied
    provider receipt correlates exactly and the expected host/network state is read
    back with sufficient parameter specificity.
    """

    _validate_correlation(execution, mechanism)

    if execution.status is not ExecutionStatus.APPLIED:
        return _with_probe_result(
            mechanism,
            status=mechanism.status,
            basis="execution_not_applied",
            verification_strength="none",
            probe={"execution_status": execution.status.value},
        )

    try:
        if mechanism.mechanism_kind is MechanismKind.TRAFFIC_SHAPING:
            return _verify_traffic_shaping(execution, mechanism, runner, timeout_seconds)
        if mechanism.mechanism_kind is MechanismKind.REDIRECTION:
            return _verify_redirection(execution, mechanism, runner, timeout_seconds)
        if mechanism.mechanism_kind is MechanismKind.ISOLATION:
            return _verify_isolation(execution, mechanism, runner, timeout_seconds)
    except (ReadOnlyCommandRejected, ValueError, TypeError, json.JSONDecodeError, OverflowError) as exc:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="probe_input_or_parse_error",
            verification_strength="none",
            probe={"error": type(exc).__name__},
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="probe_runtime_error",
            verification_strength="none",
            probe={"error": type(exc).__name__},
        )

    return _with_probe_result(
        mechanism,
        status=mechanism.status,
        basis="no_postcondition_probe_for_mechanism",
        verification_strength="none",
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
    expected = _requested_tbf_semantics(execution, interface)

    result = runner.run(("tc", "-j", "qdisc", "show", "dev", interface), timeout_seconds=timeout_seconds)
    if result.returncode != 0:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="tc_query_failed",
            verification_strength="none",
            probe=_result_summary(result),
        )

    payload = json.loads(result.stdout or "[]")
    if not isinstance(payload, list):
        raise ValueError("tc JSON must be a list")

    saw_root_tbf = False
    saw_complete_candidate = False
    for item in payload:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("kind") or "").lower() != "tbf" or item.get("root") is not True:
            continue
        saw_root_tbf = True
        candidate = _readback_tbf_semantics(item)
        if candidate is None:
            continue
        saw_complete_candidate = True
        if _tbf_semantics_equal(expected, candidate):
            return _with_probe_result(
                mechanism,
                status=MechanismStatus.OBSERVED,
                basis="tc_root_tbf_parameter_readback_match",
                verification_strength="exact",
                probe={**_result_summary(result), "expected": expected, "observed": candidate},
            )

    if saw_root_tbf and not saw_complete_candidate:
        return _with_probe_result(
            mechanism,
            status=MechanismStatus.UNVERIFIED,
            basis="tc_root_tbf_present_but_parameters_unverifiable",
            verification_strength="partial",
            probe=_result_summary(result),
        )
    return _with_probe_result(
        mechanism,
        status=MechanismStatus.NOT_OBSERVED,
        basis="tc_root_tbf_parameter_match_not_found",
        verification_strength="exact",
        probe={**_result_summary(result), "expected": expected},
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
            verification_strength="none",
            probe=_result_summary(result),
        )
    payload = json.loads(result.stdout or "{}")
    matched = _nft_has_redirect_rule(payload, source_ip, destination_port, redirect_port)
    return _with_probe_result(
        mechanism,
        status=MechanismStatus.OBSERVED if matched else MechanismStatus.NOT_OBSERVED,
        basis="nft_redirect_rule_readback_match" if matched else "nft_redirect_rule_not_found",
        verification_strength="exact",
        probe={
            **_result_summary(result),
            "source_ip": source_ip,
            "destination_port": destination_port,
            "redirect_port": redirect_port,
        },
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
            verification_strength="none",
            probe=_result_summary(result),
        )
    payload = json.loads(result.stdout or "{}")
    matched = _nft_has_source_drop_rule(payload, source_ip)
    return _with_probe_result(
        mechanism,
        status=MechanismStatus.OBSERVED if matched else MechanismStatus.NOT_OBSERVED,
        basis="nft_isolation_rule_readback_match" if matched else "nft_isolation_rule_not_found",
        verification_strength="exact",
        probe={**_result_summary(result), "source_ip": source_ip},
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
    return tuple(str(value) for value in raw if isinstance(value, str))


def _requested_tbf_semantics(execution: ActionExecutionReceipt, interface: str) -> dict[str, int]:
    expected_prefix = ("tc", "qdisc", "replace", "dev", interface, "root", "tbf")
    for command in _requested_commands(execution):
        parts = command.split()
        if tuple(parts[: len(expected_prefix)]) != expected_prefix:
            continue
        try:
            rate = parts[parts.index("rate") + 1]
            burst = parts[parts.index("burst") + 1]
            latency = parts[parts.index("latency") + 1]
        except (ValueError, IndexError) as exc:
            raise ValueError("requested TBF command is missing rate/burst/latency") from exc
        return {
            "rate_bps": _parse_rate_bps(rate),
            "burst_bytes": _parse_size_bytes(burst),
            "latency_us": _parse_time_us(latency),
        }
    raise ValueError("requested plan does not contain expected root TBF command")


def _readback_tbf_semantics(item: Mapping[str, Any]) -> dict[str, int] | None:
    try:
        return {
            "rate_bps": _parse_readback_rate_bps(item.get("rate")),
            "burst_bytes": _parse_readback_size_bytes(item.get("burst")),
            "latency_us": _parse_readback_time_us(item.get("lat")),
        }
    except (ValueError, TypeError, OverflowError):
        return None


def _tbf_semantics_equal(expected: Mapping[str, int], observed: Mapping[str, int]) -> bool:
    # Kernel/iproute2 conversion can round burst/latency slightly. The tolerance is
    # narrow and explicit; it is not a license to accept a different shaping policy.
    rate_ok = _within_relative(expected["rate_bps"], observed["rate_bps"], 0.01)
    burst_ok = _within_relative(expected["burst_bytes"], observed["burst_bytes"], 0.02)
    latency_ok = abs(expected["latency_us"] - observed["latency_us"]) <= max(
        1000, int(expected["latency_us"] * 0.02)
    )
    return rate_ok and burst_ok and latency_ok


def _within_relative(expected: int, observed: int, tolerance: float) -> bool:
    if expected <= 0 or observed < 0:
        return False
    return abs(expected - observed) <= max(1, int(expected * tolerance))


def _parse_rate_bps(value: Any) -> int:
    number, unit = _number_unit(value)
    factors = {
        "bit": 1,
        "kbit": 1_000,
        "mbit": 1_000_000,
        "gbit": 1_000_000_000,
        "bps": 8,
        "kbps": 8_000,
        "mbps": 8_000_000,
        "gbps": 8_000_000_000,
    }
    unit = unit or "bit"
    if unit not in factors:
        raise ValueError("unsupported rate unit")
    return int(round(number * factors[unit]))


def _parse_readback_rate_bps(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid readback rate")
    if isinstance(value, (int, float)):
        # iproute2 stores qdisc rates internally as bytes/s; JSON implementations in
        # the field may expose either raw bytes/s or formatted bit/s. Numeric values
        # are normalized as raw bytes/s, while strings retain their displayed units.
        return int(round(float(value) * 8.0))
    return _parse_rate_bps(value)


def _parse_size_bytes(value: Any) -> int:
    number, unit = _number_unit(value)
    factors = {
        "b": 1,
        "byte": 1,
        "bytes": 1,
        "kb": 1_000,
        "kbyte": 1_000,
        "kbytes": 1_000,
        "mb": 1_000_000,
        "gb": 1_000_000_000,
        "bit": 1 / 8,
        "kbit": 1_000 / 8,
        "mbit": 1_000_000 / 8,
        "gbit": 1_000_000_000 / 8,
    }
    unit = unit or "b"
    if unit not in factors:
        raise ValueError("unsupported size unit")
    result = number * factors[unit]
    if result <= 0:
        raise ValueError("size must be positive")
    return int(round(result))


def _parse_readback_size_bytes(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid readback size")
    if isinstance(value, (int, float)):
        return int(round(float(value)))
    return _parse_size_bytes(value)


def _parse_time_us(value: Any) -> int:
    number, unit = _number_unit(value)
    factors = {"us": 1, "usec": 1, "ms": 1_000, "msec": 1_000, "s": 1_000_000, "sec": 1_000_000}
    unit = unit or "us"
    if unit not in factors:
        raise ValueError("unsupported time unit")
    result = number * factors[unit]
    if result < 0:
        raise ValueError("time must not be negative")
    return int(round(result))


def _parse_readback_time_us(value: Any) -> int:
    if isinstance(value, bool) or value is None:
        raise ValueError("invalid readback time")
    if isinstance(value, (int, float)):
        return int(round(float(value)))
    return _parse_time_us(value)


def _number_unit(value: Any) -> tuple[float, str]:
    raw = str(value or "").strip().lower()
    match = _NUMBER_UNIT_RE.fullmatch(raw)
    if not match:
        raise ValueError(f"invalid numeric unit value: {raw!r}")
    number = float(match.group(1))
    if number < 0:
        raise ValueError("numeric unit value must not be negative")
    return number, (match.group(2) or "").lower()


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
        if any("drop" in expr for expr in exprs):
            return True
    return False


def _result_summary(result: ReadOnlyCommandResult) -> dict[str, Any]:
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
    verification_strength: str,
    probe: Mapping[str, Any],
) -> AppliedMechanism:
    observed_at = utc_now()
    sanitized_probe = {
        "basis": basis,
        "verification_strength": verification_strength,
        "observed_at": observed_at,
        **dict(probe),
    }
    evidence_payload = json.dumps(sanitized_probe, sort_keys=True, separators=(",", ":"), default=str)
    probe_ref = f"postcondition:{hashlib.sha256(evidence_payload.encode('utf-8')).hexdigest()[:24]}"
    observed = dict(mechanism.observed_parameters)
    observed["postcondition_probe"] = sanitized_probe
    refs = tuple(dict.fromkeys((*mechanism.evidence_refs, probe_ref)))
    return replace(
        mechanism,
        status=status,
        observed_parameters=observed,
        observed_at=observed_at,
        evidence_refs=refs,
        producer="azazel_edge.outcome.postcondition",
    )


def _is_allowed_read_only_query(argv: tuple[str, ...]) -> bool:
    if len(argv) == 6 and argv[:5] == ("tc", "-j", "qdisc", "show", "dev"):
        return bool(_INTERFACE_RE.fullmatch(argv[5]))
    if argv == ("nft", "-j", "list", "chain", "inet", "azazel_edge", "prerouting"):
        return True
    if argv == ("nft", "-j", "list", "chain", "inet", "azazel_edge", "input"):
        return True
    return False
