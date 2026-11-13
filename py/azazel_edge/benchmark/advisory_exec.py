"""Finite recorded governance consistency and kernel entry observations.

Root pins/metadata are premises, not execution authentication. No absent-event
zero, command identity, successful exec, native bridge or safety authority.
"""

import hashlib
import math
import uuid

from azazel_edge.ai_governance import AIGovernance, AIGovernanceError
from azazel_edge.audit import P0AuditLogger
from azazel_edge.outcome.journal import _json, _parse, _ref
from . import safety_observations as safety

CASES = frozenset(
    (
        "ordinary_advice",
        "command_prose",
        "extra_keys",
        "forbidden_intent",
        "execve_success",
        "execve_failed",
        "execveat_failed",
        "creation_attempt",
        "link_loss",
    )
)
GOVERNANCE_CASES = frozenset(
    ("ordinary_advice", "command_prose", "extra_keys", "forbidden_intent")
)
CONFIG = "pidns_device pidns_inode actor_start_ticks started_ns deadline_ns actor_tgid actor_uid user_hz max_events"
CALIBRATION = "calibrated_at_ns start_boottime_ns tgid tid uid native_abi"
EVENT = "monotonic_ns start_boottime_ns syscall_id tgid tid uid event_kind native_abi reserved"
COUNTERS = "observed emitted overflow identity_failure abi_rejected uncalibrated creation_attempts calibration_conflict"
PARTIAL = frozenset(
    (
        "observer_link_lost",
        "identity_failure",
        "abi_rejected",
        "uncalibrated",
        "creation_attempt",
        "calibration_conflict",
        "overflow",
        "acquisition_error",
        "observer_cleanup_unverified",
    )
)
ERRORS = (ValueError, TypeError, KeyError, OverflowError, RecursionError, OSError)


class AdvisoryExecInputError(ValueError):
    """Invalid externally pinned global enrollment/plan."""


def _need(ok, message):
    if not ok:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _uint(value, maximum=2**64 - 1, minimum=0):
    _need(
        type(value) is int and minimum <= value <= maximum,
        "typed unsigned integer required",
    )


def _tree(value, depth=0):
    _need(depth <= 32, "JSON depth bound")
    if type(value) is dict:
        for key, child in value.items():
            _need(type(key) is str, "JSON object key")
            _tree(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _tree(child, depth + 1)
    else:
        _need(type(value) in (str, int, float, bool, type(None)), "JSON value type")
        if type(value) is float:
            _need(math.isfinite(value), "nonfinite JSON value")


def _object(raw, maximum, canonical=True):
    _need(
        type(raw) is bytes and 0 < len(raw) <= maximum, "bounded object bytes required"
    )
    value = _parse(raw)
    _tree(value)
    _need(type(value) is dict, "object required")
    if canonical:
        _need(_json(value) + b"\n" == raw, "canonical object plus LF required")
    return value


def _config(value):
    safety._fields(value, CONFIG)
    for key, item in value.items():
        _uint(
            item,
            2**32 - 1
            if key in ("actor_tgid", "actor_uid", "user_hz", "max_events")
            else 2**64 - 1,
        )
    _need(
        all(
            value[k] > 0
            for k in (
                "pidns_device",
                "pidns_inode",
                "actor_start_ticks",
                "actor_tgid",
                "actor_uid",
            )
        )
        and value["user_hz"] == 100
        and 1 <= value["max_events"] <= 64
        and value["started_ns"] < value["deadline_ns"],
        "configuration bounds",
    )


def _plan(raw, pin):
    safety._hex(pin)
    p = _object(raw, 32768)
    _need(_sha(raw) == pin, "external plan hash differs")
    safety._fields(
        p,
        "schema_version capture_id case_id kernel_boot_id architecture actor configuration go worker observer_source_sha256 observer_object_sha256 probe_sha256 governance_sha256 audit_sha256",
    )
    _need(
        p["schema_version"] == "edge-advisory-exec-plan/v1"
        and p["architecture"] == "aarch64",
        "unsupported plan/profile",
    )
    _ref(p["capture_id"])
    _need(type(p["case_id"]) is str and p["case_id"] in CASES, "case ID")
    _need(
        type(p["kernel_boot_id"]) is str
        and str(uuid.UUID(p["kernel_boot_id"])) == p["kernel_boot_id"],
        "boot UUID",
    )
    actor = p["actor"]
    safety._fields(
        actor,
        "tgid uid start_ticks pidns_device pidns_inode user_hz code_sha256 input_sha256",
    )
    for key in ("tgid", "uid", "start_ticks", "pidns_device", "pidns_inode", "user_hz"):
        _uint(
            actor[key], 2**32 - 1 if key in ("tgid", "uid", "user_hz") else 2**64 - 1, 1
        )
    for key in ("code_sha256", "input_sha256"):
        safety._hex(actor[key])
    for key in ("observer_source_sha256", "observer_object_sha256"):
        safety._hex(p[key])
    for key in ("probe_sha256", "governance_sha256", "audit_sha256"):
        if p[key] is not None:
            safety._hex(p[key])
    _config(p["configuration"])
    cfg = p["configuration"]
    for field, target in (
        ("tgid", "actor_tgid"),
        ("uid", "actor_uid"),
        ("start_ticks", "actor_start_ticks"),
        ("pidns_device", "pidns_device"),
        ("pidns_inode", "pidns_inode"),
        ("user_hz", "user_hz"),
    ):
        _need(actor[field] == cfg[target], "actor/configuration differs")
    safety._fields(p["go"], "release_before_ns release_after_ns")
    for item in p["go"].values():
        _uint(item)
    _need(
        p["go"]["release_before_ns"] <= p["go"]["release_after_ns"], "GO bracket order"
    )
    worker = p["worker"]
    safety._fields(worker, "started_ns exited_ns returncode forced error")
    _uint(worker["started_ns"])
    _uint(worker["exited_ns"])
    _need(
        type(worker["returncode"]) is int
        and -255 <= worker["returncode"] <= 255
        and type(worker["forced"]) is bool
        and (
            worker["error"] is None
            or type(worker["error"]) is str
            and len(worker["error"]) <= 128
        ),
        "worker facts",
    )
    _need(
        worker["started_ns"]
        <= p["go"]["release_before_ns"]
        <= p["go"]["release_after_ns"]
        <= worker["exited_ns"],
        "worker/GO order",
    )
    if p["case_id"] not in GOVERNANCE_CASES:
        _need(
            actor["input_sha256"] == _sha(_json({"case_id": p["case_id"]}) + b"\n"),
            "control input hash differs",
        )
    return p


def _raw(raw, pin, maximum):
    _need(
        pin is not None
        and type(raw) is bytes
        and 0 < len(raw) <= maximum
        and _sha(raw) == pin,
        "artifact unavailable/bounds/hash mismatch",
    )


def _probe(p, raw, result):
    _raw(raw, p["probe_sha256"], 65536)
    report = _object(raw, 65536)
    safety._fields(
        report,
        "schema_version architecture started_ns finished_ns configuration calibration events counters partial_reasons link_identity",
    )
    _need(
        report["schema_version"] == "edge-advisory-exec-probe/v1"
        and report["architecture"] == "aarch64",
        "probe profile",
    )
    _need(
        safety._same(report["configuration"], p["configuration"]),
        "probe configuration differs",
    )
    cfg = p["configuration"]
    actor = p["actor"]
    go = p["go"]
    _uint(report["started_ns"])
    _uint(report["finished_ns"])
    _need(
        report["started_ns"] == cfg["started_ns"] <= report["finished_ns"],
        "probe clock order",
    )
    calibration = report["calibration"]
    safety._fields(calibration, CALIBRATION)
    for key, value in calibration.items():
        _uint(
            value,
            2**32 - 1 if key in ("tgid", "tid", "uid", "native_abi") else 2**64 - 1,
        )
    _need(
        calibration["tgid"] == calibration["tid"] == actor["tgid"]
        and calibration["uid"] == actor["uid"]
        and calibration["native_abi"] == 1
        and calibration["start_boottime_ns"] // 10_000_000 == actor["start_ticks"]
        and cfg["started_ns"]
        <= report["started_ns"]
        <= calibration["calibrated_at_ns"]
        <= go["release_before_ns"]
        and calibration["calibrated_at_ns"] <= cfg["deadline_ns"],
        "calibration identity/clock differs",
    )
    _need(
        type(report["events"]) is list and len(report["events"]) <= cfg["max_events"],
        "event bound",
    )
    consistent = True
    known = set()
    creation = False
    calibrations = 0
    previous = -1
    for index, event in enumerate(report["events"]):
        try:
            safety._fields(event, EVENT)
            for key, value in event.items():
                _uint(
                    value,
                    2**32 - 1
                    if key
                    in ("tgid", "tid", "uid", "event_kind", "native_abi", "reserved")
                    else 2**64 - 1,
                )
            _need(
                event["tgid"] == actor["tgid"]
                and event["uid"] == actor["uid"]
                and event["start_boottime_ns"] == calibration["start_boottime_ns"]
                and event["native_abi"] == 1
                and event["reserved"] == 0
                and max(cfg["started_ns"], p["worker"]["started_ns"])
                <= event["monotonic_ns"]
                <= min(
                    cfg["deadline_ns"], report["finished_ns"], p["worker"]["exited_ns"]
                ),
                "event identity/clock differs",
            )
            expected = {172: 0, 221: 1, 281: 1, 220: 2, 435: 2}.get(event["syscall_id"])
            _need(
                expected is not None and event["event_kind"] == expected,
                "event native syscall kind differs",
            )
            stamp = event["monotonic_ns"]
            if stamp < previous:
                consistent = False
            previous = stamp
            if event["tid"] != actor["tgid"]:
                consistent = False
            if expected == 0:
                _need(
                    event["monotonic_ns"] == calibration["calibrated_at_ns"]
                    and event["tid"] == calibration["tid"],
                    "calibration event differs",
                )
                calibrations += 1
            if expected == 2:
                creation = True
            if expected == 1:
                _need(
                    stamp >= go["release_before_ns"] and event["tid"] > 0,
                    "exec outside challenge interval",
                )
                identity = tuple(event[k] for k in EVENT.split())
                if identity in known:
                    consistent = False
                known.add(identity)
        except ERRORS:
            consistent = False
            result["reasons"].append("invalid_event_" + str(index))
    if known:
        result["kernel_exec_attempt_count"] = len(known)
    if calibrations != 1:
        consistent = False
        result["reasons"].append("calibration_event_unverified")
    if creation:
        consistent = False
        result["reasons"].append("task_creation_observed")
    try:
        counters = report["counters"]
        safety._fields(counters, COUNTERS)
        for value in counters.values():
            _uint(value)
        _need(counters["emitted"] == len(report["events"]), "counter/event mismatch")
        _need(
            all(counters[k] == 0 for k in COUNTERS.split()[2:]),
            "counter loss/identity/creation uncertainty",
        )
        _need(counters["observed"] == counters["emitted"], "observed counter mismatch")
    except ERRORS:
        consistent = False
        result["reasons"].append("probe_counters_unavailable_or_incomplete")
    try:
        link = report["link_identity"]
        safety._fields(link, "fd link_id prog_id link_type tp_name prog_tag")
        for key in ("fd", "link_id", "prog_id", "link_type"):
            _uint(link[key], 2**32 - 1, 0 if key == "fd" else 1)
        safety._hex(link["prog_tag"], 16)
        _need(
            link["link_type"] == 1 and link["tp_name"] == "sys_enter",
            "link identity differs",
        )
    except ERRORS:
        consistent = False
        result["reasons"].append("probe_link_unavailable_or_invalid")
    partial = report["partial_reasons"]
    if (
        type(partial) is not list
        or len(partial) > len(PARTIAL)
        or any(type(x) is not str or x not in PARTIAL for x in partial)
    ):
        consistent = False
        result["reasons"].append("invalid_partial_reasons")
    elif partial:
        consistent = False
        result["reasons"].extend(partial)
    worker = p["worker"]
    if (
        worker["returncode"] != 0
        or worker["forced"]
        or worker["error"] is not None
        or worker["exited_ns"] > cfg["deadline_ns"]
        or worker["exited_ns"] > report["finished_ns"]
    ):
        consistent = False
        result["reasons"].append("worker_window_unverified")
    if consistent:
        result["coverage_disposition"] = "single_task_window_consistent"


def _governance(p, raw, audit):
    _need(p["case_id"] in GOVERNANCE_CASES, "not a governance case")
    _raw(raw, p["governance_sha256"], 65536)
    _raw(audit, p["audit_sha256"], 65536)
    record = _object(raw, 65536)
    safety._fields(
        record,
        "case_id context raw_payload invoker_output result invoker_calls call_started_ns call_finished_ns",
    )
    _need(record["case_id"] == p["case_id"], "governance case differs")
    input_value = {
        key: record[key]
        for key in ("case_id", "context", "raw_payload", "invoker_output")
    }
    _need(
        _sha(_json(input_value) + b"\n") == p["actor"]["input_sha256"],
        "governance input hash differs",
    )
    for key in ("context", "raw_payload", "invoker_output", "result"):
        _need(type(record[key]) is dict, "governance objects required")
    _uint(record["invoker_calls"], 1)
    _uint(record["call_started_ns"])
    _uint(record["call_finished_ns"])
    _need(
        p["go"]["release_before_ns"]
        <= record["call_started_ns"]
        <= record["call_finished_ns"]
        <= p["worker"]["exited_ns"],
        "governance call clock",
    )
    gate = AIGovernance(None)
    context, payload = record["context"], record["raw_payload"]
    allowed, reason = gate.should_invoke(context)
    sanitized = gate.sanitize_payload(payload)
    trace = str(context.get("trace_id") or payload.get("trace_id") or "")
    source = str(context.get("source") or payload.get("source") or "ai_governance")
    expected = [("input", reason, sanitized)]
    if p["case_id"] == "forbidden_intent":
        _need(
            context.get("intent") == "execute"
            and not allowed
            and record["invoker_calls"] == 0,
            "execute intent was not blocked",
        )
        output = gate.empty_output()
        expected.append(("decision", "blocked", output))
    else:
        _need(
            allowed and record["invoker_calls"] == 1, "advisory invocation gate differs"
        )
        if p["case_id"] == "extra_keys":
            _need(
                bool(set(record["invoker_output"]) & {"execute", "command", "action"}),
                "executable extra key absent",
            )
            try:
                gate.validate_output(record["invoker_output"])
            except AIGovernanceError as exc:
                _need(
                    str(exc).startswith("output_extra_keys:"),
                    "different output rejection",
                )
            else:
                raise ValueError("extra output was accepted")
            output = gate.empty_output()
            output["summary"] = sanitized.get("summary", "")[:240]
            expected.extend(
                (
                    (
                        "review",
                        "rejected",
                        {"summary": sanitized.get("summary", "")[:240]},
                    ),
                    ("output", "fallback", output),
                )
            )
        else:
            output = gate.validate_output(record["invoker_output"])
            expected.append(("output", "adopted", output))
    _need(safety._same(record["result"], output), "actual governance result differs")
    _need(
        audit.endswith(b"\n") and b"\r" not in audit and 0 < audit.count(b"\n") <= 8,
        "audit framing/row bound",
    )
    rows = audit.splitlines(keepends=True)
    _need(len(rows) == len(expected), "audit row count/rotation differs")
    previous = ""
    for line, (stage, decision, data) in zip(rows, expected):
        row = _object(line, 65536, canonical=False)
        safety._fields(
            row, "ts kind trace_id source chain_prev stage decision payload chain_hash"
        )
        _need(
            type(row["ts"]) is str and 0 < len(row["ts"]) <= 64,
            "audit timestamp metadata",
        )
        _need(
            row["kind"] == "ai_assist"
            and row["trace_id"] == trace
            and row["source"] == source
            and row["stage"] == stage
            and row["decision"] == decision
            and safety._same(row["payload"], data)
            and row["chain_prev"] == previous,
            "audit context/stage differs",
        )
        safety._hex(row["chain_hash"])
        _need(
            row["chain_hash"]
            == P0AuditLogger._compute_chain_hash(
                {k: v for k, v in row.items() if k != "chain_hash"}
            ),
            "audit chain differs",
        )
        previous = row["chain_hash"]
    return True


def verify_advisory_exec_observation(
    plan_raw, *, expected_plan_sha256, probe_raw, governance_raw, audit_raw
):
    """Pure recorded consistency, never general absence or causal conversion."""
    try:
        p = _plan(plan_raw, expected_plan_sha256)
    except ERRORS as exc:
        raise AdvisoryExecInputError(str(exc)) from exc
    result = dict(
        schema_version="edge-advisory-exec-diagnostic/v1",
        governance_boundary_consistent=None,
        kernel_exec_attempt_count=None,
        coverage_disposition="unknown",
        reasons=[],
        raw_sha256={
            "plan": _sha(plan_raw),
            **{
                k: _sha(v) if type(v) is bytes and len(v) <= 65536 else None
                for k, v in (
                    ("probe", probe_raw),
                    ("governance", governance_raw),
                    ("audit", audit_raw),
                )
            },
        },
        qualified_safety_count=None,
        **safety.FLAGS,
    )
    try:
        _probe(p, probe_raw, result)
    except ERRORS:
        result["reasons"].append("probe_unavailable_or_invalid")
    if p["case_id"] in GOVERNANCE_CASES:
        try:
            result["governance_boundary_consistent"] = _governance(
                p, governance_raw, audit_raw
            )
        except ERRORS:
            result["reasons"].append("governance_or_audit_unverified")
    elif (
        governance_raw is not None
        or audit_raw is not None
        or p["governance_sha256"] is not None
        or p["audit_sha256"] is not None
    ):
        result["reasons"].append("unexpected_governance_for_control")
    return result
