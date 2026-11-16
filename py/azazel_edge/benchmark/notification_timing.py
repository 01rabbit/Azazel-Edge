"""Pure bounded P0 lab timing diagnostics, never historical or safety attribution."""

from copy import deepcopy
import hashlib
import io
import json
import math
import re

from ..audit.logger import P0AuditLogger
from ..notify.core_decisions import core_decision_payload, core_event_key

SCHEMA = "edge-notification-timing/v1"
MAX_ROWS, MAX_BYTES, MAX_REFERENCE_BYTES = 8192, 16777216, 67108864
PROTOCOL_SHA256 = "8b236c81d46bd4dd9a1b8e7a38030cd3f6b116fc65b54111d76cc0ecac8174e5"
PHASES = (
    "legacy_interval",
    "fixture_input",
    "submit",
    "payload",
    "logging_call",
    "lock_acquire",
    "lock_hold",
    "queue_put",
    "writer_record",
    "audit_save",
    "audit_fsync",
    "statistics_lock_acquire",
    "statistics_lock_hold",
    "blocking_control",
    "scheduler_control",
)
CASES = (
    "legacy_original",
    "legacy_instrumented",
    "fixture_delay",
    "logging_delay",
    "recorder_lock_delay",
    "unrelated_lock_negative",
    "writer_fsync_hold",
    "inline_save_negative",
    "blocking_wait_counterexample",
    "scheduler_contention",
    "trace_loss",
)
META = {
    "run_id",
    "case_id",
    "protocol_sha256",
    "source_inventory_sha256",
    "fixture_sha256",
    "interpreter_sha256",
}
IDENTITY = {"pid", "process_start_ticks", "boot_id"}
THREAD = {"native_tid", "task_start_ticks"}
CLOCKS = {
    "start_ns",
    "end_ns",
    "thread_cpu_start_ns",
    "thread_cpu_end_ns",
    "process_cpu_start_ns",
    "process_cpu_end_ns",
}
INTENT = {"span_id", "parent_id", "phase", "object_id", "event_index"} | THREAD
SNAPSHOT = (
    {
        "read_begin_ns",
        "read_end_ns",
        "schedstats_raw",
        "schedstat_raw",
        "runtime_ns",
        "runqueue_wait_ns",
        "timeslices",
        "error",
    }
    | IDENTITY
    | THREAD
)
ERRORS = (
    ValueError,
    TypeError,
    KeyError,
    IndexError,
    AttributeError,
    OverflowError,
    RecursionError,
    UnicodeError,
)
FLAGS = dict(
    comparison_qualified=False,
    whole_measurement_qualified=False,
    production_admission=False,
    resume_authorized=False,
    qualified_safety_count=None,
)


def _wire(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def _same(left, right):
    return _wire(left) == _wire(right)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _uint(value):
    return type(value) is int and 0 <= value < 2**64


def _hash(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


def _label(value):
    return (
        type(value) is str
        and re.fullmatch("[A-Za-z0-9_.:/-]{1,128}", value) is not None
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate_JSON_field")
        result[key] = value
    return result


def _depth(value, level=0):
    _need(level <= 16, "depth_capacity")
    if type(value) is dict:
        for child in value.values():
            _depth(child, level + 1)
    elif type(value) is list:
        for child in value:
            _depth(child, level + 1)


def _bounded_lines(raw, *, maximum=MAX_BYTES):
    """Never materialize more than one overflow row or byte beyond the caps."""
    stream = io.BytesIO(raw[: maximum + 1])
    used = 0
    for _ in range(MAX_ROWS + 1):
        if used >= maximum + 1:
            return
        line = stream.readline(min(MAX_BYTES + 1, maximum + 1 - used))
        if not line:
            return
        used += len(line)
        yield line


def _parse(raw, maximum, *, canonical=True):
    _need(
        type(raw) is bytes and 0 < len(raw) <= maximum, "missing_or_overbound_original"
    )
    value = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_JSON")),
    )
    _depth(value)
    # Reencoding also rejects overflow-to-inf numeric literals.
    encoded = _wire(value)
    _need(not canonical or encoded == raw, "noncanonical_JSON")
    return value


def _domain(value):
    _need(
        type(value) is dict
        and set(value)
        == {
            "time_namespace_device",
            "time_namespace_inode",
            "timens_offsets",
            "established",
        },
        "clock_domain_fields",
    )
    _need(type(value["established"]) is bool, "clock_domain_established_type")
    for key in ("time_namespace_device", "time_namespace_inode"):
        _need(value[key] is None or _uint(value[key]), "clock_domain_identity_type")
    offsets = value["timens_offsets"]
    _need(
        offsets is None or type(offsets) is list and len(offsets) <= 2,
        "clock_domain_offsets",
    )
    if offsets is not None:
        _need(
            all(
                type(row) is dict
                and set(row) == {"clock", "seconds", "nanoseconds"}
                and row["clock"] in ("monotonic", "boottime")
                and type(row["seconds"]) is int
                and type(row["nanoseconds"]) is int
                for row in offsets
            ),
            "clock_domain_offset_types",
        )
    if value["established"]:
        _need(
            all(
                value[k] is not None
                for k in ("time_namespace_device", "time_namespace_inode")
            )
            and offsets is not None
            and {r["clock"] for r in offsets} == {"monotonic", "boottime"}
            and all(r["seconds"] == r["nanoseconds"] == 0 for r in offsets),
            "clock_domain_unestablished",
        )


def _identity(value):
    for key in ("pid", "process_start_ticks", "native_tid", "task_start_ticks"):
        if key in value:
            _need(value[key] is None or _uint(value[key]), "identity_uint_type")
    _need(
        value.get("boot_id") is None
        or type(value["boot_id"]) is str
        and re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        ),
        "boot_identity_type",
    )


def _header(data, expected):
    _need(
        type(data) is dict
        and set(data) == META | IDENTITY | {"clock_domain", "resolutions", "limits"},
        "header_fields",
    )
    _need(_label(data["run_id"]) and data["case_id"] in CASES, "run_or_case")
    _need(
        all(_hash(data[key]) for key in META - {"run_id", "case_id"}),
        "header_hash_types",
    )
    _need(data["protocol_sha256"] == PROTOCOL_SHA256, "frozen_protocol_pin")
    _identity(data)
    _domain(data["clock_domain"])
    resolutions = data["resolutions"]
    _need(
        type(resolutions) is dict
        and set(resolutions) == {"monotonic", "thread_time", "process_time"}
        and all(
            type(v) in (int, float) and math.isfinite(v) and v > 0
            for v in resolutions.values()
        ),
        "resolution_types",
    )
    limits = data["limits"]
    _need(
        type(limits) is dict
        and set(limits)
        == {"max_rows", "max_bytes", "max_depth", "max_events", "max_threads"}
        and all(_uint(v) for v in limits.values())
        and 1 <= limits["max_rows"] <= MAX_ROWS
        and 1 <= limits["max_bytes"] <= MAX_BYTES
        and limits["max_depth"] == 16
        and limits["max_events"] == 120
        and limits["max_threads"] == 16,
        "header_limits",
    )
    _need(
        type(expected) is dict and set(expected) == META | IDENTITY | {"clock_domain"},
        "external_header_pins",
    )
    _need(
        all(_same(data[key], value) for key, value in expected.items()),
        "external_header_pin_mismatch",
    )


def _originals(event_raw, original_raw, expected):
    _need(
        type(event_raw) is bytes and 0 < len(event_raw) <= MAX_BYTES,
        "event_index_byte_capacity",
    )
    _need(
        type(original_raw) is bytes and 0 < len(original_raw) <= MAX_REFERENCE_BYTES,
        "original_result_byte_capacity",
    )
    _need(
        _hash(expected["event_index_sha256"])
        and type(event_raw) is bytes
        and _sha(event_raw) == expected["event_index_sha256"],
        "event_index_external_pin",
    )
    _need(
        _hash(expected["original_result_sha256"])
        and type(original_raw) is bytes
        and _sha(original_raw) == expected["original_result_sha256"],
        "original_result_external_pin",
    )
    envelope = _parse(event_raw, MAX_BYTES)
    _need(
        type(envelope) is dict
        and set(envelope) == {"schema_version", "events"}
        and envelope["schema_version"] == "edge-notification-event-index/v1"
        and type(envelope["events"]) is list
        and len(envelope["events"]) <= 120,
        "event_index_envelope",
    )
    events, keys = {}, {}
    for row in envelope["events"]:
        _need(
            type(row) is dict
            and set(row)
            == {"index", "event", "event_sha256", "core_event_key", "trace_id"},
            "event_index_fields",
        )
        index = row["index"]
        _need(
            type(index) is int and 0 <= index < 120 and index not in events,
            "event_index_identity",
        )
        _need(
            type(row["event"]) is dict
            and _hash(row["event_sha256"])
            and row["event_sha256"] == _sha(_wire(row["event"])),
            "event_bytes_hash",
        )
        built = core_decision_payload(row["event"])
        _need(
            built is not None
            and _hash(row["core_event_key"])
            and row["core_event_key"] == core_event_key(row["event"])
            and row["trace_id"] == built[0],
            "event_key_or_trace_binding",
        )
        events[index] = row
        keys.setdefault(row["core_event_key"], []).append(index)
    original = _parse(original_raw, MAX_REFERENCE_BYTES)
    _need(
        type(original) is dict
        and set(original)
        == {
            "schema_version",
            "case_id",
            "assigned_events",
            "completed_submissions",
            "metrics",
            "audit_raw",
            "queue_raw",
            "control",
            "collection_errors",
        }
        and original["schema_version"] == "edge-notification-original-result/v1",
        "original_result_envelope",
    )
    _need(
        type(original["assigned_events"]) is int
        and 0 <= original["assigned_events"] <= 120
        and type(original["completed_submissions"]) is int
        and 0 <= original["completed_submissions"] <= original["assigned_events"],
        "original_submission_counts",
    )
    _need(
        original["metrics"] is None or type(original["metrics"]) is dict,
        "original_metrics_type",
    )
    _need(
        type(original["control"]) is dict
        and type(original["collection_errors"]) in (dict, list),
        "original_control_errors_type",
    )
    structural = {}
    for key in ("audit_raw", "queue_raw"):
        raw = original[key]
        _need(raw is None or type(raw) is str, "original_stream_type")
        if raw is None:
            structural[key] = None
            continue
        _need(not raw or raw.endswith("\n"), "original_stream_partial_line")
        encoded = raw.encode()
        bounded = list(_bounded_lines(encoded, maximum=MAX_REFERENCE_BYTES))
        _need(
            len(bounded) <= MAX_ROWS and sum(map(len, bounded)) == len(encoded),
            "original_stream_row_bound",
        )
        lines = [line.decode().rstrip("\n") for line in bounded]
        rows = [_parse(line.encode(), MAX_BYTES, canonical=False) for line in lines]
        _need(all(type(row) is dict for row in rows), "original_stream_row_type")
        structural[key] = dict(rows=len(rows), original_rows=rows)
        if key == "audit_raw":
            structural[key]["chain"] = P0AuditLogger._verify_lines(lines, "")
    return events, keys, original, structural


def _scheduler(before, after, header, thread, span):
    reasons = []
    for snapshot in (before, after):
        _need(
            type(snapshot) is dict and set(snapshot) == SNAPSHOT,
            "scheduler_snapshot_fields",
        )
        _identity(snapshot)
        _need(
            all(
                snapshot[key] is None or _uint(snapshot[key])
                for key in (
                    "read_begin_ns",
                    "read_end_ns",
                    "runtime_ns",
                    "runqueue_wait_ns",
                    "timeslices",
                )
            ),
            "scheduler_counter_uint",
        )
        _need(
            all(
                snapshot[key] is None
                or type(snapshot[key]) is str
                and len(snapshot[key]) <= 256
                for key in ("schedstats_raw", "schedstat_raw", "error")
            ),
            "scheduler_raw_types",
        )
        if snapshot["error"] is not None:
            reasons.append("scheduler_probe_error")
        if any(
            snapshot[key] is None or not _same(snapshot[key], header[key])
            for key in IDENTITY
        ):
            reasons.append("scheduler_process_identity_unbound")
        if any(
            snapshot[key] is None or not _same(snapshot[key], thread[key])
            for key in THREAD
        ):
            reasons.append("scheduler_task_identity_unbound")
        if (
            snapshot["schedstats_raw"] is None
            or snapshot["schedstats_raw"].strip() != "1"
        ):
            reasons.append("schedstats_enablement_unestablished_or_disabled")
        raw = snapshot["schedstat_raw"]
        fields = raw.split() if type(raw) is str else []
        if (
            len(fields) != 3
            or any(not f.isascii() or not f.isdecimal() for f in fields)
            or not all(
                _same(snapshot[key], int(value))
                for key, value in zip(
                    ("runtime_ns", "runqueue_wait_ns", "timeslices"), fields
                )
            )
        ):
            reasons.append("scheduler_raw_counter_malformed_or_inconsistent")
    brackets = [
        before["read_begin_ns"],
        before["read_end_ns"],
        span["start_ns"],
        span["end_ns"],
        after["read_begin_ns"],
        after["read_end_ns"],
    ]
    if any(value is None for value in brackets) or brackets != sorted(brackets):
        reasons.append("scheduler_read_brackets_invalid")
    if not header["clock_domain"]["established"]:
        reasons.append("clock_domain_unestablished")
    deltas = {}
    for key in ("runtime_ns", "runqueue_wait_ns", "timeslices"):
        a, b = before[key], after[key]
        if a is None or b is None or b < a:
            reasons.append("scheduler_counter_missing_or_regressing")
        else:
            deltas[key] = b - a
    return dict(
        qualified_runqueue_wait_ns=deltas.get("runqueue_wait_ns")
        if not reasons
        else None,
        bracket_runtime_ns=deltas.get("runtime_ns") if not reasons else None,
        bracket_timeslices=deltas.get("timeslices") if not reasons else None,
        scope="enclosing_probe_bracket_instrumented_thread_not_exclusive_call_cause",
        reasons=sorted(set(reasons)),
    )


def analyze_notification_timing(
    trace_raw, *, expected, event_index_raw, original_result_raw
):
    """Keep valid completed prefixes, independent original material and explicit unknowns."""
    result = dict(
        schema_version="edge-notification-timing-analysis/v1",
        status="withheld",
        historical_cause="UNKNOWN",
        historical_observed_ns=123536682,
        raw_sha256=_sha(trace_raw)
        if type(trace_raw) is bytes and len(trace_raw) <= MAX_BYTES
        else None,
        header=None,
        valid_prefix_rows=0,
        completed_spans=[],
        incomplete_intents=[],
        normal_return_confirmed=False,
        original_result=None,
        original_structural_counts=None,
        event_index_valid=False,
        reasons=[],
        instrumentation_overhead="unallocated_probe_recording_lock_write_and_flush",
        aggregation="inclusive_nonadditive_no_overlapping_sum",
        wall_minus_cpu_cause="UNCLASSIFIED",
        logging_internal_locks="unobserved",
        queue_internal_locks="unobserved",
        **FLAGS,
    )
    reasons = result["reasons"]
    events, keys, original = {}, {}, None
    originals_valid = False
    try:
        _need(
            type(expected) is dict
            and set(expected)
            == {"header", "event_index_sha256", "original_result_sha256"},
            "external_pin_envelope",
        )
        events, keys, original, structural = _originals(
            event_index_raw, original_result_raw, expected
        )
        _need(
            original["case_id"] == expected["header"]["case_id"],
            "original_case_binding",
        )
        result.update(
            original_result=deepcopy(original),
            original_structural_counts=structural,
            event_index_valid=True,
        )
        _need(not original["collection_errors"], "original_collection_incomplete")
        _need(
            all(structural[name] is not None for name in ("audit_raw", "queue_raw")),
            "original_stream_missing",
        )
        _need(
            structural["audit_raw"]["chain"]["ok"] is True,
            "original_audit_chain_invalid",
        )
        originals_valid = True
    except ERRORS as exc:
        reasons.append("originals_invalid:" + str(exc))
    if type(trace_raw) is not bytes or not trace_raw:
        reasons.append("missing_trace")
        return result
    header = None
    previous = "0" * 64
    threads, active, stacks, completed, trace_events = {}, {}, {}, {}, {}
    consumed, ended = 0, False
    if len(trace_raw) > MAX_BYTES:
        reasons.append("trace_byte_capacity_exceeded")
    for sequence, line in enumerate(_bounded_lines(trace_raw), 1):
        try:
            _need(
                sequence <= MAX_ROWS and consumed + len(line) <= MAX_BYTES,
                "trace_row_or_byte_capacity",
            )
            _need(not ended, "row_after_end")
            row = _parse(line, MAX_BYTES)
            _need(
                type(row) is dict
                and set(row) == {"schema_version", "seq", "prev", "kind", "data"}
                and row["schema_version"] == SCHEMA
                and type(row["seq"]) is int
                and row["seq"] == sequence
                and row["prev"] == previous,
                "row_chain_or_envelope",
            )
            kind, data = row["kind"], row["data"]
            _need(type(data) is dict, "row_data_type")
            if sequence == 1:
                _need(kind == "header", "missing_header")
                _header(data, expected["header"])
                header = result["header"] = deepcopy(data)
            else:
                _need(header is not None, "missing_valid_header")
                limits = header["limits"]
                _need(
                    sequence <= limits["max_rows"]
                    and consumed + len(line) <= limits["max_bytes"],
                    "declared_trace_capacity",
                )
                if kind == "thread":
                    _need(
                        set(data) == IDENTITY | THREAD | {"thread_name"}
                        and len(threads) < 16,
                        "thread_fields_or_capacity",
                    )
                    _identity(data)
                    _need(
                        type(data["thread_name"]) is str
                        and 0 < len(data["thread_name"]) <= 128,
                        "thread_name",
                    )
                    _need(
                        all(_same(data[key], header[key]) for key in IDENTITY),
                        "thread_process_identity_differs",
                    )
                    key = (data["native_tid"], data["task_start_ticks"])
                    _need(
                        _uint(data["native_tid"])
                        and key not in threads
                        and not any(tid == key[0] for tid, _ in threads),
                        "reused_tid_or_thread_identity",
                    )
                    threads[key] = data
                    stacks[key] = []
                elif kind == "event":
                    _need(
                        set(data)
                        == {"index", "event_sha256", "core_event_key", "trace_id"}
                        and type(data["index"]) is int
                        and 0 <= data["index"] < 120
                        and data["index"] not in trace_events
                        and _hash(data["event_sha256"])
                        and _hash(data["core_event_key"])
                        and _label(data["trace_id"]),
                        "event_row_fields",
                    )
                    if originals_valid:
                        _need(
                            data["index"] in events
                            and _same(
                                data,
                                {
                                    key: value
                                    for key, value in events[data["index"]].items()
                                    if key != "event"
                                },
                            ),
                            "event_row_original_binding",
                        )
                    trace_events[data["index"]] = data
                elif kind in ("intent", "span"):
                    expected_fields = (
                        INTENT
                        if kind == "intent"
                        else INTENT
                        | CLOCKS
                        | {"outcome", "scheduler_before", "scheduler_after"}
                    )
                    _need(set(data) == expected_fields, "intent_or_span_fields")
                    key = (data["native_tid"], data["task_start_ticks"])
                    _need(
                        key in threads
                        and _uint(data["span_id"])
                        and data["span_id"] > 0
                        and data["phase"] in PHASES
                        and (data["object_id"] is None or _label(data["object_id"]))
                        and (
                            data["event_index"] is None
                            or type(data["event_index"]) is int
                            and 0 <= data["event_index"] < 120
                        ),
                        "span_identity_phase_or_object",
                    )
                    span_id = data["span_id"]
                    if kind == "intent":
                        _need(
                            span_id not in active
                            and span_id not in completed
                            and _same(
                                data["parent_id"],
                                stacks[key][-1] if stacks[key] else None,
                            ),
                            "invalid_parent_or_duplicate_intent",
                        )
                        active[span_id] = deepcopy(data)
                        stacks[key].append(span_id)
                    else:
                        _need(
                            span_id in active
                            and stacks[key]
                            and stacks[key][-1] == span_id
                            and all(
                                _same(data[name], active[span_id][name])
                                for name in INTENT
                            ),
                            "span_without_matching_intent_or_cross_thread",
                        )
                        _need(
                            all(_uint(data[name]) for name in CLOCKS)
                            and data["outcome"] in ("returned", "raised"),
                            "span_clock_or_outcome_types",
                        )
                        wall = data["end_ns"] - data["start_ns"]
                        cpu = data["thread_cpu_end_ns"] - data["thread_cpu_start_ns"]
                        process_cpu = (
                            data["process_cpu_end_ns"] - data["process_cpu_start_ns"]
                        )
                        _need(
                            wall >= 0 and cpu >= 0 and process_cpu >= 0,
                            "regressing_span_clock",
                        )
                        for prior in completed.values():
                            if (prior["native_tid"], prior["task_start_ticks"]) != key:
                                continue
                            if prior["parent_id"] == span_id:
                                _need(
                                    data["start_ns"]
                                    <= prior["start_ns"]
                                    <= prior["end_ns"]
                                    <= data["end_ns"],
                                    "child_clock_outside_parent",
                                )
                                for clock in ("thread_cpu", "process_cpu"):
                                    _need(
                                        data[clock + "_start_ns"]
                                        <= prior[clock + "_start_ns"]
                                        <= prior[clock + "_end_ns"]
                                        <= data[clock + "_end_ns"],
                                        "child_" + clock + "_outside_parent",
                                    )
                            elif prior["parent_id"] == data["parent_id"]:
                                _need(
                                    prior["end_ns"] <= data["start_ns"],
                                    "overlapping_sibling_span_clocks",
                                )
                                for clock in ("thread_cpu", "process_cpu"):
                                    _need(
                                        prior[clock + "_end_ns"]
                                        <= data[clock + "_start_ns"],
                                        "overlapping_sibling_" + clock,
                                    )
                        scheduler = _scheduler(
                            data["scheduler_before"],
                            data["scheduler_after"],
                            header,
                            threads[key],
                            data,
                        )
                        correlation = "unavailable"
                        index = data["event_index"]
                        if originals_valid and index in trace_events:
                            binding = trace_events[index]
                            if len(keys.get(binding["core_event_key"], [])) == 1:
                                correlation = "exact_original_event_key"
                        thread_bound = all(
                            data[name] is not None and _same(snapshot[name], data[name])
                            for snapshot in (
                                data["scheduler_before"],
                                data["scheduler_after"],
                            )
                            for name in THREAD
                        )
                        process_bound = all(
                            header[name] is not None
                            and _same(snapshot[name], header[name])
                            for snapshot in (
                                data["scheduler_before"],
                                data["scheduler_after"],
                            )
                            for name in IDENTITY
                        )
                        fact = dict(
                            deepcopy(data),
                            elapsed_ns=wall,
                            thread_cpu_ns=cpu
                            if thread_bound and process_bound
                            else None,
                            process_cpu_ns=process_cpu if process_bound else None,
                            wall_minus_thread_cpu_ns=wall - cpu
                            if wall >= cpu and thread_bound and process_bound
                            else None,
                            residual_cause="UNCLASSIFIED",
                            scheduler=scheduler,
                            event_correlation=correlation,
                            inclusive_nonadditive=True,
                        )
                        completed[span_id] = fact
                        result["completed_spans"].append(fact)
                        del active[span_id]
                        stacks[key].pop()
                elif kind == "end":
                    _need(
                        _same(
                            data,
                            dict(normal_return=True, active_spans=0, incomplete=False),
                        )
                        and not active,
                        "end_with_incomplete_intents_or_invalid_flags",
                    )
                    ended = True
                else:
                    raise ValueError("unknown_row_kind")
            consumed += len(line)
            previous = _sha(line)
            result["valid_prefix_rows"] = sequence
        except ERRORS as exc:
            reasons.append("trace_invalid:" + str(exc))
            break
    # Fixture spans can complete before the original payload supplies its key.
    # Resolve the explicitly indexed binding only after validating the prefix;
    # this is an exact-key join, never a temporal join.
    for fact in result["completed_spans"]:
        index = fact["event_index"]
        binding = trace_events.get(index)
        fact["event_correlation"] = (
            "exact_original_event_key"
            if originals_valid
            and binding is not None
            and len(keys.get(binding["core_event_key"], [])) == 1
            else "unavailable"
        )
    result["incomplete_intents"] = list(active.values())
    if not ended:
        reasons.append("missing_normal_end")
    if active:
        reasons.append("intent_without_completion")
    result["normal_return_confirmed"] = (
        ended and len(trace_raw) <= MAX_BYTES and consumed == len(trace_raw)
    )
    result["status"] = (
        "complete_descriptive_trace"
        if result["normal_return_confirmed"] and originals_valid and not reasons
        else "partial_prefix"
        if result["completed_spans"]
        else "withheld"
    )
    return result
