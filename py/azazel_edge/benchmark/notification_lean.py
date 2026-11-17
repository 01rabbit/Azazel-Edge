"""Pure replay of deferred logical-thread lab receipts; no timing admission."""

from copy import deepcopy
import math

from .notification_timing import (
    META,
    IDENTITY,
    PHASES,
    SUPPLEMENT_SHA256,
    FLAGS,
    _same,
    _sha,
    _need,
    _uint,
    _hash,
    _label,
    _parse,
    _bounded_lines,
    _domain,
    _identity,
    _originals,
    MAX_BYTES,
    MAX_ROWS,
)

SCHEMA = "edge-notification-lean/v1"
STUDY_PROTOCOL_SHA256 = (
    "5617214899eed681c435330cd456b149f214d01bc9b067be30724f6e23dfdcb8"
)
SPAN_FIELDS = {
    "span_id",
    "parent_id",
    "logical_thread_token",
    "phase",
    "object_id",
    "event_index",
    "start_ns",
    "thread_cpu_start_ns",
    "process_cpu_start_ns",
    "native_tid_start",
    "end_ns",
    "thread_cpu_end_ns",
    "process_cpu_end_ns",
    "native_tid_end",
    "outcome",
    "complete",
    "error",
}
CLOCK_PAIRS = (
    ("start_ns", "end_ns"),
    ("thread_cpu_start_ns", "thread_cpu_end_ns"),
    ("process_cpu_start_ns", "process_cpu_end_ns"),
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


def _header(data, expected, pin):
    _need(
        type(data) is dict
        and set(data)
        == META
        | IDENTITY
        | {
            "clock_domain",
            "study_protocol_sha256",
            "capture_profile",
            "resolutions",
            "limits",
        },
        "lean_header_fields",
    )
    _need(
        pin == STUDY_PROTOCOL_SHA256
        and data["study_protocol_sha256"] == pin
        and data["capture_profile"] == SCHEMA,
        "lean_study_or_profile_pin",
    )
    _need(
        type(expected) is dict and set(expected) == META | IDENTITY | {"clock_domain"},
        "external_header_pins",
    )
    _need(
        all(_same(data[key], value) for key, value in expected.items()),
        "external_header_pin_mismatch",
    )
    _need(
        _label(data["run_id"])
        and data["case_id"] == "historical_slow_fsync_instrumented"
        and data["protocol_sha256"] == SUPPLEMENT_SHA256
        and all(_hash(data[k]) for k in META - {"run_id", "case_id"}),
        "underlying_fixture_pins",
    )
    _identity(data)
    _domain(data["clock_domain"])
    limits = data["limits"]
    _need(
        type(limits) is dict
        and set(limits)
        == {
            "max_rows",
            "max_bytes",
            "max_threads",
            "max_events",
            "max_depth",
            "slots_per_thread",
        }
        and all(_uint(value) for value in limits.values())
        and 1 <= limits["max_rows"] <= MAX_ROWS
        and 1 <= limits["max_bytes"] <= MAX_BYTES
        and limits["max_threads"] == 16
        and limits["max_events"] == 120
        and limits["max_depth"] == 16
        and limits["slots_per_thread"] == 480,
        "lean_limits",
    )
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


def analyze_notification_lean(
    trace_raw,
    *,
    expected,
    event_index_raw,
    original_result_raw,
    study_protocol_sha256=STUDY_PROTOCOL_SHA256,
):
    """No I/O, clocks, v1 conversion, kernel-thread claim or missing-data fill."""
    result = dict(
        schema_version="edge-notification-lean-analysis/v1",
        capture_profile=SCHEMA,
        historical_cause="UNKNOWN",
        status="withheld",
        normal_return_confirmed=False,
        header=None,
        raw_sha256=_sha(trace_raw)
        if type(trace_raw) is bytes and len(trace_raw) <= MAX_BYTES
        else None,
        valid_prefix_rows=0,
        completed_spans=[],
        incomplete_intents=[],
        event_index_valid=False,
        original_result=None,
        original_structural_counts=None,
        reasons=[],
        finalization=None,
        scheduler_per_phase=None,
        kernel_thread_identity="UNESTABLISHED_logical_python_thread_only",
        wall_minus_cpu_cause="UNCLASSIFIED",
        aggregation="inclusive_nonadditive",
        instrumentation_overhead="clocks_GIL_scalar_buffers_and_deferred_flush_not_zero_overhead",
        **FLAGS,
    )
    reasons = result["reasons"]
    originals_valid = False
    events, keys = {}, {}
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
        result.update(
            original_result=deepcopy(original),
            original_structural_counts=structural,
            event_index_valid=True,
        )
        _need(
            original["case_id"] == expected["header"]["case_id"],
            "original_case_binding",
        )
        _need(
            not original["collection_errors"]
            and all(structural[k] is not None for k in ("audit_raw", "queue_raw")),
            "original_collection_incomplete",
        )
        _need(
            structural["audit_raw"]["chain"]["ok"] is True,
            "original_audit_chain_invalid",
        )
        originals_valid = True
        control = original["control"]
        begin, end = (
            control.get("recording_finish_begin_ns"),
            control.get("recording_finish_end_ns"),
        )
        result["finalization"] = dict(
            start_ns=begin,
            end_ns=end,
            elapsed_ns=end - begin
            if _uint(begin) and _uint(end) and end >= begin
            else None,
            scope="external_actual_deferred_serialization_close_bracket_not_workload_time",
        )
    except ERRORS as exc:
        reasons.append("originals_invalid:" + str(exc))
    if type(trace_raw) is not bytes or not trace_raw:
        reasons.append("missing_trace")
        return result
    if len(trace_raw) > MAX_BYTES:
        reasons.append("trace_byte_capacity_exceeded")
    header, ended = None, False
    consumed, previous = 0, "0" * 64
    threads, records, counts, bindings = {}, {}, {}, {}
    last_thread = 0
    for sequence, line in enumerate(_bounded_lines(trace_raw), 1):
        try:
            _need(
                not ended
                and sequence <= MAX_ROWS
                and consumed + len(line) <= MAX_BYTES,
                "row_after_end_or_capacity",
            )
            row = _parse(line, MAX_BYTES)
            _need(
                type(row) is dict
                and set(row) == {"schema_version", "seq", "prev", "kind", "data"}
                and row["schema_version"] == SCHEMA
                and type(row["seq"]) is int
                and row["seq"] == sequence
                and row["prev"] == previous,
                "lean_row_chain_or_schema",
            )
            kind, data = row["kind"], row["data"]
            _need(type(data) is dict, "lean_row_data_type")
            if sequence == 1:
                _need(kind == "header", "missing_lean_header")
                _header(data, expected["header"], study_protocol_sha256)
                header = result["header"] = deepcopy(data)
            else:
                _need(
                    header is not None
                    and sequence <= header["limits"]["max_rows"]
                    and consumed + len(line) <= header["limits"]["max_bytes"],
                    "declared_lean_capacity",
                )
                if kind == "thread":
                    _need(
                        set(data)
                        == {
                            "logical_thread_token",
                            "native_tid",
                            "task_start_ticks",
                            "thread_name",
                            "identity_scope",
                        }
                        and type(data["logical_thread_token"]) is int
                        and 1 <= data["logical_thread_token"] <= 16
                        and data["logical_thread_token"] not in threads
                        and _uint(data["native_tid"])
                        and data["task_start_ticks"] is None
                        and type(data["thread_name"]) is str
                        and 0 < len(data["thread_name"]) <= 128
                        and data["identity_scope"]
                        == "strong_python_Thread_object_native_tid_not_kernel_incarnation",
                        "logical_thread_fields_or_duplicate",
                    )
                    threads[data["logical_thread_token"]] = data
                elif kind == "event":
                    _need(
                        set(data)
                        == {"index", "event_sha256", "core_event_key", "trace_id"}
                        and type(data["index"]) is int
                        and 0 <= data["index"] < 120
                        and data["index"] not in bindings
                        and _hash(data["event_sha256"])
                        and _hash(data["core_event_key"])
                        and _label(data["trace_id"]),
                        "event_binding_fields",
                    )
                    index = data["index"]
                    if originals_valid and (
                        index not in events
                        or not _same(
                            data,
                            {k: v for k, v in events[index].items() if k != "event"},
                        )
                    ):
                        reasons.append("event_binding_differs:" + str(index))
                        bindings[index] = None
                    else:
                        bindings[index] = data
                elif kind == "span":
                    _need(set(data) == SPAN_FIELDS, "lean_span_fields")
                    token, local = data["logical_thread_token"], data["span_id"]
                    _need(
                        type(token) is int
                        and token in threads
                        and token >= last_thread
                        and type(local) is int
                        and local == counts.get(token, 0) + 1
                        and local <= 480,
                        "span_thread_or_local_sequence",
                    )
                    _need(
                        data["phase"] in PHASES
                        and (data["object_id"] is None or _label(data["object_id"]))
                        and (
                            data["event_index"] is None
                            or type(data["event_index"]) is int
                            and 0 <= data["event_index"] < 120
                        )
                        and (
                            data["parent_id"] is None
                            or type(data["parent_id"]) is int
                            and 0 < data["parent_id"] < local
                        )
                        and type(data["complete"]) is bool
                        and data["outcome"] in (None, "returned", "raised")
                        and (
                            data["error"] is None
                            or data["error"]
                            in (
                                "unfinished",
                                "start_clock_failure",
                                "end_clock_failure",
                                "native_tid_changed",
                            )
                        ),
                        "lean_span_context",
                    )
                    for name in (
                        "start_ns",
                        "end_ns",
                        "thread_cpu_start_ns",
                        "thread_cpu_end_ns",
                        "process_cpu_start_ns",
                        "process_cpu_end_ns",
                        "native_tid_start",
                        "native_tid_end",
                    ):
                        _need(
                            data[name] is None or _uint(data[name]), "lean_clock_uint"
                        )
                    parent = (
                        records.get((token, data["parent_id"]))
                        if data["parent_id"] is not None
                        else None
                    )
                    _need(
                        data["parent_id"] is None or parent is not None,
                        "lean_parent_missing",
                    )
                    if data["complete"]:
                        _need(
                            data["error"] is None
                            and data["outcome"] in ("returned", "raised")
                            and all(
                                data[start] is not None
                                and data[end] is not None
                                and data[start] <= data[end]
                                for start, end in CLOCK_PAIRS
                            )
                            and data["native_tid_start"]
                            == data["native_tid_end"]
                            == threads[token]["native_tid"],
                            "lean_clock_or_thread_mismatch",
                        )
                        if parent is not None and parent["complete"]:
                            _need(
                                all(
                                    parent[start]
                                    <= data[start]
                                    <= data[end]
                                    <= parent[end]
                                    for start, end in CLOCK_PAIRS
                                ),
                                "lean_child_clock_outside_parent",
                            )
                        for (old_token, _), sibling in records.items():
                            if (
                                old_token == token
                                and sibling["parent_id"] == data["parent_id"]
                                and sibling["complete"]
                            ):
                                _need(
                                    all(
                                        sibling[end] <= data[start]
                                        for start, end in CLOCK_PAIRS
                                    ),
                                    "lean_sibling_clock_overlap",
                                )
                        wall = data["end_ns"] - data["start_ns"]
                        cpu = data["thread_cpu_end_ns"] - data["thread_cpu_start_ns"]
                        fact = dict(
                            deepcopy(data),
                            elapsed_ns=wall,
                            thread_cpu_ns=cpu,
                            process_cpu_ns=data["process_cpu_end_ns"]
                            - data["process_cpu_start_ns"],
                            wall_minus_thread_cpu_ns=wall - cpu
                            if wall >= cpu
                            else None,
                            residual_cause="UNCLASSIFIED",
                            event_correlation="unavailable",
                            scheduler=dict(
                                qualified_runqueue_wait_ns=None,
                                reasons=[
                                    "lean_profile_no_scheduler_samples_or_kernel_task_identity"
                                ],
                            ),
                            thread_identity="logical_python_thread_only",
                            inclusive_nonadditive=True,
                        )
                        result["completed_spans"].append(fact)
                    else:
                        _need(
                            data["error"] is not None, "incomplete_slot_without_reason"
                        )
                        result["incomplete_intents"].append(deepcopy(data))
                    records[token, local] = data
                    counts[token], last_thread = local, token
                elif kind == "end":
                    _need(
                        set(data)
                        == {
                            "normal_return",
                            "active_spans",
                            "incomplete",
                            "quiescent",
                            "flush_start_ns",
                            "flush_before_end_ns",
                        }
                        and data["normal_return"] is True
                        and type(data["active_spans"]) is int
                        and data["active_spans"] == 0
                        and data["incomplete"] is False
                        and data["quiescent"] is True
                        and _uint(data["flush_start_ns"])
                        and _uint(data["flush_before_end_ns"])
                        and data["flush_start_ns"] <= data["flush_before_end_ns"]
                        and not result["incomplete_intents"],
                        "lean_end_invalid_or_incomplete",
                    )
                    _need(
                        all(
                            span["end_ns"] <= data["flush_start_ns"]
                            for span in result["completed_spans"]
                        ),
                        "flush_before_work_quiescence",
                    )
                    if originals_valid:
                        final = result["finalization"]
                        _need(
                            final is not None
                            and final["elapsed_ns"] is not None
                            and final["start_ns"]
                            <= data["flush_start_ns"]
                            <= data["flush_before_end_ns"]
                            <= final["end_ns"],
                            "external_actual_flush_bracket_unestablished",
                        )
                    ended = True
                else:
                    raise ValueError("unknown_lean_row_kind")
            consumed += len(line)
            previous = _sha(line)
            result["valid_prefix_rows"] = sequence
        except ERRORS as exc:
            reasons.append("trace_invalid:" + str(exc))
            break
    for fact in result["completed_spans"]:
        binding = bindings.get(fact["event_index"])
        if (
            originals_valid
            and binding is not None
            and len(keys.get(binding["core_event_key"], [])) == 1
        ):
            fact["event_correlation"] = "exact_original_event_key_logical_thread"
    if not ended:
        reasons.append("missing_normal_end")
    if result["incomplete_intents"]:
        reasons.append("incomplete_buffer_slots")
    if originals_valid:
        control = result["original_result"]["control"]
        if not all(
            control.get(key) is True
            for key in (
                "instrumented_workers_joined",
                "producers_joined",
                "callbacks_quiescent",
            )
        ):
            reasons.append("outer_actual_quiescence_unestablished")
        if control.get("recorder_descriptor_closed") is not True:
            reasons.append("outer_descriptor_close_success_unestablished")
        if (
            control.get("recording_incomplete") is True
            or control.get("recorder_close_error") is not None
        ):
            reasons.append("outer_recording_incomplete_or_close_unknown")
    result["normal_return_confirmed"] = (
        ended and consumed == len(trace_raw) and not reasons and originals_valid
    )
    result["status"] = (
        "complete_descriptive_trace"
        if result["normal_return_confirmed"]
        else "partial_prefix"
        if result["completed_spans"]
        else "withheld"
    )
    return result
