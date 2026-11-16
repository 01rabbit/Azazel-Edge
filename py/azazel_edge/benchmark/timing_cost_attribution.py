"""Bounded, offline descriptive timing analysis; never qualifies safety or clocks.

Hash chains detect malformed supplied bytes, not sensor authenticity. Original
cost/clock reports remain separate. Completed prefix facts survive later loss.
"""

from copy import deepcopy
import hashlib
import json
import math
import re
import statistics

SCHEMA = "edge-phase-timing-record/v1"
MAX_ROWS = 4096
MAX_BYTES = 4 * 1024 * 1024
BUDGET_NS = 5_000_000
PHASES = (
    "input_receive",
    "native_frame_validation",
    "source_append",
    "source_sign",
    "source_verify",
    "witness_rpc",
    "witness_request",
    "witness_append",
    "witness_sign",
    "input_snapshot",
    "observation",
    "journal_append",
    "observation_sample",
    "observation_event",
    "finalize_due",
    "source_fsync",
    "journal_fsync",
    "witness_fsync",
    "source_closure_wait",
    "observer_stop_wait",
    "controller_wait",
)
PINS = (
    "run_id",
    "arm",
    "role",
    "input_sha256",
    "code_sha256",
    "core_sha256",
    "interpreter_sha256",
)
ARM_ORDER = (
    "original_off",
    "instrumented_off",
    "original_on",
    "instrumented_on",
    "original_faulted",
    "instrumented_faulted",
)
EVENT_KINDS = (
    None,
    "session_prepare",
    "session_start",
    "decision",
    "session_end",
    "begin",
    "commit",
    "lost",
    "cursor",
    "seal",
    "session_close",
    "session_recovered",
)
OPERATIONS = (
    None,
    "read",
    "advance",
    "anchor",
    "response",
    "prepare",
    "session_start",
    "decision",
    "session_end",
    "poll_detection",
    "signed_source_detection",
    "wait",
)
INTENT_FIELDS = {
    "span_id",
    "parent_id",
    "phase",
    "event_kind",
    "event_seq",
    "operation",
    "previous_write_cost",
}
CLOCK_FIELDS = {
    "start_ns",
    "end_ns",
    "process_cpu_start_ns",
    "process_cpu_end_ns",
    "thread_cpu_start_ns",
    "thread_cpu_end_ns",
}


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def _integer(value):
    return type(value) is int and 0 <= value < 2**64


def _depth(value, level=0):
    if level > 16:
        raise ValueError("json_depth_limit")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, level + 1)


def _header_metadata(data):
    if (
        not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", data.get("run_id", ""))
        or data.get("arm") not in ARM_ORDER
    ):
        raise ValueError("invalid_run_or_arm")
    for key in ("input_sha256", "code_sha256", "core_sha256", "interpreter_sha256"):
        if not isinstance(data.get(key), str) or not re.fullmatch(
            "[0-9a-f]{64}", data[key]
        ):
            raise ValueError("invalid_hash_pin")
    if not re.fullmatch(
        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", data.get("boot_id", "")
    ):
        raise ValueError("invalid_boot_id")
    resolutions = data.get("clock_resolutions")
    if (
        not isinstance(resolutions, dict)
        or set(resolutions) != {"monotonic", "process_time", "thread_time"}
        or any(
            type(v) not in (int, float) or not math.isfinite(v) or v <= 0
            for v in resolutions.values()
        )
    ):
        raise ValueError("invalid_clock_resolutions")
    domain = data.get("clock_domain")
    if (
        not isinstance(domain, dict)
        or set(domain)
        != {
            "time_namespace_device",
            "time_namespace_inode",
            "timens_offsets",
            "established",
        }
        or type(domain["established"]) is not bool
    ):
        raise ValueError("invalid_clock_domain")
    for key in ("time_namespace_device", "time_namespace_inode"):
        if domain[key] is not None and not _integer(domain[key]):
            raise ValueError("invalid_namespace_identity")
    if domain["time_namespace_inode"] == 0:
        raise ValueError("invalid_namespace_inode")
    offsets = domain["timens_offsets"]
    if offsets is not None:
        if not isinstance(offsets, list) or len(offsets) > 2:
            raise ValueError("invalid_clock_offsets")
        names = set()
        for item in offsets:
            if (
                not isinstance(item, dict)
                or set(item) != {"clock", "seconds", "nanoseconds"}
                or item["clock"] not in ("monotonic", "boottime")
                or item["clock"] in names
                or type(item["seconds"]) is not int
                or type(item["nanoseconds"]) is not int
            ):
                raise ValueError("invalid_clock_offset")
            names.add(item["clock"])
    if domain["established"] and (
        not offsets
        or {item["clock"] for item in offsets} != {"monotonic", "boottime"}
        or any(item["seconds"] != 0 or item["nanoseconds"] != 0 for item in offsets)
        or any(
            domain[key] is None
            for key in ("time_namespace_device", "time_namespace_inode")
        )
    ):
        raise ValueError("unestablished_clock_domain")
    if data.get("unallocated_footer_flush_overhead") is not True:
        raise ValueError("missing_unallocated_overhead")


def _stats(values):
    if not values:
        return None
    ordered = sorted(values)
    return dict(
        observed_calls=len(values),
        minimum=min(values),
        median=statistics.median(values),
        p95=ordered[math.ceil(0.95 * len(ordered)) - 1],
        maximum=max(values),
    )


def _bounds(data):
    fields = (
        "start_ns",
        "end_ns",
        "process_cpu_start_ns",
        "process_cpu_end_ns",
        "thread_cpu_start_ns",
        "thread_cpu_end_ns",
    )
    if not all(_integer(data.get(key)) for key in fields):
        raise ValueError("invalid_clock_brackets")
    elapsed = data["end_ns"] - data["start_ns"]
    process = data["process_cpu_end_ns"] - data["process_cpu_start_ns"]
    thread = data["thread_cpu_end_ns"] - data["thread_cpu_start_ns"]
    if min(elapsed, process, thread) < 0:
        raise ValueError("reversed_clock_brackets")
    return elapsed, process, thread


def analyze_trace(raw, *, expected):
    """Analyze one externally pinned role trace, retaining only valid prefix facts.

    ``expected`` must supply all PINS; no self-declared header is a trust anchor.
    Neither pins nor a clean chain establish observer independence/authenticity.
    """
    result = dict(
        schema_version="edge-phase-timing-analysis/v1",
        raw_sha256=None,
        status="unavailable",
        reasons=[],
        header=None,
        valid_prefix_rows=0,
        complete_spans=[],
        phases={},
        write_cost_ns=None,
        timeline_join="unavailable",
        pending_spans=[],
        pending_span_intents=[],
        normal_return_confirmed=False,
        active_window_finalization_wait_ns=None,
        active_window_finalization_status="not_exercised",
        original_clock_qualification="not_supplied_unqualified",
        evidence_authenticated=False,
        causal_wait_attribution="UNKNOWN",
        inclusive_spans_additive=False,
        measurement_completed=False,
        comparison_qualified=False,
        production_admission=False,
        authorizes_transition=False,
        qualified_safety_count=None,
        unallocated_footer_flush_overhead=True,
        trace_descriptor_close_status="not_proven_by_footer",
        trace_durability_proven=False,
    )
    samples = {phase: [] for phase in PHASES}
    writes, pending, seen, completed, latest_by_thread = [], {}, {}, {}, {}
    if not isinstance(raw, bytes):
        result["reasons"].append("trace_missing_or_not_bytes")
        raw = b""
    else:
        result["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    pins_valid = isinstance(expected, dict) and all(
        isinstance(expected.get(key), str) and expected[key] for key in PINS
    )
    if not pins_valid:
        result["reasons"].append("external_pins_missing")
    previous = "0" * 64
    ended = False
    lines = raw[:MAX_BYTES].splitlines(keepends=True)
    if not raw:
        result["reasons"].append("trace_missing_or_empty")
    prefix_bytes = 0
    for index, line in enumerate(lines[:MAX_ROWS], 1):
        try:
            if not pins_valid:
                break
            if result["header"] is not None and (
                index > result["header"]["limits"]["max_rows"]
                or prefix_bytes + len(line) > result["header"]["limits"]["max_bytes"]
            ):
                raise ValueError("declared_prefix_bound")
            if not line.endswith(b"\n"):
                raise ValueError("truncated_row")
            row = json.loads(line)
            _depth(row)
            if _canonical(row) + b"\n" != line:
                raise ValueError("noncanonical_or_duplicate_json")
            if set(row) != {"schema_version", "seq", "prev", "kind", "data"}:
                raise ValueError("invalid_row_shape")
            if (
                row["schema_version"] != SCHEMA
                or type(row["seq"]) is not int
                or row["seq"] != index
                or row["prev"] != previous
            ):
                raise ValueError("broken_chain_or_sequence")
            kind, data = row["kind"], row["data"]
            if not isinstance(data, dict) or ended:
                raise ValueError("invalid_data_or_after_end")
            write = data.get("previous_write_cost")
            write_bounds = None
            if write is not None:
                if (
                    not isinstance(write, dict)
                    or set(write) != CLOCK_FIELDS | {"seq"}
                    or type(write.get("seq")) is not int
                    or write["seq"] != index - 1
                ):
                    raise ValueError("invalid_previous_write_identity")
                write_bounds = _bounds(write)
            if index == 1:
                if set(data) != set(PINS) | {
                    "pid",
                    "start_ticks",
                    "native_tid",
                    "boot_id",
                    "clock_domain",
                    "clock_ticks_per_second",
                    "clock_resolutions",
                    "limits",
                    "unallocated_footer_flush_overhead",
                    "previous_write_cost",
                } or data.get("role") not in (
                    "signer",
                    "observer",
                    "witness",
                    "controller",
                    "launcher",
                ):
                    raise ValueError("unexpected_header_fields_or_role")
                _header_metadata(data)
                if kind != "header" or any(
                    data.get(key) != expected[key] for key in PINS
                ):
                    raise ValueError("header_pin_mismatch")
                if (
                    not all(
                        _integer(data.get(key)) and data[key] > 0
                        for key in (
                            "pid",
                            "start_ticks",
                            "native_tid",
                            "clock_ticks_per_second",
                        )
                    )
                    or not isinstance(data.get("boot_id"), str)
                    or not data["boot_id"]
                ):
                    raise ValueError("missing_process_incarnation")
                limits = data.get("limits", {})
                if not isinstance(limits, dict) or any(
                    not _integer(limits.get(key)) or not 0 < limits[key] <= maximum
                    for key, maximum in (
                        ("max_rows", MAX_ROWS),
                        ("max_bytes", MAX_BYTES),
                    )
                ):
                    raise ValueError("invalid_record_limits")
                if any(
                    key in expected and data.get(key) != expected[key]
                    for key in ("pid", "start_ticks", "boot_id")
                ):
                    raise ValueError("external_process_incarnation_mismatch")
                result["header"] = deepcopy(data)
            elif kind == "intent":
                if (
                    set(data) != INTENT_FIELDS
                    or data.get("event_kind") not in EVENT_KINDS
                    or data.get("operation") not in OPERATIONS
                    or not (
                        data.get("event_seq") is None
                        or _integer(data["event_seq"])
                        and data["event_seq"] < 2**64
                    )
                ):
                    raise ValueError("unexpected_intent_metadata")
                ident, parent, phase = (
                    data.get("span_id"),
                    data.get("parent_id"),
                    data.get("phase"),
                )
                if (
                    type(ident) is not int
                    or ident < 1
                    or ident in seen
                    or phase not in PHASES
                    or (
                        parent is not None
                        and (type(parent) is not int or parent not in pending)
                    )
                ):
                    raise ValueError("invalid_intent_or_parent")
                depth, ancestor = 1, parent
                while ancestor is not None:
                    depth += 1
                    ancestor = pending[ancestor]["parent_id"]
                if depth > 16:
                    raise ValueError("nesting_limit")
                pending[ident] = dict(data)
                seen[ident] = dict(data)
            elif kind == "span":
                if set(data) != INTENT_FIELDS | CLOCK_FIELDS | {
                    "native_tid",
                    "outcome",
                }:
                    raise ValueError("unexpected_span_fields")
                ident = data.get("span_id")
                if type(ident) is not int or ident not in pending:
                    raise ValueError("span_without_unique_intent")
                intent = pending[ident]
                if (
                    any(
                        data.get(key) != intent.get(key)
                        for key in (
                            "parent_id",
                            "phase",
                            "event_kind",
                            "event_seq",
                            "operation",
                        )
                    )
                    or data.get("outcome") not in ("returned", "raised")
                    or not _integer(data.get("native_tid"))
                    or data["native_tid"] < 1
                ):
                    raise ValueError("span_intent_mismatch")
                if any(child.get("parent_id") == ident for child in pending.values()):
                    raise ValueError("parent_completed_before_child")
                elapsed, process, thread = _bounds(data)
                prior = latest_by_thread.get(data["native_tid"])
                if prior is not None:
                    ancestor = prior["span_id"]
                    while ancestor is not None and ancestor != ident:
                        ancestor = seen[ancestor]["parent_id"]
                    if data["end_ns"] < prior["end_ns"] or (
                        ancestor != ident and data["start_ns"] < prior["end_ns"]
                    ):
                        raise ValueError("thread_clock_order_or_overlap")
                for child in completed.values():
                    if child["parent_id"] == ident and any(
                        child[start] < data[start] or child[end] > data[end]
                        for start, end in (
                            ("start_ns", "end_ns"),
                            ("process_cpu_start_ns", "process_cpu_end_ns"),
                            ("thread_cpu_start_ns", "thread_cpu_end_ns"),
                        )
                    ):
                        raise ValueError("child_clock_outside_parent")
                if any(
                    child["parent_id"] == ident
                    and (
                        child["native_tid"] != data["native_tid"]
                        or child["start_ns"] < data["start_ns"]
                        or child["end_ns"] > data["end_ns"]
                    )
                    for child in result["complete_spans"]
                ):
                    raise ValueError("child_outside_parent")
                fact = dict(
                    span_id=ident,
                    parent_id=data["parent_id"],
                    phase=data["phase"],
                    start_ns=data["start_ns"],
                    end_ns=data["end_ns"],
                    native_tid=data["native_tid"],
                    elapsed_ns=elapsed,
                    process_cpu_ns=process,
                    thread_cpu_ns=thread,
                    wall_minus_thread_cpu_ns=elapsed - thread
                    if elapsed >= thread
                    else None,
                    residual_cause="UNKNOWN",
                    outcome=data["outcome"],
                    body_exceeds_5ms=elapsed > BUDGET_NS,
                    whole_wrapper_clock_qualified=False,
                )
                result["complete_spans"].append(fact)
                samples[data["phase"]].append(fact)
                completed[ident] = data
                latest_by_thread[data["native_tid"]] = data
                del pending[ident]
            elif kind == "end":
                if set(data) != {
                    "normal_return",
                    "incomplete",
                    "unallocated_footer_flush_overhead",
                    "previous_write_cost",
                }:
                    raise ValueError("unexpected_end_fields")
                if (
                    pending
                    or data.get("normal_return") is not True
                    or data.get("incomplete") is not False
                ):
                    raise ValueError("invalid_normal_return_closure")
                ended = True
            else:
                raise ValueError("invalid_record_kind")
            if write_bounds is not None:
                writes.append(write_bounds[0])
            previous = hashlib.sha256(line).hexdigest()
            result["valid_prefix_rows"] = index
            prefix_bytes += len(line)
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            result["reasons"].append("invalid_or_incomplete_row_" + str(index))
            break
    if len(raw) > MAX_BYTES or len(lines) > MAX_ROWS:
        result["reasons"].append("trace_bound_exceeded")
    if result["header"] is not None:
        limit = result["header"]["limits"]
        if len(raw) > limit["max_bytes"] or len(lines) > limit["max_rows"]:
            result["reasons"].append("declared_trace_bound_exceeded")
    if not ended:
        result["reasons"].append("normal_return_not_recorded")
    result["normal_return_confirmed"] = ended and not result["reasons"]
    result["status"] = (
        "complete_descriptive_trace"
        if result["normal_return_confirmed"]
        else "partial_prefix"
        if result["header"]
        else "unavailable"
    )
    result["pending_spans"] = sorted(pending)
    result["pending_span_intents"] = [
        {key: pending[ident][key] for key in ("span_id", "parent_id", "phase")}
        for ident in sorted(pending)
    ]
    result["write_cost_ns"] = _stats(writes)
    result["write_cost_scope"] = "observed_os_write_loop_only"
    result["unallocated_trace_costs"] = [
        "serialization",
        "hashing",
        "locking",
        "metadata_and_clocks",
        "final_write_and_close",
    ]
    result["write_cost_coverage"] = (
        "partial_samples_only_not_total_instrumentation_cost"
    )
    for phase, facts in samples.items():
        result["phases"][phase] = dict(
            status="observed_complete_calls"
            if facts
            else "not_exercised"
            if result["normal_return_confirmed"]
            else "unavailable_or_not_exercised",
            coverage="complete_trace_only"
            if result["normal_return_confirmed"]
            else "partial_prefix",
            elapsed_ns=_stats([fact["elapsed_ns"] for fact in facts]),
            process_cpu_ns=_stats([fact["process_cpu_ns"] for fact in facts]),
            thread_cpu_ns=_stats([fact["thread_cpu_ns"] for fact in facts]),
            body_over_5ms_observed_calls=sum(fact["body_exceeds_5ms"] for fact in facts)
            if facts
            else None,
        )
    # Timeline eligibility requires an EXTERNAL common-domain pin, never just a
    # self-declared established flag. No timestamp joins are performed here.
    header = result["header"]
    domain = header.get("clock_domain") if header else None
    offsets = domain.get("timens_offsets") if isinstance(domain, dict) else None
    if (
        isinstance(domain, dict)
        and domain.get("established") is True
        and expected.get("clock_domain") == domain
        and expected.get("boot_id") == header["boot_id"]
        and isinstance(offsets, list)
        and offsets
        and all(
            isinstance(item, dict)
            and type(item.get("seconds")) is int
            and item["seconds"] == 0
            and type(item.get("nanoseconds")) is int
            and item["nanoseconds"] == 0
            for item in offsets
        )
    ):
        result["timeline_join"] = "eligible_same_pinned_domain_only_no_join_performed"
    return result


def analyze_cost_arms(arms):
    """Preserve original reports alongside descriptive traces; no acceptance lift."""
    if (
        not isinstance(arms, list)
        or len(arms) != len(ARM_ORDER)
        or [arm.get("arm_id") for arm in arms] != list(ARM_ORDER)
    ):
        raise ValueError("exact_six_arm_order_required")
    reports = deepcopy(arms)
    originals = [arm["original_cost_report"] for arm in reports]
    parity = (
        all(
            isinstance(report.get(key), str) and report[key]
            for report in originals
            for key in ("input_sha256", "semantic_sha256")
        )
        and len({report["input_sha256"] for report in originals}) == 1
        and len({report["semantic_sha256"] for report in originals}) == 1
    )
    deltas = []
    for index in (0, 2, 4):
        before, after = originals[index : index + 2]

        def difference(key):
            left, right = before.get(key), after.get(key)
            if (
                type(left) not in (int, float)
                or type(right) not in (int, float)
                or not math.isfinite(left)
                or not math.isfinite(right)
            ):
                return None
            return right - left

        deltas.append(
            dict(
                original_arm=ARM_ORDER[index],
                instrumented_arm=ARM_ORDER[index + 1],
                elapsed_seconds_delta=difference("elapsed_seconds"),
                logical_store_growth_bytes_delta=difference("store_growth_bytes"),
                causal_effect_established=False,
            )
        )
    return dict(
        schema_version="edge-timing-cost-attribution/v1",
        arms=reports,
        fixed_gates=dict(
            clock_budget_ns=BUDGET_NS, minimum_fraction=0.98, load_multiplier=1.2
        ),
        six_arm_semantic_parity=parity,
        clock_qualification="unchanged_separate_original_evidence_required",
        cost_comparison="descriptive_sequential_smoke_only",
        causal_attribution="UNKNOWN",
        instrumented_minus_original=deltas,
        measurement_completed=False,
        comparison_qualified=False,
        production_admission=False,
        authorizes_transition=False,
        qualified_safety_count=None,
    )
