"""Synthetic parser/interpretation tests; not actual latency evidence."""

from copy import deepcopy
import hashlib
import json

import pytest

from azazel_edge.benchmark.timing_cost_attribution import (
    ARM_ORDER,
    PINS,
    analyze_cost_arms,
    analyze_trace,
)

PINS_DATA = {key: hashlib.sha256(key.encode()).hexdigest() for key in PINS}
PINS_DATA.update(run_id="synthetic", arm="instrumented_off", role="signer")
BOOT = "11111111-2222-3333-4444-555555555555"


def trace(*, end=True, elapsed=7_000_000, thread=100, process=200):
    header = dict(
        PINS_DATA,
        pid=123,
        start_ticks=100,
        native_tid=124,
        boot_id=BOOT,
        clock_ticks_per_second=100,
        clock_resolutions={
            "monotonic": 1e-9,
            "process_time": 1e-9,
            "thread_time": 1e-9,
        },
        limits=dict(max_rows=4096, max_bytes=4 * 1024 * 1024),
        clock_domain=dict(
            established=True,
            time_namespace_device=1,
            time_namespace_inode=12,
            timens_offsets=[
                dict(clock=clock, seconds=0, nanoseconds=0)
                for clock in ("monotonic", "boottime")
            ],
        ),
        unallocated_footer_flush_overhead=True,
        previous_write_cost=None,
    )
    intent = dict(
        span_id=1,
        parent_id=None,
        phase="source_append",
        event_kind=None,
        event_seq=None,
        operation=None,
        previous_write_cost=None,
    )
    span = dict(
        intent,
        start_ns=10,
        end_ns=10 + elapsed,
        process_cpu_start_ns=5,
        process_cpu_end_ns=5 + process,
        thread_cpu_start_ns=5,
        thread_cpu_end_ns=5 + thread,
        native_tid=124,
        outcome="returned",
    )
    rows = [("header", header), ("intent", intent), ("span", span)]
    if end:
        rows.append(
            (
                "end",
                dict(
                    normal_return=True,
                    incomplete=False,
                    unallocated_footer_flush_overhead=True,
                    previous_write_cost=None,
                ),
            )
        )
    return rows


def encode(rows):
    raw, prev = b"", "0" * 64
    for seq, (kind, data) in enumerate(rows, 1):
        row = dict(
            schema_version="edge-phase-timing-record/v1",
            seq=seq,
            prev=prev,
            kind=kind,
            data=data,
        )
        line = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        raw += line
        prev = hashlib.sha256(line).hexdigest()
    return raw


def test_synthetic_completed_body_does_not_qualify_clock_or_safety():
    result = analyze_trace(encode(trace()), expected=PINS_DATA)
    assert result["normal_return_confirmed"]
    assert result["phases"]["source_append"]["body_over_5ms_observed_calls"] == 1
    assert result["complete_spans"][0]["wall_minus_thread_cpu_ns"] == 6_999_900
    assert result["causal_wait_attribution"] == "UNKNOWN"
    assert result["phases"]["finalize_due"]["elapsed_ns"] is None
    assert result["active_window_finalization_wait_ns"] is None
    assert result["timeline_join"] == "unavailable"
    assert result["qualified_safety_count"] is None
    assert result["measurement_completed"] is False
    assert result["complete_spans"][0]["whole_wrapper_clock_qualified"] is False


@pytest.mark.parametrize("tail", [b"{", b"{}\n", b"{}", b"\n"])
def test_synthetic_later_corruption_keeps_completed_prefix(tail):
    result = analyze_trace(encode(trace(end=False)) + tail, expected=PINS_DATA)
    assert result["status"] == "partial_prefix"
    assert len(result["complete_spans"]) == 1
    assert result["normal_return_confirmed"] is False
    assert result["phases"]["source_append"]["coverage"] == "partial_prefix"


def test_missing_pins_or_bytes_never_becomes_zero():
    for raw, pins in [(None, PINS_DATA), (b"", PINS_DATA), (encode(trace()), {})]:
        result = analyze_trace(raw, expected=pins)
        assert result["status"] == "unavailable"
        assert result["phases"]["source_append"]["elapsed_ns"] is None


@pytest.mark.parametrize(
    "fault", ["pin", "process", "reverse", "duplicate", "parent", "end_pending"]
)
def test_synthetic_identity_and_lifecycle_faults(fault):
    rows = trace()
    expected = dict(PINS_DATA)
    if fault == "pin":
        expected["core_sha256"] = "different"
    elif fault == "process":
        expected.update(pid=123, start_ticks=101, boot_id=BOOT)
    elif fault == "reverse":
        rows[2][1]["end_ns"] = 1
    elif fault == "duplicate":
        rows.insert(3, rows[2])
    elif fault == "parent":
        rows[1][1]["parent_id"] = 999
    elif fault == "end_pending":
        rows.pop(2)
    result = analyze_trace(encode(rows), expected=expected)
    assert not result["normal_return_confirmed"]
    assert result["reasons"]


def test_synthetic_residual_negative_unknown_and_process_can_include_other_threads():
    result = analyze_trace(
        encode(trace(elapsed=100, thread=101, process=1000)), expected=PINS_DATA
    )
    fact = result["complete_spans"][0]
    assert fact["wall_minus_thread_cpu_ns"] is None
    assert fact["process_cpu_ns"] == 1000
    assert fact["residual_cause"] == "UNKNOWN"


def test_synthetic_external_domain_required_and_offset_must_be_zero():
    rows = trace()
    expected = dict(
        PINS_DATA,
        clock_domain=deepcopy(rows[0][1]["clock_domain"]),
        boot_id=BOOT,
    )
    assert analyze_trace(encode(rows), expected=expected)["timeline_join"].startswith(
        "eligible"
    )
    rows[0][1]["clock_domain"]["timens_offsets"][0]["seconds"] = 1
    expected["clock_domain"] = deepcopy(rows[0][1]["clock_domain"])
    assert (
        analyze_trace(encode(rows), expected=expected)["timeline_join"] == "unavailable"
    )


def test_synthetic_no_additive_total_and_originals_preserved():
    originals = [
        dict(
            input_sha256="same",
            semantic_sha256="same",
            elapsed_seconds=1,
            old_clock_verdict="WITHHELD",
            missing_metric=None,
        )
        for _ in ARM_ORDER
    ]
    arms = [
        dict(arm_id=name, original_cost_report=report)
        for name, report in zip(ARM_ORDER, originals)
    ]
    snapshot = deepcopy(arms)
    result = analyze_cost_arms(arms)
    assert arms == snapshot == result["arms"]
    assert result["fixed_gates"] == dict(
        clock_budget_ns=5_000_000, minimum_fraction=0.98, load_multiplier=1.2
    )
    assert result["six_arm_semantic_parity"]
    assert result["comparison_qualified"] is False
    result["arms"][0]["original_cost_report"]["missing_metric"] = 0
    assert arms == snapshot
    with pytest.raises(ValueError, match="six_arm"):
        analyze_cost_arms(arms[::-1])


@pytest.mark.parametrize(
    "fault",
    ["extra", "depth", "huge_clock", "bad_inode", "sibling_overlap", "child_cpu"],
)
def test_synthetic_review_regressions_preserve_only_valid_prefix(fault):
    rows = trace(elapsed=100, thread=50, process=60)
    if fault == "extra":
        rows[2][1]["raw_args"] = "must_not_be_accepted"
    elif fault == "depth":
        nested = {}
        for _ in range(20):
            nested = {"x": nested}
        rows[2][1]["unexpected"] = nested
    elif fault == "huge_clock":
        rows[2][1]["end_ns"] = 2**64
    elif fault == "bad_inode":
        rows[0][1]["clock_domain"]["time_namespace_inode"] = 0
    elif fault == "sibling_overlap":
        intent = dict(rows[1][1], span_id=2)
        span = dict(rows[2][1], span_id=2)
        rows[3:3] = [("intent", intent), ("span", span)]
    elif fault == "child_cpu":
        parent_intent = dict(rows[1][1], span_id=2, parent_id=None)
        child_intent = dict(rows[1][1], parent_id=2)
        child_span = dict(rows[2][1], parent_id=2)
        parent_span = dict(
            rows[2][1],
            span_id=2,
            parent_id=None,
            start_ns=0,
            end_ns=200,
            thread_cpu_end_ns=20,
        )
        rows = [
            rows[0],
            ("intent", parent_intent),
            ("intent", child_intent),
            ("span", child_span),
            ("span", parent_span),
            rows[-1],
        ]
    result = analyze_trace(encode(rows), expected=PINS_DATA)
    assert not result["normal_return_confirmed"]
    assert result["reasons"]
    if fault in ("sibling_overlap", "child_cpu"):
        assert len(result["complete_spans"]) == 1
