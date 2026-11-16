"""Real offline six-arm evidence; software success never forces a 5ms pass."""

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="disposable offline Linux Root and prestaged matching core required",
)


def test_actual_normal_stop_clock_at_120_percent_load():
    from run_observer_normal_clock import export_public, run
    from run_observer_phase_cost import ARM_ORDER
    from test_observer_hostile_cost_linux import require_instrumented_capture

    destination = os.environ.get("EDGE_NORMAL_CLOCK_PUBLIC_DIR")
    try:
        result = run()
    except BaseException as exc:
        if destination and hasattr(exc, "normal_stop_partial_report"):
            export_public(exc.normal_stop_partial_report, destination)
        raise
    if destination:
        export_public(result, destination)
    load = result["original_load_evaluation"]
    assert [arm["arm_id"] for arm in load["arms"]] == list(ARM_ORDER)
    assert load["marker_semantic_parity"] is True
    assert load["all_load_gates_valid"] is True
    assert result["both_on_stops_verified"] is True
    assert result["instrumented_on_five_ms_status"] in (
        "qualified_sampled_anchors",
        "withheld",
    )
    assert result["whole_measurement_qualified"] is False
    assert result["comparison_qualified"] is False
    assert result["qualified_safety_count"] is None
    rows = {row["arm_id"]: row for row in result["normal_end_evaluations"]}
    for arm, original in zip(load["arms"], load["original_arm_inputs"]):
        require_instrumented_capture(arm, original)
        assert arm["load_status"] == "valid_declared_120_percent_load"
        assert len(arm["marker_samples"]) == 3
        assert arm["quota_load"]["writer_error"] is None
        assert (
            original["eve_evidence"]["written_by_class"] == arm["quota_load"]["written"]
        )
        cost = arm["original_cost_report"]
        assert (
            cost["expected_decisions"]
            == cost["native_decisions"]
            == cost["signed_decisions"]
            == 3
        )
        row = rows[arm["arm_id"]]
        if original["mode"] == "on":
            assert cost["observer_exit"] == 0
            assert row["normal_end_verified"] is True
            assert row["authenticated_source_closed"] is True
            assert row["journal_close_verified"] is True
            assert row["input_coverage_complete"] is False
            if original["instrumented"]:
                assert original["clock_report"]["context"]["closed"] is True
                assert original["clock_report"]["context"]["end"] is not None
        elif original["mode"] == "faulted":
            assert cost["observer_exit"] == -9
            assert cost["observer_input_records"] == 3
            assert cost["observer_unprocessed_decisions"] == 2
            assert row["status"] == "expected_uncatchable_fault_prefix"
            assert row["five_ms_status"] == "withheld"
            assert row["normal_end_verified"] is False
            if original["instrumented"]:
                assert original["clock_report"]["context"]["end"] is None
