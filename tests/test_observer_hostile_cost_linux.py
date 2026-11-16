"""Actual bounded offline software load; withheld clock gates remain withheld."""

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="disposable Linux Root and prestaged matching core required",
)


def require_instrumented_capture(arm, original):
    if not original["instrumented"]:
        return
    assert original["functional_phase_gate"]["accepted"] is True
    if original["mode"] == "off":
        return
    clock = arm["clock_report"]
    assert type(clock["observed_calls"]) is int and clock["observed_calls"] > 0
    assert clock["calls_error"] is None
    assert clock["context"]["begin"] is not None
    assert clock["context"]["error"] is None
    assert "external_recording_pair_policy_binding_unavailable" not in clock["reasons"]
    if original["mode"] == "on":
        count = arm["observed_completed_callbacks_inside_load_after_warmup"]
        assert type(count) is int and count >= 1


def test_declared_120_percent_load_preserves_markers_and_withholds_unclosed_clock():
    from run_observer_hostile_cost import export_public, run
    from run_observer_phase_cost import ARM_ORDER

    destination = os.environ.get("EDGE_HOSTILE_COST_PUBLIC_DIR")
    try:
        result = run(keep=True)
    except BaseException as exc:
        if destination and hasattr(exc, "hostile_cost_partial_report"):
            export_public(exc.hostile_cost_partial_report, destination)
        raise
    if destination:
        export_public(result, destination)
    assert [arm["arm_id"] for arm in result["arms"]] == list(ARM_ORDER)
    assert result["marker_semantic_parity"] is True
    assert result["all_load_gates_valid"] is True
    assert result["measurement_verdict"] == "withheld"
    assert result["whole_measurement_qualified"] is False
    for arm, original in zip(result["arms"], result["original_arm_inputs"]):
        require_instrumented_capture(arm, original)
        assert arm["load_status"] == "valid_declared_120_percent_load"
        assert arm["original_cost_report"] == original["original_cost_report"]
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
        if original["mode"] == "faulted":
            assert cost["observer_exit"] == -9
            assert cost["observer_input_records"] == 3
            assert cost["observer_unprocessed_decisions"] == 2
        if original["instrumented"] and original["mode"] != "off":
            assert arm["clock_status"] == "withheld"
            assert arm["clock_report"]["eligible"] is False
            assert arm["clock_report"]["original_qualification"]["status"] == "withheld"
            assert arm["clock_report"]["context"]["end"] is None
