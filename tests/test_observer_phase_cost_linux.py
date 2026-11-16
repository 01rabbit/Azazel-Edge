"""Actual offline six-arm software pilot, never a new sensor/efficacy trial."""

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="disposable Linux Root and matching prestaged core required",
)


def test_six_original_and_instrumented_arms_preserve_exact_workload_and_fault_prefix():
    from run_observer_phase_cost import ARM_ORDER, export_public, run

    destination = os.environ.get("EDGE_PHASE_COST_PUBLIC_DIR")
    try:
        result = run(keep=True)
    except BaseException as exc:
        if destination and hasattr(exc, "phase_cost_partial_report"):
            export_public(exc.phase_cost_partial_report, destination)
        raise
    if destination:
        export_public(result, destination)
    assert [arm["arm_id"] for arm in result["arms"]] == list(ARM_ORDER)
    assert result["six_arm_semantic_parity"] is True
    assert result["measurement_completed"] is False
    assert result["qualified_safety_count"] is None
    assert result["functional_phase_status"] == "functional_phase_evidence_observed"
    for arm in result["arms"]:
        report = arm["original_cost_report"]
        assert (
            report["expected_decisions"]
            == report["native_decisions"]
            == report["signed_decisions"]
            == 3
        )
        if arm["mode"] == "off":
            assert report["observer_input_records"] is None
        elif arm["mode"] == "on":
            assert report["observer_input_records"] == 5
            assert report["observer_unprocessed_decisions"] == 0
        else:
            assert report["observer_input_records"] == 3
            assert report["observer_unprocessed_decisions"] == 2
            assert report["observer_exit"] == -9
            assert report["processes"]["observer"]["cpu_seconds"] is None
        if not arm["instrumented"]:
            assert arm["phase_reports"] == {}
            continue
        phases = arm["phase_reports"]
        gate = arm["functional_phase_gate"]
        assert gate["accepted"] is True
        if gate["status"] == "intended_fault_interruption_prefix_observed":
            assert arm["arm_id"] == "instrumented_faulted"
            assert arm["phase_collection_status"] == "incomplete"
            assert arm["missing_required_phase_calls"] == ["observer.observation"]
            assert phases["observer"]["phases"]["observation"]["elapsed_ns"] is None
        else:
            assert gate["status"] == "required_phase_calls_observed"
            assert arm["phase_collection_status"] == "required_phase_calls_observed"
            assert arm["missing_required_phase_calls"] == []
        for role in ("signer", "witness", "controller"):
            assert phases[role]["complete_spans"]
        assert (
            phases["signer"]["phases"]["source_sign"]["elapsed_ns"]["observed_calls"]
            == 6
        )
        assert (
            phases["signer"]["phases"]["input_receive"]["elapsed_ns"]["observed_calls"]
            > 0
        )
        assert (
            phases["controller"]["phases"]["source_closure_wait"]["elapsed_ns"][
                "observed_calls"
            ]
            > 0
        )
        assert (
            arm["controller_process_metrics"]["scope"]
            == "mixed_controller_harness_witness_and_instrumentation"
        )
        if arm["mode"] != "off":
            assert phases["observer"]["active_window_finalization_wait_ns"] is None
            assert phases["observer"]["normal_return_confirmed"] is False
