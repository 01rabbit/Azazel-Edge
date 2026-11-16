"""One existing actual matrix; nonempty windows remain explicitly SYNTHETIC."""

import os
import json
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="Root disposable offline Linux and matching cached core required",
)


def test_actual_cost_and_synthetic_windows_remain_separate(tmp_path):
    from run_window_cost_completion import run

    output = Path(
        os.environ.get(
            "EDGE_WINDOW_COST_PUBLIC_DIR", str(tmp_path / "window-cost-public")
        )
    )
    result = run(output)
    publication = json.loads(
        (output / "publication/publication-index.json").read_bytes()
    )
    assert publication["status"] == "complete", publication["errors"]
    assert publication["planned_files"] == publication["copied_files"] == 99
    assert publication["errors"] == []
    actual = result["original_normal_clock_evaluation"]
    assert actual["both_on_stops_verified"] is True
    assert actual["original_load_evaluation"]["all_load_gates_valid"] is True
    assert actual["original_load_evaluation"]["marker_semantic_parity"] is True
    assert (
        result["actual_applied_window_status"] == "unavailable_under_existing_authority"
    )
    assert result["actual_lifecycle"]["applied_window_exercised"] is False
    assert result["actual_lifecycle"]["expiry_commit_cost"] is None
    assert result["actual_lifecycle"]["pending_stop_loss_cost"] is None
    assert result["actual_lifecycle"]["active_deadline_wait"] is None
    stops = {
        item["arm_id"]: item for item in result["actual_lifecycle"]["normal_stops"]
    }
    for arm_id in ("original_on", "instrumented_on"):
        assert stops[arm_id]["replay"]["normal_end_verified"] is True
        assert stops[arm_id]["published_evaluation_matches"] is True
    on_cost = next(
        item
        for item in result["actual_cost_by_arm_role"]
        if item["arm_id"] == "instrumented_on" and item["role"] == "observer"
    )
    assert on_cost["status"] in ("replayed_descriptive_phase_calls", "partial_prefix")
    assert on_cost["phase_report"]["normal_return_confirmed"] is True
    assert on_cost["phase_report"]["complete_spans"]
    if on_cost["status"] == "partial_prefix":
        assert on_cost["reasons"]
        assert on_cost["full_interval_cpu_seconds"] is None
        assert on_cost["full_interval_read_bytes"] is None
        assert on_cost["full_interval_write_bytes"] is None
    expected_cases = {
        "pre_deadline_not_committed",
        "expiry_commit",
        "stop_pending_loss",
        "duplicate_does_not_reopen",
        "commit_failure_loss",
        "witness_close_failure",
        "recording_failure_prefix",
    }
    assert len(result["synthetic_window_cases"]) == len(expected_cases)
    cases = {case["id"]: case for case in result["synthetic_window_cases"]}
    assert set(cases) == expected_cases
    assert (
        "synthetic_fixed_case_coverage_incomplete_or_changed" not in result["blockers"]
    )
    assert cases["expiry_commit"]["journal_summary"]["committed"] == 1
    assert cases["stop_pending_loss"]["journal_summary"]["lost"] == 1
    assert cases["stop_pending_loss"]["outcomes"] == []
    assert all(
        case["evidence_kind"] == "SYNTHETIC_RECORDED_TEST_ONLY"
        for case in cases.values()
    )
    assert all(
        case["status"]
        == (
            "partial_prefix"
            if case["id"] == "recording_failure_prefix"
            else "withheld"
            if case["id"] == "witness_close_failure"
            else "recorded_synthetic_case"
        )
        for case in cases.values()
    )
    witness = cases["witness_close_failure"]
    assert witness["control_receipt"] is None
    assert witness["journal_summary"]["normal_close_rows"] == 0
    assert witness["observed_lifecycle"] == "unavailable"
    assert "synthetic_final_journal_status_differs_from_original" in witness["reasons"]
    assert (
        result["whole_measurement_qualified"] is result["comparison_qualified"] is False
    )
    assert result["qualified_safety_count"] is None
    assert (output / "original-normal-clock/report.json").is_file()
    assert (output / "window-cost-completion.json").is_file()
