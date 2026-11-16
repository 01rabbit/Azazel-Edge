"""Actual ordinary-UID offline harness; scheduler absence is explicit, never skip."""

import json
import os
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0
    or not os.environ.get("EDGE_NOTIFICATION_TIMING_PUBLIC_DIR"),
    reason="explicit unprivileged offline notification harness required")


def test_fixed_notification_diagnostics_preserve_originals_and_unknowns():
    from run_notification_timing import run, process_boundary
    from p0_handoff_attribution_lab import PROTOCOL
    from azazel_edge.notify.core_decisions import CORE_DECISION_SOURCE

    boundary = process_boundary()
    assert boundary["no_new_privileges"] == 1
    assert all(int(value, 16) == 0 for value in boundary["capabilities"].values())
    output = Path(os.environ["EDGE_NOTIFICATION_TIMING_PUBLIC_DIR"])
    report = run(output)  # All public originals/report persist before assertions.
    protocol = json.loads(PROTOCOL.read_bytes())
    assert [case["case_id"] for case in report["cases"]] == [case["id"] for case in protocol["cases"]]
    assert report["historical_cause"] == "UNKNOWN" and report["qualified_safety_count"] is None
    assert not report["blockers"], report["blockers"]
    for case in report["cases"]:
        identifier = case["case_id"]
        original = json.loads((output / (identifier + ".original-result.json")).read_bytes())
        analysis = json.loads((output / (identifier + ".analysis.json")).read_bytes())
        control = original["control"]
        assert analysis["historical_cause"] == "UNKNOWN"
        assert all(analysis[name] is False for name in ("comparison_qualified", "whole_measurement_qualified", "production_admission", "resume_authorized"))
        if identifier == "scheduler_contention" and control["status"] == "unmeasured_scheduler_enablement":
            assert original["completed_submissions"] == 0 and original["metrics"] is None
            assert original["audit_raw"] is original["queue_raw"] is None
            assert case["artifacts"]["audit.raw"] is case["artifacts"]["queue.raw"] is None
            assert control["workload_started"] is False
            continue
        assert original["collection_errors"] == {}, original["collection_errors"]
        assert original["completed_submissions"] == original["assigned_events"] == case["recipe"]["events"]
        metric = original["metrics"]
        assert metric["core_recorded_total"] + metric["core_record_handoff_dropped_total"] == original["assigned_events"]
        assert metric["core_record_failed_total"] == 0
        assert control["chain_verification"]["ok"] is True
        audit = [json.loads(line) for line in original["audit_raw"].splitlines()]
        assert sum(row["source"] == CORE_DECISION_SOURCE for row in audit) == metric["core_recorded_total"]
        if metric["core_record_handoff_dropped_total"]:
            queue = [json.loads(line) for line in original["queue_raw"].splitlines()]
            assert any(row.get("event") == "core_record_loss" and row.get("core_record_handoff_dropped_total") == metric["core_record_handoff_dropped_total"] for row in queue)
        assert control["producers_joined"] and control["recorder_joined"] and control["relay_joined"]
        if identifier == "legacy_original":
            assert case["artifacts"]["trace.jsonl"] is None
        elif identifier == "trace_loss":
            assert control["recording_incomplete"] and control["recording_lost_rows"] > 0
            assert analysis["valid_prefix_rows"] > 0
        else:
            assert analysis["normal_return_confirmed"] is True, analysis["reasons"]
            assert analysis["event_index_valid"] is True
            assert analysis["completed_spans"]
        if identifier in ("fixture_delay", "logging_delay", "recorder_lock_delay", "blocking_wait_counterexample"):
            assert control["status"] == "observed_intervention"
            assert control["held_ns"] <= control["release_ns"] <= control["target_return_ns"]
            assert control["target_attempt_ns"] <= control["target_entered_ns"] <= control["target_return_ns"]
        if identifier == "unrelated_lock_negative":
            assert control["held_object_id"] != control["target_object_id"]
            assert control["target_returned_before_unrelated_release"] is True
        if identifier in ("writer_fsync_hold", "logging_delay"):
            assert control["receivers_completed_while_fsync_held"] is True
            assert control["completed_while_held"] == 120
            assert metric["core_record_handoff_dropped_total"] > 0
            assert control["writer_fsync_entered_ns"] <= control["writer_fsync_held_ns"] <= control["writer_fsync_release_ns"] <= control["writer_fsync_return_ns"]
        if identifier == "inline_save_negative":
            assert control["injected_audit_rows"] == 1
            assert sum(row.get("synthetic_injected") is True for row in audit) == 1
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["files"]["report.json"] is not None
