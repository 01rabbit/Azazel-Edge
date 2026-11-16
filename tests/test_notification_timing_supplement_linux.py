"""Dedicated two NEW supplemental cases; never a rerun of the first base pilot."""

import json
import os
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0
    or not os.environ.get("EDGE_NOTIFICATION_SUPPLEMENT_PUBLIC_DIR"),
    reason="explicit ordinary-UID offline supplemental harness required")


def test_two_fresh_child_global_slow_fsync_cases_preserve_originals():
    from run_notification_timing_supplement import run
    from p0_handoff_attribution_lab import SUPPLEMENT_CASES
    from azazel_edge.notify.core_decisions import CORE_DECISION_SOURCE

    output = Path(os.environ["EDGE_NOTIFICATION_SUPPLEMENT_PUBLIC_DIR"])
    result = run(output)  # All originals/partial outcomes persist BEFORE assertions.
    assert not result["blockers"], result["blockers"]
    assert tuple(row["case_id"] for row in result["cases"]) == SUPPLEMENT_CASES
    pids = set()
    for case in result["cases"]:
        identifier = case["case_id"]
        child = case["child"]
        assert child["returncode"] == 0 and child["timed_out"] is False
        assert child["pid"] not in pids
        pids.add(child["pid"])
        boundary = child["bootstrap"]["boundary"]
        assert boundary["uid"] == os.geteuid() and boundary["no_new_privileges"] == 1
        assert all(int(value, 16) == 0 for value in boundary["capabilities"].values())
        original = json.loads((output / (identifier + ".original-result.json")).read_bytes())
        assert original["collection_errors"] == {}
        assert original["assigned_events"] == original["completed_submissions"] == 120
        metrics = original["metrics"]
        assert metrics["core_recorded_total"] + metrics["core_record_handoff_dropped_total"] == 120
        assert metrics["core_record_failed_total"] == 0
        control = original["control"]
        assert control["chain_verification"]["ok"] is True
        assert control["original_ready_observed_ns"] <= control["global_fsync_installed_ns"]
        assert control["global_fsync_restore_begin_ns"] <= control["global_fsync_restore_end_ns"]
        assert control["global_fsync_restore_end_ns"] <= control["recorder_stop_begin_ns"]
        assert control["global_fsync_calls"]
        assert all(row["outcome"] == "returned" and row["requested_wait_ns"] == 50_000_000 for row in control["global_fsync_calls"])
        assert len(control["legacy_intervals"]) == 120
        assert all(row["elapsed_seconds"] == row["end_monotonic_seconds"] - row["start_monotonic_seconds"] for row in control["legacy_intervals"])
        index = json.loads((output / (identifier + ".event-index.json")).read_bytes())["events"]
        for row in index:
            base, offset = divmod(row["index"], 20)
            assert row["event"]["enforcement"]["trace_id"] == f"trace-{base}-{offset}"
            assert row["event"]["normalized"]["sid"] == 9_400_000 + base * 100 + offset
        audit = [json.loads(line) for line in original["audit_raw"].splitlines()]
        assert sum(row["source"] == CORE_DECISION_SOURCE for row in audit) == metrics["core_recorded_total"]
        if metrics["core_record_handoff_dropped_total"]:
            queue = [json.loads(line) for line in original["queue_raw"].splitlines()]
            assert any(row.get("event") == "core_record_loss" and row.get("core_record_handoff_dropped_total") == metrics["core_record_handoff_dropped_total"] for row in queue)
        analysis = json.loads((output / (identifier + ".analysis.json")).read_bytes())
        assert analysis["historical_cause"] == "UNKNOWN" and analysis["qualified_safety_count"] is None
        if case["recipe"]["instrumented"]:
            assert analysis["normal_return_confirmed"] is True, analysis["reasons"]
            assert analysis["completed_spans"] and analysis["event_index_valid"] is True
        else:
            assert case["artifacts"]["trace.jsonl"] is None
    assert result["historical_cause"] == "UNKNOWN" and result["performance_acceptance"] is False
