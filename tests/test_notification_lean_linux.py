"""Three fresh ordinary-UID assignments; descriptive evidence, no latency pass."""

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0
    or not os.environ.get("EDGE_NOTIFICATION_LEAN_PUBLIC_DIR"),
    reason="explicit offline ordinary-UID lean study required")


def test_three_assigned_profiles_preserve_originals_and_deferred_flush():
    from run_notification_lean import run
    from azazel_edge.notify.core_decisions import CORE_DECISION_SOURCE

    output = Path(os.environ["EDGE_NOTIFICATION_LEAN_PUBLIC_DIR"])
    result = run(output)  # Retain every assigned outcome before assertions.
    assert not result["blockers"], result["blockers"]
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["inventory_errors"] == []
    assert manifest["source"]["head"] == os.environ["EDGE_NOTIFICATION_SOURCE_HEAD"]
    assert manifest["source"]["tree"] == os.environ["EDGE_NOTIFICATION_SOURCE_TREE"]
    assert [entry["arm"]["id"] for entry in result["arms"]] == ["original", "v1", "deferred"]
    instances = set()
    for entry in result["arms"]:
        arm, child = entry["arm"], entry["child"]
        assert arm["events"] == 120 and arm["producers"] == 6
        assert child["returncode"] == 0 and not child["timed_out"]
        assert not child["binding_errors"] and child["stdout_decode_error"] is None
        boundary = child["bootstrap"]["boundary"]
        assert boundary["uid"] == os.geteuid() and boundary["no_new_privileges"] == 1
        assert all(int(value, 16) == 0 for value in boundary["capabilities"].values())
        identity = boundary["identity"]
        assert identity["pid"] == child["pid"]
        instance = (identity["pid"], identity["process_start_ticks"])
        assert instance not in instances
        instances.add(instance)
        directory = output / arm["id"]
        prefix = arm["fixture_case"]
        original_raw = (directory / (prefix + ".original-result.json")).read_bytes()
        index_raw = (directory / (prefix + ".event-index.json")).read_bytes()
        assert entry["expected"]["original_result_sha256"] == hashlib.sha256(original_raw).hexdigest()
        assert entry["expected"]["event_index_sha256"] == hashlib.sha256(index_raw).hexdigest()
        original = json.loads(original_raw)
        assert original["collection_errors"] == {}
        assert original["assigned_events"] == original["completed_submissions"] == 120
        metrics, control = original["metrics"], original["control"]
        assert metrics["core_recorded_total"] + metrics["core_record_handoff_dropped_total"] == 120
        assert metrics["core_record_failed_total"] == 0
        assert control["chain_verification"]["ok"] is True
        assert control["producers_joined"] and control["recorder_joined"] and control["relay_joined"]
        assert control["callbacks_quiescent"] is True
        assert control["original_ready_observed_ns"] <= control["global_fsync_installed_ns"]
        assert control["global_fsync_restore_end_ns"] <= control["recorder_stop_begin_ns"]
        assert len(control["legacy_intervals"]) == 120
        audit = [json.loads(line) for line in original["audit_raw"].splitlines()]
        assert sum(row["source"] == CORE_DECISION_SOURCE for row in audit) == metrics["core_recorded_total"]
        if metrics["core_record_handoff_dropped_total"]:
            queue = [json.loads(line) for line in original["queue_raw"].splitlines()]
            assert any(row.get("event") == "core_record_loss" and row.get("core_record_handoff_dropped_total") == metrics["core_record_handoff_dropped_total"] for row in queue)
        index = json.loads(index_raw)["events"]
        assert {row["index"] for row in index} == set(range(120))
        analysis = json.loads((directory / (prefix + ".analysis.json")).read_bytes())
        assert analysis["historical_cause"] == "UNKNOWN" and analysis["qualified_safety_count"] is None
        if arm["profile"] == "none":
            assert entry["artifacts"]["trace.jsonl"] is None
        else:
            assert analysis["normal_return_confirmed"] is True, analysis["reasons"]
            assert analysis["event_index_valid"] is True and analysis["completed_spans"]
        if arm["id"] == "deferred":
            assert control["global_fsync_calls"] is None
            assert control["recorder_descriptor_closed"] is True and control["recorder_close_error"] is None
            assert analysis["scheduler_per_phase"] is None
            assert analysis["finalization"]["start_ns"] <= analysis["finalization"]["end_ns"]
            assert analysis["finalization"]["elapsed_ns"] is not None
            assert any(span["phase"] == "audit_fsync" and span["object_id"] == "global.os.fsync.callsite.unclassified_fd" for span in analysis["completed_spans"])
        else:
            assert control["global_fsync_calls"]
            assert all(row["requested_wait_ns"] == 50_000_000 and row["outcome"] == "returned" for row in control["global_fsync_calls"])
    assert result["performance_acceptance"] is False and result["historical_cause"] == "UNKNOWN"
