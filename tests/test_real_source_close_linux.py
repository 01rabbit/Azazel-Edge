"""Mandatory three actual signed Source scopes, separate from native truth."""

import json
import os
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0
    or not os.environ.get("EDGE_REAL_SOURCE_CLOSE_PUBLIC_DIR"), reason="explicit existing Root offline fixture required")


def test_original_signed_source_close_loss_and_abrupt_prefix_are_preserved():
    from run_real_source_close import run
    from real_source_close_lab import CASES
    output = Path(os.environ["EDGE_REAL_SOURCE_CLOSE_PUBLIC_DIR"])
    report = run(output)  # Originals, forensic logs, report and manifest precede assertions.
    assert report["blockers"] == [], report["blockers"]
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["inventory_errors"] == [] and manifest["missing_or_errors"] == {}
    assert [row["case_id"] for row in report["cases"]] == list(CASES)
    for row in report["cases"]:
        assert row["expected_disposition"] is True
        result = row["analysis"]
        assert result["native_registry_authentication"] == "not_exercised"
        assert result["actual_native_execution"] is False and result["actual_native_terminal_verified"] is None
        assert result["source_immutability"] is False and result["old_evaluation_modified"] is False
        assert result["independent_read_verified"] is True
        assert result["original_witness_evaluation"]["witness_prefix_authenticated"] is True
        assert result["original_witness_evaluation"]["source_checkpoint"]["seq"] == 4
        assert len(result["known_signed_ids"]) == {"clean": 8, "explicit_loss": 7, "abrupt_writer": 4}[row["case_id"]]
        state = json.loads((output / row["case_id"] / "case-state.json").read_bytes())
        assert state["stage_facts"]["collector_private_probes_denied"] == [True] * 4
        for role, uid in (("producer", 1000), ("observer", 65534), ("collector", 61002)):
            observed = state["actor_boundaries"][role]
            binding = state["clock_provenance"][role]
            assert binding["identity"] == observed["identity"]
            assert binding["clock_provenance"]["matched"] is True
            assert binding["clock_provenance"]["cross_uid_namespace_lookup"] == "NOT_ATTEMPTED"
            assert observed["identity"]["uid"] == uid
            assert observed["groups"] == [] and observed["no_new_privileges"] == 1
            assert all(int(value, 16) == 0 for value in observed["capabilities"].values())
        controller = json.loads((output / row["case_id"] / "controller.json").read_bytes())
        assert controller["prefix_selection"]["finished_ns"] <= controller["C"]["started_ns"]
        assert controller["W"]["finished_ns"] <= controller["final_selection"]["started_ns"]
        assert all(late["poll_before_returncode"] is late["poll_after_returncode"] is None for late in controller["late_controls"])
        if row["case_id"] == "abrupt_writer":
            assert controller["W"]["returncode"] == 7 and controller["writer_close"] is None
            assert result["test_gate_missing_count"] is None and result["complete_assigned_test_capture"] is False
        else:
            assert controller["W"]["returncode"] == 0
            assert result["original_source_evaluation"]["normal_terminal_verified"] is True
            assert controller["post_close_append"]["exception_type"] == "OutcomeJournalError"
            assert controller["post_close_append"]["source_unchanged"] is True
