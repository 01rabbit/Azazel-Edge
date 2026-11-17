"""Six actual finite-object controls; never old safety or deadline coverage."""

import errno
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux" or os.geteuid() == 0
    or not os.environ.get("EDGE_CAPTURE_CLOSE_PUBLIC_DIR"),
    reason="explicit offline ordinary-UID capture harness required")


def test_six_finite_capture_controls_keep_kernel_and_unknown_evidence():
    from run_capture_close import run
    from capture_close_lab import CASES

    output = Path(os.environ["EDGE_CAPTURE_CLOSE_PUBLIC_DIR"])
    result = run(output)  # All assigned originals precede these assertions.
    assert not result["blockers"], result["blockers"]
    assert tuple(case["case_id"] for case in result["cases"]) == CASES
    for case in result["cases"]:
        identifier = case["case_id"]
        assert case["expected_disposition"] is True
        directory = output / identifier
        refs = {}
        for name in ("plan", "enrollment", "admission", "terminal", "collector"):
            raw = (directory / (name + ".json")).read_bytes()
            assert case["expected"][name + "_sha256"] == hashlib.sha256(raw).hexdigest()
            refs[name] = json.loads(raw)
        capture = (directory / "capture.raw").read_bytes()
        assert case["expected"]["capture_sha256"] == hashlib.sha256(capture).hexdigest()
        plan, admission, terminal, collector = (refs[name] for name in ("plan", "admission", "terminal", "collector"))
        enrollment = refs["enrollment"]
        assert enrollment["finished_ns"] <= min(row["attempt_started_ns"] for row in admission["attempts"])
        assert len({plan[name]["pid"] for name in ("controller_identity", "writer_identity", "collector_identity")}) == 3
        for identity in (plan["controller_identity"], plan["writer_identity"], plan["collector_identity"]):
            assert identity["uid"] == os.geteuid()
        assert admission["C"]["admitted_ids"] == [f"a{index:02}" for index in range(16)]
        assert [row["id"] for row in admission["late_controls"]] == ["late0", "late1"]
        for late in admission["late_controls"]:
            assert late["gate_id"] == plan["gate_id"] and late["gate_token"] == plan["gate_token"]
            assert late["poll_before_returncode"] is late["poll_after_returncode"] is None
            assert admission["C"]["finished_ns"] <= late["poll_before_ns"] <= late["started_ns"] <= late["finished_ns"] <= late["poll_after_ns"]
        analysis = case["analysis"]
        assert analysis["qualified_safety_count"] is None
        assert all(value is None for value in analysis["old_category_counts"].values())
        assert all(analysis[name] is False for name in ("whole_window_coverage", "comparison_qualified", "production_admission", "resume_authorized"))
        assert analysis["upstream_produced"] is analysis["upstream_dropped"] is analysis["runtime_inflight"] is None
        if identifier == "seal_busy":
            assert terminal["S"]["result"] == "failed" and terminal["S"]["errno"] == errno.EBUSY
            assert collector["object_before"]["size"] > 0 and collector["complete"] is False
            assert capture == b""  # Refused read is UNKNOWN, never a captured-zero count.
            assert analysis["terminal_missing_count"] is None
            continue
        assert terminal["S"]["result"] == "sealed" and terminal["S"]["seals_after"] == 15
        assert terminal["post_seal_write"]["errno"] == errno.EPERM
        assert collector["access_mode"] == 0 and collector["seals_before"] == collector["seals_after"] == 15
        assert collector["complete"] is True
        if identifier == "clean":
            assert analysis["complete_finite_capture"] and analysis["finite_accounting_complete"]
            assert analysis["terminal_missing_count"] == 0 and len(analysis["known_matching_ids"]) == 16
        elif identifier == "explicit_loss":
            assert analysis["finite_accounting_complete"] and not analysis["complete_finite_capture"]
            assert analysis["terminal_missing_ids"] == ["a07"] and analysis["terminal_missing_count"] == 1
            assert len(analysis["known_matching_ids"]) == 15
        elif identifier == "abrupt_writer":
            assert terminal["W"]["returncode"] == 7 and terminal["W"]["waited"] is True
            assert terminal["D"]["footer_sha256"] is None
            assert len(analysis["known_matching_ids"]) == 8 and analysis["terminal_missing_count"] is None
        elif identifier == "missing_loss_counter":
            footer = json.loads(capture.splitlines()[-1])
            assert "declared_lost" not in footer
            assert len(analysis["known_matching_ids"]) == 16 and analysis["terminal_missing_count"] is None
        elif identifier == "late_bypass":
            assert "late0" in analysis["unexpected_ids"]
            assert "late0" not in analysis["admitted_ids"] and not analysis["complete_finite_capture"]
