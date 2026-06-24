from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREP = ROOT / "bin" / "azazel-edge-bhusa-prep"
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaPrepV1Tests(unittest.TestCase):
    def test_ops_pack_generates_bundle_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "ops"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "ops-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force", "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue((out_root / "offline-bundle" / "INDEX.md").exists())
            self.assertTrue((out_root / "report" / "REPORT.md").exists())

    def test_freeze_pack_generates_archive_and_freeze_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "freeze"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "freeze-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force", "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue((out_root / "archive" / "ARCHIVED_COMMANDS.md").exists())
            self.assertTrue((out_root / "freeze-record" / "FREEZE_RECORD.md").exists())

    def test_full_pack_generates_both_ops_and_freeze_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "full"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "full-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force", "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["mode"], "full-pack")
            self.assertTrue((out_root / "ops-pack" / "offline-bundle" / "INDEX.md").exists())
            self.assertTrue((out_root / "ops-pack" / "report" / "REPORT.md").exists())
            self.assertTrue((out_root / "freeze-pack" / "archive" / "ARCHIVED_COMMANDS.md").exists())
            self.assertTrue((out_root / "freeze-pack" / "freeze-record" / "FREEZE_RECORD.md").exists())

    def test_repo_sync_refreshes_repo_side_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "repo-sync"
            for duration in ("310", "320"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            result = subprocess.run(
                [str(PREP), "repo-sync", "--record-path", str(record_path), "--output-root", str(out_root), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["mode"], "repo-sync")
            self.assertEqual(payload["output_root"], str(out_root))
            self.assertTrue(payload["status"]["status_doc_path"].endswith("15-status.md"))
            self.assertTrue(payload["sync_links"]["written"])
            self.assertTrue(payload["parent_comment"]["written"])
            self.assertTrue(payload["progress_comment"]["written"])

    def test_repo_sync_text_output_reports_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "repo-sync"
            for duration in ("310", "320"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            result = subprocess.run(
                [str(PREP), "repo-sync", "--record-path", str(record_path), "--output-root", str(out_root)],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            output = result.stdout
            self.assertIn("BHUSA 2026 PREP", output)
            self.assertIn("mode: repo-sync", output)
            self.assertIn("status_doc_path:", output)
            self.assertIn("parent_comment_path:", output)

    def test_daily_pack_refreshes_repo_state_and_generates_ops_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "daily"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "daily-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force", "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["mode"], "daily-pack")
            self.assertTrue(payload["repo_sync"]["status"]["status_doc_path"].endswith("15-status.md"))
            self.assertTrue((out_root / "ops-pack" / "offline-bundle" / "INDEX.md").exists())
            self.assertTrue((out_root / "ops-pack" / "report" / "REPORT.md").exists())

    def test_daily_pack_text_output_reports_repo_and_ops_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "daily"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "daily-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            output = result.stdout
            self.assertIn("mode: daily-pack", output)
            self.assertIn("status_doc_path:", output)
            self.assertIn("bundle_dir:", output)
            self.assertIn("report_dir:", output)

    def test_candidate_pack_generates_repo_ops_freeze_and_gate_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "candidate"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "candidate-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force", "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["mode"], "candidate-pack")
            self.assertTrue(payload["repo_sync"]["status"]["status_doc_path"].endswith("15-status.md"))
            self.assertIsNotNone(payload["repo_sync"]["status"]["freeze_check"])
            self.assertTrue(payload["repo_sync"]["status"]["freeze_check"]["ok"])
            self.assertEqual(len(payload["repo_sync"]["status"]["freeze_check"]["offline_doc_checks"]), 1)
            self.assertIn("candidate_summary", payload)
            self.assertTrue(payload["candidate_summary"]["freeze_gate_ok"])
            self.assertEqual(payload["candidate_summary"]["open_child_issue_count"], 8)
            self.assertFalse(payload["candidate_summary"]["ready_for_freeze"])
            self.assertTrue((out_root / "ops-pack" / "offline-bundle" / "INDEX.md").exists())
            self.assertTrue((out_root / "freeze-pack" / "freeze-record" / "FREEZE_RECORD.md").exists())
            self.assertTrue(payload["freeze_gate"]["ok"])

    def test_candidate_pack_text_output_reports_freeze_gate_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            out_root = Path(tmp) / "candidate"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [str(REHEARSE), "record", "--variant", "full", "--duration-sec", duration, "--record-path", str(record_path), "--json"],
                    capture_output=True, text=True, cwd=str(ROOT), check=True
                )
            subprocess.run(
                [str(REHEARSE), "record", "--variant", "fallback-drill", "--duration-sec", "95", "--record-path", str(record_path), "--json"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            result = subprocess.run(
                [str(PREP), "candidate-pack", "--record-path", str(record_path), "--output-root", str(out_root), "--force"],
                capture_output=True, text=True, cwd=str(ROOT), check=True
            )
            output = result.stdout
            self.assertIn("mode: candidate-pack", output)
            self.assertIn("archive_dir:", output)
            self.assertIn("freeze_record_dir:", output)
            self.assertIn("freeze_gate_ok:", output)
            self.assertIn("ready_for_freeze:", output)
            self.assertIn("open_child_issue_count:", output)
            self.assertIn("blocker_count:", output)


if __name__ == "__main__":
    unittest.main()
