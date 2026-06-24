from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "bin" / "azazel-edge-bhusa-archive"
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaArchiveV1Tests(unittest.TestCase):
    def test_archive_writes_report_commands_and_git_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            archive_dir = Path(tmp) / "archive"
            for duration in ("310", "320", "330"):
                subprocess.run(
                    [
                        str(REHEARSE),
                        "record",
                        "--variant",
                        "full",
                        "--duration-sec",
                        duration,
                        "--record-path",
                        str(record_path),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    check=True,
                )
            subprocess.run(
                [
                    str(REHEARSE),
                    "record",
                    "--variant",
                    "fallback-drill",
                    "--duration-sec",
                    "95",
                    "--record-path",
                    str(record_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )

            result = subprocess.run(
                [
                    str(ARCHIVE),
                    "--record-path",
                    str(record_path),
                    "--archive-dir",
                    str(archive_dir),
                    "--force",
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertTrue((archive_dir / "ARCHIVED_COMMANDS.md").exists())
            self.assertTrue((archive_dir / "git.json").exists())
            self.assertTrue((archive_dir / "archive.json").exists())
            self.assertTrue((archive_dir / "readiness-report" / "REPORT.md").exists())
            self.assertTrue((archive_dir / "readiness-report" / "status.json").exists())
            commands = (archive_dir / "ARCHIVED_COMMANDS.md").read_text(encoding="utf-8")
            self.assertIn("Expected compact output snippet", commands)
            self.assertIn("azazel-edge-demo run mixed_correlation_demo", commands)
            self.assertTrue(payload["status_json_path"].endswith("status.json"))


if __name__ == "__main__":
    unittest.main()
