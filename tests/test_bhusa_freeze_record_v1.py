from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FREEZE_RECORD = ROOT / "bin" / "azazel-edge-bhusa-freeze-record"
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaFreezeRecordV1Tests(unittest.TestCase):
    def test_freeze_record_writes_markdown_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "rehearsal.jsonl"
            record_dir = Path(tmp) / "freeze-record"
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
                    str(FREEZE_RECORD),
                    "--record-path",
                    str(record_path),
                    "--archive-dir",
                    str(archive_dir),
                    "--record-dir",
                    str(record_dir),
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
            self.assertTrue((record_dir / "FREEZE_RECORD.md").exists())
            self.assertTrue((record_dir / "freeze-record.json").exists())
            markdown = (record_dir / "FREEZE_RECORD.md").read_text(encoding="utf-8")
            self.assertIn("# BHUSA 2026 Freeze Record", markdown)
            self.assertIn("## Candidate", markdown)
            self.assertIn("## Archive", markdown)
            self.assertIn("## Readiness Snapshot", markdown)


if __name__ == "__main__":
    unittest.main()
