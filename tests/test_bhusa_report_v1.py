from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "bin" / "azazel-edge-bhusa-report"
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaReportV1Tests(unittest.TestCase):
    def test_report_writes_markdown_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            report_dir = Path(tmp) / "report"
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
                    str(REPORT),
                    "--record-path",
                    str(record_path),
                    "--report-dir",
                    str(report_dir),
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
            self.assertTrue((report_dir / "REPORT.md").exists())
            self.assertTrue((report_dir / "report.json").exists())
            self.assertTrue((report_dir / "status.json").exists())
            markdown = (report_dir / "REPORT.md").read_text(encoding="utf-8")
            self.assertIn("# BHUSA 2026 Readiness Report", markdown)
            self.assertIn("Freeze gate: PASS", markdown)
            self.assertIn("Fallback drill runs", markdown)
            self.assertIn("## Child Issue State", markdown)


if __name__ == "__main__":
    unittest.main()
