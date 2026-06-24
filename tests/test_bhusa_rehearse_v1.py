from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaRehearseV1Tests(unittest.TestCase):
    def test_record_appends_rehearsal_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            result = subprocess.run(
                [
                    str(REHEARSE),
                    "record",
                    "--variant",
                    "full",
                    "--duration-sec",
                    "312.5",
                    "--fallback-drill",
                    "--clear-after",
                    "--notes",
                    "full booth run",
                    "--record-path",
                    str(record_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["record"]["variant"], "full")
            self.assertEqual(payload["record"]["scenario_id"], "mixed_correlation_demo")
            self.assertEqual(payload["record"]["trace_id"], "demo:mixed_correlation_demo")
            self.assertEqual(payload["record"]["presenter_duration_sec"], 312.5)
            self.assertTrue(payload["record"]["fallback_drill"])
            self.assertEqual(payload["record"]["result"], "pass")
            self.assertTrue(payload["record"]["booth_verify"]["ok"])
            self.assertTrue(payload["record"]["clear_after"]["ok"])

            rows = [json.loads(line) for line in record_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["notes"], "full booth run")

    def test_summary_reports_counts_and_averages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            subprocess.run(
                [
                    str(REHEARSE),
                    "record",
                    "--variant",
                    "visitor-90s",
                    "--duration-sec",
                    "88",
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
                    "visitor-90s",
                    "--duration-sec",
                    "92",
                    "--fallback-drill",
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
                [str(REHEARSE), "summary", "--record-path", str(record_path), "--json"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["total_runs"], 2)
            self.assertEqual(payload["pass_runs"], 2)
            self.assertEqual(payload["fallback_drill_runs"], 1)
            self.assertEqual(len(payload["variants"]), 1)
            variant = payload["variants"][0]
            self.assertEqual(variant["variant"], "visitor-90s")
            self.assertEqual(variant["runs"], 2)
            self.assertEqual(variant["passes"], 2)
            self.assertEqual(variant["fallback_drills"], 1)
            self.assertEqual(variant["avg_presenter_duration_sec"], 90.0)


if __name__ == "__main__":
    unittest.main()
