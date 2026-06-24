from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FREEZE_CHECK = ROOT / "bin" / "azazel-edge-bhusa-freeze-check"
REHEARSE = ROOT / "bin" / "azazel-edge-bhusa-rehearse"


class BhusaFreezeCheckV1Tests(unittest.TestCase):
    def test_freeze_check_passes_with_three_full_rehearsals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            offline_doc = Path(tmp) / "offline-bundle.txt"
            offline_doc.write_text("bundle", encoding="utf-8")

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
                    str(FREEZE_CHECK),
                    "--record-path",
                    str(record_path),
                    "--offline-doc-path",
                    str(offline_doc),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["full_rehearsal_variant"]["passes"], 3)
            self.assertEqual(payload["rehearsal_summary"]["fallback_drill_runs"], 1)
            self.assertTrue(all(item["ok"] for item in payload["doc_checks"]))
            self.assertTrue(all(item["ok"] for item in payload["offline_doc_checks"]))

    def test_freeze_check_fails_when_full_rehearsals_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            record_path = Path(tmp) / "bhusa-rehearsal.jsonl"
            subprocess.run(
                [
                    str(REHEARSE),
                    "record",
                    "--variant",
                    "full",
                    "--duration-sec",
                    "310",
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
                    str(FREEZE_CHECK),
                    "--record-path",
                    str(record_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["ok"])
            self.assertTrue(
                any("successful full rehearsals below threshold" in item for item in payload["failures"])
            )


if __name__ == "__main__":
    unittest.main()
