from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "bin" / "azazel-edge-bhusa-verify"


class BhusaVerifyV1Tests(unittest.TestCase):
    def test_json_verification_passes_without_service_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            explanations_path = Path(tmp) / "demo-explanations.jsonl"
            audit_path = Path(tmp) / "demo-audit.jsonl"
            result = subprocess.run(
                [
                    str(VERIFY),
                    "--skip-services",
                    "--explanations-path",
                    str(explanations_path),
                    "--audit-path",
                    str(audit_path),
                    "--json",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["scenario_id"], "mixed_correlation_demo")
            self.assertEqual(payload["trace_id"], "demo:mixed_correlation_demo")
            self.assertEqual(payload["demo"]["mode"], "deterministic_replay")
            self.assertFalse(payload["demo"]["ai_used"])
            self.assertTrue(payload["demo"]["local_only"])
            self.assertTrue(payload["demo"]["offline_demo"])
            self.assertEqual(payload["demo"]["action"], "throttle")
            self.assertEqual(payload["audit_review"]["selected_action"], "throttle")
            self.assertTrue(payload["audit_review"]["schema_valid"])
            self.assertTrue(payload["audit_review"]["chain_ok"])
            self.assertGreater(payload["audit_review"]["chain_entries"], 0)

    def test_text_verification_reports_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            explanations_path = Path(tmp) / "demo-explanations.jsonl"
            audit_path = Path(tmp) / "demo-audit.jsonl"
            result = subprocess.run(
                [
                    str(VERIFY),
                    "--skip-services",
                    "--explanations-path",
                    str(explanations_path),
                    "--audit-path",
                    str(audit_path),
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            output = result.stdout
            self.assertIn("BHUSA 2026 BOOTH VERIFY", output)
            self.assertIn("scenario: mixed_correlation_demo", output)
            self.assertIn("trace_id: demo:mixed_correlation_demo", output)
            self.assertIn("result: PASS", output)


if __name__ == "__main__":
    unittest.main()
