from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "bin" / "azazel-edge-scenario-replay"
AUDIT_REVIEW = ROOT / "bin" / "azazel-edge-audit-review"


class BhusaAuditWalkthroughV1Tests(unittest.TestCase):
    def test_demo_run_emits_audit_review_artifact_paths(self) -> None:
        result = subprocess.run(
            [str(RUNNER), "run", "mixed_correlation_demo"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            check=True,
        )
        payload = json.loads(result.stdout)
        execution = payload["result"]["execution"]
        self.assertEqual(execution["trace_id"], "demo:mixed_correlation_demo")
        self.assertEqual(
            execution["explanations_path"], "/tmp/azazel-edge-demo-explanations.jsonl"
        )
        self.assertEqual(
            execution["audit_path"], "/tmp/azazel-edge-demo-triage-audit.jsonl"
        )

    def test_compact_audit_review_works_after_demo_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            explanations_path = Path(tmp) / "demo-explanations.jsonl"
            audit_path = Path(tmp) / "demo-audit.jsonl"
            env = {
                **os.environ,
                "AZAZEL_DEMO_EXPLANATIONS_PATH": str(explanations_path),
                "AZAZEL_DEMO_AUDIT_PATH": str(audit_path),
            }
            subprocess.run(
                [str(RUNNER), "run", "mixed_correlation_demo"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env=env,
                check=True,
            )
            result = subprocess.run(
                [
                    str(AUDIT_REVIEW),
                    "--explanations-path",
                    str(explanations_path),
                    "--audit-path",
                    str(audit_path),
                    "--trace-id",
                    "demo:mixed_correlation_demo",
                    "--compact",
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                check=True,
            )
            output = result.stdout.strip()
            self.assertIn("trace=demo:mixed_correlation_demo", output)
            self.assertIn("action=throttle", output)
            self.assertIn("policy=soc-policy-default-v1", output)
            self.assertIn("schema:OK", output)
            self.assertIn("chain:OK(", output)


if __name__ == "__main__":
    unittest.main()
