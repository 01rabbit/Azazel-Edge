from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from azazel_edge.soc_policy_dry_run import run


class SocPolicyDryRunV1Tests(unittest.TestCase):
    def test_run_returns_policy_and_arbiter_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy = root / "soc_policy.yaml"
            policy.write_text(
                json.dumps(
                    {
                        "version": "soc-policy-test-v1",
                        "action_mapping": {
                            "strong_soc": {"confidence_min": 60},
                            "throttle": {"confidence_min": 60, "blast_min": 40},
                            "redirect": {"suspicion_min": 90, "confidence_min": 80, "blast_min": 70},
                            "isolate": {"suspicion_min": 95, "confidence_min": 90, "blast_min": 80},
                        },
                        "suppression_defaults": {},
                    }
                ),
                encoding="utf-8",
            )
            events = root / "events.jsonl"
            events.write_text(
                json.dumps(
                    {
                        "normalized": {
                            "ts": "2026-05-12T00:00:00Z",
                            "sid": 210001,
                            "severity": 1,
                            "attack_type": "test",
                            "category": "test",
                            "event_type": "alert",
                            "action": "allowed",
                            "protocol": "tcp",
                            "target_port": 443,
                            "src_ip": "10.0.0.8",
                            "dst_ip": "10.0.0.1",
                            "risk_score": 95,
                            "confidence": 90,
                            "ingest_epoch": 0.0,
                        }
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            payload = run(policy, events, limit=50)
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["policy_version"], "soc-policy-test-v1")
            self.assertIn("arbiter", payload)
            self.assertIn("action", payload["arbiter"])


if __name__ == "__main__":
    unittest.main()

