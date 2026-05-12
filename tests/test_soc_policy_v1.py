from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.policy import load_soc_policy


class SocPolicyV1Tests(unittest.TestCase):
    def test_load_soc_policy_requires_action_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.yaml"
            path.write_text("version: bad\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_soc_policy(path)

    def test_arbiter_emits_policy_hash_and_version(self) -> None:
        policy = {
            "version": "soc-policy-test-v1",
            "action_mapping": {
                "strong_soc": {"confidence_min": 60},
                "throttle": {"confidence_min": 60, "blast_min": 40},
                "redirect": {"suspicion_min": 90, "confidence_min": 80, "blast_min": 70},
                "isolate": {"suspicion_min": 95, "confidence_min": 90, "blast_min": 80},
            },
        }
        arbiter = ActionArbiter(policy=policy)
        noc = {
            "availability": {"label": "good"},
            "path_health": {"label": "good"},
            "device_health": {"label": "good"},
            "capacity_health": {"label": "good"},
            "client_inventory_health": {"label": "good"},
            "config_drift_health": {"label": "good"},
            "client_health": {"label": "good"},
            "summary": {},
            "evidence_ids": [],
        }
        soc = {
            "suspicion": {"score": 96, "label": "critical", "evidence_ids": []},
            "confidence": {"score": 92, "label": "critical", "evidence_ids": []},
            "technique_likelihood": {"score": 80, "label": "high", "evidence_ids": []},
            "blast_radius": {"score": 85, "label": "critical", "evidence_ids": []},
            "summary": {},
            "evidence_ids": [],
        }
        result = arbiter.decide(noc, soc)
        self.assertIn("policy", result)
        self.assertEqual(result["policy"]["version"], "soc-policy-test-v1")
        self.assertTrue(result["policy"]["hash"])


if __name__ == "__main__":
    unittest.main()

