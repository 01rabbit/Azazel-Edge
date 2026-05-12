from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from azazel_edge.knowledge.attack_mapping import load_attack_mapping, map_attack_techniques


class AttackMappingV1Tests(unittest.TestCase):
    def test_load_mapping_requires_rules_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "bad.yaml"
            p.write_text("version: x\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_attack_mapping(p)

    def test_map_returns_unmapped_fallback(self) -> None:
        mapping = {"version": "x", "rules": []}
        payload = {"attrs": {"sid": 1, "attack_type": "unknown", "category": "unknown"}}
        rows = map_attack_techniques(payload, mapping)
        self.assertEqual(rows[0]["technique_id"], "unmapped")

    def test_conflicting_mappings_keep_higher_confidence(self) -> None:
        mapping = {
            "version": "x",
            "rules": [
                {
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                    "tactic": "credential-access",
                    "confidence": 60,
                    "sid": [1001],
                    "attack_type_contains": ["login"],
                    "category_contains": [],
                    "service_contains": [],
                },
                {
                    "technique_id": "T1110",
                    "technique_name": "Brute Force",
                    "tactic": "credential-access",
                    "confidence": 80,
                    "sid": [1001],
                    "attack_type_contains": ["login"],
                    "category_contains": [],
                    "service_contains": [],
                },
            ],
        }
        payload = {"attrs": {"sid": 1001, "attack_type": "login attempt", "category": "attempted-admin"}}
        rows = map_attack_techniques(payload, mapping)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["confidence"], 80)


if __name__ == "__main__":
    unittest.main()

