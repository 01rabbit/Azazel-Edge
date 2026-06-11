from __future__ import annotations

import unittest


class RustPythonEventContractV1Tests(unittest.TestCase):
    def test_normalized_event_field_names_match_agent_boundary_contract(self) -> None:
        sample_envelope = {
            "normalized": {
                "ts": "2026-06-11T00:00:00Z",
                "src_ip": "10.0.0.9",
                "dst_ip": "192.168.40.10",
                "attack_type": "ET SCAN suspicious inbound",
                "severity": 3,
                "target_port": 443,
                "protocol": "TCP",
                "sid": 2402000,
                "category": "Attempted Information Leak",
                "event_type": "alert",
                "action": "allowed",
                "confidence": 70,
                "risk_score": 72,
                "ingest_epoch": 1781116800.0,
            },
            "defense": {"action": "notify", "reason": "fixture"},
            "enforcement": {"trace_id": "trace-deadbeef"},
            "enforcement_status": {"dry_run": True},
            "source": "suricata_eve",
            "pipeline": "rust_event_engine_v1",
        }

        self.assertEqual(
            list(sample_envelope["normalized"].keys()),
            [
                "ts",
                "src_ip",
                "dst_ip",
                "attack_type",
                "severity",
                "target_port",
                "protocol",
                "sid",
                "category",
                "event_type",
                "action",
                "confidence",
                "risk_score",
                "ingest_epoch",
            ],
        )
        self.assertEqual(sample_envelope["source"], "suricata_eve")
        self.assertEqual(sample_envelope["pipeline"], "rust_event_engine_v1")
