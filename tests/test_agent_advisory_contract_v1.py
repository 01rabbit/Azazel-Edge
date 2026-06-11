from __future__ import annotations

import unittest
from unittest.mock import patch

from azazel_edge_ai import agent


class _FixedScorer:
    def score_with_features(self, features: dict) -> tuple[int, list[str]]:
        return 72, [
            f"sid={features['suricata_sid']}",
            f"port={features['target_port']}",
        ]


class _FixedDecisionLayers:
    def enrich_with_second_pass(self, event: dict, advisory: dict) -> dict:
        return {
            "stage": "second_pass",
            "engine": "evidence_plane_soc_v1",
            "status": "completed",
            "soc": {"status": "medium", "reasons": ["fixture"]},
        }


class _NoopDecisionLogger:
    def log_decision(self, record: object) -> bool:
        return True


class AgentAdvisoryContractV1Tests(unittest.TestCase):
    def test_build_advisory_preserves_rust_event_fields_in_advisory(self) -> None:
        event = {
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

        with patch.object(agent, "SCORER", _FixedScorer()), patch.object(
            agent, "DECISION_LAYERS", _FixedDecisionLayers()
        ), patch.object(agent, "DECISION_LOGGER", _NoopDecisionLogger()), patch.object(
            agent, "_evaluate_correlation", return_value={"force_llm": False}
        ), patch.object(agent, "_metrics_inc"), patch.object(
            agent, "_LAST_RISK_SCORE", 0
        ), patch.object(
            agent, "_LAST_STATE_NAME", "NORMAL"
        ):
            advisory = agent._build_advisory(event)

        self.assertEqual(advisory["risk_score"], 72)
        self.assertEqual(advisory["trace_id"], "trace-deadbeef")
        self.assertEqual(advisory["risk_level"], "HIGH")
        self.assertEqual(advisory["attack_type"], "ET SCAN suspicious inbound")
        self.assertEqual(advisory["src_ip"], "10.0.0.9")
        self.assertEqual(advisory["dst_ip"], "192.168.40.10")
        self.assertEqual(advisory["target_port"], 443)
        self.assertEqual(advisory["suricata_severity"], 3)
        self.assertEqual(advisory["suricata_sid"], 2402000)
        self.assertEqual(advisory["score_engine"], "tactical_scorer_v1")
        self.assertEqual(advisory["second_pass"]["status"], "completed")
        self.assertEqual(advisory["correlation"], {"force_llm": False})

    def test_build_advisory_generates_trace_id_when_enforcement_trace_is_missing(self) -> None:
        event = {
            "normalized": {
                "sid": 2402001,
                "severity": 2,
                "attack_type": "fixture",
                "category": "test",
                "action": "allowed",
                "target_port": 22,
                "protocol": "TCP",
            }
        }

        with patch.object(agent, "SCORER", _FixedScorer()), patch.object(
            agent, "DECISION_LAYERS", _FixedDecisionLayers()
        ), patch.object(agent, "DECISION_LOGGER", _NoopDecisionLogger()), patch.object(
            agent, "_evaluate_correlation", return_value={"force_llm": False}
        ), patch.object(agent, "_metrics_inc"), patch.object(
            agent, "_LAST_RISK_SCORE", 0
        ), patch.object(
            agent, "_LAST_STATE_NAME", "NORMAL"
        ), patch.object(
            agent.secrets, "token_hex", return_value="0123456789abcdef"
        ):
            advisory = agent._build_advisory(event)

        self.assertEqual(advisory["trace_id"], "trace-0123456789abcdef")


if __name__ == "__main__":
    unittest.main()
