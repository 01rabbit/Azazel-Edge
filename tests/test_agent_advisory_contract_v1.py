from __future__ import annotations

import unittest
from unittest.mock import patch

from azazel_edge_ai import agent


class _FixedScorer:
    class Result:
        def __init__(self, features: dict) -> None:
            self.score = 72
            self.factors = [f"sid={features['suricata_sid']}", f"port={features['target_port']}"]
            self.shadow = {"status": "complete", "score": 72, "matches": True,
                           "factors": ["severity=3", "threat_class=scan(36)"]}

    def score(self, features: dict) -> "_FixedScorer.Result":
        return self.Result(features)


class _ShadowStatusScorer(_FixedScorer):
    def __init__(self, shadow: dict) -> None:
        self.shadow = shadow

    def score(self, features: dict) -> "_FixedScorer.Result":
        result = super().score(features)
        result.shadow = self.shadow
        return result


class _FixedMioAuxiliary:
    def submit(self, event: dict, *, score: int, factors: list[str], risk_level: str) -> dict:
        return {
            "schema_version": "azazel.mio_auxiliary.v1", "status": "queued",
            "authority": "read_only_advisory", "source": "mio_shared_core",
            "generation": "generation-1", "trace_id": "mio-trace-1",
        }


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
        self.assertEqual(advisory["score_factors"], ["sid=2402000", "port=443"])
        self.assertEqual(advisory["mio_score_comparison"]["edge_score"], 72)
        self.assertEqual(advisory["mio_score_comparison"]["mio_score"], 72)
        self.assertTrue(advisory["mio_score_comparison"]["matches"])
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

    def test_live_advisory_surfaces_bounded_shadow_and_preserves_edge_result_on_mio_statuses(self) -> None:
        event = {
            "normalized": {"sid": 2402000, "severity": 3, "attack_type": "fixture",
                           "category": "scan", "action": "allowed", "target_port": 443,
                           "protocol": "TCP"},
            "enforcement": {"trace_id": "trace-live"},
        }
        edge_result = (72, ["sid=2402000", "port=443"], "HIGH",
                       "Apply delay policy and increase telemetry (port=443)", "DEGRADED")
        shadows = (
            ("complete", {"status": "complete", "score": 72, "matches": True,
                           "factors": ["severity=3", "threat_class=scan(36)"]}, 72, True),
            ("complete_mismatch", {"status": "complete", "score": 73, "matches": False,
                                     "factors": ["severity=3", "threat_class=scan(37)"]}, 73, False),
            ("unavailable", {"status": "unavailable", "reason": "package_unavailable",
                             "score": 72, "factors": ["must not leak"]}, None, None),
            ("degraded", {"status": "degraded", "reason": "assessment_failed",
                           "score": 0, "matches": False, "factors": ["must not leak"]}, None, None),
        )
        for _name, shadow, visible_score, visible_match in shadows:
            with self.subTest(status=shadow["status"]):
                with patch.object(agent, "SCORER", _ShadowStatusScorer(shadow)), patch.object(
                    agent, "LIVE_MIO_AUXILIARY", _FixedMioAuxiliary()
                ), patch.object(agent, "DECISION_LAYERS", _FixedDecisionLayers()), patch.object(
                    agent, "DECISION_LOGGER", _NoopDecisionLogger()
                ), patch.object(agent, "_evaluate_correlation", return_value={"force_llm": False}), patch.object(
                    agent, "_metrics_inc"
                ), patch.object(agent, "_LAST_RISK_SCORE", 0), patch.object(agent, "_LAST_STATE_NAME", "NORMAL"):
                    advisory = agent._build_advisory(event)

                self.assertEqual(
                    (advisory["risk_score"], advisory["score_factors"], advisory["risk_level"],
                     advisory["recommendation"], advisory["state_name"]), edge_result,
                )
                comparison = advisory["mio_score_comparison"]
                self.assertEqual(comparison["status"], shadow["status"])
                self.assertEqual(comparison["mio_score"], visible_score)
                self.assertEqual(comparison["matches"], visible_match)
                self.assertEqual(comparison["authority"], "comparison_only")
                self.assertEqual(comparison["generation"], "generation-1")
                self.assertEqual(comparison["trace_id"], "mio-trace-1")
                if shadow["status"] != "complete":
                    self.assertEqual(comparison["mio_factors"], [])

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
