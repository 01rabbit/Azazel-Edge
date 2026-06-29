"""
Step 0 regression guard: prove the detection-accuracy benchmark actually exercises
TacticalScorer (it used to hardcode risk_score = 75 + severity*5 and never call the
scorer), that replay features match production keys, that the corpus categories match
the real Suricata classtypes, and that the score->SOC->arbiter detection gate behaves
as the redesign assumes (risk>=60 detects, <60 does not).

These tests deliberately do NOT assert the *target* calibration (every benign <40,
every positive >=85, etc.) -- that lands with the scorer recalibration (ranks 2-5).
Step 0 only guarantees the measurement itself is real.
"""

from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.arbiter.action import ActionArbiter
from azazel_edge.benchmark.detection_accuracy import (
    DETECT_MIN,
    DetectionAccuracyBenchmark,
)
from azazel_edge.decision_layers import _normalized_confidence_from_risk
from azazel_edge.evaluators.noc import NocEvaluator
from azazel_edge.evaluators.soc import SocEvaluator
from azazel_edge.evidence_plane.schema import EvidenceEvent
from azazel_edge.tactics_engine.eve_parser import EVEParser
from azazel_edge.tactics_engine.scorer import TacticalScorer

CORPUS = Path(__file__).resolve().parent / "corpus"
RULES = ROOT / "security" / "suricata" / "azazel-lite.rules"

# The exact feature keys the live agent builds at agent.py:_build_advisory.
# If production changes, this tuple and EVEParser.SCORER_FEATURE_KEYS must move together.
PRODUCTION_FEATURE_KEYS = (
    "suricata_sid",
    "suricata_sev",
    "suricata_signature",
    "suricata_category",
    "suricata_action",
    "target_port",
    "protocol",
)


def _rule_classtypes() -> dict[int, str]:
    mapping: dict[int, str] = {}
    for line in RULES.read_text(encoding="utf-8").splitlines():
        sid_m = re.search(r"sid:(\d+)", line)
        cls_m = re.search(r"classtype:([a-z-]+)", line)
        if sid_m and cls_m:
            mapping[int(sid_m.group(1))] = cls_m.group(1)
    return mapping


def _run_gate(risk: int, confidence_raw: int = 90) -> str:
    """Push one synthetic alert at a chosen risk through the real SOC+arbiter path."""
    event = EvidenceEvent.build(
        ts="2026-01-01T00:00:00.000000+0000",
        source="suricata_eve",
        kind="alert",
        subject="10.0.0.5->172.16.0.1:22/TCP",
        severity=risk,
        confidence=confidence_raw / 100.0,
        attrs={
            "sid": 9901221,
            "src_ip": "10.0.0.5",
            "dst_ip": "172.16.0.1",
            "target_port": 22,
            "protocol": "TCP",
            "category": "network-scan",
            "risk_score": risk,
            "confidence_raw": confidence_raw,
        },
        status="alert",
        evidence_refs=["suricata_sid:9901221"],
    ).to_dict()
    noc, soc, arbiter = NocEvaluator(), SocEvaluator(), ActionArbiter()
    decision = arbiter.decide(
        noc.to_arbiter_input(noc.evaluate([event])),
        soc.to_arbiter_input(soc.evaluate([event])),
    )
    return str(decision.get("action") or "observe")


class ScorerWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = DetectionAccuracyBenchmark(corpus_dir=CORPUS).run()
        self.by_id = {s.session_id: s for s in self.result.sessions}

    def test_benchmark_actually_calls_the_scorer(self) -> None:
        """Recorded risk must equal a direct TacticalScorer call, NOT the old 75+sev*5 fake."""
        parser, scorer = EVEParser(), TacticalScorer()
        for label_file in CORPUS.glob("*.labels.json"):
            eve_file = label_file.with_name(label_file.name.replace(".labels.json", ".jsonl"))
            sid_line = eve_file.read_text(encoding="utf-8").strip().splitlines()[0]
            parsed = parser.parse_line(sid_line)
            expected_risk, _ = scorer.score_with_features(parser.extract_scorer_features(parsed) or {})
            session = self.by_id[label_file.name.replace(".labels.json", "")]
            self.assertEqual(
                session.risk_score,
                expected_risk,
                f"{session.session_id}: benchmark risk {session.risk_score} != scorer {expected_risk}",
            )

    def test_replay_features_match_production_keys(self) -> None:
        self.assertEqual(tuple(EVEParser.SCORER_FEATURE_KEYS), PRODUCTION_FEATURE_KEYS)
        sample = EVEParser().extract_scorer_features(
            {"dest_port": 22, "proto": "TCP", "attack_type": "port_scan",
             "alert": {"signature_id": 9901221, "severity": 2, "category": "network-scan"}}
        )
        self.assertEqual(tuple(sample.keys()), PRODUCTION_FEATURE_KEYS)

    def test_corpus_categories_match_real_classtypes(self) -> None:
        rule_cls = _rule_classtypes()
        for eve_file in CORPUS.glob("*.jsonl"):
            line = eve_file.read_text(encoding="utf-8").strip().splitlines()[0]
            alert = json.loads(line).get("alert", {})
            sid = int(alert.get("signature_id") or 0)
            if sid in rule_cls:  # benign controls use sid 0 -> skipped
                self.assertEqual(
                    alert.get("category"),
                    rule_cls[sid],
                    f"{eve_file.name}: category {alert.get('category')} != rule classtype {rule_cls[sid]}",
                )

    def test_detection_gate_trace(self) -> None:
        """risk>=DETECT_MIN must reach the arbiter; just below must not."""
        self.assertNotEqual(_run_gate(DETECT_MIN + 2), "observe")
        self.assertEqual(_run_gate(DETECT_MIN - 2), "observe")

    def test_confidence_back_fill_clears_the_gate(self) -> None:
        """Resolves the 'single-alert confidence' blocker: risk>=60 => confidence>=60 after penalty."""
        self.assertGreaterEqual(_normalized_confidence_from_risk(DETECT_MIN) - 10, 60)
        self.assertLess(_normalized_confidence_from_risk(DETECT_MIN - 11) - 10, 60)

    def test_positive_sessions_detected(self) -> None:
        for s in self.result.sessions:
            if s.expected_detection:
                self.assertTrue(s.detected, f"{s.session_id} positive but not detected (risk={s.risk_score})")
                self.assertGreaterEqual(s.risk_score, DETECT_MIN)

    def test_benign_controls_not_detected(self) -> None:
        benign = [s for s in self.result.sessions if not s.expected_detection]
        self.assertGreaterEqual(len(benign), 5)
        for s in benign:
            self.assertFalse(s.false_positive, f"{s.session_id} benign but flagged (risk={s.risk_score})")
            self.assertEqual(s.action_taken, "observe")

    def test_metrics_are_split_positive_vs_benign(self) -> None:
        summary = self.result.summary()
        self.assertIn("false_positive_rate_pct", summary)
        self.assertEqual(summary["total_positive"] + summary["total_benign"], summary["total_sessions"])
        self.assertGreater(summary["total_benign"], 0)

    def test_band_telemetry_present_and_dead_zone_empty(self) -> None:
        summary = self.result.summary()
        for key in ("llm_band_count", "critical_count", "dead_zone_count"):
            self.assertIn(key, summary)
        self.assertEqual(summary["dead_zone_count"], 0, "a session landed in the [80,84] dead zone")


if __name__ == "__main__":
    unittest.main()
