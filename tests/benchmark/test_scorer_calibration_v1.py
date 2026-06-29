"""
Calibration gates for the recalibrated TacticalScorer (ranks 2-5). These ship WITH
the scorer change. They assert the *separation* and *band* properties, not memorized
per-class numbers, so they guard against overfitting rather than freezing magic values.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.benchmark.detection_accuracy import DETECT_MIN, DetectionAccuracyBenchmark
from azazel_edge.tactics_engine.scorer import (
    DECEPTION_SIDS,
    TacticalScorer,
    _CLASS_WEIGHT,
)

CORPUS = Path(__file__).resolve().parent / "corpus"
RULES = ROOT / "security" / "suricata" / "azazel-lite.rules"
CRITICAL_MIN = 85
SEPARATION_MARGIN = 20


class ScorerCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = DetectionAccuracyBenchmark(corpus_dir=CORPUS).run()
        self.pos = [s for s in self.result.sessions if s.expected_detection]
        self.benign = [s for s in self.result.sessions if not s.expected_detection]

    def test_deception_sids_match_rules(self) -> None:
        sids = {int(m.group(1)) for m in re.finditer(r"sid:(\d+)", RULES.read_text(encoding="utf-8"))}
        self.assertEqual(set(DECEPTION_SIDS), sids)

    def test_every_positive_clears_the_gate(self) -> None:
        for s in self.pos:
            self.assertGreaterEqual(s.risk_score, DETECT_MIN, f"{s.session_id} below detection gate")
            self.assertTrue(s.detected)

    def test_high_consequence_classes_reach_critical(self) -> None:
        by_cat = {s.attack_category: s for s in self.pos}
        for cat in ("c2_beacon", "dns_exfil"):
            self.assertGreaterEqual(by_cat[cat].risk_score, CRITICAL_MIN, f"{cat} should be CRITICAL")

    def test_benign_crushed_below_floor(self) -> None:
        for s in self.benign:
            self.assertLess(s.risk_score, 40, f"{s.session_id} not dampened")
            self.assertFalse(s.false_positive)

    def test_separation_margin(self) -> None:
        min_pos = min(s.risk_score for s in self.pos)
        max_benign = max(s.risk_score for s in self.benign)
        self.assertGreaterEqual(min_pos - max_benign, SEPARATION_MARGIN)

    def test_no_session_in_critical_dead_zone(self) -> None:
        for s in self.result.sessions:
            self.assertFalse(80 <= s.risk_score <= 84, f"{s.session_id} in [80,84] dead zone")

    def test_class_weight_ordering(self) -> None:
        order = ["rce", "c2", "exfil", "cred", "phishing", "mitm", "scan", "recon"]
        weights = [_CLASS_WEIGHT[c] for c in order]
        self.assertEqual(weights, sorted(weights, reverse=True))

    # --- unit-level invariants on the scorer directly ---

    def test_action_never_reduces_score(self) -> None:
        scorer = TacticalScorer()
        base = {"suricata_sid": 9901221, "suricata_sev": 2, "suricata_signature": "",
                "suricata_category": "network-scan", "target_port": 22}
        allowed, _ = scorer.score_with_features({**base, "suricata_action": "allowed"})
        for act in ("blocked", "drop", "rejected", "", "weird-attacker-value"):
            s, _ = scorer.score_with_features({**base, "suricata_action": act})
            self.assertGreaterEqual(s, allowed, f"action={act!r} reduced the score")

    def test_token_only_cannot_reach_floor(self) -> None:
        """A free-text token with no SID-class and no safe classtype stays below 40."""
        s, _ = TacticalScorer().score_with_features({
            "suricata_sid": 0, "suricata_sev": 2,
            "suricata_signature": "c2 beacon callback", "suricata_category": "unknown",
            "target_port": 443,
        })
        self.assertLess(s, 40)

    def test_deception_sid_floored(self) -> None:
        """A deception SID that would otherwise score low is floored to the high gate."""
        s, _ = TacticalScorer().score_with_features({
            "suricata_sid": 9901101, "suricata_sev": 4, "suricata_signature": "",
            "suricata_category": "attempted-recon", "target_port": 0,
        })
        self.assertGreaterEqual(s, DETECT_MIN)

    def test_benign_classtype_admin_port_stays_low(self) -> None:
        """Benign internal SMB on an admin port (no threat class) must not be flagged."""
        s, _ = TacticalScorer().score_with_features({
            "suricata_sid": 0, "suricata_sev": 3, "suricata_signature": "",
            "suricata_category": "tcp-connection", "target_port": 445,
        })
        self.assertLess(s, 40)


if __name__ == "__main__":
    unittest.main()
