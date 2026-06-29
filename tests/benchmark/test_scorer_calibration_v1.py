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

    def test_shared_classtype_disambiguated_by_sid(self) -> None:
        """
        The crux of the design: policy-violation/bad-unknown are shared by benign traffic
        AND real AZAZEL threats. The SAME classtype+port must dampen when there is no
        threat SID, but clear the detection gate when carried on a real AZAZEL SID.
        """
        scorer = TacticalScorer()
        shared = {"suricata_sev": 2, "suricata_signature": "", "target_port": 53}
        benign, _ = scorer.score_with_features(
            {**shared, "suricata_sid": 0, "suricata_category": "policy-violation"}
        )
        threat, _ = scorer.score_with_features(
            {**shared, "suricata_sid": 9901232, "suricata_category": "policy-violation"}
        )
        self.assertLess(benign, 40, "benign on shared classtype should dampen")
        self.assertGreaterEqual(threat, DETECT_MIN, "real exfil SID on same classtype should detect")
        self.assertGreaterEqual(threat - benign, SEPARATION_MARGIN)

    def test_non_english_attack_type_detects_via_sid(self) -> None:
        """A Japanese attack_type matches no English token, but the SID still carries it."""
        jp = [s for s in self.pos if s.session_id == "c2_beacon_jp_01"]
        self.assertTrue(jp and jp[0].detected and jp[0].risk_score >= CRITICAL_MIN)
        # unit: same SID, non-English label -> still c2-weighted; SID 0 + unmapped -> not.
        scorer = TacticalScorer()
        with_sid, _ = scorer.score_with_features({
            "suricata_sid": 9901251, "suricata_sev": 2, "suricata_signature": "C2ビーコン",
            "suricata_category": "trojan-activity", "target_port": 443,
        })
        no_class, _ = scorer.score_with_features({
            "suricata_sid": 0, "suricata_sev": 2, "suricata_signature": "C2ビーコン",
            "suricata_category": "unknown", "target_port": 443,
        })
        self.assertGreaterEqual(with_sid, CRITICAL_MIN)
        self.assertLess(no_class, 40)

    def test_blocked_action_does_not_suppress_detection(self) -> None:
        """A real threat reported as action=blocked must still detect (old scorer did -8)."""
        blk = [s for s in self.pos if s.session_id == "arp_spoof_blocked_01"]
        self.assertTrue(blk and blk[0].detected and blk[0].risk_score >= DETECT_MIN)

    def test_ablation_threat_weight_drives_detection(self) -> None:
        """Zeroing the threat signal must drop a detected positive below the gate."""
        scorer = TacticalScorer()
        detected, _ = scorer.score_with_features({
            "suricata_sid": 9901251, "suricata_sev": 2, "suricata_signature": "",
            "suricata_category": "trojan-activity", "target_port": 443,
        })
        ablated, _ = scorer.score_with_features({
            "suricata_sid": 0, "suricata_sev": 2, "suricata_signature": "",
            "suricata_category": "unknown", "target_port": 443,
        })
        self.assertGreaterEqual(detected, DETECT_MIN)
        self.assertLess(ablated, DETECT_MIN)

    def test_base_row_coverage_guards_provisional_severities(self) -> None:
        """
        The severity base curve is a single-point fit on an all-sev2/3 corpus; rows 1
        and 4 are provisional pending hardware measurement. Fail loudly if a session
        starts relying on an unmeasured base row, so nobody trusts it silently.
        """
        severities = set()
        for eve_file in CORPUS.glob("*.jsonl"):
            line = eve_file.read_text(encoding="utf-8").strip().splitlines()[0]
            import json as _json
            severities.add(int(_json.loads(line).get("alert", {}).get("severity") or 0))
        self.assertTrue(
            severities <= {2, 3},
            f"corpus exercises base rows {severities}; rows 1/4 are provisional "
            "(measure classtype->priority->severity on hardware before relying on them)",
        )

    def test_adversarial_benign_severity2_not_flagged(self) -> None:
        """
        sev-2 benign on shared classtypes / admin ports -- the cases the OLD additive
        scorer pushed to >=60 (55 base +5 sid +4 action +8 port). All must stay <40.
        """
        adversarial = [s for s in self.benign if "adversarial" in (s.technique or "")
                       or s.session_id.startswith(("benign_cleartext", "benign_bad_unknown",
                                                    "benign_smb_admin", "benign_rdp_admin"))]
        self.assertGreaterEqual(len(adversarial), 4)
        for s in adversarial:
            self.assertLess(s.risk_score, 40, f"{s.session_id} (sev2 adversarial benign) flagged")
            self.assertEqual(s.action_taken, "observe")


if __name__ == "__main__":
    unittest.main()
