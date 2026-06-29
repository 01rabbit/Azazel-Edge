from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from azazel_edge.arbiter.action import ActionArbiter
from azazel_edge.evaluators.noc import NocEvaluator
from azazel_edge.evaluators.soc import SocEvaluator
from azazel_edge.evidence_plane.schema import EvidenceEvent
from azazel_edge.tactics_engine.eve_parser import EVEParser
from azazel_edge.tactics_engine.scorer import TacticalScorer

# Score-band detection gate. Mirrors SUSPICION_HIGH_MIN / soc._bucket "high".
# A single alert whose risk_score reaches this is "high" suspicion, and because
# production back-fills confidence from risk (decision_layers._normalized_confidence_from_risk),
# risk>=60 also clears the strong_soc confidence>=60 co-requisite.
DETECT_MIN = 60

# Pinned deterministic harness input. Real EVE carries no confidence field, so this
# stands in for the production risk-derived value; >=70 so that after soc.py's single
# -10 single-event penalty it is still >=60 (strong_soc requires confidence>=60).
HARNESS_CONFIDENCE_RAW = 90

_SCORER = TacticalScorer()


@dataclass
class SessionResult:
    session_id: str
    attack_category: str
    technique: str
    expected_detection: bool
    detected: bool
    action_taken: str
    matched_sids: List[int]
    breach: bool
    risk_score: int = 0
    score_band_detected: bool = False
    false_positive: bool = False


@dataclass
class AccuracyResult:
    total_sessions: int
    detected: int
    breached: int
    detection_rate_pct: float
    breach_rate_pct: float
    # Detection metrics are computed over POSITIVE sessions only (expected_detection=true);
    # false-positive metrics over BENIGN sessions (expected_detection=false). Mixing them
    # (the pre-Step-0 behavior) made detection_rate meaningless once benign controls existed.
    total_positive: int = 0
    total_benign: int = 0
    false_positive: int = 0
    false_positive_rate_pct: float = 0.0
    # Band telemetry over ALL sessions -- gives operators the LLM-load and dead-zone
    # visibility the deferred ops/decoy-tuning decisions need (Step 4 of the eval plan).
    llm_band_count: int = 0       # risk in [40,79] -> routed to the LLM advisory band
    critical_count: int = 0       # risk >= 85 -> auto-ops escalation
    dead_zone_count: int = 0      # risk in [80,84] -> MUST be 0 (display/ops disagree)
    sessions: List[SessionResult] = field(default_factory=list)
    corpus_path: str = ""
    hardware: str = "software-only (EVE replay)"

    def summary(self) -> Dict[str, Any]:
        return {
            "corpus_path": self.corpus_path,
            "hardware": self.hardware,
            "total_sessions": self.total_sessions,
            "total_positive": self.total_positive,
            "total_benign": self.total_benign,
            "detected": self.detected,
            "breached": self.breached,
            "false_positive": self.false_positive,
            "detection_rate_pct": round(self.detection_rate_pct, 1),
            "breach_rate_pct": round(self.breach_rate_pct, 1),
            "false_positive_rate_pct": round(self.false_positive_rate_pct, 1),
            "llm_band_count": self.llm_band_count,
            "critical_count": self.critical_count,
            "dead_zone_count": self.dead_zone_count,
            "per_session": [
                {
                    "session_id": s.session_id,
                    "category": s.attack_category,
                    "technique": s.technique,
                    "expected_detection": s.expected_detection,
                    "detected": s.detected,
                    "risk_score": s.risk_score,
                    "score_band_detected": s.score_band_detected,
                    "action": s.action_taken,
                    "breach": s.breach,
                    "false_positive": s.false_positive,
                    "matched_sids": s.matched_sids,
                }
                for s in self.sessions
            ],
        }


class DetectionAccuracyBenchmark:
    def __init__(self, corpus_dir: str | Path):
        self.corpus_dir = Path(corpus_dir)

    @staticmethod
    def _to_event(parsed: Dict[str, Any], parser: EVEParser) -> EvidenceEvent:
        alert = parsed.get("alert") if isinstance(parsed.get("alert"), dict) else {}
        src = str(parsed.get("src_ip") or "-")
        dst = str(parsed.get("dest_ip") or "-")
        port = int(parsed.get("dest_port") or 0)
        proto = str(parsed.get("proto") or "-")
        sid = int(alert.get("signature_id") or alert.get("sid") or 0)
        # Run the REAL scorer on production-identical features instead of faking the
        # risk with 75 + severity*5. This is the whole point of Step 0: the benchmark
        # now exercises scorer.py, so detection/FP numbers reflect the live judge.
        features = parser.extract_scorer_features(parsed) or {}
        risk_score, _factors = _SCORER.score_with_features(features)
        confidence_raw = HARNESS_CONFIDENCE_RAW
        return EvidenceEvent.build(
            ts=str(parsed.get("timestamp") or ""),
            source="suricata_eve",
            kind=str(parsed.get("event_type") or "alert"),
            subject=f"{src}->{dst}:{port}/{proto}",
            severity=risk_score,
            confidence=confidence_raw / 100.0,
            attrs={
                "sid": sid,
                "src_ip": src,
                "dst_ip": dst,
                "target_port": port,
                "protocol": proto,
                "attack_type": str(parsed.get("attack_type") or alert.get("category") or ""),
                "category": str(alert.get("category") or ""),
                "risk_score": risk_score,
                "confidence_raw": confidence_raw,
                "signature": str(alert.get("signature") or ""),
            },
            status="alert",
            evidence_refs=[f"suricata_sid:{sid}"] if sid else [],
        )

    @staticmethod
    def _load_labels(label_path: Path) -> Dict[str, Any]:
        with label_path.open(encoding="utf-8") as f:
            return json.load(f)

    def _replay_session(self, eve_path: Path, labels: Dict[str, Any]) -> SessionResult:
        parser = EVEParser()
        noc_eval = NocEvaluator()
        soc_eval = SocEvaluator()
        arbiter = ActionArbiter()

        events: List[Dict[str, Any]] = []
        matched_sids: List[int] = []
        max_risk = 0
        for line in eve_path.read_text(encoding="utf-8").splitlines():
            payload = line.strip()
            if not payload:
                continue
            parsed = parser.parse_line(payload)
            if not parsed:
                continue
            event = self._to_event(parsed, parser).to_dict()
            events.append(event)
            sid = int(event.get("attrs", {}).get("sid") or 0)
            if sid:
                matched_sids.append(sid)
            max_risk = max(max_risk, int(event.get("attrs", {}).get("risk_score") or 0))

        noc_result = noc_eval.evaluate(events)
        soc_result = soc_eval.evaluate(events)
        decision = arbiter.decide(noc_eval.to_arbiter_input(noc_result), soc_eval.to_arbiter_input(soc_result))
        action = str(decision.get("action") or "observe")
        # Two detection signals, recorded separately (see Step 0 spec): the arbiter
        # containment outcome and the score-band signal. They are made to coincide
        # (risk>=DETECT_MIN => high suspicion => strong_soc), but we surface both so a
        # divergence is visible rather than hidden.
        detected = action != "observe"
        score_band_detected = max_risk >= DETECT_MIN
        expected = bool(labels.get("expected_detection", True))

        return SessionResult(
            session_id=labels.get("session_id", eve_path.stem),
            attack_category=labels.get("attack_category", "unknown"),
            technique=labels.get("attack_technique", ""),
            expected_detection=expected,
            detected=detected,
            action_taken=action,
            matched_sids=matched_sids,
            breach=(expected and not detected),
            risk_score=max_risk,
            score_band_detected=score_band_detected,
            false_positive=(not expected and detected),
        )

    def run(self) -> AccuracyResult:
        sessions: List[SessionResult] = []
        for label_file in sorted(self.corpus_dir.glob("*.labels.json")):
            eve_file = label_file.with_name(label_file.name.replace(".labels.json", ".jsonl"))
            if not eve_file.exists():
                continue
            labels = self._load_labels(label_file)
            sessions.append(self._replay_session(eve_file, labels))

        total = len(sessions)
        positives = [s for s in sessions if s.expected_detection]
        benign = [s for s in sessions if not s.expected_detection]
        total_positive = len(positives)
        total_benign = len(benign)
        detected = sum(1 for s in positives if s.detected)
        breached = sum(1 for s in positives if s.breach)
        false_positive = sum(1 for s in benign if s.false_positive)
        llm_band_count = sum(1 for s in sessions if 40 <= s.risk_score <= 79)
        critical_count = sum(1 for s in sessions if s.risk_score >= 85)
        dead_zone_count = sum(1 for s in sessions if 80 <= s.risk_score <= 84)
        return AccuracyResult(
            total_sessions=total,
            total_positive=total_positive,
            total_benign=total_benign,
            detected=detected,
            breached=breached,
            false_positive=false_positive,
            detection_rate_pct=(detected / total_positive * 100.0) if total_positive else 0.0,
            breach_rate_pct=(breached / total_positive * 100.0) if total_positive else 0.0,
            false_positive_rate_pct=(false_positive / total_benign * 100.0) if total_benign else 0.0,
            llm_band_count=llm_band_count,
            critical_count=critical_count,
            dead_zone_count=dead_zone_count,
            sessions=sessions,
            corpus_path=str(self.corpus_dir),
        )


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure detection accuracy with EVE corpus replay")
    ap.add_argument("--corpus", type=str, required=True)
    args = ap.parse_args()
    summary = DetectionAccuracyBenchmark(args.corpus).run().summary()
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
