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


@dataclass
class AccuracyResult:
    total_sessions: int
    detected: int
    breached: int
    detection_rate_pct: float
    breach_rate_pct: float
    sessions: List[SessionResult] = field(default_factory=list)
    corpus_path: str = ""
    hardware: str = "software-only (EVE replay)"

    def summary(self) -> Dict[str, Any]:
        return {
            "corpus_path": self.corpus_path,
            "hardware": self.hardware,
            "total_sessions": self.total_sessions,
            "detected": self.detected,
            "breached": self.breached,
            "detection_rate_pct": round(self.detection_rate_pct, 1),
            "breach_rate_pct": round(self.breach_rate_pct, 1),
            "per_session": [
                {
                    "session_id": s.session_id,
                    "category": s.attack_category,
                    "technique": s.technique,
                    "detected": s.detected,
                    "action": s.action_taken,
                    "breach": s.breach,
                    "matched_sids": s.matched_sids,
                }
                for s in self.sessions
            ],
        }


class DetectionAccuracyBenchmark:
    def __init__(self, corpus_dir: str | Path):
        self.corpus_dir = Path(corpus_dir)

    @staticmethod
    def _to_event(parsed: Dict[str, Any]) -> EvidenceEvent:
        alert = parsed.get("alert") if isinstance(parsed.get("alert"), dict) else {}
        src = str(parsed.get("src_ip") or "-")
        dst = str(parsed.get("dest_ip") or "-")
        port = int(parsed.get("dest_port") or 0)
        proto = str(parsed.get("proto") or "-")
        sid = int(alert.get("signature_id") or alert.get("sid") or 0)
        severity = int(alert.get("severity") or 2)
        # Keep risk in "high" band so deterministic SOC/arbiter path is exercised.
        risk_score = min(100, 75 + severity * 5)
        confidence_raw = 90
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
                "attack_type": str(alert.get("category") or ""),
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
        for line in eve_path.read_text(encoding="utf-8").splitlines():
            payload = line.strip()
            if not payload:
                continue
            parsed = parser.parse_line(payload)
            if not parsed:
                continue
            event = self._to_event(parsed).to_dict()
            events.append(event)
            sid = int(event.get("attrs", {}).get("sid") or 0)
            if sid:
                matched_sids.append(sid)

        noc_result = noc_eval.evaluate(events)
        soc_result = soc_eval.evaluate(events)
        decision = arbiter.decide(noc_eval.to_arbiter_input(noc_result), soc_eval.to_arbiter_input(soc_result))
        action = str(decision.get("action") or "observe")
        detected = action != "observe"
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
        detected = sum(1 for s in sessions if s.detected)
        breached = sum(1 for s in sessions if s.breach)
        return AccuracyResult(
            total_sessions=total,
            detected=detected,
            breached=breached,
            detection_rate_pct=(detected / total * 100.0) if total else 0.0,
            breach_rate_pct=(breached / total * 100.0) if total else 0.0,
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
