"""
scorer.py - Tactical Engine risk scoring

Deterministic score builder for Suricata-derived features.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class ScoreBreakdown:
    score: int
    factors: List[str]


class TacticalScorer:
    """Build a 0-100 risk score from normalized Suricata features."""

    _SEVERITY_BASE = {
        1: 70,
        2: 55,
        3: 40,
        4: 25,
    }

    _HIGH_RISK_PORTS = {22, 23, 80, 443, 445, 3389, 5900}

    def score(self, features: Dict[str, Any]) -> ScoreBreakdown:
        severity = int(features.get("suricata_sev") or 0)
        sid = int(features.get("suricata_sid") or 0)
        signature = str(features.get("suricata_signature") or "").lower()
        category = str(features.get("suricata_category") or "").lower()
        action = str(features.get("suricata_action") or "allowed").lower()
        target_port = int(features.get("target_port") or 0)

        score = self._SEVERITY_BASE.get(severity, 15 if severity > 4 else 20)
        factors: List[str] = [f"severity={severity}"]

        if sid > 0:
            score += 5
            factors.append("sid_present")

        if action in {"blocked", "drop"}:
            score -= 8
            factors.append(f"action={action}(-)")
        else:
            score += 4
            factors.append(f"action={action}(+)")

        if "nmap" in signature or "scan" in signature:
            score += 10
            factors.append("recon_pattern")
        if "brute" in signature or "password" in signature:
            score += 12
            factors.append("credential_attack_pattern")
        if "rce" in signature or "command injection" in signature:
            score += 15
            factors.append("rce_pattern")

        if "attempted-admin" in category or "attempted-user" in category:
            score += 10
            factors.append("attempted_access_category")
        elif "attempted-recon" in category:
            score += 6
            factors.append("recon_category")

        if target_port in self._HIGH_RISK_PORTS:
            score += 8
            factors.append(f"sensitive_port={target_port}")

        score = max(0, min(100, score))
        return ScoreBreakdown(score=score, factors=factors)

    def score_with_features(self, features: Dict[str, Any]) -> Tuple[int, List[str]]:
        """Compatibility helper for callers that need plain tuple."""
        result = self.score(features)
        return result.score, result.factors
