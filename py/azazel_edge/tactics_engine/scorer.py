"""
scorer.py - Tactical Engine risk scoring

Deterministic, ML-free risk score for Suricata-derived features. The model keys
threat weight on the exact AZAZEL SID range first, falls back to a small set of
SAFE Suricata classtypes, and uses attack_type free-text tokens only as ceilinged
corroboration. Severity is a weak prior; detection must be EARNED by a recognized
threat class. Scores are calibrated to the downstream gates:

    < 40   auto-dismiss (below the LLM advisory floor)
    40-59  LLM-advisory only (arbiter cannot escalate)
    60-84  HIGH  -> arbiter "high" suspicion, detection gate
    85-100 CRITICAL -> auto-ops escalation (CRITICAL_MIN)

Everything here is O(1) per event (frozenset/dict lookups + one regex pass) and
emits a `factors` list so every point is explainable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


@dataclass
class ScoreBreakdown:
    score: int
    factors: List[str]


# AZAZEL deception/honeypot SIDs. Pinned to security/suricata/azazel-lite.rules by
# test_scorer_calibration_v1; NOT a 9901xxx wildcard, so future 9902xxx SIDs do not
# silently inherit the deception floor.
DECEPTION_SIDS = frozenset(
    {
        9901101, 9901102, 9901103,
        9901201, 9901202, 9901203,
        9901211,
        9901221, 9901222,
        9901231, 9901232,
        9901241,
        9901251,
    }
)

# PRIMARY: exact SID -> threat class for AZAZEL rules.
_SID_CLASS: Dict[int, str] = {
    9901251: "c2",
    9901231: "exfil", 9901232: "exfil",
    9901241: "cred",
    9901211: "mitm",
    9901221: "scan", 9901222: "scan",
    9901201: "phishing", 9901202: "phishing", 9901203: "phishing",
    9901101: "recon", 9901102: "recon", 9901103: "recon",
}

# SECONDARY: Suricata classtype -> threat class, for non-AZAZEL/future rules. SAFE
# classtypes only. Shared catch-alls (policy-violation, bad-unknown, ...) are NOT
# mapped here -- a real AZAZEL threat carried on them is disambiguated by its SID.
_CLASSTYPE_CLASS: Dict[str, str] = {
    "trojan-activity": "c2",
    "social-engineering": "phishing",
    "network-scan": "scan",
    "attempted-recon": "recon",
    "attempted-admin": "cred",
    "attempted-user": "cred",
}

# TERTIARY: attack_type free-text tokens -> class. Corroboration only; a token-only
# match is hard-ceilinged below the LLM floor (see _TOKEN_CEILING), so a missing or
# novel or non-English token degrades to SID/classtype scoring, never a silent FN/FP.
_TOKEN_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(?:beacon|c2)\b"), "c2"),
    (re.compile(r"\b(?:exfil|tunnel)\b"), "exfil"),
    (re.compile(r"\barp ?spoof\b|\bpoison\b"), "mitm"),
    (re.compile(r"\b(?:port ?scan|nmap)\b"), "scan"),
    (re.compile(r"\b(?:brute|credential)\b|password="), "cred"),
    (re.compile(r"phish|\bfake\b"), "phishing"),
]

# Suppresses token matching entirely when the label is a known benign operation.
_BENIGN_GUARD = re.compile(
    r"av scan|antivirus|scanner update|password change|password reset|vuln feed"
)

# Catch-all classtypes dampened to <=_BENIGN_CAP when NO threat class matched.
_BENIGN_CLASSTYPES = frozenset(
    {
        "not-suspicious",
        "unknown",
        "misc-activity",
        "protocol-command-decode",
        "tcp-connection",
        "policy-violation",
        "bad-unknown",
    }
)

# Saturating threat weights (added once, as max over matched classes).
_CLASS_WEIGHT: Dict[str, int] = {
    "rce": 50,
    "c2": 48,
    "exfil": 46,
    "cred": 44,
    "phishing": 42,
    "mitm": 40,
    "scan": 36,
    "recon": 30,
}

_TOKEN_CEILING = 39      # token-only match cannot reach the 40 LLM floor
# Benign catch-alls normalize to a single low band value: below the 40 LLM/detection
# floor (so a single benign alert is never a false positive) but inside the agent's
# correlation window [CORR_MIN_RISK_SCORE=20, LLM_AMBIG_MIN=40), so genuine low-and-slow
# repeats from one source still escalate to the LLM. (See agent._evaluate_correlation.)
_BENIGN_LEVEL = 25
_DECEPTION_FLOOR = 60    # == SUSPICION_HIGH_MIN: arbiter-detected AND LLM-visible
_SEV1_NO_THREAT_CAP = 35


class TacticalScorer:
    """Build a 0-100 risk score from normalized Suricata features."""

    _SEVERITY_BASE = {1: 38, 2: 30, 3: 24, 4: 18}
    _UNKNOWN_SEV_BASE = 16

    _ADMIN_PORTS = {22, 23, 445, 3389, 5900}
    _WEB_PORTS = {80, 443}
    _DNS_PORTS = {53}
    _DECOY_PORTS = {12222, 18080}

    def score(self, features: Dict[str, Any]) -> ScoreBreakdown:
        severity = int(features.get("suricata_sev") or 0)
        sid = int(features.get("suricata_sid") or 0)
        signature = str(features.get("suricata_signature") or "").lower()
        category = str(features.get("suricata_category") or "").lower()
        action = str(features.get("suricata_action") or "allowed").lower()
        target_port = int(features.get("target_port") or 0)

        factors: List[str] = [f"severity={severity}"]

        # --- threat class resolution (saturating max) ---
        authoritative = set()
        if sid in _SID_CLASS:
            authoritative.add(_SID_CLASS[sid])
        classtype_class = _CLASSTYPE_CLASS.get(category)
        if classtype_class:
            authoritative.add(classtype_class)

        token_classes = set()
        if signature and not _BENIGN_GUARD.search(signature):
            for pattern, cls in _TOKEN_PATTERNS:
                if pattern.search(signature):
                    token_classes.add(cls)

        matched = authoritative | token_classes
        token_only = bool(matched) and not authoritative
        threat_weight = max((_CLASS_WEIGHT[c] for c in matched), default=0)

        score = self._SEVERITY_BASE.get(severity, self._UNKNOWN_SEV_BASE)

        # +5 only when corroborated by a real class or a deception SID; a bare alert
        # never earns it (kills the bare-alert -> LLM-flood vector).
        if threat_weight > 0 or sid in DECEPTION_SIDS:
            score += 5
            factors.append("sid_present")

        if threat_weight > 0:
            score += threat_weight
            for cls in sorted(matched):
                factors.append(f"threat_class={cls}({_CLASS_WEIGHT[cls]})")

        # Ports corroborate an existing threat; they never manufacture one. Decoy
        # ports are honeypot-only and suspicious by construction, so they always count.
        if threat_weight > 0:
            if target_port in self._ADMIN_PORTS:
                score += 8
                factors.append(f"admin_port={target_port}")
            elif target_port in self._WEB_PORTS:
                score += 8
                factors.append(f"web_port={target_port}")
            elif target_port in self._DNS_PORTS:
                score += 8
                factors.append(f"dns_port={target_port}")
        if target_port in self._DECOY_PORTS:
            score += 10
            factors.append(f"decoy_port={target_port}")

        # Action is neutral-or-positive: a contained verdict is evidence the system
        # reacted to hostility, not benignity. Never subtract (an attacker who
        # influences the reported verdict must not be able to suppress the score).
        if action in {"blocked", "drop", "rejected"}:
            score += 2
            factors.append(f"action={action}(contained)")

        # Token-only corroboration cannot, by itself, reach the LLM floor.
        if token_only:
            score = min(score, _TOKEN_CEILING)
            factors.append("token_only_ceiling")

        # The noisiest priority field alone cannot escalate a class-less alert.
        if severity == 1 and threat_weight == 0:
            score = min(score, _SEV1_NO_THREAT_CAP)
            factors.append("sev1_no_threat_cap")

        # Deception floor and benign dampener are mutually exclusive (floor only on
        # DECEPTION_SIDS; dampener excludes them).
        if sid in DECEPTION_SIDS:
            if score < _DECEPTION_FLOOR:
                score = _DECEPTION_FLOOR
                factors.append("deception_floor")
        elif threat_weight == 0 and category in _BENIGN_CLASSTYPES:
            # Normalize to the low, correlation-eligible band (not below it) so
            # low-and-slow benign-looking repeats remain visible to correlation.
            score = _BENIGN_LEVEL
            factors.append("benign_dampener")

        score = max(0, min(100, score))
        return ScoreBreakdown(score=score, factors=factors)

    def score_with_features(self, features: Dict[str, Any]) -> Tuple[int, List[str]]:
        """Compatibility helper for callers that need a plain tuple."""
        result = self.score(features)
        return result.score, result.factors
