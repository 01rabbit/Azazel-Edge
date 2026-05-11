from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stable_json(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _ai_advice_hash(ai_payload: Dict[str, Any] | None) -> str | None:
    if not isinstance(ai_payload, dict) or not ai_payload:
        return None
    text = _stable_json(ai_payload)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sign_payload(payload: Dict[str, Any]) -> str:
    secret = str(os.environ.get("AZAZEL_TRUST_CAPSULE_HMAC_KEY", "azazel-edge-dev-key")).encode("utf-8")
    text = _stable_json(payload).encode("utf-8")
    return hmac.new(secret, text, hashlib.sha256).hexdigest()


def _confidence_score(explanation: Dict[str, Any]) -> float:
    machine = explanation.get("machine") if isinstance(explanation.get("machine"), dict) else {}
    soc_summary = machine.get("soc_summary") if isinstance(machine.get("soc_summary"), dict) else {}
    status = str(soc_summary.get("status") or "").strip().lower()
    mapping = {
        "critical": 0.95,
        "high": 0.85,
        "elevated": 0.7,
        "medium": 0.6,
        "degraded": 0.5,
        "low": 0.4,
        "good": 0.3,
        "quiet": 0.2,
        "unknown": 0.3,
    }
    return float(mapping.get(status, 0.3))


def build_trust_capsule(explanation: Dict[str, Any]) -> Dict[str, Any]:
    why_chosen = explanation.get("why_chosen") if isinstance(explanation.get("why_chosen"), dict) else {}
    why_not = explanation.get("why_not_others") if isinstance(explanation.get("why_not_others"), list) else []
    evidence_ids = [str(x) for x in explanation.get("evidence_ids", []) if str(x)]
    machine = explanation.get("machine") if isinstance(explanation.get("machine"), dict) else {}
    soc_summary = machine.get("soc_summary") if isinstance(machine.get("soc_summary"), dict) else {}
    ai_candidates = soc_summary.get("ai_attack_candidates") if isinstance(soc_summary.get("ai_attack_candidates"), list) else []
    ai_payload = {
        "ai_attack_candidates": ai_candidates,
        "ti_matches": why_chosen.get("ti_matches"),
    } if ai_candidates else None

    ai_contributed = bool(ai_candidates)
    capsule_core: Dict[str, Any] = {
        "trace_id": str(explanation.get("trace_id") or ""),
        "timestamp": str(explanation.get("ts") or _utc_iso_now()),
        "action": str(why_chosen.get("action") or ""),
        "confidence": round(_confidence_score(explanation), 3),
        "evidence_ids": evidence_ids,
        "why_chosen": str(why_chosen.get("reason") or ""),
        "why_not_others": [
            {"action": str(item.get("action") or ""), "reason": str(item.get("reason") or "")}
            for item in why_not
            if isinstance(item, dict)
        ],
        "operator_wording": str(explanation.get("operator_wording") or ""),
        "ai_contributed": ai_contributed,
        "ai_advice_hash": _ai_advice_hash(ai_payload),
    }
    capsule_core["hmac_sig"] = _sign_payload(capsule_core)
    return capsule_core
