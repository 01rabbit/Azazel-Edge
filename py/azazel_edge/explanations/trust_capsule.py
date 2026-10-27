"""Decision trust capsule: the tamper-evidence summary of one decision.

The capsule is signed with HMAC-SHA256 under ``AZAZEL_TRUST_CAPSULE_HMAC_KEY``
(Edge#477). The installer creates a random key in
``/etc/azazel-edge/trust-capsule.env`` (0600 root:root) and the AI agent's unit
reads it with ``EnvironmentFile=``.

Fail-closed: without a key the capsule is **not** signed. It then carries
``signature_state: "unsigned"`` and an empty ``hmac_sig``, so no reader can
take it for a signed capsule. The former built-in fallback key is public (it
is in this repository); it is never used to sign, also not when it is set
explicitly. Tests that need a signature set their own key in the environment.

Records written before this change have no ``signature_state``. Unless the
device had a key set, they were signed with that public key and prove
nothing; they are kept as they are (the decision log is append-only).
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from azazel_edge._util import stable_json as _stable_json

logger = logging.getLogger(__name__)

KEY_ENV = "AZAZEL_TRUST_CAPSULE_HMAC_KEY"
SIGNED = "signed"
UNSIGNED = "unsigned"
# The fallback key of earlier versions. It is public, so a signature under it
# proves nothing: it is refused as a key and never used to sign.
_PUBLIC_FORMER_DEFAULT_KEY = "azazel-edge-dev-key"
_warned_unsigned = False


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ai_advice_hash(ai_payload: Dict[str, Any] | None) -> str | None:
    if not isinstance(ai_payload, dict) or not ai_payload:
        return None
    text = _stable_json(ai_payload)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _signing_key() -> bytes | None:
    """The configured key, or None (unset, empty or the public former default)."""
    global _warned_unsigned
    raw = os.environ.get(KEY_ENV, "")
    reason = ""
    if not raw.strip():
        reason = "is not set"
    elif raw == _PUBLIC_FORMER_DEFAULT_KEY:
        reason = "holds the public former default key"
    if not reason:
        return raw.encode("utf-8")
    if not _warned_unsigned:
        # Logged once per process; the key's value is never logged.
        logger.warning("trust capsules are written unsigned: %s %s", KEY_ENV, reason)
        _warned_unsigned = True
    return None


def _sign_payload(payload: Dict[str, Any], secret: bytes) -> str:
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
    secret = _signing_key()
    if secret is None:
        capsule_core["signature_state"] = UNSIGNED
        capsule_core["hmac_sig"] = ""
        return capsule_core
    # signature_state is part of the signed payload: a verifier drops only
    # hmac_sig and recomputes the HMAC over the rest.
    capsule_core["signature_state"] = SIGNED
    capsule_core["hmac_sig"] = _sign_payload(capsule_core, secret)
    return capsule_core
