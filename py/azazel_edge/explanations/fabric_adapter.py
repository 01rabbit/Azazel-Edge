"""Emit-alongside projections into the shared Azazel-Fabric contracts.

Phase 3 of ``docs/AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md`` §3.1 / §3.2. Edge keeps
writing its own, richer ``decision-explanations.jsonl`` byte-for-byte
unchanged; this module additionally serializes a *lossy* projection of each
persisted decision explanation into the shared
``azazel_fabric.schema.DecisionExplanation`` shape (and its embedded trust
capsule into ``azazel_fabric.schema.TrustCapsule``), written to **separate**
JSONL streams next to the originals.

The shared package is imported optionally: if ``azazel_fabric`` is not
installed every function here becomes a safe no-op, so Edge runs identically
with or without it — matching the guarded-import pattern already used across
the codebase. No function here ever raises into its caller.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:  # optional dependency — pinned in requirements/runtime.txt, absent is fine
    from azazel_fabric.schema import (
        ActionIntent,
        DecisionExplanation,
        EvidenceRef,
        TrustCapsule,
    )

    HAVE_AZAZEL_FABRIC = True
except Exception:  # pragma: no cover - exercised only when the dep is absent
    HAVE_AZAZEL_FABRIC = False

# Edge's arbiter action set is a subset of azazel_fabric.schema.ActionKind
# (observe/notify/throttle/redirect/isolate/decoy/release). Anything outside the
# shared enum degrades to "observe" so the projection never raises on an
# unexpected action word.
_ACTION_KINDS = {
    "observe",
    "notify",
    "throttle",
    "redirect",
    "isolate",
    "decoy",
    "release",
}

# Projection stream filenames, written beside the Edge-native output.
DECISION_PROJECTION_NAME = "fabric-decision-explanations.jsonl"
TRUST_PROJECTION_NAME = "fabric-trust-capsules.jsonl"


def _append_line(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(payload + "\n")


def build_decision_projection(explanation: Dict[str, Any]) -> "Optional[DecisionExplanation]":
    """Project Edge's v2 explanation dict into a Fabric ``DecisionExplanation``.

    Lossy by design (plan §3.1): the rich ``why_chosen`` dict narrows to a
    string, ``selected_action`` (an action name) is assembled into an
    ``ActionIntent``, and ``why_not_others`` flattens to strings. Returns
    ``None`` if Fabric is not installed. Never raises on ordinary shape
    variation.
    """
    if not HAVE_AZAZEL_FABRIC:
        return None

    why_chosen = explanation.get("why_chosen") if isinstance(explanation.get("why_chosen"), dict) else {}
    trace_id = str(explanation.get("trace_id") or "")
    action = str(explanation.get("selected_action") or why_chosen.get("action") or "observe")
    kind = action if action in _ACTION_KINDS else "observe"
    target = str(why_chosen.get("target") or "azazel-edge")
    observed_at = str(explanation.get("ts") or "")

    evidence: List[EvidenceRef] = []
    for ev_id in explanation.get("evidence_ids", []) or []:
        if not str(ev_id):
            continue
        evidence.append(
            EvidenceRef(
                evidence_id=str(ev_id),
                source="edge_arbiter",
                trace_id=trace_id,
                observed_at=observed_at,
            )
        )

    selected_action = ActionIntent(
        kind=kind,
        target=target,
        issued_by="edge_arbiter",
        evidence=evidence,
        trace_id=trace_id,
    )

    why_not: List[str] = []
    for item in explanation.get("why_not_others", []) or []:
        if isinstance(item, dict):
            act = str(item.get("action") or "")
            reason = str(item.get("reason") or "")
            why_not.append(f"{act}: {reason}".strip(": ").strip() or reason or act)

    release_condition = str(explanation.get("release_condition") or "") or None

    capsule = explanation.get("trust_capsule") if isinstance(explanation.get("trust_capsule"), dict) else {}
    raw_conf = capsule.get("confidence")
    confidence = None
    if isinstance(raw_conf, (int, float)):
        confidence = max(0.0, min(1.0, float(raw_conf)))

    why_chosen_str = str(explanation.get("reason") or why_chosen.get("reason") or "")

    return DecisionExplanation(
        selected_action=selected_action,
        why_chosen=why_chosen_str,
        why_not_others=why_not,
        release_condition=release_condition,
        confidence=confidence,
        trace_id=trace_id,
    )


def build_trust_capsule_projection(explanation: Dict[str, Any]) -> "Optional[TrustCapsule]":
    """Project Edge's decision explanation into a Fabric ``TrustCapsule``.

    Field mapping (plan §3.2): ``hmac_sig``->``hmac``, ``timestamp``->
    ``issued_at``; ``config_hash`` is absent from Edge's capsule and is sourced
    from the explanation's top-level ``config_hash``. Returns ``None`` if Fabric
    is not installed.
    """
    if not HAVE_AZAZEL_FABRIC:
        return None

    capsule = explanation.get("trust_capsule") if isinstance(explanation.get("trust_capsule"), dict) else {}
    trace_id = str(capsule.get("trace_id") or explanation.get("trace_id") or "")
    issued_at = str(capsule.get("timestamp") or explanation.get("ts") or "")
    hmac_value = str(capsule.get("hmac_sig") or "")
    config_hash = str(explanation.get("config_hash") or "")

    return TrustCapsule(
        trace_id=trace_id,
        config_hash=config_hash,
        hmac=hmac_value,
        issued_at=issued_at,
    )


def project_decision_explanation(explanation: Dict[str, Any], native_path: Path) -> None:
    """Emit the Fabric DecisionExplanation + TrustCapsule projections alongside.

    ``native_path`` is Edge's own ``decision-explanations.jsonl``; the
    projections are written to sibling files in the same directory. Best-effort:
    a no-op when Fabric is absent and never raises into the caller.
    """
    if not HAVE_AZAZEL_FABRIC:
        return
    try:
        native_path = Path(native_path)
        decision = build_decision_projection(explanation)
        if decision is not None:
            _append_line(native_path.with_name(DECISION_PROJECTION_NAME), decision.model_dump_json())
        capsule = build_trust_capsule_projection(explanation)
        if capsule is not None:
            _append_line(native_path.with_name(TRUST_PROJECTION_NAME), capsule.model_dump_json())
    except Exception as exc:  # pragma: no cover - defensive; must never raise
        logger.debug("fabric_projection_failed: %s", exc)
