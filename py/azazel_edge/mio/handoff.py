"""Deterministic no-model summary/handoff (#385, #365 degradation case 5).

When the model is absent, blocked, invalid, or the cycle ends before a
validated recommendation, the operator still gets a situation summary built
only from the SituationFrame (and, optionally, the playbook and the
hypotheses already validated in this cycle). No model output is used, the
bytes are stable for identical inputs, and the handoff carries no action or
authority: it is advisory text for a human.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Sequence

from .contracts import MioHypothesis, MioSituationFrame
from .playbook import ReasoningPlaybook

NO_MODEL_HANDOFF_SCHEMA_VERSION = "mio.no_model_handoff.v1"
NO_MODEL_HANDOFF_MAX_BYTES = 8192
_LIST_CAPS = {"known_facts": 8, "unknowns": 8, "contradictions": 6, "evidence_refs": 12, "check_next": 4, "stop_conditions": 4, "claim_boundaries": 4, "hypotheses": 6}
# Fixed operator wording. Deliberately not derived from attacker-facing text.
_OPERATOR_GUIDANCE = (
    "Review the listed facts and unknowns; no model contributed to this summary.",
    "Edge deterministic decisions are unaffected; this handoff authorizes nothing.",
    "Resolve the unknowns with the playbook checks before relying on any hypothesis.",
)


@dataclass(frozen=True)
class NoModelHandoff:
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_canonical_json())

    def to_canonical_json(self) -> bytes:
        return json.dumps(self.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.to_canonical_json()).hexdigest()


def build_no_model_handoff(
    frame: MioSituationFrame,
    *,
    reason: str,
    playbook: ReasoningPlaybook | None = None,
    hypotheses: Sequence[MioHypothesis] = (),
) -> NoModelHandoff:
    c = _LIST_CAPS
    summary = (
        f"Trace {frame.trace_id}: defensive state {frame.current_defensive_state}, "
        f"threat level {frame.threat_level}; {len(frame.known_facts)} known facts, "
        f"{len(frame.unknowns)} unknowns, {len(frame.contradictions)} contradictions, "
        f"{len(frame.evidence_refs)} evidence refs. M.I.O. reasoning ended without a "
        f"model recommendation ({reason[:64]})."
    )
    payload: dict[str, Any] = {
        "schema_version": NO_MODEL_HANDOFF_SCHEMA_VERSION,
        "frame_id": frame.frame_id,
        "trace_id": frame.trace_id,
        "frame_digest": frame.canonical_digest(),
        "reason": reason[:64],
        "model_contribution": "none",
        "current_defensive_state": frame.current_defensive_state,
        "threat_level": frame.threat_level,
        "summary": summary,
        "known_facts": list(frame.known_facts[: c["known_facts"]]),
        "unknowns": list(frame.unknowns[: c["unknowns"]]),
        "contradictions": list(frame.contradictions[: c["contradictions"]]),
        "evidence_refs": list(frame.evidence_refs[: c["evidence_refs"]]),
        "dependency_status": {"knowledge": frame.knowledge_status, "deception": frame.deception_status},
        "playbook": None,
        "validated_hypotheses": [
            {"hypothesis_id": h.hypothesis_id, "status": h.status.value, "statement": h.statement[:160], "falsification_conditions": list(h.falsification_conditions[:2])}
            for h in list(hypotheses)[: c["hypotheses"]]
        ],
        "operator_guidance": list(_OPERATOR_GUIDANCE),
        "limitations": ["no_model_contribution", "frame_derived_only"] + (["frame_truncated"] if frame.truncated else []),
    }
    if playbook is not None:
        payload["playbook"] = {
            "playbook_id": playbook.playbook_id,
            "version": playbook.version,
            "check_next": list(playbook.discriminating_questions[: c["check_next"]]),
            "stop_conditions": list(playbook.stop_conditions[: c["stop_conditions"]]),
            "claim_boundaries": list(playbook.claim_boundaries[: c["claim_boundaries"]]),
        }
    handoff = NoModelHandoff(payload)
    # Deterministic shrink: drop list tails in a fixed order until in budget.
    order = ("evidence_refs", "validated_hypotheses", "known_facts", "contradictions", "unknowns")
    while len(handoff.to_canonical_json()) > NO_MODEL_HANDOFF_MAX_BYTES:
        for key in order:
            if payload[key]:
                payload[key] = payload[key][:-1]
                if "handoff_truncated" not in payload["limitations"]:
                    payload["limitations"].append("handoff_truncated")
                break
        else:
            payload["summary"] = payload["summary"][: len(payload["summary"]) // 2]
            if not payload["summary"]:
                break
        handoff = NoModelHandoff(payload)
    return handoff
