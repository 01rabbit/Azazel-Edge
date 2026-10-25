"""Deterministic no-model summary/handoff (#385, #365 degradation case 5).

When the model is absent, blocked, invalid, or the cycle ends before a
validated recommendation, the operator still gets a situation summary built
from the SituationFrame and, optionally, the playbook. The summary, guidance
and lists are frame/playbook-derived only. If the model already proposed
hypotheses that passed grounding/lifecycle checks this cycle, they are listed
separately as ``model_proposed_hypotheses`` with ``verification:
model_proposed_unverified`` and ``model_contribution`` says so; they are never
presented as frame-derived. Bytes are stable for identical inputs, and the
handoff carries no action or authority: it is advisory text for a human.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Sequence

from .contracts import MioHypothesis, MioSituationFrame
from .playbook import ReasoningPlaybook
from .redaction import redact_text

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
    # Free text below is masked (#389): frame facts and model hypotheses may
    # carry credentials or PII-like strings that must not be echoed verbatim.
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
        "model_contribution": "unverified_hypotheses_only" if hypotheses else "none",
        "current_defensive_state": frame.current_defensive_state,
        "threat_level": frame.threat_level,
        "summary": summary,
        "known_facts": [redact_text(x) for x in frame.known_facts[: c["known_facts"]]],
        "unknowns": [redact_text(x) for x in frame.unknowns[: c["unknowns"]]],
        "contradictions": [redact_text(x) for x in frame.contradictions[: c["contradictions"]]],
        "evidence_refs": list(frame.evidence_refs[: c["evidence_refs"]]),
        "dependency_status": {"knowledge": frame.knowledge_status, "deception": frame.deception_status},
        "playbook": None,
        "model_proposed_hypotheses": [
            {"hypothesis_id": h.hypothesis_id[:96], "model_status": h.status.value, "verification": "model_proposed_unverified", "statement": redact_text(h.statement)[:160], "falsification_conditions": [redact_text(x)[:160] for x in h.falsification_conditions[:2]]}
            for h in list(hypotheses)[: c["hypotheses"]]
        ],
        "operator_guidance": list(_OPERATOR_GUIDANCE),
        "limitations": (["includes_unverified_model_hypotheses", "summary_frame_derived"] if hypotheses else ["no_model_contribution", "frame_derived_only"]) + (["frame_truncated"] if frame.truncated else []),
    }
    if playbook is not None:
        payload["playbook"] = {
            "playbook_id": playbook.playbook_id[:96],
            "version": playbook.version[:32],
            "check_next": [x[:160] for x in playbook.discriminating_questions[: c["check_next"]]],
            "stop_conditions": [x[:160] for x in playbook.stop_conditions[: c["stop_conditions"]]],
            "claim_boundaries": [x[:160] for x in playbook.claim_boundaries[: c["claim_boundaries"]]],
        }
    # Deterministic shrink: drop list tails in a fixed order, then halve the
    # summary, then drop the playbook block, until within budget.
    order = ("evidence_refs", "model_proposed_hypotheses", "known_facts", "contradictions", "unknowns")

    def size() -> int:
        return len(NoModelHandoff(payload).to_canonical_json())

    while size() > NO_MODEL_HANDOFF_MAX_BYTES:
        if "handoff_truncated" not in payload["limitations"]:
            payload["limitations"].append("handoff_truncated")
            continue
        key = next((k for k in order if payload[k]), None)
        if key is not None:
            payload[key] = payload[key][:-1]
        elif payload["summary"]:
            payload["summary"] = payload["summary"][: len(payload["summary"]) // 2]
        elif payload["playbook"] is not None:
            payload["playbook"] = None
        else:
            break
    handoff = NoModelHandoff(payload)
    if len(handoff.to_canonical_json()) > NO_MODEL_HANDOFF_MAX_BYTES:
        # Unreachable with bounded frame fields; refuse rather than exceed the cap.
        raise ValueError("no_model_handoff_budget_unreachable")
    return handoff
