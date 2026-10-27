"""Deterministic no-model summary/handoff (#385, #365 degradation case 5).

When the model is absent, blocked, invalid, or the cycle ends before a
validated recommendation, the operator still gets a situation summary built
from the SituationFrame and, optionally, the playbook.

v2 is built from allowlisted structured fields only. No free text is copied
from any input: frame facts, unknowns, contradictions, mission, NOC/SOC text,
model statements and the ``reason`` argument never reach the payload. What
does reach it is

* closed vocabularies (defensive state, threat level, dependency status,
  reasoning state, hypothesis status, current-action record, the fixed
  uncertainty marker codes the frame builder and contract emit),
* identifiers that match a closed set of shapes the repo itself produces
  (``HANDOFF_ID_KINDS`` over ``id_grammar.ID_KINDS``: allowlisted words and
  bounded digits, no dots, no free words); anything else, including
  addresses, hostnames, hex/decimal address forms and secret-like values,
  becomes a fixed placeholder, and
  integer counts,
* the built-in playbooks: the ID only when it is a ``DEFAULT_PLAYBOOKS`` key,
  the version only when it equals that entry's version, and the fixed
  wording only when the whole playbook equals the built-in entry.

If the model proposed hypotheses that passed grounding/lifecycle checks this
cycle, they are listed separately by ID, status and evidence refs, marked
``verification: model_proposed_unverified``; their statements are not copied.
Bytes are stable for identical inputs, and the handoff carries no action or
authority: it is advisory guidance for a human.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Sequence

from .contracts import (
    ACTION_APPLIED_STATES,
    ACTION_MODES,
    ACTION_RECORD_MALFORMED,
    ACTION_RELEASE_CONDITIONS,
    ACTOR_SUMMARY_MALFORMED,
    CURRENT_ACTION_STATE_MISMATCH,
    DECEPTION_LIFECYCLE_UNKNOWN,
    DEFENSIVE_STATES,
    MULTIPLE_CURRENT_ACTIONS,
    OPTIONAL_DEPENDENCY_STATUSES,
    HypothesisStatus,
    MioHypothesis,
    MioSituationFrame,
    ReasoningState,
)
from .id_grammar import EVIDENCE_REF, id_ok
from .playbook import DEFAULT_PLAYBOOKS, ReasoningPlaybook

NO_MODEL_HANDOFF_SCHEMA_VERSION = "mio.no_model_handoff.v2"
NO_MODEL_HANDOFF_MAX_BYTES = 8192
_LIST_CAPS = {"evidence_refs": 12, "check_next": 4, "stop_conditions": 4, "claim_boundaries": 4, "hypotheses": 6, "hypothesis_refs": 4}

# Closed vocabularies. Anything outside them is rendered as a fixed value.
_DEFENSIVE_STATES = tuple(sorted(DEFENSIVE_STATES))
THREAT_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN")
HANDOFF_REASONS = tuple(s.value for s in ReasoningState)
_HYPOTHESIS_STATUSES = tuple(s.value for s in HypothesisStatus)
# Fixed uncertainty marker codes emitted by the contract (dependency
# degradation, malformed nested records) and by MioSituationFrameBuilder.
# Caller-supplied free-text unknowns/contradictions are counted, never copied.
UNKNOWN_MARKERS = frozenset(
    {f"{dep}_{status}" for dep in ("KNOWLEDGE", "DECEPTION") for status in ("UNAVAILABLE", "TIMEOUT", "MALFORMED")}
    | {DECEPTION_LIFECYCLE_UNKNOWN, ACTOR_SUMMARY_MALFORMED, ACTION_RECORD_MALFORMED}
    | {"NOC_DEGRADED_MODE", "NO_TIMESTAMPED_EVIDENCE", "EVIDENCE_TIMESTAMP_FUTURE", "EVIDENCE_STALE"}
    | {f"SOC_VISIBILITY={v}" for v in ("UNKNOWN", "DEGRADED", "LIMITED", "PARTIAL", "POOR", "CRITICAL")}
)
CONTRADICTION_MARKERS = frozenset({CURRENT_ACTION_STATE_MISMATCH, MULTIPLE_CURRENT_ACTIONS, "HIGH_SOC_RISK_WITH_FRAGILE_NOC"})

# Fixed operator wording. Deliberately not derived from attacker-facing text.
_OPERATOR_GUIDANCE = (
    "Review the situation frame for the counted facts and unknowns; no model contributed to this summary.",
    "Edge deterministic decisions are unaffected; this handoff authorizes nothing.",
    "Resolve the unknowns with the playbook checks before relying on any hypothesis.",
)


# Closed ID kinds (id_grammar.ID_KINDS, shared with the model output parser
# and the broker audit). The ID grammars in trace_audit admit any word, dotted
# address, MAC, IPv6 or hex/decimal address form, so they are not enough for
# text a human will read. Anything that does not match becomes a fixed
# placeholder; no digest is emitted because the value may be low-entropy.
# Frame evidence refs are caller-supplied (MioSituationFrame.build, replay
# fixtures), so flow:<flow_id> refs are never shown (see id_grammar).
HANDOFF_ID_KINDS: dict[str, tuple[str, ...]] = {
    "trace_id": ("trace_id",),
    "frame_id": ("frame_id",),
    "evidence_ref": EVIDENCE_REF,
    "hypothesis_id": ("hypothesis_id",),
}


def _safe_id(kind: str, value: Any, placeholder: str) -> str:
    """Keep ``value`` only if it fully matches one of its closed kinds."""
    return value if id_ok(value, HANDOFF_ID_KINDS[kind]) else placeholder


def _vocab(value: Any, allowed: Sequence[str], fallback: str) -> str:
    return value if isinstance(value, str) and value in allowed else fallback


def _refs(values: Sequence[Any], cap: int) -> list[str]:
    return [_safe_id("evidence_ref", r, "[redacted:evidence_ref]") for r in list(values)[:cap]]


def _markers(values: Sequence[Any], allowed: frozenset[str]) -> list[str]:
    return [v for v in dict.fromkeys(values) if isinstance(v, str) and v in allowed]


def _builtin_playbook(playbook: ReasoningPlaybook) -> ReasoningPlaybook | None:
    builtin = DEFAULT_PLAYBOOKS.get(playbook.playbook_id) if type(playbook.playbook_id) is str else None
    return builtin if builtin is not None and builtin == playbook else None


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
    trace_id = _safe_id("trace_id", frame.trace_id, "invalid-trace-id")
    frame_id = _safe_id("frame_id", frame.frame_id, "invalid-frame-id")
    reason_code = _vocab(reason, HANDOFF_REASONS, "unspecified")
    defensive_state = _vocab(frame.current_defensive_state, _DEFENSIVE_STATES, "UNKNOWN")
    threat_level = _vocab(frame.threat_level, THREAT_LEVELS, "UNKNOWN")
    counts = {
        "known_facts": len(frame.known_facts),
        "unknowns": len(frame.unknowns),
        "contradictions": len(frame.contradictions),
        "evidence_refs": len(frame.evidence_refs),
        "knowledge_refs": len(frame.knowledge_refs),
        "actors": len(frame.actors),
        "actions": len(frame.actions),
    }
    current = next((a for a in frame.actions if a.role == "current"), None)
    current_action = None
    if current is not None:
        current_action = {
            "action": _vocab(current.action, _DEFENSIVE_STATES, "UNKNOWN"),
            "applied_state": _vocab(current.applied_state, ACTION_APPLIED_STATES, "none"),
            "mode": _vocab(current.mode, ACTION_MODES, "none"),
            "release_condition": _vocab(current.release_condition, ACTION_RELEASE_CONDITIONS, "none"),
        }
    model_hypotheses = [
        {
            "hypothesis_id": _safe_id("hypothesis_id", h.hypothesis_id, f"hypothesis-{i + 1}"),
            "model_status": _vocab(getattr(h.status, "value", None), _HYPOTHESIS_STATUSES, "unknown"),
            "verification": "model_proposed_unverified",
            "supporting_evidence_refs": _refs(h.supporting_evidence_refs, c["hypothesis_refs"]),
            "contradicting_evidence_refs": _refs(h.contradicting_evidence_refs, c["hypothesis_refs"]),
            "falsification_condition_count": len(h.falsification_conditions),
        }
        for i, h in enumerate(list(hypotheses)[: c["hypotheses"]])
    ]
    summary = (
        f"Trace {trace_id}: defensive state {defensive_state}, threat level {threat_level}; "
        f"{counts['known_facts']} known facts, {counts['unknowns']} unknowns, "
        f"{counts['contradictions']} contradictions, {counts['evidence_refs']} evidence refs. "
        f"M.I.O. reasoning ended without a model recommendation ({reason_code})."
    )
    payload: dict[str, Any] = {
        "schema_version": NO_MODEL_HANDOFF_SCHEMA_VERSION,
        "frame_id": frame_id,
        "trace_id": trace_id,
        "frame_digest": frame.canonical_digest(),
        "reason": reason_code,
        "model_contribution": "unverified_hypotheses_only" if model_hypotheses else "none",
        "current_defensive_state": defensive_state,
        "threat_level": threat_level,
        "summary": summary,
        "counts": counts,
        "unknown_markers": _markers(frame.unknowns, UNKNOWN_MARKERS),
        "contradiction_markers": _markers(frame.contradictions, CONTRADICTION_MARKERS),
        "evidence_refs": _refs(frame.evidence_refs, c["evidence_refs"]),
        "dependency_status": {
            "knowledge": _vocab(frame.knowledge_status, OPTIONAL_DEPENDENCY_STATUSES, "malformed"),
            "deception": _vocab(frame.deception_status, OPTIONAL_DEPENDENCY_STATUSES, "malformed"),
        },
        "current_action": current_action,
        "playbook": None,
        "model_proposed_hypotheses": model_hypotheses,
        "operator_guidance": list(_OPERATOR_GUIDANCE),
        "limitations": (["includes_unverified_model_hypotheses", "summary_frame_derived"] if model_hypotheses else ["no_model_contribution", "frame_derived_only"])
        + ["structured_fields_only"]
        + (["frame_truncated"] if frame.truncated else []),
    }
    if playbook is not None:
        builtin = _builtin_playbook(playbook)
        known = DEFAULT_PLAYBOOKS.get(playbook.playbook_id) if type(playbook.playbook_id) is str else None
        payload["playbook"] = {
            "playbook_id": playbook.playbook_id if known is not None else "invalid-playbook-id",
            "version": playbook.version if known is not None and playbook.version == known.version else "invalid-version",
            "guidance_source": "builtin" if builtin is not None else "omitted_not_builtin",
            "check_next": list(builtin.discriminating_questions[: c["check_next"]]) if builtin else [],
            "stop_conditions": list(builtin.stop_conditions[: c["stop_conditions"]]) if builtin else [],
            "claim_boundaries": list(builtin.claim_boundaries[: c["claim_boundaries"]]) if builtin else [],
        }
    # Deterministic shrink: drop list tails in a fixed order until within budget.
    order = ("evidence_refs", "model_proposed_hypotheses")

    def size() -> int:
        return len(NoModelHandoff(payload).to_canonical_json())

    while size() > NO_MODEL_HANDOFF_MAX_BYTES:
        if "handoff_truncated" not in payload["limitations"]:
            payload["limitations"].append("handoff_truncated")
            continue
        key = next((k for k in order if payload[k]), None)
        if key is None:
            break
        payload[key] = payload[key][:-1]
    handoff = NoModelHandoff(payload)
    if len(handoff.to_canonical_json()) > NO_MODEL_HANDOFF_MAX_BYTES:
        # Unreachable with bounded fields; refuse rather than exceed the cap.
        raise ValueError("no_model_handoff_budget_unreachable")
    return handoff
