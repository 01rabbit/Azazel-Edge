from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


def _bounded_text(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _bounded_unique(values: Sequence[Any] | None, *, limit: int, item_limit: int = 160) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values or ():
        value = _bounded_text(raw, item_limit)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return tuple(out)


DEFENSIVE_STATES = {"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"}


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    ACTIVE = "active"
    WEAKENED = "weakened"
    STRENGTHENED = "strengthened"
    FALSIFIED = "falsified"
    UNRESOLVED = "unresolved"
    SUPERSEDED = "superseded"


class ReasoningState(str, Enum):
    FRAME_READY = "frame_ready"
    HYPOTHESES_READY = "hypotheses_ready"
    EVIDENCE_GAPS_IDENTIFIED = "evidence_gaps_identified"
    REQUEST_PLANNED = "request_planned"
    EVIDENCE_COLLECTED = "evidence_collected"
    HYPOTHESES_UPDATED = "hypotheses_updated"
    RECOMMENDATION_READY = "recommendation_ready"
    COMPLETE = "complete"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    BUDGET_EXHAUSTED = "budget_exhausted"
    STALE_SUPERSEDED = "stale_superseded"
    OPERATOR_CANCELLED = "operator_cancelled"
    VALIDATION_REJECTED = "validation_rejected"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    ERROR_FALLBACK = "error_fallback"


@dataclass(frozen=True)
class MioSituationFrame:
    frame_id: str
    trace_id: str
    created_at: str
    mission: str
    current_defensive_state: str
    threat_level: str
    noc_summary: str = ""
    soc_summary: str = ""
    known_facts: tuple[str, ...] = ()
    unknowns: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    knowledge_refs: tuple[str, ...] = ()
    freshness_seconds: int = 0
    truncated: bool = False

    @classmethod
    def build(cls, *, frame_id: str, trace_id: str, created_at: str, mission: str, current_defensive_state: str, threat_level: str, noc_summary: str = "", soc_summary: str = "", known_facts: Sequence[Any] | None = None, unknowns: Sequence[Any] | None = None, contradictions: Sequence[Any] | None = None, evidence_refs: Sequence[Any] | None = None, knowledge_refs: Sequence[Any] | None = None, freshness_seconds: int = 0) -> "MioSituationFrame":
        source_counts = {"known_facts": len(known_facts or ()), "unknowns": len(unknowns or ()), "contradictions": len(contradictions or ()), "evidence_refs": len(evidence_refs or ()), "knowledge_refs": len(knowledge_refs or ())}
        caps = {"known_facts": 16, "unknowns": 12, "contradictions": 8, "evidence_refs": 32, "knowledge_refs": 16}
        defensive_state = _bounded_text(current_defensive_state, 24).upper()
        if defensive_state not in DEFENSIVE_STATES:
            raise ValueError("invalid_defensive_state")
        return cls(frame_id=_bounded_text(frame_id, 96), trace_id=_bounded_text(trace_id, 96), created_at=_bounded_text(created_at, 64), mission=_bounded_text(mission, 240), current_defensive_state=defensive_state, threat_level=_bounded_text(threat_level, 24).upper(), noc_summary=_bounded_text(noc_summary, 480), soc_summary=_bounded_text(soc_summary, 480), known_facts=_bounded_unique(known_facts, limit=caps["known_facts"]), unknowns=_bounded_unique(unknowns, limit=caps["unknowns"]), contradictions=_bounded_unique(contradictions, limit=caps["contradictions"]), evidence_refs=_bounded_unique(evidence_refs, limit=caps["evidence_refs"], item_limit=128), knowledge_refs=_bounded_unique(knowledge_refs, limit=caps["knowledge_refs"], item_limit=128), freshness_seconds=max(0, min(int(freshness_seconds), 86400)), truncated=any(source_counts[key] > caps[key] for key in caps))

    def to_dict(self) -> dict[str, Any]:
        return {"frame_id": self.frame_id, "trace_id": self.trace_id, "created_at": self.created_at, "mission": self.mission, "current_defensive_state": self.current_defensive_state, "threat_level": self.threat_level, "noc_summary": self.noc_summary, "soc_summary": self.soc_summary, "known_facts": list(self.known_facts), "unknowns": list(self.unknowns), "contradictions": list(self.contradictions), "evidence_refs": list(self.evidence_refs), "knowledge_refs": list(self.knowledge_refs), "freshness_seconds": self.freshness_seconds, "truncated": self.truncated}


@dataclass(frozen=True)
class MioHypothesis:
    hypothesis_id: str
    statement: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    supporting_evidence_refs: tuple[str, ...] = ()
    contradicting_evidence_refs: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    falsification_conditions: tuple[str, ...] = ()
    expected_observations: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, ordinal: int) -> "MioHypothesis":
        raw_status = str(payload.get("status") or HypothesisStatus.PROPOSED.value)
        try:
            status = HypothesisStatus(raw_status)
        except ValueError:
            status = HypothesisStatus.PROPOSED
        return cls(hypothesis_id=_bounded_text(payload.get("hypothesis_id") or f"h{ordinal}", 96), statement=_bounded_text(payload.get("statement"), 360), status=status, supporting_evidence_refs=_bounded_unique(payload.get("supporting_evidence_refs"), limit=16, item_limit=128), contradicting_evidence_refs=_bounded_unique(payload.get("contradicting_evidence_refs"), limit=16, item_limit=128), assumptions=_bounded_unique(payload.get("assumptions"), limit=8), falsification_conditions=_bounded_unique(payload.get("falsification_conditions"), limit=8), expected_observations=_bounded_unique(payload.get("expected_observations"), limit=8), missing_evidence=_bounded_unique(payload.get("missing_evidence"), limit=8))

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, "statement": self.statement, "status": self.status.value, "supporting_evidence_refs": list(self.supporting_evidence_refs), "contradicting_evidence_refs": list(self.contradicting_evidence_refs), "assumptions": list(self.assumptions), "falsification_conditions": list(self.falsification_conditions), "expected_observations": list(self.expected_observations), "missing_evidence": list(self.missing_evidence)}


@dataclass(frozen=True)
class MioEvidenceGap:
    gap_id: str
    question: str
    discriminates_hypothesis_ids: tuple[str, ...]
    capability: str
    priority: int = 50

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, ordinal: int) -> "MioEvidenceGap":
        return cls(gap_id=_bounded_text(payload.get("gap_id") or f"g{ordinal}", 96), question=_bounded_text(payload.get("question"), 300), discriminates_hypothesis_ids=_bounded_unique(payload.get("discriminates_hypothesis_ids"), limit=8, item_limit=96), capability=_bounded_text(payload.get("capability"), 96), priority=max(0, min(int(payload.get("priority", 50)), 100)))


@dataclass(frozen=True)
class MioCapabilityRequest:
    request_id: str
    trace_id: str
    capability: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MioCapabilityResult:
    request_id: str
    capability: str
    ok: bool
    data: Mapping[str, Any]
    evidence_refs: tuple[str, ...] = ()
    error: str = ""


@dataclass(frozen=True)
class MioRecommendation:
    advisory_id: str
    summary: str
    recommended_action: str
    rationale: str
    evidence_refs: tuple[str, ...]
    limitations: tuple[str, ...] = ()
    executable: bool = False

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any], *, advisory_id: str) -> "MioRecommendation":
        return cls(advisory_id=_bounded_text(advisory_id, 96), summary=_bounded_text(payload.get("summary"), 360), recommended_action=_bounded_text(payload.get("recommended_action"), 32).upper(), rationale=_bounded_text(payload.get("rationale"), 720), evidence_refs=_bounded_unique(payload.get("evidence_refs"), limit=32, item_limit=128), limitations=_bounded_unique(payload.get("limitations"), limit=8), executable=False)
