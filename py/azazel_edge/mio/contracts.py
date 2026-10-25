from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
from enum import Enum
from typing import Any, Mapping, Sequence


def _bounded_text(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _bounded_unique(values: Sequence[Any] | None, *, limit: int, item_limit: int = 160) -> tuple[str, ...]:
    # Strings are sequences in Python, but treating a malformed model string as
    # a list of characters would silently create bogus evidence/ID entries.
    if not isinstance(values, (list, tuple)):
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        value = _bounded_text(raw, item_limit)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
        if len(out) >= limit:
            break
    return tuple(out)


def _sequence_len(value: Any) -> int:
    return len(value) if isinstance(value, (list, tuple)) else 0


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


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


# --- SituationFrame contract ownership -------------------------------------
# #361 kept the frame Edge-local (not Fabric). This module is the single owner
# of the schema: any change to the serialized field set, caps, or semantics
# must bump SITUATION_FRAME_SCHEMA_VERSION and update the golden fixture
# tests/fixtures/mio/situation_frame_canonical_v1.json in the same PR.
# The frame is advisory-only input to M.I.O.; it carries no Edge authority.
SITUATION_FRAME_SCHEMA_VERSION = "mio.situation_frame.v1"
SITUATION_FRAME_SCHEMA_OWNER = "azazel_edge.mio.contracts"
SITUATION_FRAME_CAPS = {"known_facts": 16, "unknowns": 12, "contradictions": 8, "evidence_refs": 32, "knowledge_refs": 16}
# Hard ceiling for to_canonical_json(). Documented in
# docs/architecture/mio-situation-frame.md; enforced by deterministic trimming.
SITUATION_FRAME_MAX_SERIALIZED_BYTES = 16384
# Optional dependency status vocabulary (Knowledge / AZ-06 deception facts).
OPTIONAL_DEPENDENCY_STATUSES = ("available", "not_provided", "unavailable", "timeout", "malformed")
_DEGRADED_DEPENDENCY_STATUSES = {"unavailable", "timeout", "malformed"}
# Provenance vocabulary: which deterministic input produced each fact group.
PROVENANCE_GROUPS = ("known_facts", "unknowns", "contradictions", "evidence_refs", "knowledge_refs", "freshness_seconds")
PROVENANCE_SOURCES = ("caller", "evidence_plane", "frame_builder", "knowledge", "noc_evaluation", "soc_evaluation")
# Deterministic trim order when the serialized ceiling is exceeded: drop
# low-value detail before uncertainty markers, never touch identity fields.
_TRIM_ORDER = ("evidence_refs", "knowledge_refs", "known_facts", "contradictions", "unknowns")
_TRIM_TEXT_FIELDS = ("noc_summary", "soc_summary", "mission")


def _dependency_status(value: Any, *, has_refs: bool) -> str:
    if value is None:
        return "available" if has_refs else "not_provided"
    text = str(value).strip().lower()
    if text not in OPTIONAL_DEPENDENCY_STATUSES:
        return "malformed"
    if text == "available" and not has_refs:
        # "available" with nothing to show is indistinguishable from absence;
        # downgrade rather than render empty confidence.
        return "not_provided"
    return text


_FRAME_TEXT_KEYS = ("schema_version", "frame_id", "trace_id", "created_at", "mission", "current_defensive_state", "threat_level", "noc_summary", "soc_summary", "knowledge_status", "deception_status")
_FRAME_LIST_KEYS = ("known_facts", "unknowns", "contradictions", "evidence_refs", "knowledge_refs")
_FRAME_KEYS = frozenset(_FRAME_TEXT_KEYS + _FRAME_LIST_KEYS + ("provenance", "freshness_seconds", "truncated"))


def _validate_frame_payload(payload: Any) -> None:
    if not isinstance(payload, Mapping) or set(payload) != _FRAME_KEYS:
        raise ValueError("invalid_situation_frame_payload")
    if payload["schema_version"] != SITUATION_FRAME_SCHEMA_VERSION:
        raise ValueError("unsupported_situation_frame_schema_version")
    if any(not isinstance(payload[key], str) for key in _FRAME_TEXT_KEYS):
        raise ValueError("invalid_situation_frame_payload")
    if any(not isinstance(payload[key], list) or any(not isinstance(item, str) for item in payload[key]) for key in _FRAME_LIST_KEYS):
        raise ValueError("invalid_situation_frame_payload")
    if type(payload["freshness_seconds"]) is not int or type(payload["truncated"]) is not bool:
        raise ValueError("invalid_situation_frame_payload")
    prov = payload["provenance"]
    if not isinstance(prov, Mapping) or any(not isinstance(v, list) for v in prov.values()):
        raise ValueError("invalid_situation_frame_payload")
    if payload["deception_status"] not in OPTIONAL_DEPENDENCY_STATUSES or payload["knowledge_status"] not in OPTIONAL_DEPENDENCY_STATUSES:
        raise ValueError("invalid_situation_frame_payload")
    has_refs = bool(payload["knowledge_refs"])
    if (payload["knowledge_status"] == "available") != has_refs:
        raise ValueError("inconsistent_knowledge_status")
    if has_refs and "knowledge" not in prov.get("knowledge_refs", []):
        raise ValueError("inconsistent_knowledge_provenance")


def _normalize_provenance(value: Any) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if value is None:
        return ()
    if not isinstance(value, Mapping):
        raise ValueError("invalid_provenance")
    out: list[tuple[str, tuple[str, ...]]] = []
    for group in sorted(value):
        if group not in PROVENANCE_GROUPS:
            raise ValueError("invalid_provenance_group")
        sources = value[group]
        if not isinstance(sources, (list, tuple)) or any(src not in PROVENANCE_SOURCES for src in sources):
            raise ValueError("invalid_provenance_source")
        if sources:
            out.append((group, tuple(sorted(set(sources)))))
    return tuple(out)


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
    schema_version: str = SITUATION_FRAME_SCHEMA_VERSION
    knowledge_status: str = "not_provided"
    deception_status: str = "not_provided"
    provenance: tuple[tuple[str, tuple[str, ...]], ...] = ()

    @classmethod
    def build(cls, *, frame_id: str, trace_id: str, created_at: str, mission: str, current_defensive_state: str, threat_level: str, noc_summary: str = "", soc_summary: str = "", known_facts: Sequence[Any] | None = None, unknowns: Sequence[Any] | None = None, contradictions: Sequence[Any] | None = None, evidence_refs: Sequence[Any] | None = None, knowledge_refs: Sequence[Any] | None = None, freshness_seconds: int = 0, knowledge_status: str | None = None, deception_status: str | None = None, provenance: Mapping[str, Sequence[str]] | None = None, input_truncated: bool = False) -> "MioSituationFrame":
        caps = SITUATION_FRAME_CAPS
        defensive_state = _bounded_text(current_defensive_state, 24).upper()
        if defensive_state not in DEFENSIVE_STATES:
            raise ValueError("invalid_defensive_state")
        k_status = _dependency_status(knowledge_status, has_refs=bool(_sequence_len(knowledge_refs)))
        d_status = _dependency_status(deception_status, has_refs=False)
        unknown_items = list(unknowns) if isinstance(unknowns, (list, tuple)) else []
        if k_status != "available":
            # No fabricated context: a degraded/absent Knowledge projection
            # never contributes refs, and degradation is an explicit unknown.
            knowledge_refs = ()
        # Dependency degradation markers go first so caller-supplied unknowns
        # can never crowd them out of the capped list.
        markers = [f"{name}_{status.upper()}" for name, status in (("KNOWLEDGE", k_status), ("DECEPTION", d_status)) if status in _DEGRADED_DEPENDENCY_STATUSES]
        unknown_items = markers + unknown_items
        source_counts = {"known_facts": _sequence_len(known_facts), "unknowns": len(unknown_items), "contradictions": _sequence_len(contradictions), "evidence_refs": _sequence_len(evidence_refs), "knowledge_refs": _sequence_len(knowledge_refs)}
        freshness = max(0, min(_safe_int(freshness_seconds, 86400), 86400))
        prov = dict(_normalize_provenance(provenance))
        if k_status != "available":
            prov.pop("knowledge_refs", None)
        frame = cls(frame_id=_bounded_text(frame_id, 96), trace_id=_bounded_text(trace_id, 96), created_at=_bounded_text(created_at, 64), mission=_bounded_text(mission, 240), current_defensive_state=defensive_state, threat_level=_bounded_text(threat_level, 24).upper(), noc_summary=_bounded_text(noc_summary, 480), soc_summary=_bounded_text(soc_summary, 480), known_facts=_bounded_unique(known_facts, limit=caps["known_facts"]), unknowns=_bounded_unique(unknown_items, limit=caps["unknowns"]), contradictions=_bounded_unique(contradictions, limit=caps["contradictions"]), evidence_refs=_bounded_unique(evidence_refs, limit=caps["evidence_refs"], item_limit=128), knowledge_refs=_bounded_unique(knowledge_refs, limit=caps["knowledge_refs"], item_limit=128), freshness_seconds=freshness, truncated=bool(input_truncated) or any(source_counts[key] > caps[key] for key in caps), knowledge_status=k_status, deception_status=d_status, provenance=tuple(sorted(prov.items())))
        return frame._enforce_byte_budget()

    def _enforce_byte_budget(self) -> "MioSituationFrame":
        frame = self
        while len(frame.to_canonical_json()) > SITUATION_FRAME_MAX_SERIALIZED_BYTES:
            changes: dict[str, Any] = {"truncated": True}
            for name in _TRIM_ORDER:
                items = getattr(frame, name)
                # Keep one knowledge ref so "available" stays consistent with
                # its refs (from_dict rejects available-without-refs).
                if len(items) > (1 if name == "knowledge_refs" else 0):
                    changes[name] = items[:-1]
                    break
            else:
                longest = max(_TRIM_TEXT_FIELDS, key=lambda n: len(getattr(frame, n)))
                text = getattr(frame, longest)
                if not text:
                    raise ValueError("situation_frame_budget_unreachable")
                changes[longest] = text[: len(text) // 2]
            frame = replace(frame, **changes)
        return frame

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "MioSituationFrame":
        """Rebuild a frame from to_dict() output. The key set and types are closed;
        Knowledge "available" must carry refs with "knowledge" provenance."""
        _validate_frame_payload(payload)
        frame = cls.build(frame_id=payload.get("frame_id", ""), trace_id=payload.get("trace_id", ""), created_at=payload.get("created_at", ""), mission=payload.get("mission", ""), current_defensive_state=payload.get("current_defensive_state", ""), threat_level=payload.get("threat_level", ""), noc_summary=payload.get("noc_summary", ""), soc_summary=payload.get("soc_summary", ""), known_facts=payload.get("known_facts"), unknowns=payload.get("unknowns"), contradictions=payload.get("contradictions"), evidence_refs=payload.get("evidence_refs"), knowledge_refs=payload.get("knowledge_refs"), freshness_seconds=payload.get("freshness_seconds", 0), knowledge_status=payload["knowledge_status"], deception_status=payload["deception_status"], provenance=payload["provenance"], input_truncated=bool(payload.get("truncated")))
        return frame

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "frame_id": self.frame_id, "trace_id": self.trace_id, "created_at": self.created_at, "mission": self.mission, "current_defensive_state": self.current_defensive_state, "threat_level": self.threat_level, "noc_summary": self.noc_summary, "soc_summary": self.soc_summary, "known_facts": list(self.known_facts), "unknowns": list(self.unknowns), "contradictions": list(self.contradictions), "evidence_refs": list(self.evidence_refs), "knowledge_refs": list(self.knowledge_refs), "knowledge_status": self.knowledge_status, "deception_status": self.deception_status, "provenance": {group: list(sources) for group, sources in self.provenance}, "freshness_seconds": self.freshness_seconds, "truncated": self.truncated}

    def to_canonical_json(self) -> bytes:
        """Canonical bytes for replay/golden fixtures: sorted keys, no spaces, ASCII-escaped."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.to_canonical_json()).hexdigest()


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
        return cls(gap_id=_bounded_text(payload.get("gap_id") or f"g{ordinal}", 96), question=_bounded_text(payload.get("question"), 300), discriminates_hypothesis_ids=_bounded_unique(payload.get("discriminates_hypothesis_ids"), limit=8, item_limit=96), capability=_bounded_text(payload.get("capability"), 96), priority=max(0, min(_safe_int(payload.get("priority", 50), 50), 100)))


@dataclass(frozen=True)
class MioCapabilityRequest:
    request_id: str
    trace_id: str
    capability: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    # Hypothesis IDs this request is meant to discriminate (audit only).
    purpose_hypothesis_ids: tuple[str, ...] = ()
    # Optional tighter freshness requirement; the broker applies min(spec, request).
    max_age_seconds: int | None = None


@dataclass(frozen=True)
class MioCapabilityResult:
    request_id: str
    capability: str
    ok: bool
    data: Mapping[str, Any]
    evidence_refs: tuple[str, ...] = ()
    error: str = ""
    # Broker-assigned execution metadata (#384). Adapters cannot set these.
    status: str = "ok"  # ok|unavailable|timeout|stale|rejected|invalid|truncated|error
    source_component: str = ""
    source_timestamp: str = ""
    retrieved_at: str = ""
    age_seconds: int | None = None
    max_age_seconds: int | None = None
    latency_ms: int = 0
    result_chars: int = 0
    truncated: bool = False
    limitations: tuple[str, ...] = ()
    # Free-form strings from adapters may originate from attacker-facing
    # sources: they are data, never instructions.
    trust: str = "untrusted_data"


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
