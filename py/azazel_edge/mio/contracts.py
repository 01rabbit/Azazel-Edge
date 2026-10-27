from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import re
from enum import Enum
from typing import Any, Mapping, Sequence

from .id_grammar import EVIDENCE_REF, EVIDENCE_REF_KINDS, id_ok, opaque_id as _opaque_id  # noqa: F401


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
# must bump SITUATION_FRAME_SCHEMA_VERSION and add/update the golden fixture
# tests/fixtures/mio/situation_frame_canonical_<version>.json in the same PR.
# The frame is advisory-only input to M.I.O.; it carries no Edge authority.
SITUATION_FRAME_SCHEMA_VERSION = "mio.situation_frame.v2"
# Older versions from_dict() still reads (replay fixtures, stored frames). They
# are upgraded on read: v1 had no actors/actions/deception_context, so those
# come back empty and nothing is invented for them.
SITUATION_FRAME_LEGACY_SCHEMA_VERSIONS = ("mio.situation_frame.v1",)
SITUATION_FRAME_SCHEMA_OWNER = "azazel_edge.mio.contracts"
SITUATION_FRAME_CAPS = {"known_facts": 16, "unknowns": 12, "contradictions": 8, "evidence_refs": 32, "knowledge_refs": 16, "actors": 8, "actions": 4}
# Per-actor caps (v2). Counts (event_count, distinct_target_ports) stay exact
# so the capped lists carry their own truncation metadata.
SITUATION_FRAME_ACTOR_CAPS = {"protocols": 4, "target_ports": 8, "event_kinds": 4, "evidence_refs": 4}
SITUATION_FRAME_ACTION_EVIDENCE_REFS_CAP = 4
SITUATION_FRAME_DECEPTION_OBSERVATION_REFS_CAP = 8
# Hard ceiling for to_canonical_json(). Documented in
# docs/architecture/mio-situation-frame.md; enforced by deterministic trimming.
SITUATION_FRAME_MAX_SERIALIZED_BYTES = 16384
# Optional dependency status vocabulary (Knowledge / AZ-06 deception facts).
OPTIONAL_DEPENDENCY_STATUSES = ("available", "not_provided", "unavailable", "timeout", "malformed")
_DEGRADED_DEPENDENCY_STATUSES = {"unavailable", "timeout", "malformed"}
# Closed vocabularies of the v2 nested records. Out-of-vocabulary values are
# rendered as "unknown" by build() and rejected by from_dict().
ACTION_ROLES = ("current", "previous")
# Action vocabularies are the ones Edge's own records use, so the producer
# (#385) maps nothing it does not have. applied_state: explanations/live.py
# applied_state(); mode: the Rust core's enforcement.mode (maybe_enforce), with
# "none" when the record has no mode (live.py control_mode); release_condition:
# "lease_expiry" only for an applied action whose release ledger state is
# active/uncertain (live.py _release_condition), otherwise "none". A record
# with any other value is malformed and dropped, never rendered as "unknown".
ACTION_APPLIED_STATES = ("applied", "not_applied", "apply_failed", "none")
ACTION_MODES = ("disabled", "dry_run", "policy_gated", "release_guard_failed", "enforced", "none")
ACTION_RELEASE_CONDITIONS = ("lease_expiry", "none")
# Closed vocabularies for actor features; anything else counts as "other".
ACTOR_PROTOCOLS = ("tcp", "udp", "icmp", "icmpv6", "sctp", "gre", "esp", "ah", "igmp", "other")
_PROTOCOL_ALIASES = {"ipv6-icmp": "icmpv6", "icmp6": "icmpv6"}
ACTOR_EVENT_KINDS = ("alert", "anomaly", "drop", "flow", "flow_summary", "netflow", "dns", "http", "tls", "ssh", "smtp", "ftp", "smb", "dhcp", "fileinfo", "other")
DECEPTION_LIFECYCLE_STATES = ("inactive", "provisioning", "active", "terminating", "terminated", "unknown")
# Provenance vocabulary: which deterministic input produced each fact group.
PROVENANCE_GROUPS = ("known_facts", "unknowns", "contradictions", "evidence_refs", "knowledge_refs", "freshness_seconds", "actors", "actions", "deception_context")
PROVENANCE_SOURCES = ("caller", "deception", "decision_audit", "evidence_plane", "frame_builder", "knowledge", "noc_evaluation", "soc_evaluation")
# Deterministic trim order when the serialized ceiling is exceeded: drop
# low-value detail before uncertainty markers, never touch identity fields.
# (field, items always kept): one knowledge ref keeps "available" consistent,
# one action keeps the current action.
_TRIM_ORDER = (("evidence_refs", 0), ("knowledge_refs", 1), ("actors", 0), ("actions", 1), ("known_facts", 0), ("contradictions", 0), ("unknowns", 0))
_TRIM_TEXT_FIELDS = ("noc_summary", "soc_summary", "mission")

# Markers placed by build() when a caller-supplied nested record is dropped.
ACTOR_SUMMARY_MALFORMED = "ACTOR_SUMMARY_MALFORMED"
ACTION_RECORD_MALFORMED = "ACTION_RECORD_MALFORMED"
MULTIPLE_CURRENT_ACTIONS = "MULTIPLE_CURRENT_ACTIONS"
CURRENT_ACTION_STATE_MISMATCH = "CURRENT_ACTION_STATE_MISMATCH"
DECEPTION_LIFECYCLE_UNKNOWN = "DECEPTION_LIFECYCLE_UNKNOWN"

# Nested strings are never free text: keys, ids, tokens and timestamps have a
# fixed shape, so attacker-authored text cannot enter through them.
# Frame-local ordinal: actor:0001 is the first actor of this frame. It is not
# derived from the source in any way, so it cannot be inverted to an address.
_ACTOR_KEY_RE = re.compile(r"actor:\d{4}\Z")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_MAX_COUNT = 1_000_000


def actor_key_at(position: int) -> str:
    return f"actor:{position + 1:04d}"


# --- MODEL ID GRAMMAR (#386) ------------------------------------------------
# Identifiers the MODEL writes are attacker-reachable. Each field accepts a
# fixed tuple of the kinds defined once in id_grammar.ID_KINDS (shared with the
# no-model handoff and the broker audit); anything else is refused. The second
# layer (address and secret shapes) is id_grammar.second_layer_ok. A refused
# value is replaced at parse time by INVALID_MODEL_ID and never kept; the
# grounding validator rejects the output with the fixed code
# ``invalid_model_id:<field>``. Integers and other non-str values are refused,
# never stringified.
INVALID_MODEL_ID = "invalid-model-id"
INVALID_MODEL_ID_CODE = "invalid_model_id"
MODEL_ID_GRAMMAR: Mapping[str, tuple[str, ...]] = {
    # Edge refs plus the model-only ATT&CK knowledge and offline fixture refs.
    "evidence_ref": EVIDENCE_REF + ("knowledge_ref", "fixture_ref"),
    "hypothesis_id": ("hypothesis_id",),
    "gap_id": ("gap_id",),
    "capability": ("capability",),
}


def model_id_ok(value: Any, kind: str) -> bool:
    """True when ``value`` exactly matches the allowlist for ``kind``."""
    kinds = MODEL_ID_GRAMMAR.get(kind)
    return kinds is not None and id_ok(value, kinds)


def safe_model_id(value: Any, kind: str) -> str:
    """``value`` if it passes ``model_id_ok`` for ``kind``, else ``INVALID_MODEL_ID``."""
    return value if model_id_ok(value, kind) else INVALID_MODEL_ID


def _model_id(value: Any, default: str, kind: str) -> str:
    # Missing or empty -> the deterministic default; anything else must pass.
    if value is None or value == "":
        return default
    return safe_model_id(value, kind)


def _model_id_list(values: Any, *, limit: int, kind: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    out: list[str] = []
    for raw in values:
        if raw is None or raw == "":
            continue
        value = safe_model_id(raw, kind)
        if value not in out:
            out.append(value)
            if len(out) >= limit:
                break
    return tuple(out)


def _id_list(values: Any, limit: int) -> tuple[str, ...]:
    out: list[str] = []
    for raw in values if isinstance(values, (list, tuple)) else ():
        value = _opaque_id(raw)
        if value and value not in out:
            out.append(value)
            if len(out) >= limit:
                break
    return tuple(out)


def normalize_protocol(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text or text == "-":
        return ""
    text = _PROTOCOL_ALIASES.get(text, text)
    return text if text in ACTOR_PROTOCOLS else "other"


def normalize_event_kind(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    return text if text in ACTOR_EVENT_KINDS else "other"


def _vocab_list(values: Any, vocabulary: Sequence[str], limit: int) -> tuple[str, ...]:
    out: list[str] = []
    for raw in values if isinstance(values, (list, tuple)) else ():
        if isinstance(raw, str) and raw in vocabulary and raw not in out:
            out.append(raw)
            if len(out) >= limit:
                break
    return tuple(out)


def _canonical_ts(value: Any) -> str:
    return value if isinstance(value, str) and _TS_RE.match(value) else ""


def _count(value: Any, upper: int = _MAX_COUNT) -> int:
    return max(0, min(value, upper)) if type(value) is int else 0


def _vocab(value: Any, vocabulary: Sequence[str]) -> str:
    return value if isinstance(value, str) and value in vocabulary else "unknown"


def _as_plain(value: Any) -> Any:
    return value.to_dict() if hasattr(value, "to_dict") else value


def _same_json(a: Any, b: Any) -> bool:
    # Type-exact comparison (1 != 1.0 != True) for the closed from_dict check.
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


@dataclass(frozen=True)
class MioActorSummary:
    """Bounded behavioural summary of one actor (v2). No address, no free text."""

    actor_key: str
    first_seen: str = ""
    last_seen: str = ""
    event_count: int = 0
    max_severity: int = 0
    protocols: tuple[str, ...] = ()
    target_ports: tuple[int, ...] = ()
    distinct_target_ports: int = 0
    event_kinds: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def coerce(cls, value: Any) -> "MioActorSummary | None":
        value = _as_plain(value)
        if not isinstance(value, Mapping):
            return None
        key = value.get("actor_key")
        if not isinstance(key, str) or not _ACTOR_KEY_RE.match(key):
            return None
        first, last = _canonical_ts(value.get("first_seen")), _canonical_ts(value.get("last_seen"))
        if first and last and first > last:
            return None
        caps = SITUATION_FRAME_ACTOR_CAPS
        ports: list[int] = []
        raw_ports = value.get("target_ports")
        for port in raw_ports if isinstance(raw_ports, (list, tuple)) else ():
            if type(port) is int and 0 < port <= 65535 and port not in ports:
                ports.append(port)
                if len(ports) >= caps["target_ports"]:
                    break
        return cls(
            actor_key=key,
            first_seen=first,
            last_seen=last,
            event_count=_count(value.get("event_count")),
            max_severity=_count(value.get("max_severity"), 100),
            protocols=_vocab_list(value.get("protocols"), ACTOR_PROTOCOLS, caps["protocols"]),
            target_ports=tuple(ports),
            distinct_target_ports=max(len(ports), _count(value.get("distinct_target_ports"), 65535)),
            event_kinds=_vocab_list(value.get("event_kinds"), ACTOR_EVENT_KINDS, caps["event_kinds"]),
            evidence_refs=_id_list(value.get("evidence_refs"), caps["evidence_refs"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"actor_key": self.actor_key, "first_seen": self.first_seen, "last_seen": self.last_seen, "event_count": self.event_count, "max_severity": self.max_severity, "protocols": list(self.protocols), "target_ports": list(self.target_ports), "distinct_target_ports": self.distinct_target_ports, "event_kinds": list(self.event_kinds), "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class MioActionRecord:
    """A defensive action Edge already selected (current or previous). A fact
    recorded from Edge's decision audit; M.I.O. never selects or changes it.
    The producer that turns Edge's records into these is #385."""

    role: str
    action: str
    decision_ref: str
    applied_state: str
    mode: str
    release_condition: str = "none"
    decided_at: str = ""
    expires_at: str = ""
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def coerce(cls, value: Any) -> "MioActionRecord | None":
        value = _as_plain(value)
        if not isinstance(value, Mapping):
            return None
        role, action, ref = value.get("role"), value.get("action"), _opaque_id(value.get("decision_ref"))
        if role not in ACTION_ROLES or not isinstance(action, str) or action not in DEFENSIVE_STATES or not ref:
            return None
        applied, mode = value.get("applied_state"), value.get("mode")
        release = value.get("release_condition", "none")
        if applied not in ACTION_APPLIED_STATES or mode not in ACTION_MODES or release not in ACTION_RELEASE_CONDITIONS:
            return None
        expires_raw = value.get("expires_at", "")
        expires = _canonical_ts(expires_raw)
        decided_raw = value.get("decided_at", "")
        decided = _canonical_ts(decided_raw)
        if (expires_raw and not expires) or (decided_raw and not decided):
            return None
        # A lease exists only for an applied action (live.py); its due time
        # only with a lease.
        if release == "lease_expiry" and applied != "applied":
            return None
        if expires and release != "lease_expiry":
            return None
        return cls(role=role, action=action, decision_ref=ref, applied_state=applied, mode=mode, release_condition=release, decided_at=decided, expires_at=expires, evidence_refs=_id_list(value.get("evidence_refs"), SITUATION_FRAME_ACTION_EVIDENCE_REFS_CAP))

    def sort_key(self) -> tuple:
        # current first, then newest first; undated records last; then by ref.
        newest = -int("".join(ch for ch in self.decided_at if ch.isdigit()) or 0)
        return (self.role != "current", not self.decided_at, newest, self.decision_ref)

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "action": self.action, "decision_ref": self.decision_ref, "applied_state": self.applied_state, "mode": self.mode, "release_condition": self.release_condition, "decided_at": self.decided_at, "expires_at": self.expires_at, "evidence_refs": list(self.evidence_refs)}


@dataclass(frozen=True)
class MioDeceptionContext:
    """AZ-06 facts only: identifiers, lifecycle state, observation refs. Never
    belief, intent or authority; AZ-06 state is not Edge authority."""

    environment_id: str
    package_id: str = ""
    node_id: str = ""
    lifecycle_state: str = "unknown"
    observation_refs: tuple[str, ...] = ()

    @classmethod
    def coerce(cls, value: Any) -> "MioDeceptionContext | None":
        value = _as_plain(value)
        if not isinstance(value, Mapping):
            return None
        environment_id = _opaque_id(value.get("environment_id"))
        if not environment_id:
            return None
        return cls(environment_id=environment_id, package_id=_opaque_id(value.get("package_id")), node_id=_opaque_id(value.get("node_id")), lifecycle_state=_vocab(value.get("lifecycle_state"), DECEPTION_LIFECYCLE_STATES), observation_refs=_id_list(value.get("observation_refs"), SITUATION_FRAME_DECEPTION_OBSERVATION_REFS_CAP))

    def to_dict(self) -> dict[str, Any]:
        return {"environment_id": self.environment_id, "package_id": self.package_id, "node_id": self.node_id, "lifecycle_state": self.lifecycle_state, "observation_refs": list(self.observation_refs)}


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
_FRAME_KEYS_V1 = frozenset(_FRAME_TEXT_KEYS + _FRAME_LIST_KEYS + ("provenance", "freshness_seconds", "truncated"))
_FRAME_KEYS = _FRAME_KEYS_V1 | {"actors", "actions", "deception_context"}


def _validate_nested(payload: Mapping[str, Any]) -> None:
    """v2 nested records must be fixed points of their coercion: same keys,
    same types, in-vocabulary values, within caps. Nothing is repaired."""
    actors, actions, context = payload["actors"], payload["actions"], payload["deception_context"]
    if not isinstance(actors, list) or len(actors) > SITUATION_FRAME_CAPS["actors"]:
        raise ValueError("invalid_situation_frame_actors")
    for position, item in enumerate(actors):
        actor = MioActorSummary.coerce(item) if isinstance(item, Mapping) else None
        if actor is None or not _same_json(actor.to_dict(), item) or actor.actor_key != actor_key_at(position):
            raise ValueError("invalid_situation_frame_actors")
    if not isinstance(actions, list) or len(actions) > SITUATION_FRAME_CAPS["actions"]:
        raise ValueError("invalid_situation_frame_actions")
    for item in actions:
        action = MioActionRecord.coerce(item) if isinstance(item, Mapping) else None
        if action is None or not _same_json(action.to_dict(), item):
            raise ValueError("invalid_situation_frame_actions")
    if sum(1 for item in actions if item["role"] == "current") > 1:
        raise ValueError("invalid_situation_frame_actions")
    if context is not None:
        ctx = MioDeceptionContext.coerce(context) if isinstance(context, Mapping) else None
        if ctx is None or not _same_json(ctx.to_dict(), context):
            raise ValueError("invalid_situation_frame_deception_context")
    if (payload["deception_status"] == "available") != (context is not None):
        raise ValueError("inconsistent_deception_status")
    if context is not None and "deception" not in payload["provenance"].get("deception_context", []):
        raise ValueError("inconsistent_deception_provenance")


def _validate_frame_payload(payload: Any) -> None:
    if not isinstance(payload, Mapping):
        raise ValueError("invalid_situation_frame_payload")
    version = payload.get("schema_version")
    if version not in (SITUATION_FRAME_SCHEMA_VERSION,) + SITUATION_FRAME_LEGACY_SCHEMA_VERSIONS:
        raise ValueError("unsupported_situation_frame_schema_version")
    if set(payload) != (_FRAME_KEYS if version == SITUATION_FRAME_SCHEMA_VERSION else _FRAME_KEYS_V1):
        raise ValueError("invalid_situation_frame_payload")
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
    if version == SITUATION_FRAME_SCHEMA_VERSION:
        _validate_nested(payload)
    elif payload["deception_status"] == "available":
        # v1 never carried deception content, so "available" was never valid.
        raise ValueError("inconsistent_deception_status")


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


def _coerce_actors(values: Any) -> tuple[list[MioActorSummary], bool]:
    out: list[MioActorSummary] = []
    malformed = False
    for raw in values if isinstance(values, (list, tuple)) else ():
        actor = MioActorSummary.coerce(raw)
        if actor is None:
            malformed = True
        else:
            # Keys are frame-local positions: renumber, so a caller cannot
            # carry a source-derived key and trimming keeps them contiguous.
            out.append(replace(actor, actor_key=actor_key_at(len(out))))
    return out, malformed


def _coerce_actions(values: Any) -> tuple[list[MioActionRecord], bool, bool]:
    records: list[MioActionRecord] = []
    malformed = False
    for raw in values if isinstance(values, (list, tuple)) else ():
        record = MioActionRecord.coerce(raw)
        if record is None:
            malformed = True
        elif all(r.decision_ref != record.decision_ref for r in records):
            records.append(record)
    records.sort(key=MioActionRecord.sort_key)
    # Edge has one current action. More than one is a contradiction in the
    # input: keep the newest and drop the others rather than demote them.
    currents = [r for r in records if r.role == "current"]
    if len(currents) > 1:
        records = [r for r in records if r.role != "current" or r is currents[0]]
    return records, malformed, len(currents) > 1


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
    actors: tuple[MioActorSummary, ...] = ()
    actions: tuple[MioActionRecord, ...] = ()
    deception_context: MioDeceptionContext | None = None

    @classmethod
    def build(cls, *, frame_id: str, trace_id: str, created_at: str, mission: str, current_defensive_state: str, threat_level: str, noc_summary: str = "", soc_summary: str = "", known_facts: Sequence[Any] | None = None, unknowns: Sequence[Any] | None = None, contradictions: Sequence[Any] | None = None, evidence_refs: Sequence[Any] | None = None, knowledge_refs: Sequence[Any] | None = None, freshness_seconds: int = 0, knowledge_status: str | None = None, deception_status: str | None = None, provenance: Mapping[str, Sequence[str]] | None = None, input_truncated: bool = False, actors: Sequence[Any] | None = None, actions: Sequence[Any] | None = None, deception_context: Any = None) -> "MioSituationFrame":
        caps = SITUATION_FRAME_CAPS
        defensive_state = _bounded_text(current_defensive_state, 24).upper()
        if defensive_state not in DEFENSIVE_STATES:
            raise ValueError("invalid_defensive_state")
        k_status = _dependency_status(knowledge_status, has_refs=bool(_sequence_len(knowledge_refs)))
        context = MioDeceptionContext.coerce(deception_context) if deception_context is not None else None
        if deception_context is not None and context is None and str(deception_status or "").strip().lower() not in _DEGRADED_DEPENDENCY_STATUSES:
            # A supplied but unusable projection is malformed, not absent.
            deception_status = "malformed"
        d_status = _dependency_status(deception_status, has_refs=context is not None)
        if d_status != "available":
            context = None
        actor_items, actors_malformed = _coerce_actors(actors)
        action_items, actions_malformed, several_current = _coerce_actions(actions)
        unknown_items = list(unknowns) if isinstance(unknowns, (list, tuple)) else []
        if k_status != "available":
            # No fabricated context: a degraded/absent Knowledge projection
            # never contributes refs, and degradation is an explicit unknown.
            knowledge_refs = ()
        # Dependency degradation markers go first so caller-supplied unknowns
        # can never crowd them out of the capped list. They are re-derived on
        # every build, so they stay a prefix and from_dict() is idempotent.
        markers = [f"{name}_{status.upper()}" for name, status in (("KNOWLEDGE", k_status), ("DECEPTION", d_status)) if status in _DEGRADED_DEPENDENCY_STATUSES]
        if context is not None and context.lifecycle_state == "unknown":
            markers.append(DECEPTION_LIFECYCLE_UNKNOWN)
        markers += [m for m, bad in ((ACTOR_SUMMARY_MALFORMED, actors_malformed), (ACTION_RECORD_MALFORMED, actions_malformed)) if bad]
        unknown_items = markers + unknown_items
        contradiction_items = list(contradictions) if isinstance(contradictions, (list, tuple)) else []
        current = next((r for r in action_items if r.role == "current"), None)
        # The mismatch marker is re-derived on every build; MULTIPLE_CURRENT_ACTIONS
        # is not (only one current survives), so it must come after it.
        action_markers = [m for m, bad in ((CURRENT_ACTION_STATE_MISMATCH, current is not None and current.action != defensive_state), (MULTIPLE_CURRENT_ACTIONS, several_current)) if bad]
        contradiction_items = action_markers + contradiction_items
        source_counts = {"known_facts": _sequence_len(known_facts), "unknowns": len(unknown_items), "contradictions": len(contradiction_items), "evidence_refs": _sequence_len(evidence_refs), "knowledge_refs": _sequence_len(knowledge_refs), "actors": len(actor_items), "actions": len(action_items)}
        freshness = max(0, min(_safe_int(freshness_seconds, 86400), 86400))
        prov = dict(_normalize_provenance(provenance))
        if k_status != "available":
            prov.pop("knowledge_refs", None)
        if context is None:
            prov.pop("deception_context", None)
        frame = cls(frame_id=_bounded_text(frame_id, 96), trace_id=_bounded_text(trace_id, 96), created_at=_bounded_text(created_at, 64), mission=_bounded_text(mission, 240), current_defensive_state=defensive_state, threat_level=_bounded_text(threat_level, 24).upper(), noc_summary=_bounded_text(noc_summary, 480), soc_summary=_bounded_text(soc_summary, 480), known_facts=_bounded_unique(known_facts, limit=caps["known_facts"]), unknowns=_bounded_unique(unknown_items, limit=caps["unknowns"]), contradictions=_bounded_unique(contradiction_items, limit=caps["contradictions"]), evidence_refs=_bounded_unique(evidence_refs, limit=caps["evidence_refs"], item_limit=128), knowledge_refs=_bounded_unique(knowledge_refs, limit=caps["knowledge_refs"], item_limit=128), freshness_seconds=freshness, truncated=bool(input_truncated) or any(source_counts[key] > caps[key] for key in caps), knowledge_status=k_status, deception_status=d_status, provenance=tuple(sorted(prov.items())), actors=tuple(actor_items[: caps["actors"]]), actions=tuple(action_items[: caps["actions"]]), deception_context=context)
        return frame._enforce_byte_budget()

    def _enforce_byte_budget(self) -> "MioSituationFrame":
        frame = self
        while len(frame.to_canonical_json()) > SITUATION_FRAME_MAX_SERIALIZED_BYTES:
            changes: dict[str, Any] = {"truncated": True}
            for name, keep in _TRIM_ORDER:
                items = getattr(frame, name)
                if len(items) > keep:
                    changes[name] = items[:-1]
                    break
                if name == "actions" and frame.deception_context is not None and frame.deception_context.observation_refs:
                    # The context itself stays (it is what "available" means);
                    # its observation refs go before facts and markers.
                    ctx = frame.deception_context
                    changes["deception_context"] = replace(ctx, observation_refs=ctx.observation_refs[:-1])
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
        Knowledge "available" must carry refs with "knowledge" provenance, AZ-06
        "available" a deception_context with "deception" provenance.
        A legacy v1 payload is upgraded: its fields are kept as they are and the
        v2 fields come back empty (v1 never captured them)."""
        _validate_frame_payload(payload)
        frame = cls.build(frame_id=payload.get("frame_id", ""), trace_id=payload.get("trace_id", ""), created_at=payload.get("created_at", ""), mission=payload.get("mission", ""), current_defensive_state=payload.get("current_defensive_state", ""), threat_level=payload.get("threat_level", ""), noc_summary=payload.get("noc_summary", ""), soc_summary=payload.get("soc_summary", ""), known_facts=payload.get("known_facts"), unknowns=payload.get("unknowns"), contradictions=payload.get("contradictions"), evidence_refs=payload.get("evidence_refs"), knowledge_refs=payload.get("knowledge_refs"), freshness_seconds=payload.get("freshness_seconds", 0), knowledge_status=payload["knowledge_status"], deception_status=payload["deception_status"], provenance=payload["provenance"], input_truncated=bool(payload.get("truncated")), actors=payload.get("actors"), actions=payload.get("actions"), deception_context=payload.get("deception_context"))
        return frame

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "frame_id": self.frame_id, "trace_id": self.trace_id, "created_at": self.created_at, "mission": self.mission, "current_defensive_state": self.current_defensive_state, "threat_level": self.threat_level, "noc_summary": self.noc_summary, "soc_summary": self.soc_summary, "known_facts": list(self.known_facts), "unknowns": list(self.unknowns), "contradictions": list(self.contradictions), "evidence_refs": list(self.evidence_refs), "knowledge_refs": list(self.knowledge_refs), "knowledge_status": self.knowledge_status, "deception_status": self.deception_status, "provenance": {group: list(sources) for group, sources in self.provenance}, "freshness_seconds": self.freshness_seconds, "truncated": self.truncated, "actors": [a.to_dict() for a in self.actors], "actions": [a.to_dict() for a in self.actions], "deception_context": None if self.deception_context is None else self.deception_context.to_dict()}

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
        return cls(hypothesis_id=_model_id(payload.get("hypothesis_id"), f"h{ordinal}", "hypothesis_id"), statement=_bounded_text(payload.get("statement"), 360), status=status, supporting_evidence_refs=_model_id_list(payload.get("supporting_evidence_refs"), limit=16, kind="evidence_ref"), contradicting_evidence_refs=_model_id_list(payload.get("contradicting_evidence_refs"), limit=16, kind="evidence_ref"), assumptions=_bounded_unique(payload.get("assumptions"), limit=8), falsification_conditions=_bounded_unique(payload.get("falsification_conditions"), limit=8), expected_observations=_bounded_unique(payload.get("expected_observations"), limit=8), missing_evidence=_bounded_unique(payload.get("missing_evidence"), limit=8))

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
        raw_capability = payload.get("capability")
        capability = "" if raw_capability is None or raw_capability == "" else safe_model_id(raw_capability, "capability")
        return cls(gap_id=_model_id(payload.get("gap_id"), f"g{ordinal}", "gap_id"), question=_bounded_text(payload.get("question"), 300), discriminates_hypothesis_ids=_model_id_list(payload.get("discriminates_hypothesis_ids"), limit=8, kind="hypothesis_id"), capability=capability, priority=max(0, min(_safe_int(payload.get("priority", 50), 50), 100)))


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
        return cls(advisory_id=_bounded_text(advisory_id, 96), summary=_bounded_text(payload.get("summary"), 360), recommended_action=_bounded_text(payload.get("recommended_action"), 32).upper(), rationale=_bounded_text(payload.get("rationale"), 720), evidence_refs=_model_id_list(payload.get("evidence_refs"), limit=32, kind="evidence_ref"), limitations=_bounded_unique(payload.get("limitations"), limit=8), executable=False)
