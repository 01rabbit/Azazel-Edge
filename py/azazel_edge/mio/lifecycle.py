"""Hypothesis lifecycle policy and per-trace reasoning-cycle coordination (#385).

Everything here is advisory-only bookkeeping for the M.I.O. shadow loop. No
function in this module calls the arbiter, the enforcement path, or AZ-06, and
no state here grants or implies an Edge action. The coordinator decides only
which advisory result is *current* for a trace; stale/superseded/cancelled
results are discarded from the current view but retained in the audit log.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import threading
from enum import Enum
from typing import Any, Collection, Mapping, Sequence

from .contracts import HypothesisStatus, MioHypothesis, MioSituationFrame


# --- Hypothesis lifecycle --------------------------------------------------

_H = HypothesisStatus
# Terminal statuses: a falsified or superseded hypothesis cannot be revived or edited.
TERMINAL_HYPOTHESIS_STATUSES = frozenset({_H.FALSIFIED, _H.SUPERSEDED})
# Statuses a hypothesis may have when it first appears (round one or a new ID
# in an update). Anything stronger needs a prior state and evidence.
ENTRY_HYPOTHESIS_STATUSES = frozenset({_H.PROPOSED, _H.ACTIVE})
# ``proposed`` is promoted to ``active`` implicitly by the first evidence
# revision, so it may move to any status ``active`` may move to.
_FROM_ACTIVE = frozenset({_H.ACTIVE, _H.STRENGTHENED, _H.WEAKENED, _H.FALSIFIED, _H.UNRESOLVED, _H.SUPERSEDED})
ALLOWED_HYPOTHESIS_TRANSITIONS: Mapping[HypothesisStatus, frozenset[HypothesisStatus]] = {
    _H.PROPOSED: _FROM_ACTIVE | {_H.PROPOSED},
    _H.ACTIVE: _FROM_ACTIVE,
    _H.STRENGTHENED: _FROM_ACTIVE,
    _H.WEAKENED: _FROM_ACTIVE,
    _H.UNRESOLVED: _FROM_ACTIVE,
    _H.FALSIFIED: frozenset({_H.FALSIFIED}),
    _H.SUPERSEDED: frozenset({_H.SUPERSEDED}),
}

# Audit reasons for hypotheses of a cycle that ended early. There is no
# "cancelled" hypothesis status, so both use ``superseded`` with a distinct reason.
REASON_CYCLE_SUPERSEDED = "cycle_superseded_by_newer_frame"
REASON_CYCLE_CANCELLED = "cycle_cancelled_by_operator"


@dataclass(frozen=True)
class HypothesisAuditEntry:
    """One preserved lifecycle step. Entries are never deleted by the loop."""

    hypothesis_id: str
    from_status: str
    to_status: str
    reason: str
    evidence_refs: tuple[str, ...] = ()
    falsification_conditions: tuple[str, ...] = ()
    statement: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "from_status": self.from_status,
            "to_status": self.to_status,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "falsification_conditions": list(self.falsification_conditions),
            "statement": self.statement,
        }


@dataclass(frozen=True)
class LifecycleResult:
    ok: bool
    hypotheses: tuple[MioHypothesis, ...]
    audit: tuple[HypothesisAuditEntry, ...]
    errors: tuple[str, ...]


def _entry(h: MioHypothesis, from_status: str, reason: str) -> HypothesisAuditEntry:
    refs = tuple(dict.fromkeys(h.supporting_evidence_refs + h.contradicting_evidence_refs))
    return HypothesisAuditEntry(h.hypothesis_id, from_status, h.status.value, reason, refs, h.falsification_conditions, h.statement)


def _evidence_errors(h: MioHypothesis, allowed_refs: Collection[str] | None) -> list[str]:
    """strengthened needs supporting refs; weakened needs refuting refs or a named gap.
    When ``allowed_refs`` is given, the cited refs must belong to the current context."""
    errors: list[str] = []
    if h.status is _H.STRENGTHENED:
        refs = h.supporting_evidence_refs
        if not refs:
            errors.append(f"strengthened_without_supporting_evidence:{h.hypothesis_id}")
    elif h.status is _H.WEAKENED:
        refs = h.contradicting_evidence_refs
        if not refs and not h.missing_evidence:
            errors.append(f"weakened_without_refuting_evidence_or_gap:{h.hypothesis_id}")
    elif h.status is _H.FALSIFIED:
        refs = h.contradicting_evidence_refs
    else:
        return errors
    if allowed_refs is not None:
        for ref in refs:
            if ref not in allowed_refs:
                errors.append(f"lifecycle_ref_outside_context:{h.hypothesis_id}:{ref}")
    return errors


def validate_initial_hypotheses(hypotheses: Sequence[MioHypothesis]) -> tuple[str, ...]:
    """Round one has no prior state, so it may only enter as proposed/active."""
    return tuple(
        f"initial_hypothesis_must_start_proposed:{h.hypothesis_id}:{h.status.value}"
        for h in hypotheses
        if h.status not in ENTRY_HYPOTHESIS_STATUSES
    )


def record_initial(hypotheses: Sequence[MioHypothesis]) -> tuple[HypothesisAuditEntry, ...]:
    return tuple(_entry(h, "", "proposed_by_model") for h in hypotheses)


def apply_hypothesis_update(
    previous: Sequence[MioHypothesis],
    proposed: Sequence[MioHypothesis],
    *,
    allowed_refs: Collection[str] | None = None,
) -> LifecycleResult:
    """Validate a model-proposed revision against the deterministic policy.

    * every transition must be in ALLOWED_HYPOTHESIS_TRANSITIONS;
    * ``falsified`` needs contradicting evidence and a falsification condition
      (absence of evidence alone never falsifies);
    * ``strengthened`` needs supporting evidence; ``weakened`` needs refuting
      evidence or a named missing-evidence gap;
    * cited refs must be in ``allowed_refs`` when it is given;
    * a terminal (falsified/superseded) hypothesis cannot be edited at all;
    * a hypothesis the model omits is carried forward unchanged, never
      silently dropped (omission is not falsification);
    * a new hypothesis ID must enter as ``proposed`` or ``active``.
    Any violation rejects the whole update (fail closed, no partial merge).
    """
    prior = {h.hypothesis_id: h for h in previous}
    errors: list[str] = []
    audit: list[HypothesisAuditEntry] = []
    out: list[MioHypothesis] = []
    seen: set[str] = set()
    for h in proposed:
        seen.add(h.hypothesis_id)
        before = prior.get(h.hypothesis_id)
        if before is None:
            if h.status not in ENTRY_HYPOTHESIS_STATUSES:
                errors.append(f"new_hypothesis_must_start_proposed:{h.hypothesis_id}:{h.status.value}")
            audit.append(_entry(h, "", "proposed_in_update"))
            out.append(h)
            continue
        if h.status not in ALLOWED_HYPOTHESIS_TRANSITIONS[before.status]:
            errors.append(f"invalid_hypothesis_transition:{h.hypothesis_id}:{before.status.value}->{h.status.value}")
            continue
        if before.status in TERMINAL_HYPOTHESIS_STATUSES:
            if h != before:
                errors.append(f"terminal_hypothesis_modified:{h.hypothesis_id}:{before.status.value}")
            out.append(before)
            continue
        errors.extend(_evidence_errors(h, allowed_refs))
        if h.status is _H.FALSIFIED and not (h.falsification_conditions or before.falsification_conditions):
            errors.append(f"falsified_without_falsification_condition:{h.hypothesis_id}")
        if h.status is _H.FALSIFIED and not h.contradicting_evidence_refs:
            errors.append(f"falsified_without_contradicting_evidence:{h.hypothesis_id}")
        if h.status is not before.status:
            audit.append(_entry(h, before.status.value, "revised_by_evidence"))
        elif h != before:
            audit.append(_entry(h, before.status.value, "content_revised"))
        out.append(h)
    for before in previous:
        if before.hypothesis_id not in seen:
            audit.append(HypothesisAuditEntry(before.hypothesis_id, before.status.value, before.status.value, "carried_forward_omitted_by_update", (), before.falsification_conditions, before.statement))
            out.append(before)
    if errors:
        return LifecycleResult(False, tuple(previous), (), tuple(errors))
    return LifecycleResult(True, tuple(out), tuple(audit), ())


def supersede_all(hypotheses: Sequence[MioHypothesis], reason: str) -> tuple[HypothesisAuditEntry, ...]:
    """Audit entries marking every non-terminal hypothesis of a dead cycle superseded."""
    entries = []
    for h in hypotheses:
        if h.status in TERMINAL_HYPOTHESIS_STATUSES:
            continue
        refs = tuple(dict.fromkeys(h.supporting_evidence_refs + h.contradicting_evidence_refs))
        entries.append(HypothesisAuditEntry(h.hypothesis_id, h.status.value, _H.SUPERSEDED.value, reason, refs, h.falsification_conditions, h.statement))
    return tuple(entries)


# --- Material frame identity -----------------------------------------------

# Identity, clock and bookkeeping fields. Everything else in the v1 frame is
# material, including mission and the NOC/SOC summaries (derived from status
# and reason codes, no timestamps) and ``truncated`` (it marks lost data).
NON_MATERIAL_FRAME_FIELDS = frozenset({"frame_id", "created_at", "freshness_seconds", "provenance"})
# List fields whose order carries no meaning for the situation (the builder's
# ordering is a capping priority, not semantics); sorted before hashing.
_UNORDERED_FRAME_LISTS = ("known_facts", "unknowns", "contradictions", "evidence_refs", "knowledge_refs")
# v2 actor counters that move with every new event of an ongoing incident. A
# newer material frame supersedes the in-flight cycle, so if these were
# material, sustained traffic could supersede every cycle before it finished.
# The actor's position, severity, protocols, ports and kinds stay material.
NON_MATERIAL_ACTOR_FIELDS = frozenset({"event_count", "first_seen", "last_seen", "distinct_target_ports", "evidence_refs"})


def material_frame_digest(frame: MioSituationFrame) -> str:
    payload = {k: v for k, v in frame.to_dict().items() if k not in NON_MATERIAL_FRAME_FIELDS}
    payload["actors"] = [{k: v for k, v in actor.items() if k not in NON_MATERIAL_ACTOR_FIELDS} for actor in payload["actors"]]
    for key in _UNORDERED_FRAME_LISTS:
        payload[key] = sorted(payload[key])
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


# --- Cycle coordination ----------------------------------------------------


class CycleStatus(str, Enum):
    IN_FLIGHT = "in_flight"
    ACCEPTED = "accepted"
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"
    ABANDONED_ON_RESTART = "abandoned_on_restart"
    RESTORED_STALE = "restored_stale"


# Fixed reason codes for a result that may not become current. The reason is
# chosen from the ticket and the cycle record only, never from the outcome.
STALE_PRE_RESTART = "stale_pre_restart_cycle"
STALE_UNKNOWN_OR_EVICTED = "stale_unknown_or_evicted_cycle"
STALE_TICKET_MISMATCH = "stale_ticket_mismatch"
STALE_SUPERSEDED = "stale_cycle_superseded"
STALE_CANCELLED = "stale_cycle_cancelled"
STALE_ALREADY_COMPLETED = "stale_cycle_already_completed"
STALE_RESULT_REASONS = frozenset({STALE_PRE_RESTART, STALE_UNKNOWN_OR_EVICTED, STALE_TICKET_MISMATCH, STALE_SUPERSEDED, STALE_CANCELLED, STALE_ALREADY_COMPLETED})


@dataclass(frozen=True)
class CycleTicket:
    trace_id: str
    cycle_id: str
    epoch: int
    frame_id: str
    material_digest: str
    deduplicated: bool = False


@dataclass(frozen=True)
class CompletionResult:
    accepted: bool
    cycle_status: str
    reason: str
    outcome: Any = None


@dataclass
class _Cycle:
    ticket: CycleTicket
    status: CycleStatus
    outcome_state: str = ""
    advisory_id: str = ""


COORDINATOR_SNAPSHOT_SCHEMA = "mio.reasoning_coordinator.v1"
_SNAPSHOT_KEYS = frozenset({"schema", "epoch", "next_cycle", "latest", "cycles", "audit", "audit_dropped"})
_CYCLE_KEYS = frozenset({"cycle_id", "trace_id", "epoch", "frame_id", "material_digest", "status", "outcome_state", "advisory_id"})
# Per-row bounds so one audit row cannot grow with model output.
_AUDIT_TEXT_LIMIT = 160
_AUDIT_LIST_LIMIT = 8
_AUDIT_HYPOTHESES_LIMIT = 6
_ID_LIMIT = 192


def _bound(value: Any, depth: int = 0) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, str):
        return value[:_AUDIT_TEXT_LIMIT]
    if isinstance(value, Mapping) and depth < 3:
        return {str(k)[:64]: _bound(v, depth + 1) for k, v in list(value.items())[:16]}
    if isinstance(value, (list, tuple)) and depth < 3:
        return [_bound(v, depth + 1) for v in list(value)[:_AUDIT_LIST_LIMIT]]
    return str(value)[:_AUDIT_TEXT_LIMIT]


def _is_int(value: Any) -> bool:
    return type(value) is int


def _same_cycle(ticket: CycleTicket, own: CycleTicket) -> bool:
    """Ticket identity ignoring the ``deduplicated`` flag."""
    return (ticket.cycle_id, ticket.trace_id, ticket.epoch, ticket.frame_id, ticket.material_digest) == (own.cycle_id, own.trace_id, own.epoch, own.frame_id, own.material_digest)


class ReasoningCoordinator:
    """Owns cycle identity per trace. Thread-safe; working state never crosses traces.

    The coordinator is a pure bookkeeper: it hands out cycle tickets, decides
    whether a finished cycle may become the current advisory for its trace,
    and appends every decision to a bounded audit log. It has no clock: all
    ordering is by begin/complete call order, so replays are deterministic.

    Memory is bounded: at most ``max_traces`` cycles are in flight (one per
    trace), at most ``max_retained_cycles`` finished cycles are kept (oldest
    evicted first, with their trace's current advisory), and the audit log
    keeps ``max_audit_events`` size-bounded rows.
    """

    def __init__(self, *, max_traces: int = 64, max_retained_cycles: int = 256, max_audit_events: int = 512, epoch: int = 0):
        if not _is_int(epoch) or epoch < 0:
            raise ValueError("invalid_coordinator_epoch")
        self._lock = threading.Lock()
        self._max_traces = max(1, int(max_traces))
        self._max_retained = max(1, int(max_retained_cycles))
        self._max_audit = max(1, int(max_audit_events))
        self.epoch = epoch
        # Global (not per-trace) sequence so an evicted cycle ID is never reused.
        self._next_cycle = 1
        self._cycles: "OrderedDict[str, _Cycle]" = OrderedDict()  # cycle_id -> cycle, oldest first
        self._latest: dict[str, str] = {}  # trace_id -> newest retained cycle_id
        self._current: dict[str, Any] = {}  # trace_id -> accepted outcome (in memory only)
        self._audit: list[dict[str, Any]] = []
        self._audit_seq = 0
        self._audit_dropped = 0

    # -- audit ------------------------------------------------------------
    def _log(self, event: str, cycle: _Cycle | None = None, **fields: Any) -> None:
        self._audit_seq += 1
        row: dict[str, Any] = {"seq": self._audit_seq, "epoch": self.epoch, "event": event}
        if cycle is not None:
            row.update(trace_id=cycle.ticket.trace_id, cycle_id=cycle.ticket.cycle_id, frame_id=cycle.ticket.frame_id, cycle_status=cycle.status.value)
        row.update(fields)
        self._audit.append(_bound(row))
        if len(self._audit) > self._max_audit:
            del self._audit[0]
            self._audit_dropped += 1

    def audit(self, trace_id: str | None = None) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = [json.loads(json.dumps(r)) for r in self._audit if trace_id is None or r.get("trace_id") == trace_id]
        return tuple(rows)

    @property
    def audit_dropped(self) -> int:
        return self._audit_dropped

    def _prune(self) -> None:
        finished = [cid for cid, c in self._cycles.items() if c.status is not CycleStatus.IN_FLIGHT]
        for cid in finished[: max(0, len(finished) - self._max_retained)]:
            cycle = self._cycles.pop(cid)
            trace_id = cycle.ticket.trace_id
            if self._latest.get(trace_id) == cid:
                self._latest.pop(trace_id, None)
                if self._current.pop(trace_id, None) is not None:
                    self._log("current_advisory_evicted", cycle)
            self._log("cycle_evicted", cycle)

    # -- lifecycle --------------------------------------------------------
    def begin(self, frame: MioSituationFrame) -> CycleTicket:
        """Open a cycle for ``frame``. A materially different newer frame for
        the same trace supersedes the in-flight cycle; an immaterial one reuses it."""
        digest = material_frame_digest(frame)
        trace_id = frame.trace_id
        with self._lock:
            latest_id = self._latest.get(trace_id)
            latest = self._cycles.get(latest_id) if latest_id else None
            if latest is not None and latest.status is CycleStatus.IN_FLIGHT and latest.ticket.material_digest == digest:
                self._log("frame_not_material", latest, new_frame_id=frame.frame_id)
                t = latest.ticket
                return CycleTicket(t.trace_id, t.cycle_id, t.epoch, t.frame_id, t.material_digest, deduplicated=True)
            in_flight = sum(1 for c in self._cycles.values() if c.status is CycleStatus.IN_FLIGHT)
            if not (latest is not None and latest.status is CycleStatus.IN_FLIGHT) and in_flight >= self._max_traces:
                self._log("begin_rejected_backpressure", None, trace_id=trace_id, frame_id=frame.frame_id)
                raise RuntimeError("reasoning_coordinator_backpressure")
            n = self._next_cycle
            self._next_cycle += 1
            ticket = CycleTicket(trace_id, f"{trace_id}:e{self.epoch}:c{n}", self.epoch, frame.frame_id, digest)
            cycle = _Cycle(ticket, CycleStatus.IN_FLIGHT)
            if latest is not None and latest.status is CycleStatus.IN_FLIGHT:
                latest.status = CycleStatus.SUPERSEDED
                self._log("cycle_superseded", latest, superseded_by=ticket.cycle_id)
            if latest is not None and trace_id in self._current and latest.ticket.material_digest != digest:
                # The accepted advisory described an older material situation.
                self._current.pop(trace_id, None)
                self._log("current_advisory_retired", latest, superseded_by=ticket.cycle_id)
            self._cycles[ticket.cycle_id] = cycle
            self._latest[trace_id] = ticket.cycle_id
            self._log("cycle_started", cycle, material_digest=digest)
            self._prune()
            return ticket

    def _status(self, ticket: CycleTicket) -> CycleStatus | None:
        with self._lock:
            cycle = self._cycles.get(ticket.cycle_id)
            if cycle is None or ticket.epoch != self.epoch or not _same_cycle(ticket, cycle.ticket):
                return None
            return cycle.status

    def is_current(self, ticket: CycleTicket) -> bool:
        return self._status(ticket) is CycleStatus.IN_FLIGHT

    def cancel_check(self, ticket: CycleTicket):
        """For BoundedReasoningLoop.run(cancel_check=...): true once the operator cancelled the cycle."""
        return lambda: self._status(ticket) is CycleStatus.CANCELLED

    def stale_check(self, ticket: CycleTicket):
        """For BoundedReasoningLoop.run(stale_check=...): true once a newer material
        frame superseded the cycle, it was evicted, or it predates a restart."""
        return lambda: self._status(ticket) not in (CycleStatus.IN_FLIGHT, CycleStatus.CANCELLED)

    def cancel(self, trace_id: str, *, reason: str = "operator_cancelled") -> bool:
        with self._lock:
            cycle = self._cycles.get(self._latest.get(trace_id, ""))
            if cycle is None or cycle.status is not CycleStatus.IN_FLIGHT:
                return False
            cycle.status = CycleStatus.CANCELLED
            self._log("cycle_cancelled", cycle, reason=str(reason)[:64])
            self._prune()
            return True

    def complete(self, ticket: CycleTicket, outcome: Any) -> CompletionResult:
        """Offer a finished outcome. Only the current in-flight cycle of the
        current epoch is accepted; anything else is discarded and audited."""
        state = getattr(getattr(outcome, "state", None), "value", str(getattr(outcome, "state", "")))
        hypotheses = tuple(getattr(outcome, "hypotheses", ()) or ())[:_AUDIT_HYPOTHESES_LIMIT]
        rec = getattr(outcome, "recommendation", None)
        advisory_id = getattr(rec, "advisory_id", "") if rec is not None else ""
        with self._lock:
            cycle = self._cycles.get(ticket.cycle_id)
            reason, status = self._stale_reason(ticket, cycle)
            if reason:
                # Audit under the recorded cycle's trace when the ticket matches it;
                # a mismatched or unknown ticket is logged without touching any cycle.
                own = cycle if reason in (STALE_SUPERSEDED, STALE_CANCELLED, STALE_ALREADY_COMPLETED) else None
                h_reason = REASON_CYCLE_CANCELLED if reason == STALE_CANCELLED else REASON_CYCLE_SUPERSEDED
                ids = {} if own is not None else {"trace_id": ticket.trace_id, "cycle_id": ticket.cycle_id, "frame_id": ticket.frame_id, "ticket_epoch": ticket.epoch}
                self._log("stale_result_discarded", own, **ids, reason=reason, outcome_state=state, advisory_id=advisory_id, hypotheses=[e.to_dict() for e in supersede_all(hypotheses, h_reason)])
                return CompletionResult(False, status, reason)
            cycle.status = CycleStatus.ACCEPTED
            cycle.outcome_state = state[:64]
            cycle.advisory_id = str(advisory_id)[:_ID_LIMIT]
            self._current[cycle.ticket.trace_id] = outcome
            self._log("result_accepted", cycle, outcome_state=state, advisory_id=advisory_id)
            self._prune()
            return CompletionResult(True, CycleStatus.ACCEPTED.value, "current", outcome)

    def _stale_reason(self, ticket: CycleTicket, cycle: _Cycle | None) -> tuple[str, str]:
        """('', '') when ``ticket`` is the current in-flight cycle, else a fixed
        reason code from STALE_RESULT_REASONS and the cycle status to report."""
        if not _is_int(ticket.epoch) or ticket.epoch < self.epoch:
            return STALE_PRE_RESTART, CycleStatus.ABANDONED_ON_RESTART.value
        if cycle is None or ticket.epoch != self.epoch:
            return STALE_UNKNOWN_OR_EVICTED, "unknown"
        if not _same_cycle(ticket, cycle.ticket):
            # A ticket naming another trace's cycle must not land in that trace.
            return STALE_TICKET_MISMATCH, "unknown"
        if cycle.status is CycleStatus.IN_FLIGHT:
            return "", ""
        if cycle.status is CycleStatus.CANCELLED:
            return STALE_CANCELLED, cycle.status.value
        if cycle.status is CycleStatus.ACCEPTED:
            return STALE_ALREADY_COMPLETED, cycle.status.value
        if cycle.status in (CycleStatus.ABANDONED_ON_RESTART, CycleStatus.RESTORED_STALE):
            return STALE_PRE_RESTART, cycle.status.value
        return STALE_SUPERSEDED, cycle.status.value

    def run_cycle(self, loop: Any, frame: MioSituationFrame, playbook: Any) -> CompletionResult:
        """begin -> loop.run(cancel_check, stale_check) -> complete, for one frame."""
        ticket = self.begin(frame)
        if ticket.deduplicated:
            return CompletionResult(False, CycleStatus.IN_FLIGHT.value, "frame_not_material")
        outcome = loop.run(frame=frame, playbook=playbook, cycle_id=ticket.cycle_id, cancel_check=self.cancel_check(ticket), stale_check=self.stale_check(ticket))
        return self.complete(ticket, outcome)

    def current(self, trace_id: str) -> Any:
        """The accepted advisory outcome for ``trace_id`` or None. Never stale."""
        with self._lock:
            return self._current.get(trace_id)

    # -- restart ----------------------------------------------------------
    def snapshot(self) -> bytes:
        """Canonical, byte-stable persistence image. It holds cycle metadata and
        the size-bounded audit rows only: no outcome objects, prompts or raw logs."""
        with self._lock:
            payload = {
                "schema": COORDINATOR_SNAPSHOT_SCHEMA,
                "epoch": self.epoch,
                "next_cycle": self._next_cycle,
                "latest": dict(sorted(self._latest.items())),
                "cycles": [
                    {
                        "cycle_id": c.ticket.cycle_id, "trace_id": c.ticket.trace_id, "epoch": c.ticket.epoch,
                        "frame_id": c.ticket.frame_id, "material_digest": c.ticket.material_digest,
                        "status": c.status.value, "outcome_state": c.outcome_state, "advisory_id": c.advisory_id,
                    }
                    for c in self._cycles.values()
                ],
                "audit": list(self._audit),
                "audit_dropped": self._audit_dropped,
            }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @staticmethod
    def _validate_snapshot(snapshot: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(bytes(snapshot).decode("ascii"))
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError("malformed_coordinator_snapshot") from exc
        if not isinstance(payload, dict) or payload.get("schema") != COORDINATOR_SNAPSHOT_SCHEMA:
            raise ValueError("unsupported_coordinator_snapshot")
        if set(payload) != _SNAPSHOT_KEYS:
            raise ValueError("malformed_coordinator_snapshot")
        epoch, next_cycle = payload["epoch"], payload["next_cycle"]
        if not _is_int(epoch) or epoch < 0 or not _is_int(next_cycle) or next_cycle < 1:
            raise ValueError("malformed_coordinator_snapshot")
        if not _is_int(payload["audit_dropped"]) or payload["audit_dropped"] < 0:
            raise ValueError("malformed_coordinator_snapshot")
        cycles, latest, audit = payload["cycles"], payload["latest"], payload["audit"]
        if not isinstance(cycles, list) or not isinstance(latest, dict) or not isinstance(audit, list):
            raise ValueError("malformed_coordinator_snapshot")
        seen: dict[str, str] = {}
        for row in cycles:
            if not isinstance(row, dict) or set(row) != _CYCLE_KEYS:
                raise ValueError("malformed_coordinator_snapshot")
            if any(not isinstance(row[k], str) or len(row[k]) > _ID_LIMIT for k in _CYCLE_KEYS - {"epoch"}):
                raise ValueError("malformed_coordinator_snapshot")
            if not _is_int(row["epoch"]) or not 0 <= row["epoch"] <= epoch:
                raise ValueError("invalid_cycle_epoch_in_snapshot")
            if row["status"] not in {s.value for s in CycleStatus}:
                raise ValueError("malformed_coordinator_snapshot")
            if row["cycle_id"] in seen:
                raise ValueError("duplicate_cycle_in_snapshot")
            seen[row["cycle_id"]] = row["trace_id"]
        for trace_id, cycle_id in latest.items():
            if not isinstance(cycle_id, str) or seen.get(cycle_id) != trace_id:
                raise ValueError("inconsistent_latest_in_snapshot")
        for row in audit:
            if not isinstance(row, dict) or not _is_int(row.get("seq")) or not isinstance(row.get("event"), str):
                raise ValueError("malformed_coordinator_snapshot")
        return payload

    @classmethod
    def restore(cls, snapshot: bytes, **kwargs: Any) -> "ReasoningCoordinator":
        """Rebuild after a restart with ``epoch + 1``. In-flight cycles become
        ``abandoned_on_restart``; previously accepted advisories become
        ``restored_stale`` and are not served by current(). Audit is kept.
        A malformed or tampered snapshot raises ValueError."""
        payload = cls._validate_snapshot(snapshot)
        coord = cls(epoch=payload["epoch"] + 1, **kwargs)
        coord._next_cycle = payload["next_cycle"]
        coord._latest = dict(payload["latest"])
        coord._audit = [_bound(r) for r in payload["audit"]][-coord._max_audit:]
        coord._audit_seq = max((r["seq"] for r in coord._audit), default=0)
        coord._audit_dropped = payload["audit_dropped"]
        for row in payload["cycles"]:
            ticket = CycleTicket(row["trace_id"], row["cycle_id"], row["epoch"], row["frame_id"], row["material_digest"])
            status = CycleStatus(row["status"])
            cycle = _Cycle(ticket, status, row["outcome_state"], row["advisory_id"])
            coord._cycles[ticket.cycle_id] = cycle
            if status is CycleStatus.IN_FLIGHT:
                cycle.status = CycleStatus.ABANDONED_ON_RESTART
                coord._log("cycle_abandoned_on_restart", cycle)
            elif status is CycleStatus.ACCEPTED:
                cycle.status = CycleStatus.RESTORED_STALE
                coord._log("advisory_restored_as_stale", cycle, advisory_id=cycle.advisory_id)
        with coord._lock:
            coord._prune()
        return coord
