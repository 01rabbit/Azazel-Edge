"""Hypothesis lifecycle policy and per-trace reasoning-cycle coordination (#385).

Everything here is advisory-only bookkeeping for the M.I.O. shadow loop. No
function in this module calls the arbiter, the enforcement path, or AZ-06, and
no state here grants or implies an Edge action. The coordinator decides only
which advisory result is *current* for a trace; stale/superseded/cancelled
results are discarded from the current view but retained in the audit log.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import threading
from enum import Enum
from typing import Any, Mapping, Sequence

from .contracts import HypothesisStatus, MioHypothesis, MioSituationFrame


# --- Hypothesis lifecycle --------------------------------------------------

_H = HypothesisStatus
# Terminal statuses: a falsified or superseded hypothesis cannot be revived.
TERMINAL_HYPOTHESIS_STATUSES = frozenset({_H.FALSIFIED, _H.SUPERSEDED})
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


def record_initial(hypotheses: Sequence[MioHypothesis]) -> tuple[HypothesisAuditEntry, ...]:
    return tuple(_entry(h, "", "proposed_by_model") for h in hypotheses)


def apply_hypothesis_update(previous: Sequence[MioHypothesis], proposed: Sequence[MioHypothesis]) -> LifecycleResult:
    """Validate a model-proposed revision against the deterministic policy.

    * every transition must be in ALLOWED_HYPOTHESIS_TRANSITIONS;
    * ``falsified`` needs contradicting evidence and a falsification condition
      (absence of evidence alone never falsifies);
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
            if h.status not in (_H.PROPOSED, _H.ACTIVE):
                errors.append(f"new_hypothesis_must_start_proposed:{h.hypothesis_id}:{h.status.value}")
            audit.append(_entry(h, "", "proposed_in_update"))
            out.append(h)
            continue
        if h.status not in ALLOWED_HYPOTHESIS_TRANSITIONS[before.status]:
            errors.append(f"invalid_hypothesis_transition:{h.hypothesis_id}:{before.status.value}->{h.status.value}")
            continue
        if h.status is _H.FALSIFIED and before.status is not _H.FALSIFIED:
            if not h.contradicting_evidence_refs:
                errors.append(f"falsified_without_contradicting_evidence:{h.hypothesis_id}")
            if not (h.falsification_conditions or before.falsification_conditions):
                errors.append(f"falsified_without_falsification_condition:{h.hypothesis_id}")
        if h.status is not before.status:
            audit.append(_entry(h, before.status.value, "revised_by_evidence"))
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

# Fields that do not change the situation itself: identity, clock, and
# derived bookkeeping. Everything else in the v1 frame is material.
NON_MATERIAL_FRAME_FIELDS = frozenset({"frame_id", "created_at", "freshness_seconds", "truncated", "provenance"})


def material_frame_digest(frame: MioSituationFrame) -> str:
    payload = {k: v for k, v in frame.to_dict().items() if k not in NON_MATERIAL_FRAME_FIELDS}
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


class ReasoningCoordinator:
    """Owns cycle identity per trace. Thread-safe; working state never crosses traces.

    The coordinator is a pure bookkeeper: it hands out cycle tickets, decides
    whether a finished cycle may become the current advisory for its trace,
    and appends every decision to a bounded audit log. It has no clock: all
    ordering is by begin/complete call order, so replays are deterministic.
    """

    def __init__(self, *, max_traces: int = 64, max_audit_events: int = 512, epoch: int = 0):
        self._lock = threading.Lock()
        self._max_traces = max(1, int(max_traces))
        self._max_audit = max(1, int(max_audit_events))
        self.epoch = int(epoch)
        self._counters: dict[str, int] = {}
        self._cycles: dict[str, _Cycle] = {}  # cycle_id -> cycle
        self._latest: dict[str, str] = {}  # trace_id -> newest cycle_id
        self._current: dict[str, Any] = {}  # trace_id -> accepted outcome
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
        self._audit.append(row)
        if len(self._audit) > self._max_audit:
            del self._audit[0]
            self._audit_dropped += 1

    def audit(self, trace_id: str | None = None) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = [dict(r) for r in self._audit if trace_id is None or r.get("trace_id") == trace_id]
        return tuple(rows)

    @property
    def audit_dropped(self) -> int:
        return self._audit_dropped

    # -- lifecycle --------------------------------------------------------
    def begin(self, frame: MioSituationFrame) -> CycleTicket:
        """Open a cycle for ``frame``. A materially different newer frame for
        the same trace supersedes the in-flight cycle; an immaterial one reuses it."""
        digest = material_frame_digest(frame)
        trace_id = frame.trace_id
        with self._lock:
            latest_id = self._latest.get(trace_id)
            latest = self._cycles.get(latest_id) if latest_id else None
            if latest is not None and latest.status is CycleStatus.IN_FLIGHT:
                if latest.ticket.material_digest == digest:
                    self._log("frame_not_material", latest, new_frame_id=frame.frame_id)
                    t = latest.ticket
                    return CycleTicket(t.trace_id, t.cycle_id, t.epoch, t.frame_id, t.material_digest, deduplicated=True)
            active_traces = {c.ticket.trace_id for c in self._cycles.values() if c.status is CycleStatus.IN_FLIGHT}
            if trace_id not in active_traces and len(active_traces) >= self._max_traces:
                self._log("begin_rejected_backpressure", None, trace_id=trace_id, frame_id=frame.frame_id)
                raise RuntimeError("reasoning_coordinator_backpressure")
            n = self._counters.get(trace_id, 0) + 1
            self._counters[trace_id] = n
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
            return ticket

    def is_current(self, ticket: CycleTicket) -> bool:
        with self._lock:
            cycle = self._cycles.get(ticket.cycle_id)
            return bool(cycle and ticket.epoch == self.epoch and cycle.status is CycleStatus.IN_FLIGHT and self._latest.get(ticket.trace_id) == ticket.cycle_id)

    def _status(self, ticket: CycleTicket) -> CycleStatus | None:
        with self._lock:
            cycle = self._cycles.get(ticket.cycle_id)
            if cycle is None or ticket.epoch != self.epoch:
                return None
            return cycle.status

    def cancel_check(self, ticket: CycleTicket):
        """For BoundedReasoningLoop.run(cancel_check=...): true once the operator cancelled the cycle."""
        return lambda: self._status(ticket) is CycleStatus.CANCELLED

    def stale_check(self, ticket: CycleTicket):
        """For BoundedReasoningLoop.run(stale_check=...): true once a newer material
        frame superseded the cycle or the cycle predates a restart."""
        return lambda: self._status(ticket) not in (CycleStatus.IN_FLIGHT, CycleStatus.CANCELLED)

    def cancel(self, trace_id: str, *, reason: str = "operator_cancelled") -> bool:
        with self._lock:
            cycle = self._cycles.get(self._latest.get(trace_id, ""))
            if cycle is None or cycle.status is not CycleStatus.IN_FLIGHT:
                return False
            cycle.status = CycleStatus.CANCELLED
            self._log("cycle_cancelled", cycle, reason=str(reason)[:64])
            return True

    def complete(self, ticket: CycleTicket, outcome: Any) -> CompletionResult:
        """Offer a finished outcome. Only the current in-flight cycle of the
        current epoch is accepted; anything else is discarded and audited."""
        state = getattr(getattr(outcome, "state", None), "value", str(getattr(outcome, "state", "")))
        hypotheses = tuple(getattr(outcome, "hypotheses", ()) or ())
        rec = getattr(outcome, "recommendation", None)
        advisory_id = getattr(rec, "advisory_id", "") if rec is not None else ""
        with self._lock:
            cycle = self._cycles.get(ticket.cycle_id)
            if cycle is None or ticket.epoch != self.epoch:
                reason = "unknown_or_pre_restart_cycle"
                self._log("stale_result_discarded", None, trace_id=ticket.trace_id, cycle_id=ticket.cycle_id, frame_id=ticket.frame_id, ticket_epoch=ticket.epoch, reason=reason, outcome_state=state, advisory_id=advisory_id, hypotheses=[e.to_dict() for e in supersede_all(hypotheses, reason)])
                return CompletionResult(False, CycleStatus.ABANDONED_ON_RESTART.value, reason)
            if cycle.status is not CycleStatus.IN_FLIGHT:
                reason = f"cycle_{cycle.status.value}"
                self._log("stale_result_discarded", cycle, reason=reason, outcome_state=state, advisory_id=advisory_id, hypotheses=[e.to_dict() for e in supersede_all(hypotheses, reason)])
                return CompletionResult(False, cycle.status.value, reason)
            cycle.status = CycleStatus.ACCEPTED
            cycle.outcome_state = state
            cycle.advisory_id = advisory_id
            self._current[ticket.trace_id] = outcome
            self._log("result_accepted", cycle, outcome_state=state, advisory_id=advisory_id)
            return CompletionResult(True, CycleStatus.ACCEPTED.value, "current", outcome)

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
        """Canonical, byte-stable persistence image (no outcomes, no prompts)."""
        with self._lock:
            payload = {
                "schema": COORDINATOR_SNAPSHOT_SCHEMA,
                "epoch": self.epoch,
                "counters": dict(sorted(self._counters.items())),
                "latest": dict(sorted(self._latest.items())),
                "cycles": [
                    {
                        "cycle_id": c.ticket.cycle_id, "trace_id": c.ticket.trace_id, "epoch": c.ticket.epoch,
                        "frame_id": c.ticket.frame_id, "material_digest": c.ticket.material_digest,
                        "status": c.status.value, "outcome_state": c.outcome_state, "advisory_id": c.advisory_id,
                    }
                    for c in sorted(self._cycles.values(), key=lambda c: c.ticket.cycle_id)
                ],
                "audit": list(self._audit),
                "audit_dropped": self._audit_dropped,
            }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @classmethod
    def restore(cls, snapshot: bytes, **kwargs: Any) -> "ReasoningCoordinator":
        """Rebuild after a restart with ``epoch + 1``. In-flight cycles become
        ``abandoned_on_restart``; previously accepted advisories become
        ``restored_stale`` and are not served by current(). Audit is kept."""
        payload = json.loads(snapshot.decode("ascii"))
        if not isinstance(payload, Mapping) or payload.get("schema") != COORDINATOR_SNAPSHOT_SCHEMA:
            raise ValueError("unsupported_coordinator_snapshot")
        coord = cls(epoch=int(payload["epoch"]) + 1, **kwargs)
        coord._counters = {str(k): int(v) for k, v in payload["counters"].items()}
        coord._latest = {str(k): str(v) for k, v in payload["latest"].items()}
        coord._audit = [dict(r) for r in payload["audit"]][-coord._max_audit:]
        coord._audit_seq = max((int(r.get("seq", 0)) for r in coord._audit), default=0)
        coord._audit_dropped = int(payload.get("audit_dropped", 0))
        for row in payload["cycles"]:
            ticket = CycleTicket(row["trace_id"], row["cycle_id"], int(row["epoch"]), row["frame_id"], row["material_digest"])
            status = CycleStatus(row["status"])
            cycle = _Cycle(ticket, status, row.get("outcome_state", ""), row.get("advisory_id", ""))
            coord._cycles[ticket.cycle_id] = cycle
            if status is CycleStatus.IN_FLIGHT:
                cycle.status = CycleStatus.ABANDONED_ON_RESTART
                coord._log("cycle_abandoned_on_restart", cycle)
            elif status is CycleStatus.ACCEPTED:
                cycle.status = CycleStatus.RESTORED_STALE
                coord._log("advisory_restored_as_stale", cycle, advisory_id=cycle.advisory_id)
        return coord
