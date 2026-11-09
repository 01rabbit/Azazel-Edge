"""Cross-restart Outcome identity and deduplication (Outcome-as-Evidence G5).

The G3 collector derives ``OutcomeRecord.outcome_id`` from the collector receipt
time of the triggering record, so the same execution re-delivered to a fresh
collector after a restart produces a *different* ``outcome_id``. Counting both
would double-count one execution's Outcome and would also pair an old action
with telemetry sampled after the restart.

This module gives every Outcome a restart-independent identity key derived only
from durable provider-grounded identifiers (``execution_id`` from the Rust trace
and the policy-instantiated ``objective_id``) and a bounded ledger that admits
the first Outcome per identity and suppresses later ones.

It is evidence bookkeeping only: it never executes, retries, releases or
authorizes anything, and it never changes an Outcome's assessment.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .contracts import OutcomeRecord

LEDGER_SCHEMA_VERSION = "outcome-identity-ledger/v2"
DEFAULT_MAX_IDENTITIES = 4096


def outcome_identity_key(*, execution_id: str, objective_id: str) -> str:
    """Restart-independent identity of "the Outcome of this execution for this objective"."""

    if any(type(value) is not str or not value.strip() or len(value) > 2048 for value in (execution_id, objective_id)):
        raise ValueError("outcome identity requires execution_id and objective_id")
    execution = execution_id.strip()
    objective = objective_id.strip()
    payload = f"{execution}\x1f{objective}".encode("utf-8")
    return f"outcome-identity-{hashlib.sha256(payload).hexdigest()[:24]}"


def outcome_content_digest(outcome: OutcomeRecord) -> str:
    payload = json.dumps(outcome.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


class AdmissionStatus(str, Enum):
    ADMITTED = "admitted"
    # Byte-identical re-delivery of an Outcome already admitted (e.g. the same
    # JSONL line read again from a rotated file).
    DUPLICATE_IDENTICAL = "duplicate_identical"
    # Same execution/objective identity, different record: typically the same
    # Rust record re-observed by a fresh collector after a restart. The first
    # admitted record is retained; the later one is never counted.
    DUPLICATE_SUPPRESSED = "duplicate_suppressed"
    # Bounded ledger is full: the new identity is not admitted (fail closed)
    # rather than forgetting an older identity and re-opening double counting.
    CAPACITY_EXHAUSTED = "capacity_exhausted"
    WINDOW_LOST = "window_lost"


@dataclass(frozen=True)
class Admission:
    status: AdmissionStatus
    identity_key: str
    outcome_id: str
    retained_outcome_id: str

    @property
    def counted(self) -> bool:
        return self.status is AdmissionStatus.ADMITTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "identity_key": self.identity_key,
            "outcome_id": self.outcome_id,
            "retained_outcome_id": self.retained_outcome_id,
        }


class OutcomeIdentityLedger:
    """Bounded first-wins ledger of admitted Outcome identities.

    The ledger state is a plain mapping (``to_dict``/``from_mapping``) so it can
    be carried across a process restart. It is not wired into the live G3 CLI:
    persisting it on the Pi is a G6 (disk growth/wear) decision.
    """

    def __init__(self, *, max_identities: int = DEFAULT_MAX_IDENTITIES) -> None:
        self.max_identities = _positive_int(max_identities)
        self._entries: dict[str, dict[str, str]] = {}
        self._lost_windows: dict[str, dict[str, str]] = {}
        self._counters = {status.value: 0 for status in AdmissionStatus}
        self._sealed = False

    def __len__(self) -> int:
        return len(self._entries)

    def mark_window_lost(self, *, execution_id: str, objective_id: str, decision_id: str) -> None:
        """Retain a tombstone, never let later telemetry replace a lost window.

        On saturation, seal admission of all new identities rather than evicting
        an identity or losing a tombstone. Already retained duplicates still work.
        """
        key = outcome_identity_key(execution_id=execution_id, objective_id=objective_id)
        if type(decision_id) is not str or not decision_id or len(decision_id) > 2048:
            raise ValueError("lost window requires decision_id")
        existing = self._entries.get(key) or self._lost_windows.get(key)
        if existing is not None:
            if existing["decision_id"] != decision_id:
                raise ValueError("outcome identity collision across decisions")
            return
        if self._sealed or len(self._entries) + len(self._lost_windows) >= self.max_identities:
            self._sealed = True
            return
        self._lost_windows[key] = {
            "decision_id": decision_id, "execution_id": execution_id, "objective_id": objective_id,
        }

    def status(self) -> dict[str, Any]:
        used = len(self._entries) + len(self._lost_windows)
        return {
            "capacity": self.max_identities, "used": used,
            "remaining": self.max_identities - used,
            "admitted_identities": len(self._entries),
            "lost_window_identities": len(self._lost_windows),
            "new_admission_closed": self._sealed or used >= self.max_identities,
            "counters": dict(self._counters),
        }

    def window_lost(self, *, execution_id: str, objective_id: str) -> bool:
        key = outcome_identity_key(execution_id=execution_id, objective_id=objective_id)
        return key in self._lost_windows or (self._sealed and key not in self._entries)

    def checkpoint(self) -> dict[str, Any]:
        state = self.to_dict()
        digest = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {"state": state, "sha256": digest}

    @classmethod
    def from_checkpoint(cls, payload: Mapping[str, Any], *, max_identities: int = DEFAULT_MAX_IDENTITIES) -> "OutcomeIdentityLedger":
        if not isinstance(payload, Mapping) or set(payload) != {"state", "sha256"}:
            raise ValueError("invalid ledger checkpoint")
        state = payload["state"]
        ledger = cls.from_mapping(state, max_identities=max_identities)
        digest = hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if payload["sha256"] != digest:
            raise ValueError("ledger checkpoint digest mismatch")
        return ledger

    def admit(self, outcome: OutcomeRecord) -> Admission:
        admission = self._admit(outcome)
        self._counters[admission.status.value] += 1
        return admission

    def _admit(self, outcome: OutcomeRecord) -> Admission:
        key = outcome_identity_key(execution_id=outcome.execution_id, objective_id=outcome.objective_id)
        digest = outcome_content_digest(outcome)
        existing = self._entries.get(key)
        if existing is not None:
            if existing["decision_id"] != outcome.decision_id:
                raise ValueError("outcome identity collision across decisions")
            identical = existing["outcome_id"] == outcome.outcome_id and existing["content_digest"] == digest
            return Admission(
                status=AdmissionStatus.DUPLICATE_IDENTICAL if identical else AdmissionStatus.DUPLICATE_SUPPRESSED,
                identity_key=key,
                outcome_id=outcome.outcome_id,
                retained_outcome_id=existing["outcome_id"],
            )
        lost = self._lost_windows.get(key)
        if lost is not None:
            if lost["decision_id"] != outcome.decision_id:
                raise ValueError("outcome identity collision across decisions")
            return Admission(AdmissionStatus.WINDOW_LOST, key, outcome.outcome_id, "")
        if self._sealed or len(self._entries) + len(self._lost_windows) >= self.max_identities:
            return Admission(
                status=AdmissionStatus.CAPACITY_EXHAUSTED,
                identity_key=key,
                outcome_id=outcome.outcome_id,
                retained_outcome_id="",
            )
        self._entries[key] = {
            "decision_id": outcome.decision_id,
            "execution_id": outcome.execution_id,
            "objective_id": outcome.objective_id,
            "outcome_id": outcome.outcome_id,
            "content_digest": digest,
        }
        return Admission(
            status=AdmissionStatus.ADMITTED,
            identity_key=key,
            outcome_id=outcome.outcome_id,
            retained_outcome_id=outcome.outcome_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "max_identities": self.max_identities,
            "sealed": self._sealed,
            "counters": dict(self._counters),
            "lost_windows": [
                {"identity_key": key, **self._lost_windows[key]} for key in sorted(self._lost_windows)
            ],
            "identities": [
                {"identity_key": key, **self._entries[key]} for key in sorted(self._entries)
            ],
        }

    @classmethod
    def from_mapping(
        cls,
        payload: Mapping[str, Any],
        *,
        max_identities: int = DEFAULT_MAX_IDENTITIES,
    ) -> "OutcomeIdentityLedger":
        """Restore ledger state under the caller's configured bound.

        The bound recorded in the state is validated but never replaces the
        configured one, so stored state cannot raise its own limit.
        """

        if not isinstance(payload, Mapping) or payload.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise ValueError("unsupported outcome identity ledger schema")
        recorded_bound = _positive_int(payload.get("max_identities"))
        ledger = cls(max_identities=max_identities)
        if type(payload.get("sealed")) is not bool:
            raise ValueError("ledger requires sealed state")
        ledger._sealed = payload["sealed"]
        counters = payload.get("counters")
        if not isinstance(counters, Mapping) or set(counters) != set(ledger._counters):
            raise ValueError("ledger requires admission counters")
        for name, value in counters.items():
            if type(value) is not int or value < 0:
                raise ValueError("invalid admission counter")
            ledger._counters[name] = value
        identities = payload.get("identities")
        if not isinstance(identities, list):
            raise ValueError("outcome identity ledger requires identities list")
        lost_windows = payload.get("lost_windows")
        if not isinstance(lost_windows, list):
            raise ValueError("ledger requires lost windows")
        if len(identities) + len(lost_windows) > min(recorded_bound, ledger.max_identities):
            raise ValueError("outcome identity ledger exceeds its bound")
        fields = ("decision_id", "execution_id", "objective_id", "outcome_id", "content_digest")
        for raw in identities:
            if not isinstance(raw, Mapping):
                raise ValueError("malformed outcome identity entry")
            entry = {name: raw.get(name) for name in fields}
            if any(not isinstance(value, str) or not value or len(value) > 2048 for value in entry.values()):
                raise ValueError("incomplete outcome identity entry")
            key = str(raw.get("identity_key") or "")
            expected = outcome_identity_key(execution_id=entry["execution_id"], objective_id=entry["objective_id"])
            if key != expected:
                raise ValueError("outcome identity key does not match its execution/objective")
            if key in ledger._entries:
                raise ValueError("duplicate outcome identity entry")
            ledger._entries[key] = entry
        for raw in lost_windows:
            if not isinstance(raw, Mapping):
                raise ValueError("malformed lost window")
            entry = {name: raw.get(name) for name in ("decision_id", "execution_id", "objective_id")}
            if any(type(value) is not str or not value or len(value) > 2048 for value in entry.values()):
                raise ValueError("invalid lost window identity")
            key = outcome_identity_key(execution_id=entry["execution_id"], objective_id=entry["objective_id"])
            if raw.get("identity_key") != key or key in ledger._entries or key in ledger._lost_windows:
                raise ValueError("conflicting lost window identity")
            ledger._lost_windows[key] = entry
        return ledger


def _positive_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("max_identities must be a positive integer")
    return value
