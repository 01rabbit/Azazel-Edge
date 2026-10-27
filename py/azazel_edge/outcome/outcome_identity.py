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

LEDGER_SCHEMA_VERSION = "outcome-identity-ledger/v1"
DEFAULT_MAX_IDENTITIES = 4096


def outcome_identity_key(*, execution_id: str, objective_id: str) -> str:
    """Restart-independent identity of "the Outcome of this execution for this objective"."""

    execution = str(execution_id or "").strip()
    objective = str(objective_id or "").strip()
    if not execution or not objective:
        raise ValueError("outcome identity requires execution_id and objective_id")
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

    def __len__(self) -> int:
        return len(self._entries)

    def admit(self, outcome: OutcomeRecord) -> Admission:
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
        if len(self._entries) >= self.max_identities:
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
        _positive_int(payload.get("max_identities"))
        ledger = cls(max_identities=max_identities)
        identities = payload.get("identities")
        if not isinstance(identities, list):
            raise ValueError("outcome identity ledger requires identities list")
        if len(identities) > ledger.max_identities:
            raise ValueError("outcome identity ledger exceeds its bound")
        fields = ("decision_id", "execution_id", "objective_id", "outcome_id", "content_digest")
        for raw in identities:
            if not isinstance(raw, Mapping):
                raise ValueError("malformed outcome identity entry")
            entry = {name: str(raw.get(name) or "") for name in fields}
            if not all(entry.values()):
                raise ValueError("incomplete outcome identity entry")
            key = str(raw.get("identity_key") or "")
            expected = outcome_identity_key(execution_id=entry["execution_id"], objective_id=entry["objective_id"])
            if key != expected:
                raise ValueError("outcome identity key does not match its execution/objective")
            if key in ledger._entries:
                raise ValueError("duplicate outcome identity entry")
            ledger._entries[key] = entry
        return ledger


def _positive_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("max_identities must be a positive integer")
    return value
