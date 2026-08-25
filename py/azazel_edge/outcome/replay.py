from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import ActionExecutionReceipt


class ReplayExecutionForbidden(RuntimeError):
    pass


class LiveExecutionProvider:
    """Marker interface for the live execution boundary.

    Outcome-as-Evidence v1 deliberately does not implement this interface. Live
    authority remains in the existing Rust enforcement path.
    """

    def execute(self, *_args: object, **_kwargs: object) -> ActionExecutionReceipt:
        raise NotImplementedError


@dataclass(frozen=True)
class ReplayExecutionProvider:
    """Read-only provider for recorded execution receipts."""

    records: tuple[ActionExecutionReceipt, ...]

    @classmethod
    def from_records(cls, records: Iterable[ActionExecutionReceipt]) -> "ReplayExecutionProvider":
        return cls(tuple(records))

    def records_for_decision(self, decision_id: str) -> tuple[ActionExecutionReceipt, ...]:
        return tuple(record for record in self.records if record.decision_id == decision_id)

    def execute(self, *_args: object, **_kwargs: object) -> ActionExecutionReceipt:
        raise ReplayExecutionForbidden("replay provider cannot execute live actions")
