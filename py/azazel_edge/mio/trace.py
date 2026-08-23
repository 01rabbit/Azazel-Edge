from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class ReasoningTraceEvent:
    seq: int
    trace_id: str
    cycle_id: str
    state: str
    kind: str
    payload: Mapping[str, Any]


class ReasoningTrace:
    """Minimized replay trace. Raw prompts and raw logs are intentionally excluded."""

    def __init__(self, *, trace_id: str, cycle_id: str):
        self.trace_id = str(trace_id)[:96]
        self.cycle_id = str(cycle_id)[:96]
        self._events: list[ReasoningTraceEvent] = []

    def record(self, *, state: str, kind: str, payload: Mapping[str, Any] | None = None) -> None:
        safe_payload = dict(payload or {})
        safe_payload.pop("raw_prompt", None)
        safe_payload.pop("raw_log", None)
        self._events.append(
            ReasoningTraceEvent(
                seq=len(self._events) + 1,
                trace_id=self.trace_id,
                cycle_id=self.cycle_id,
                state=str(state)[:64],
                kind=str(kind)[:64],
                payload=safe_payload,
            )
        )

    def events(self) -> tuple[ReasoningTraceEvent, ...]:
        return tuple(self._events)
