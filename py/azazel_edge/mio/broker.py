from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .contracts import MioCapabilityRequest, MioCapabilityResult


class CapabilityBrokerError(RuntimeError):
    pass


@dataclass(frozen=True)
class CapabilitySpec:
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    max_calls_per_cycle: int = 2
    max_result_chars: int = 4096


class CapabilityBroker:
    """Typed, allowlisted, read-only capability surface for M.I.O.

    Handlers return data only. This broker intentionally provides no shell,
    arbitrary HTTP, filesystem path, packet-control, or enforcement primitive.
    """

    def __init__(self, capabilities: Mapping[str, CapabilitySpec] | None = None, *, max_total_calls: int = 4):
        self._capabilities = dict(capabilities or {})
        self._max_total_calls = max(0, int(max_total_calls))
        self._total_calls = 0
        self._per_capability_calls: dict[str, int] = {}

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._capabilities))

    def execute(self, request: MioCapabilityRequest) -> MioCapabilityResult:
        if self._total_calls >= self._max_total_calls:
            raise CapabilityBrokerError("broker_total_budget_exhausted")
        spec = self._capabilities.get(request.capability)
        if spec is None:
            raise CapabilityBrokerError("capability_not_allowlisted")
        used = self._per_capability_calls.get(request.capability, 0)
        if used >= spec.max_calls_per_cycle:
            raise CapabilityBrokerError("capability_budget_exhausted")
        self._total_calls += 1
        self._per_capability_calls[request.capability] = used + 1
        try:
            raw = dict(spec.handler(dict(request.arguments)))
        except Exception as exc:
            return MioCapabilityResult(
                request_id=request.request_id,
                capability=request.capability,
                ok=False,
                data={},
                error=str(exc)[:160],
            )
        rendered = repr(raw)
        if len(rendered) > spec.max_result_chars:
            return MioCapabilityResult(
                request_id=request.request_id,
                capability=request.capability,
                ok=False,
                data={},
                error="capability_result_too_large",
            )
        refs = raw.pop("evidence_refs", ())
        if not isinstance(refs, (list, tuple)):
            refs = ()
        return MioCapabilityResult(
            request_id=request.request_id,
            capability=request.capability,
            ok=True,
            data=raw,
            evidence_refs=tuple(str(x)[:128] for x in refs[:32]),
        )
