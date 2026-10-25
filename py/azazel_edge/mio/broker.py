"""Typed, allowlisted, read-only Capability Broker for M.I.O. (#364 / #384).

Security boundary rules enforced here:

* The registry is static and frozen at construction. Capability names cannot
  be created by the model, and names/parameter names that look like write,
  execution, network, path or enforcement primitives are refused at
  registration time.
* Requests are validated against closed, typed parameter schemas. Unknown
  keys, type confusion (``bool`` for ``int``, nested containers, ...),
  oversized values and control characters are refused before any handler runs.
* Every handler call has a per-capability timeout, a per-capability
  concurrency cap and a global in-flight cap. Slots are acquired without
  blocking, so overload returns a typed refusal instead of waiting.
* Results carry broker-assigned status, provenance and freshness. Adapters
  cannot claim their own provenance; reserved keys returned by adapters are
  ignored.
* Every request (allowed or refused) produces a sanitized, size-bounded audit
  record that never contains raw parameter text or raw handler errors.

There is no shell, subprocess, socket, HTTP, filesystem-path, packet-control,
Action Arbiter or AZ-06 control primitive in this module.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .contracts import MioCapabilityRequest, MioCapabilityResult


class CapabilityBrokerError(RuntimeError):
    pass


class CapabilityUnavailable(RuntimeError):
    """Raised by an adapter when its read-only source is unavailable."""


class CapabilityStatus(str, Enum):
    OK = "ok"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    STALE = "stale"
    REJECTED = "rejected"
    INVALID = "invalid"
    TRUNCATED = "truncated"
    ERROR = "error"


# Statuses where the broker refused the request before any handler work.
# ``execute()`` raises for these to keep the legacy loop contract.
REFUSAL_STATUSES = frozenset({CapabilityStatus.REJECTED.value, CapabilityStatus.INVALID.value})

_NAME_RE = re.compile(r"[a-z][a-z0-9_]{2,63}\Z")
_PARAM_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_IDENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._@#+=-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_ANY_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

# Tokens (split on "_") that may not appear in a capability name: v1 is
# read-only, so anything that sounds like a write / execute / network /
# enforcement / AZ-06 transition primitive is structurally refused.
FORBIDDEN_NAME_TOKENS = frozenset(
    {
        "exec", "execute", "run", "shell", "sh", "bash", "cmd", "command", "spawn", "eval",
        "write", "put", "post", "patch", "delete", "remove", "rm", "set", "update", "create",
        "apply", "commit", "save", "store", "upload", "modify", "mutate",
        "http", "https", "url", "fetch", "request", "socket", "connect", "download", "curl", "wget",
        "file", "path", "open", "docker", "container",
        "enforce", "enforcement", "block", "isolate", "redirect", "throttle", "quarantine", "kill",
        "nft", "nftables", "iptables", "tc", "firewall", "arbiter", "action", "approve", "approval",
        "transition", "activate", "deactivate", "deploy", "trigger", "control", "az06", "decoy",
    }
)
# Parameter names that would let a model aim a handler at an arbitrary target.
FORBIDDEN_PARAM_NAMES = frozenset(
    {"path", "file", "filename", "url", "uri", "host", "hostname", "port", "command", "cmd",
     "shell", "script", "code", "exec", "args", "argv", "endpoint", "socket", "target_url"}
)
# Keys an adapter may not use to claim provenance/status/authority for itself.
RESERVED_RESULT_KEYS = frozenset(
    {"source_component", "provenance", "status", "retrieved_at", "freshness", "trust",
     "age_seconds", "ok", "executable", "authority", "approved"}
)

MAX_RESULT_DEPTH = 4
MAX_EVIDENCE_REFS = 32
MAX_AUDIT_RECORD_CHARS = 2048
FUTURE_SKEW_SECONDS = 60


@dataclass(frozen=True)
class ParamSpec:
    """Typed parameter schema. ``text`` is opaque data: never a path/URL/command."""

    kind: str  # "text" | "identifier" | "integer" | "boolean"
    max_length: int = 160
    required: bool = False
    minimum: int = 0
    maximum: int = 10_000

    def __post_init__(self) -> None:
        if self.kind not in {"text", "identifier", "integer", "boolean"}:
            raise CapabilityBrokerError(f"invalid_param_kind:{self.kind}")


# Parameters the bounded reasoning loop sends today.
DEFAULT_PARAMS: Mapping[str, ParamSpec] = MappingProxyType(
    {"question": ParamSpec("text", 300), "frame_id": ParamSpec("identifier", 96)}
)


@dataclass(frozen=True)
class CapabilitySpec:
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    max_calls_per_cycle: int = 2
    max_result_chars: int = 4096
    params: Mapping[str, ParamSpec] = field(default_factory=lambda: DEFAULT_PARAMS)
    timeout_seconds: float = 2.0
    max_concurrency: int = 1
    max_age_seconds: int | None = None
    source_component: str = "edge-local"


def _iso(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and 0 < len(value) <= 64:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def _depth(value: Any, level: int = 0) -> int:
    if level > MAX_RESULT_DEPTH + 1:
        return level
    if isinstance(value, Mapping):
        return max([level + 1] + [_depth(v, level + 1) for v in value.values()])
    if isinstance(value, (list, tuple)):
        return max([level + 1] + [_depth(v, level + 1) for v in value])
    return level


def _digest(value: Any) -> str:
    return hashlib.sha256(repr(value).encode("utf-8", "replace")).hexdigest()[:16]


def _safe_label(value: Any, limit: int = 128) -> str:
    """Bounded, printable label for audit IDs (never raw free text)."""
    if not isinstance(value, str):
        return f"<{type(value).__name__}>"
    return _ANY_CONTROL_RE.sub("?", value[:limit])


def _validate_registry_name(name: Any) -> None:
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise CapabilityBrokerError("capability_name_malformed")
    if set(name.split("_")) & FORBIDDEN_NAME_TOKENS:
        raise CapabilityBrokerError(f"capability_name_forbidden:{name}")


def _validate_spec(name: str, spec: Any) -> None:
    if not isinstance(spec, CapabilitySpec) or not callable(spec.handler):
        raise CapabilityBrokerError(f"capability_spec_invalid:{name}")
    if not isinstance(spec.params, Mapping):
        raise CapabilityBrokerError(f"capability_params_invalid:{name}")
    for pname, pspec in spec.params.items():
        if not isinstance(pname, str) or not _PARAM_NAME_RE.match(pname):
            raise CapabilityBrokerError(f"capability_param_name_malformed:{name}")
        if pname in FORBIDDEN_PARAM_NAMES:
            raise CapabilityBrokerError(f"capability_param_name_forbidden:{name}:{pname}")
        if not isinstance(pspec, ParamSpec):
            raise CapabilityBrokerError(f"capability_param_spec_invalid:{name}:{pname}")
    if not (0 < float(spec.timeout_seconds) <= 30):
        raise CapabilityBrokerError(f"capability_timeout_out_of_range:{name}")
    if not (1 <= int(spec.max_concurrency) <= 8):
        raise CapabilityBrokerError(f"capability_concurrency_out_of_range:{name}")
    if not _IDENT_RE.match(str(spec.source_component)):
        raise CapabilityBrokerError(f"capability_source_component_invalid:{name}")


class CapabilityBroker:
    """Typed, allowlisted, read-only capability surface for M.I.O.

    Handlers return data only. This broker intentionally provides no shell,
    arbitrary HTTP, filesystem path, packet-control, or enforcement primitive.
    """

    def __init__(
        self,
        capabilities: Mapping[str, CapabilitySpec] | None = None,
        *,
        max_total_calls: int = 4,
        max_in_flight: int = 4,
        clock: Callable[[], float] = time.time,
        audit_capacity: int = 256,
        audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ):
        registry: dict[str, CapabilitySpec] = {}
        for name, spec in dict(capabilities or {}).items():
            _validate_registry_name(name)
            _validate_spec(name, spec)
            registry[name] = spec
        self._capabilities: Mapping[str, CapabilitySpec] = MappingProxyType(registry)
        self._max_total_calls = max(0, int(max_total_calls))
        self._total_calls = 0
        self._per_capability_calls: dict[str, int] = {}
        self._clock = clock
        self._lock = threading.Lock()
        self._global_slots = threading.BoundedSemaphore(max(1, min(int(max_in_flight), 16)))
        self._capability_slots = MappingProxyType(
            {name: threading.BoundedSemaphore(int(spec.max_concurrency)) for name, spec in registry.items()}
        )
        self._audit: deque[dict[str, Any]] = deque(maxlen=max(1, min(int(audit_capacity), 4096)))
        self._audit_sink = audit_sink

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._capabilities))

    def audit_records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(item) for item in self._audit)

    # -- public entrypoints -------------------------------------------------

    def execute(self, request: MioCapabilityRequest) -> MioCapabilityResult:
        """Legacy entrypoint: refusals raise ``CapabilityBrokerError``."""
        result = self.submit(request)
        if result.status in REFUSAL_STATUSES:
            raise CapabilityBrokerError(result.error)
        return result

    def submit(self, request: MioCapabilityRequest) -> MioCapabilityResult:
        """Never raises and never blocks beyond the capability timeout."""
        started = time.monotonic()
        params_audit: dict[str, Any] = {}
        try:
            result, params_audit = self._submit(request)
        except Exception as exc:  # defensive: the broker must not break Edge
            result = self._result(request, CapabilityStatus.ERROR, f"broker_internal_error:{type(exc).__name__}")
        result = replace(result, latency_ms=int((time.monotonic() - started) * 1000))
        self._record_audit(request, result, params_audit)
        return result

    # -- internals ------------------------------------------------------------

    def _result(self, request: Any, status: CapabilityStatus, error: str = "", **extra: Any) -> MioCapabilityResult:
        capability = getattr(request, "capability", "")
        return MioCapabilityResult(
            request_id=_safe_label(getattr(request, "request_id", "")),
            capability=capability if isinstance(capability, str) and capability in self._capabilities else "",
            ok=status is CapabilityStatus.OK,
            data=extra.pop("data", {}),
            evidence_refs=extra.pop("evidence_refs", ()),
            error=error,
            status=status.value,
            retrieved_at=_iso(self._clock()),
            **extra,
        )

    def _submit(self, request: Any) -> tuple[MioCapabilityResult, dict[str, Any]]:
        for attr in ("request_id", "trace_id"):
            value = getattr(request, attr, None)
            if not isinstance(value, str) or not value or len(value) > 128 or _ANY_CONTROL_RE.search(value):
                return self._result(request, CapabilityStatus.INVALID, f"invalid_{attr}"), {}
        capability = getattr(request, "capability", None)
        with self._lock:
            if self._total_calls >= self._max_total_calls:
                return self._result(request, CapabilityStatus.REJECTED, "broker_total_budget_exhausted"), {}
        if not isinstance(capability, str) or not _NAME_RE.match(capability):
            return self._result(request, CapabilityStatus.REJECTED, "capability_name_malformed"), {}
        spec = self._capabilities.get(capability)
        if spec is None:
            return self._result(request, CapabilityStatus.REJECTED, "capability_not_allowlisted"), {}

        args, params_audit, arg_error = self._validate_arguments(getattr(request, "arguments", None), spec)
        if arg_error:
            return self._result(request, CapabilityStatus.INVALID, arg_error), params_audit

        max_age = spec.max_age_seconds
        req_age = getattr(request, "max_age_seconds", None)
        if req_age is not None:
            if type(req_age) is not int or req_age < 0:
                return self._result(request, CapabilityStatus.INVALID, "invalid_max_age_seconds"), params_audit
            max_age = req_age if max_age is None else min(max_age, req_age)

        cap_slots = self._capability_slots[capability]
        with self._lock:
            used = self._per_capability_calls.get(capability, 0)
            if used >= spec.max_calls_per_cycle:
                return self._result(request, CapabilityStatus.REJECTED, "capability_budget_exhausted"), params_audit
            if not self._global_slots.acquire(blocking=False):
                return self._result(request, CapabilityStatus.REJECTED, "broker_overloaded"), params_audit
            if not cap_slots.acquire(blocking=False):
                self._global_slots.release()
                return self._result(request, CapabilityStatus.REJECTED, "capability_overloaded"), params_audit
            self._total_calls += 1
            self._per_capability_calls[capability] = used + 1

        outcome: dict[str, Any] = {}
        frozen_args = MappingProxyType(dict(args))

        def _run() -> None:
            try:
                outcome["raw"] = spec.handler(frozen_args)
            except CapabilityUnavailable:
                outcome["status"] = CapabilityStatus.UNAVAILABLE
                outcome["error"] = "capability_unavailable"
            except Exception as exc:
                outcome["status"] = CapabilityStatus.ERROR
                outcome["error"] = f"handler_error:{type(exc).__name__}"[:96]
            finally:
                cap_slots.release()
                self._global_slots.release()

        worker = threading.Thread(target=_run, name=f"mio-cap-{capability}", daemon=True)
        worker.start()
        worker.join(float(spec.timeout_seconds))
        base = {"source_component": spec.source_component, "max_age_seconds": max_age}
        if worker.is_alive():
            # The slot stays held until the handler returns: later requests get
            # a typed overload refusal instead of piling up behind it.
            return self._result(request, CapabilityStatus.TIMEOUT, "capability_timeout", **base), params_audit
        if "status" in outcome:
            return self._result(request, outcome["status"], outcome["error"], **base), params_audit
        return self._finalize(request, spec, outcome.get("raw"), max_age, base), params_audit

    def _validate_arguments(self, arguments: Any, spec: CapabilitySpec) -> tuple[dict[str, Any], dict[str, Any], str]:
        audit: dict[str, Any] = {}
        if not isinstance(arguments, Mapping):
            return {}, audit, "arguments_not_mapping"
        unknown = [k for k in arguments.keys() if not isinstance(k, str) or k not in spec.params]
        if unknown:
            audit["unknown_param_count"] = len(unknown)
            return {}, audit, "unknown_argument"
        out: dict[str, Any] = {}
        for name, pspec in spec.params.items():
            if name not in arguments:
                if pspec.required:
                    return {}, audit, f"missing_argument:{name}"
                continue
            value = arguments[name]
            entry: dict[str, Any] = {"kind": pspec.kind, "type": type(value).__name__}
            audit[name] = entry
            if pspec.kind in {"text", "identifier"}:
                if type(value) is not str:
                    return {}, audit, f"argument_type_mismatch:{name}"
                entry["length"] = len(value)
                if len(value) > pspec.max_length:
                    return {}, audit, f"argument_too_long:{name}"
                if pspec.kind == "text":
                    if _CONTROL_RE.search(value):
                        return {}, audit, f"argument_control_chars:{name}"
                else:
                    entry["digest"] = _digest(value)
                    if not _IDENT_RE.match(value) or ".." in value:
                        return {}, audit, f"argument_malformed_identifier:{name}"
            elif pspec.kind == "integer":
                if type(value) is not int:
                    return {}, audit, f"argument_type_mismatch:{name}"
                if not (pspec.minimum <= value <= pspec.maximum):
                    return {}, audit, f"argument_out_of_range:{name}"
            elif type(value) is not bool:
                return {}, audit, f"argument_type_mismatch:{name}"
            out[name] = value
        return out, audit, ""

    def _finalize(self, request: Any, spec: CapabilitySpec, raw: Any, max_age: int | None, base: dict[str, Any]) -> MioCapabilityResult:
        if not isinstance(raw, Mapping):
            return self._result(request, CapabilityStatus.ERROR, "capability_result_not_mapping", **base)
        data = dict(raw)
        limitations: list[str] = []
        refs = data.pop("evidence_refs", ())
        source_ts_raw = data.pop("source_timestamp", None)
        reserved = sorted(k for k in data if isinstance(k, str) and k in RESERVED_RESULT_KEYS)
        for key in reserved:
            data.pop(key, None)
        if reserved:
            limitations.append("adapter_reserved_keys_ignored")
        if any(not isinstance(k, str) for k in data):
            return self._result(request, CapabilityStatus.INVALID, "capability_result_non_string_key", **base)
        if _depth(data) > MAX_RESULT_DEPTH:
            return self._result(request, CapabilityStatus.INVALID, "capability_result_too_deep", **base)
        try:
            rendered = json.dumps(data, sort_keys=True, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError):
            return self._result(request, CapabilityStatus.INVALID, "capability_result_not_json", **base)
        if len(rendered) > spec.max_result_chars:
            return self._result(
                request, CapabilityStatus.TRUNCATED, "capability_result_too_large",
                truncated=True, result_chars=len(rendered), **base,
            )
        clean_refs: list[str] = []
        if isinstance(refs, (list, tuple)):
            for ref in refs:
                if isinstance(ref, str) and _IDENT_RE.match(ref) and ref not in clean_refs:
                    clean_refs.append(ref)
            if len(clean_refs) > MAX_EVIDENCE_REFS:
                clean_refs = clean_refs[:MAX_EVIDENCE_REFS]
                limitations.append("evidence_refs_capped")
            elif len(clean_refs) < len(refs):
                limitations.append("evidence_refs_dropped")
        elif refs:
            limitations.append("evidence_refs_dropped")

        now = self._clock()
        source_ts = _parse_timestamp(source_ts_raw)
        age: int | None = None
        if source_ts_raw is not None and source_ts is None:
            limitations.append("source_timestamp_unparseable")
        if source_ts is not None:
            if source_ts - now > FUTURE_SKEW_SECONDS:
                return self._result(request, CapabilityStatus.INVALID, "source_timestamp_in_future", **base)
            age = max(0, int(now - source_ts))
        common = dict(
            source_timestamp=_iso(source_ts),
            age_seconds=age,
            result_chars=len(rendered),
            limitations=tuple(limitations),
            **base,
        )
        if max_age is not None and (age is None or age > max_age):
            reason = "source_timestamp_missing" if age is None else "result_stale"
            # Stale data cannot ground hypotheses: no data, no evidence refs.
            return self._result(request, CapabilityStatus.STALE, reason, **common)
        return self._result(request, CapabilityStatus.OK, "", data=data, evidence_refs=tuple(clean_refs), **common)

    def _record_audit(self, request: Any, result: MioCapabilityResult, params_audit: Mapping[str, Any]) -> None:
        capability = getattr(request, "capability", None)
        allowlisted = isinstance(capability, str) and capability in self._capabilities
        purpose = getattr(request, "purpose_hypothesis_ids", ())
        record: dict[str, Any] = {
            "schema": "mio_capability_audit/v1",
            "request_id": _safe_label(getattr(request, "request_id", None)),
            "trace_id": _safe_label(getattr(request, "trace_id", None)),
            "purpose_hypothesis_ids": [_safe_label(x, 96) for x in purpose[:8]] if isinstance(purpose, (list, tuple)) else [],
            "capability": capability if allowlisted else None,
            "capability_digest": None if allowlisted else _digest(capability),
            "decision": "refused" if result.status in REFUSAL_STATUSES else "allowed",
            "status": result.status,
            "reason": result.error,
            "params": dict(params_audit),
            "evidence_refs": list(result.evidence_refs),
            "source_component": result.source_component,
            "age_seconds": result.age_seconds,
            "latency_ms": result.latency_ms,
            "result_chars": result.result_chars,
            "truncated": result.truncated,
        }
        if len(json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)) > MAX_AUDIT_RECORD_CHARS:
            record["evidence_refs"] = record["evidence_refs"][:4]
            record["purpose_hypothesis_ids"] = record["purpose_hypothesis_ids"][:2]
            record["params"] = {"omitted": True}
            record["audit_truncated"] = True
        with self._lock:
            self._audit.append(record)
        if self._audit_sink is not None:
            try:
                self._audit_sink(dict(record))
            except Exception:
                pass  # audit sink failure must not affect Edge or the loop
