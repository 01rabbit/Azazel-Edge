"""Typed, allowlisted, read-only Capability Broker for M.I.O. (#364 / #384).

Security boundary rules enforced here:

* The registry is static and deep-frozen at construction (specs and their
  parameter schemas are copied, validated and frozen; later mutation of the
  caller's objects has no effect). Capability names cannot be created by the
  model, and names/parameter names that look like write, execution, network,
  path or enforcement primitives are refused at registration time.
* Requests are validated against closed, typed parameter schemas. Unknown
  keys, type confusion (``bool`` for ``int``, nested containers, ...),
  oversized values and control/bidi characters are refused before any handler
  runs.
* Every handler call has a per-capability timeout, a per-capability
  concurrency cap and a global in-flight cap. Slots are acquired without
  blocking, so overload returns a typed refusal instead of waiting. A handler
  that times out releases its slot and is accounted in a bounded quarantine.
* Results carry broker-assigned status, provenance and freshness. Adapters
  cannot claim provenance/status/authority: reserved keys are stripped
  case-insensitively at every depth.
* Every request (allowed or refused) produces a sanitized, size-bounded audit
  record built from a fixed field allowlist. Free-text parameter values and
  handler error text are never recorded; identifiers that are not well-formed,
  or that contain an address or a credential shape, are recorded only as a
  keyed (per-process HMAC) digest.
* ``close()`` ends the broker's cycle: later requests are refused and a
  handler still running when the cycle closes yields ``stale`` with no data.

There is no shell, subprocess, socket, HTTP, filesystem-path, packet-control,
Action Arbiter or AZ-06 control primitive in this module. Only the offline
shadow/replay reasoning loop calls the broker; no deterministic Edge path does.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .contracts import MioCapabilityRequest, MioCapabilityResult
from .id_grammar import AUDIT_ID_KINDS, CAPABILITY_NAME_RE, ID_WORDS, id_ok


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

_NAME_RE = CAPABILITY_NAME_RE
_PARAM_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
_IDENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._@#+=-]{0,127}\Z")
# Refused inside free text: C0 (except \t \n), DEL, C1, bidi controls, lone surrogates.
_TEXT_FORBIDDEN_RE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩\ud800-\udfff]"
)
_ID_FORBIDDEN_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩\ud800-\udfff]"
)

# v1 is read-only. A capability name is refused when any "_"-separated token is
# in FORBIDDEN_NAME_TOKENS (short words that would false-positive as
# substrings) or when it contains any FORBIDDEN_NAME_STEMS substring
# (catches run-together names such as ``writefile`` / ``fetchurl``).
FORBIDDEN_NAME_TOKENS = frozenset(
    {
        "run", "sh", "cmd", "eval", "put", "post", "patch", "rm", "set", "update", "create",
        "apply", "save", "store", "open", "file", "files", "kill", "block", "tc", "nft",
        "action", "act", "send", "exe",
    }
)
FORBIDDEN_NAME_STEMS = (
    "exec", "shell", "bash", "spawn", "command", "write", "delete", "remove", "upload", "download",
    "modif", "mutat", "commit", "http", "url", "fetch", "socket", "connect", "curl", "wget",
    "filesystem", "filename", "filepath", "path", "docker", "container", "enforce", "isolat",
    "redirect", "throttl", "quarantin", "firewall", "iptables", "nftables", "arbiter", "approv",
    "transition", "activat", "deploy", "trigger", "control", "az06", "decoy",
)
# Parameter names that would let a model aim a handler at an arbitrary target.
FORBIDDEN_PARAM_TOKENS = frozenset({"uri", "port", "code", "args", "argv", "dir", "dest", "to"})
FORBIDDEN_PARAM_STEMS = (
    "path", "file", "url", "host", "cmd", "command", "script", "shell", "exec", "endpoint", "socket",
    "folder", "target",
)
# Keys an adapter may not use to claim provenance/status/authority for itself
# (matched case-insensitively at every depth).
RESERVED_RESULT_KEYS = frozenset(
    {"source_component", "provenance", "status", "retrieved_at", "freshness", "trust",
     "age_seconds", "ok", "executable", "authority", "approved", "approval", "trusted"}
)

MAX_RESULT_DEPTH = 4
MAX_RESULT_NODES = 2048
MAX_EVIDENCE_REFS = 32
MAX_AUDIT_RECORD_CHARS = 2048
MAX_PURPOSE_HYPOTHESIS_IDS = 8
# Every audit record has exactly these keys (plus ``audit_truncated`` when
# reduced). Nothing outside this allowlist is ever projected.
AUDIT_RECORD_FIELDS = (
    "schema", "request_id", "trace_id", "purpose_hypothesis_ids", "capability", "capability_digest",
    "decision", "status", "reason", "params", "evidence_refs", "source_component", "age_seconds",
    "latency_ms", "result_chars", "truncated",
)
# Broker reasons are fixed codes with optional identifier suffixes; anything
# else is replaced before it reaches the audit record.
_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}(?::[A-Za-z0-9_]{1,64}){0,2}\Z")
FUTURE_SKEW_SECONDS = 60

# Per-process key: audit digests cannot be brute-forced offline from low-entropy
# inputs (IPs, hostnames) and are only comparable within one process lifetime.
_AUDIT_KEY = secrets.token_bytes(32)

# Event type used for submit wake-ups (module-level so tests can observe ordering).
_Event = threading.Event


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


class _ResultReject(Exception):
    def __init__(self, status: CapabilityStatus, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    try:
        return getattr(obj, name, default)
    except Exception:
        return default


def _iso(epoch: float | None) -> str:
    if epoch is None:
        return ""
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return ""


def _parse_timestamp(value: Any) -> float | None:
    """Parse an adapter-claimed timestamp. Returns None if unusable."""
    parsed: float | None = None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        parsed = float(value)
    elif isinstance(value, str) and 0 < len(value) <= 64:
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            parsed = dt.timestamp()
        except (ValueError, OverflowError, OSError):
            return None
    if parsed is None or not math.isfinite(parsed) or parsed < 0:
        return None
    return parsed


def _digest(value: Any) -> str:
    if type(value) is not str:
        try:
            label = type(value).__name__
        except Exception:
            label = "object"
        return f"<{label}>"
    return hmac.new(_AUDIT_KEY, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:16]


def _safe_label(value: Any, limit: int = 128) -> str:
    """Bounded, control-free label used for result request_id correlation."""
    if type(value) is not str:
        return _digest(value)
    return _ID_FORBIDDEN_RE.sub("?", value[:limit])


# Identifiers kept verbatim in the audit: an Evidence Plane event id or the
# cycle / request id grammar, both from id_grammar (shared with the model output
# parser and the no-model handoff), plus its second layer (address and secret
# shapes). Every other value (hostnames, person names, packed or
# integer-encoded addresses, bare hex, tokens) is replaced by the keyed digest.
AUDIT_ID_VOCABULARY = ID_WORDS


def _audit_safe(value: Any) -> bool:
    """An identifier may appear verbatim in the audit only if it fits the
    closed id grammar and carries no address or credential shape."""
    return id_ok(value, AUDIT_ID_KINDS)


def _audit_id(value: Any) -> str:
    """Safe identifiers are kept; anything else becomes a keyed digest."""
    if _audit_safe(value):
        return value
    return "h:" + _digest(value)


def _audit_reason(value: Any) -> str:
    if type(value) is str and (value == "" or _REASON_RE.match(value)):
        return value
    return "reason_redacted"


def _name_forbidden(name: str, tokens: frozenset[str], stems: tuple[str, ...]) -> bool:
    return bool(set(name.split("_")) & tokens) or any(stem in name for stem in stems)


def _frozen_spec(name: Any, spec: Any) -> CapabilitySpec:
    if type(name) is not str or not _NAME_RE.match(name):
        raise CapabilityBrokerError("capability_name_malformed")
    if _name_forbidden(name, FORBIDDEN_NAME_TOKENS, FORBIDDEN_NAME_STEMS):
        raise CapabilityBrokerError(f"capability_name_forbidden:{name}")
    if not isinstance(spec, CapabilitySpec) or not callable(spec.handler):
        raise CapabilityBrokerError(f"capability_spec_invalid:{name}")
    if not isinstance(spec.params, Mapping):
        raise CapabilityBrokerError(f"capability_params_invalid:{name}")
    # Deep copy then validate the copy: later mutation of the caller's dict
    # cannot widen the schema.
    params_copy = {pname: pspec for pname, pspec in list(spec.params.items())}
    for pname, pspec in params_copy.items():
        if type(pname) is not str or not _PARAM_NAME_RE.match(pname):
            raise CapabilityBrokerError(f"capability_param_name_malformed:{name}")
        if _name_forbidden(pname, FORBIDDEN_PARAM_TOKENS, FORBIDDEN_PARAM_STEMS):
            raise CapabilityBrokerError(f"capability_param_name_forbidden:{name}:{pname}")
        if type(pspec) is not ParamSpec:
            raise CapabilityBrokerError(f"capability_param_spec_invalid:{name}:{pname}")
    if not (0 < float(spec.timeout_seconds) <= 30):
        raise CapabilityBrokerError(f"capability_timeout_out_of_range:{name}")
    if not (1 <= int(spec.max_concurrency) <= 8):
        raise CapabilityBrokerError(f"capability_concurrency_out_of_range:{name}")
    if type(spec.source_component) is not str or not _IDENT_RE.match(spec.source_component):
        raise CapabilityBrokerError(f"capability_source_component_invalid:{name}")
    max_age = spec.max_age_seconds
    if max_age is not None and (type(max_age) is not int or max_age < 0):
        raise CapabilityBrokerError(f"capability_max_age_invalid:{name}")
    return replace(
        spec,
        params=MappingProxyType(params_copy),
        max_calls_per_cycle=int(spec.max_calls_per_cycle),
        max_result_chars=int(spec.max_result_chars),
        timeout_seconds=float(spec.timeout_seconds),
        max_concurrency=int(spec.max_concurrency),
    )


def _sanitize_result(value: Any, level: int, state: dict[str, int], limit: int) -> Any:
    """Bounded walk: reject non-JSON / too deep, strip reserved keys, cap size early."""
    state["nodes"] += 1
    if state["nodes"] > MAX_RESULT_NODES:
        raise _ResultReject(CapabilityStatus.TRUNCATED, "capability_result_too_large")
    if isinstance(value, Mapping) or isinstance(value, (list, tuple)):
        if level > MAX_RESULT_DEPTH:
            raise _ResultReject(CapabilityStatus.INVALID, "capability_result_too_deep")
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in list(value.items()):
            if type(key) is not str:
                raise _ResultReject(CapabilityStatus.INVALID, "capability_result_non_string_key")
            state["chars"] += len(key) + 4
            if key.lower() in RESERVED_RESULT_KEYS:
                state["stripped"] += 1
                continue
            out[key] = _sanitize_result(item, level + 1, state, limit)
        return out
    if isinstance(value, (list, tuple)):
        return [_sanitize_result(item, level + 1, state, limit) for item in value]
    if type(value) is str:
        state["chars"] += len(value) + 2
    elif value is None or type(value) in (bool, int):
        state["chars"] += 8
        if type(value) is int and abs(value) > 10**18:
            raise _ResultReject(CapabilityStatus.INVALID, "capability_result_not_json")
    elif type(value) is float:
        if not math.isfinite(value):
            raise _ResultReject(CapabilityStatus.INVALID, "capability_result_not_json")
        state["chars"] += 24
    else:
        raise _ResultReject(CapabilityStatus.INVALID, "capability_result_not_json")
    if state["chars"] > limit:
        raise _ResultReject(CapabilityStatus.TRUNCATED, "capability_result_too_large")
    return value


class _Slot:
    """Concurrency slot that can be released exactly once."""

    def __init__(
        self,
        cap_sem: threading.BoundedSemaphore,
        global_sem: threading.BoundedSemaphore,
        on_release: Callable[[], None] = lambda: None,
    ):
        self.lock = threading.Lock()
        self._cap_sem = cap_sem
        self._global_sem = global_sem
        self._on_release = on_release
        self._released = False
        self.done = False
        self.hung = False

    def release(self) -> None:
        with self.lock:
            if self._released:
                return
            self._released = True
        self._cap_sem.release()
        self._global_sem.release()
        self._on_release()


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
        max_quarantined: int = 4,
        clock: Callable[[], float] = time.time,
        audit_capacity: int = 256,
        audit_sink: Callable[[Mapping[str, Any]], None] | None = None,
    ):
        registry: dict[str, CapabilitySpec] = {}
        for name, spec in list(dict(capabilities or {}).items()):
            registry[name] = _frozen_spec(name, spec)
        self._capabilities: Mapping[str, CapabilitySpec] = MappingProxyType(registry)
        self._max_total_calls = max(0, int(max_total_calls))
        self._total_calls = 0
        self._per_capability_calls: dict[str, int] = {}
        self._clock = clock
        self._lock = threading.Lock()
        self._max_in_flight = max(1, min(int(max_in_flight), 16))
        self._global_slots = threading.BoundedSemaphore(self._max_in_flight)
        self._capability_slots = MappingProxyType(
            {name: threading.BoundedSemaphore(spec.max_concurrency) for name, spec in registry.items()}
        )
        # Timed-out handlers that are still running (bounded).
        self._max_quarantined = max(1, min(int(max_quarantined), 16))
        self._quarantined = 0
        self._quarantined_per_capability: dict[str, int] = {}
        # Admitted handlers whose slot is still held.
        self._in_flight = 0
        self._in_flight_per_capability: dict[str, int] = {}
        self._audit: deque[dict[str, Any]] = deque(maxlen=max(1, min(int(audit_capacity), 4096)))
        self._audit_sink = audit_sink
        # Cycle end: set by close(); wakes every waiting submit at once.
        self._closed = False
        self._waiters: set[threading.Event] = set()

    def close(self) -> None:
        """End this broker's reasoning cycle (e.g. the cycle was superseded).

        Later requests are refused with ``broker_closed``. A submit waiting on a
        handler returns ``stale`` / ``cycle_closed`` immediately, with no data;
        the handler thread cannot be killed, so it stays in the bounded
        quarantine until it returns and its result is discarded. Idempotent.
        """
        with self._lock:
            self._closed = True
            waiters = list(self._waiters)
        for event in waiters:
            event.set()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def for_new_cycle(self) -> "CapabilityBroker":
        """A new, open broker for the next reasoning cycle.

        Budgets are per broker (= per cycle), so each cycle gets its own: same
        frozen registry, limits, clock and audit sink, fresh call counters and
        slots. This broker is not changed; the caller closes it when its own
        cycle ends. The registry is the reviewed one already frozen here, so
        nothing new can be registered this way.
        """
        return CapabilityBroker(
            dict(self._capabilities),
            max_total_calls=self._max_total_calls,
            max_in_flight=self._max_in_flight,
            max_quarantined=self._max_quarantined,
            clock=self._clock,
            audit_capacity=self._audit.maxlen or 1,
            audit_sink=self._audit_sink,
        )

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._capabilities))

    def audit_records(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(copy.deepcopy(item) for item in self._audit)

    def quarantine_limit(self) -> int:
        """Upper bound on quarantined workers (and on running + quarantined)."""
        return self._max_quarantined

    def quarantined(self) -> int:
        with self._lock:
            return self._quarantined

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
        try:
            self._record_audit(request, result, params_audit)
        except Exception:
            try:
                fallback: dict[str, Any] = dict.fromkeys(AUDIT_RECORD_FIELDS)
                fallback.update(
                    schema="mio_capability_audit/v1", decision="refused" if result.status in REFUSAL_STATUSES else "allowed",
                    status=result.status, reason="audit_error", params={}, purpose_hypothesis_ids=[], evidence_refs=[],
                )
                self._append_audit(fallback)
            except Exception:
                pass
        return result

    # -- internals ------------------------------------------------------------

    def _result(self, request: Any, status: CapabilityStatus, error: str = "", **extra: Any) -> MioCapabilityResult:
        capability = _attr(request, "capability", "")
        try:
            retrieved_at = _iso(float(self._clock()))
        except Exception:
            retrieved_at = ""
        return MioCapabilityResult(
            request_id=_safe_label(_attr(request, "request_id", "")),
            capability=capability if type(capability) is str and capability in self._capabilities else "",
            ok=status is CapabilityStatus.OK,
            data=extra.pop("data", {}),
            evidence_refs=extra.pop("evidence_refs", ()),
            error=error,
            status=status.value,
            retrieved_at=retrieved_at,
            **extra,
        )

    def _submit(self, request: Any) -> tuple[MioCapabilityResult, dict[str, Any]]:
        # Closed contract: only the frozen request dataclass is accepted, so a
        # duck-typed object cannot smuggle extra fields past the schema.
        if type(request) is not MioCapabilityRequest:
            return self._result(request, CapabilityStatus.INVALID, "request_type_invalid"), {}
        for attr in ("request_id", "trace_id"):
            value = _attr(request, attr)
            if type(value) is not str or not value or len(value) > 128 or _ID_FORBIDDEN_RE.search(value):
                return self._result(request, CapabilityStatus.INVALID, f"invalid_{attr}"), {}
        purpose = _attr(request, "purpose_hypothesis_ids")
        if (
            not isinstance(purpose, (list, tuple))
            or len(purpose) > MAX_PURPOSE_HYPOTHESIS_IDS
            or any(type(x) is not str or not x or len(x) > 96 or _ID_FORBIDDEN_RE.search(x) for x in purpose)
        ):
            return self._result(request, CapabilityStatus.INVALID, "invalid_purpose_hypothesis_ids"), {}
        capability = _attr(request, "capability")
        if type(capability) is not str or not _NAME_RE.match(capability):
            return self._result(request, CapabilityStatus.REJECTED, "capability_name_malformed"), {}
        spec = self._capabilities.get(capability)
        if spec is None:
            return self._result(request, CapabilityStatus.REJECTED, "capability_not_allowlisted"), {}

        args, params_audit, arg_error = self._validate_arguments(_attr(request, "arguments"), spec)
        if arg_error:
            return self._result(request, CapabilityStatus.INVALID, arg_error), params_audit

        max_age = spec.max_age_seconds
        req_age = _attr(request, "max_age_seconds")
        if req_age is not None:
            if type(req_age) is not int or req_age < 0:
                return self._result(request, CapabilityStatus.INVALID, "invalid_max_age_seconds"), params_audit
            max_age = req_age if max_age is None else min(max_age, req_age)

        cap_slots = self._capability_slots[capability]
        # Admission is one atomic critical section: budget check + increment +
        # quarantine check + non-blocking slot acquisition.
        wake = _Event()
        with self._lock:
            if self._closed:
                return self._result(request, CapabilityStatus.REJECTED, "broker_closed"), params_audit
            if self._total_calls >= self._max_total_calls:
                return self._result(request, CapabilityStatus.REJECTED, "broker_total_budget_exhausted"), params_audit
            used = self._per_capability_calls.get(capability, 0)
            if used >= spec.max_calls_per_cycle:
                return self._result(request, CapabilityStatus.REJECTED, "capability_budget_exhausted"), params_audit
            # Live workers (running + quarantined) never exceed
            # max_quarantined, so even if every running handler times out (or
            # close() strands them) the quarantine stays within its bound. The
            # same holds per capability against max_concurrency.
            if self._quarantined + self._in_flight >= self._max_quarantined:
                reason = "broker_quarantine_full" if self._quarantined else "broker_overloaded"
                return self._result(request, CapabilityStatus.REJECTED, reason), params_audit
            cap_quarantined = self._quarantined_per_capability.get(capability, 0)
            if cap_quarantined + self._in_flight_per_capability.get(capability, 0) >= spec.max_concurrency:
                reason = "capability_quarantined" if cap_quarantined else "capability_overloaded"
                return self._result(request, CapabilityStatus.REJECTED, reason), params_audit
            if not self._global_slots.acquire(blocking=False):
                return self._result(request, CapabilityStatus.REJECTED, "broker_overloaded"), params_audit
            if not cap_slots.acquire(blocking=False):
                self._global_slots.release()
                return self._result(request, CapabilityStatus.REJECTED, "capability_overloaded"), params_audit
            self._total_calls += 1
            self._per_capability_calls[capability] = used + 1
            self._in_flight += 1
            self._in_flight_per_capability[capability] = self._in_flight_per_capability.get(capability, 0) + 1
            self._waiters.add(wake)

        def _leave_in_flight() -> None:
            with self._lock:
                self._in_flight -= 1
                self._in_flight_per_capability[capability] -= 1

        slot = _Slot(cap_slots, self._global_slots, _leave_in_flight)
        outcome: dict[str, Any] = {}
        frozen_args = MappingProxyType(dict(args))

        def _run() -> None:
            try:
                outcome["raw"] = spec.handler(frozen_args)
            except CapabilityUnavailable:
                outcome["status"] = CapabilityStatus.UNAVAILABLE
                outcome["error"] = "capability_unavailable"
            except BaseException as exc:
                outcome["status"] = CapabilityStatus.ERROR
                outcome["error"] = f"handler_error:{type(exc).__name__}"[:96]
            finally:
                slot.release()
                # Mark done before waking the submitter: a woken submitter
                # must never see a finished handler as still running.
                with slot.lock:
                    slot.done = True
                    was_hung = slot.hung
                    if was_hung:
                        with self._lock:
                            self._quarantined -= 1
                            self._quarantined_per_capability[capability] -= 1
                wake.set()

        base = {"source_component": spec.source_component, "max_age_seconds": max_age}
        worker = threading.Thread(target=_run, name=f"mio-cap-{capability}", daemon=True)
        try:
            try:
                worker.start()
            except Exception:
                slot.release()
                return self._result(request, CapabilityStatus.ERROR, "worker_start_failed", **base), params_audit
            # Wakes when the handler finishes, the timeout elapses, or close().
            wake.wait(spec.timeout_seconds)
        finally:
            with self._lock:
                self._waiters.discard(wake)
                cycle_closed = self._closed
        with slot.lock:
            timed_out = not slot.done
            if timed_out:
                slot.hung = True
                with self._lock:
                    self._quarantined += 1
                    self._quarantined_per_capability[capability] = self._quarantined_per_capability.get(capability, 0) + 1
        if timed_out:
            # Free the concurrency slot; the still-running worker is accounted
            # in the bounded quarantine until it returns.
            slot.release()
            if cycle_closed:
                return self._result(request, CapabilityStatus.STALE, "cycle_closed", **base), params_audit
            return self._result(request, CapabilityStatus.TIMEOUT, "capability_timeout", **base), params_audit
        if cycle_closed:
            # The cycle ended while the handler ran: its data belongs to a
            # superseded cycle and cannot ground anything.
            return self._result(request, CapabilityStatus.STALE, "cycle_closed", **base), params_audit
        worker.join(0.5)
        if "status" in outcome:
            return self._result(request, outcome["status"], outcome["error"], **base), params_audit
        return self._finalize(request, spec, outcome.get("raw"), max_age, base), params_audit

    def _validate_arguments(self, arguments: Any, spec: CapabilitySpec) -> tuple[dict[str, Any], dict[str, Any], str]:
        audit: dict[str, Any] = {}
        if not isinstance(arguments, Mapping):
            return {}, audit, "arguments_not_mapping"
        items = list(arguments.items())
        if len(items) > len(spec.params):
            audit["unknown_param_count"] = max(1, len(items) - len(spec.params))
            return {}, audit, "unknown_argument"
        supplied: dict[str, Any] = {}
        unknown = 0
        for key, value in items:
            if type(key) is not str or key not in spec.params:
                unknown += 1
            else:
                supplied[key] = value
        if unknown:
            audit["unknown_param_count"] = unknown
            return {}, audit, "unknown_argument"
        out: dict[str, Any] = {}
        for name, pspec in spec.params.items():
            if name not in supplied:
                if pspec.required:
                    return {}, audit, f"missing_argument:{name}"
                continue
            value = supplied[name]
            entry: dict[str, Any] = {"kind": pspec.kind, "type": type(value).__name__}
            audit[name] = entry
            if pspec.kind in {"text", "identifier"}:
                if type(value) is not str:
                    return {}, audit, f"argument_type_mismatch:{name}"
                entry["length"] = len(value)
                if len(value) > pspec.max_length:
                    return {}, audit, f"argument_too_long:{name}"
                if pspec.kind == "text":
                    if _TEXT_FORBIDDEN_RE.search(value):
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
        # NOTE: source_timestamp is adapter self-claimed; the broker bounds and
        # checks it but cannot independently verify it.
        source_ts_raw = data.pop("source_timestamp", None)
        state = {"nodes": 0, "chars": 0, "stripped": 0}
        try:
            data = _sanitize_result(data, 1, state, spec.max_result_chars)
        except _ResultReject as rej:
            truncated = rej.status is CapabilityStatus.TRUNCATED
            return self._result(request, rej.status, rej.reason, truncated=truncated, **base)
        if state["stripped"]:
            limitations.append("adapter_reserved_keys_ignored")
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
            candidates = list(refs[: MAX_EVIDENCE_REFS * 4])
            for ref in candidates:
                if type(ref) is str and _IDENT_RE.match(ref) and ref not in clean_refs:
                    clean_refs.append(ref)
            if len(clean_refs) > MAX_EVIDENCE_REFS or len(refs) > len(candidates):
                clean_refs = clean_refs[:MAX_EVIDENCE_REFS]
                limitations.append("evidence_refs_capped")
            elif len(clean_refs) < len(candidates):
                limitations.append("evidence_refs_dropped")
        elif refs:
            limitations.append("evidence_refs_dropped")

        now = float(self._clock())
        age: int | None = None
        if source_ts_raw is not None:
            source_ts = _parse_timestamp(source_ts_raw)
            if source_ts is None:
                return self._result(request, CapabilityStatus.INVALID, "source_timestamp_invalid", **base)
            if source_ts - now > FUTURE_SKEW_SECONDS:
                return self._result(request, CapabilityStatus.INVALID, "source_timestamp_in_future", **base)
            age = max(0, int(now - source_ts))
        else:
            source_ts = None
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

    def _append_audit(self, record: dict[str, Any]) -> None:
        with self._lock:
            self._audit.append(record)
        if self._audit_sink is not None:
            try:
                self._audit_sink(copy.deepcopy(record))
            except Exception:
                pass  # audit sink failure must not affect Edge or the loop

    def _record_audit(self, request: Any, result: MioCapabilityResult, params_audit: Mapping[str, Any]) -> None:
        capability = _attr(request, "capability")
        allowlisted = type(capability) is str and capability in self._capabilities
        purpose = _attr(request, "purpose_hypothesis_ids", ())
        record: dict[str, Any] = {
            "schema": "mio_capability_audit/v1",
            "request_id": _audit_id(_attr(request, "request_id")),
            "trace_id": _audit_id(_attr(request, "trace_id")),
            "purpose_hypothesis_ids": [_audit_id(x) for x in purpose[:8]] if isinstance(purpose, (list, tuple)) else [],
            "capability": capability if allowlisted else None,
            "capability_digest": None if allowlisted else _digest(capability),
            "decision": "refused" if result.status in REFUSAL_STATUSES else "allowed",
            "status": result.status,
            "reason": _audit_reason(result.error),
            "params": copy.deepcopy(dict(params_audit)),
            "evidence_refs": [_audit_id(ref) for ref in result.evidence_refs],
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
        self._append_audit(record)
