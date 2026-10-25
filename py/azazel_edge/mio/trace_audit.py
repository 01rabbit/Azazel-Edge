"""M.I.O. reasoning trace: identity rules, per-cycle working memory, durable
minimized audit projection and retention/quota behaviour (#389, parent #377).

Everything here is advisory-only. Nothing in this module is imported by the
deterministic Edge path (Arbiter, enforcement, Rust core) and nothing here can
approve, execute, or change an Edge decision. When the durable audit sink cannot
write (quota, retention, I/O error), only the M.I.O. advisory path closes; the
deterministic path never waits on, reads, or depends on this module.

Identity rules
    IDs are minted by Edge or by this code from validated parts, never parsed
    out of attacker-supplied or model-supplied text. Each kind has a closed
    grammar (``ID_GRAMMAR``). A value that does not match its kind's grammar is
    never written as-is: the projection records it as ``h:<keyed digest>``.
    A M.I.O. advisory ID (``...:advisory``) can never pass as an Edge decision
    reference (``EDGE_DECISION_REF``) and vice versa.

Projection
    ``project_outcome`` is a pure function of (ticket, outcome, key, refs). It
    keeps IDs, versions, digests, statuses, counts and closed-vocabulary codes.
    It drops all free text (hypothesis statements, recommendation summary and
    rationale, broker result data, prompts, raw model output, frame facts); for
    text needed for replay correlation it keeps only a keyed digest and length.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from typing import Any, Callable, Mapping, Protocol

from .redaction import contains_token_like
from .lifecycle import CycleTicket, ReasoningCoordinator, material_frame_digest
from .contracts import MioSituationFrame

TRACE_AUDIT_SCHEMA = "mio.trace_audit.v1"
MAX_RECORD_BYTES = 4096
_LIST_CAP = 16

# --- identity -----------------------------------------------------------------

_TRACE = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_CYCLE = _TRACE + r":e[0-9]{1,9}:c[0-9]{1,12}"
ID_GRAMMAR: dict[str, re.Pattern[str]] = {
    # Edge-side correlation key for one incident/situation.
    "trace_id": re.compile(rf"^{_TRACE}$"),
    # Minted only by ReasoningCoordinator.begin: <trace>:e<epoch>:c<seq>.
    "cycle_id": re.compile(rf"^{_CYCLE}$"),
    "frame_id": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$"),
    # Model may propose hypothesis IDs; only this short shape survives as-is.
    "hypothesis_id": re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$"),
    "request_id": re.compile(rf"^{_CYCLE}:req:[0-9]{{1,3}}$"),
    "advisory_id": re.compile(rf"^{_CYCLE}:advisory$"),
    # Authoritative Edge decision reference. Never ends in ':advisory' and never
    # carries the M.I.O. cycle shape, so the two kinds are disjoint.
    "edge_decision_ref": re.compile(r"^edge-dec:[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    "evidence_ref": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$"),
    "code": re.compile(r"^[a-z][a-z0-9_.]{0,63}$"),
    # Content digests (playbook/frame/handoff). Hex only, so never secret-shaped text.
    "digest": re.compile(r"^[0-9a-f]{16,64}$"),
}
EDGE_DECISION_REF = "edge_decision_ref"


def is_valid_id(kind: str, value: Any) -> bool:
    pattern = ID_GRAMMAR.get(kind)
    if pattern is None:
        raise ValueError(f"unknown_id_kind:{kind}")
    if type(value) is not str or pattern.fullmatch(value) is None:
        return False
    if kind == EDGE_DECISION_REF and ID_GRAMMAR["advisory_id"].fullmatch(value[len("edge-dec:"):]):
        return False
    return True


def require_id(kind: str, value: Any) -> str:
    """Raise unless ``value`` is a well-formed ID of ``kind``. Use at boundaries
    where a specific kind is required (e.g. an Edge decision reference)."""
    if not is_valid_id(kind, value):
        raise ValueError(f"invalid_{kind}")
    return value


def cycle_belongs_to(cycle_id: Any, trace_id: Any) -> bool:
    return is_valid_id("cycle_id", cycle_id) and is_valid_id("trace_id", trace_id) and cycle_id.startswith(trace_id + ":e")


def new_audit_key() -> bytes:
    return secrets.token_bytes(32)


def keyed_digest(key: bytes, value: Any) -> str:
    if type(value) is not str:
        value = json.dumps(value, sort_keys=True, ensure_ascii=True, default=lambda o: type(o).__name__)
    return hmac.new(key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:24]


def _id(key: bytes, kind: str, value: Any, known: Any = None) -> str:
    """Keep ``value`` only if it matches its grammar, is not token-shaped, and
    (when ``known`` is given) was issued by Edge/the broker this cycle."""
    if (
        is_valid_id(kind, value)
        and (kind == "digest" or not contains_token_like(value))
        and (known is None or value in known)
    ):
        return value
    return "h:" + keyed_digest(key, value)


def _ids(key: bytes, kind: str, values: Any, known: Any = None) -> list[str]:
    return [_id(key, kind, v, known) for v in list(values or ())[:_LIST_CAP]]


def _code(key: bytes, value: Any) -> str:
    """Closed-vocabulary error/reason code. ``prefix:free-text`` keeps the prefix
    and digests the rest, because the suffix may echo model or attacker text."""
    if type(value) is not str:
        return "h:" + keyed_digest(key, value)
    head, sep, tail = value.partition(":")
    if not is_valid_id("code", head):
        return "h:" + keyed_digest(key, value)
    return head + (":h:" + keyed_digest(key, tail) if sep else "")


def _text_ref(key: bytes, value: Any) -> dict[str, Any]:
    text = value if type(value) is str else ""
    return {"digest": keyed_digest(key, text), "chars": len(text)}


# --- per-cycle working memory -------------------------------------------------


class WorkingMemoryExpired(RuntimeError):
    pass


class CycleWorkingMemory:
    """Ephemeral per-cycle scratch space bound to one coordinator ticket.

    * namespace: one instance per ``cycle_id``; keys are never shared across cycles
    * bounded: ``max_items`` keys and ``max_bytes`` of JSON-encoded values
    * expiry: deterministic, no wall clock. The memory is cleared and refuses all
      access once (a) the ticket is no longer current in the coordinator
      (accepted, superseded, cancelled, abandoned on restart), (b) ``tick()`` has
      been called ``max_steps`` times (logical timeout), or (c) ``close()``.
    * restart: never serialized. ``ReasoningCoordinator.snapshot`` does not see
      it, so a restored coordinator starts every cycle with empty memory.
    """

    def __init__(self, coordinator: ReasoningCoordinator, ticket: CycleTicket, *, max_items: int = 32, max_bytes: int = 16384, max_steps: int = 64):
        self._coord = coordinator
        self.ticket = ticket
        self._max_items = max(1, int(max_items))
        self._max_bytes = max(1, int(max_bytes))
        self._max_steps = max(1, int(max_steps))
        self._steps = 0
        self._items: dict[str, bytes] = {}
        self._closed_reason = ""
        self._lock = threading.Lock()

    @property
    def expired_reason(self) -> str:
        self._check()
        return self._closed_reason

    def _expire(self, reason: str) -> None:
        if not self._closed_reason:
            self._closed_reason = reason
        self._items.clear()

    def _check(self) -> None:
        if not self._closed_reason:
            if self._steps >= self._max_steps:
                self._expire("step_budget_exhausted")
            elif not self._coord.is_current(self.ticket):
                self._expire("cycle_not_current")

    def _live(self) -> None:
        self._check()
        if self._closed_reason:
            raise WorkingMemoryExpired(self._closed_reason)

    def tick(self) -> None:
        with self._lock:
            self._steps += 1
            self._check()

    def put(self, name: str, value: Any) -> None:
        with self._lock:
            self._live()
            if type(name) is not str or not is_valid_id("code", name):
                raise ValueError("invalid_working_memory_key")
            encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode("ascii")
            others = sum(len(v) for k, v in self._items.items() if k != name)
            if name not in self._items and len(self._items) >= self._max_items:
                raise ValueError("working_memory_item_limit")
            if others + len(encoded) > self._max_bytes:
                raise ValueError("working_memory_byte_limit")
            self._items[name] = encoded

    def get(self, name: str, default: Any = None) -> Any:
        with self._lock:
            self._live()
            raw = self._items.get(name)
            return default if raw is None else json.loads(raw)

    def close(self, reason: str = "closed") -> None:
        with self._lock:
            self._expire(reason)

    def __len__(self) -> int:
        with self._lock:
            self._check()
            return len(self._items)


# --- deterministic minimized projection ---------------------------------------


def _event_payloads(trace: Any, kind: str) -> list[Mapping[str, Any]]:
    out = []
    for ev in trace or ():
        if getattr(ev, "kind", None) == kind and isinstance(getattr(ev, "payload", None), Mapping):
            out.append(ev.payload)
    return out


def project_outcome(
    *,
    ticket: CycleTicket,
    outcome: Any,
    key: bytes,
    frame: MioSituationFrame | None = None,
    edge_decision_ref: str | None = None,
    cycle_status: str = "",
) -> dict[str, Any]:
    """Pure, deterministic minimized audit record for one finished cycle.

    Same inputs and key give the same record. No free text survives; see the
    module docstring. ``edge_decision_ref`` must be a valid Edge decision ref
    (``edge-dec:...``) supplied by Edge; a M.I.O. advisory ID is rejected.
    """
    if edge_decision_ref is not None:
        require_id(EDGE_DECISION_REF, edge_decision_ref)
    k = key
    provenance = (_event_payloads(outcome.trace, "reasoning_provenance") or [{}])[0]
    requests = _event_payloads(outcome.trace, "capability_request")
    results = {p.get("request_id"): p for p in _event_payloads(outcome.trace, "capability_result")}
    # Evidence refs survive verbatim only if Edge (frame) or the broker issued
    # them this cycle; a model-invented ref is recorded as a digest.
    known: set[str] | None = None
    if frame is not None:
        known = set(frame.evidence_refs) | set(frame.knowledge_refs)
        for p in results.values():
            if p.get("ok") is True:
                known.update(r for r in p.get("evidence_refs") or () if type(r) is str)
    broker = []
    for req in requests[:_LIST_CAP]:
        res = results.get(req.get("request_id"))
        broker.append({
            "request_id": _id(k, "request_id", req.get("request_id")),
            "capability": _id(k, "code", req.get("capability")),
            "result": "missing" if res is None else ("ok" if res.get("ok") is True else "not_ok"),
            "evidence_refs": _ids(k, "evidence_ref", (res or {}).get("evidence_refs"), known),
        })
    rec = outcome.recommendation
    record: dict[str, Any] = {
        "schema": TRACE_AUDIT_SCHEMA,
        "trace_id": _id(k, "trace_id", ticket.trace_id),
        "cycle_id": _id(k, "cycle_id", ticket.cycle_id),
        "epoch": ticket.epoch if type(ticket.epoch) is int else -1,
        "frame_id": _id(k, "frame_id", ticket.frame_id),
        "frame_material_digest": _id(k, "digest", ticket.material_digest),
        "frame_digest": None if frame is None else material_frame_digest(frame),
        "cycle_status": _code(k, cycle_status) if cycle_status else "",
        "terminal_state": _code(k, getattr(outcome.state, "value", outcome.state)),
        "errors": [_code(k, e) for e in list(outcome.errors)[:_LIST_CAP]],
        "playbook": {
            "playbook_id": _id(k, "frame_id", provenance.get("playbook_id")),
            "playbook_version": _id(k, "frame_id", provenance.get("playbook_version")),
            "playbook_digest": _id(k, "digest", provenance.get("playbook_digest")),
            "template_id": _id(k, "frame_id", provenance.get("template_id")),
        },
        "hypotheses": [
            {
                "hypothesis_id": _id(k, "hypothesis_id", h.hypothesis_id),
                "status": _code(k, getattr(h.status, "value", h.status)),
                "statement": _text_ref(k, h.statement),
                "supporting_evidence_refs": _ids(k, "evidence_ref", h.supporting_evidence_refs, known),
                "contradicting_evidence_refs": _ids(k, "evidence_ref", h.contradicting_evidence_refs, known),
            }
            for h in list(outcome.hypotheses)[:_LIST_CAP]
        ],
        "hypothesis_audit": [
            {
                "hypothesis_id": _id(k, "hypothesis_id", e.hypothesis_id),
                "from_status": _code(k, e.from_status) if e.from_status else "",
                "to_status": _code(k, e.to_status),
                "reason": _code(k, e.reason),
                "evidence_refs": _ids(k, "evidence_ref", e.evidence_refs, known),
            }
            for e in list(outcome.hypothesis_audit)[:_LIST_CAP]
        ],
        "evidence_gap_count": len(outcome.evidence_gaps),
        "broker": broker,
        "recommendation": None if rec is None else {
            "advisory_id": _id(k, "advisory_id", rec.advisory_id),
            "recommended_action": _id(k, "code", rec.recommended_action.lower()),
            "evidence_refs": _ids(k, "evidence_ref", rec.evidence_refs, known),
            "summary": _text_ref(k, rec.summary),
            "rationale": _text_ref(k, rec.rationale),
            "executable": False,
        },
        "handoff_digest": None if outcome.handoff is None else outcome.handoff.canonical_digest(),
        "edge_decision_ref": edge_decision_ref,
        "authority": "advisory_only",
    }
    return _fit(record)


def _fit(record: dict[str, Any]) -> dict[str, Any]:
    """Bound the encoded size deterministically by trimming list fields."""
    for name in ("hypothesis_audit", "broker", "hypotheses", "errors"):
        if len(encode_record(record)) <= MAX_RECORD_BYTES:
            break
        dropped = len(record[name])
        record[name] = record[name][:2]
        record["truncated_" + name] = dropped - len(record[name])
    if len(encode_record(record)) > MAX_RECORD_BYTES:
        raise ValueError("trace_audit_record_too_large")
    return record


def encode_record(record: Mapping[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


# --- durable append-only sink with retention / quota --------------------------


class AuditFS(Protocol):
    def size(self, path: str) -> int: ...
    def append_fsync(self, path: str, data: bytes) -> None: ...
    def rename(self, src: str, dst: str) -> None: ...
    def remove(self, path: str) -> None: ...
    def exists(self, path: str) -> bool: ...


class OsAuditFS:
    def size(self, path: str) -> int:
        try:
            return os.path.getsize(path)
        except FileNotFoundError:
            return 0

    def append_fsync(self, path: str, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)

    def rename(self, src: str, dst: str) -> None:
        os.replace(src, dst)

    def remove(self, path: str) -> None:
        os.remove(path)

    def exists(self, path: str) -> bool:
        return os.path.exists(path)


@dataclass
class AppendResult:
    written: bool
    reason: str


@dataclass
class TraceAuditSink:
    """Append-only JSONL with fsync, size rotation and a total quota.

    Retention: the active file rotates at ``max_file_bytes`` into ``.1`` ...
    ``.{max_files-1}``; the oldest rotated file is deleted. Total on-disk use is
    therefore bounded by ``max_file_bytes * max_files``.

    Failure (rotation/delete/write/fsync error, ENOSPC/EDQUOT, oversize record):
    the record is not written, ``dropped`` and ``drop_reasons`` count it, and the
    sink becomes *degraded*. While degraded, ``advisory_allowed()`` is False:
    the caller must not publish a M.I.O. advisory whose audit was not durable
    (fail-closed for the advisory path). The sink never raises to its caller and
    never blocks: the deterministic Edge path does not call it at all.
    ``reset_degraded()`` is an explicit operator action after the cause is fixed.
    """

    path: str
    max_file_bytes: int = 1 << 20
    max_files: int = 4
    fs: AuditFS = field(default_factory=OsAuditFS)
    dropped: int = 0
    written: int = 0
    degraded_reason: str = ""
    drop_reasons: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        if self.max_file_bytes < MAX_RECORD_BYTES or self.max_files < 1:
            raise ValueError("invalid_trace_audit_retention")

    def advisory_allowed(self) -> bool:
        return not self.degraded_reason

    def reset_degraded(self) -> None:
        with self._lock:
            self.degraded_reason = ""

    def _drop(self, reason: str) -> AppendResult:
        self.dropped += 1
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + 1
        if not self.degraded_reason:
            self.degraded_reason = reason
        return AppendResult(False, reason)

    def _rotate(self) -> None:
        oldest = f"{self.path}.{self.max_files - 1}" if self.max_files > 1 else self.path
        if self.fs.exists(oldest):
            self.fs.remove(oldest)
        for i in range(self.max_files - 2, 0, -1):
            src = f"{self.path}.{i}"
            if self.fs.exists(src):
                self.fs.rename(src, f"{self.path}.{i + 1}")
        if self.max_files > 1 and self.fs.exists(self.path):
            self.fs.rename(self.path, f"{self.path}.1")

    def append(self, record: Mapping[str, Any]) -> AppendResult:
        with self._lock:
            try:
                data = encode_record(record)
            except (TypeError, ValueError):
                return self._drop("unencodable_record")
            if len(data) > MAX_RECORD_BYTES:
                return self._drop("record_too_large")
            try:
                if self.fs.size(self.path) + len(data) > self.max_file_bytes:
                    self._rotate()
            except OSError as exc:
                return self._drop(_os_reason("rotation_failed", exc))
            try:
                self.fs.append_fsync(self.path, data)
            except OSError as exc:
                return self._drop(_os_reason("append_failed", exc))
            self.written += 1
            return AppendResult(True, "written")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {"written": self.written, "dropped": self.dropped, "drop_reasons": dict(self.drop_reasons), "degraded_reason": self.degraded_reason, "advisory_allowed": not self.degraded_reason}


def _os_reason(prefix: str, exc: OSError) -> str:
    name = {errno.ENOSPC: "enospc", getattr(errno, "EDQUOT", -1): "edquot", errno.EROFS: "erofs", errno.EACCES: "eacces"}.get(exc.errno or 0, "oserror")
    return f"{prefix}:{name}"


def record_cycle(sink: TraceAuditSink, projection: Callable[[], Mapping[str, Any]]) -> bool:
    """Project and append; return whether the advisory may be published.

    Any projection or sink failure returns False (advisory withheld). Never raises.
    """
    try:
        record = projection()
    except Exception:  # projection failure must not escape into callers
        with sink._lock:
            sink._drop("projection_failed")
        return False
    return sink.append(record).written and sink.advisory_allowed()
