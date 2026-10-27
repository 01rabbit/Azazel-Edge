"""Read-only decision-level trace for the Web UI (Edge#341).

Joins, per core decision, the two records that already exist for it:

* the v2 decision explanation the AI agent writes
  (``decision-explanations.jsonl`` and, after a rotation, ``.1``; Edge#477),
  keyed by ``trace_id``;
* the ``action_decision`` record of the core decision chain
  (``core-decision-audit.jsonl`` and ``.1``; P0 decisions only), whose
  ``trace_id`` is the same (``core_decisions.core_decision_payload``).

The explanation fields and the chain verdict are the ones
``azazel-edge-audit-review --json`` prints (:func:`audit_review.record_review`,
:func:`audit_review.verify_audit_chain`, :func:`audit_review.chain_review`),
so the Web UI and the CLI never disagree about a record.

Never fabricated: a trace exists only for a decision. An alert row of the AI
event log has a decision trace id only when its event is a core decision
event (:func:`alert_decision_trace_id`, the same function the agent uses to
name the decision); every other alert has none and nothing is looked up for
it. Several alerts of one decision (the same EVE line delivered twice) share
one trace. What is not there is said, never filled in:

* explanation ``not_found``: no explanation with that ``trace_id`` in the
  retained files (``.1`` present: older ones may have been rotated out);
* chain record ``not_found``: the chain holds P0 decisions only, and records
  rotated out of the retained files are gone;
* ``segment`` ``rotated``: the record is in the older file (``.1``);
* chain ``integrity``: ``verified`` only when the whole retained chain
  verifies as ``audit_review`` verifies it; ``failed_here`` for the record
  where verification failed (rewritten, removed or reordered before it);
  ``not_verified`` otherwise (the chain failed elsewhere, or it could not be
  read);
* a source that is missing or unreadable is ``missing`` / ``unreadable``,
  never an empty success.

Read only: files are opened ``O_RDONLY`` (no symlink is followed), nothing is
written, decided, enforced or notified. Indexes are kept in memory (byte
offsets only) and refreshed when a file changes: the explanation files
incrementally while they grow, the chain (re)verified whenever any of its
files changes.
"""

from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from azazel_edge import audit_review
from azazel_edge.audit.segments import MAX_SEGMENTS, segment_path
from azazel_edge.notify.core_decisions import core_decision_payload

FORMAT = "azazel-edge/decision-trace/v1"
# At most this many decisions per request (the dashboard asks for the
# decisions of the alerts it shows).
MAX_TRACE_IDS = 16
TRACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CHAIN_KIND = "action_decision"
NOT_APPLIED_PREFIX = "NOT APPLIED"
SEGMENT_ACTIVE = "active"
SEGMENT_ROTATED = "rotated"
# An explanation file is rotated at 8 MiB (explanations.live); a larger one
# is indexed from its newest bytes only (``truncated``).
MAX_INDEX_BYTES = 32 * 1024 * 1024

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_FAIL_AT = re.compile(r"^(?:chain_hash_mismatch|chain_prev_mismatch|chain_id_mismatch|parse_error)_at:(\d+)$")

# Fields of a chain record that are shown. Not copied: the core event key,
# the core's own trace id, the target address and the agent's receive stamps.
_CHAIN_FIELDS = (
    "ts", "kind", "trace_id", "action", "decided_action", "effective_action", "enforcement_mode",
    "enforcement_result", "enforce_dry_run", "recorded_by", "reconcile_stale", "event_ts", "sid", "severity",
)

LIMITS = (
    "read only; a trace is shown only for a core decision, never per alert. The explanation file is not"
    " hash-chained and its trust capsule is not verified here; the core decision chain holds P0 decisions"
    " only, its hashes are not keyed (see chain.limits), and records rotated out of the retained files are gone."
)


def valid_trace_id(value: Any) -> bool:
    return isinstance(value, str) and bool(TRACE_ID_RE.match(value))


def alert_decision_trace_id(row: Any) -> str:
    """The decision trace id of one AI event log row (``{"event", "advisory"}``),
    or '' when its event is not a core decision event. The same id the agent
    gives the decision's explanation and chain record."""

    event = row.get("event") if isinstance(row, Mapping) else None
    if not isinstance(event, Mapping):
        return ""
    try:
        built = core_decision_payload(event)
    except Exception:
        return ""
    return built[0] if built else ""


def _open(path: Path) -> Optional[int]:
    try:
        return os.open(str(path), os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
    except FileNotFoundError:
        return None


def _pread_all(fd: int, start: int, length: int) -> bytes:
    chunks = []
    offset = start
    remaining = length
    while remaining > 0:
        chunk = os.pread(fd, min(remaining, 1 << 20), offset)
        if not chunk:
            break
        chunks.append(chunk)
        offset += len(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_line(path: Path, key: Tuple[int, int], offset: int, length: int) -> Optional[Dict[str, Any]]:
    """The JSON object at ``offset`` of ``path`` if the file is still the one
    indexed (same device and inode), else None."""

    fd = _open(path)
    if fd is None:
        return None
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != key or st.st_size < offset + length:
            return None
        raw = os.pread(fd, length, offset)
    finally:
        os.close(fd)
    try:
        row = json.loads(raw)
    except Exception:
        return None
    return row if isinstance(row, dict) else None


class _ExplanationFile:
    """trace_id -> (count, offset, length of the newest line) of one JSONL file,
    indexed incrementally while the file grows."""

    def __init__(self, path: Path):
        self.path = path
        self.key: Optional[Tuple[int, int]] = None
        self.offset = 0
        self.entries: Dict[str, Tuple[int, int, int]] = {}
        self.unparsed = 0
        self.truncated = False
        self._skip_partial = False

    def _reset(self, key: Optional[Tuple[int, int]]) -> None:
        self.key = key
        self.offset = 0
        self.entries = {}
        self.unparsed = 0
        self.truncated = False
        self._skip_partial = False

    def refresh(self) -> str:
        """'present' or 'missing'; an unreadable file raises OSError."""

        fd = _open(self.path)
        if fd is None:
            self._reset(None)
            return "missing"
        try:
            st = os.fstat(fd)
            key = (st.st_dev, st.st_ino)
            if key != self.key or st.st_size < self.offset:
                self._reset(key)
                if st.st_size > MAX_INDEX_BYTES:
                    self.offset = st.st_size - MAX_INDEX_BYTES
                    self.truncated = True
                    self._skip_partial = True
            if st.st_size <= self.offset:
                return "present"
            data = _pread_all(fd, self.offset, st.st_size - self.offset)
        finally:
            os.close(fd)
        end = data.rfind(b"\n")
        if end < 0:
            return "present"  # no complete line yet
        pos = self.offset
        lines = data[: end + 1].split(b"\n")[:-1]
        if self._skip_partial and lines:
            # The window started inside a line: skip it.
            self._skip_partial = False
            pos += len(lines[0]) + 1
            lines = lines[1:]
        for raw in lines:
            self._add(raw, pos)
            pos += len(raw) + 1
        self.offset += end + 1
        return "present"

    def _add(self, raw: bytes, pos: int) -> None:
        if not raw.strip():
            return
        try:
            row = json.loads(raw)
        except Exception:
            self.unparsed += 1
            return
        if not isinstance(row, dict):
            self.unparsed += 1
            return
        tid = row.get("trace_id")
        if not valid_trace_id(tid):
            return
        count = self.entries.get(tid, (0, 0, 0))[0]
        self.entries[tid] = (count + 1, pos, len(raw))

    def lookup(self, trace_id: str) -> Tuple[int, Optional[Dict[str, Any]]]:
        entry = self.entries.get(trace_id)
        if entry is None or self.key is None:
            return 0, None
        count, offset, length = entry
        row = _read_line(self.path, self.key, offset, length)
        if row is None or row.get("trace_id") != trace_id:
            return count, None
        return count, row


class _ChainIndex:
    """The core decision chain's verdict (``audit_review.verify_audit_chain``)
    and trace_id -> [(position, file, offset, length)] of its
    ``action_decision`` records, rebuilt whenever a file of the chain changes."""

    def __init__(self, path: Path):
        self.path = path
        self.signature: Any = None
        self.state = "missing"
        self.verdict: Dict[str, Any] = {}
        self.entries: Dict[str, List[Tuple[int, str, Tuple[int, int], int, int]]] = {}

    def _signature(self) -> Tuple[Any, ...]:
        sig = []
        for p in [self.path] + [segment_path(self.path, n) for n in range(1, MAX_SEGMENTS + 1)]:
            try:
                st = os.stat(str(p), follow_symlinks=False)
            except (FileNotFoundError, NotADirectoryError):
                if p != self.path:
                    break
                sig.append(None)
                continue
            sig.append((st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns))
        return tuple(sig)

    def refresh(self) -> None:
        try:
            sig = self._signature()
        except OSError as exc:
            self._unreadable(exc)
            return
        if sig == self.signature:
            return
        for _ in range(3):
            try:
                before = self._signature()
                verdict = audit_review.verify_audit_chain(self.path)
                entries = self._index([str(name) for name in verdict.get("files") or []])
                after = self._signature()
            except Exception as exc:  # OSError (permission) and anything unexpected: never a success
                self._unreadable(exc)
                return
            if before == after:
                break
        else:
            verdict = dict(verdict, ok=False, verified=False, scope=audit_review.SCOPE_NOT_VERIFIED,
                           error="snapshot_inconsistent:rotation_kept_moving_files")
        self.signature = after
        self.verdict = verdict
        self.entries = entries
        self.state = "missing" if verdict.get("scope") == audit_review.SCOPE_EMPTY and not verdict.get("files") else "present"

    def _unreadable(self, exc: BaseException) -> None:
        self.signature = None
        self.state = "unreadable"
        self.verdict = {
            "ok": False, "verified": False, "entries": 0, "scope": audit_review.SCOPE_NOT_VERIFIED,
            "error": f"unreadable:{type(exc).__name__}", "files": [], "chain_id": "",
        }
        self.entries = {}

    def _index(self, names: Iterable[str]) -> Dict[str, List[Tuple[int, str, Tuple[int, int], int, int]]]:
        entries: Dict[str, List[Tuple[int, str, Tuple[int, int], int, int]]] = {}
        position = 0
        for name in names:
            path = self.path.with_name(name)
            fd = _open(path)
            if fd is None:
                continue
            try:
                st = os.fstat(fd)
                key = (st.st_dev, st.st_ino)
                data = _pread_all(fd, 0, st.st_size)
            finally:
                os.close(fd)
            offset = 0
            for raw in data.split(b"\n")[:-1]:  # complete lines, as read_chain counts them
                position += 1
                if b'"' + CHAIN_KIND.encode() + b'"' in raw:
                    try:
                        row = json.loads(raw)
                    except Exception:
                        row = None
                    if isinstance(row, dict) and row.get("kind") == CHAIN_KIND and valid_trace_id(row.get("trace_id")):
                        entries.setdefault(row["trace_id"], []).append((position, name, key, offset, len(raw)))
                offset += len(raw) + 1
        return entries

    def lookup(self, trace_id: str) -> Tuple[int, Optional[Dict[str, Any]], Optional[Tuple[int, str]]]:
        found = self.entries.get(trace_id) or []
        if not found:
            return 0, None, None
        position, name, key, offset, length = found[-1]
        row = _read_line(self.path.with_name(name), key, offset, length)
        if row is None or row.get("trace_id") != trace_id:
            return len(found), None, (position, name)
        return len(found), row, (position, name)


_LOCK = threading.Lock()
_EXPLANATIONS: Dict[str, Tuple[_ExplanationFile, _ExplanationFile]] = {}
_CHAINS: Dict[str, _ChainIndex] = {}


def reset_caches() -> None:
    """Forget every index (tests)."""

    with _LOCK:
        _EXPLANATIONS.clear()
        _CHAINS.clear()


def _integrity(verdict: Mapping[str, Any], position: int) -> str:
    if verdict.get("ok") and verdict.get("verified"):
        return "verified"
    m = _FAIL_AT.match(str(verdict.get("error") or ""))
    if m and int(m.group(1)) == position:
        return "failed_here"
    return "not_verified"


def _segment(name: str, active_name: str) -> str:
    return SEGMENT_ACTIVE if name == active_name else SEGMENT_ROTATED


def _explanation_view(record: Dict[str, Any], *, count: int, segment: str) -> Dict[str, Any]:
    view = dict(audit_review.record_review(record))
    machine = record.get("machine") if isinstance(record.get("machine"), dict) else {}
    arbiter = machine.get("arbiter") if isinstance(machine.get("arbiter"), dict) else {}
    release = str(record.get("release_condition") or "")
    view.update(
        status="found",
        segment=segment,
        records=count,
        reason=str(record.get("reason") or ""),
        applied_state=str(arbiter.get("applied_state") or ""),
        not_applied=release.startswith(NOT_APPLIED_PREFIX),
    )
    return view


def _chain_view(record: Dict[str, Any], *, count: int, position: int, name: str, active_name: str,
                verdict: Mapping[str, Any]) -> Dict[str, Any]:
    view: Dict[str, Any] = {key: record[key] for key in _CHAIN_FIELDS if key in record}
    view.update(
        status="found",
        segment=_segment(name, active_name),
        file=name,
        position=position,
        records=count,
        integrity=_integrity(verdict, position),
    )
    return view


def trace_report(
    trace_ids: Iterable[str],
    *,
    explanations_path: str | Path,
    audit_path: str | Path,
) -> Dict[str, Any]:
    """The decision traces of ``trace_ids`` (deduplicated, in order, at most
    :data:`MAX_TRACE_IDS`; invalid ids raise ValueError). Read only."""

    ids: List[str] = []
    for tid in trace_ids:
        if not valid_trace_id(tid):
            raise ValueError("invalid_trace_id")
        if tid not in ids:
            ids.append(tid)
    if len(ids) > MAX_TRACE_IDS:
        raise ValueError("too_many_trace_ids")
    exp_path = Path(explanations_path)
    chain_path = Path(audit_path)

    with _LOCK:
        files = _EXPLANATIONS.get(str(exp_path))
        if files is None:
            files = (_ExplanationFile(exp_path), _ExplanationFile(segment_path(exp_path, 1)))
            _EXPLANATIONS[str(exp_path)] = files
        active, rotated = files
        exp_state = "missing"
        exp_error = ""
        try:
            states = [active.refresh(), rotated.refresh()]
            exp_state = "present" if "present" in states else "missing"
        except OSError as exc:
            exp_state, exp_error = "unreadable", type(exc).__name__
        chain = _CHAINS.get(str(chain_path))
        if chain is None:
            chain = _CHAINS[str(chain_path)] = _ChainIndex(chain_path)
        chain.refresh()
        verdict = dict(chain.verdict)

        traces = []
        for tid in ids:
            explanation: Dict[str, Any]
            if exp_state == "unreadable":
                explanation = {"status": "source_unreadable"}
            else:
                n_active, rec = active.lookup(tid)
                n_rotated, rec_rotated = rotated.lookup(tid)
                count = n_active + n_rotated
                if rec is not None:
                    explanation = _explanation_view(rec, count=count, segment=SEGMENT_ACTIVE)
                elif rec_rotated is not None:
                    explanation = _explanation_view(rec_rotated, count=count, segment=SEGMENT_ROTATED)
                else:
                    explanation = {
                        "status": "not_found",
                        "rotated_file_present": rotated.key is not None,
                        "note": "no explanation with this trace_id in the retained files"
                        + ("; older ones may have been rotated out" if rotated.key is not None else ""),
                    }
            chain_record: Dict[str, Any]
            if chain.state == "unreadable":
                chain_record = {"status": "source_unreadable"}
            else:
                count, row, where = chain.lookup(tid)
                if row is not None and where is not None:
                    chain_record = _chain_view(row, count=count, position=where[0], name=where[1],
                                               active_name=chain_path.name, verdict=verdict)
                elif where is not None:
                    chain_record = {"status": "changed", "note": "the record changed after it was indexed; ask again"}
                else:
                    chain_record = {
                        "status": "not_found",
                        "note": "the core decision chain holds P0 decisions only; records rotated out are not retained",
                    }
            consistency: Dict[str, Any] = {}
            if explanation.get("status") == "found" and chain_record.get("status") == "found":
                consistency["action_matches"] = (
                    str(explanation.get("selected_action") or "") == str(chain_record.get("action") or "")
                )
            traces.append({
                "trace_id": tid,
                "explanation": explanation,
                "chain_record": chain_record,
                "consistency": consistency,
            })

        return {
            "ok": True,
            "format": FORMAT,
            "read_only": True,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "sources": {
                "explanations": {
                    "state": exp_state,
                    "error": exp_error,
                    "files": [p.path.name for p in (rotated, active) if p.key is not None],
                    "unparsed_lines": active.unparsed + rotated.unparsed,
                    "truncated": bool(active.truncated or rotated.truncated),
                },
                "chain": dict(audit_review.chain_review(verdict), state=chain.state),
            },
            "traces": traces,
            "limits": LIMITS,
        }
