"""Read-only incident export of the M.I.O. trace audit (#389).

``export_incident`` collects the ``mio.trace_audit`` records of one trace from
the active file and its rotated files (oldest first) and returns them as one
JSON document. It never writes, renames, locks or truncates anything, and it
needs no key.

Allowlist, not masking: every record is checked field by field against the
shape ``project_outcome`` writes (IDs that match their grammar or are
``h:<digest>``, closed-vocabulary codes, hex digests, counts, ``{digest,
chars}`` text references). A record with any other field or value is not
exported, only counted as ``invalid``, so text that was put in the file by
hand or by a bug is not echoed. The records themselves hold no free text, no
key and no address outside IDs and evidence refs.
"""
from __future__ import annotations

from collections import deque
import errno
import json
import os
import re
import stat
from typing import Any, Callable, Mapping

from .redaction import contains_token_like
from .trace_audit import DIGEST_KEY_STATES, TRACE_AUDIT_SCHEMAS, MAX_RECORD_BYTES, is_valid_id
from .trace_recorder import has_symlink_parent

EXPORT_SCHEMA = "mio.trace_audit_export.v1"
MAX_FILE_BYTES = 64 << 20
MAX_LIMIT = 1024
_LIST_CAP = 16
_H = re.compile(r"h:[0-9a-f]{24}")
_CODE_H = re.compile(r"[a-z][a-z0-9_.]{0,63}:h:[0-9a-f]{24}")
_HEX64 = re.compile(r"[0-9a-f]{64}")


class _Invalid(Exception):
    pass


def _check(ok: bool) -> None:
    if not ok:
        raise _Invalid()


def _id(kind: str) -> Callable[[Any], None]:
    def check(v: Any) -> None:
        _check(type(v) is str and (_H.fullmatch(v) is not None or (is_valid_id(kind, v) and (kind == "digest" or not contains_token_like(v)))))
    return check


def _code(v: Any) -> None:
    _check(type(v) is str and (is_valid_id("code", v) or _CODE_H.fullmatch(v) is not None or _H.fullmatch(v) is not None))


def _code_or_empty(v: Any) -> None:
    if v != "":
        _code(v)


def _int(v: Any) -> None:
    _check(type(v) is int and -1 <= v < (1 << 53))


def _hex64_or_none(v: Any) -> None:
    _check(v is None or (type(v) is str and _HEX64.fullmatch(v) is not None))


def _text_ref(v: Any) -> None:
    _check(isinstance(v, dict) and set(v) == {"digest", "chars"})
    _check(type(v["digest"]) is str and re.fullmatch(r"[0-9a-f]{24}", v["digest"]) is not None)
    _check(type(v["chars"]) is int and 0 <= v["chars"] < (1 << 31))


def _list(item: Callable[[Any], None]) -> Callable[[Any], None]:
    def check(v: Any) -> None:
        _check(isinstance(v, list) and len(v) <= _LIST_CAP)
        for x in v:
            item(x)
    return check


def _obj(fields: Mapping[str, Callable[[Any], None]], optional: Mapping[str, Callable[[Any], None]] | None = None) -> Callable[[Any], None]:
    optional = optional or {}

    def check(v: Any) -> None:
        _check(isinstance(v, dict) and set(fields) <= set(v) <= set(fields) | set(optional))
        for name, item in fields.items():
            item(v[name])
        for name, item in optional.items():
            if name in v:
                item(v[name])
    return check


def _const(*values: Any) -> Callable[[Any], None]:
    def check(v: Any) -> None:
        _check(any(type(v) is type(c) and v == c for c in values))
    return check


def _edge_ref(v: Any) -> None:
    _check(v is None or is_valid_id("edge_decision_ref", v))


_REFS = _list(_id("evidence_ref"))
_RECOMMENDATION = _obj({
    "advisory_id": _id("advisory_id"),
    "recommended_action": _id("code"),
    "evidence_refs": _REFS,
    "summary": _text_ref,
    "rationale": _text_ref,
    "executable": _const(False),
})
_RECORD = _obj(
    {
        "schema": _const(*sorted(TRACE_AUDIT_SCHEMAS)),
        "trace_id": _id("trace_id"),
        "cycle_id": _id("cycle_id"),
        "epoch": _int,
        "frame_id": _id("frame_id"),
        "frame_material_digest": _id("digest"),
        "frame_digest": _hex64_or_none,
        "cycle_status": _code_or_empty,
        "terminal_state": _code,
        "errors": _list(_code),
        "playbook": _obj({k: _id(kind) for k, kind in (("playbook_id", "frame_id"), ("playbook_version", "frame_id"), ("playbook_digest", "digest"), ("template_id", "frame_id"))}),
        "hypotheses": _list(_obj({
            "hypothesis_id": _id("hypothesis_id"),
            "status": _code,
            "statement": _text_ref,
            "supporting_evidence_refs": _REFS,
            "contradicting_evidence_refs": _REFS,
        })),
        "hypothesis_audit": _list(_obj({
            "hypothesis_id": _id("hypothesis_id"),
            "from_status": _code_or_empty,
            "to_status": _code,
            "reason": _code,
            "evidence_refs": _REFS,
        })),
        "evidence_gap_count": _int,
        "broker": _list(_obj({
            "request_id": _id("request_id"),
            "capability": _id("code"),
            "result": _const("missing", "ok", "not_ok"),
            "evidence_refs": _REFS,
        })),
        "recommendation": lambda v: None if v is None else _RECOMMENDATION(v),
        "handoff_digest": _hex64_or_none,
        "edge_decision_ref": _edge_ref,
        "authority": _const("advisory_only"),
    },
    {
        "digest_key": _const(*sorted(DIGEST_KEY_STATES)),
        **{f"truncated_{n}": _int for n in ("hypothesis_audit", "broker", "hypotheses", "errors")},
    },
)


def valid_record(record: Any) -> bool:
    """Whether ``record`` has exactly the allowlisted shape.

    ``digest_key`` is required in v2 and absent in v1.
    """
    try:
        _RECORD(record)
    except _Invalid:
        return False
    if record["schema"] == "mio.trace_audit.v1":
        return "digest_key" not in record
    return "digest_key" in record


def valid_trace_selector(kind: str, value: str) -> bool:
    try:
        _id(kind)(value)
    except _Invalid:
        return False
    return True


def _open_readonly(path: str) -> tuple[int | None, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        return None, {errno.ELOOP: "refused:symlink", errno.EACCES: "refused:eacces", errno.EPERM: "refused:eperm"}.get(exc.errno or 0, "refused:oserror")
    try:
        st = os.fstat(fd)
    except OSError:
        os.close(fd)
        return None, "refused:oserror"
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        return None, "refused:not_regular"
    if st.st_size > MAX_FILE_BYTES:
        os.close(fd)
        return None, "refused:too_large"
    return fd, "read"


def export_incident(path: str, *, trace_id: str, max_files: int = 4, cycle_id: str | None = None, limit: int = 256) -> dict[str, Any]:
    """Records of ``trace_id`` (optionally one ``cycle_id``), oldest first.

    At most ``limit`` records are returned (the newest ones); ``omitted``
    counts the rest. Raises ``ValueError`` only for invalid arguments.
    """
    if not valid_trace_selector("trace_id", trace_id):
        raise ValueError("invalid_trace_id")
    if cycle_id is not None and not valid_trace_selector("cycle_id", cycle_id):
        raise ValueError("invalid_cycle_id")
    if type(max_files) is not int or not 1 <= max_files <= 64:
        raise ValueError("invalid_max_files")
    if type(limit) is not int or not 1 <= limit <= MAX_LIMIT:
        raise ValueError("invalid_limit")
    names = [f"{path}.{i}" for i in range(max_files - 1, 0, -1)] + [path]
    parent_link = has_symlink_parent(path)
    kept: deque[dict[str, Any]] = deque(maxlen=limit)
    matched = 0
    skipped = {"malformed": 0, "oversize": 0, "invalid": 0}
    files = []
    for name in names:
        fd, state = (None, "refused:symlink_parent") if parent_link else _open_readonly(name)
        files.append({"name": os.path.basename(name), "state": state})
        if fd is None:
            continue
        budget = MAX_FILE_BYTES
        with os.fdopen(fd, "rb") as fh:
            while budget > 0:
                line = fh.readline(MAX_RECORD_BYTES + 2)
                if not line:
                    break
                budget -= len(line)
                if len(line) > MAX_RECORD_BYTES:
                    skipped["oversize"] += 1
                    while line and not line.endswith(b"\n") and budget > 0:  # skip the rest of that line
                        line = fh.readline(65536)
                        budget -= len(line)
                    continue
                if not line.strip():
                    continue
                try:
                    record = json.loads(line.decode("ascii"))
                except (UnicodeDecodeError, ValueError, RecursionError):
                    skipped["malformed"] += 1
                    continue
                if not valid_record(record):
                    skipped["invalid"] += 1
                    continue
                if record["trace_id"] != trace_id or (cycle_id is not None and record["cycle_id"] != cycle_id):
                    continue
                matched += 1
                kept.append(record)
    records = list(kept)
    states = [f["state"] for f in files]
    return {
        "schema": EXPORT_SCHEMA,
        "authority": "advisory_only",
        # False when no file could be read or any file was refused: then
        # "records" may lack records that exist. A missing rotated file is
        # normal (fewer rotations so far) and does not make it incomplete.
        "complete": "read" in states and not any(x.startswith("refused") for x in states),
        # "complete" is about files only. False here when a line was skipped
        # (malformed, oversize or invalid): a record of this trace may be
        # among them. The exit status of the CLI does not change for it.
        "all_lines_valid": not any(skipped.values()),
        "trace_id": trace_id,
        "cycle_id": cycle_id,
        "records": records,
        # Self-declared by each record, not a signature (see the docs).
        "digest_key_counts": {
            state: sum(1 for r in records if r.get("digest_key", "not_recorded") == state)
            for state in (*sorted(DIGEST_KEY_STATES), "not_recorded")
        },
        "omitted": matched - len(kept),
        "skipped": skipped,
        "files": files,
    }
