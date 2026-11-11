"""Local append-only experiment accounting, not a trusted runtime witness.

Every assignment is frozen before a run starts. Reopening for mutation requires
an independently retained exact head. A crash never becomes a completed run or
permission to repeat the same assignment. This module executes nothing.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

from .benefit import BenefitInputError, MAX_BYTES, _receipt, _text, manifest_digest, validate_manifest

SCHEMA = "azazel-benefit-run-ledger/v1"
ZERO = "0" * 64
MAX_LEDGER_BYTES = 32 * 1024 * 1024


def _json(value, *, maximum=None):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise BenefitInputError("invalid finite ledger JSON") from exc
    if len(raw) > (MAX_BYTES if maximum is None else maximum):
        raise BenefitInputError("ledger record exceeds byte bound")
    return raw


def _decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BenefitInputError("duplicate ledger JSON key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(BenefitInputError("non-finite ledger JSON")))
    except (ValueError, TypeError, RecursionError) as exc:
        raise BenefitInputError("invalid ledger JSON") from exc


class RunLedger:
    """One private regular file, held under an exclusive lifetime lock.

    The operator owns the local directory and must retain the head outside this
    store. Hashes detect changes against that checkpoint, not malicious owner
    compromise or coordinated rollback of the file and its checkpoint.
    """

    def __init__(self, path, *, manifest=None, expected_head=None):
        self._fd = None
        self._parent = None
        self._failed = False
        self.head_sha256 = ZERO
        self._sequence = 0
        self._size = 0
        self._runs = {}
        target = Path(path)
        self._name = target.name
        if target.name in ("", ".", ".."):
            raise BenefitInputError("ledger filename required")
        creating = manifest is not None
        if creating:
            validate_manifest(manifest)
            _json(manifest)
        elif not isinstance(expected_head, str) or len(expected_head) != 64 or any(c not in "0123456789abcdef" for c in expected_head):
            raise BenefitInputError("externally retained exact head required for reopen")
        try:
            self._parent = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            parent = os.fstat(self._parent)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
                raise BenefitInputError("ledger requires an operator-owned private directory")
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if creating:
                flags |= os.O_CREAT | os.O_EXCL
            self._fd = os.open(target.name, flags, 0o600, dir_fd=self._parent)
            info = os.fstat(self._fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise BenefitInputError("unsafe ledger file")
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BenefitInputError("experiment ledger already held") from exc
            if creating:
                self._manifest = _decode(_json(manifest))
                self._assignments = validate_manifest(self._manifest)
                self._append({"op": "freeze", "schema_version": SCHEMA, "manifest": self._manifest})
                os.fsync(self._parent)
            else:
                if info.st_size > MAX_LEDGER_BYTES:
                    raise BenefitInputError("ledger exceeds byte bound")
                raw = os.read(self._fd, MAX_LEDGER_BYTES + 1)
                if not raw or len(raw) > MAX_LEDGER_BYTES or not raw.endswith(b"\n"):
                    raise BenefitInputError("empty, oversized or incomplete ledger; no repair permitted")
                lines = raw.splitlines()
                for line in lines:
                    row = _decode(line)
                    if not isinstance(row, dict) or set(row) != {"sequence", "previous_sha256", "event", "sha256"}:
                        raise BenefitInputError("invalid ledger envelope")
                    unsigned = {k: row[k] for k in ("sequence", "previous_sha256", "event")}
                    if type(row["sequence"]) is not int or row["sequence"] != self._sequence or row["previous_sha256"] != self.head_sha256 or hashlib.sha256(_json(unsigned)).hexdigest() != row["sha256"]:
                        raise BenefitInputError("ledger chain verification failed")
                    self._apply(row["event"])
                    self.head_sha256 = row["sha256"]
                    self._sequence += 1
                self._size = len(raw)
                if self.head_sha256 != expected_head:
                    raise BenefitInputError("ledger does not match retained head; no resume")
        except BaseException:
            self.close()
            raise

    def _apply(self, event):
        if not isinstance(event, dict):
            raise BenefitInputError("invalid ledger event")
        if self._sequence == 0:
            if set(event) != {"op", "schema_version", "manifest"} or event["op"] != "freeze" or event["schema_version"] != SCHEMA:
                raise BenefitInputError("frozen manifest must be first")
            self._manifest = event["manifest"]
            self._assignments = validate_manifest(self._manifest)
            return
        if event.get("op") == "start" and set(event) == {"op", "assignment_id", "run_id"}:
            key, run_id = event["assignment_id"], _text(event["run_id"])
            if key not in self._assignments or key in self._runs or any(r["run_id"] == run_id for r in self._runs.values()):
                raise BenefitInputError("unknown, repeated assignment or run identity")
            self._runs[key] = {"run_id": run_id, "status": "running"}
        elif event.get("op") == "finish" and set(event) == {"op", "receipt"}:
            receipt = event["receipt"]
            if not isinstance(receipt, dict):
                raise BenefitInputError("receipt required")
            allowed = {"assignment_id", "run_id", "status", "horizon_verified",
                       "protected_goal_seconds", "legitimate_latency_p95_ms",
                       "legitimate_transactions", "legitimate_errors",
                       "safety_violations", "evidence_sha256"}
            if set(receipt) - allowed:
                raise BenefitInputError("receipt contains unsupported fields; retain raw evidence separately")
            key = receipt.get("assignment_id")
            previous = self._runs.get(key)
            if not previous or previous["status"] != "running" or receipt.get("run_id") != previous["run_id"]:
                raise BenefitInputError("receipt does not match an unfinished run")
            _receipt(receipt, float(self._manifest["horizon_seconds"]))
            self._runs[key] = dict(receipt)
        else:
            raise BenefitInputError("unknown ledger transition")

    def _append(self, event):
        if self._fd is None or self._failed:
            raise BenefitInputError("ledger closed or write failed; reopen against retained head")
        # Validate without publishing an in-memory transition before durability.
        old_runs = {k: dict(v) for k, v in self._runs.items()}
        self._apply(event)
        next_runs = self._runs
        self._runs = old_runs
        unsigned = {"sequence": self._sequence, "previous_sha256": self.head_sha256, "event": event}
        digest = hashlib.sha256(_json(unsigned)).hexdigest()
        raw = _json(dict(unsigned, sha256=digest)) + b"\n"
        if self._size + len(raw) > MAX_LEDGER_BYTES:
            raise BenefitInputError("ledger capacity reached; no run may start")
        try:
            info = os.fstat(self._fd)
            named = os.stat(self._name, dir_fd=self._parent, follow_symlinks=False)
            if info.st_size != self._size or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
                raise BenefitInputError("ledger file changed outside the held writer")
            os.lseek(self._fd, 0, os.SEEK_END)
            view = memoryview(raw)
            while view:
                written = os.write(self._fd, view)
                if written <= 0:
                    raise OSError("ledger write made no progress")
                view = view[written:]
            os.fsync(self._fd)
        except BaseException:
            self._failed = True
            raise
        self._runs = next_runs
        self.head_sha256 = digest
        self._sequence += 1
        self._size += len(raw)
        return digest

    @property
    def manifest(self):
        return _decode(_json(self._manifest))

    def start(self, assignment_id, run_id):
        """Commit intent before the caller starts any workload; never auto-retry."""
        return self._append({"op": "start", "assignment_id": assignment_id, "run_id": run_id})

    def finish(self, receipt):
        """Store a caller-observed receipt; no inferred safety zeros or horizon."""
        return self._append({"op": "finish", "receipt": _decode(_json(receipt))})

    def snapshot(self):
        """All assignments, including unstarted/crashed runs, stay visible."""
        if self._fd is None or self._failed:
            raise BenefitInputError("ledger unavailable after close/write failure")
        return _decode(_json({"schema_version": SCHEMA, "manifest_sha256": manifest_digest(self._manifest),
                "head_sha256": self.head_sha256,
                "assignments": [{"assignment_id": key, **self._runs.get(key, {"status": "pending"})} for key in self._assignments],
                "observations": {"manifest_sha256": manifest_digest(self._manifest),
                                 "runs": [_decode(_json(row)) for row in self._runs.values() if row["status"] != "running"]},
                "limitations": ["local accounting is not independent preregistration or source authentication",
                                "pending/running assignments have no completed receipt and remain missing in analysis",
                                "no automatic replay, reset, workload execution or runtime authority"]},
                              maximum=MAX_LEDGER_BYTES * 2 + MAX_BYTES))

    def close(self):
        for name in ("_fd", "_parent"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
