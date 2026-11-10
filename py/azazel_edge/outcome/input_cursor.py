"""Read-only bounded append-stream verification; no producer/control authority."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from .journal import OutcomeJournalError

DEFAULT_INPUT_BYTES = 16 * 1024 * 1024
DEFAULT_INPUT_RECORDS = 8192
MAX_LINE_BYTES = 65536
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class InputLine:
    raw: bytes
    position: dict


class BoundedInput:
    """One pinned regular input; rotation/repair/partial startup are refused.

    Verifies observable byte-prefix continuity, not producer authenticity or
    absence of unobserved truncation/regrowth under a hostile same-UID writer.
    The operator must supply a trusted append-only producer and parent path.
    """

    def __init__(
        self, path, *, max_bytes=DEFAULT_INPUT_BYTES, max_records=DEFAULT_INPUT_RECORDS
    ):
        path = Path(path)
        if not path.is_absolute() or ".." in path.parts:
            raise OutcomeJournalError("physical absolute input path required")
        if (
            type(max_bytes) is not int
            or not MAX_LINE_BYTES <= max_bytes <= 64 * 1024 * 1024
        ):
            raise OutcomeJournalError("invalid input byte budget")
        if type(max_records) is not int or not 1 <= max_records <= 32768:
            raise OutcomeJournalError("invalid input record budget")
        self.fd = None
        self.parent = None
        self.path = path
        self.max_bytes = max_bytes
        self.max_records = max_records
        self._candidate = None
        self._candidate_previous = None
        self._snapshot_data = self._snapshot_position = None
        try:
            self.parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            for part in path.parts[1:-1]:
                new = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=self.parent,
                )
                os.close(self.parent)
                self.parent = new
            before = os.stat(path.name, dir_fd=self.parent, follow_symlinks=False)
            self._safe(before)
            self.fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=self.parent,
            )
            info = os.fstat(self.fd)
            self._safe(info)
            self.config = dict(
                path_sha256=hashlib.sha256(str(path).encode()).hexdigest(),
                device=info.st_dev,
                inode=info.st_ino,
                uid=info.st_uid,
                max_bytes=max_bytes,
                max_records=max_records,
            )
            self._namespace()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _safe(info):
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022
        ):
            raise OutcomeJournalError(
                "input must be a trusted single-link regular file without group/world write"
            )

    def _namespace(self):
        if self.fd is None:
            raise OutcomeJournalError("input closed")
        info = os.stat(self.path.name, dir_fd=self.parent, follow_symlinks=False)
        self._safe(info)
        if (info.st_dev, info.st_ino, info.st_uid) != (
            self.config["device"],
            self.config["inode"],
            self.config["uid"],
        ):
            raise OutcomeJournalError("input path identity changed")
        self._safe(os.fstat(self.fd))
        if info.st_size > self.max_bytes:
            raise OutcomeJournalError("input byte budget exhausted")
        return info.st_size

    @staticmethod
    def position(value):
        if (
            type(value) is not dict
            or set(value) != {"offset", "sha256"}
            or type(value["offset"]) is not int
            or value["offset"] < 0
            or type(value["sha256"]) is not str
            or len(value["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in value["sha256"])
        ):
            raise OutcomeJournalError("invalid input position")
        return dict(value)

    def _read(self, size):
        value = bytearray()
        while len(value) < size:
            part = os.pread(self.fd, min(65536, size - len(value)), len(value))
            if not part:
                raise OutcomeJournalError("input truncated during verification")
            value.extend(part)
        return bytes(value)

    def snapshot(self, position, *, require_complete=False):
        position = self.position(position)
        size = self._namespace()
        if position["offset"] > size:
            raise OutcomeJournalError("input behind durable position")
        data = self._read(size)
        if data.count(b"\n") > self.max_records:
            raise OutcomeJournalError("input record budget exhausted")
        if self._namespace() < size or self._read(size) != data:
            raise OutcomeJournalError("input changed during verification")
        offset = position["offset"]
        if hashlib.sha256(data[:offset]).hexdigest() != position["sha256"] or (
            offset and data[offset - 1 : offset] != b"\n"
        ):
            raise OutcomeJournalError("input prefix continuity unavailable")
        end = data.rfind(b"\n") + 1
        if require_complete and end != size:
            raise OutcomeJournalError("incomplete input tail; automatic resume refused")
        if size - end > MAX_LINE_BYTES:
            raise OutcomeJournalError("oversized incomplete input record")
        self._candidate = None
        self._snapshot_data = data[:end]
        self._snapshot_position = dict(position)
        return self._snapshot_data

    def lines(self, position, data):
        if data is not self._snapshot_data or position != self._snapshot_position:
            raise OutcomeJournalError(
                "lines require the current verified input snapshot"
            )
        offset = position["offset"]
        digest = hashlib.sha256(data[:offset])
        for raw in data[offset:].splitlines(keepends=True):
            if data is not self._snapshot_data:
                raise OutcomeJournalError(
                    "input snapshot superseded before cursor advance"
                )
            if not raw.endswith(b"\n") or len(raw) > MAX_LINE_BYTES:
                raise OutcomeJournalError("invalid bounded input record")
            self._candidate_previous = dict(offset=offset, sha256=digest.hexdigest())
            offset += len(raw)
            digest.update(raw)
            self._candidate = dict(offset=offset, sha256=digest.hexdigest())
            yield InputLine(raw=raw, position=dict(self._candidate))

    def validate_candidate(self, previous, candidate):
        self.position(candidate)
        self._namespace()
        if candidate != self._candidate or previous != self._candidate_previous:
            raise OutcomeJournalError("position was not read from verified input")

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent is not None:
            os.close(self.parent)
            self.parent = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
