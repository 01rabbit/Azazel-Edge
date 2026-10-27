"""Port for wiring the M.I.O. trace audit into a service (#389).

Nothing starts this today: the cognitive core runs only in the offline tools
(see docs/architecture/mio-cognitive-plane.md), and running it as a resident
service is #385. This module is the port such a service will use, and it is
off by default:

* ``load_trace_audit_config`` reads a JSON file (``config/mio_trace_audit.json``
  ships with ``"enabled": false``). A missing file is the same as disabled.
* ``open_trace_audit`` returns ``None`` when disabled, so a caller does
  nothing. When enabled it opens a ``TraceAuditSink`` and loads the digest key.
* ``TraceAuditRecorder.record`` projects one finished cycle and appends it;
  it returns whether the M.I.O. advisory may be published (``record_cycle``).

The digest key (HMAC-SHA256 for ``project_outcome``) is handled like the
trust capsule key of #498, with stricter checks in addition:

* It lives in a file of its own (``/etc/azazel-edge/mio-trace-audit.key`` by
  default), written by ``installer/internal/provision_mio_trace_audit_key.sh``:
  256 random bits as hex, ``0600``, from its first byte. There is no
  environment variable for it and no built-in key.
* A key is used only when the file is a regular file (no symlink), owned by
  root or the current user, not readable by group or others, no directory on
  its path is a symlink, and it holds one
  value of at least 32 characters of ``[A-Za-z0-9._~+/=-]`` after surrounding
  whitespace is removed, with at least 8 different characters and none of the
  markers of a test or example key. Anything else is refused.
* Without a usable key the records are still written, but with a random
  per-process key and ``"digest_key": "ephemeral"``: their digests cannot be
  correlated across restarts, and the record says so. A known or test key is
  never used in place of a missing one.

The key's value is never logged, printed or put in a reason; reasons are
fixed codes.

This adds no decision or enforcement authority. The recorder only writes the
minimized advisory audit; the deterministic Edge path never calls it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import errno
import json
import os
import re
import stat
from typing import Any, Mapping

from .contracts import MioSituationFrame
from .lifecycle import CycleTicket
from .trace_audit import (
    MAX_RECORD_BYTES,
    AuditFS,
    OsAuditFS,
    TraceAuditSink,
    new_audit_key,
    project_outcome,
    record_cycle,
)

TRACE_AUDIT_CONFIG_SCHEMA = "mio.trace_audit_config.v1"
DEFAULT_KEY_FILE = "/etc/azazel-edge/mio-trace-audit.key"
_KEY_FILE_MAX_BYTES = 4096
_USABLE_KEY = re.compile(r"[A-Za-z0-9._~+/=-]{32,256}")
_MIN_DISTINCT = 8
# Markers of keys written for tests, documentation or examples. A random hex
# key from the provisioner can contain none of them ("t", "s", "x", ... are
# not hex digits).
_NOT_A_DEVICE_KEY = ("test", "example", "dummy", "sample", "changeme", "devkey", "dev-key", "not-for-devices")


def has_symlink_parent(path: str) -> bool:
    """Whether a directory on the way to ``path`` is a symlink.

    ``O_NOFOLLOW`` covers only the last component; this covers the rest. A
    missing directory is not a symlink (the file itself is then missing).
    """
    current = os.path.dirname(os.path.abspath(path))
    while True:
        try:
            if stat.S_ISLNK(os.lstat(current).st_mode):
                return True
        except OSError:
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def key_is_usable(value: str) -> bool:
    """The same rule as ``usable`` in provision_mio_trace_audit_key.sh."""
    if _USABLE_KEY.fullmatch(value) is None or len(set(value)) < _MIN_DISTINCT:
        return False
    lowered = value.lower()
    return not any(marker in lowered for marker in _NOT_A_DEVICE_KEY)


@dataclass(frozen=True)
class AuditKeyState:
    """Outcome of loading the digest key. ``reason`` is a fixed code."""

    state: str  # "persistent", "absent" or "refused"
    reason: str
    key: bytes | None = field(default=None, repr=False, compare=False)


def load_audit_key(path: str) -> AuditKeyState:
    """Read the persisted digest key; never raises, never echoes the value."""
    if not path:
        return AuditKeyState("absent", "not_configured")
    if has_symlink_parent(path):
        return AuditKeyState("refused", "symlink_parent")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return AuditKeyState("absent", "missing")
    except OSError as exc:
        return AuditKeyState("refused", "symlink" if exc.errno == errno.ELOOP else "unreadable")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return AuditKeyState("refused", "not_regular")
        if st.st_uid not in {0, os.geteuid()}:
            return AuditKeyState("refused", "owner")
        if stat.S_IMODE(st.st_mode) & 0o077:
            return AuditKeyState("refused", "mode_too_wide")
        raw = os.read(fd, _KEY_FILE_MAX_BYTES + 1)
    except OSError:
        return AuditKeyState("refused", "unreadable")
    finally:
        os.close(fd)
    if len(raw) > _KEY_FILE_MAX_BYTES:
        return AuditKeyState("refused", "too_large")
    try:
        value = raw.decode("ascii").strip(" \t\r\n\v\f")  # bash [:space:], as in the provisioner
    except UnicodeDecodeError:
        return AuditKeyState("refused", "not_usable")
    if not key_is_usable(value):
        return AuditKeyState("refused", "not_usable")
    return AuditKeyState("persistent", "loaded", value.encode("ascii"))


@dataclass(frozen=True)
class TraceAuditConfig:
    enabled: bool = False
    path: str = ""
    key_file: str = DEFAULT_KEY_FILE
    max_file_bytes: int = 1 << 20
    max_files: int = 4


_CONFIG_FIELDS = {"schema", "enabled", "path", "key_file", "max_file_bytes", "max_files"}


def parse_trace_audit_config(data: Any) -> TraceAuditConfig:
    """Validate a config mapping. Raises ``ValueError("invalid_trace_audit_config:<field>")``."""

    def bad(name: str) -> ValueError:
        return ValueError(f"invalid_trace_audit_config:{name}")

    if not isinstance(data, Mapping):
        raise bad("document")
    unknown = set(data) - _CONFIG_FIELDS
    if unknown:
        raise bad("unknown_field")
    if data.get("schema") != TRACE_AUDIT_CONFIG_SCHEMA:
        raise bad("schema")
    enabled = data.get("enabled", False)
    if type(enabled) is not bool:
        raise bad("enabled")
    path = data.get("path", "")
    key_file = data.get("key_file", DEFAULT_KEY_FILE)
    for name, value in (("path", path), ("key_file", key_file)):
        if type(value) is not str or (value and (not os.path.isabs(value) or "\x00" in value or value.endswith("/"))):
            raise bad(name)
    if enabled and not path:
        raise bad("path")
    max_file_bytes = data.get("max_file_bytes", 1 << 20)
    max_files = data.get("max_files", 4)
    if type(max_file_bytes) is not int or not MAX_RECORD_BYTES <= max_file_bytes <= (1 << 30):
        raise bad("max_file_bytes")
    if type(max_files) is not int or not 1 <= max_files <= 64:
        raise bad("max_files")
    return TraceAuditConfig(enabled, path, key_file, max_file_bytes, max_files)


def load_trace_audit_config(path: str) -> TraceAuditConfig:
    """Read the JSON config; a missing file means disabled.

    Opened like the key file: no symlink (also not in a parent directory),
    a regular file only, without blocking on a FIFO.
    """
    if has_symlink_parent(path):
        raise ValueError("invalid_trace_audit_config:symlink_parent")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return TraceAuditConfig()
    except OSError as exc:
        raise ValueError("invalid_trace_audit_config:" + ("symlink" if exc.errno == errno.ELOOP else "unreadable")) from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("invalid_trace_audit_config:not_regular")
        raw = os.read(fd, 65537)
    except OSError:
        raise ValueError("invalid_trace_audit_config:unreadable") from None
    finally:
        os.close(fd)
    if len(raw) > 65536:
        raise ValueError("invalid_trace_audit_config:too_large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("invalid_trace_audit_config:json") from None
    return parse_trace_audit_config(data)


class TraceAuditRecorder:
    """One sink plus its digest key. Only ``record`` and ``stats`` are public."""

    def __init__(self, sink: TraceAuditSink, key_state: AuditKeyState):
        self.sink = sink
        self._key = key_state.key if key_state.state == "persistent" and key_state.key else new_audit_key()
        self.digest_key = "persistent" if key_state.state == "persistent" and key_state.key else "ephemeral"
        self.key_reason = key_state.reason

    def __repr__(self) -> str:
        return f"TraceAuditRecorder(path={self.sink.path!r}, digest_key={self.digest_key!r})"

    def record(
        self,
        *,
        ticket: CycleTicket,
        outcome: Any,
        frame: MioSituationFrame | None = None,
        edge_decision_ref: str | None = None,
        cycle_status: str = "",
    ) -> bool:
        """Project and append one cycle; True only if the advisory may be published."""
        return record_cycle(
            self.sink,
            lambda: project_outcome(
                ticket=ticket,
                outcome=outcome,
                key=self._key,
                frame=frame,
                edge_decision_ref=edge_decision_ref,
                cycle_status=cycle_status,
                digest_key=self.digest_key,
            ),
        )

    def stats(self) -> dict[str, Any]:
        out = self.sink.stats()
        out.update({"digest_key": self.digest_key, "key_reason": self.key_reason})
        return out


def open_trace_audit(config: TraceAuditConfig, *, fs: AuditFS | None = None) -> TraceAuditRecorder | None:
    """``None`` when disabled (the default); otherwise a recorder."""
    if not config.enabled:
        return None
    sink = TraceAuditSink(config.path, config.max_file_bytes, config.max_files, fs=fs or OsAuditFS())
    return TraceAuditRecorder(sink, load_audit_key(config.key_file))
