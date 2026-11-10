"""Bounded local observation journal, never decision/enforcement authority.

Every begin/result/loss is fd-fsynced; creation additionally syncs the private
parent directory. No rotation, repair, history replay, eviction or automatic
reinitialization. Hashes detect corruption, not authenticated source/rollback.
"""

from __future__ import annotations

from copy import deepcopy
import fcntl
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .contracts import OutcomeAssessment, CausalSupport, OutcomeRecord
from .outcome_identity import OutcomeIdentityLedger, outcome_identity_key

SCHEMA = "outcome-observation-journal/v1"
NAME = "observations.journal"
MAX_RECORD_BYTES = 65536
CONTROL_RESERVE = 4096
DEFAULT_MAX_BYTES = 16 * 1024 * 1024
MAX_SESSIONS = 64
ZERO_HASH = "0" * 64
META = {"decision_id", "execution_id", "objective_id", "boot_id"}


class OutcomeJournalError(OSError):
    """Continuity/durability unavailable. Never clear the journal and retry."""


class _RetentionFull(OutcomeJournalError):
    """A bounded append was refused before any write was attempted."""


def _json(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise OutcomeJournalError("invalid bounded journal JSON") from exc


def _parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise OutcomeJournalError("duplicate journal key")
            value[key] = item
        return value

    try:
        return json.loads(
            raw,
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                OutcomeJournalError("nonfinite journal JSON")
            ),
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise OutcomeJournalError("invalid journal JSON") from exc


def _ref(value):
    if type(value) is not str or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", value
    ):
        raise OutcomeJournalError("invalid bounded journal identifier")
    return value


def _wire(record):
    if type(record) is not OutcomeRecord:
        raise OutcomeJournalError("OutcomeRecord required")
    if (
        record.assessment is not OutcomeAssessment.INCONCLUSIVE
        or record.causal_support is not CausalSupport.INCONCLUSIVE
    ):
        raise OutcomeJournalError("G3 journal cannot introduce supported outcomes")
    wire = record.to_dict()
    for key in (
        "decision_id",
        "execution_id",
        "objective_id",
        "mechanism_id",
        "incident_id",
        "outcome_id",
    ):
        _ref(wire[key])
    return wire


def _outcome(wire):
    try:
        value = deepcopy(dict(wire))
        value["assessment"] = OutcomeAssessment(value["assessment"])
        value["causal_support"] = CausalSupport(value["causal_support"])
        record = OutcomeRecord(**value)
        if _wire(record) != wire:
            raise ValueError("noncanonical Outcome")
        return record
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise OutcomeJournalError("invalid retained Outcome") from exc


def _directory(path):
    """Walk pinned descriptors without following any path-component symlink."""
    value = Path(path)
    if not value.is_absolute() or ".." in value.parts:
        raise OutcomeJournalError("absolute physical private directory required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in value.parts[1:]:
            new = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise OutcomeJournalError(
                "journal directory must be owned by this uid with mode 0700"
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


class ObservationJournal:
    """One private scope/policy, one nonblocking locked writer, finite lifetime.

    `create=True` is an explicit first initialization in an empty directory.
    Normal open never creates a missing file. Every unfinished begin is durably
    tombstoned on open, even when the process restarts within the same OS boot.
    """

    def __init__(
        self,
        directory,
        *,
        scope_ref,
        policy_ref,
        boot_id,
        create=False,
        max_identities=4096,
        max_bytes=DEFAULT_MAX_BYTES,
    ):
        _ref(scope_ref)
        _ref(boot_id)
        if type(policy_ref) is not str or not policy_ref or len(policy_ref) > 4096:
            raise OutcomeJournalError("explicit bounded policy identity required")
        if (
            type(create) is not bool
            or type(max_identities) is not int
            or not 1 <= max_identities <= 16384
        ):
            raise OutcomeJournalError("invalid journal capacity/initialization")
        if (
            type(max_bytes) is not int
            or not 2 * MAX_RECORD_BYTES <= max_bytes <= 64 * 1024 * 1024
        ):
            raise OutcomeJournalError("invalid journal byte budget")
        self.config = dict(
            schema_version=SCHEMA,
            scope_ref=scope_ref,
            policy_sha256=hashlib.sha256(policy_ref.encode()).hexdigest(),
            max_identities=max_identities,
            max_bytes=max_bytes,
        )
        self.boot_id = boot_id
        self.max_bytes = max_bytes
        self.max_identities = max_identities
        self._dir = self._fd = None
        self._size = self._seq = 0
        self._hash = ZERO_HASH
        self._states = {}
        self._sealed = self._poisoned = False
        self._ready = self._active = self._unclean = False
        self._sessions = 0
        self._session_boot = None
        self._seal_reason = None
        self._ledger = OutcomeIdentityLedger(max_identities=max_identities)
        self.counters = dict(
            duplicates=0, capacity_drops=0, write_failures=0, recovered_windows=0
        )
        try:
            self._dir = _directory(directory)
            if create and os.listdir(self._dir):
                raise OutcomeJournalError(
                    "initialization requires a new empty scope directory"
                )
            if not create:
                before = os.stat(NAME, dir_fd=self._dir, follow_symlinks=False)
                self._file_info(before)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            self._fd = os.open(NAME, flags, 0o600, dir_fd=self._dir)
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._inode = os.fstat(self._fd)
            self._file_info(self._inode)
            self._namespace()
            if create:
                self._append("header", self.config)
                os.fsync(self._dir)  # failure is fatal; no unsupported-sync fallback
            else:
                self._load()
            self._unclean = self._active
            for state in list(self._states.values()):
                if state["state"] == "pending":
                    self._append(
                        "lost",
                        {**state["meta"], "reason": "recovered_unfinished_window"},
                    )
                    self.counters["recovered_windows"] += 1
            if self._unclean:
                self._seal("unclean_restart")
            elif not self._sealed:
                if self._sessions >= MAX_SESSIONS:
                    self._seal("session_capacity")
                else:
                    try:
                        self._append("session_open", {"boot_id": self.boot_id})
                    except _RetentionFull:
                        self._seal("byte_capacity")
            self._ready = True
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _file_info(info):
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise OutcomeJournalError(
                "journal must be a single-link private regular file owned by this uid"
            )

    def _namespace(self):
        current = os.stat(NAME, dir_fd=self._dir, follow_symlinks=False)
        self._file_info(current)
        if (current.st_dev, current.st_ino) != (self._inode.st_dev, self._inode.st_ino):
            raise OutcomeJournalError("journal path identity changed")

    def _usable(self):
        if self._fd is None or self._poisoned:
            raise OutcomeJournalError("journal closed or continuity unavailable")

    def _pending(self):
        return sum(s["state"] == "pending" for s in self._states.values())

    def _validate(self, kind, data):
        if kind == "header":
            if (
                self._seq
                or type(data) is not dict
                or data != self.config
                or type(data.get("max_identities")) is not int
                or type(data.get("max_bytes")) is not int
            ):
                raise OutcomeJournalError("journal scope/policy/budget mismatch")
            return
        if not self._seq:
            raise OutcomeJournalError("journal header missing")
        if kind == "seal":
            if (
                type(data) is not dict
                or set(data) != {"reason"}
                or data["reason"]
                not in (
                    "identity_capacity",
                    "byte_capacity",
                    "session_capacity",
                    "unclean_restart",
                )
                or self._sealed
            ):
                raise OutcomeJournalError("invalid journal seal")
            return
        if kind == "session_open":
            if (
                type(data) is not dict
                or set(data) != {"boot_id"}
                or self._active
                or self._sealed
                or self._sessions >= MAX_SESSIONS
            ):
                raise OutcomeJournalError("invalid journal session start")
            _ref(data["boot_id"])
            return
        if kind == "session_close":
            if (
                data != {"boot_id": self._session_boot}
                or not self._active
                or self._pending()
            ):
                raise OutcomeJournalError("invalid journal clean close")
            return
        if kind not in ("begin", "lost", "commit") or type(data) is not dict:
            raise OutcomeJournalError("unsupported journal transition")
        fields = META | (
            {"outcome"} if kind == "commit" else {"reason"} if kind == "lost" else set()
        )
        if set(data) != fields:
            raise OutcomeJournalError("invalid journal transition fields")
        for name in META:
            _ref(data[name])
        key = outcome_identity_key(
            execution_id=data["execution_id"], objective_id=data["objective_id"]
        )
        old = self._states.get(key)
        if old and any(data[n] != old["meta"][n] for n in META):
            raise OutcomeJournalError("journal identity collision")
        if not old and (self._sealed or len(self._states) >= self.max_identities):
            raise OutcomeJournalError("journal capacity exhausted")
        if kind == "begin" and (
            old
            or self._sealed
            or not self._active
            or data["boot_id"] != self._session_boot
        ):
            raise OutcomeJournalError("observation identity cannot reopen")
        if kind == "commit":
            if not old or old["state"] != "pending":
                raise OutcomeJournalError("no pending observation to commit")
            record = _outcome(data["outcome"])
            if any(
                getattr(record, n) != data[n]
                for n in ("decision_id", "execution_id", "objective_id")
            ):
                raise OutcomeJournalError("Outcome does not match pending identity")
        if kind == "lost":
            if old and old["state"] != "pending":
                raise OutcomeJournalError("retained identity cannot become lost")
            if data["reason"] not in (
                "recovered_unfinished_window",
                "capacity_drop",
                "explicit_window_loss",
            ):
                raise OutcomeJournalError("invalid loss reason")

    def _apply(self, kind, data):
        if kind == "header":
            return
        if kind == "seal":
            self._sealed = True
            self._seal_reason = data["reason"]
            return
        if kind == "session_open":
            self._active = True
            self._sessions += 1
            self._session_boot = data["boot_id"]
            return
        if kind == "session_close":
            self._active = False
            self._session_boot = None
            return
        key = outcome_identity_key(
            execution_id=data["execution_id"], objective_id=data["objective_id"]
        )
        meta = {n: data[n] for n in META}
        if kind == "begin":
            self._states[key] = dict(state="pending", meta=meta)
        elif kind == "lost":
            self._ledger.mark_window_lost(
                **{n: data[n] for n in ("decision_id", "execution_id", "objective_id")}
            )
            self._states[key] = dict(state="lost", meta=meta)
        else:
            record = _outcome(data["outcome"])
            if not self._ledger.admit(record).counted:
                raise OutcomeJournalError("duplicate committed Outcome")
            self._states[key] = dict(
                state="committed", meta=meta, outcome=data["outcome"]
            )

    def _load(self):
        size = os.fstat(self._fd).st_size
        if not 0 < size <= self.max_bytes:
            raise OutcomeJournalError("journal missing header or oversized")
        os.lseek(self._fd, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= self.max_bytes:
            chunk = os.read(self._fd, min(65536, self.max_bytes + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != size or not raw.endswith(b"\n"):
            raise OutcomeJournalError(
                "incomplete or changing journal; no automatic repair"
            )
        for line in raw.splitlines(keepends=True):
            if (
                len(line) > MAX_RECORD_BYTES
                or self._seq >= 2 * self.max_identities + 2 * MAX_SESSIONS + 4
            ):
                raise OutcomeJournalError("journal record budget exceeded")
            event = _parse(line)
            if (
                type(event) is not dict
                or set(event) != {"seq", "prev", "kind", "data", "sha256"}
                or type(event["seq"]) is not int
            ):
                raise OutcomeJournalError("invalid journal frame")
            core = {k: v for k, v in event.items() if k != "sha256"}
            if (
                event["seq"] != self._seq + 1
                or event["prev"] != self._hash
                or event["sha256"] != hashlib.sha256(_json(core)).hexdigest()
            ):
                raise OutcomeJournalError("journal chain integrity failure")
            self._validate(event["kind"], event["data"])
            self._apply(event["kind"], event["data"])
            self._seq += 1
            self._hash = event["sha256"]
        self._size = size
        self._namespace()
        if not self._seq:
            raise OutcomeJournalError("journal header missing")

    def _append(self, kind, data):
        self._usable()
        self._validate(kind, data)
        core = dict(seq=self._seq + 1, prev=self._hash, kind=kind, data=data)
        digest = hashlib.sha256(_json(core)).hexdigest()
        line = _json({**core, "sha256": digest}) + b"\n"
        pending = self._pending()
        if kind == "begin":
            pending += 1
        elif kind in ("commit", "lost"):
            key = outcome_identity_key(
                execution_id=data["execution_id"], objective_id=data["objective_id"]
            )
            if self._states.get(key, {}).get("state") == "pending":
                pending -= 1
        reserve = pending * MAX_RECORD_BYTES + (
            0 if kind in ("seal", "session_close") or self._sealed else CONTROL_RESERVE
        )
        if (
            len(line) > MAX_RECORD_BYTES
            or self._size + len(line) + reserve > self.max_bytes
        ):
            raise _RetentionFull("journal retention budget exhausted")
        try:
            self._namespace()
            if os.fstat(self._fd).st_size != self._size:
                raise OutcomeJournalError("journal changed outside locked writer")
            os.lseek(self._fd, 0, os.SEEK_END)
            view = memoryview(line)
            while view:
                written = os.write(self._fd, view)
                if written <= 0:
                    raise OutcomeJournalError("journal short write made no progress")
                view = view[written:]
            os.fsync(self._fd)
            self._namespace()
            self._apply(kind, data)
            self._size += len(line)
            self._seq += 1
            self._hash = digest
        except BaseException:
            self._poisoned = True
            self.counters["write_failures"] += 1
            raise

    def _seal(self, reason):
        if not self._sealed:
            self._append("seal", {"reason": reason})

    def _meta(self, *, decision_id, execution_id, objective_id):
        return dict(
            decision_id=_ref(decision_id),
            execution_id=_ref(execution_id),
            objective_id=_ref(objective_id),
            boot_id=self.boot_id,
        )

    def check_context(self, policy_ref):
        if (
            hashlib.sha256(policy_ref.encode()).hexdigest()
            != self.config["policy_sha256"]
        ):
            raise OutcomeJournalError("collector context differs from retained journal")

    def begin_window(self, *, decision_id, execution_id, objective_id):
        self._usable()
        meta = self._meta(
            decision_id=decision_id,
            execution_id=execution_id,
            objective_id=objective_id,
        )
        key = outcome_identity_key(execution_id=execution_id, objective_id=objective_id)
        old = self._states.get(key)
        if old:
            if old["meta"]["decision_id"] != decision_id:
                raise OutcomeJournalError("journal decision identity collision")
            self.counters["duplicates"] += 1
            return False
        if self._sealed:
            return False
        if len(self._states) >= self.max_identities:
            self._seal("identity_capacity")
            self.counters["capacity_drops"] += 1
            return False
        try:
            self._append("begin", meta)
        except _RetentionFull:
            self._seal("byte_capacity")
            self.counters["capacity_drops"] += 1
            return False
        return True

    def lose_window(self, *, decision_id, execution_id, objective_id):
        self._usable()
        meta = self._meta(
            decision_id=decision_id,
            execution_id=execution_id,
            objective_id=objective_id,
        )
        key = outcome_identity_key(execution_id=execution_id, objective_id=objective_id)
        old = self._states.get(key)
        if old and old["meta"]["decision_id"] != decision_id:
            raise OutcomeJournalError("journal decision identity collision")
        if old and old["state"] != "pending":
            return
        if old:
            meta = dict(old["meta"])
        if not old and (self._sealed or len(self._states) >= self.max_identities):
            if not self._sealed:
                self._seal("identity_capacity")
            return
        try:
            self._append("lost", {**meta, "reason": "explicit_window_loss"})
        except _RetentionFull:
            self._seal("byte_capacity")

    def commit_outcome(self, outcome):
        self._usable()
        wire = _wire(outcome)
        key = outcome_identity_key(
            execution_id=outcome.execution_id, objective_id=outcome.objective_id
        )
        old = self._states.get(key)
        if old and old["meta"]["decision_id"] != outcome.decision_id:
            raise OutcomeJournalError("journal decision identity collision")
        if old and old["state"] != "pending":
            self.counters["duplicates"] += 1
            return False
        if not old:
            raise OutcomeJournalError("cannot commit without durable begin")
        self._append("commit", {**old["meta"], "outcome": wire})
        return True

    def retained_outcomes(self):
        """Bounded projection; consumers deduplicate by retained outcome identity."""
        self._usable()
        return tuple(
            _outcome(s["outcome"])
            for s in self._states.values()
            if s["state"] == "committed"
        )

    def status(self):
        return dict(
            schema_version=SCHEMA,
            bytes=self._size,
            max_bytes=self.max_bytes,
            identities=len(self._states),
            max_identities=self.max_identities,
            pending=self._pending(),
            committed=sum(s["state"] == "committed" for s in self._states.values()),
            lost=sum(s["state"] == "lost" for s in self._states.values()),
            new_admission_closed=self._sealed
            or len(self._states) >= self.max_identities,
            sessions=self._sessions,
            unclean_recovery=self._unclean,
            seal_reason=self._seal_reason,
            continuity_available=not self._poisoned and self._fd is not None,
            sequence=self._seq,
            chain_head=self._hash,
            counters=dict(self.counters),
        )

    def close(self):
        try:
            if self._ready and self._fd is not None and not self._poisoned:
                for state in list(self._states.values()):
                    if state["state"] == "pending":
                        self._append(
                            "lost", {**state["meta"], "reason": "explicit_window_loss"}
                        )
                if self._active and not self._sealed:
                    self._append("session_close", {"boot_id": self._session_boot})
        finally:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None
            if self._dir is not None:
                os.close(self._dir)
                self._dir = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
