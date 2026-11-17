"""Bounded deferred test capture. No observer I/O or global mutex in spans."""

from contextlib import contextmanager
import hashlib
import json
import os
import platform
import re
import threading
import time

from p0_handoff_attribution_recording import process_identity

SCHEMA = "edge-notification-lean/v1"
STUDY_PROTOCOL_SHA256 = (
    "5617214899eed681c435330cd456b149f214d01bc9b067be30724f6e23dfdcb8"
)
UNDERLYING_PROTOCOL_SHA256 = (
    "98e610da6e8b0906b448fcca259d226e1f2b13957e9d78fdd383f52aad8aaec5"
)
PHASES = (
    "legacy_interval",
    "fixture_input",
    "submit",
    "payload",
    "logging_call",
    "lock_acquire",
    "lock_hold",
    "queue_put",
    "writer_record",
    "audit_save",
    "audit_fsync",
    "statistics_lock_acquire",
    "statistics_lock_hold",
    "blocking_control",
    "scheduler_control",
)
META = {
    "run_id",
    "case_id",
    "protocol_sha256",
    "source_inventory_sha256",
    "fixture_sha256",
    "interpreter_sha256",
}
MAX_ROWS, MAX_BYTES, THREADS, SLOTS = 8192, 16777216, 16, 480


def canonical(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def _clocks():
    return (
        time.monotonic_ns(),
        time.thread_time_ns(),
        time.process_time_ns(),
        threading.get_native_id(),
    )


def _end_clocks():
    process = time.process_time_ns()
    thread = time.thread_time_ns()
    tid = threading.get_native_id()
    return (time.monotonic_ns(), thread, process, tid)


class LeanRecording:
    def __init__(
        self,
        path,
        *,
        metadata,
        max_rows=MAX_ROWS,
        max_bytes=MAX_BYTES,
        study_protocol_sha256=STUDY_PROTOCOL_SHA256,
    ):
        self.path, self.metadata = (
            path,
            dict(metadata) if type(metadata) is dict else {},
        )
        self.incomplete = self.closed = False
        self.close_error = self.descriptor_closed = None
        self.rows_written = self.bytes_written = 0
        self._lost = [0] * THREADS
        self._unassigned_loss = False
        self._flush_lost_unknown = False
        self.max_rows, self.max_bytes = max_rows, max_bytes
        self.local = threading.local()
        self.buffers = [[None] * SLOTS for _ in range(THREADS)]
        self.owners = [
            None
        ] * THREADS  # Strong Thread refs prevent Python object reuse.
        self.thread_rows = [None] * THREADS
        self.used = [0] * THREADS
        self.active = [0] * THREADS
        self.free = list(reversed(range(THREADS)))
        self.events = [None] * 120
        self.bindings = {}
        self.aborted = False
        self.identity = {}
        self.resolutions = {}
        self.finalization = None
        self.study_pin = study_protocol_sha256
        self.supported = True
        try:
            if (
                platform.python_implementation() != "CPython"
                or type(metadata) is not dict
                or set(metadata) != META
                or metadata["protocol_sha256"] != UNDERLYING_PROTOCOL_SHA256
                or metadata["case_id"] != "historical_slow_fsync_instrumented"
                or study_protocol_sha256 != STUDY_PROTOCOL_SHA256
                or type(max_rows) is not int
                or not 1 <= max_rows <= MAX_ROWS
                or type(max_bytes) is not int
                or not 1 <= max_bytes <= MAX_BYTES
            ):
                raise ValueError("lean profile metadata or capacity")
            if any(
                type(metadata[k]) is not str
                or not metadata[k]
                or len(metadata[k]) > 128
                for k in META
            ):
                raise ValueError("lean metadata type")
            if (
                any(
                    re.fullmatch("[0-9a-f]{64}", metadata[k]) is None
                    for k in META - {"run_id", "case_id"}
                )
                or re.fullmatch("[A-Za-z0-9_.:/-]{1,128}", metadata["run_id"]) is None
            ):
                raise ValueError("lean pin syntax")
            self.identity = process_identity()  # Bootstrap only, never a span fallback.
            self.resolutions = {
                name: time.get_clock_info(name).resolution
                for name in ("monotonic", "thread_time", "process_time")
            }
        except BaseException:
            self.incomplete = True
            self.supported = False

    @property
    def lost_rows(self):
        # Read after quiescence. An unprepared thread cannot acquire a counter
        # slot without synchronization, so its exact loss count stays unknown.
        return (
            None
            if self._unassigned_loss or self._flush_lost_unknown
            else sum(self._lost)
        )

    def prepare_thread(self):
        """Explicit outside-target registration; never called implicitly by span."""
        try:
            if not self.supported or self.closed:
                self.incomplete = True
                return None
            current = threading.current_thread()
            existing = getattr(self.local, "slot", None)
            if existing is not None and self.owners[existing] is current:
                return existing + 1
            # CPython list.pop is the single slot claim. No recorder-wide mutex.
            slot = self.free.pop()
            self.owners[slot] = current
            self.thread_rows[slot] = dict(
                logical_thread_token=slot + 1,
                native_tid=threading.get_native_id(),
                task_start_ticks=None,
                thread_name=current.name,
                identity_scope="strong_python_Thread_object_native_tid_not_kernel_incarnation",
            )
            self.local.slot, self.local.stack, self.local.event_index = slot, [], None
            return slot + 1
        except BaseException:
            self.incomplete = True
            self._unassigned_loss = True
            return None

    @contextmanager
    def event_context(self, index):
        old = getattr(self.local, "event_index", None)
        self.local.event_index = index
        try:
            yield
        finally:
            self.local.event_index = old

    def bind_event(self, index, event, key):
        try:
            if (
                type(index) is not int
                or not 0 <= index < 120
                or type(event) is not dict
                or type(key) is not dict
                or set(key) != {"core_event_key", "trace_id"}
                or any(
                    type(key[k]) is not str or not key[k] or len(key[k]) > 128
                    for k in key
                )
            ):
                raise ValueError("lean event binding")
            old = self.events[index]
            if old is not None:
                if old[0] is not event or old[1:] != (
                    key["core_event_key"],
                    key["trace_id"],
                ):
                    self.incomplete = True
                    for name, value in list(self.bindings.items()):
                        if value == index:
                            self.bindings[name] = None
                return
            self.events[index] = (event, key["core_event_key"], key["trace_id"])
            old_index = self.bindings.setdefault(key["core_event_key"], index)
            if old_index != index:
                self.bindings[key["core_event_key"]] = None
        except BaseException:
            self.incomplete = True

    def lookup_event(self, key):
        try:
            return self.bindings.get(key)
        except BaseException:
            self.incomplete = True
            return None

    @contextmanager
    def span(self, phase, *, event_index=None, object_id=None):
        slot = position = None
        start = (None,) * 4
        error = None
        try:
            slot = getattr(self.local, "slot", None)
            if (
                slot is None
                or self.owners[slot] is not threading.current_thread()
                or phase not in PHASES
                or self.closed
                or not self.supported
                or self.used[slot] >= SLOTS
                or object_id is not None
                and (type(object_id) is not str or len(object_id) > 128)
            ):
                raise ValueError("unprepared_or_full_lean_capture")
            index = event_index if event_index is not None else self.local.event_index
            if index is not None and (type(index) is not int or not 0 <= index < 120):
                raise ValueError("lean event index")
            position = self.used[slot]
            self.used[slot] += 1
            parent = self.local.stack[-1] if self.local.stack else None
            # Fixed scalar slot: identity/context, raw start/end clocks, outcome/error.
            context = (position + 1, parent, slot + 1, phase, object_id, index)
            self.buffers[slot][position] = (
                context + start + (None,) * 4 + (None, False, "unfinished")
            )
            self.local.stack.append(position + 1)
            self.active[slot] += 1
            try:
                start = _clocks()
            except BaseException:
                error = "start_clock_failure"
                self.incomplete = True
        except BaseException:
            self.incomplete = True
            if slot is None:
                self._unassigned_loss = True
            else:
                self._lost[slot] += 1
            slot = position = None
        outcome = "raised"
        try:
            yield
            outcome = "returned"
        finally:
            if position is not None:
                end = (None,) * 4
                try:
                    end = _end_clocks()
                except BaseException:
                    error = "end_clock_failure"
                    self.incomplete = True
                try:
                    if error is None and start[3] != end[3]:
                        error = "native_tid_changed"
                        self.incomplete = True
                    self.buffers[slot][position] = (
                        context + start + end + (outcome, error is None, error)
                    )
                    self.local.stack.pop()
                    self.active[slot] -= 1
                except BaseException:
                    self.incomplete = True

    def call(self, phase, function, *args, event_index=None, object_id=None, **kwargs):
        with self.span(phase, event_index=event_index, object_id=object_id):
            return function(*args, **kwargs)

    def _flush(self, *, normal):
        if self.closed:
            return
        if any(self.active):
            self.incomplete = True
            return
        fd = None
        previous = "0" * 64
        started = time.monotonic_ns()
        self.finalization = dict(start_ns=started, end_ns=None, error=None)

        def emit(kind, data):
            nonlocal previous
            raw = canonical(
                dict(
                    schema_version=SCHEMA,
                    seq=self.rows_written + 1,
                    prev=previous,
                    kind=kind,
                    data=data,
                )
            )
            if (
                self.rows_written >= self.max_rows
                or self.bytes_written + len(raw) > self.max_bytes
            ):
                raise ValueError("lean serialized capacity")
            view = memoryview(raw)
            while view:
                wrote = os.write(fd, view)
                if wrote <= 0:
                    raise OSError("lean short write")
                view = view[wrote:]
            self.rows_written += 1
            self.bytes_written += len(raw)
            previous = hashlib.sha256(raw).hexdigest()

        try:
            fd = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
            emit(
                "header",
                dict(
                    self.metadata,
                    **self.identity,
                    study_protocol_sha256=self.study_pin,
                    capture_profile=SCHEMA,
                    resolutions=self.resolutions,
                    limits=dict(
                        max_rows=self.max_rows,
                        max_bytes=self.max_bytes,
                        max_threads=THREADS,
                        max_events=120,
                        max_depth=16,
                        slots_per_thread=SLOTS,
                    ),
                ),
            )
            for row in self.thread_rows:
                if row is not None:
                    emit("thread", row)
            for index, row in enumerate(self.events):
                if row is not None:
                    event, key, trace_id = row
                    emit(
                        "event",
                        dict(
                            index=index,
                            event_sha256=hashlib.sha256(canonical(event)).hexdigest(),
                            core_event_key=key,
                            trace_id=trace_id,
                        ),
                    )
            fields = (
                "span_id",
                "parent_id",
                "logical_thread_token",
                "phase",
                "object_id",
                "event_index",
                "start_ns",
                "thread_cpu_start_ns",
                "process_cpu_start_ns",
                "native_tid_start",
                "end_ns",
                "thread_cpu_end_ns",
                "process_cpu_end_ns",
                "native_tid_end",
                "outcome",
                "complete",
                "error",
            )
            for slot in range(THREADS):
                for position in range(self.used[slot]):
                    emit("span", dict(zip(fields, self.buffers[slot][position])))
            if normal and not self.incomplete:
                emit(
                    "end",
                    dict(
                        normal_return=True,
                        active_spans=0,
                        incomplete=False,
                        quiescent=True,
                        flush_start_ns=started,
                        flush_before_end_ns=time.monotonic_ns(),
                    ),
                )
        except BaseException as exc:
            self.incomplete = True
            self._flush_lost_unknown = True
            self.finalization["error"] = type(exc).__name__
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                    self.descriptor_closed = True
                except BaseException as exc:
                    self.incomplete = True
                    self.close_error = dict(
                        type=type(exc).__name__, errno=getattr(exc, "errno", None)
                    )
                    self.descriptor_closed = None
            self.closed = True
            try:
                self.finalization["end_ns"] = time.monotonic_ns()
            except BaseException:
                self.finalization["error"] = "finish_clock_failure"
                self.incomplete = True

    def finish(self, *, quiescent=False):
        if quiescent is not True:
            self.incomplete = True
            return
        try:
            self._flush(normal=not self.aborted)
        except BaseException:
            self.incomplete = True

    def abort(self, *, quiescent=False):
        self.aborted = self.incomplete = True
        if quiescent is True:
            try:
                self._flush(normal=False)
            except BaseException:
                self.incomplete = True
