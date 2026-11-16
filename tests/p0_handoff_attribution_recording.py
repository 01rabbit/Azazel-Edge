"""Opt-in, bounded P0 lab receipts; never changes a delegated call's result."""

from contextlib import contextmanager
import hashlib
import json
import os
import re
from pathlib import Path
import threading
import time

SCHEMA = "edge-notification-timing/v1"
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
MAX_ROWS, MAX_BYTES = 8192, 16777216


def canonical(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def _start(path):
    raw = Path(path).read_text()
    return int(raw[raw.rfind(")") + 2 :].split()[19])


def process_identity():
    """Read bootstrap identity independently of any trace, without privilege."""
    result = dict(
        pid=os.getpid(),
        process_start_ticks=None,
        boot_id=None,
        clock_domain=dict(
            time_namespace_device=None,
            time_namespace_inode=None,
            timens_offsets=None,
            established=False,
        ),
    )
    try:
        result["process_start_ticks"] = _start("/proc/self/stat")
        result["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        namespace = os.stat("/proc/self/ns/time")
        offsets = []
        for line in Path("/proc/self/timens_offsets").read_text().splitlines():
            clock, seconds, nanos = line.split()
            offsets.append(
                dict(clock=clock, seconds=int(seconds), nanoseconds=int(nanos))
            )
        result["clock_domain"].update(
            time_namespace_device=namespace.st_dev,
            time_namespace_inode=namespace.st_ino,
            timens_offsets=offsets,
            established=(
                {r["clock"] for r in offsets} == {"monotonic", "boottime"}
                and all(r["seconds"] == r["nanoseconds"] == 0 for r in offsets)
            ),
        )
    except (OSError, ValueError, IndexError):
        pass
    return result


def scheduler_snapshot():
    """Counter observations enclose probe work; unavailable data never becomes 0."""
    result = dict(
        read_begin_ns=time.monotonic_ns(),
        read_end_ns=None,
        pid=os.getpid(),
        process_start_ticks=None,
        native_tid=threading.get_native_id(),
        task_start_ticks=None,
        boot_id=None,
        schedstats_raw=None,
        schedstat_raw=None,
        runtime_ns=None,
        runqueue_wait_ns=None,
        timeslices=None,
        error=None,
    )
    try:
        result["process_start_ticks"] = _start("/proc/self/stat")
        result["boot_id"] = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        task = f"/proc/self/task/{result['native_tid']}"
        result["task_start_ticks"] = _start(task + "/stat")
        result["schedstats_raw"] = Path("/proc/sys/kernel/sched_schedstats").read_text()
        result["schedstat_raw"] = Path(task + "/schedstat").read_text()
        fields = result["schedstat_raw"].split()
        if len(fields) != 3 or any(
            not field.isascii() or not field.isdecimal() for field in fields
        ):
            raise ValueError("malformed schedstat")
        for key, value in zip(("runtime_ns", "runqueue_wait_ns", "timeslices"), fields):
            result[key] = int(value)
        if _start(task + "/stat") != result["task_start_ticks"]:
            raise ValueError("task identity changed")
    except (OSError, ValueError, IndexError) as exc:
        result["error"] = type(exc).__name__
    result["read_end_ns"] = time.monotonic_ns()
    return result


def _clocks():
    return dict(
        start_ns=time.monotonic_ns(),
        thread_cpu_start_ns=time.thread_time_ns(),
        process_cpu_start_ns=time.process_time_ns(),
    )


def _end_clocks(start):
    return dict(
        start,
        process_cpu_end_ns=time.process_time_ns(),
        thread_cpu_end_ns=time.thread_time_ns(),
        end_ns=time.monotonic_ns(),
    )


class NotificationRecording:
    def __init__(self, path, *, metadata, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
        self.incomplete = False
        self.rows_written = self.bytes_written = self.lost_rows = 0
        self.fd = None
        self.closed = False
        self.close_error = None
        self.descriptor_closed = None
        self.lock = threading.RLock()
        self.local = threading.local()
        self.previous = "0" * 64
        self.next_span = self.active = 0
        self.threads, self.events, self.bindings = {}, {}, {}
        self.max_rows, self.max_bytes = max_rows, max_bytes
        try:
            if (
                type(metadata) is not dict
                or set(metadata) != META
                or type(max_rows) is not int
                or not 1 <= max_rows <= MAX_ROWS
                or type(max_bytes) is not int
                or not 1 <= max_bytes <= MAX_BYTES
            ):
                raise ValueError("invalid notification recording metadata or bound")
            if not all(
                type(metadata[k]) is str and re.fullmatch("[0-9a-f]{64}", metadata[k])
                for k in META - {"run_id", "case_id"}
            ) or not all(
                type(metadata[k]) is str
                and re.fullmatch("[A-Za-z0-9_.:/-]{1,128}", metadata[k])
                for k in ("run_id", "case_id")
            ):
                raise ValueError("invalid notification metadata values")
            self.fd = os.open(
                path,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
            )
            self._append(
                "header",
                dict(
                    metadata,
                    **process_identity(),
                    resolutions={
                        name: time.get_clock_info(name).resolution
                        for name in ("monotonic", "thread_time", "process_time")
                    },
                    limits=dict(
                        max_rows=max_rows,
                        max_bytes=max_bytes,
                        max_depth=16,
                        max_events=120,
                        max_threads=16,
                    ),
                ),
            )
        except BaseException:
            self.incomplete = True

    def _append(self, kind, data):
        try:
            with self.lock:
                if self.incomplete or self.closed or self.fd is None:
                    self.lost_rows += 1
                    return
                raw = canonical(
                    dict(
                        schema_version=SCHEMA,
                        seq=self.rows_written + 1,
                        prev=self.previous,
                        kind=kind,
                        data=data,
                    )
                )
                if (
                    self.rows_written >= self.max_rows
                    or self.bytes_written + len(raw) > self.max_bytes
                ):
                    raise ValueError("notification trace capacity")
                view = memoryview(raw)
                while view:
                    size = os.write(self.fd, view)
                    if size <= 0:
                        raise OSError("notification trace short write")
                    view = view[size:]
                self.rows_written += 1
                self.bytes_written += len(raw)
                self.previous = hashlib.sha256(raw).hexdigest()
        except BaseException:
            self.incomplete = True
            self.lost_rows += 1

    @contextmanager
    def event_context(self, index):
        old = getattr(self.local, "event_index", None)
        try:
            self.local.event_index = index
        except BaseException:
            self.incomplete = True
        try:
            yield
        finally:
            try:
                self.local.event_index = old
            except BaseException:
                self.incomplete = True

    def bind_event(self, index, event, key):
        try:
            if (
                type(index) is not int
                or not 0 <= index < 120
                or type(event) is not dict
                or type(key) is not dict
                or set(key) != {"core_event_key", "trace_id"}
            ):
                raise ValueError("invalid event binding")
            row = dict(
                index=index,
                event_sha256=hashlib.sha256(canonical(event)).hexdigest(),
                **key,
            )
            with self.lock:
                if index in self.events:
                    if self.events[index] != row:
                        self.incomplete = True
                        for old_key, old_index in list(self.bindings.items()):
                            if old_index == index:
                                self.bindings[old_key] = None
                        self.bindings[key["core_event_key"]] = None
                    return
                self.events[index] = row
                event_key = key["core_event_key"]
                if event_key in self.bindings and self.bindings[event_key] != index:
                    self.bindings[event_key] = None
                else:
                    self.bindings[event_key] = index
                self._append("event", row)
        except BaseException:
            self.incomplete = True

    def lookup_event(self, key):
        try:
            with self.lock:
                return self.bindings.get(key)
        except BaseException:
            self.incomplete = True
            return None

    @contextmanager
    def span(self, phase, *, event_index=None, object_id=None):
        context = timing = before = None
        try:
            if phase not in PHASES:
                raise ValueError("unknown notification phase")
            before = scheduler_snapshot()
            tid, task = before["native_tid"], before["task_start_ticks"]
            with self.lock:
                if (tid, task) not in self.threads:
                    if len(self.threads) >= 16:
                        raise ValueError("notification thread bound")
                    self.threads[tid, task] = True
                    self._append(
                        "thread",
                        {
                            key: before[key]
                            for key in (
                                "native_tid",
                                "task_start_ticks",
                                "pid",
                                "process_start_ticks",
                                "boot_id",
                            )
                        }
                        | {"thread_name": threading.current_thread().name},
                    )
                self.next_span += 1
                stack = getattr(self.local, "stack", [])
                context = dict(
                    span_id=self.next_span,
                    parent_id=stack[-1] if stack else None,
                    phase=phase,
                    object_id=object_id,
                    event_index=event_index
                    if event_index is not None
                    else getattr(self.local, "event_index", None),
                    native_tid=tid,
                    task_start_ticks=task,
                )
                self._append("intent", context)
                self.local.stack = stack + [self.next_span]
                self.active += 1
            timing = _clocks()
        except BaseException:
            self.incomplete = True
            context = None
        outcome = "raised"
        try:
            yield
            outcome = "returned"
        finally:
            if context is not None:
                try:
                    clocks = _end_clocks(timing)
                    after = scheduler_snapshot()
                    self._append(
                        "span",
                        dict(
                            context,
                            **clocks,
                            outcome=outcome,
                            scheduler_before=before,
                            scheduler_after=after,
                        ),
                    )
                    with self.lock:
                        self.local.stack = self.local.stack[:-1]
                        self.active -= 1
                except BaseException:
                    self.incomplete = True

    def call(self, phase, function, *args, event_index=None, object_id=None, **kwargs):
        with self.span(phase, event_index=event_index, object_id=object_id):
            return function(*args, **kwargs)

    def _close_descriptor(self):
        # After a close error the descriptor's kernel state is unknown. Never
        # retry its numeric value, which another thread might already reuse.
        fd, self.fd = self.fd, None
        try:
            if fd is not None:
                os.close(fd)
                self.descriptor_closed = True
        except BaseException as exc:
            self.incomplete = True
            self.close_error = dict(
                type=type(exc).__name__, errno=getattr(exc, "errno", None)
            )
            self.descriptor_closed = None
        finally:
            self.closed = True

    def abort(self):
        """Stop sidecar recording without END; never affect original workers."""
        self.incomplete = True
        try:
            with self.lock:
                if not self.closed:
                    self._close_descriptor()
        except BaseException:
            self.incomplete = True

    def finish(self):
        try:
            with self.lock:
                if self.closed:
                    return
                if self.active:
                    self.incomplete = True
                if not self.incomplete:
                    self._append(
                        "end",
                        dict(normal_return=True, active_spans=0, incomplete=False),
                    )
                self._close_descriptor()
        except BaseException:
            self.incomplete = True
