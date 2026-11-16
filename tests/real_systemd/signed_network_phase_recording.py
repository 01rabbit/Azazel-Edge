"""Opt-in test-only call receipts. Recording failures never alter original calls."""

from contextlib import contextmanager, ExitStack
import functools
import hashlib
import json
import os
import re
from pathlib import Path
import threading
import time

from azazel_edge.outcome import input_auth, input_cursor, input_live, input_resume
from azazel_edge.outcome import input_witness, journal, telemetry

SCHEMA = "edge-phase-timing-record/v1"
PHASES = (
    "input_receive", "native_frame_validation", "source_append", "source_sign",
    "source_verify", "witness_rpc", "witness_request", "witness_append", "witness_sign",
    "input_snapshot", "observation", "journal_append", "observation_sample",
    "observation_event", "finalize_due", "source_fsync", "journal_fsync", "witness_fsync",
    "source_closure_wait", "observer_stop_wait", "controller_wait",
)
ROLES = ("signer", "observer", "witness", "controller", "launcher")
OPERATIONS = (None, "read", "advance", "anchor", "response", "prepare", "session_start",
              "decision", "session_end", "poll_detection", "signed_source_detection", "wait")
EVENT_KINDS = (None, "session_prepare", "session_start", "decision", "session_end",
               "begin", "commit", "lost", "cursor", "seal", "session_close", "session_recovered")
MAX_ROWS = 4096
MAX_BYTES = 4 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def _clocks():
    return dict(start_ns=time.monotonic_ns(), process_cpu_start_ns=time.process_time_ns(),
                thread_cpu_start_ns=time.thread_time_ns())


def _finished(start):
    # Read CPU before the final wallclock so CPU intervals lie within wall brackets.
    thread = time.thread_time_ns()
    process = time.process_time_ns()
    end = time.monotonic_ns()
    return dict(start, end_ns=end, process_cpu_end_ns=process, thread_cpu_end_ns=thread)


def _identity():
    stat = Path("/proc/self/stat").read_text()
    start = int(stat[stat.rfind(")") + 2:].split()[19])
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    domain = dict(time_namespace_device=None, time_namespace_inode=None,
                  timens_offsets=None, established=False)
    try:
        namespace = os.stat("/proc/self/ns/time")
        offsets = []
        for line in Path("/proc/self/timens_offsets").read_text().splitlines():
            clock, seconds, nanos = line.split()
            offsets.append(dict(clock=clock, seconds=int(seconds), nanoseconds=int(nanos)))
        domain.update(time_namespace_device=namespace.st_dev, time_namespace_inode=namespace.st_ino,
                      timens_offsets=offsets, established=(
                          {r["clock"] for r in offsets} == {"monotonic", "boottime"}
                          and all(r["seconds"] == r["nanoseconds"] == 0 for r in offsets)))
    except (OSError, ValueError):
        pass
    return dict(pid=os.getpid(), start_ticks=start, native_tid=threading.get_native_id(),
                boot_id=boot, clock_domain=domain, clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
                clock_resolutions={name: time.get_clock_info(name).resolution
                                   for name in ("monotonic", "process_time", "thread_time")})


class PhaseRecording:
    """Append-only bounded metadata receipts, with sticky incomplete state."""

    def __init__(self, path, *, metadata, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
        self.fd = None
        self.count = self.size = self.span_count = self.active = 0
        self.previous = "0" * 64
        self.previous_write_cost = None
        self.incomplete = False
        self.closed = False
        self.lock = threading.RLock()
        self.local = threading.local()
        self.max_rows, self.max_bytes = max_rows, max_bytes
        try:
            if set(metadata) != {"run_id", "arm", "role", "input_sha256", "code_sha256",
                                 "core_sha256", "interpreter_sha256"} or metadata["role"] not in ROLES:
                raise ValueError("invalid phase metadata")
            if (type(metadata["run_id"]) is not str
                    or not re.fullmatch("[A-Za-z0-9_-]{1,128}", metadata["run_id"])
                    or metadata["arm"] not in (
                        "original_off", "instrumented_off", "original_on", "instrumented_on",
                        "original_faulted", "instrumented_faulted")
                    or any(type(metadata[k]) is not str or not re.fullmatch("[0-9a-f]{64}", metadata[k])
                           for k in ("input_sha256", "code_sha256", "core_sha256", "interpreter_sha256"))):
                raise ValueError("invalid phase metadata value")
            if not (type(max_rows) is int and 1 <= max_rows <= MAX_ROWS
                    and type(max_bytes) is int and 1 <= max_bytes <= MAX_BYTES):
                raise ValueError("invalid phase bounds")
            self.fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
                              | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            self._append("header", dict(metadata, **_identity(),
                                      limits=dict(max_rows=max_rows, max_bytes=max_bytes),
                                      unallocated_footer_flush_overhead=True))
        except BaseException:
            self.incomplete = True

    def _append(self, kind, data):
        with self.lock:
            if self.incomplete or self.closed or self.fd is None:
                return
            try:
                data = dict(data, previous_write_cost=self.previous_write_cost)
                raw = canonical(dict(schema_version=SCHEMA, seq=self.count + 1,
                                     prev=self.previous, kind=kind, data=data))
                if self.count >= self.max_rows or self.size + len(raw) > self.max_bytes:
                    raise ValueError("phase recording capacity")
                start = _clocks()
                view = memoryview(raw)
                while view:
                    wrote = os.write(self.fd, view)
                    if wrote <= 0:
                        raise OSError("phase short write")
                    view = view[wrote:]
                cost = _finished(start)
                self.count += 1
                self.size += len(raw)
                self.previous = hashlib.sha256(raw).hexdigest()
                self.previous_write_cost = dict(seq=self.count, **cost)
            except BaseException:
                self.incomplete = True

    def call(self, phase, function, *args, event_kind=None, event_seq=None, operation=None, **kwargs):
        span = None
        try:
            with self.lock:
                if (phase not in PHASES or event_kind not in EVENT_KINDS or operation not in OPERATIONS
                        or not (event_seq is None or type(event_seq) is int and 0 <= event_seq < 2**64)):
                    raise ValueError("invalid receipt enum")
                self.span_count += 1
                span = self.span_count
                stack = getattr(self.local, "stack", [])
                context = dict(span_id=span, parent_id=stack[-1] if stack else None, phase=phase,
                               event_kind=event_kind, event_seq=event_seq, operation=operation)
                self._append("intent", context)
                self.local.stack = stack + [span]
                self.active += 1
            start = _clocks()
        except BaseException:
            self.incomplete = True
            span = None
        outcome = "raised"
        try:
            result = function(*args, **kwargs)
            outcome = "returned"
            return result
        finally:
            if span is not None:
                try:
                    timing = _finished(start)
                    self._append("span", dict(context, **timing, outcome=outcome,
                                              native_tid=threading.get_native_id()))
                    with self.lock:
                        self.local.stack = self.local.stack[:-1]
                        self.active -= 1
                except BaseException:
                    self.incomplete = True

    def close(self, *, normal_return=False):
        with self.lock:
            if self.closed:
                return
            if self.active:
                self.incomplete = True
            if normal_return and not self.incomplete:
                self._append("end", dict(normal_return=True, incomplete=False,
                                         unallocated_footer_flush_overhead=True))
            try:
                if self.fd is not None:
                    os.close(self.fd)
            except BaseException:
                self.incomplete = True
            finally:
                self.fd = None
                self.closed = True


class ModuleProxy:
    """Forward one module binding without modifying the shared stdlib module."""

    def __init__(self, original, **overrides):
        self.original = original
        self.overrides = overrides

    def __getattr__(self, name):
        return self.overrides[name] if name in self.overrides else getattr(self.original, name)


@contextmanager
def _replace(owner, name, value):
    original = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield
    finally:
        setattr(owner, name, original)


def _wrap(recorder, phase, function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        return recorder.call(phase, function, *args, **kwargs)
    return wrapped


class ReceiveSocketProxy:
    def __init__(self, original, recorder):
        self.original, self.recorder = original, recorder

    def __getattr__(self, name):
        return getattr(self.original, name)

    def __enter__(self):
        self.original.__enter__()
        return self

    def __exit__(self, *args):
        return self.original.__exit__(*args)

    def recv(self, *args, **kwargs):
        return self.recorder.call("input_receive", self.original.recv, *args, **kwargs)


@contextmanager
def record_receiver(recorder, receive_fd):
    original_socket = input_live.socket
    used = False

    def factory(*args, **kwargs):
        nonlocal used
        if args or kwargs != {"fileno": receive_fd} or used:
            raise ValueError("phase receiver socket shape refused")
        used = True
        return ReceiveSocketProxy(original_socket.socket(*args, **kwargs), recorder)

    original_sign = input_auth.sign

    def source_sign(private, domain, body):
        if domain != input_auth.SOURCE_DOMAIN:
            return original_sign(private, domain, body)
        return recorder.call("source_sign", original_sign, private, domain, body,
                             event_seq=body.get("seq"))

    with ExitStack() as stack:
        stack.enter_context(_replace(input_live, "socket", ModuleProxy(original_socket, socket=factory)))
        stack.enter_context(_replace(input_live, "native_frame", _wrap(recorder, "native_frame_validation", input_live.native_frame)))
        stack.enter_context(_replace(input_auth.SignedCaptureWriter, "append", _wrap(recorder, "source_append", input_auth.SignedCaptureWriter.append)))
        stack.enter_context(_replace(input_auth.SourceVerifier, "verify", _wrap(recorder, "source_verify", input_auth.SourceVerifier.verify)))
        stack.enter_context(_replace(input_auth, "sign", source_sign))
        stack.enter_context(_replace(input_auth, "os", ModuleProxy(input_auth.os, fsync=_wrap(recorder, "source_fsync", input_auth.os.fsync))))
        yield


@contextmanager
def record_observer(recorder):
    with ExitStack() as stack:
        for owner, name, phase in (
            (input_cursor.BoundedInput, "snapshot", "input_snapshot"),
            (input_auth.SourceVerifier, "verify", "source_verify"),
            (input_witness.WitnessClient, "call", "witness_rpc"),
            (input_resume, "observe_input", "observation"),
            (journal.ObservationJournal, "_append", "journal_append"),
            (telemetry.OutcomeTelemetryCollector, "record_sample", "observation_sample"),
            (telemetry.OutcomeTelemetryCollector, "observe_event", "observation_event"),
            (telemetry.OutcomeTelemetryCollector, "finalize_due", "finalize_due"),
        ):
            stack.enter_context(_replace(owner, name, _wrap(recorder, phase, getattr(owner, name))))
        stack.enter_context(_replace(journal, "os", ModuleProxy(journal.os, fsync=_wrap(recorder, "journal_fsync", journal.os.fsync))))
        yield


@contextmanager
def record_witness(recorder):
    original_sign = input_witness.sign

    def witness_sign(private, domain, body):
        if domain not in (input_witness.ANCHOR_DOMAIN, input_witness.RESPONSE_DOMAIN):
            return original_sign(private, domain, body)
        return recorder.call("witness_sign", original_sign, private, domain, body,
                             operation="anchor" if domain == input_witness.ANCHOR_DOMAIN else "response")

    with ExitStack() as stack:
        for name, phase in (("request", "witness_request"), ("_append", "witness_append")):
            stack.enter_context(_replace(input_witness.WitnessStore, name,
                                         _wrap(recorder, phase, getattr(input_witness.WitnessStore, name))))
        stack.enter_context(_replace(input_witness, "sign", witness_sign))
        stack.enter_context(_replace(input_witness, "os", ModuleProxy(input_witness.os, fsync=_wrap(recorder, "witness_fsync", input_witness.os.fsync))))
        yield


def install_hooks(recorder, role):
    if role == "observer":
        return record_observer(recorder)
    if role == "witness":
        return record_witness(recorder)
    raise ValueError("explicit receiver FD required for signer hooks")
