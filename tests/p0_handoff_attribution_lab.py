"""Opt-in original P0 submit probes; no socket ingress or historical attribution."""

from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

from azazel_edge.audit import P0AuditLogger, logger as audit_module
from azazel_edge.notify import core_decisions
from azazel_edge.notify.p0_alert import attach_p0_alert_relay
import test_agent_core_p0_path_v1 as original
from p0_handoff_attribution_recording import (
    NotificationRecording, canonical, process_identity, scheduler_snapshot,
)

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "tests/fixtures/notification-timing/v1/protocol.json"
MAXIMUM = 16 * 1024 * 1024
RETAINED_UNFINISHED_CASES = []


def has_retained_unfinished_resources():
    """Sticky resource ownership survives exceptions after partial export."""
    return bool(RETAINED_UNFINISHED_CASES)


@contextmanager
def case_resources(state):
    """Keep hooks and private originals alive if real callbacks remain alive."""
    resources = ExitStack()
    work = resources.enter_context(tempfile.TemporaryDirectory(prefix="notification-attribution-"))
    try:
        yield work, resources
    finally:
        if state.get("quiescent") is True:
            resources.close()
        else:
            RETAINED_UNFINISHED_CASES.append(resources)


def cleanup_workers(control, errors, threads, receiver, audit, relay, first_continue, held_lock):
    first_continue.set()
    control.release_fsync.set()

    def attempt(name, function):
        try:
            return function()
        except Exception as exc:
            errors["cleanup_" + name] = type(exc).__name__
            return None

    if held_lock is not None:
        control.data["release_ns"] = time.monotonic_ns()
        attempt("held_lock", held_lock.release)
    for index, thread in enumerate(threads):
        if thread.ident is not None:
            attempt("producer_" + str(index), lambda thread=thread: thread.join(timeout=30))
    if receiver is not None:
        control.data["recorder_stop_result"] = attempt("recorder_stop", lambda: receiver.stop(timeout=30))
    delivered = attempt("durable_listeners", lambda: audit.wait_durable_listeners(30)) if audit is not None else None
    if relay is None and audit is not None:
        relay = getattr(audit, "_p0_alert_relay", None)
    if relay is not None:
        attempt("relay_stop", lambda: relay.stop(timeout=30))
    recorder_thread = getattr(receiver, "_thread", None)
    relay_thread = getattr(relay, "_thread", None)
    all_threads = [thread for thread in [*threads, recorder_thread, relay_thread] if thread is not None]
    stopped = all(not thread.is_alive() for thread in all_threads)
    pending = len(audit._durable_handoff) if audit is not None else None
    handed = audit._durable_handed if audit is not None else None
    handed_off = audit._durable_delivered if audit is not None else None
    callbacks_done = audit is None or (delivered is True and pending == 0 and handed_off >= handed)
    quiescent = stopped and callbacks_done
    control.data.update(producers_joined=all(thread.ident is not None and not thread.is_alive() for thread in threads) if threads else None,
        producer_started=[thread.ident is not None for thread in threads],
        recorder_joined=not recorder_thread.is_alive() if recorder_thread is not None else None,
        relay_joined=not relay_thread.is_alive() if relay_thread is not None else None,
        durable_dispatcher_alive=getattr(audit, "_durable_dispatcher", None) is not None and audit._durable_dispatcher.is_alive(),
        durable_handed=handed, durable_delivered=handed_off, durable_pending=pending,
        callbacks_quiescent=quiescent)
    if not quiescent:
        errors["workers"] = "original_workers_or_callbacks_not_quiescent"
    return dict(quiescent=quiescent, workers_joined=bool(all_threads) and stopped)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read_original(path, maximum=MAXIMUM):
    """Bounded identity-fenced read, never manufacture a missing original."""
    import stat

    before = Path(path).lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        def version(info):
            return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or version(before) != version(opened):
            raise ValueError("unstable regular original")
        if not 0 <= opened.st_size <= maximum:
            raise ValueError("original exceeds bound")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) != opened.st_size or version(os.fstat(fd)) != version(opened) or version(Path(path).lstat()) != version(opened):
            raise ValueError("original changed during read")
        return raw
    finally:
        os.close(fd)


class NoRecording:
    """Uninstrumented timing baseline, with common event-binding bookkeeping."""

    incomplete = False
    lost_rows = rows_written = bytes_written = 0
    descriptor_closed = close_error = None

    def span(self, *args, **kwargs):
        return nullcontext()

    def event_context(self, index):
        return nullcontext()

    def call(self, phase, function, *args, event_index=None, object_id=None, **kwargs):
        return function(*args, **kwargs)

    def bind_event(self, *args):
        pass

    def abort(self):
        self.incomplete = True

    def finish(self):
        pass


def logger_profile(logger):
    result = []
    while logger is not None:
        result.append(dict(logger_type=type(logger).__module__ + "." + type(logger).__qualname__,
            level=logger.level, propagate=logger.propagate,
            handlers=[dict(handler_type=type(handler).__module__ + "." + type(handler).__qualname__, level=handler.level)
                      for handler in logger.handlers]))
        logger = logger.parent
    return result


class Control:
    def __init__(self, recipe):
        self.recipe = recipe
        self.lock = threading.Lock()
        self.attempt = threading.Event()
        self.selected_return = threading.Event()
        self.next_attempt = 0
        self.selected_attempt = None
        self.fsync_entered = threading.Event()
        self.release_fsync = threading.Event()
        self.data = dict(recipe=recipe["control"], requested_wait_ns=20_000_000 if recipe["id"] in (
                         "fixture_delay", "logging_delay", "recorder_lock_delay", "unrelated_lock_negative",
                         "blocking_wait_counterexample") else None,
                         status="not_exercised", target_attempt_ns=None, target_entered_ns=None,
                         held_ns=None, release_ns=None, target_return_ns=None)

    def first_attempt(self, object_id):
        with self.lock:
            self.next_attempt += 1
            token = (self.next_attempt, threading.get_native_id())
            if self.data["target_attempt_ns"] is None:
                self.selected_attempt = token
                self.data.update(target_attempt_ns=time.monotonic_ns(), target_object_id=object_id,
                                 target_native_tid=token[1], target_attempt_token=token[0])
                self.data["target_entered_ns"] = time.monotonic_ns()
                self.attempt.set()
            return token

    def first_return(self, token):
        with self.lock:
            if token == self.selected_attempt and token[1] == threading.get_native_id() and self.data["target_return_ns"] is None:
                self.data["target_return_ns"] = time.monotonic_ns()
                self.data["target_return_native_tid"] = threading.get_native_id()
                self.data["target_return_token"] = token[0]
                self.selected_return.set()

    def delayed_call(self, recorder, object_id, function, *args, **kwargs):
        with self.lock:
            first = self.data["target_attempt_ns"] is None
            if first:
                stamp = time.monotonic_ns()
                self.data.update(target_attempt_ns=stamp, target_entered_ns=time.monotonic_ns(), held_ns=time.monotonic_ns(),
                                 target_object_id=object_id, target_native_tid=threading.get_native_id())
                self.attempt.set()
        if first:
            with recorder.span("blocking_control", object_id=object_id):
                threading.Event().wait(0.020)
            self.data["release_ns"] = time.monotonic_ns()
        try:
            result = function(*args, **kwargs)
            if first:
                self.data["target_outcome"] = "returned"
            return result
        except BaseException:
            if first:
                self.data["target_outcome"] = "raised"
            raise
        finally:
            if first:
                self.data.update(target_return_ns=time.monotonic_ns(), status="observed_intervention")


class LockProxy:
    """Forward the same primitive, recording only observed acquire/held brackets."""

    def __init__(self, primitive, recorder, object_id, *, tracker=None):
        self.primitive, self.recorder, self.object_id = primitive, recorder, object_id
        self.tracker = tracker
        self.local = threading.local()

    def acquire(self, *args, **kwargs):
        tracked = self.tracker is not None and threading.current_thread().name.startswith("notification-producer-")
        token = None
        if tracked:
            token = self.tracker.first_attempt(self.object_id)
        result = self.recorder.call("lock_acquire", self.primitive.acquire, *args, object_id=self.object_id, **kwargs)
        if tracked:
            self.tracker.first_return(token)
        if result:
            context = self.recorder.span("lock_hold", object_id=self.object_id)
            context.__enter__()
            self.local.held = context
        return result

    def release(self):
        try:
            context = getattr(self.local, "held", None)
            if context is not None:
                self.local.held = None
                context.__exit__(None, None, None)
        finally:
            self.primitive.release()

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *exc):
        self.release()

    def __getattr__(self, name):
        return getattr(self.primitive, name)


class FixtureProxy:
    def __init__(self, path, recorder, control):
        self.path, self.recorder, self.control = path, recorder, control

    def read_text(self, *args, **kwargs):
        return self.control.delayed_call(self.recorder, "original.fixture.read_text", self.path.read_text, *args, **kwargs)


class LoggerProxy:
    def __init__(self, logger, recorder, control):
        self.logger, self.recorder, self.control = logger, recorder, control

    def error(self, *args, **kwargs):
        def delegate():
            if (self.control.recipe["id"] == "logging_delay" and args
                    and args[0] == "core decision hand-off full; P0 decision %s not recorded now"):
                return self.control.delayed_call(self.recorder, "original.overflow.error", self.logger.error, *args, **kwargs)
            return self.logger.error(*args, **kwargs)
        return self.recorder.call("logging_call", delegate, object_id="core_decisions.logger.error")

    def __getattr__(self, name):
        return getattr(self.logger, name)


class FsyncProxy:
    def __init__(self, actual_os, audit, recorder, control):
        self.actual, self.audit, self.recorder, self.control = actual_os, audit, recorder, control

    def __getattr__(self, name):
        return getattr(self.actual, name)

    def fsync(self, fd):
        try:
            opened = self.actual.fstat(fd)
            named = self.audit.path.stat() if self.audit.path.exists() else None
        except Exception as exc:
            try:
                with self.control.lock:
                    self.control.data.setdefault("fsync_probe_errors", []).append(type(exc).__name__)
            except Exception:
                pass
            return self.actual.fsync(fd)
        if named is None or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            return self.actual.fsync(fd)

        def delegate():
            held = False
            if self.control.recipe["id"] in ("writer_fsync_hold", "logging_delay"):
                with self.control.lock:
                    if not self.control.fsync_entered.is_set():
                        held = True
                        self.control.data.update(writer_fsync_entered_ns=time.monotonic_ns(),
                            writer_fsync_native_tid=threading.get_native_id(), audit_device=opened.st_dev, audit_inode=opened.st_ino)
                        self.control.data["writer_fsync_held_ns"] = time.monotonic_ns()
                        self.control.fsync_entered.set()
                if not self.control.release_fsync.wait(30):
                    raise TimeoutError("writer fsync control watchdog")
            result = self.actual.fsync(fd)
            if held:
                self.control.data["writer_fsync_return_ns"] = time.monotonic_ns()
            return result
        return self.recorder.call("audit_fsync", delegate, object_id="audit.target.fsync")


class Hooks:
    def __init__(self, stack, recorder, recording, audit, receiver, control, event_rows):
        self.recorder, self.recording, self.control = recorder, recording, control
        self.local = threading.local()
        self.events, self.bindings, self.event_rows = {}, {}, event_rows
        self.binding_lock = threading.Lock()
        actual_payload = core_decisions.core_decision_payload

        def payload(event):
            result = recording.call("payload", actual_payload, event, object_id="core_decision_payload")
            index = getattr(self.local, "event_index", None)
            if result is not None and index is not None:
                trace_id, value = result
                key = dict(core_event_key=value["core_event_key"], trace_id=trace_id)
                recording.bind_event(index, event, key)
                with self.binding_lock:
                    self.event_rows[index] = dict(index=index, event=deepcopy(event), event_sha256=sha(canonical(event)), **key)
                    old = self.bindings.get(key["core_event_key"], index)
                    self.bindings[key["core_event_key"]] = index if old == index else None
            return result

        stack.enter_context(patch.object(core_decisions, "core_decision_payload", payload))
        if not control.recipe["instrumented"]:
            return
        for target, name, phase, identifier in ((receiver._pending, "put_nowait", "queue_put", "receiver.queue"),
                (audit, "log_reporting_durability", "audit_save", "audit.save")):
            function = getattr(target, name)
            def wrapper(*args, _function=function, _phase=phase, _identifier=identifier, **kwargs):
                return recording.call(_phase, _function, *args, object_id=_identifier, **kwargs)
            stack.enter_context(patch.object(target, name, wrapper))
        tracker = control if control.recipe["id"] in ("recorder_lock_delay", "unrelated_lock_negative") else None
        stack.enter_context(patch.object(receiver, "_lock", LockProxy(receiver._lock, recording, "recorder.lock", tracker=tracker)))
        stack.enter_context(patch.object(audit, "_lock", LockProxy(audit._lock, recording, "audit.lock")))
        record = receiver._record

        def writer(trace_id, value):
            with self.binding_lock:
                index = self.bindings.get(value.get("core_event_key"))
            with recording.event_context(index):
                return recording.call("writer_record", record, trace_id, value, event_index=index, object_id="writer._record")

        stack.enter_context(patch.object(receiver, "_record", writer))
        stack.enter_context(patch.object(core_decisions, "_LOG", LoggerProxy(core_decisions._LOG, recording, control)))
        stack.enter_context(patch.object(audit_module, "os", FsyncProxy(audit_module.os, audit, recording, control)))
        if control.recipe["id"] == "fixture_delay":
            stack.enter_context(patch.object(original, "FIXTURE", FixtureProxy(original.FIXTURE, recording, control)))


def _scheduler_control(recording, control):
    """Exactly one bounded, ordinary competitor; no affinity/priority changes."""
    code = ("import json,time,os;print(json.dumps({'ready_ns':time.monotonic_ns(),'uid':os.geteuid(),'pid':os.getpid()}),flush=True);"
            "start=time.monotonic_ns();cpu=time.thread_time_ns();"
            "exec('while time.thread_time_ns()-cpu<100000000:\\n if time.monotonic_ns()-start>30000000000: raise TimeoutError(\"competitor watchdog\")');"
            "print(json.dumps({'start_ns':start,'end_ns':time.monotonic_ns(),'cpu_start_ns':cpu,'cpu_end_ns':time.thread_time_ns()}),flush=True)")
    child = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=30):
                raise TimeoutError("competitor ready watchdog")
            ready = child.stdout.readline(4096)
        control.data["competitor_ready"] = json.loads(ready)
        control.data["observed_start_ns"] = time.monotonic_ns()
        with recording.span("scheduler_control", object_id="observed.runnable.window"):
            begin_cpu = time.thread_time_ns()
            while time.thread_time_ns() - begin_cpu < 50_000_000:
                if time.monotonic_ns() - control.data["observed_start_ns"] > 30_000_000_000:
                    raise TimeoutError("observed CPU window watchdog")
            control.data.update(observed_cpu_start_ns=begin_cpu, observed_cpu_end_ns=time.thread_time_ns())
        control.data["observed_end_ns"] = time.monotonic_ns()
        stdout, stderr = child.communicate(timeout=30)
        control.data.update(competitor_returncode=child.returncode, competitor_result=json.loads(stdout),
                            competitor_stderr=stderr.decode(), status="observed_control_not_scheduler_acceptance")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=30)


def collect_case(directory, recipe, metadata):
    """Run an assigned case once; save original bytes before any analysis."""
    directory = Path(directory)
    identifier = recipe["id"]
    recording = NoRecording()
    expected_header = dict(metadata, **process_identity())  # Independent pre-tracer bootstrap.
    control, errors, event_rows, intervals = Control(recipe), {}, {}, []
    trace = directory / (identifier + ".trace.jsonl")
    setup_begin = time.monotonic_ns()
    if recipe["instrumented"]:
        recording = NotificationRecording(trace, metadata=metadata, max_rows=32 if identifier == "trace_loss" else 8192)
    control.data.update(recording_setup_begin_ns=setup_begin, recording_setup_end_ns=time.monotonic_ns(),
                        input_scope="direct_CoreDecisionRecorder.submit_and_fixture_construction",
                        statistics_hold_scope="measured_prefix_only_release_and_trace_overhead_unallocated")
    try:
        control.data["logger_profile"] = logger_profile(core_decisions._LOG)
    except Exception as exc:
        control.data.update(logger_profile=None, logger_profile_error=type(exc).__name__)
    scheduler = scheduler_snapshot()
    control.data["scheduler_precheck"] = scheduler
    completed, metric, audit_raw, queue_raw = [], None, None, None
    lifecycle = dict(quiescent=False, workers_joined=False)
    with case_resources(lifecycle) as (work, resources):
        audit = receiver = relay = None
        threads = []
        first_continue = threading.Event()
        stats = threading.Lock()
        held_lock = None
        cleaned = False

        def cleanup():
            nonlocal cleaned, held_lock
            if not cleaned:
                cleaned = True
                lifecycle.update(cleanup_workers(control, errors, threads, receiver, audit, relay, first_continue, held_lock))
                held_lock = None
        try:
            if identifier == "scheduler_contention" and (scheduler["schedstats_raw"] != "1\n" or scheduler["error"] is not None):
                control.data.update(status="unmeasured_scheduler_enablement", workload_started=False)
                lifecycle["quiescent"] = True
                cleaned = True  # No original worker/primitive was created.
            else:
                control.data["workload_started"] = True
                audit = P0AuditLogger(Path(work) / "audit.raw")
                relay = attach_p0_alert_relay(audit, Path(work) / "queue.raw")
                receiver = core_decisions.CoreDecisionRecorder(audit, relay, None, max_pending=8)
                with nullcontext(resources.enter_context(ExitStack())) as patches:
                    try:
                        hooks = Hooks(patches, receiver, recording, audit, receiver, control, event_rows)
                        receiver.start()
                        if not receiver.ready.wait(30) or not relay.ready.wait(30):
                            raise TimeoutError("original worker readiness watchdog")
                        if identifier == "scheduler_contention":
                            _scheduler_control(recording, control)
                        if identifier in ("recorder_lock_delay", "unrelated_lock_negative"):
                            held_lock = receiver._lock.primitive if identifier == "recorder_lock_delay" else threading.Lock()
                            held_lock.acquire()
                            control.data.update(held_ns=time.monotonic_ns(), held_object_id="recorder.lock" if identifier == "recorder_lock_delay" else "unrelated.lock")
                        original_submit = receiver.submit

                        def submit(event):
                            if identifier == "inline_save_negative":
                                before = time.monotonic_ns()
                                control.data.update(target_attempt_ns=before, target_entered_ns=time.monotonic_ns(),
                                                    held_ns=time.monotonic_ns(), target_object_id="inline.receiver.audit_save")
                                audit.log_action_decision(trace_id="SYNTHETIC-inline-save", source="SYNTHETIC_receiver_save",
                                                          action="throttle", synthetic_injected=True)
                                control.data.update(injected_audit_rows=1, injected_save_begin_ns=before,
                                                    injected_save_end_ns=time.monotonic_ns(), injected_trace_id="SYNTHETIC-inline-save",
                                                    release_ns=time.monotonic_ns(), target_return_ns=time.monotonic_ns(), status="observed_intervention")
                            return original_submit(event)

                        def producer(base):
                            count = recipe["events"] // recipe["producers"]
                            for offset in range(count):
                                index = base * count + offset
                                hooks.local.event_index = index
                                with recording.event_context(index):
                                    legacy = recording.span("legacy_interval", event_index=index, object_id="legacy.interval")
                                    legacy.__enter__()
                                    closed = False
                                    try:
                                        t0 = time.monotonic_ns()
                                        event = recording.call("fixture_input", original.core_event, "throttle", f"notification-{index}", 9_400_000 + index,
                                                               event_index=index, object_id="original.core_event")
                                        if identifier == "blocking_wait_counterexample":
                                            control.delayed_call(recording, "explicit.blocking.wait", lambda: None)
                                        recording.call("submit", submit, event, event_index=index, object_id="CoreDecisionRecorder.submit")
                                        completed.append(index)
                                        recording.call("statistics_lock_acquire", stats.acquire, object_id="legacy.statistics")
                                        interval = None
                                        try:
                                            with recording.span("statistics_lock_hold", object_id="legacy.statistics.held_prefix"):
                                                t1 = time.monotonic_ns()
                                                interval = dict(index=index, start_ns=t0, end_ns=t1, elapsed_ns=t1-t0)
                                                intervals.append(interval)
                                            legacy.__exit__(None, None, None)
                                            closed = True
                                        finally:
                                            release_begin = time.monotonic_ns()
                                            stats.release()
                                            release_end = time.monotonic_ns()
                                            if interval is not None:
                                                interval.update(statistics_release_begin_ns=release_begin, statistics_release_end_ns=release_end)
                                    except BaseException:
                                        if not closed:
                                            legacy.__exit__(*sys.exc_info())
                                        raise
                                if base == 0 and offset == 0 and identifier in ("writer_fsync_hold", "logging_delay"):
                                    if not first_continue.wait(30):
                                        raise TimeoutError("first producer staging watchdog")

                        def guarded(base):
                            try:
                                producer(base)
                            except Exception as exc:
                                errors["producer_" + str(base)] = type(exc).__name__

                        for base in range(recipe["producers"]):
                            if base == 1 and identifier in ("writer_fsync_hold", "logging_delay"):
                                if not control.fsync_entered.wait(30):
                                    raise TimeoutError("writer did not reach fsync control")
                                first_continue.set()
                            thread = threading.Thread(target=guarded, args=(base,), name="notification-producer-" + str(base))
                            threads.append(thread)
                            thread.start()
                        if identifier in ("writer_fsync_hold", "logging_delay") and recipe["producers"] == 1:
                            first_continue.set()
                        if held_lock is not None:
                            if control.attempt.wait(30):
                                threading.Event().wait(0.020)
                                if identifier == "unrelated_lock_negative" and not control.selected_return.wait(30):
                                    errors["unrelated_control"] = "selected_same_acquirer_return_watchdog"
                                control.data["status"] = "observed_intervention"
                            else:
                                errors["lock_control"] = "target_attempt_unavailable"
                            control.data["release_ns"] = time.monotonic_ns()
                            held_lock.release()
                            held_lock = None
                        for thread in threads:
                            thread.join(timeout=30)
                        if any(thread.is_alive() for thread in threads):
                            raise TimeoutError("producer completion watchdog")
                        if identifier in ("writer_fsync_hold", "logging_delay"):
                            control.data.update(receivers_completed_while_fsync_held=not control.release_fsync.is_set(),
                                                completed_while_held=len(completed), writer_fsync_release_ns=time.monotonic_ns())
                            control.release_fsync.set()
                            if identifier == "writer_fsync_hold":
                                control.data["status"] = "observed_intervention"
                        if not receiver.wait_idle(30) or not audit.wait_durable_listeners(30) or not relay.wait_idle(30):
                            raise TimeoutError("original drain watchdog")
                    finally:
                        cleanup()
                if lifecycle["quiescent"]:
                    metric = receiver.metrics()
                    control.data["chain_verification"] = P0AuditLogger.verify_chain(audit.path)
                if identifier == "unrelated_lock_negative":
                    returned = control.data["target_return_ns"]
                    control.data["target_returned_before_unrelated_release"] = returned is not None and returned < control.data["release_ns"]
                    if not control.data["target_returned_before_unrelated_release"]:
                        control.data["status"] = "unexercised_negative_control"
        except Exception as exc:
            errors["case"] = type(exc).__name__
            if receiver is not None and lifecycle["quiescent"]:
                metric = receiver.metrics()
        finally:
            cleanup()  # Includes constructor/start failures before hook setup.
            for name in ("audit", "queue"):
                if audit is None:
                    continue
                path = Path(work) / (name + ".raw")
                try:
                    raw = read_original(path)
                    save(directory / (identifier + "." + name + ".raw"), raw)
                    if name == "audit":
                        audit_raw = raw.decode()
                    else:
                        queue_raw = raw.decode()
                except (OSError, ValueError, UnicodeError) as exc:
                    errors[name] = type(exc).__name__
    control.data.update(legacy_intervals=sorted(intervals, key=lambda row: row["index"]),
                        recording_finish_begin_ns=time.monotonic_ns(),
                        recording_incomplete_before_finish=recording.incomplete,
                        process_cpu_scope="shared_process_including_overlapping_workers_and_idle_original_daemons")
    if recipe["instrumented"]:
        if lifecycle["quiescent"] and not errors:
            recording.finish()
        else:
            recording.abort()
    control.data.update(recording_finish_end_ns=time.monotonic_ns(), recording_incomplete=recording.incomplete,
                        recording_lost_rows=recording.lost_rows, instrumented_workers_joined=lifecycle["workers_joined"],
                        callbacks_quiescent=lifecycle["quiescent"], recorder_close_error=getattr(recording, "close_error", None),
                        recorder_descriptor_closed=getattr(recording, "descriptor_closed", None))
    if recording.incomplete and identifier != "trace_loss":
        errors["recording"] = "recorder_incomplete_after_finish"
    if control.data.get("fsync_probe_errors"):
        errors["fsync_probe"] = "target_identity_probe_failed_original_fsync_preserved"
    if getattr(recording, "close_error", None) is not None:
        errors["recording_close"] = "recorder_descriptor_close_failed"
    result = dict(schema_version="edge-notification-original-result/v1", case_id=identifier,
                  assigned_events=recipe["events"], completed_submissions=len(completed), metrics=metric,
                  audit_raw=audit_raw, queue_raw=queue_raw, control=control.data, collection_errors=errors)
    index = dict(schema_version="edge-notification-event-index/v1", events=[event_rows[key] for key in sorted(event_rows)])
    original_raw, index_raw = canonical(result), canonical(index)
    save(directory / (identifier + ".original-result.json"), original_raw)
    save(directory / (identifier + ".event-index.json"), index_raw)
    return dict(original=result, expected=dict(header=expected_header,
                event_index_sha256=sha(index_raw), original_result_sha256=sha(original_raw)),
                recording_incomplete=recording.incomplete, trace_present=trace.exists(), safe_to_continue=lifecycle["quiescent"])
