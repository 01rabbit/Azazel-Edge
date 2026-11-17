"""Synthetic structural guards, not latency or historical-cause acceptance."""

from contextlib import ExitStack
import json
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

import p0_handoff_attribution_lab as lab
import p0_handoff_attribution_recording as eager
import p0_handoff_lean_recording as lean


def metadata():
    return dict(run_id="SYNTHETIC-lean", case_id="historical_slow_fsync_instrumented",
        protocol_sha256=lean.UNDERLYING_PROTOCOL_SHA256, source_inventory_sha256="1" * 64,
        fixture_sha256="2" * 64, interpreter_sha256="3" * 64)


class OwnershipGuard:
    def __init__(self):
        self.local = threading.local()
        self.forbidden = []

    def call(self, name, function, *args, **kwargs):
        if getattr(self.local, "depth", 0):
            self.forbidden.append(name)
            raise AssertionError("observer operation while original target owned: " + name)
        return function(*args, **kwargs)


class ModuleSpy:
    def __init__(self, actual, guard, prefix, methods):
        self.actual, self.guard, self.prefix, self.methods = actual, guard, prefix, methods

    def __getattr__(self, name):
        value = getattr(self.actual, name)
        if name not in self.methods:
            return value
        return lambda *args, **kwargs: self.guard.call(self.prefix + "." + name, value, *args, **kwargs)


class OwnedPrimitive:
    def __init__(self, actual, guard):
        self.actual, self.guard = actual, guard

    def acquire(self, *args, **kwargs):
        result = self.actual.acquire(*args, **kwargs)
        if result:
            self.guard.local.depth = getattr(self.guard.local, "depth", 0) + 1
        return result

    def release(self):
        result = self.actual.release()
        self.guard.local.depth -= 1
        return result


def guarded_recorder(tmp_path, monkeypatch):
    guard = OwnershipGuard()
    recording = lean.LeanRecording(tmp_path / "trace.jsonl", metadata=metadata())
    recording.prepare_thread()
    monkeypatch.setattr(lean, "json", ModuleSpy(lean.json, guard, "json", {"dumps", "dump"}))
    monkeypatch.setattr(lean, "hashlib", ModuleSpy(lean.hashlib, guard, "hash", {"sha256"}))
    monkeypatch.setattr(lean, "os", ModuleSpy(lean.os, guard, "file", {"open", "read", "write", "close", "stat", "fstat"}))
    identity = lean.process_identity
    monkeypatch.setattr(lean, "process_identity", lambda: guard.call("proc.identity", identity))
    primitive = OwnedPrimitive(threading.Lock(), guard)
    return recording, guard, lab.LockProxy(primitive, recording, "SYNTHETIC.target")


def test_owned_acquire_hold_release_has_no_observer_io_json_hash_or_mutex_but_original_audit_io_remains(tmp_path, monkeypatch):
    recording, guard, target = guarded_recorder(tmp_path, monkeypatch)
    # If a recorder-global mutex is ever introduced on these paths it must fail.
    class RecorderMutex:
        def __enter__(self):
            guard.call("recorder.global_mutex", lambda: None)

        def __exit__(self, *args):
            pass
    recording.lock = RecorderMutex()
    audit = lab.P0AuditLogger(tmp_path / "original-audit")
    called = []

    def original():
        called.append(True)
        # This original serialization/write/real-fsync under target ownership
        # is explicitly allowed; only observer-origin calls are trapped.
        return audit.log_action_decision(trace_id="SYNTHETIC", source="SYNTHETIC", action="throttle")

    with target:
        result = recording.call("audit_save", original, object_id="original.audit")
    assert called == [True] and result["trace_id"] == "SYNTHETIC"
    assert lab.P0AuditLogger.verify_chain(audit.path)["ok"] is True
    assert guard.forbidden == []
    assert not (tmp_path / "trace.jsonl").exists()
    recording.finish(quiescent=True)
    assert recording.descriptor_closed is True and guard.forbidden == []


def test_deferred_fsync_uses_only_buffered_callsite_and_original_control_under_owned_mutex(tmp_path, monkeypatch):
    recording, guard, target = guarded_recorder(tmp_path, monkeypatch)
    waits, calls = [], []
    monkeypatch.setattr(lab, "time", SimpleNamespace(sleep=waits.append))
    returned = object()
    with target:
        assert lab.deferred_fsync_call(recording, lambda fd: calls.append(fd) or returned, 99) is returned
    assert calls == [99] and waits == [0.050] and guard.forbidden == []
    recording.finish(quiescent=True)
    rows = [json.loads(line) for line in (tmp_path / "trace.jsonl").read_bytes().splitlines()]
    assert any(row["kind"] == "span" and row["data"]["object_id"] == "global.os.fsync.callsite.unclassified_fd" for row in rows)


def test_deliberately_eager_observer_is_rejected_without_changing_original_call(tmp_path, monkeypatch):
    guard = OwnershipGuard()
    recording = eager.NotificationRecording(tmp_path / "eager.jsonl", metadata=metadata())
    actual = eager.scheduler_snapshot
    monkeypatch.setattr(eager, "scheduler_snapshot", lambda: guard.call("proc.scheduler_snapshot", actual))
    target = lab.LockProxy(OwnedPrimitive(threading.Lock(), guard), lab.NoRecording(), "SYNTHETIC.target")
    calls = []
    with target:
        assert recording.call("submit", lambda: calls.append(1) or "same-result") == "same-result"
    assert calls == [1] and guard.forbidden == ["proc.scheduler_snapshot"]
    assert recording.incomplete is True
    recording.abort()


@pytest.mark.parametrize("raises", [False, True])
def test_optional_preparation_never_replaces_original_entry_result_or_exception(raises):
    calls = []
    failure = ValueError("SYNTHETIC original failure")
    returned = object()

    def prepare():
        calls.append("prepare")
        raise RuntimeError("SYNTHETIC enrollment unavailable")

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        if raises:
            raise failure
        return returned

    control = lab.Control({"id": "SYNTHETIC", "control": "none"})
    wrapper = lab.prepared_entry(SimpleNamespace(prepare_thread=prepare), control, original)
    if raises:
        with pytest.raises(ValueError) as caught:
            wrapper(1, key=2)
        assert caught.value is failure
    else:
        assert wrapper(1, key=2) is returned
    assert calls == ["prepare", ((1,), {"key": 2})]
    assert control.data["thread_preparation_errors"] == ["RuntimeError"]


def test_default_factory_and_finalizer_stay_unchanged_and_new_factory_requires_quiescence(tmp_path, monkeypatch):
    calls = []

    class Default(lab.NoRecording):
        def __init__(self, path, **kwargs):
            Path(path).write_bytes(b"SYNTHETIC old trace\n")

        def prepare_thread(self):
            raise AssertionError("default must not add enrollment calls")

        def finish(self):
            calls.append("old_finish_no_kwargs")

    class Deferred(lab.NoRecording):
        def __init__(self, path, **kwargs):
            Path(path).write_bytes(b"SYNTHETIC deferred trace\n")

        def prepare_thread(self):
            calls.append("new_prepare")

        def finish(self, *, quiescent=False):
            calls.append(("new_finish", quiescent))

    monkeypatch.setattr(lab, "NotificationRecording", Default)
    monkeypatch.setattr(lab, "scheduler_snapshot", lambda: {"schedstats_raw": "0\n", "error": None})
    assigned = dict(id="scheduler_contention", control="disabled", instrumented=True, events=1, producers=1)
    old = tmp_path / "old"
    new = tmp_path / "new"
    old.mkdir()
    new.mkdir()
    lab.collect_case(old, assigned, {})
    lab.collect_case(new, assigned, {}, recording_factory=Deferred)
    assert calls == ["old_finish_no_kwargs", "new_prepare", ("new_finish", True)]


def test_unprepared_thread_does_not_lazily_probe_and_preserves_original_return(tmp_path, monkeypatch):
    recording = lean.LeanRecording(tmp_path / "unprepared", metadata=metadata())
    def forbidden():
        raise AssertionError("no lazy proc fallback")
    monkeypatch.setattr(lean, "process_identity", forbidden)
    returned = object()
    assert recording.call("submit", lambda: returned) is returned
    assert recording.incomplete is True
    recording.abort(quiescent=True)
    assert b'"kind":"end"' not in (tmp_path / "unprepared").read_bytes()


def test_reused_native_tid_does_not_merge_distinct_python_thread_objects(tmp_path, monkeypatch):
    recording = lean.LeanRecording(tmp_path / "reuse", metadata=metadata())
    actual = lean.threading
    monkeypatch.setattr(lean, "threading", SimpleNamespace(current_thread=actual.current_thread, get_native_id=lambda: 77))
    def worker():
        recording.prepare_thread()
        recording.call("submit", lambda: None)
    for _ in range(2):
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=1)
        assert not thread.is_alive()
    recording.finish(quiescent=True)
    rows = [json.loads(line) for line in (tmp_path / "reuse").read_bytes().splitlines()]
    threads = [row["data"] for row in rows if row["kind"] == "thread"]
    assert len(threads) == 2 and {row["native_tid"] for row in threads} == {77}
    assert len({row["logical_thread_token"] for row in threads}) == 2


def test_capacity_loss_keeps_original_calls_and_no_normal_end(tmp_path, monkeypatch):
    monkeypatch.setattr(lean, "SLOTS", 2)
    recording = lean.LeanRecording(tmp_path / "capacity", metadata=metadata())
    recording.prepare_thread()
    calls = []
    for index in range(3):
        assert recording.call("submit", lambda index=index: calls.append(index) or index) == index
    assert calls == [0, 1, 2] and recording.incomplete
    recording.finish(quiescent=True)
    rows = [json.loads(line) for line in (tmp_path / "capacity").read_bytes().splitlines()]
    assert sum(row["kind"] == "span" for row in rows) == 2
    assert all(row["kind"] != "end" for row in rows)


def test_deferred_hooks_bypass_eager_inode_proxy_and_prepare_worker_entry_before_original(tmp_path):
    prepared, actual = [], []
    class Recording(lab.NoRecording):
        def prepare_thread(self):
            prepared.append(threading.get_native_id())
    receiver = SimpleNamespace(_lock=threading.Lock(), _pending=SimpleNamespace(put_nowait=lambda item: None),
        _record=lambda *args: True, _run=lambda: actual.append("run") or "original-return")
    audit = SimpleNamespace(_lock=threading.Lock(), log_reporting_durability=lambda *args, **kwargs: None)
    control = lab.Control(dict(id="historical_slow_fsync_instrumented", instrumented=True, control="none"))
    original_os = lab.audit_module.os
    with ExitStack() as stack:
        lab.Hooks(stack, receiver, Recording(), audit, receiver, control, {}, deferred=True)
        assert lab.audit_module.os is original_os
        assert receiver._run() == "original-return"
    assert len(prepared) == 1 and actual == ["run"]
