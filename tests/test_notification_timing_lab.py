"""SYNTHETIC hook/loss/orchestration tests; never the assigned eleven-case pilot."""

from contextlib import ExitStack
from copy import deepcopy
import ast
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

import p0_handoff_attribution_lab as lab
import run_notification_timing as runner


def recipe(identifier):
    return next(row for row in json.loads(lab.PROTOCOL.read_bytes())["cases"] if row["id"] == identifier)


@pytest.mark.parametrize("raises", [False, True])
def test_payload_binding_delegates_once_preserving_exact_result_or_exception(monkeypatch, raises):
    event = {"SYNTHETIC": True}
    returned = ("core-test", {"core_event_key": "a" * 64})
    failure = ValueError("SYNTHETIC original exception")
    calls, rows = [], {}

    def payload(value):
        calls.append(value)
        if raises:
            raise failure
        return returned

    monkeypatch.setattr(lab.core_decisions, "core_decision_payload", payload)
    with ExitStack() as stack:
        hooks = lab.Hooks(stack, None, lab.NoRecording(), None, None, lab.Control(recipe("legacy_original")), rows)
        hooks.local.event_index = 3
        if raises:
            with pytest.raises(ValueError) as caught:
                lab.core_decisions.core_decision_payload(event)
            assert caught.value is failure and rows == {}
        else:
            assert lab.core_decisions.core_decision_payload(event) is returned
            assert rows[3]["event"] == event
            assert rows[3]["core_event_key"] == "a" * 64 and rows[3]["trace_id"] == "core-test"
    assert calls == [event] and calls[0] is event
    assert lab.core_decisions.core_decision_payload is payload


def test_proxy_waits_for_same_real_lock_and_restores_original_exception():
    primitive = threading.Lock()
    tracker = lab.Control(recipe("recorder_lock_delay"))
    proxy = lab.LockProxy(primitive, lab.NoRecording(), "recorder.lock", tracker=tracker)
    done = threading.Event()
    primitive.acquire()

    def receiver():
        with proxy:
            done.set()

    worker = threading.Thread(target=receiver, name="notification-producer-unit")
    try:
        worker.start()
        assert tracker.attempt.wait(1)
        assert not done.is_set()
        primitive.release()
        assert done.wait(1)
    finally:
        if primitive.locked():
            primitive.release()
        worker.join(timeout=1)
    assert not worker.is_alive()
    assert tracker.data["target_attempt_ns"] <= tracker.data["target_entered_ns"] <= tracker.data["target_return_ns"]
    with pytest.raises(RuntimeError):
        proxy.release()  # Original unlocked-lock exception is preserved.


def test_unrelated_held_lock_cannot_be_reported_as_target_lock_dependency():
    unrelated, actual = threading.Lock(), threading.Lock()
    tracker = lab.Control(recipe("unrelated_lock_negative"))
    proxy = lab.LockProxy(actual, lab.NoRecording(), "recorder.lock", tracker=tracker)
    unrelated.acquire()
    try:
        assert proxy.acquire(blocking=False) is True
        assert unrelated.locked() and actual.locked()
        proxy.release()
    finally:
        unrelated.release()


def test_selected_return_requires_same_attempt_token_and_native_tid():
    primitive = threading.Lock()
    tracker = lab.Control(recipe("recorder_lock_delay"))
    proxy = lab.LockProxy(primitive, lab.NoRecording(), "recorder.lock", tracker=tracker)
    primitive.acquire()
    selected_done, other_done = threading.Event(), threading.Event()

    def selected():
        with proxy:
            selected_done.set()

    def other():
        assert proxy.acquire(blocking=False) is False
        other_done.set()

    first = threading.Thread(target=selected, name="notification-producer-selected")
    second = threading.Thread(target=other, name="notification-producer-other")
    try:
        first.start()
        assert tracker.attempt.wait(1)
        second.start()
        assert other_done.wait(1)
        assert tracker.data["target_return_ns"] is None
        tracker.first_return(tracker.selected_attempt)  # Correct token, WRONG native TID.
        assert tracker.data["target_return_ns"] is None
        primitive.release()
        assert selected_done.wait(1) and tracker.selected_return.wait(1)
    finally:
        if primitive.locked():
            primitive.release()
        first.join(timeout=1)
        second.join(timeout=1)
    assert tracker.data["target_return_token"] == tracker.data["target_attempt_token"]
    assert tracker.data["target_return_native_tid"] == tracker.data["target_native_tid"]


@pytest.mark.parametrize("probe", ["fstat", "exists", "stat"])
@pytest.mark.parametrize("raises", [False, True])
def test_fsync_probe_failure_still_delegates_original_once(probe, raises):
    calls, returned = [], object()
    failure = OSError(5, "SYNTHETIC original fsync failure")

    def fstat(fd):
        if probe == "fstat":
            raise PermissionError("SYNTHETIC probe denied")
        return SimpleNamespace(st_dev=1, st_ino=2)

    def exists():
        if probe == "exists":
            raise PermissionError("SYNTHETIC probe denied")
        return True

    def named_stat():
        raise PermissionError("SYNTHETIC probe denied")

    def fsync(fd):
        calls.append(fd)
        if raises:
            raise failure
        return returned

    control = lab.Control(recipe("writer_fsync_hold"))
    proxy = lab.FsyncProxy(SimpleNamespace(fstat=fstat, fsync=fsync),
        SimpleNamespace(path=SimpleNamespace(exists=exists, stat=named_stat)), lab.NoRecording(), control)
    if raises:
        with pytest.raises(OSError) as caught:
            proxy.fsync(123)
        assert caught.value is failure
    else:
        assert proxy.fsync(123) is returned
    assert calls == [123]
    assert control.data["fsync_probe_errors"] == ["PermissionError"]
    assert not control.fsync_entered.is_set()


def test_fixture_delay_calls_same_original_read_once_per_request(tmp_path):
    path = tmp_path / "fixture.json"
    path.write_text('{"SYNTHETIC":true}\n')
    calls = []

    def read_text(*args, **kwargs):
        calls.append((args, kwargs))
        return path.read_text(*args, **kwargs)

    control = lab.Control(recipe("fixture_delay"))
    proxy = lab.FixtureProxy(SimpleNamespace(read_text=read_text), lab.NoRecording(), control)
    assert proxy.read_text(encoding="utf-8") == path.read_text()
    first = dict(control.data)
    assert proxy.read_text(encoding="utf-8") == path.read_text()
    assert control.data == first
    assert calls == [((), {"encoding": "utf-8"})] * 2
    assert first["target_attempt_ns"] <= first["held_ns"] <= first["release_ns"] <= first["target_return_ns"]
    assert first["target_outcome"] == "returned"


def test_logging_delay_requires_the_original_overflow_call_and_preserves_return():
    returned = object()
    calls = []

    def error(*args, **kwargs):
        calls.append((args, kwargs))
        return returned

    control = lab.Control(recipe("logging_delay"))
    proxy = lab.LoggerProxy(SimpleNamespace(error=error), lab.NoRecording(), control)
    assert proxy.error("unrelated error") is returned
    assert control.data["target_attempt_ns"] is None
    message = "core decision hand-off full; P0 decision %s not recorded now"
    assert proxy.error(message, "test-key") is returned
    assert len(calls) == 2 and calls[-1] == ((message, "test-key"), {})
    assert control.data["target_outcome"] == "returned"


def test_lock_hooks_do_not_consume_logging_control_selection(monkeypatch):
    calls = []
    monkeypatch.setattr(lab.core_decisions, "_LOG", SimpleNamespace(error=lambda *args, **kwargs: calls.append(args)))
    receiver = SimpleNamespace(_lock=threading.Lock(), _pending=SimpleNamespace(put_nowait=lambda item: None),
                               _record=lambda *args: True)
    audit = SimpleNamespace(_lock=threading.Lock(), log_reporting_durability=lambda *args, **kwargs: None)
    control = lab.Control(recipe("logging_delay"))
    with ExitStack() as stack:
        lab.Hooks(stack, receiver, lab.NoRecording(), audit, receiver, control, {})
        with receiver._lock:
            pass
        assert control.data["target_attempt_ns"] is None
        lab.core_decisions._LOG.error("core decision hand-off full; P0 decision %s not recorded now", "SYNTHETIC")
    assert len(calls) == 1
    assert control.data["target_object_id"] == "original.overflow.error"
    assert control.data["status"] == "observed_intervention"


def test_fsync_control_is_real_matching_inode_and_releases_in_finally(tmp_path):
    path = tmp_path / "audit"
    path.write_bytes(b"SYNTHETIC durable write\n")
    control = lab.Control(recipe("writer_fsync_hold"))
    proxy = lab.FsyncProxy(os, SimpleNamespace(path=path), lab.NoRecording(), control)
    fd = os.open(path, os.O_RDONLY)
    returned = threading.Event()

    def writer():
        proxy.fsync(fd)
        returned.set()

    thread = threading.Thread(target=writer)
    try:
        thread.start()
        assert control.fsync_entered.wait(1)
        assert not returned.is_set()
        assert control.data["audit_inode"] == path.stat().st_ino
    finally:
        control.release_fsync.set()
        thread.join(timeout=1)
        os.close(fd)
    assert returned.is_set() and not thread.is_alive()


def test_disabled_scheduler_emits_explicit_unmeasured_without_original_workload(tmp_path, monkeypatch):
    class DiagnosticRecorder(lab.NoRecording):
        def __init__(self, path, **kwargs):
            Path(path).write_bytes(b"SYNTHETIC trace\n")

        def finish(self):
            pass

    def forbidden(*args, **kwargs):
        raise AssertionError("disabled scheduler must not create a workload")

    monkeypatch.setattr(lab, "NotificationRecording", DiagnosticRecorder)
    monkeypatch.setattr(lab, "scheduler_snapshot", lambda: {"schedstats_raw": "0\n", "error": None})
    monkeypatch.setattr(lab, "P0AuditLogger", forbidden)
    monkeypatch.setattr(lab, "_scheduler_control", forbidden)
    result = lab.collect_case(tmp_path, recipe("scheduler_contention"), {})
    original = result["original"]
    assert set(original) == {"schema_version", "case_id", "assigned_events", "completed_submissions",
                             "metrics", "audit_raw", "queue_raw", "control", "collection_errors"}
    assert original["metrics"] is original["audit_raw"] is original["queue_raw"] is None
    assert original["completed_submissions"] == 0 and original["assigned_events"] == 1
    assert original["control"]["status"] == "unmeasured_scheduler_enablement"
    assert original["control"]["workload_started"] is False
    assert original["collection_errors"] == {}
    assert not (tmp_path / "scheduler_contention.audit.raw").exists()
    assert not (tmp_path / "scheduler_contention.queue.raw").exists()
    assert json.loads((tmp_path / "scheduler_contention.event-index.json").read_bytes())["events"] == []


@pytest.mark.parametrize("ready", [True, False])
def test_enabled_scheduler_uses_frozen_cpu_budgets_and_bounded_handshake_without_launch(monkeypatch, ready):
    calls = []

    class Child:
        stdout = io.BytesIO(b'{"ready_ns":1,"uid":1000,"pid":99}\n')
        returncode = 0

        def communicate(self, timeout):
            assert timeout == 30
            return b'{"start_ns":1,"end_ns":2,"cpu_start_ns":0,"cpu_end_ns":100000000}', b""

        def poll(self):
            return 0 if ready else None

        def kill(self):
            calls.append("kill")

        def wait(self, timeout):
            calls.append("wait")

    def launch(argv, **kwargs):
        calls.append("launch")
        tree = ast.parse(argv[2])
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exec":
                compile(ast.literal_eval(node.args[0]), "SYNTHETIC-competitor", "exec")
        assert "thread_time_ns()-cpu<100000000" in argv[2]
        return Child()

    class Selector:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def register(self, *args):
            pass

        def select(self, timeout):
            assert timeout == 30
            return [True] if ready else []

    values = iter([0, 50_000_000, 50_000_000])
    monkeypatch.setattr(lab, "subprocess", SimpleNamespace(Popen=launch, PIPE=-1))
    monkeypatch.setattr(lab, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1))
    monkeypatch.setattr(lab, "time", SimpleNamespace(monotonic_ns=lambda: 1, thread_time_ns=lambda: next(values)))
    control = lab.Control(recipe("scheduler_contention"))
    if ready:
        lab._scheduler_control(lab.NoRecording(), control)
        assert calls == ["launch"]
        assert control.data["observed_cpu_end_ns"] - control.data["observed_cpu_start_ns"] == 50_000_000
    else:
        with pytest.raises(TimeoutError):
            lab._scheduler_control(lab.NoRecording(), control)
        assert calls == ["launch", "kill", "wait"]


def test_runner_preserves_originals_before_analysis_continues_siblings_and_refuses_overwrite(tmp_path, monkeypatch):
    called, analyzed = [], []

    def collect(output, assigned, metadata):
        identifier = assigned["id"]
        called.append(identifier)
        if identifier == "fixture_delay":
            raise OSError("SYNTHETIC case failure")
        value = {"SYNTHETIC": identifier}
        lab.save(output / (identifier + ".original-result.json"), lab.canonical(value))
        lab.save(output / (identifier + ".event-index.json"), lab.canonical({"events": []}))
        return dict(expected={"SYNTHETIC": True}, original={"collection_errors": {}})

    def analyze(trace, *, expected, event_index_raw, original_result_raw):
        analyzed.append(original_result_raw)
        if original_result_raw is not None:
            value = json.loads(original_result_raw)
            assert (tmp_path / "public" / (value["SYNTHETIC"] + ".original-result.json")).read_bytes() == original_result_raw
        return dict(historical_cause="UNKNOWN", status="SYNTHETIC", **runner.FLAGS)

    monkeypatch.setattr(runner, "collect_case", collect)
    monkeypatch.setattr(runner, "analyze_notification_timing", analyze)
    monkeypatch.setattr(runner, "process_boundary", lambda: {"SYNTHETIC": True})
    result = runner.run(tmp_path / "public")
    assert called == [item["id"] for item in json.loads(lab.PROTOCOL.read_bytes())["cases"]]
    assert len(called) == len(set(called)) == len(analyzed) == 11
    assert any("fixture_delay:collection_failed:OSError" == error for error in result["blockers"])
    assert (tmp_path / "public/legacy_original.original-result.json").is_file()
    assert (tmp_path / "public/trace_loss.original-result.json").is_file()
    manifest = json.loads((tmp_path / "public/manifest.json").read_bytes())
    assert manifest["files"]["fixture_delay.original-result.json"] is None
    assert manifest["files"]["legacy_original.trace.jsonl"] is None
    assert all("/" not in name for name in manifest["files"])
    before = list(called)
    with pytest.raises(FileExistsError):
        runner.run(tmp_path / "public")
    assert called == before


@pytest.mark.parametrize("counter,status", [(17, "observed_positive_identity_bound_counter"),
    (0, "unexercised_zero_counter"), (None, "unmeasured_counter_unavailable"),
    (True, "unmeasured_counter_unavailable")])
def test_scheduler_summary_is_derived_without_rewriting_saved_original(counter, status):
    analysis = {"completed_spans": [{"phase": "scheduler_control", "scheduler": {"qualified_runqueue_wait_ns": counter}}],
                "original_result": {"control": {"status": "workload_only_not_acceptance"}}}
    before = deepcopy(analysis)
    assert runner.scheduler_control_summary(analysis)["status"] == status
    assert analysis == before


def test_constructor_failure_stops_existing_relay_and_aborts_without_end(tmp_path, monkeypatch):
    calls = []
    stopped = threading.Event()

    class DiagnosticRecorder(lab.NoRecording):
        def __init__(self, path, **kwargs):
            self.path = Path(path)
            self.path.write_bytes(b"SYNTHETIC header prefix\n")

        def finish(self):
            calls.append("FAKE_END_FORBIDDEN")

        def abort(self):
            calls.append("abort")
            self.incomplete = True

    class Audit:
        _durable_handed = _durable_delivered = 0
        _durable_handoff = []
        _durable_dispatcher = None

        def __init__(self, path):
            self.path = path
            path.write_bytes(b"SYNTHETIC partial audit\n")

        def wait_durable_listeners(self, timeout):
            return True

    class Relay:
        def __init__(self, path):
            path.write_bytes(b"SYNTHETIC partial queue\n")
            self._thread = threading.Thread(target=lambda: stopped.wait(), daemon=True)
            self._thread.start()

        def stop(self, timeout):
            calls.append("relay_stop")
            stopped.set()
            self._thread.join(timeout=timeout)

    def attach(audit, path):
        audit._p0_alert_relay = Relay(path)
        return audit._p0_alert_relay

    def constructor(*args, **kwargs):
        calls.append("constructor")
        raise OSError("SYNTHETIC constructor failure")

    monkeypatch.setattr(lab, "NotificationRecording", DiagnosticRecorder)
    monkeypatch.setattr(lab, "P0AuditLogger", Audit)
    monkeypatch.setattr(lab, "attach_p0_alert_relay", attach)
    monkeypatch.setattr(lab.core_decisions, "CoreDecisionRecorder", constructor)
    result = lab.collect_case(tmp_path, recipe("legacy_instrumented"), {})
    assert calls == ["constructor", "relay_stop", "abort"]
    assert stopped.is_set() and result["safe_to_continue"] is True
    original = result["original"]
    assert original["metrics"] is None and original["completed_submissions"] == 0
    assert original["collection_errors"]["case"] == "OSError"
    assert original["control"]["recorder_joined"] is None
    assert original["control"]["relay_joined"] is True
    assert original["audit_raw"] == "SYNTHETIC partial audit\n"
    assert original["queue_raw"] == "SYNTHETIC partial queue\n"
    assert (tmp_path / "legacy_instrumented.trace.jsonl").read_bytes() == b"SYNTHETIC header prefix\n"


def test_live_worker_keeps_hooks_and_private_originals_until_real_join():
    state = {"quiescent": False}
    target = SimpleNamespace(value="original")
    stop = threading.Event()
    thread = threading.Thread(target=lambda: stop.wait(), daemon=True)
    thread.start()
    retained_before = len(lab.RETAINED_UNFINISHED_CASES)
    try:
        with lab.case_resources(state) as (work, resources):
            from unittest.mock import patch
            resources.enter_context(patch.object(target, "value", "hook_still_held"))
            private = Path(work)
            (private / "partial").write_bytes(b"SYNTHETIC retained original")
            relay = SimpleNamespace(_thread=thread, stop=lambda timeout: None)
            state.update(lab.cleanup_workers(lab.Control(recipe("legacy_instrumented")), {}, [], None, None,
                                            relay, threading.Event(), None))
        assert state["quiescent"] is False
        assert private.exists() and target.value == "hook_still_held"
        assert len(lab.RETAINED_UNFINISHED_CASES) == retained_before + 1
    finally:
        stop.set()
        thread.join(timeout=1)
        while len(lab.RETAINED_UNFINISHED_CASES) > retained_before:
            lab.RETAINED_UNFINISHED_CASES.pop().close()
    assert target.value == "original" and not private.exists()


def test_runner_stops_new_workloads_after_unfinished_case(tmp_path, monkeypatch):
    called = []

    def collect(output, assigned, metadata):
        called.append(assigned["id"])
        return dict(expected=None, safe_to_continue=False, original={"collection_errors": {"workers": "still_alive"}})

    monkeypatch.setattr(runner, "collect_case", collect)
    monkeypatch.setattr(runner, "process_boundary", lambda: {"SYNTHETIC": True})
    result = runner.run(tmp_path / "public")
    assert called == ["legacy_original"]
    assert len(result["cases"]) == 11
    assert all(case["collection_error"] == "not_run_prior_unfinished_workers" for case in result["cases"][1:])


def test_save_failure_after_retention_still_halts_all_later_workloads(tmp_path, monkeypatch):
    from unittest.mock import patch

    called, private_paths = [], []
    target = SimpleNamespace(value="original")
    stop = threading.Event()
    worker = threading.Thread(target=lambda: stop.wait(), daemon=True)
    retained_before = len(lab.RETAINED_UNFINISHED_CASES)
    worker.start()

    def collect(output, assigned, metadata):
        called.append(assigned["id"])
        state = {"quiescent": not worker.is_alive()}
        with lab.case_resources(state) as (work, resources):
            private = Path(work)
            private_paths.append(private)
            resources.enter_context(patch.object(target, "value", "live_hook"))
            (private / "partial-original").write_bytes(b"SYNTHETIC unfinished original")
            lab.save(output / (assigned["id"] + ".audit.raw"), b"SYNTHETIC public prefix\n")
            lab.save(output / (assigned["id"] + ".original-result.json"), b'{"SYNTHETIC":"prior partial receipt"}\n')
        assert lab.has_retained_unfinished_resources()
        # Exact failure location: after the resource context, before returning
        # safe_to_continue=False to the runner.
        lab.save(output / (assigned["id"] + ".original-result.json"), b"must never overwrite")

    monkeypatch.setattr(runner, "collect_case", collect)
    monkeypatch.setattr(runner, "process_boundary", lambda: {"SYNTHETIC": True})
    try:
        result = runner.run(tmp_path / "public")
        assert called == ["legacy_original"]
        assert result["cases"][0]["collection_error"] == "FileExistsError"
        assert all(case["collection_error"] == "not_run_prior_unfinished_workers" for case in result["cases"][1:])
        assert (tmp_path / "public/legacy_original.audit.raw").read_bytes() == b"SYNTHETIC public prefix\n"
        assert (tmp_path / "public/legacy_original.original-result.json").read_bytes() == b'{"SYNTHETIC":"prior partial receipt"}\n'
        assert private_paths[0].exists() and target.value == "live_hook" and worker.is_alive()
        assert (tmp_path / "public/manifest.json").is_file()
    finally:
        stop.set()
        worker.join(timeout=1)
        while len(lab.RETAINED_UNFINISHED_CASES) > retained_before:
            lab.RETAINED_UNFINISHED_CASES.pop().close()
    assert target.value == "original" and not private_paths[0].exists()
