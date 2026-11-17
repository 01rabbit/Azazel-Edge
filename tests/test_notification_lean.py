"""Synthetic deferred-recorder/parser checks; no actual pilot or latency gate."""

from copy import deepcopy
import json
import threading

import pytest

from azazel_edge.benchmark import notification_lean as a
from azazel_edge.benchmark.notification_timing import _wire
import p0_handoff_lean_recording as r
from test_notification_timing import _with_protocol, sha, rows_wire as old_rows_wire


def wire(value):
    return _wire(value)


def fixture():
    old, expected, index, original = _with_protocol(
        r.UNDERLYING_PROTOCOL_SHA256, "historical_slow_fsync_instrumented"
    )
    header = dict(
        old[0][1],
        study_protocol_sha256=r.STUDY_PROTOCOL_SHA256,
        capture_profile=r.SCHEMA,
    )
    header["limits"] = dict(
        max_rows=8192,
        max_bytes=16777216,
        max_threads=16,
        max_events=120,
        max_depth=16,
        slots_per_thread=480,
    )
    thread = dict(
        logical_thread_token=1,
        native_tid=789,
        task_start_ticks=None,
        thread_name="SYNTHETIC",
        identity_scope="strong_python_Thread_object_native_tid_not_kernel_incarnation",
    )
    oldspan = old[4][1]
    span = {
        key: oldspan[key]
        for key in (
            "span_id",
            "parent_id",
            "phase",
            "object_id",
            "event_index",
            "start_ns",
            "end_ns",
            "thread_cpu_start_ns",
            "thread_cpu_end_ns",
            "process_cpu_start_ns",
            "process_cpu_end_ns",
            "outcome",
        )
    }
    span.update(
        logical_thread_token=1,
        native_tid_start=789,
        native_tid_end=789,
        complete=True,
        error=None,
    )
    rows = [
        ("header", header),
        ("thread", thread),
        ("event", old[2][1]),
        ("span", span),
        (
            "end",
            dict(
                normal_return=True,
                active_spans=0,
                incomplete=False,
                quiescent=True,
                flush_start_ns=1000,
                flush_before_end_ns=1100,
            ),
        ),
    ]
    original = json.loads(original)
    original["control"] = dict(
        instrumented_workers_joined=True,
        producers_joined=True,
        callbacks_quiescent=True,
        recording_finish_begin_ns=900,
        recording_finish_end_ns=1200,
        recording_incomplete=False,
        recorder_close_error=None,
        recorder_descriptor_closed=True,
    )
    original = wire(original)
    expected["original_result_sha256"] = sha(original)
    return rows, expected, index, original


def rows_wire(rows):
    previous = "0" * 64
    output = []
    for seq, (kind, data) in enumerate(rows, 1):
        raw = wire(
            dict(schema_version=r.SCHEMA, seq=seq, prev=previous, kind=kind, data=data)
        )
        output.append(raw)
        previous = sha(raw)
    return b"".join(output)


def analyze(value, raw=None, **kwargs):
    rows, expected, index, original = value
    return a.analyze_notification_lean(
        rows_wire(rows) if raw is None else raw,
        expected=expected,
        event_index_raw=index,
        original_result_raw=original,
        **kwargs,
    )


def metadata():
    return {key: fixture()[1]["header"][key] for key in r.META}


class Proxy:
    def __init__(self, original, **overrides):
        self.original, self.overrides = original, overrides

    def __getattr__(self, name):
        return (
            self.overrides[name]
            if name in self.overrides
            else getattr(self.original, name)
        )


def test_valid_nested_logical_spans_are_not_kernel_or_scheduler_evidence():
    value = fixture()
    parent = value[0][3][1]
    child = dict(
        parent,
        span_id=2,
        parent_id=1,
        phase="payload",
        start_ns=20,
        end_ns=90,
        thread_cpu_start_ns=21,
        thread_cpu_end_ns=29,
        process_cpu_start_ns=41,
        process_cpu_end_ns=59,
    )
    value[0].insert(4, ("span", child))
    before = deepcopy(value)
    result = analyze(value)
    assert result["status"] == "complete_descriptive_trace"
    assert len(result["completed_spans"]) == 2
    assert all(
        span["scheduler"]["qualified_runqueue_wait_ns"] is None
        for span in result["completed_spans"]
    )
    assert all(
        span["residual_cause"] == "UNCLASSIFIED" for span in result["completed_spans"]
    )
    assert result["kernel_thread_identity"].startswith("UNESTABLISHED")
    assert result["finalization"]["elapsed_ns"] == 300
    assert result["comparison_qualified"] is result["production_admission"] is False
    assert (
        result["qualified_safety_count"] is None
        and result["historical_cause"] == "UNKNOWN"
    )
    assert value == before and result == analyze(value)


@pytest.mark.parametrize(
    "fault",
    [
        "run",
        "source",
        "profile",
        "study",
        "original_pin",
        "event_key",
        "unknown",
        "duplicate",
        "reorder",
        "missingclock",
        "regress",
        "thread_cpu",
        "taskstart",
        "token",
        "parent",
        "depth",
        "capacity",
    ],
)
def test_strict_new_profile_does_not_accept_modified_or_v1_material(fault):
    value = fixture()
    rows, expected, index, original = value
    if fault == "run":
        rows[0][1]["run_id"] = "OTHER"
    elif fault == "source":
        rows[0][1]["source_inventory_sha256"] = "a" * 64
    elif fault == "profile":
        rows[0][1]["capture_profile"] = "edge-notification-timing/v1"
    elif fault == "study":
        return_result = analyze(value, study_protocol_sha256="a" * 64)
    elif fault == "original_pin":
        expected["original_result_sha256"] = "a" * 64
    elif fault == "event_key":
        rows[2][1]["core_event_key"] = "a" * 64
    elif fault == "unknown":
        rows[3][1]["scheduler_delta_ns"] = 0
    elif fault == "duplicate":
        rows.insert(4, deepcopy(rows[3]))
    elif fault == "reorder":
        rows[3], rows[1] = rows[1], rows[3]
    elif fault == "missingclock":
        rows[3][1]["end_ns"] = None
    elif fault == "regress":
        rows[3][1]["end_ns"] = 0
    elif fault == "thread_cpu":
        rows[3][1]["thread_cpu_end_ns"] = 0
    elif fault == "taskstart":
        rows[1][1]["task_start_ticks"] = 999
    elif fault == "token":
        rows[3][1]["logical_thread_token"] = True
    elif fault == "parent":
        rows[3][1]["parent_id"] = 1
    elif fault == "depth":
        d = 1
        for _ in range(17):
            d = [d]
        rows[3][1]["unknown"] = d
    else:
        rows[0][1]["limits"]["max_rows"] = 4
    result = return_result if fault == "study" else analyze(value)
    assert result["status"] != "complete_descriptive_trace" and result["reasons"]
    if fault == "event_key":
        assert len(result["completed_spans"]) == 1
        assert result["completed_spans"][0]["event_correlation"] == "unavailable"


def test_v1_schema_is_never_implicitly_converted():
    old, expected, index, original = _with_protocol(
        r.UNDERLYING_PROTOCOL_SHA256, "historical_slow_fsync_instrumented"
    )
    result = a.analyze_notification_lean(
        old_rows_wire(old),
        expected=expected,
        event_index_raw=index,
        original_result_raw=original,
    )
    assert result["status"] == "withheld" and result["completed_spans"] == []


def test_valid_prefix_survives_later_corruption_and_dense_tail():
    value = fixture()
    result = analyze(value, rows_wire(value[0][:-1]) + b"\n" * 100000)
    assert result["status"] == "partial_prefix"
    assert len(result["completed_spans"]) == 1 and result["valid_prefix_rows"] == 4


def test_logical_tokens_do_not_collapse_reused_native_tid():
    value = fixture()
    thread = dict(value[0][1][1], logical_thread_token=2, thread_name="OTHER")
    second = dict(value[0][3][1], logical_thread_token=2)
    value[0].insert(2, ("thread", thread))
    value[0].insert(5, ("span", second))
    result = analyze(value)
    assert result["status"] == "complete_descriptive_trace"
    assert [span["logical_thread_token"] for span in result["completed_spans"]] == [
        1,
        2,
    ]
    assert all(
        span["thread_identity"] == "logical_python_thread_only"
        for span in result["completed_spans"]
    )


def test_prepared_capture_does_no_observer_io_json_hash_or_global_lock(
    tmp_path, monkeypatch
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    recorder.prepare_thread()
    value = json.loads(fixture()[2])["events"][0]
    key = {k: value[k] for k in ("core_event_key", "trace_id")}
    real_os, real_json, real_hashlib = r.os, r.json, r.hashlib
    fd = real_os.open(
        tmp_path / "original-audit", real_os.O_CREAT | real_os.O_WRONLY, 0o600
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("forbidden observer work")

    with monkeypatch.context() as patch:
        patch.setattr(
            r, "os", Proxy(real_os, write=forbidden, open=forbidden, stat=forbidden)
        )
        patch.setattr(r, "json", Proxy(real_json, dumps=forbidden))
        patch.setattr(r, "hashlib", Proxy(real_hashlib, sha256=forbidden))
        patch.setattr(r, "process_identity", forbidden)

        def original_audit():
            return real_os.write(fd, real_json.dumps({"original": "audit"}).encode())

        recorder.bind_event(0, value["event"], key)
        with recorder.event_context(0):
            assert recorder.call("audit_save", original_audit) > 0
        assert not hasattr(recorder, "lock")
        with pytest.raises(AssertionError):
            r.canonical({"deliberately_eager_negative": True})
    real_os.close(fd)
    assert not (tmp_path / "trace").exists()
    recorder.finish(quiescent=True)
    assert recorder.closed and not recorder.incomplete


def test_unprepared_thread_delegates_without_lazy_identity_fallback(
    tmp_path, monkeypatch
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    monkeypatch.setattr(
        r, "process_identity", lambda: (_ for _ in ()).throw(AssertionError("lazyproc"))
    )
    calls = []
    assert recorder.call("submit", lambda: calls.append(1) or 9) == 9
    assert calls == [1] and recorder.incomplete and not any(recorder.used)
    recorder.abort(quiescent=True)
    assert not any(
        json.loads(line)["kind"] == "end"
        for line in (tmp_path / "trace").read_bytes().splitlines()
    )


def test_real_thread_objects_with_same_native_id_keep_distinct_tokens(
    tmp_path, monkeypatch
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    monkeypatch.setattr(r, "threading", Proxy(threading, get_native_id=lambda: 999))

    def worker():
        recorder.prepare_thread()
        recorder.call("submit", lambda: None)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
        thread.join()
    recorder.finish(quiescent=True)
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    owners = [row["data"] for row in rows if row["kind"] == "thread"]
    assert len(owners) == 2 and {row["native_tid"] for row in owners} == {999}
    assert len({row["logical_thread_token"] for row in owners}) == 2
    assert recorder.owners[0] is threads[0] and recorder.owners[1] is threads[1]


@pytest.mark.parametrize("fault", ["start", "end", "overflow"])
def test_observer_failure_preserves_exact_original_return_exception_multiplicity(
    tmp_path, monkeypatch, fault
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    recorder.prepare_thread()
    if fault in ("start", "end"):
        monkeypatch.setattr(
            r,
            "_clocks" if fault == "start" else "_end_clocks",
            lambda: (_ for _ in ()).throw(OSError("clock")),
        )
    else:
        for _ in range(r.SLOTS):
            recorder.call("submit", lambda: None)
    calls = []
    token = object()

    def original():
        calls.append(1)
        return token

    assert recorder.call("submit", original) is token
    failure = KeyError("exactoriginal")

    def raised():
        calls.append(2)
        raise failure

    with pytest.raises(KeyError) as seen:
        recorder.call("submit", raised)
    assert seen.value is failure and calls == [1, 2]
    recorder.abort(quiescent=True)
    assert recorder.incomplete
    if fault != "overflow":
        rows = [
            json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()
        ]
        spans = [row["data"] for row in rows if row["kind"] == "span"]
        assert all(span["complete"] is False for span in spans)
        assert all(
            span["start_ns" if fault == "start" else "end_ns"] is None for span in spans
        )


def test_explicit_quiescence_and_no_active_span_required_before_any_flush(tmp_path):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    recorder.prepare_thread()
    ctx = recorder.span("submit")
    ctx.__enter__()
    recorder.abort()
    recorder.finish(quiescent=True)
    assert not (tmp_path / "trace").exists() and not recorder.closed
    ctx.__exit__(None, None, None)
    recorder.abort(quiescent=True)
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    assert any(row["kind"] == "span" for row in rows) and not any(
        row["kind"] == "end" for row in rows
    )
    other = r.LeanRecording(tmp_path / "early", metadata=metadata())
    other.prepare_thread()
    other.call("submit", lambda: None)
    other.finish()
    assert other.incomplete and not (tmp_path / "early").exists()


@pytest.mark.parametrize("fault", ["short_write", "close"])
def test_flush_failures_preserve_prefix_and_unknown_descriptor_state(
    tmp_path, monkeypatch, fault
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    recorder.prepare_thread()
    recorder.call("submit", lambda: None)
    real_os = r.os

    def short_write(fd, raw):
        return 0

    def close_error(fd):
        real_os.close(fd)
        raise OSError(5, "SYNTHETIC afterclose")

    monkeypatch.setattr(
        r,
        "os",
        Proxy(
            real_os,
            **(
                {"write": short_write}
                if fault == "short_write"
                else {"close": close_error}
            ),
        ),
    )
    recorder.finish(quiescent=True)
    assert recorder.incomplete and recorder.closed
    if fault == "close":
        assert (
            recorder.close_error == dict(type="OSError", errno=5)
            and recorder.descriptor_closed is None
        )
    else:
        assert recorder.finalization["error"] == "OSError"
    recorder.finish(quiescent=True)  # Never retry an uncertain numeric descriptor.


def test_thread_pool_capacity_keeps_exact_original_calls_and_unknown_unassigned_loss(
    tmp_path,
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    calls = []

    def worker():
        recorder.prepare_thread()
        recorder.call("submit", lambda: calls.append(1))

    workers = [threading.Thread(target=worker) for _ in range(17)]
    for worker_thread in workers:
        worker_thread.start()
        worker_thread.join()
    assert (
        len(calls) == 17 and sum(owner is not None for owner in recorder.owners) == 16
    )
    assert sum(recorder.used) == 16 and recorder.lost_rows is None
    recorder.abort(quiescent=True)
    assert not any(
        json.loads(line)["kind"] == "end"
        for line in (tmp_path / "trace").read_bytes().splitlines()
    )


@pytest.mark.parametrize("fault", ["descriptor", "quiescence", "flush_bracket"])
def test_outer_completion_premises_are_required_even_with_valid_end(fault):
    rows, expected, index, original = fixture()
    value = json.loads(original)
    if fault == "descriptor":
        value["control"]["recorder_descriptor_closed"] = None
    elif fault == "quiescence":
        value["control"]["callbacks_quiescent"] = False
    else:
        value["control"]["recording_finish_end_ns"] = 1050
    original = wire(value)
    expected["original_result_sha256"] = sha(original)
    result = analyze((rows, expected, index, original))
    assert (
        result["status"] == "partial_prefix"
        and result["normal_return_confirmed"] is False
    )
    assert len(result["completed_spans"]) == 1


@pytest.mark.parametrize("clock", ["wall", "thread_cpu", "process_cpu"])
def test_child_clock_outside_parent_keeps_parent_prefix(clock):
    value = fixture()
    parent = value[0][3][1]
    child = dict(
        parent,
        span_id=2,
        parent_id=1,
        phase="payload",
        start_ns=20,
        end_ns=90,
        thread_cpu_start_ns=21,
        thread_cpu_end_ns=29,
        process_cpu_start_ns=41,
        process_cpu_end_ns=59,
    )
    end = "end_ns" if clock == "wall" else clock + "_end_ns"
    child[end] = parent[end] + 1
    value[0].insert(4, ("span", child))
    result = analyze(value)
    assert result["status"] == "partial_prefix" and len(result["completed_spans"]) == 1
    assert any(
        "lean_child_clock_outside_parent" in reason for reason in result["reasons"]
    )


def test_recorder_roundtrip_deferred_event_mutation_is_uncorrelated(tmp_path):
    rows, expected, index, original = fixture()
    before = r.process_identity()
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    recorder.prepare_thread()
    event_row = json.loads(index)["events"][0]
    event = event_row["event"]
    recorder.bind_event(
        0, event, {key: event_row[key] for key in ("core_event_key", "trace_id")}
    )
    with recorder.event_context(0):
        recorder.call("submit", lambda: None)
    # Non-key content can mutate; deferred hashing must not silently pretend it
    # is the independent original event bytes.
    event["new_content_after_call"] = "SYNTHETIC mutation"
    begin = r.time.monotonic_ns()
    recorder.finish(quiescent=True)
    end = r.time.monotonic_ns()
    value = json.loads(original)
    value["control"].update(
        recording_finish_begin_ns=begin, recording_finish_end_ns=end
    )
    original = wire(value)
    expected["original_result_sha256"] = sha(original)
    expected["header"].update(before)
    result = analyze(
        (rows, expected, index, original), raw=(tmp_path / "trace").read_bytes()
    )
    assert result["status"] == "partial_prefix" and len(result["completed_spans"]) == 1
    assert result["completed_spans"][0]["event_correlation"] == "unavailable"
    assert "event_binding_differs:0" in result["reasons"]


@pytest.mark.parametrize("failure_call", [1, 3])
def test_finish_clock_failure_retains_null_endpoint_and_original_calls(
    tmp_path, monkeypatch, failure_call
):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    recorder.prepare_thread()
    token, calls = object(), []

    def original():
        calls.append(1)
        return token

    assert recorder.call("submit", original) is token
    real_time = r.time
    count = [0]

    def monotonic():
        count[0] += 1
        if count[0] == failure_call:
            raise OSError("SYNTHETIC finish clock failure")
        return real_time.monotonic_ns()

    with monkeypatch.context() as patch:
        patch.setattr(r, "time", Proxy(real_time, monotonic_ns=monotonic))
        recorder.finish(quiescent=True)
    assert (
        recorder.incomplete and recorder.closed and recorder.descriptor_closed is True
    )
    assert recorder.finalization["start_ns" if failure_call == 1 else "end_ns"] is None
    assert recorder.finalization["error"] == (
        "finish_start_clock_failure" if failure_call == 1 else "finish_clock_failure"
    )
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    assert any(row["kind"] == "span" for row in rows)
    if failure_call == 1:
        assert not any(row["kind"] == "end" for row in rows)
    # The END of a successful write precedes close/final clock; that raw prefix
    # is retained on a final-clock error and never upgraded via END alone.
    assert recorder.call("submit", original) is token and calls == [1, 1]
    failure = LookupError("exactoriginal")

    def raised():
        raise failure

    with pytest.raises(LookupError) as seen:
        recorder.call("submit", raised)
    assert seen.value is failure


def test_overlong_thread_name_is_refused_before_slot_claim_without_truncation(tmp_path):
    recorder = r.LeanRecording(tmp_path / "trace", metadata=metadata())
    calls = []

    def worker():
        assert recorder.prepare_thread() is None
        assert recorder.call("submit", lambda: calls.append(1) or 8) == 8

    thread = threading.Thread(target=worker, name="X" * 129)
    thread.start()
    thread.join()
    assert recorder.incomplete and recorder.lost_rows is None
    assert len(recorder.free) == 16 and all(owner is None for owner in recorder.owners)
    assert calls == [1]
    recorder.abort(quiescent=True)
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    assert not any(row["kind"] in ("thread", "end") for row in rows)
