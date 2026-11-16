"""Synthetic wire/API checks; no workload or historical cause measurement."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from azazel_edge.benchmark import notification_timing as a
from azazel_edge.notify.core_decisions import core_decision_payload, core_event_key
import p0_handoff_attribution_recording as r

BOOT = "00000000-0000-4000-8000-000000000001"
DOMAIN = dict(
    time_namespace_device=1,
    time_namespace_inode=2,
    timens_offsets=[
        dict(clock=c, seconds=0, nanoseconds=0) for c in ("monotonic", "boottime")
    ],
    established=True,
)
IDENTITY = dict(pid=123, process_start_ticks=456, boot_id=BOOT)
THREAD = dict(native_tid=789, task_start_ticks=987)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return a._wire(value)


def rows_wire(rows):
    previous = "0" * 64
    result = []
    for seq, (kind, data) in enumerate(rows, 1):
        raw = wire(
            dict(schema_version=a.SCHEMA, seq=seq, prev=previous, kind=kind, data=data)
        )
        result.append(raw)
        previous = sha(raw)
    return b"".join(result)


def snapshot(*, after=False):
    return dict(
        read_begin_ns=101 if after else 0,
        read_end_ns=102 if after else 1,
        **IDENTITY,
        **THREAD,
        schedstats_raw="1\n",
        schedstat_raw="15 17 2\n" if after else "5 7 1\n",
        runtime_ns=15 if after else 5,
        runqueue_wait_ns=17 if after else 7,
        timeslices=2 if after else 1,
        error=None,
    )


def fixture():
    raw = (Path(__file__).parent / "fixtures/rust_core_event_v1.json").read_bytes()
    event = json.loads(raw)
    built = core_decision_payload(event)
    key = dict(core_event_key=core_event_key(event), trace_id=built[0])
    metadata = dict(
        run_id="SYNTHETIC",
        case_id="legacy_instrumented",
        protocol_sha256=a.PROTOCOL_SHA256,
        source_inventory_sha256="1" * 64,
        fixture_sha256=sha(raw),
        interpreter_sha256="2" * 64,
    )
    header = dict(
        metadata,
        **IDENTITY,
        clock_domain=DOMAIN,
        resolutions={key: 1e-9 for key in ("monotonic", "thread_time", "process_time")},
        limits=dict(
            max_rows=8192,
            max_bytes=16777216,
            max_depth=16,
            max_events=120,
            max_threads=16,
        ),
    )
    binding = dict(index=0, event_sha256=sha(wire(event)), **key)
    intent = dict(
        span_id=1,
        parent_id=None,
        phase="submit",
        object_id="recorder",
        event_index=0,
        **THREAD,
    )
    span = dict(
        intent,
        outcome="returned",
        start_ns=10,
        end_ns=100,
        thread_cpu_start_ns=20,
        thread_cpu_end_ns=30,
        process_cpu_start_ns=40,
        process_cpu_end_ns=60,
        scheduler_before=snapshot(),
        scheduler_after=snapshot(after=True),
    )
    rows = [
        ("header", header),
        ("thread", dict(**IDENTITY, **THREAD, thread_name="synthetic-receiver")),
        ("event", binding),
        ("intent", intent),
        ("span", span),
        ("end", dict(normal_return=True, active_spans=0, incomplete=False)),
    ]
    index = wire(
        dict(
            schema_version="edge-notification-event-index/v1",
            events=[dict(binding, event=event)],
        )
    )
    original = wire(
        dict(
            schema_version="edge-notification-original-result/v1",
            case_id=metadata["case_id"],
            assigned_events=1,
            completed_submissions=1,
            metrics=dict(core_recorded_total=0, core_record_handoff_dropped_total=1),
            audit_raw="",
            queue_raw="",
            control={},
            collection_errors=[],
        )
    )
    expected = dict(
        header=dict(metadata, **IDENTITY, clock_domain=DOMAIN),
        event_index_sha256=sha(index),
        original_result_sha256=sha(original),
    )
    return rows, expected, index, original


def analyze(value, *, raw=None):
    rows, expected, index, original = value
    return a.analyze_notification_timing(
        rows_wire(rows) if raw is None else raw,
        expected=expected,
        event_index_raw=index,
        original_result_raw=original,
    )


def test_valid_completed_span_exact_event_and_scheduler_binding():
    value = fixture()
    before = deepcopy(value)
    report = analyze(value)
    assert report["status"] == "complete_descriptive_trace"
    assert report["normal_return_confirmed"] is True
    span = report["completed_spans"][0]
    assert span["event_correlation"] == "exact_original_event_key"
    assert span["elapsed_ns"] == 90 and span["thread_cpu_ns"] == 10
    assert span["wall_minus_thread_cpu_ns"] == 80
    assert span["residual_cause"] == "UNCLASSIFIED"
    assert span["scheduler"]["qualified_runqueue_wait_ns"] == 10
    assert report["original_structural_counts"]["audit_raw"]["chain"]["ok"] is True
    assert report["historical_cause"] == "UNKNOWN"
    assert report["comparison_qualified"] is report["production_admission"] is False
    assert report["qualified_safety_count"] is None
    assert value == before
    assert analyze(value) == report


@pytest.mark.parametrize("outcome", ["returned", "raised"])
def test_actual_call_outcome_enum_retained(outcome):
    value = fixture()
    value[0][4][1]["outcome"] = outcome
    assert analyze(value)["completed_spans"][0]["outcome"] == outcome


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate",
        "noncanonical",
        "tamper",
        "unknown_field",
        "unknown_phase",
        "protocol",
        "source",
        "fixture",
        "pid",
        "boot",
        "tid_reused",
        "cross_thread",
        "parent",
        "sum_claim",
        "missing_end",
        "intent_only",
        "rows",
        "bytes",
        "depth",
    ],
)
def test_frozen_parser_invalid_trace_cases_retain_only_valid_prefix(fault):
    value = fixture()
    rows, expected, _, _ = value
    if fault == "missing":
        raw = b""
    elif fault == "duplicate":
        raw = rows_wire(rows).replace(b'"seq":1', b'"seq":1,"seq":1', 1)
    elif fault == "noncanonical":
        raw = b" " + rows_wire(rows)
    elif fault == "tamper":
        raw = rows_wire(rows).replace(b'"phase":"submit"', b'"phase":"payload"', 1)
    else:
        if fault == "unknown_field":
            rows[4][1]["surprise"] = True
        elif fault == "unknown_phase":
            rows[3][1]["phase"] = "unknown"
        elif fault == "protocol":
            rows[0][1]["protocol_sha256"] = "a" * 64
        elif fault == "source":
            expected["header"]["source_inventory_sha256"] = "a" * 64
        elif fault == "fixture":
            expected["header"]["fixture_sha256"] = "a" * 64
        elif fault == "pid":
            rows[1][1]["pid"] += 1
        elif fault == "boot":
            rows[1][1]["boot_id"] = "00000000-0000-4000-8000-000000000002"
        elif fault == "tid_reused":
            duplicate = deepcopy(rows[1][1])
            duplicate["task_start_ticks"] += 1
            rows.insert(2, ("thread", duplicate))
        elif fault == "cross_thread":
            rows[4][1]["native_tid"] += 1
        elif fault == "parent":
            rows[3][1]["parent_id"] = 999
        elif fault == "sum_claim":
            rows[4][1]["exclusive_summed_elapsed_ns"] = 999
        elif fault == "missing_end":
            rows.pop()
        elif fault == "intent_only":
            del rows[4:]
        elif fault == "rows":
            rows[0][1]["limits"]["max_rows"] = 5
        elif fault == "bytes":
            rows[0][1]["limits"]["max_bytes"] = len(rows_wire(rows)) - 100
        else:
            value_depth = 1
            for _ in range(18):
                value_depth = [value_depth]
            rows[4][1]["surprise"] = value_depth
        raw = rows_wire(rows)
    result = analyze(value, raw=raw)
    assert result["normal_return_confirmed"] is False
    assert result["status"] != "complete_descriptive_trace"
    assert result["reasons"]
    if fault in ("missing_end", "rows"):
        assert len(result["completed_spans"]) == 1
    if fault == "intent_only":
        assert len(result["incomplete_intents"]) == 1


@pytest.mark.parametrize(
    "fault",
    [
        "disabled_stale",
        "denied",
        "missing_marker",
        "task_start",
        "pid",
        "boot",
        "regression",
        "raw_mismatch",
        "bool_counter",
        "bad_brackets",
        "unknown_domain",
    ],
)
def test_scheduler_unknowns_never_turn_residual_into_scheduling(fault):
    value = fixture()
    span = value[0][4][1]
    after = span["scheduler_after"]
    if fault == "disabled_stale":
        after["schedstats_raw"] = "0\n"
    elif fault == "denied":
        after["error"] = "PermissionError"
    elif fault == "missing_marker":
        after["schedstats_raw"] = None
    elif fault == "task_start":
        after["task_start_ticks"] += 1
    elif fault == "pid":
        after["pid"] += 1
    elif fault == "boot":
        after["boot_id"] = "00000000-0000-4000-8000-000000000002"
    elif fault == "regression":
        after["runqueue_wait_ns"] = 1
        after["schedstat_raw"] = "15 1 2\n"
    elif fault == "raw_mismatch":
        after["schedstat_raw"] = "15 99 2\n"
    elif fault == "bool_counter":
        after["runqueue_wait_ns"] = True
    elif fault == "bad_brackets":
        after["read_begin_ns"] = 99
    else:
        value[0][0][1]["clock_domain"] = deepcopy(DOMAIN)
        value[0][0][1]["clock_domain"]["established"] = False
        value[1]["header"]["clock_domain"] = deepcopy(value[0][0][1]["clock_domain"])
    result = analyze(value)
    assert all(
        row["scheduler"]["qualified_runqueue_wait_ns"] is None
        for row in result["completed_spans"]
    )
    assert all(
        row["residual_cause"] == "UNCLASSIFIED" for row in result["completed_spans"]
    )
    if fault != "bool_counter":
        assert result["completed_spans"][0]["scheduler"]["reasons"]
    else:
        assert result["status"] != "complete_descriptive_trace"


@pytest.mark.parametrize(
    "fault",
    [
        "missing_original",
        "bad_index",
        "same_time_other_key",
        "unbound_original",
        "unknown_original_field",
    ],
)
def test_bad_originals_withhold_correlation_but_preserve_complete_trace_prefix(fault):
    rows, expected, index, original = fixture()
    if fault == "missing_original":
        original = None
    elif fault == "bad_index":
        parsed = json.loads(index)
        parsed["events"][0]["index"] = True
        index = wire(parsed)
        expected["event_index_sha256"] = sha(index)
    elif fault == "same_time_other_key":
        parsed = json.loads(index)
        parsed["events"][0]["core_event_key"] = "a" * 64
        index = wire(parsed)
        expected["event_index_sha256"] = sha(index)
    elif fault == "unbound_original":
        expected["original_result_sha256"] = "a" * 64
    else:
        parsed = json.loads(original)
        parsed["caller_eligible"] = True
        original = wire(parsed)
        expected["original_result_sha256"] = sha(original)
    result = analyze((rows, expected, index, original))
    assert result["status"] == "partial_prefix"
    assert len(result["completed_spans"]) == 1
    assert result["completed_spans"][0]["event_correlation"] == "unavailable"
    assert result["qualified_safety_count"] is None


def test_later_bad_row_preserves_genuine_completed_prefix():
    value = fixture()
    raw = rows_wire(value[0][:-1]) + b'{"broken":true}\n'
    result = analyze(value, raw=raw)
    assert result["valid_prefix_rows"] == 5
    assert len(result["completed_spans"]) == 1
    assert result["status"] == "partial_prefix"


def test_nested_span_clock_containment_is_required():
    value = fixture()
    parent = value[0][3][1]
    child = dict(parent, span_id=2, parent_id=1, phase="payload")
    child_span = dict(value[0][4][1], **child)
    # Completed child lies outside subsequently supplied parent endpoint.
    child_span.update(start_ns=11, end_ns=120)
    child_span["scheduler_after"] = dict(
        snapshot(after=True), read_begin_ns=121, read_end_ns=122
    )
    value[0].insert(4, ("intent", child))
    value[0].insert(5, ("span", child_span))
    result = analyze(value)
    assert result["status"] == "partial_prefix"
    assert len(result["completed_spans"]) == 1
    assert any("child_clock_outside_parent" in reason for reason in result["reasons"])


def test_recorder_original_results_and_exceptions_survive_every_recording_failure(
    tmp_path, monkeypatch
):
    _, expected, _, _ = fixture()
    metadata = {key: expected["header"][key] for key in r.META}
    recorder = r.NotificationRecording(
        tmp_path / "trace", metadata=metadata, max_rows=1
    )
    calls = []
    token = object()

    def original():
        calls.append(1)
        return token

    assert recorder.call("submit", original) is token
    failure = RuntimeError("original failure")

    def raised():
        calls.append(2)
        raise failure

    with pytest.raises(RuntimeError) as seen:
        recorder.call("submit", raised)
    assert seen.value is failure and calls == [1, 2]
    recorder.finish()
    assert recorder.incomplete is True and recorder.lost_rows > 0
    # Even probe/clock exceptions must leave the delegated call multiplicity intact.
    recorder = r.NotificationRecording(tmp_path / "probe-failure", metadata=metadata)
    monkeypatch.setattr(
        r, "scheduler_snapshot", lambda: (_ for _ in ()).throw(OSError("probe"))
    )
    assert recorder.call("submit", original) is token
    recorder.finish()
    assert calls == [1, 2, 1] and recorder.incomplete


def test_recorder_binding_lookup_ambiguity_and_context(tmp_path, monkeypatch):
    value = fixture()
    metadata = {key: value[1]["header"][key] for key in r.META}
    recorder = r.NotificationRecording(tmp_path / "trace", metadata=metadata)
    event_row = json.loads(value[2])["events"][0]
    key = {k: event_row[k] for k in ("core_event_key", "trace_id")}
    recorder.bind_event(0, event_row["event"], key)
    assert recorder.lookup_event(key["core_event_key"]) == 0
    recorder.bind_event(1, event_row["event"], key)
    assert recorder.lookup_event(key["core_event_key"]) is None
    monkeypatch.setattr(r, "scheduler_snapshot", lambda: snapshot())
    with recorder.event_context(0):
        assert recorder.call("submit", lambda: 4) == 4
    recorder.finish()
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    assert (
        next(row for row in rows if row["kind"] == "intent")["data"]["event_index"] == 0
    )


def test_pure_analyzer_never_reads_files_or_clocks(monkeypatch):
    value = fixture()
    monkeypatch.setattr(
        Path, "read_bytes", lambda *a, **k: (_ for _ in ()).throw(AssertionError("IO"))
    )
    monkeypatch.setattr(
        r.time, "monotonic_ns", lambda: (_ for _ in ()).throw(AssertionError("clock"))
    )
    assert analyze(value)["status"] == "complete_descriptive_trace"


@pytest.mark.parametrize("fault", ["bad_chain", "missing_audit", "collection_error"])
def test_original_stream_failures_are_not_replaced_by_collector_success(fault):
    rows, expected, index, original = fixture()
    value = json.loads(original)
    if fault == "bad_chain":
        value["audit_raw"] = '{"chain_prev":"","chain_hash":"wrong"}\n'
        value["control"]["chain_verification"] = {"ok": True}
    elif fault == "missing_audit":
        value["audit_raw"] = None
    else:
        value["collection_errors"] = ["audit read unavailable"]
    original = wire(value)
    expected["original_result_sha256"] = sha(original)
    result = analyze((rows, expected, index, original))
    assert result["status"] == "partial_prefix"
    assert result["original_result"] == value
    assert result["completed_spans"][0]["event_correlation"] == "unavailable"


def test_recorder_end_probe_failure_never_replaces_original_exception(
    tmp_path, monkeypatch
):
    metadata = {key: fixture()[1]["header"][key] for key in r.META}
    recorder = r.NotificationRecording(tmp_path / "trace", metadata=metadata)
    monkeypatch.setattr(
        r, "_end_clocks", lambda _: (_ for _ in ()).throw(OSError("probe end"))
    )
    token, calls = object(), []

    def success():
        calls.append("success")
        return token

    assert recorder.call("submit", success) is token
    failure = LookupError("real original exception")

    def fail():
        calls.append("failed")
        raise failure

    with pytest.raises(LookupError) as seen:
        recorder.call("submit", fail)
    assert seen.value is failure
    recorder.finish()
    assert recorder.incomplete and calls == ["success", "failed"]


def test_fixture_span_can_bind_later_by_explicit_index_not_time():
    value = fixture()
    binding = value[0].pop(2)
    value[0].insert(4, binding)
    result = analyze(value)
    assert result["status"] == "complete_descriptive_trace"
    assert (
        result["completed_spans"][0]["event_correlation"] == "exact_original_event_key"
    )


def test_cross_thread_endpoint_cannot_publish_same_thread_cpu_or_residual():
    value = fixture()
    value[0][4][1]["scheduler_after"]["native_tid"] += 1
    result = analyze(value)
    span = result["completed_spans"][0]
    assert span["elapsed_ns"] == 90
    assert span["thread_cpu_ns"] is span["wall_minus_thread_cpu_ns"] is None
    assert span["scheduler"]["qualified_runqueue_wait_ns"] is None
    assert "scheduler_task_identity_unbound" in span["scheduler"]["reasons"]


def test_dense_newlines_are_iteration_bounded_before_materialization():
    dense = b"\n" * a.MAX_BYTES
    lines = list(a._bounded_lines(dense))
    assert len(lines) == a.MAX_ROWS + 1
    assert sum(map(len, lines)) == a.MAX_ROWS + 1
    value = fixture()
    prefix = rows_wire(value[0][:-1])
    result = analyze(value, raw=prefix + dense)
    assert result["valid_prefix_rows"] == 5
    assert len(result["completed_spans"]) == 1
    assert result["normal_return_confirmed"] is False
    assert "trace_byte_capacity_exceeded" in result["reasons"]


@pytest.mark.parametrize("clock", ["thread_cpu", "process_cpu"])
def test_child_cpu_endpoint_outside_parent_retains_prior_child_fact(clock):
    value = fixture()
    parent = value[0][3][1]
    child = dict(parent, span_id=2, parent_id=1, phase="payload")
    child_span = dict(value[0][4][1], **child)
    child_span.update(start_ns=11, end_ns=90)
    child_span[clock + "_end_ns"] += 1
    value[0].insert(4, ("intent", child))
    value[0].insert(5, ("span", child_span))
    result = analyze(value)
    assert len(result["completed_spans"]) == 1
    assert result["completed_spans"][0]["span_id"] == 2
    assert result["status"] == "partial_prefix"
    assert any(
        "child_" + clock + "_outside_parent" in reason for reason in result["reasons"]
    )


@pytest.mark.parametrize("clock", ["thread_cpu", "process_cpu"])
def test_sibling_cpu_overlap_rejects_later_fact_without_erasing_first(clock):
    value = fixture()
    second_intent = dict(value[0][3][1], span_id=2)
    second = dict(value[0][4][1], **second_intent)
    second.update(
        start_ns=110,
        end_ns=200,
        thread_cpu_start_ns=30,
        thread_cpu_end_ns=40,
        process_cpu_start_ns=60,
        process_cpu_end_ns=70,
    )
    second[clock + "_start_ns"] -= 1
    second["scheduler_before"] = dict(snapshot(), read_begin_ns=103, read_end_ns=104)
    second["scheduler_after"] = dict(
        snapshot(after=True), read_begin_ns=201, read_end_ns=202
    )
    value[0].insert(5, ("intent", second_intent))
    value[0].insert(6, ("span", second))
    result = analyze(value)
    assert len(result["completed_spans"]) == 1
    assert result["completed_spans"][0]["span_id"] == 1
    assert result["status"] == "partial_prefix"
    assert any("overlapping_sibling_" + clock in reason for reason in result["reasons"])


def test_partial_constructor_abort_never_emits_end_and_original_call_still_runs(
    tmp_path, monkeypatch
):
    metadata = {key: fixture()[1]["header"][key] for key in r.META}
    monkeypatch.setattr(
        r, "process_identity", lambda: (_ for _ in ()).throw(OSError("setup identity"))
    )
    path = tmp_path / "partial-setup"
    recorder = r.NotificationRecording(path, metadata=metadata)
    assert recorder.incomplete and recorder.fd is not None
    token, calls = object(), []

    def original():
        calls.append(1)
        return token

    assert recorder.call("submit", original) is token
    recorder.abort()
    recorder.abort()
    recorder.finish()
    assert (
        recorder.incomplete and recorder.closed and recorder.descriptor_closed is True
    )
    assert recorder.close_error is None and recorder.fd is None
    assert calls == [1] and path.read_bytes() == b""


def test_abort_valid_prefix_has_no_end_and_does_not_disable_original_calls(tmp_path):
    metadata = {key: fixture()[1]["header"][key] for key in r.META}
    recorder = r.NotificationRecording(tmp_path / "trace", metadata=metadata)
    assert recorder.call("submit", lambda: 7) == 7
    recorder.abort()
    assert recorder.call("submit", lambda: 8) == 8
    recorder.finish()
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    assert any(row["kind"] == "span" for row in rows)
    assert not any(row["kind"] == "end" for row in rows)
    assert (
        recorder.incomplete and recorder.closed and recorder.descriptor_closed is True
    )


def test_abort_close_failure_retains_unknown_close_state_and_exact_original_exception(
    tmp_path, monkeypatch
):
    metadata = {key: fixture()[1]["header"][key] for key in r.META}
    recorder = r.NotificationRecording(tmp_path / "trace", metadata=metadata)
    real_os, fd = r.os, recorder.fd

    class RefuseClose:
        def __getattr__(self, name):
            return getattr(real_os, name)

        def close(self, descriptor):
            assert descriptor == fd
            raise OSError(5, "SYNTHETIC close failure")

    monkeypatch.setattr(r, "os", RefuseClose())
    recorder.abort()
    assert recorder.close_error == dict(type="OSError", errno=5)
    assert (
        recorder.descriptor_closed is None and recorder.incomplete and recorder.closed
    )
    failure = KeyError("real original exception")
    calls = []

    def original():
        calls.append(1)
        raise failure

    with pytest.raises(KeyError) as seen:
        recorder.call("submit", original)
    assert seen.value is failure and calls == [1]
    recorder.finish()  # No dangerous retry of the uncertain numeric descriptor.
    assert recorder.close_error == dict(type="OSError", errno=5)
    real_os.close(fd)  # This fake refused to enter the real close syscall.
    rows = [json.loads(line) for line in (tmp_path / "trace").read_bytes().splitlines()]
    assert not any(row["kind"] == "end" for row in rows)
