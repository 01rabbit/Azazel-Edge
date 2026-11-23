"""Synthetic blocked measurement I/O; never actual Linux timing evidence."""

import hashlib
import json
from pathlib import Path
import sys
import threading

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import fresh_publication as pub
import fresh_source_recording as inputs
import signed_network_recording as recording
from azazel_edge.outcome import input_resume
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy
from test_signed_network_recording import Source, POLICY
from test_fresh_source_observer import Journal, event, line


def setup(tmp_path):
    paths = {k: tmp_path / k for k in ("calls", "input_calls")}
    p = pub.Publisher(
        paths,
        tmp_path / "publication",
        metadata={"test": "synthetic"},
        identity={"pid": 1},
    )
    return p, paths


def rows(path):
    return [json.loads(x) for x in path.read_bytes().splitlines()]


def blocked_sync(monkeypatch, paths):
    entered = threading.Event()
    release = threading.Event()
    original = pub.os.fsync

    def sync(fd):
        if pub.os.fstat(fd).st_ino == paths["calls"].stat().st_ino:
            entered.set()
            assert release.wait(2)
        return original(fd)

    monkeypatch.setattr(pub.os, "fsync", sync)
    return entered, release


def test_original_returns_once_while_measurement_fsync_blocked_and_actual_ack_is_later(
    tmp_path, monkeypatch
):
    p, paths = setup(tmp_path)
    entered, release = blocked_sync(monkeypatch, paths)
    with recording.record_collector(
        paths["calls"],
        policy=POLICY,
        policy_source_ref="unit",
        sink_factory=p.call_sink,
    ):
        collector = input_resume.OutcomeTelemetryCollector(
            source=Source(),
            policy=OutcomeTelemetryPolicy.from_mapping(POLICY, source_ref="unit"),
            interface="lo",
            sample_interval_seconds=0.1,
        )
        result = collector.record_sample(epoch=1000)
        assert result.epoch == 1000
        assert entered.wait(1)
        # Calls have returned and written, but there can be no successful commit.
        assert not [r for r in rows(tmp_path / "publication") if r["kind"] == "commit"]
        assert p.thread.is_alive()
    release.set()
    out = p.close(normal_return=True)
    assert {k: out[k] for k in ("joined", "complete", "incomplete", "error")} == dict(
        joined=True, complete=True, incomplete=False, error=None
    )
    assert (
        out["owner_close"]["end_ns"] - out["owner_close"]["start_ns"]
        <= pub.LIMITS["close_ns"]
    )
    commits = [
        r["data"] for r in rows(tmp_path / "publication") if r["kind"] == "commit"
    ]
    assert commits[-1]["bytes"] == len(paths["calls"].read_bytes())
    assert (
        commits[-1]["sha256"] == hashlib.sha256(paths["calls"].read_bytes()).hexdigest()
    )
    assert commits[-1]["fsync"]["start_ns"] <= commits[-1]["fsync"]["end_ns"]
    assert (
        recording.decode_calls(paths["calls"].read_bytes())["calls"][0]["data"]["epoch"]
        == 1000
    )


def test_two_stream_original_context_real_callback_and_mutation_is_frozen(tmp_path):
    p, paths = setup(tmp_path)
    j = Journal()
    # Same policy bytes/ref as the original collector constructor.
    value = {
        "schema_version": "outcome-telemetry-policy/v1",
        "policy_version": "test-policy-v1",
        "actions": {
            "throttle": {
                "metric": "source_ip_event_rate_hz",
                "direction": "decrease",
                "target_or_range": {},
                "observation_window": {"pre_seconds": 3.0, "post_seconds": 3.0},
                "guardrails": [],
            }
        },
    }
    with recording.record_collector(
        paths["calls"], policy=value, policy_source_ref="unit", sink_factory=p.call_sink
    ):
        with inputs.record_inputs(
            paths["input_calls"],
            metadata={},
            identity={},
            binding={},
            publisher=p,
            version=2,
        ) as context:
            collector = input_resume.OutcomeTelemetryCollector(
                source=object(),
                policy=OutcomeTelemetryPolicy.from_mapping(value, source_ref="unit"),
                interface="lo",
                sample_interval_seconds=0.1,
            )
            data = event(1000.01)
            input_resume.observe_input(
                line(data, 0), j, collector, live_floor=1000, now=1000.05
            )
            data["normalized"]["sid"] = 123
            assert len(collector.activity) == 1
    assert context.closed and not context.incomplete
    assert p.close(normal_return=True)["complete"]
    ir = rows(paths["input_calls"])
    cr = rows(paths["calls"])
    assert (
        ir[-1]["kind"] == "end"
        and ir[-1]["schema_version"] == "edge-fresh-input-record/v2"
    )
    callback = next(
        r["data"]["callbacks"][0] for r in ir if r["kind"] == "input_return"
    )
    actual = next(r for r in cr if r["kind"] == "event")
    assert callback["call_seq"] == actual["seq"] and callback["return_value"] is False
    assert (
        callback["event_sha256"]
        == hashlib.sha256(pub.canonical(actual["data"]["event"])).hexdigest()
    )
    assert actual["data"]["event"]["normalized"]["sid"] != 123
    end = rows(tmp_path / "publication")[-1]["data"]
    assert end["complete"]
    for stream, marks in end["streams"].items():
        assert marks["enqueued"] == marks["written"] == marks["fsynced"]
        assert (
            marks["fsynced"]["sha256"]
            == hashlib.sha256(paths[stream].read_bytes()).hexdigest()
        )


def test_original_exception_identity_no_retry_no_fabricated_footer(
    tmp_path, monkeypatch
):
    p, paths = setup(tmp_path)
    error = RuntimeError("same original")
    calls = []

    def original(*args, **kwargs):
        calls.append(1)
        raise error

    monkeypatch.setattr(
        input_resume.OutcomeTelemetryCollector, "observe_event", original
    )
    with pytest.raises(RuntimeError) as caught:
        with recording.record_collector(
            paths["calls"],
            policy=POLICY,
            policy_source_ref="unit",
            sink_factory=p.call_sink,
        ):
            collector = input_resume.OutcomeTelemetryCollector(
                source=Source(),
                policy=OutcomeTelemetryPolicy.from_mapping(POLICY, source_ref="unit"),
                interface="lo",
            )
            collector.observe_event({}, observed_epoch=1000)
    assert caught.value is error and calls == [1]
    assert not p.close(normal_return=False)["complete"]
    assert [r["kind"] for r in rows(paths["calls"])] == ["begin"]


@pytest.mark.parametrize("fault", ["row", "bytes", "sequence", "invalid"])
def test_capacity_and_bad_input_poison_without_claiming_commit(
    tmp_path, monkeypatch, fault
):
    p, paths = setup(tmp_path)
    if fault == "row":
        monkeypatch.setitem(pub.LIMITS["stream_rows"], "calls", 0)
    if fault == "bytes":
        monkeypatch.setitem(pub.LIMITS["stream_bytes"], "calls", 1)
    raw = b"{}\n" if fault != "invalid" else b"no-newline"
    assert not p.submit("calls", raw, 1 if fault == "sequence" else 0)
    assert p.incomplete
    assert not p.submit("calls", b"{}\n", 0)
    out = p.close(normal_return=True)
    assert out["joined"] and not out["complete"]
    assert not [r for r in rows(tmp_path / "publication") if r["kind"] == "commit"]


@pytest.mark.parametrize("fault", ["zero", "partial", "fsync"])
def test_write_and_sync_failures_retain_prefix_no_success_commit(
    tmp_path, monkeypatch, fault
):
    p, paths = setup(tmp_path)
    original_write = pub.os.write
    original_sync = pub.os.fsync
    fired = []

    def target(fd):
        return pub.os.fstat(fd).st_ino == paths["calls"].stat().st_ino

    def write(fd, data):
        if target(fd):
            if fault == "zero":
                return 0
            if fault == "partial":
                if not fired:
                    fired.append(1)
                    return original_write(fd, data[:1])
                raise OSError("partial failure")
        return original_write(fd, data)

    def sync(fd):
        if target(fd) and fault == "fsync":
            raise OSError("sync failure")
        return original_sync(fd)

    monkeypatch.setattr(pub.os, "write", write)
    monkeypatch.setattr(pub.os, "fsync", sync)
    assert p.submit("calls", b"{}\n", 0)
    out = p.close(normal_return=True)
    assert out["joined"] and not out["complete"] and out["error"]["type"] == "OSError"
    assert not [r for r in rows(tmp_path / "publication") if r["kind"] == "commit"]
    assert not [r for r in rows(tmp_path / "publication") if r["kind"] == "end"]
    assert (
        paths["calls"].read_bytes()
        == ({"zero": b"", "partial": b"{", "fsync": b"{}\n"}[fault])
    )


def test_eintr_and_short_writes_complete_in_order(tmp_path, monkeypatch):
    p, paths = setup(tmp_path)
    original = pub.os.write
    state = []

    def write(fd, data):
        if pub.os.fstat(fd).st_ino == paths["calls"].stat().st_ino:
            if not state:
                state.append(1)
                raise InterruptedError()
            return original(fd, data[:1])
        return original(fd, data)

    monkeypatch.setattr(pub.os, "write", write)
    assert p.submit("calls", b"{}\n", 0) and p.submit("calls", b"[]\n", 1)
    assert p.close(normal_return=True)["complete"]
    assert paths["calls"].read_bytes() == b"{}\n[]\n"
    commit = next(
        r["data"] for r in rows(tmp_path / "publication") if r["kind"] == "commit"
    )
    assert (commit["first_seq"], commit["last_seq"], commit["rows"]) == (0, 1, 2)


def test_join_timeout_never_closes_worker_fd_or_invents_success(tmp_path, monkeypatch):
    p, paths = setup(tmp_path)
    entered, release = blocked_sync(monkeypatch, paths)
    assert p.submit("calls", b"{}\n", 0)
    assert entered.wait(1)
    monkeypatch.setitem(pub.LIMITS, "close_ns", 1_000_000)
    out = p.close(normal_return=True)
    assert not out["joined"] and not out["complete"] and out["incomplete"]
    assert p.thread.is_alive()
    assert not [r for r in rows(tmp_path / "publication") if r["kind"] == "end"]
    release.set()
    p.thread.join(2)
    assert not p.thread.is_alive()
    end = rows(tmp_path / "publication")[-1]["data"]
    assert not end["complete"] and end["incomplete"]


def test_late_successful_join_observation_is_incomplete(tmp_path, monkeypatch):
    p, paths = setup(tmp_path)
    original = p.thread.join

    def join(timeout):
        original(timeout)
        assert not p.thread.is_alive()
        # A scheduling gap after worker exit still belongs to the deadline.
        p.close_start["start_ns"] -= pub.LIMITS["close_ns"] + 1

    monkeypatch.setattr(p.thread, "join", join)
    out = p.close(normal_return=True)
    assert out["joined"] and not out["complete"] and out["incomplete"]
    assert out["error"]["type"] == "TimeoutError"
    assert (
        out["owner_close"]["end_ns"] - out["owner_close"]["start_ns"]
        > pub.LIMITS["close_ns"]
    )
    # A successful worker footer is retained, not rewritten after late observation.
    assert rows(tmp_path / "publication")[-1]["data"]["complete"] is True


def test_join_failure_cleanup_never_masks_original_exception(tmp_path, monkeypatch):
    p, paths = setup(tmp_path)
    error = RuntimeError("original handler exception")

    def broken(timeout):
        raise OSError("join diagnostic failure")

    monkeypatch.setattr(p.thread, "join", broken)
    with pytest.raises(RuntimeError) as caught:
        try:
            raise error
        finally:
            out = p.close(normal_return=False)
    assert caught.value is error
    assert not out["complete"] and out["incomplete"] and out["owner_close"] is None
    assert out["error"]["type"] == "OSError"
    # Test teardown only; runtime does not retry or close underneath its worker.
    threading.Thread.join(p.thread, 2)


def test_worker_and_owner_close_cpu_endpoints_are_same_thread(tmp_path, monkeypatch):
    p, paths = setup(tmp_path)
    assert p.submit("calls", b"{}\n", 0)
    out = p.close(normal_return=True)
    worker = rows(tmp_path / "publication")[-1]["data"]["close"]
    assert out["complete"]
    for span in (worker, out["owner_close"]):
        assert span["thread_cpu_start_ns"] <= span["thread_cpu_end_ns"]
        assert span["process_cpu_start_ns"] <= span["process_cpu_end_ns"]
    assert (
        out["owner_close"]["start_ns"]
        <= worker["start_ns"]
        <= worker["end_ns"]
        <= out["owner_close"]["end_ns"]
    )


@pytest.mark.parametrize("stream", ["phase", "context"])
def test_v3_measurement_io_is_worker_only_and_original_calls_return_while_blocked(
    tmp_path, monkeypatch, stream
):
    import fresh_source_observer as helper

    main = threading.get_native_id()
    identity = dict(pid=1, start_ticks=2, native_tid=main, boot_id="synthetic")
    monkeypatch.setattr(helper.phase, "_identity", lambda: identity.copy())
    monkeypatch.setattr(helper.clock, "_identity", lambda: identity.copy())
    paths = {s: tmp_path / s for s in ("calls", "input_calls", "phase", "context")}
    original_open = pub.os.open
    original_write = pub.os.write
    original_sync = pub.os.fsync
    entered = threading.Event()
    release = threading.Event()
    operations = []
    owned = {}

    def opened(path, *args, **kwargs):
        fd = original_open(path, *args, **kwargs)
        if str(path).startswith(str(tmp_path)):
            owned[fd] = str(path)
            operations.append(("open", threading.get_native_id()))
        return fd

    def write(fd, raw):
        if fd in owned:
            operations.append(("write", threading.get_native_id()))
        return original_write(fd, raw)

    def sync(fd):
        if fd in owned:
            operations.append(("fsync", threading.get_native_id()))
            if owned[fd] == str(paths[stream]):
                entered.set()
                assert release.wait(2)
        return original_sync(fd)

    monkeypatch.setattr(pub.os, "open", opened)
    monkeypatch.setattr(pub.os, "write", write)
    monkeypatch.setattr(pub.os, "fsync", sync)
    p = pub.Publisher(
        paths, tmp_path / "publication", metadata={}, identity=identity, version=3
    )
    metadata = dict(
        run_id="a" * 32,
        arm="fresh-controls",
        role="observer",
        input_recipe_sha256=helper.RECIPE_SHA256,
        code_sha256="b" * 64,
        core_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    phase = helper.FreshPhaseRecording(
        paths["phase"], metadata=metadata, version=3, publisher=p
    )
    context = helper.FreshClockContext(
        paths["context"], metadata=metadata, version=3, publisher=p
    )
    calls = []
    assert (
        phase.call("observation_sample", lambda: calls.append("original") or False)
        is False
    )
    assert calls == ["original"] and entered.wait(1)
    # Another original operation must run while the measurement fd fsync is stuck.
    assert (
        phase.call("observation_event", lambda: calls.append("second") or False)
        is False
    )
    assert calls == ["original", "second"]
    context.append("end", dict(anchor=helper._clock_anchor(), normal_return=True))
    context.close()
    phase.close(normal_return=True)
    release.set()
    assert p.close(normal_return=True)["complete"]
    assert operations and all(tid != main for _, tid in operations)
    phase_rows = rows(paths["phase"])
    context_rows = rows(paths["context"])
    assert all(
        r["schema_version"] == "edge-fresh-phase-timing-record/v3" for r in phase_rows
    )
    assert all(
        "previous_enqueue_cost" in r["data"] and "previous_write_cost" not in r["data"]
        for r in phase_rows
    )
    assert all(
        r["schema_version"] == "edge-fresh-clock-context/v3" for r in context_rows
    )
    receipts = rows(tmp_path / "publication")
    assert receipts[0]["schema_version"] == "edge-observer-publication/v2"
    assert receipts[0]["data"]["limits"] == pub.V3_LIMITS
    assert set(receipts[-1]["data"]["streams"]) == set(paths)


@pytest.mark.parametrize(
    "stream,limit", [("phase", "stream_rows"), ("context", "stream_bytes")]
)
def test_v3_new_stream_bounds_sticky_incomplete(tmp_path, monkeypatch, stream, limit):
    paths = {s: tmp_path / s for s in ("calls", "input_calls", "phase", "context")}
    p = pub.Publisher(
        paths, tmp_path / "publication", metadata={}, identity={}, version=3
    )
    monkeypatch.setitem(pub.V3_LIMITS[limit], stream, 0)
    assert not p.submit(stream, b"{}\n", 1)
    assert not p.close(normal_return=True)["complete"]
    assert p.incomplete


def test_v3_original_sample_callback_and_all_four_genuine_footers(
    tmp_path, monkeypatch
):
    import fresh_source_observer as helper

    identity = dict(
        pid=1, start_ticks=2, native_tid=threading.get_native_id(), boot_id="synthetic"
    )
    monkeypatch.setattr(helper.phase, "_identity", lambda: identity.copy())
    monkeypatch.setattr(helper.clock, "_identity", lambda: identity.copy())
    paths = {s: tmp_path / s for s in ("calls", "input_calls", "phase", "context")}
    p = pub.Publisher(
        paths, tmp_path / "publication", metadata={}, identity=identity, version=3
    )
    metadata = dict(
        run_id="a" * 32,
        arm="fresh-controls",
        role="observer",
        input_recipe_sha256=helper.RECIPE_SHA256,
        code_sha256="b" * 64,
        core_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    phase = helper.FreshPhaseRecording(
        paths["phase"], metadata=metadata, version=3, publisher=p
    )
    j = Journal()
    with helper.phase.record_observer(phase):
        with helper.record_clock(
            paths["calls"],
            paths["context"],
            metadata=metadata,
            policy=POLICY,
            policy_source_ref="unit",
            publisher=p,
            version=3,
        ):
            with inputs.record_inputs(
                paths["input_calls"],
                metadata=metadata,
                identity=identity,
                binding={},
                publisher=p,
                version=3,
            ):
                collector = input_resume.OutcomeTelemetryCollector(
                    source=Source(),
                    policy=OutcomeTelemetryPolicy.from_mapping(
                        POLICY, source_ref="unit"
                    ),
                    interface="lo",
                    sample_interval_seconds=0.1,
                )
                sample = collector.record_sample(epoch=1000)
                assert sample.epoch == 1000
                input_resume.observe_input(
                    line(event(1000.01), 0), j, collector, live_floor=1000, now=1000.05
                )
                assert len(collector.activity) == 1 and len(j.advanced) == 1
    phase.close(normal_return=True)
    assert p.close(normal_return=True)["complete"]
    actual = recording.decode_calls(paths["calls"].read_bytes())
    assert [r["kind"] for r in actual["calls"]] == ["sample", "event"]
    assert actual["calls"][1]["data"]["accepted"] is False
    for stream in paths:
        assert rows(paths[stream])[-1]["kind"] == "end"
    phase_rows = rows(paths["phase"])
    assert {r["data"].get("phase") for r in phase_rows if r["kind"] == "span"} >= {
        "observation_sample",
        "observation_event",
        "observation",
    }
    assert all(
        r["schema_version"] == "edge-fresh-input-record/v3"
        for r in rows(paths["input_calls"])
    )
