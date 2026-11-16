"""Synthetic identity/context controls around original real collector callbacks."""

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_load_clock as clock
import signed_network_recording as old
import signed_network_phase_recording as phase
from azazel_edge.outcome import input_resume
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy, POLICY_SCHEMA_VERSION
from test_signed_network_recording import Source

META = dict(run_id="synthetic", arm="instrumented_on", role="observer",
            input_sha256="1" * 64, code_sha256="2" * 64,
            core_sha256="3" * 64, interpreter_sha256="4" * 64)
POLICY = dict(schema_version=POLICY_SCHEMA_VERSION, policy_version="empty-test", actions={})


@pytest.fixture(autouse=True)
def synthetic_identity(monkeypatch):
    identity = dict(pid=123, start_ticks=456, native_tid=123,
                    boot_id="12345678-1234-1234-1234-123456789abc",
                    clock_domain=dict(time_namespace_device=1, time_namespace_inode=2,
                                      timens_offsets=None, established=False),
                    clock_ticks_per_second=100,
                    clock_resolutions={name: 1e-9 for name in ("monotonic", "process_time", "thread_time")})
    monkeypatch.setattr(clock, "_identity", lambda: identity)
    monkeypatch.setattr(phase, "_identity", lambda: identity)


def collect_once():
    collector = input_resume.OutcomeTelemetryCollector(
        source=Source(), policy=OutcomeTelemetryPolicy.from_mapping(POLICY, source_ref="synthetic-policy"),
        interface="lo", sample_interval_seconds=0.05,
    )
    sample = collector.record_sample(epoch=100.0)
    accepted = collector.observe_event({"SYNTHETIC_ORIGINAL": True}, observed_epoch=100.25)
    outcomes = collector.finalize_due(epoch=100.5)
    return sample, accepted, outcomes


def context(tmp_path):
    return clock.record_observer_clock(tmp_path / "calls", tmp_path / "context", metadata=META,
                                       policy=POLICY, policy_source_ref="synthetic-policy")


def test_original_callback_epochs_results_and_actual_normal_end(tmp_path):
    expected = collect_once()
    with context(tmp_path):
        actual = collect_once()
    assert actual == expected
    recorded = old.decode_calls_prefix((tmp_path / "calls").read_bytes())
    assert recorded["closed"] is True
    assert [(row["kind"], row["data"]["epoch"]) for row in recorded["calls"]] == [
        ("sample", 100.0), ("event", 100.25), ("finalize", 100.5),
    ]
    previous = "0" * 64
    data = []
    for seq, line in enumerate((tmp_path / "context").read_bytes().splitlines(keepends=True), 1):
        row = json.loads(line)
        assert line == phase.canonical(row)
        assert row["schema_version"] == clock.SCHEMA
        assert row["seq"] == seq and row["prev"] == previous
        previous = hashlib.sha256(line).hexdigest()
        data.append(row)
    assert [row["kind"] for row in data] == ["begin", "end"]
    assert data[0]["data"]["metadata"] == META
    assert data[1]["data"]["normal_return"] is True
    assert data[0]["data"]["anchor"]["monotonic_after_ns"] <= data[1]["data"]["anchor"]["monotonic_before_ns"]


def test_interruption_retains_prefix_but_never_creates_end_anchor(tmp_path):
    original = SystemExit(17)
    with pytest.raises(SystemExit) as caught:
        with context(tmp_path):
            collect_once()
            raise original
    assert caught.value is original
    assert [json.loads(line)["kind"] for line in (tmp_path / "context").read_bytes().splitlines()] == ["begin"]
    recorded = old.decode_calls_prefix((tmp_path / "calls").read_bytes())
    assert recorded["closed"] is False
    assert len(recorded["calls"]) == 3


def test_combined_phase_and_original_clock_context_call_each_callback_once(tmp_path):
    recorder = phase.PhaseRecording(tmp_path / "phase", metadata=META)
    with phase.record_observer(recorder):
        with context(tmp_path):
            assert collect_once()[1:] == (False, ())
    recorder.close(normal_return=True)
    calls = old.decode_calls_prefix((tmp_path / "calls").read_bytes())["calls"]
    assert len(calls) == 3
    spans = [json.loads(line)["data"] for line in (tmp_path / "phase").read_bytes().splitlines()
             if json.loads(line)["kind"] == "span"]
    assert [row["phase"] for row in spans] == ["observation_sample", "observation_event", "finalize_due"]


def test_clock_recording_failure_invalidates_only_this_observer_context(tmp_path, monkeypatch):
    @contextmanager
    def fail(*args, **kwargs):
        raise OSError("synthetic sidecar loss")
        yield

    original_class = input_resume.OutcomeTelemetryCollector
    monkeypatch.setattr(clock, "record_collector", fail)
    with pytest.raises(OSError):
        with context(tmp_path):
            pytest.fail("observer trial continued without its clock recorder")
    assert input_resume.OutcomeTelemetryCollector is original_class
    assert [json.loads(line)["kind"] for line in (tmp_path / "context").read_bytes().splitlines()] == ["begin"]


def test_original_call_limit_not_relaxed_and_context_end_missing_on_loss(tmp_path, monkeypatch):
    monkeypatch.setattr(old, "MAX_ROWS", 2)
    with pytest.raises(ValueError):
        with context(tmp_path):
            collect_once()
    assert len((tmp_path / "calls").read_bytes().splitlines()) == 2
    assert len((tmp_path / "context").read_bytes().splitlines()) == 1


def test_context_uses_exclusive_own_file_and_fixed_bounds(tmp_path):
    path = tmp_path / "context"
    recorder = clock.ClockContext(path, metadata=META)
    recorder.append("end", dict(anchor=old._clock_anchor(), normal_return=True))
    with pytest.raises(ValueError):
        recorder.append("end", {})
    recorder.close()
    with pytest.raises(FileExistsError):
        clock.ClockContext(path, metadata=META)
    assert clock.MAX_CONTEXT_BYTES == 16 * 1024
    assert clock.MAX_CONTEXT_ROWS == 2
    assert old.MAX_ROWS == 900
    assert old.MAX_BYTES == 4 * 1024 * 1024
