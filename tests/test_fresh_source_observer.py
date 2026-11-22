"""SYNTHETIC handler/clock contexts; not signed-native or Linux acceptance."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import fresh_source_recording as fresh
import fresh_source_observer as helper
import signed_network_recording as recording
from azazel_edge.outcome import input_resume
from azazel_edge.outcome.input_cursor import InputLine
from azazel_edge.outcome.journal import _json
from test_outcome_live_origin import frame
from test_outcome_telemetry_g3 import policy


class Journal:
    def __init__(self):
        self.cursor = dict(offset=0, sha256=hashlib.sha256(b"").hexdigest())
        self.input_source = SimpleNamespace(authentication=None)
        self.advanced = []

    def input_position(self):
        return self.cursor.copy()

    def status(self):
        return dict(
            continuity_available=True, new_admission_closed=False, seal_reason=None
        )

    def advance_input(self, position, *, missed):
        self.cursor = position.copy()
        self.advanced.append((position.copy(), missed))


def event(epoch, index=0):
    value = deepcopy(frame("decision_execution", 2)["event"])
    value["normalized"]["ts"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    value["enforcement"].update(
        mode="disabled", result="no_disruptive_action", executed_count=0
    )
    value["enforcement_status"].update(enforce_enabled=False, dry_run=True)
    value["ingress_origin"] = dict(
        schema_version="azazel-edge/ingress-origin/v1",
        range_ref="a" * 32,
        device=1,
        inode=2,
        start_offset=index * 100,
        end_offset=(index + 1) * 100,
        raw_sha256="b" * 64,
    )
    return value


def line(value, index):
    return InputLine(
        _json(value) + b"\n",
        dict(offset=(index + 1) * 4096, sha256=str(index + 1) * 64),
    )


def rows(path):
    return [json.loads(raw) for raw in path.read_bytes().splitlines()]


def assert_chain(path):
    previous = "0" * 64
    for seq, raw in enumerate(path.read_bytes().splitlines(keepends=True), 1):
        row = json.loads(raw)
        assert (
            row["schema_version"] == fresh.SCHEMA
            and row["seq"] == seq
            and row["prev"] == previous
        )
        assert _json(row) + b"\n" == raw
        previous = hashlib.sha256(raw).hexdigest()


def test_fresh_calls_are_original_false_returns_and_actual_activity_with_distinct_spans(
    tmp_path,
):
    calls, inputs = tmp_path / "calls", tmp_path / "inputs"
    p = policy()
    j = Journal()
    with recording.record_collector(
        calls,
        policy=p.to_dict()
        if hasattr(p, "to_dict")
        else {
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
        },
        policy_source_ref="unit-test",
    ):
        with fresh.record_inputs(
            inputs, metadata={}, identity={}, binding={}
        ) as context:
            collector = input_resume.OutcomeTelemetryCollector(
                source=object(), policy=p, interface="lo", sample_interval_seconds=0.1
            )
            for index in range(2):
                input_resume.observe_input(
                    line(event(1000.01, index), index),
                    j,
                    collector,
                    live_floor=1000.0,
                    now=1000.05,
                )
            assert len(collector.activity) == 2
            assert (
                collector.activity[0].evidence_ref == collector.activity[1].evidence_ref
            )
            assert not collector.pending
    assert context.closed and not context.incomplete
    assert_chain(inputs)
    returns = [r["data"] for r in rows(inputs) if r["kind"] == "input_return"]
    actual = [r for r in rows(calls) if r["kind"] == "event"]
    assert len(returns) == len(actual) == 2
    for index, (result, callback) in enumerate(zip(returns, actual)):
        nested = result["callbacks"][0]
        assert nested["call_seq"] == callback["seq"]
        assert nested["return_value"] is callback["data"]["accepted"] is False
        assert (
            nested["event_sha256"]
            == hashlib.sha256(_json(callback["data"]["event"]) + b"\n").hexdigest()
        )
        assert (
            nested["activity"]["evidence_ref"]
            == "rust-activity:" + callback["data"]["event"]["enforcement"]["trace_id"]
        )
        assert result["cursor_after"] == line(event(1000.01, index), index).position
    assert (
        returns[0]["callbacks"][0]["event_sha256"]
        != returns[1]["callbacks"][0]["event_sha256"]
    )
    assert all(not missed for _, missed in j.advanced)


def test_stale_and_future_have_actual_completed_handler_and_missed_cursor_not_absence_inference(
    tmp_path,
):
    j = Journal()
    p = policy()
    with fresh.record_inputs(
        tmp_path / "inputs", metadata={}, identity={}, binding={}
    ) as context:
        collector = input_resume.OutcomeTelemetryCollector(
            source=object(), policy=p, interface="lo", sample_interval_seconds=0.1
        )
        for index, stamp in enumerate((400.0, 1600.0)):
            input_resume.observe_input(
                line(event(stamp, index), index),
                j,
                collector,
                live_floor=1000.0,
                now=1000.05,
            )
        assert not collector.activity
    returns = [
        r["data"] for r in rows(tmp_path / "inputs") if r["kind"] == "input_return"
    ]
    assert len(returns) == 2 and all(r["callbacks"] == [] for r in returns)
    assert all(missed for _, missed in j.advanced)
    assert context.completed == 2 and context.callbacks == 0


def test_context_intent_is_not_written_or_fsynced_before_actual_handler(
    tmp_path, monkeypatch
):
    path = tmp_path / "inputs"
    sink = fresh.InputRecording(path, metadata={}, identity={}, binding={})
    initial = path.read_bytes()
    j = Journal()
    called = []
    sync = []
    original_sync = fresh.os.fsync

    def close_sync(fd):
        assert rows(path)[-1]["kind"] == "end"
        sync.append(fd)
        return original_sync(fd)

    monkeypatch.setattr(fresh.os, "fsync", close_sync)

    def original(*args, **kwargs):
        assert path.read_bytes() == initial and sync == []
        called.append(1)
        j.advance_input(args[0].position, missed=False)

    sink.input(original, line(event(1000), 0), j, None, live_floor=999, now=1000)
    assert called == [1] and sync == []
    assert [r["kind"] for r in rows(path)] == ["begin", "input_intent", "input_return"]
    sink.close(normal_return=True)
    assert len(sync) == 1


def test_original_exception_identity_and_partial_context_are_preserved(
    tmp_path, monkeypatch
):
    error = RuntimeError("original-handler")
    calls = []

    def original(*args, **kwargs):
        calls.append(1)
        raise error

    monkeypatch.setattr(input_resume, "observe_input", original)
    with pytest.raises(RuntimeError) as caught:
        with fresh.record_inputs(
            tmp_path / "inputs", metadata={}, identity={}, binding={}
        ) as sink:
            input_resume.observe_input(
                line(event(1000), 0), Journal(), None, live_floor=999, now=1000
            )
    assert caught.value is error and calls == [1]
    assert sink.closed and sink.incomplete
    assert [r["kind"] for r in rows(tmp_path / "inputs")] == [
        "begin",
        "input_intent",
        "input_raise",
    ]
    assert input_resume.observe_input is original


def test_overflow_never_replays_handler_or_fabricates_end(tmp_path, monkeypatch):
    monkeypatch.setattr(fresh, "MAX_ROWS", 1)
    calls = []

    def original(*args, **kwargs):
        calls.append(1)

    monkeypatch.setattr(input_resume, "observe_input", original)
    with fresh.record_inputs(
        tmp_path / "inputs", metadata={}, identity={}, binding={}
    ) as sink:
        input_resume.observe_input(
            line(event(1000), 0), Journal(), None, live_floor=999, now=1000
        )
    assert calls == [1] and sink.incomplete
    assert [r["kind"] for r in rows(tmp_path / "inputs")] == ["begin"]


def test_new_helper_audit_and_run_contexts_use_explicit_100ms_without_old_mutation():
    import inspect
    import finite_load_observer as old

    assert "sample_interval_seconds=0.1" in inspect.getsource(helper.run)
    assert 'persistence_context(policy, "lo", 0.1)' in inspect.getsource(helper.audit)
    assert "sample_interval_seconds=0.05" in inspect.getsource(old.run)
    assert helper.PHASE_SCHEMA == "edge-fresh-phase-timing-record/v1"
    assert helper.CLOCK_SCHEMA == "edge-fresh-clock-context/v1"


@pytest.mark.parametrize("age,missed", [(0.09, False), (0.11, True)])
def test_new_100ms_context_keeps_original_freshness_guard(age, missed, tmp_path):
    j = Journal()
    p = policy()
    with fresh.record_inputs(tmp_path / "inputs", metadata={}, identity={}, binding={}):
        collector = input_resume.OutcomeTelemetryCollector(
            source=object(), policy=p, interface="lo", sample_interval_seconds=0.1
        )
        input_resume.observe_input(
            line(event(1000), 0), j, collector, live_floor=999.0, now=1000 + age
        )
    assert j.advanced[0][1] is missed
    assert len(collector.activity) == (0 if missed else 1)


@pytest.mark.parametrize(
    "fault",
    [
        "valid",
        "old_schema",
        "recipe",
        "dynamic_hash",
        "alias",
        "outside_output",
        "old_prefix",
        "helper_pin",
        "composite_pin",
    ],
)
def test_config_is_fresh_version_pinned_and_uses_only_existing_paths(
    monkeypatch, fault
):
    run = "a" * 32
    path = Path("/opt/edge400-runtime/finite-load-configs") / (
        "fresh-" + run + "-config.json"
    )
    top = Path(helper.__file__).read_bytes()
    adjacent = Path(fresh.__file__).read_bytes()
    original = {
        str(helper.BASE / "origin.json"): b"registration",
        str(helper.BASE / "trust.json"): b"trust",
    }
    paths = dict(
        registration=str(helper.BASE / "origin.json"),
        trust=str(helper.BASE / "trust.json"),
        policy=str(helper.POLICY),
    )
    paths.update(
        {key: str(helper.BASE / "observer" / (run + "-" + key)) for key in helper.EXTRA}
    )
    metadata = dict(
        run_id=run,
        arm="fresh-controls",
        role="observer",
        input_recipe_sha256=helper.RECIPE_SHA256,
        code_sha256=hashlib.sha256(top + b"\0" + adjacent).hexdigest(),
        core_sha256="c" * 64,
        interpreter_sha256=hashlib.sha256(
            Path(sys.executable).resolve().read_bytes()
        ).hexdigest(),
    )
    config = dict(
        schema_version="edge-fresh-source-observer-config/v1",
        case_id="fresh-controls",
        protocol_sha256=helper.PROTOCOL_SHA256,
        input_recipe_sha256=helper.RECIPE_SHA256,
        registration_sha256=hashlib.sha256(b"registration").hexdigest(),
        trust_sha256=hashlib.sha256(b"trust").hexdigest(),
        helper_sha256=hashlib.sha256(top).hexdigest(),
        paths=paths,
        metadata=metadata,
    )
    if fault == "old_schema":
        config["schema_version"] = "edge-finite-load-observer-config/v1"
    elif fault == "recipe":
        config["input_recipe_sha256"] = "e" * 64
    elif fault == "dynamic_hash":
        config["metadata"]["input_sha256"] = "e" * 64
    elif fault == "alias":
        paths["input_calls"] = paths["calls"]
    elif fault == "outside_output":
        paths["input_calls"] = "/tmp/ungranted"
    elif fault == "old_prefix":
        path = path.with_name("load-" + run + "-config.json")
    elif fault == "helper_pin":
        config["helper_sha256"] = "e" * 64
    elif fault == "composite_pin":
        config["metadata"]["code_sha256"] = "e" * 64
    raw = helper.accounting.canonical(config)
    original[str(path)] = raw
    original[str(Path(helper.__file__).with_name("fresh_source_recording.py"))] = (
        adjacent
    )
    monkeypatch.setattr(
        helper.input_auth,
        "read_regular",
        lambda path, **kwargs: (original[str(path)], None),
    )
    policy_object = SimpleNamespace()
    monkeypatch.setattr(
        helper.input_auth.TrustPolicy,
        "from_file",
        lambda *args, **kwargs: policy_object,
    )
    registration = dict(
        schema_version="outcome-live-origin-registration/v4",
        binary_sha256="c" * 64,
        environment={"AZAZEL_LIVE_ORIGIN_LOAD_COST": "v1"},
    )
    monkeypatch.setattr(helper.input_live, "registration", lambda *args: registration)
    if fault == "valid":
        got, trust = helper.load_config(path, hashlib.sha256(raw).hexdigest())
        assert got == config and trust is policy_object
    else:
        with pytest.raises(ValueError):
            helper.load_config(path, hashlib.sha256(raw).hexdigest())


def test_fresh_context_restores_all_original_hooks_on_recording_failure(
    tmp_path, monkeypatch
):
    original_input = input_resume.observe_input
    original_collector = input_resume.OutcomeTelemetryCollector
    original_append = recording.CallRecording.append
    with fresh.record_inputs(
        tmp_path / "inputs", metadata={}, identity={}, binding={}
    ) as sink:
        monkeypatch.setattr(sink, "_flush", lambda: setattr(sink, "incomplete", True))
        # Actual stale handling still executes once and advances its real cursor.
        j = Journal()
        collector = input_resume.OutcomeTelemetryCollector(
            source=object(),
            policy=policy(),
            interface="lo",
            sample_interval_seconds=0.1,
        )
        input_resume.observe_input(
            line(event(400), 0), j, collector, live_floor=1000, now=1000.05
        )
        assert len(j.advanced) == 1
    assert input_resume.observe_input is original_input
    assert input_resume.OutcomeTelemetryCollector is original_collector
    assert recording.CallRecording.append is original_append
    assert sink.incomplete and sink.closed


def test_synthetic_cursor_failure_after_actual_callback_keeps_prefix_not_handler_success(
    tmp_path,
):
    error = OSError("synthetic cursor failure")

    class BrokenJournal(Journal):
        def advance_input(self, *args, **kwargs):
            raise error

    j = BrokenJournal()
    p = policy()
    mapping = {
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
    with pytest.raises(OSError) as caught:
        with recording.record_collector(
            tmp_path / "calls", policy=mapping, policy_source_ref="unit-test"
        ):
            with fresh.record_inputs(
                tmp_path / "inputs", metadata={}, identity={}, binding={}
            ):
                collector = input_resume.OutcomeTelemetryCollector(
                    source=object(),
                    policy=p,
                    interface="lo",
                    sample_interval_seconds=0.1,
                )
                input_resume.observe_input(
                    line(event(1000.01), 0), j, collector, live_floor=1000, now=1000.05
                )
    assert caught.value is error
    context = rows(tmp_path / "inputs")
    assert [r["kind"] for r in context] == ["begin", "input_intent", "input_raise"]
    raised = context[-1]["data"]
    assert (
        len(raised["callbacks"]) == 1
        and raised["callbacks"][0]["return_value"] is False
    )
    assert raised["cursor_after"]["offset"] == 0
    assert not any(r["kind"] == "input_return" for r in context)


def test_new_phase_and_clock_versions_are_not_relabelled_legacy_files(
    tmp_path, monkeypatch
):
    identity = dict(pid=123, start_ticks=456, native_tid=123, boot_id="synthetic")
    monkeypatch.setattr(helper.phase, "_identity", lambda: identity.copy())
    monkeypatch.setattr(helper.clock, "_identity", lambda: identity.copy())
    metadata = dict(
        run_id="a" * 32,
        arm="fresh-controls",
        role="observer",
        input_recipe_sha256=helper.RECIPE_SHA256,
        code_sha256="b" * 64,
        core_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    recorder = helper.FreshPhaseRecording(tmp_path / "phase", metadata=metadata)
    calls = []
    assert recorder.call("observation_event", lambda: calls.append(1) or False) is False
    recorder.close(normal_return=True)
    assert calls == [1]
    assert all(
        r["schema_version"] == helper.PHASE_SCHEMA for r in rows(tmp_path / "phase")
    )
    clock = helper.FreshClockContext(tmp_path / "context", metadata=metadata)
    clock.append("end", dict(anchor=helper._clock_anchor(), normal_return=True))
    clock.close()
    assert all(
        r["schema_version"] == helper.CLOCK_SCHEMA for r in rows(tmp_path / "context")
    )
    assert helper.phase.SCHEMA == "edge-phase-timing-record/v1"
    assert helper.clock.SCHEMA == "edge-load-clock-context/v1"


def test_missing_original_callback_record_never_becomes_filtered_or_complete(tmp_path):
    # Deliberately omit original record_collector, simulating unavailable evidence.
    j = Journal()
    with fresh.record_inputs(
        tmp_path / "inputs", metadata={}, identity={}, binding={}
    ) as sink:
        collector = input_resume.OutcomeTelemetryCollector(
            source=object(),
            policy=policy(),
            interface="lo",
            sample_interval_seconds=0.1,
        )
        input_resume.observe_input(
            line(event(1000.01), 0), j, collector, live_floor=1000, now=1000.05
        )
        assert len(collector.activity) == 1 and len(j.advanced) == 1
    assert sink.incomplete and not any(
        row["kind"] == "end" for row in rows(tmp_path / "inputs")
    )


def test_composite_pin_reads_existing_protected_source_without_denied_ancestor_walk():
    import ast

    text = Path(helper.__file__).read_text()
    tree = ast.parse(text)
    load = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "load_config"
    )
    reads = [
        node
        for node in ast.walk(load)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "read_regular"
    ]
    assert reads
    for call in reads:
        arg = ast.get_source_segment(text, call.args[0])
        assert "__file__" not in arg and "fresh_source_recording" not in arg
    assert 'Path(__file__).with_name("fresh_source_recording.py").read_bytes()' in text
    top = Path(helper.__file__).read_bytes()
    dependency = Path(fresh.__file__).read_bytes()
    assert (
        hashlib.sha256(top + b"\0" + dependency).hexdigest()
        != hashlib.sha256(top).hexdigest()
    )
