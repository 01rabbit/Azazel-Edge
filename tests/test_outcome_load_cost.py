"""Synthetic clock/meter receipts and TEST-key Source parity, not Linux cost data."""

from copy import deepcopy
import json

import pytest

from azazel_edge.outcome import phase_cost
from azazel_edge.outcome.input_auth import (
    SignedCaptureWriter,
    SourceVerifier,
    TrustPolicy,
)
from azazel_edge.outcome.native_close_receipts import load_cost_enabled
from azazel_edge.benchmark.native_close_receipts import (
    _cost,
    NATIVE_COST_PHASES,
    RECEIVER_COST_PHASES,
)
from auth_input_helpers import make_policy


def clocks(monkeypatch):
    count = iter(range(0, 100000, 10))
    for name in ("monotonic_ns", "process_time_ns", "thread_time_ns"):
        monkeypatch.setattr(phase_cost.time, name, lambda: next(count))


def test_meter_has_explicit_unmeasured_slots_and_actual_operation_count(monkeypatch):
    clocks(monkeypatch)
    m = phase_cost.Meter()
    assert m.snapshot()["complete"] is True
    assert all(v is None for v in m.snapshot()["phases"].values())
    called = []
    assert m.call("receive_wait", lambda: called.append("once") or "answer") == "answer"
    assert called == ["once"]
    payload = m.snapshot()
    assert payload["phases"]["receive_wait"] == dict(
        count=1, wall_ns=50, process_cpu_ns=30, thread_cpu_ns=10, max_wall_ns=50
    )
    assert payload["phases"]["source_append"] is None
    assert _cost(payload, RECEIVER_COST_PHASES) == payload


@pytest.mark.parametrize("fault", ["entry", "exit", "decreasing", "overflow"])
def test_cost_faults_are_sticky_and_never_replay_or_block_operation(monkeypatch, fault):
    clocks(monkeypatch)
    m = phase_cost.Meter()
    if fault == "overflow":
        m.phases["receive_wait"] = dict(
            count=2**63 - 1, wall_ns=0, process_cpu_ns=0, thread_cpu_ns=0, max_wall_ns=0
        )
    if fault == "entry":

        def unavailable():
            raise OSError("clock unavailable")

        monkeypatch.setattr(phase_cost.time, "monotonic_ns", unavailable)
    elif fault == "exit":

        def unavailable():
            raise OSError("clock unavailable")

        ticks = iter((1,))
        monkeypatch.setattr(phase_cost.time, "monotonic_ns", lambda: next(ticks))
    elif fault == "decreasing":
        ticks = iter((100, 1))
        monkeypatch.setattr(phase_cost.time, "monotonic_ns", lambda: next(ticks))
    calls = []
    for _ in range(2):
        assert m.call("receive_wait", lambda: calls.append("call") or 7) == 7
    assert calls == ["call", "call"]
    payload = m.snapshot()
    assert payload["complete"] is False
    assert payload["invalid_reason"] == (
        "counter_overflow" if fault == "overflow" else "clock_error"
    )
    assert _cost(payload, RECEIVER_COST_PHASES) == payload


def test_operation_exception_is_preserved_without_extra_call(monkeypatch):
    clocks(monkeypatch)
    m = phase_cost.Meter()
    error = RuntimeError("original operation failure")
    calls = []

    def operation():
        calls.append(1)
        raise error

    with pytest.raises(RuntimeError) as caught:
        m.call("source_append", operation)
    assert caught.value is error and calls == [1]


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "unknown_phase",
        "bool",
        "negative",
        "overflow",
        "zero_count",
        "maxwall",
        "bad_complete",
        "bad_reason",
    ],
)
def test_phase_payload_strictness_cannot_be_filled_with_zero(monkeypatch, fault):
    clocks(monkeypatch)
    m = phase_cost.Meter()
    m.call("receive_wait", lambda: None)
    value = m.snapshot()
    aggregate = value["phases"]["receive_wait"]
    if fault == "extra":
        value["derived_success"] = True
    elif fault == "unknown_phase":
        value["phases"]["repair"] = None
    elif fault == "bool":
        aggregate["count"] = True
    elif fault == "negative":
        aggregate["process_cpu_ns"] = -1
    elif fault == "overflow":
        aggregate["wall_ns"] = 2**63
    elif fault == "zero_count":
        aggregate["count"] = 0
    elif fault == "maxwall":
        aggregate["max_wall_ns"] = aggregate["wall_ns"] + 1
    elif fault == "bad_complete":
        value["complete"] = False
    elif fault == "bad_reason":
        value["invalid_reason"] = "retry"
    with pytest.raises(ValueError):
        _cost(value, RECEIVER_COST_PHASES)


def test_load_profile_is_explicit_and_requires_all_registered_prerequisites():
    r = dict(
        schema_version="outcome-live-origin-registration/v4",
        environment={
            "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_LIVE_ORIGIN_ACCOUNTING": "v1",
            "AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS": "v1",
            "AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING": "v1",
            "AZAZEL_LIVE_ORIGIN_LOAD_COST": "v1",
        },
    )
    assert load_cost_enabled(r) is True
    for key in (
        "AZAZEL_LIVE_ORIGIN_ACCOUNTING",
        "AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS",
        "AZAZEL_LIVE_ORIGIN_INGRESS_ACCOUNTING",
    ):
        changed = deepcopy(r)
        changed["environment"].pop(key)
        with pytest.raises(OSError):
            load_cost_enabled(changed)
    changed = deepcopy(r)
    changed["environment"].pop("AZAZEL_LIVE_ORIGIN_LOAD_COST")
    assert load_cost_enabled(changed) is False


def test_measured_source_signatures_and_persistence_match_original_bytes(tmp_path):
    p, _, _, rawkey, _ = make_policy(tmp_path)
    key = tmp_path / "key"
    key.write_bytes(rawkey)
    key.chmod(0o600)
    captured = []
    for index, meter in enumerate((None, phase_cost.Meter())):
        source = tmp_path / ("source-" + str(index))
        source.write_bytes(b"")
        policy = TrustPolicy({**dict(p.data), "source_path": str(source)})
        options = dict(boot_ref="test-boot")
        if meter is not None:
            options["cost_meter"] = meter
        with SignedCaptureWriter(policy, key, **options) as writer:
            tip = writer.append({"test": "same actual signed operation"})
        raw = source.read_bytes()
        assert SourceVerifier(policy).verify(raw) == tip
        captured.append(raw)
        if meter is not None:
            value = meter.snapshot()
            assert value["complete"] is True
            assert value["phases"]["source_sign"]["count"] == 1
            assert value["phases"]["source_verify"]["count"] == 2
            assert value["phases"]["source_fsync"]["count"] == 1
            assert value["phases"]["source_append"] is None
    assert captured[0] == captured[1]


def test_largest_closed_phase_payloads_fit_unchanged_pipe_budget():
    maximum = 2**63 - 1
    aggregate = dict.fromkeys(
        ("count", "wall_ns", "process_cpu_ns", "thread_cpu_ns", "max_wall_ns"), maximum
    )
    for names, limit in ((NATIVE_COST_PHASES, 661), (RECEIVER_COST_PHASES, 1207)):
        value = dict(
            schema_version="azazel-edge/phase-cost/v1",
            complete=False,
            invalid_reason="counter_overflow",
            phases=dict.fromkeys(names, aggregate),
        )
        assert (
            len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            <= limit
        )
