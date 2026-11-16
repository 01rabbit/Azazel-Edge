"""SYNTHETIC V3 pins/order tests; legacy paths retain their original contracts."""

from contextlib import contextmanager, nullcontext
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_phase_worker as w
import signed_network_normal_stop as normal
import signed_network_load_clock as clock
from signed_network_phase_recording import canonical
from test_signed_network_phase_worker_v2 import v2_config, observer_args


def v3_config(monkeypatch, profile="phase_and_clock", arm="instrumented_on"):
    config, data = v2_config(monkeypatch)
    config["schema_version"] = w.SCHEMA_V3
    config["metadata"]["arm"] = arm
    helper = str(Path(config["worker_path"]).with_name("signed_network_normal_stop.py"))
    data[helper] = b"SYNTHETIC NORMAL STOP HELPER"
    config["normal_stop"] = dict(
        helper_path=helper,
        helper_sha256=hashlib.sha256(data[helper]).hexdigest(),
        profile=profile,
        receipt_path="/lab/observer/normal-completion.json",
    )
    names = (
        "signed_network_phase_worker.py",
        "signed_network_phase_recording.py",
        "signed_network_load_clock.py",
        "signed_network_recording.py",
        "signed_network_normal_stop.py",
    )
    # The synthetic worker's real basename still matches its module path.
    config["metadata"]["code_sha256"] = hashlib.sha256(
        b"\0".join(
            data[str(Path(config["worker_path"]).with_name(name))] for name in names
        )
    ).hexdigest()
    data["/lab/config"] = canonical(config)
    return config, data


@pytest.mark.parametrize(
    "profile,arm",
    [
        ("stop_only", "original_on"),
        ("stop_only", "original_faulted"),
        ("phase_and_clock", "instrumented_off"),
        ("phase_and_clock", "instrumented_on"),
        ("phase_and_clock", "instrumented_faulted"),
    ],
)
def test_explicit_v3_five_file_pin_and_only_frozen_arm_profiles(
    monkeypatch, profile, arm
):
    config, data = v3_config(monkeypatch, profile, arm)
    assert (
        w.load_config("/lab/config", hashlib.sha256(data["/lab/config"]).hexdigest())
        == config
    )
    assert (
        w._observer_args(observer_args(), config)["--journal-directory"]
        == "/lab/observer"
    )


@pytest.mark.parametrize(
    "fault",
    [
        "helper_pin",
        "alternate_helper",
        "missing_stop",
        "extra_stop",
        "receipt_alias",
        "profile",
        "original_off",
        "baseline_instrumented",
        "instrumented_baseline",
        "v1_stop",
        "v2_stop",
    ],
)
def test_v3_rejects_unpinned_fields_profile_downgrade_or_legacy_adoption(
    monkeypatch, fault
):
    config, data = v3_config(monkeypatch)
    if fault == "helper_pin":
        data[config["normal_stop"]["helper_path"]] += b"changed"
    elif fault == "alternate_helper":
        config["normal_stop"]["helper_path"] = "/alternate/helper"
    elif fault == "missing_stop":
        del config["normal_stop"]
    elif fault == "extra_stop":
        config["normal_stop"]["invent_end"] = True
    elif fault == "receipt_alias":
        config["normal_stop"]["receipt_path"] = config["clock"]["context_path"]
    elif fault == "profile":
        config["normal_stop"]["profile"] = "fallback_from_confinement"
    elif fault == "original_off":
        config["normal_stop"]["profile"] = "stop_only"
        config["metadata"]["arm"] = "original_off"
    elif fault == "baseline_instrumented":
        config["normal_stop"]["profile"] = "stop_only"
    elif fault == "instrumented_baseline":
        config["metadata"]["arm"] = "original_on"
    else:
        config["schema_version"] = w.SCHEMA if fault == "v1_stop" else w.SCHEMA_V2
    data["/lab/config"] = canonical(config)
    with pytest.raises(ValueError):
        w.load_config("/lab/config", hashlib.sha256(data["/lab/config"]).hexdigest())


@pytest.mark.parametrize(
    "target",
    [
        "/elsewhere/completion",
        "/lab/observer/outcomes",
        "/lab/observer/observations.journal",
    ],
)
def test_normal_completion_is_distinct_and_uses_only_existing_observer_directory(
    monkeypatch, target
):
    config, _ = v3_config(monkeypatch)
    config["normal_stop"]["receipt_path"] = target
    with pytest.raises(ValueError):
        w._observer_args(observer_args(), config)


@pytest.mark.parametrize("profile", ["stop_only", "phase_and_clock"])
def test_receipt_validation_precedes_real_end_and_completion_follows_all_closes(
    tmp_path, monkeypatch, profile
):
    config, _ = v3_config(
        monkeypatch,
        profile,
        "original_on" if profile == "stop_only" else "instrumented_on",
    )
    policy = tmp_path / "policy"
    policy.write_bytes(b'{"synthetic":true}')
    options = w._observer_args(observer_args(policy), config)
    events = []
    captured = SimpleNamespace(
        restored=False, require_result=lambda: events.append("validated")
    )

    @contextmanager
    def capture(*args):
        events.append("handler_installed")
        try:
            yield captured
        finally:
            captured.restored = True
            events.append("handler_restored")

    @contextmanager
    def clocks(*args, **kwargs):
        events.append("clock_begin")
        yield
        events.append("clock_closed_with_real_end")

    class Recorder:
        def __init__(self, *args, **kwargs):
            events.append("phase_begin")
            self.closed = False

        def close(self, **kwargs):
            assert kwargs["normal_return"] is True
            self.closed = True
            events.append("phase_closed")

    def publish(actual, *, phase_recorder):
        assert actual is captured and captured.restored is True
        assert (
            phase_recorder is None if profile == "stop_only" else phase_recorder.closed
        )
        events.append("completion")

    monkeypatch.setattr(normal, "capture_control", capture)
    monkeypatch.setattr(normal, "publish_completion", publish)
    monkeypatch.setattr(clock, "record_observer_clock", clocks)
    monkeypatch.setattr(w, "PhaseRecording", Recorder)
    monkeypatch.setattr(w, "record_observer", lambda *args: nullcontext())
    monkeypatch.setattr(
        w.telemetry, "main", lambda argv: events.append("actual_cli_return") or 0
    )
    assert w._normal_observer(config, ["exact-original-arguments"], options) == 0
    assert (
        events.index("actual_cli_return")
        < events.index("validated")
        < events.index("handler_restored")
        < events.index("completion")
    )
    if profile == "phase_and_clock":
        assert (
            events.index("validated")
            < events.index("clock_closed_with_real_end")
            < events.index("phase_closed")
            < events.index("handler_restored")
        )
    else:
        assert "phase_begin" not in events and "clock_begin" not in events


def test_validation_failure_prevents_clock_end_and_completion(tmp_path, monkeypatch):
    config, _ = v3_config(monkeypatch)
    policy = tmp_path / "policy"
    policy.write_bytes(b'{"synthetic":true}')
    options = w._observer_args(observer_args(policy), config)
    events = []

    def fail():
        raise ValueError("synthetic missing genuine result")

    @contextmanager
    def capture(*args):
        yield SimpleNamespace(require_result=fail)

    @contextmanager
    def clocks(*args, **kwargs):
        yield
        events.append("FORBIDDEN_END")

    class Recorder:
        def __init__(self, *args, **kwargs):
            pass

        def close(self, **kwargs):
            assert kwargs["normal_return"] is False
            events.append("incomplete_phase_close")

    monkeypatch.setattr(normal, "capture_control", capture)
    monkeypatch.setattr(
        normal,
        "publish_completion",
        lambda *args, **kwargs: pytest.fail("completion from failed API validation"),
    )
    monkeypatch.setattr(clock, "record_observer_clock", clocks)
    monkeypatch.setattr(w, "PhaseRecording", Recorder)
    monkeypatch.setattr(w, "record_observer", lambda *args: nullcontext())
    monkeypatch.setattr(w.telemetry, "main", lambda argv: 0)
    with pytest.raises(ValueError):
        w._normal_observer(config, [], options)
    assert events == ["incomplete_phase_close"]
