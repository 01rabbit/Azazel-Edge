"""Synthetic pinned-v2 bootstrap controls, preserving the existing v1 boundary."""

from contextlib import contextmanager, nullcontext
import hashlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_phase_worker as w
import signed_network_load_clock as clock
from signed_network_phase_recording import canonical
from test_signed_network_phase_worker import synthetic_config


def v2_config(monkeypatch):
    config, data = synthetic_config(monkeypatch)
    helper_path = str(Path(config["worker_path"]).with_name("signed_network_load_clock.py"))
    recording_path = str(Path(config["worker_path"]).with_name("signed_network_recording.py"))
    data[helper_path] = b"SYNTHETIC CLOCK HELPER"
    data[recording_path] = b"SYNTHETIC ORIGINAL CLOCK RECORDER"
    config["schema_version"] = w.SCHEMA_V2
    config["clock"] = dict(helper_path=helper_path, helper_sha256=hashlib.sha256(data[helper_path]).hexdigest(),
                           recording_path=recording_path, recording_sha256=hashlib.sha256(data[recording_path]).hexdigest(),
                           calls_path="/lab/observer/hostile-clock-calls.jsonl", context_path="/lab/observer/hostile-clock-context.jsonl")
    phase_path = str(Path(config["worker_path"]).with_name("signed_network_phase_recording.py"))
    config["metadata"]["code_sha256"] = hashlib.sha256(
        b"\0".join(data[path] for path in (config["worker_path"], phase_path, helper_path, recording_path))
    ).hexdigest()
    data["/lab/config"] = canonical(config)
    return config, data


def test_explicit_v2_loads_all_four_pinned_bootstrap_files(monkeypatch):
    config, data = v2_config(monkeypatch)
    assert w.load_config("/lab/config", hashlib.sha256(data["/lab/config"]).hexdigest()) == config


@pytest.mark.parametrize("fault", ["helper", "original_recorder", "extra_clock", "alias", "alternate_helper", "missing_clock", "unknown_schema", "v1_with_clock"])
def test_v2_pin_shape_and_version_failures_refuse_before_calls(monkeypatch, fault):
    config, data = v2_config(monkeypatch)
    if fault == "helper":
        data[config["clock"]["helper_path"]] += b"changed"
    elif fault == "original_recorder":
        data[config["clock"]["recording_path"]] += b"changed"
    elif fault == "extra_clock":
        config["clock"]["inferred_end"] = True
    elif fault == "alias":
        config["clock"]["calls_path"] = config["traces"]["observer"]
    elif fault == "alternate_helper":
        config["clock"]["helper_path"] = "/alternate/helper.py"
    elif fault == "missing_clock":
        del config["clock"]
    elif fault == "v1_with_clock":
        config["schema_version"] = w.SCHEMA
    else:
        config["schema_version"] = "edge-phase-timing-config/v3"
    data["/lab/config"] = canonical(config)
    with pytest.raises(ValueError):
        w.load_config("/lab/config", hashlib.sha256(data["/lab/config"]).hexdigest())


def observer_args(policy_path="/lab/telemetry-policy"):
    return ["--input", "/lab/source", "--output", "/lab/observer/outcomes",
            "--policy", str(policy_path), "--interface", "lo", "--poll-seconds", "0.05",
            "--sample-interval-seconds", "0.05", "--journal-directory", "/lab/observer",
            "--journal-scope", "synthetic", "--journal-boot-id", "boot",
            "--journal-max-bytes", "1048576", "--journal-resume-input", "--input-auth-policy", "/lab/trust"]


def test_v2_clock_outputs_must_stay_in_existing_observer_directory(monkeypatch):
    config, _ = v2_config(monkeypatch)
    assert w._observer_args(observer_args(), config)["--journal-directory"] == "/lab/observer"
    config["clock"]["context_path"] = "/somewhere/else/context"
    with pytest.raises(ValueError, match="existing observer directory"):
        w._observer_args(observer_args(), config)


@pytest.mark.parametrize("version", [w.SCHEMA, w.SCHEMA_V2])
def test_worker_invokes_exact_original_cli_once_and_v1_never_uses_clocks(tmp_path, monkeypatch, version):
    config, _ = v2_config(monkeypatch)
    config["schema_version"] = version
    policy_path = tmp_path / "policy"
    policy_path.write_bytes(b'{"synthetic":true}')
    arguments = observer_args(policy_path)
    monkeypatch.setattr(w, "load_config", lambda *a: config)
    calls, closed, clock_calls = [], [], []

    class Recorder:
        def __init__(self, *args, **kwargs):
            pass

        def close(self, **kwargs):
            closed.append(kwargs)

    @contextmanager
    def clock_context(*args, **kwargs):
        clock_calls.append((args, kwargs))
        yield

    monkeypatch.setattr(w, "PhaseRecording", Recorder)
    monkeypatch.setattr(w, "record_observer", lambda *a: nullcontext())
    monkeypatch.setattr(clock, "record_observer_clock", clock_context)
    monkeypatch.setattr(w.telemetry, "main", lambda args: calls.append(args) or 0)
    assert w.main(["--role", "observer", "--config", "/lab/config", "--config-sha256", "1" * 64, "--", *arguments]) == 0
    assert calls == [arguments]
    assert closed == [{"normal_return": True}]
    assert len(clock_calls) == (1 if version == w.SCHEMA_V2 else 0)
    if clock_calls:
        assert clock_calls[0][1]["metadata"]["role"] == "observer"
        assert clock_calls[0][1]["policy"] == {"synthetic": True}
        assert clock_calls[0][1]["policy_source_ref"] == str(policy_path)


@pytest.mark.parametrize("reserved", ["/lab/observer/outcomes", "/lab/observer/observations.journal"])
def test_v2_clock_output_cannot_alias_original_output_or_journal(monkeypatch, reserved):
    config, _ = v2_config(monkeypatch)
    config["clock"]["calls_path"] = reserved
    with pytest.raises(ValueError, match="aliases original evidence"):
        w._observer_args(observer_args(), config)
