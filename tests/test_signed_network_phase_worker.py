"""Synthetic strict bootstrap/proxy controls; no Linux actors or actual trials."""

from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_phase_worker as w


@pytest.mark.parametrize("value", [
    {"capture_apparmor_profile": "enforced"}, {"native_profile": None},
    {"nested": {"AppArmorProfile": "x"}}, {"nested": [{"profile": "x"}]},
])
def test_any_declared_profile_refuses_instead_of_fallback(value):
    with pytest.raises(ValueError, match="profile"):
        w.refuse_profiles(value)


def config():
    return dict(policy_path="/lab/trust", registration_path="/lab/registration", worker_path="/lab/worker.py")


def receiver_argv():
    return [sys.executable, "-m", "azazel_edge.outcome.input_live", "--policy", "/lab/trust",
            "--registration", "/lab/registration", "--private-key", "/private/key",
            "--boot-ref", "boot", "--receive-fd", "77", "--session-ref", "a" * 32]


def expected_kwargs():
    return dict(pass_fds=(77,), stdin=w.input_live.subprocess.DEVNULL,
                stdout=w.input_live.subprocess.PIPE, user=1234, group=1234,
                extra_groups=[], cwd="/", env={"PATH": "/nonexistent", "PYTHONPATH": str(Path(w.input_live.__file__).resolve().parents[2])},
                close_fds=True)


def prepare(monkeypatch):
    calls = []
    sentinel = object()
    module = w.input_live.subprocess
    monkeypatch.setattr(w.input_live, "subprocess", w.ModuleProxy(module, Popen=lambda *a, **k: (calls.append((a, k)), sentinel)[1]))
    policy = SimpleNamespace(data={"producer_uid": 1234})
    monkeypatch.setattr(w.input_auth.TrustPolicy, "from_file", lambda *a, **k: policy)
    monkeypatch.setattr(w.input_live, "registration", lambda *a: {"no_enforcing_fields": True})
    return calls, sentinel


def test_exact_receiver_only_transformed_with_native_passthrough(monkeypatch):
    calls, sentinel = prepare(monkeypatch)
    original_module = w.input_live.subprocess
    kwargs = expected_kwargs()
    with w.launcher_receiver_proxy(config(), "/lab/config", "b" * 64):
        assert w.input_live.subprocess.Popen(receiver_argv(), **kwargs) is sentinel
        native = ["/proc/self/fd/19", "--live-origin-fd", "20"]
        assert w.input_live.subprocess.Popen(native, close_fds=True) is sentinel
        with pytest.raises(ValueError):
            w.input_live.subprocess.Popen(receiver_argv(), **kwargs)
    assert w.input_live.subprocess is original_module
    transformed = calls[0][0][0]
    assert transformed[:9] == [sys.executable, "/lab/worker.py", "--role", "receiver", "--config", "/lab/config", "--config-sha256", "b" * 64, "--"]
    assert transformed[9:] == receiver_argv()[3:]
    assert calls[0][1] == kwargs
    assert calls[1] == ((native,), {"close_fds": True})


@pytest.mark.parametrize("fault", ["uid", "fd", "env", "stdio", "session", "interpreter", "extraarg"])
def test_nonexact_receiver_refused_before_popen(monkeypatch, fault):
    calls, _ = prepare(monkeypatch)
    argv, kwargs = receiver_argv(), expected_kwargs()
    if fault == "uid":
        kwargs["user"] = 0
    elif fault == "fd":
        kwargs["pass_fds"] = (77, 78)
    elif fault == "env":
        kwargs["env"] = {"PATH": "/bin"}
    elif fault == "stdio":
        kwargs["stdout"] = None
    elif fault == "session":
        argv[-1] = "unknown"
    elif fault == "interpreter":
        argv[0] = "/alternate/python"
    else:
        argv += ["--unknown", "x"]
    with w.launcher_receiver_proxy(config(), "/lab/config", "b" * 64):
        with pytest.raises(ValueError):
            w.input_live.subprocess.Popen(argv, **kwargs)
    assert calls == []


def test_cli_requires_explicit_original_delimiter(monkeypatch):
    monkeypatch.setattr(w, "load_config", lambda *a: pytest.fail("configuration loaded before delimiter check"))
    with pytest.raises(ValueError):
        w.main(["--role", "observer", "--config", "/lab/config", "--config-sha256", "b" * 64])


def test_profile_refuses_before_launcher_child(monkeypatch):
    calls, _ = prepare(monkeypatch)
    monkeypatch.setattr(w.input_live, "registration", lambda *a: {"capture_apparmor_profile": "enforcing"})
    with pytest.raises(ValueError, match="profile"):
        with w.launcher_receiver_proxy(config(), "/lab/config", "b" * 64):
            pytest.fail("profile was accepted")
    assert calls == []


def synthetic_config(monkeypatch):
    import hashlib
    import json
    from signed_network_phase_recording import canonical

    worker_bytes, helper_bytes = b"SYNTHETIC WORKER", b"SYNTHETIC HELPER"
    worker_path = str(Path(w.__file__).absolute())
    result = dict(
        schema_version=w.SCHEMA,
        metadata=dict(run_id="synthetic", arm="instrumented_on", input_sha256="1" * 64,
                      code_sha256=hashlib.sha256(worker_bytes + b"\0" + helper_bytes).hexdigest(),
                      core_sha256="3" * 64,
                      interpreter_sha256=hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()),
        policy_path="/lab/trust", registration_path="/lab/registration",
        traces=dict(signer="/lab/producer/trace", observer="/lab/observer/trace", witness="/lab/witness/trace"),
        worker_path=worker_path, worker_sha256=hashlib.sha256(worker_bytes).hexdigest(),
    )
    data = {"/lab/config": canonical(result), worker_path: worker_bytes,
            str(Path(worker_path).with_name("signed_network_phase_recording.py")): helper_bytes}
    monkeypatch.setattr(w, "_root_bytes", lambda path, *args: data[str(path)])
    monkeypatch.setattr(w.input_auth, "read_regular", lambda *a, **k: (json.dumps(dict(binary_sha256="3" * 64)).encode(), None))
    return result, data


def test_pinned_root_bootstrap_config_round_trip(monkeypatch):
    import hashlib

    expected, data = synthetic_config(monkeypatch)
    assert w.load_config("/lab/config", hashlib.sha256(data["/lab/config"]).hexdigest()) == expected


@pytest.mark.parametrize("fault", ["config_pin", "worker_pin", "helper_pin", "profile", "alias", "unknown_field"])
def test_pinned_bootstrap_refuses_changed_code_profile_and_shape(monkeypatch, fault):
    import hashlib
    import json
    from signed_network_phase_recording import canonical

    config_value, data = synthetic_config(monkeypatch)
    if fault == "worker_pin":
        data[config_value["worker_path"]] += b"changed"
    elif fault == "helper_pin":
        data[str(Path(config_value["worker_path"]).with_name("signed_network_phase_recording.py"))] += b"changed"
    elif fault == "profile":
        monkeypatch.setattr(w.input_auth, "read_regular", lambda *a, **k: (json.dumps(dict(binary_sha256="3" * 64, capture_apparmor_profile="enforcing")).encode(), None))
    elif fault == "alias":
        config_value["traces"]["observer"] = config_value["traces"]["signer"]
    elif fault == "unknown_field":
        config_value["extra"] = True
    data["/lab/config"] = canonical(config_value)
    pin = "0" * 64 if fault == "config_pin" else hashlib.sha256(data["/lab/config"]).hexdigest()
    with pytest.raises(ValueError):
        w.load_config("/lab/config", pin)


def test_root_bytes_uses_existing_strict_root_mode_and_bound(monkeypatch):
    calls = []
    monkeypatch.setattr(w.input_auth, "read_regular", lambda *a, **k: (calls.append((a, k)) or b"original", None))
    assert w._root_bytes("/lab/config", 65536) == b"original"
    assert calls == [((Path("/lab/config"),), dict(owner=0, mode=0o444, max_bytes=65536))]
