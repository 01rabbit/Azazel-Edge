"""Mocked role handshake binding; no native process, Source or systemd launch."""

import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "native_accounting_lab_under_test",
    Path(__file__).parent / "real_systemd/native_accounting.py",
)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


def handshake(monkeypatch, fault=None):
    challenge = "a" * 32
    invocation = "b" * 32
    actual = dict(
        pid=8123,
        ppid=1,
        start_ticks=4567,
        uid=61002,
        gid=61002,
        groups=[61002],
        apparmor_label="edge400-observer (enforce)",
        cap_eff=0,
        cap_prm=0,
        cap_bnd=0,
        cap_amb=0,
        no_new_privs=True,
    )
    own = dict(actual, start_ticks=None)
    bootstrap = dict(
        schema_version="edge-native-source-reader-bootstrap/v1",
        pid=actual["pid"],
        challenge=challenge,
        invocation_id=invocation,
        actor=own,
    )
    if fault == "reported_pid":
        bootstrap["pid"] += 1
    elif fault == "nonce":
        bootstrap["challenge"] = "c" * 32
    elif fault == "invocation":
        bootstrap["invocation_id"] = "c" * 32
    elif fault == "own_identity":
        bootstrap["actor"] = dict(own, uid=0)
    calls = []

    class Process:
        def __init__(self, *args, **kwargs):
            self.stdout = io.StringIO(json.dumps(bootstrap) + "\n")
            self.returncode = 0

        def poll(self):
            return 0

        def communicate(self, data=None, timeout=None):
            calls.append(data)
            return json.dumps(dict(receipt=dict(actor=own), source_base64="")), ""

    def systemctl(*args, **kwargs):
        if "--property=LoadState" in args:
            return SimpleNamespace(stdout="not-found\n")
        return SimpleNamespace(
            stdout=f"MainPID={actual['pid']}\nInvocationID={invocation}\n"
        )

    g = SimpleNamespace(
        PYTHON=Path("/opt/edge400-runtime/bin/python"),
        SRC=Path("/opt/edge400-src"),
        systemctl=systemctl,
    )
    expected = [
        str(g.PYTHON.with_name("edge-observe")),
        "-I",
        str(g.SRC / "tests/real_systemd/role_probe.py"),
        "readonly-source",
        "--challenge",
        challenge,
    ]
    cmdline = b"\0".join(x.encode() for x in expected) + b"\0"
    if fault == "actual_command":
        cmdline = b"unrelated-process\0"
    monkeypatch.setattr(lab.secrets, "token_hex", lambda size: challenge)
    monkeypatch.setattr(lab.subprocess, "Popen", Process)
    monkeypatch.setattr(
        lab.select,
        "select",
        lambda *args: ([], [], []) if fault == "timeout" else ([True], [], []),
    )
    monkeypatch.setattr(
        lab,
        "actor",
        lambda pid: actual
        if pid == actual["pid"]
        else pytest.fail("unbound actor read"),
    )
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda path: cmdline
        if str(path) == f"/proc/{actual['pid']}/cmdline"
        else pytest.fail("unexpected target read"),
    )
    files = {}

    def command(*args, **kwargs):
        return ["fixed-existing-role-command"]

    return g, command, calls, files, actual


def test_observer_root_binding_supplies_only_actually_observed_start_tick(monkeypatch):
    g, command, calls, files, actual = handshake(monkeypatch)
    result = lab.observed_readback(g, command, "normal-four", files)
    assert calls == ["GO " + "a" * 32 + "\n"]
    assert result["receipt"]["actor"] == actual
    binding = json.loads(files["reader-binding.json"])
    assert binding["status"] == "verified_root_observed_role"
    assert binding["actual_actor"]["start_ticks"] == 4567
    assert binding["bootstrap"]["actor"]["start_ticks"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "reported_pid",
        "nonce",
        "invocation",
        "own_identity",
        "actual_command",
        "timeout",
    ],
)
def test_observer_binding_rejection_never_releases_read_and_retains_diagnostic(
    monkeypatch, fault
):
    g, command, calls, files, _ = handshake(monkeypatch, fault)
    with pytest.raises((AssertionError, OSError)):
        lab.observed_readback(g, command, "normal-four", files)
    assert calls == []
    binding = json.loads(files["reader-binding.json"])
    assert binding["status"] == "failure" and binding["error"] is not None
