"""Mocked role handshake binding; no native process, Source or systemd launch."""

import importlib.util
import base64
import io
import json
from pathlib import Path
import subprocess
import sys
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
            self.stdout = io.BytesIO(
                b""
                if fault == "import_error"
                else json.dumps(bootstrap).encode() + b"\n"
            )
            self.returncode = 1 if fault == "import_error" else 0

        def poll(self):
            return 0

        def communicate(self, data=None, timeout=None):
            calls.append(data)
            if fault == "import_error":
                return b"", b"ModuleNotFoundError: native_accounting\n" + b"x" * 40000
            return json.dumps(
                dict(receipt=dict(actor=own), source_base64="")
            ).encode(), b""

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
    assert calls == [("GO " + "a" * 32 + "\n").encode()]
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
    assert not any(data is not None for data in calls)
    binding = json.loads(files["reader-binding.json"])
    assert binding["status"] == "failure" and binding["error"] is not None


def test_fast_exit_before_bootstrap_retains_bounded_original_stderr(monkeypatch):
    g, command, calls, files, _ = handshake(monkeypatch, "import_error")
    with pytest.raises(OSError, match="bootstrap EOF"):
        lab.observed_readback(g, command, "normal-four", files)
    assert calls == [None]  # Already exited runner must still be drained.
    binding = json.loads(files["reader-binding.json"])
    stderr = base64.b64decode(binding["runner_stderr_base64"], validate=True)
    assert stderr.startswith(b"ModuleNotFoundError: native_accounting\n")
    assert len(stderr) == 32768 and binding["runner_stderr_truncated"] is True
    assert binding["runner_stderr_bytes"] == 40000 + len(
        b"ModuleNotFoundError: native_accounting\n"
    )
    assert binding["runner_returncode"] == 1
    assert binding["runner_stdout_base64"] == "" and binding["bootstrap"] is None


def test_isolated_role_script_resolves_trusted_sibling_without_running_role():
    script = Path(__file__).parent / "real_systemd/role_probe.py"
    probe = (
        "import pathlib,runpy,sys;"
        "runpy.run_path(sys.argv[1],run_name='isolated_import_probe');"
        "import native_accounting;"
        "assert pathlib.Path(native_accounting.__file__).resolve()"
        "==pathlib.Path(sys.argv[1]).resolve().with_name('native_accounting.py')"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", probe, str(script)],
        check=True,
        capture_output=True,
        timeout=10,
    )
