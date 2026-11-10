"""Real witness process death/readiness; no system service or network mutation."""

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

import pytest

from test_outcome_input_auth_linux import Fixture, Child, ROOT
from azazel_edge.outcome.input_witness import WitnessStore, serve

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root for real witness roles",
)


@pytest.fixture
def f():
    value = Fixture()
    try:
        yield value
    finally:
        value.clean()


def start(f, initialize=False):
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "azazel_edge.outcome.input_witness",
            "--policy",
            str(f.policy_file),
            "--private-key",
            str(f.wk),
            *(["--initialize"] if initialize else []),
        ],
        env=dict(os.environ, PYTHONPATH=str(ROOT / "py")),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(process.stderr.read().decode())
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.connect(f.p.data["socket_path"])
            return process
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.02)
    process.kill()
    process.wait()
    raise AssertionError("witness start deadline")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_normal_service_stop_cleans_only_endpoint_and_reopens_same_history(f, sig):
    process = start(f, True)
    try:
        child = Child(f, True)
        assert child.initial.get("ready"), child.initial
        child.close()
        anchor = f.anchors.read_bytes()
        journal = f.journal.read_bytes()
        process.send_signal(sig)
        assert process.wait(timeout=5) == 0
        process.stderr.close()
        assert not Path(f.p.data["socket_path"]).exists()
        process = start(f)
        assert f.anchors.read_bytes() == anchor and f.journal.read_bytes() == journal
    finally:
        process.terminate()
        process.wait(timeout=5)
        process.stderr.close()


def test_sigkill_stale_transport_reopens_without_changing_protected_history(f):
    process = start(f, True)
    try:
        child = Child(f, True)
        assert child.initial.get("ready"), child.initial
        child.close()
        path = Path(f.p.data["socket_path"])
        before = f.anchors.read_bytes(), f.journal.read_bytes(), f.source.read_bytes()
        inode = path.stat().st_ino
        process.kill()
        process.wait(timeout=5)
        assert path.stat().st_ino == inode
        process.stderr.close()
        process = start(f)
        # A filesystem may reuse the retired inode number. Liveness and a
        # fresh authenticated peer response, not inode inequality, prove reopen.
        assert path.exists()
        assert before == (
            f.anchors.read_bytes(),
            f.journal.read_bytes(),
            f.source.read_bytes(),
        )
        child = Child(f)
        assert child.initial.get("ready"), child.initial
        child.close()
    finally:
        process.terminate()
        process.wait(timeout=5)
        process.stderr.close()


@pytest.mark.parametrize("fault", ["file", "symlink", "foreign", "live", "bad_anchor"])
def test_unverifiable_store_or_endpoint_never_cleanup_or_signal_ready(f, fault):
    with WitnessStore(f.p, f.wk, initialize=True):
        pass
    path = Path(f.p.data["socket_path"])
    server = None
    if fault == "file":
        path.write_text("preserve")
    elif fault == "symlink":
        path.symlink_to(f.wk)
    else:
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        if fault == "live":
            server.listen(1)
        else:
            server.close()
        if fault == "foreign":
            os.chown(path, 1000, 1000)
        if fault == "bad_anchor":
            f.anchors.write_bytes(b"invalid\n")
    before = f.anchors.read_bytes(), f.source.read_bytes(), path.lstat().st_ino

    class NeverReady:
        def set(self):
            raise AssertionError("unverified witness announced readiness")

    try:
        with pytest.raises(OSError):
            serve(f.p, f.wk, ready=NeverReady())
        assert before == (
            f.anchors.read_bytes(),
            f.source.read_bytes(),
            path.lstat().st_ino,
        )
    finally:
        if server is not None:
            server.close()


def test_notify_failure_closes_transport_without_resetting_store(f):
    with WitnessStore(f.p, f.wk, initialize=True):
        pass
    before = f.anchors.read_bytes()

    class Unavailable:
        def set(self):
            raise OSError("manager unavailable")

    with pytest.raises(OSError):
        serve(f.p, f.wk, ready=Unavailable())
    assert f.anchors.read_bytes() == before
    assert not Path(f.p.data["socket_path"]).exists()
