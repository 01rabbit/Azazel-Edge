"""Real private fork/pipes/session/reap; EXPLICITLY FAKE namespace/setns/proof.

No actual network namespace, UID role, socket, signed proof or systemd is used.
"""

import ctypes
import json
import os
from pathlib import Path
import signal
import sys
import time
from types import SimpleNamespace

import pytest
from azazel_edge.outcome.input_transport import transport

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_switch_witness as s

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux waitid/pipe2 private lifecycle"
)


def fixture(tmp_path, monkeypatch):
    parent = os.getpid()
    edge = dict(device=5, inode=20)
    sampled = dict(cookie=71, kernel_boot_id="095d28ff-ca7d-4b08-9e4b-e36a62db4810")
    monkeypatch.setattr(s.g, "boot", lambda: sampled["kernel_boot_id"])
    monkeypatch.setattr(s, "socket_namespace", lambda sock: dict(sampled))
    monkeypatch.setattr(s.g, "guard", lambda: None)
    monkeypatch.setattr(s.context.p, "_output", lambda output: None)
    monkeypatch.setenv(s.context.material.FLAG, "1")
    monkeypatch.setattr(
        s, "_net", lambda: dict(device=1, inode=1) if os.getpid() == parent else edge
    )
    real_stat = os.stat
    proxy = SimpleNamespace(
        **{key: getattr(os, key) for key in dir(os) if not key.startswith("__")}
    )
    proxy.stat = (
        lambda path, **kw: SimpleNamespace(st_dev=5, st_ino=20)
        if str(path).endswith("/ns/net")
        else real_stat(path, **kw)
    )
    monkeypatch.setattr(s, "os", proxy)

    class Setns:
        def __call__(self, fd, flag):
            assert fd >= 0 and flag == 0x40000000
            return 0

    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **k: SimpleNamespace(setns=Setns()))
    fd = os.open(os.devnull, os.O_RDONLY)
    owner = SimpleNamespace(failed=False, edge=lambda: (fd, [5, 20]))
    policy = SimpleNamespace(
        data=dict(
            schema_version="outcome-input-trust/v4",
            scope_ref="synthetic-scope",
            witness_transport=transport("synthetic-scope", sampled),
        )
    )
    adapter = s.WitnessProof(owner, tmp_path)
    adapter.namespace = dict(sampled)
    return adapter, owner, policy, fd


def test_owned_child_calls_original_then_reaps_before_return(tmp_path, monkeypatch):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    marker = tmp_path / "original-called"

    def original(system, bundle, current):
        assert current is policy and os.getpgrp() == os.getpid() == os.getsid(0)
        marker.write_text("original unchanged callback invoked")

    try:
        adapter.run(original, object(), tmp_path, policy)
        proof = json.loads((tmp_path / "switch-witness-1-receipt.json").read_bytes())
        assert marker.exists() and not owner.failed
        assert (
            proof["reaped"] and proof["group_empty_before_reap"] and not proof["errors"]
        )
        with pytest.raises(ChildProcessError):
            os.waitpid(proof["pid"], os.WNOHANG)
    finally:
        os.close(fd)


def test_exited_leader_cannot_leave_live_descendant_or_claim_clean(
    tmp_path, monkeypatch
):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    grandchild = tmp_path / "descendant-pid"
    original_frame = s._frame

    def delayed_frame(channel, deadline, retained):
        original_frame(channel, deadline, retained)
        if b'"blocked"' in retained and os.getpid() == parent:
            time.sleep(0.1)  # Ensure the session leader has exited before cleanup.

    parent = os.getpid()
    monkeypatch.setattr(s, "_frame", delayed_frame)

    def original(*args):
        child = os.fork()
        if child == 0:
            grandchild.write_text(
                json.dumps(
                    dict(
                        pid=os.getpid(),
                        start_ticks=s.lab.pid_identity(
                            Path("/proc/self/stat").read_text()
                        )[1],
                    )
                )
            )
            time.sleep(30)
            os._exit(0)
        deadline = time.monotonic() + 1
        while not grandchild.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        raise RuntimeError("synthetic leader dies after spawning descendant")

    try:
        with pytest.raises(AssertionError):
            adapter.run(original, None, tmp_path, policy)
        identity = json.loads(grandchild.read_text())
        pid = identity["pid"]
        proof = json.loads((tmp_path / "switch-witness-1-receipt.json").read_bytes())
        assert str(pid) in proof["members_before_reap"]
        assert owner.failed and proof["forced"]
        if proof.get("group_empty_before_reap"):
            assert proof["reaped"]
        else:
            assert not proof["reaped"]
            assert "leader_pid_retained_unknown_group" in proof["errors"]
            assert os.waitid(
                os.P_PID, proof["pid"], os.WEXITED | os.WNOHANG | os.WNOWAIT
            )
        # Acceptance assertion BEFORE emergency cleanup: descendant cannot run.
        path = Path(f"/proc/{pid}/stat")
        assert not path.exists() or path.read_text().rsplit(")", 1)[1].split()[0] == "Z"
        if proof["reaped"]:
            with pytest.raises(ChildProcessError):
                os.waitpid(proof["pid"], os.WNOHANG)
    finally:
        if grandchild.exists():
            identity = json.loads(grandchild.read_text())
            pid = identity["pid"]
            pinned = None
            try:
                pinned = os.pidfd_open(pid)
                current = s.lab.pid_identity(Path(f"/proc/{pid}/stat").read_text())
                if current == (str(pid), identity["start_ticks"]):
                    signal.pidfd_send_signal(pinned, signal.SIGKILL)
                    try:
                        os.waitpid(pid, 0)  # Docker PID1 may adopt our dead child.
                    except ChildProcessError:
                        pass
            except ProcessLookupError:
                pass
            except FileNotFoundError:
                pass
            finally:
                if pinned is not None:
                    os.close(pinned)
        receipt_path = tmp_path / "switch-witness-1-receipt.json"
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_bytes())
            if not receipt["reaped"]:
                assert s._members(receipt["pid"]) == {}
                os.waitpid(
                    receipt["pid"], 0
                )  # Emergency test cleanup after assertions.
        os.close(fd)


def test_inventory_failure_still_kills_reserved_owned_group(tmp_path, monkeypatch):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    calls = []
    original_kill = s.os.killpg
    real_members = s._members
    monkeypatch.setattr(
        s,
        "_members",
        lambda pid: (_ for _ in ()).throw(PermissionError("synthetic unknown view")),
    )

    def killing(pid, sig):
        calls.append((pid, sig))
        return original_kill(pid, sig)

    monkeypatch.setattr(s.os, "killpg", killing)
    try:
        with pytest.raises(AssertionError):
            adapter.run(lambda *a: None, None, tmp_path, policy)
        assert calls and owner.failed
        receipt = json.loads((tmp_path / "switch-witness-1-receipt.json").read_bytes())
        assert not receipt["reaped"] and receipt["errors"] and receipt["forced"]
        assert "leader_pid_retained_unknown_group" in receipt["errors"]
        assert os.waitid(os.P_PID, receipt["pid"], os.WEXITED | os.WNOHANG | os.WNOWAIT)
    finally:
        receipt_path = tmp_path / "switch-witness-1-receipt.json"
        if receipt_path.exists():
            receipt = json.loads(receipt_path.read_bytes())
            if not receipt["reaped"]:
                assert real_members(receipt["pid"]) == {}
                os.waitpid(receipt["pid"], 0)
        os.close(fd)


def test_metadata_operation_samples_before_original_without_parent_setns(
    tmp_path, monkeypatch
):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    adapter.namespace = None
    marker = tmp_path / "original-only-after-sample"
    try:
        sampled = adapter.sample_namespace()
        assert sampled == policy.data["witness_transport"]["network_namespace"]
        receipt = json.loads(
            (tmp_path / "namespace-cookie-1-receipt.json").read_bytes()
        )
        assert receipt["operation"] == "namespace-metadata"
        assert receipt["namespace_observation"] == sampled
        assert receipt["reaped"] and receipt["group_empty_before_reap"]
        assert not marker.exists() and not owner.failed
        assert (
            adapter.run(
                lambda *args: marker.write_text("original"), None, tmp_path, policy
            )
            is None
        )
        assert marker.read_text() == "original"
        assert s._net() == dict(device=1, inode=1)
    finally:
        os.close(fd)


def test_unsampled_context_cannot_authorize_original(tmp_path, monkeypatch):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    adapter.namespace = None
    try:
        with pytest.raises(AssertionError, match="current sampled transport"):
            adapter.run(
                lambda *args: pytest.fail("original must not run"),
                None,
                tmp_path,
                policy,
            )
        assert list(tmp_path.iterdir()) == [] and not owner.failed
    finally:
        os.close(fd)


def test_changed_cookie_is_retained_and_poisons_owned_scope(tmp_path, monkeypatch):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    changed = dict(adapter.namespace, cookie=72)
    monkeypatch.setattr(s, "socket_namespace", lambda sock: changed)
    try:
        with pytest.raises(RuntimeError, match="cookie/boot changed"):
            adapter.sample_namespace()
        receipt = json.loads(
            (tmp_path / "namespace-cookie-1-receipt.json").read_bytes()
        )
        assert receipt["namespace_observation"] == changed and receipt["reaped"]
        assert owner.failed and adapter.namespace["cookie"] == 71
    finally:
        os.close(fd)


def test_observed_other_boot_fails_with_child_reaped(tmp_path, monkeypatch):
    adapter, owner, policy, fd = fixture(tmp_path, monkeypatch)
    changed = dict(
        adapter.namespace, kernel_boot_id="195d28ff-ca7d-4b08-9e4b-e36a62db4810"
    )
    monkeypatch.setattr(s, "socket_namespace", lambda sock: changed)
    try:
        with pytest.raises(AssertionError, match="sample boot differs"):
            adapter.sample_namespace()
        receipt = json.loads(
            (tmp_path / "namespace-cookie-1-receipt.json").read_bytes()
        )
        assert receipt["reaped"] and owner.failed
        assert (
            json.loads((tmp_path / "namespace-cookie-1-result.raw").read_bytes())[
                "namespace"
            ]
            == changed
        )
    finally:
        os.close(fd)
