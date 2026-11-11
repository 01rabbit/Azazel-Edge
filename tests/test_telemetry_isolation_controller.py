"""Synthetic two-role controller flow and real private stdio only; no VM/LSM proof."""

from copy import deepcopy
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_controller as c
from test_telemetry_isolation_result import BOOT, final, raw


def fixture(tmp_path, monkeypatch, fault=None):
    output = tmp_path / "output"
    events = []
    instances = []
    fixture_data = tmp_path / "synthetic-proc"
    fixture_data.mkdir()
    probe_ready, probe_final = final(fixture_data)
    peer_ready, peer_final = final(fixture_data, "peer")
    baseline = dict(
        kernel_boot_id=BOOT,
        root_before={"parent": "original"},
        intended_assets={},
        asset_confirmations={},
    )

    def stage(path):
        path.mkdir(mode=0o700)
        c.LAB.save_json(path / "root-before.json", baseline["root_before"])
        events.append("staged")
        return baseline

    monkeypatch.setattr(c.setup, "stage", stage)

    def workspace(path, base):
        work = path / "namespace-evidence"
        work.mkdir(mode=0o700)
        events.append("workspace")
        return work

    monkeypatch.setattr(c, "_workspace", workspace)

    class Assets:
        def __init__(self, work):
            self.work = work
            self.created = {}
            self.names = {}
            instances.append(self)

        def create_namespace(self, name):
            events.append("create:" + name)
            fd = os.open(os.devnull, os.O_RDONLY)
            info = os.fstat(fd)
            self.created[name] = (fd, info.st_dev, info.st_ino)

        def ns(self, *argv):
            events.append("ns-command")
            return SimpleNamespace(stdout="")

        def close(self):
            events.append("namespace-close")
            assert (output / "actor-cleanup.json").exists()
            for fd, _, _ in self.created.values():
                os.close(fd)
            c.LAB.save_json(self.work / "cleanup.json", dict(synthetic_cleanup=True))
            if fault == "namespaceclose":
                raise OSError("synthetic evidence error")

    monkeypatch.setattr(c.network, "Assets", Assets)

    def command(*argv, **kwargs):
        assert argv[:3] == ("ip", "netns", "pids") and kwargs == dict(timeout=2)
        events.append("namespace-residents")
        return SimpleNamespace(stdout="999\n" if fault == "resident" else "")

    monkeypatch.setattr(c.network, "command", command)
    monkeypatch.setattr(
        c, "_fenced", lambda assets, mode: [5, 20 if mode == "probe" else 21]
    )

    class Stream:
        closed = False

        def close(self):
            self.closed = True
            events.append("pipe-close")

    class Process:
        def __init__(self, mode):
            self.mode = mode
            self.returncode = None
            self.pid = 900 if mode == "peer" else 901
            self.stdin = Stream()
            self.stdout = Stream()
            self.stderr = Stream()

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            assert timeout <= 1
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    def launch(mode, path):
        events.append("launch:" + mode)
        return Process(mode)

    monkeypatch.setattr(c, "_launch", launch)

    def ready(process, mode, assets, base, path, tracked):
        events.append("ready-proof:" + mode)
        unit = c.C.role_spec(mode)["unit"]
        tracked[unit].append(dict(MainPID=str(123 if mode == "peer" else 456)))
        if fault == "ready":
            raise ValueError("synthetic unexpected FD")
        value = peer_ready if mode == "peer" else probe_ready
        identity = deepcopy(value["identity"])
        return value, dict(
            identity=identity,
            evidence=dict(
                namespaces=dict(net=[5, 21 if mode == "peer" else 20]),
                binfmt_before={
                    "status": 999 if fault == "binfmtroles" and mode == "probe" else 100
                },
            ),
        )

    monkeypatch.setattr(c, "_ready", ready)
    live = []

    def targets(*args):
        live.append(args[-1])
        events.append("live:" + args[-1])
        if fault == "postlive" and args[-1] == "after":
            raise ValueError("synthetic peer changed")
        return dict(pid1_stat="1 (systemd) " + " ".join(["S"] + ["0"] * 18 + ["1"]))

    monkeypatch.setattr(c, "_live_targets", targets)

    def exchange(process, payload, prefix, path):
        events.append("exchange:" + prefix)
        if payload is None:
            process.returncode = 0
            return b"", b""
        if process.mode == "probe":
            assert (
                events.index("ready-proof:peer")
                < events.index("ready-proof:probe")
                < events.index("live:before")
            )
            value = json.loads(payload)
            assert (
                set(value) == {"pid", "tgid", "address", "size", "kernel_boot_id"}
                and value["pid"] == 123
            )
            if fault == "reply":
                raise RuntimeError("synthetic partial reply")
            process.returncode = 0
            value = deepcopy(probe_final)
            if fault == "missingop":
                value["operations"].pop()
            return raw(value), b""
        assert payload == b"stop\n" and live == ["before", "after"]
        process.returncode = 0
        return raw(peer_final), b""

    monkeypatch.setattr(c, "_exchange", exchange)

    def cleanup(units, tracked):
        events.append("all-actor-stop")
        assert units == c.UNITS and set(tracked) == set(c.UNITS)
        return dict(
            errors=["synthetic unknown cgroup"] if fault == "cgroup" else [],
            units=[dict(unit=unit) for unit in units],
        )

    monkeypatch.setattr(c.LAB, "cleanup", cleanup)

    def invariants(*args, **kw):
        events.append("all-invariants")
        assert kw == dict(require_new=True)
        if fault == "invariants":
            raise ValueError("synthetic old asset changed")

    monkeypatch.setattr(c.setup, "invariants", invariants)
    if fault == "actorreceipt":
        save = c.LAB.save_json

        def saving(path, value):
            if path.name == "actor-cleanup.json":
                raise OSError("synthetic disk failure")
            save(path, value)

        monkeypatch.setattr(c.LAB, "save_json", saving)
    return output, events, instances


def test_complete_synthetic_flow_retains_actor_and_asset_cleanup_separately(
    tmp_path, monkeypatch
):
    output, events, instances = fixture(tmp_path, monkeypatch)
    result = c.run(output)
    assert result["status"] == "new_role_precheck_complete"
    assert (
        result["authorizes_transition"]
        is result["experiment"]
        is result["production_admission"]
        is False
    )
    assert events.index("launch:peer") < events.index("launch:probe")
    assert (
        events.index("live:after")
        < events.index("exchange:peer-final")
        < events.index("all-actor-stop")
    )
    assert (
        events.index("all-actor-stop")
        < events.index("namespace-close")
        < events.index("all-invariants")
    )
    assert (output / "actor-cleanup.json").exists() and (
        output / "namespace-evidence/cleanup.json"
    ).exists()
    assert (output / "final-result.json").exists()
    for fd, _, _ in instances[0].created.values():
        with pytest.raises(OSError) as error:
            os.fstat(fd)
        assert error.value.errno == errno.EBADF


@pytest.mark.parametrize(
    "fault",
    [
        "ready",
        "reply",
        "missingop",
        "postlive",
        "binfmtroles",
        "namespaceclose",
        "invariants",
        "actorreceipt",
        "cgroup",
        "resident",
    ],
)
def test_any_gap_blocks_success_and_always_attempts_actor_stops_and_invariants(
    tmp_path, monkeypatch, fault
):
    output, events, instances = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((ValueError, RuntimeError, OSError, AssertionError)):
        c.run(output)
    assert "all-actor-stop" in events and "all-invariants" in events
    assert (
        not (output / "final-result.json").exists()
        and (output / "failure.json").exists()
    )
    if fault in ("actorreceipt", "cgroup", "resident"):
        assert "namespace-close" not in events
    elif fault in ("ready", "reply", "missingop", "postlive"):
        assert "namespace-close" in events
    for fd, _, _ in instances[0].created.values():
        with pytest.raises(OSError):
            os.fstat(fd)


def process(script):
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def test_bounded_exchange_preserves_exact_private_streams_without_running_any_role(
    tmp_path,
):
    child = process(
        "import sys; data=sys.stdin.buffer.readline(); sys.stdout.buffer.write(data); sys.stderr.write('private diagnostic')"
    )
    try:
        stdout, stderr = c._exchange(child, b"PUBLIC FRAME\n", "fixed", tmp_path)
        assert stdout == b"PUBLIC FRAME\n" and stderr == b"private diagnostic"
        assert (tmp_path / "fixed.stdout").read_bytes() == stdout
        assert (tmp_path / "fixed.stderr").read_bytes() == stderr
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_oversized_stream_is_retained_as_failure_not_unbounded_read(tmp_path):
    child = process(
        "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(b'x'*70000)"
    )
    try:
        with pytest.raises(AssertionError, match="retention bound"):
            c._exchange(child, b"PUBLIC\n", "large", tmp_path)
        assert len((tmp_path / "large.stdout").read_bytes()) == 65537
        assert (tmp_path / "large.stderr").exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_first_stream_save_error_never_skips_remaining_stream_receipt(
    tmp_path, monkeypatch
):
    save = c.LAB.save

    def saving(path, value):
        if path.name == "failure.stdout":
            raise OSError("synthetic write failure")
        save(path, value)

    monkeypatch.setattr(c.LAB, "save", saving)
    child = process(
        "import sys;sys.stdin.buffer.read();sys.stderr.write('unchanged stderr')"
    )
    try:
        with pytest.raises(OSError):
            c._exchange(child, b"PUBLIC\n", "failure", tmp_path)
        assert (tmp_path / "failure.stderr").read_bytes() == b"unchanged stderr"
        assert (tmp_path / "failure.result.json").exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_ready_handoff_uses_only_pid_dumpable_projection_and_real_counterparts(
    tmp_path, monkeypatch
):
    from test_telemetry_isolation_result import ready
    import hashlib

    value = ready("peer")
    source = b"PUBLIC SYNTHETIC WORKER SOURCE"
    value["source_sha256"] = hashlib.sha256(source).hexdigest()
    calls = []
    counterparts = {fd: dict(device=1, inode=100 + fd) for fd in range(3)}
    monkeypatch.setattr(
        c.p, "stdio_identity", lambda process: calls.append("stdio") or counterparts
    )

    def receive(process, path):
        calls.append("ready")
        c.LAB.save(path, raw(value))

    monkeypatch.setattr(c, "_receive_ready", receive)
    monkeypatch.setattr(
        c.setup,
        "_read",
        lambda path, *a: (
            (raw(value) if str(path).endswith("ready.raw") else source),
            {},
        ),
    )
    monkeypatch.setattr(c.LAB, "unit_snapshot", lambda unit: dict(MainPID="123"))
    monkeypatch.setattr(c.p, "collect_effective", lambda *a: {"synthetic": "effective"})
    monkeypatch.setattr(c, "_fenced", lambda *a: [5, 21])

    def actor(mode, **kw):
        calls.append("actor")
        assert mode == "peer" and kw["ready_identity"] == dict(pid=123, dumpable=1)
        assert kw["expected_stdio"] is counterparts and kw["expected_namespace"] == [
            5,
            21,
        ]
        return dict(identity=value["identity"], evidence={})

    monkeypatch.setattr(c.p, "collect_actor", actor)
    tracked = {c.C.role_spec("peer")["unit"]: []}
    actual, proof = c._ready(
        SimpleNamespace(poll=lambda: None),
        "peer",
        None,
        dict(kernel_boot_id=BOOT),
        tmp_path,
        tracked,
    )
    assert actual == value and proof["identity"] == value["identity"]
    assert calls == ["stdio", "ready", "actor"]


@pytest.mark.parametrize("fault", [None, "pid", "namespace", "boot", "binfmt"])
def test_live_target_drift_is_retained_before_refusal(tmp_path, monkeypatch, fault):
    unit = c.C.role_spec("peer")["unit"]
    state = dict(
        LoadState="loaded",
        ActiveState="active",
        MainPID="123",
        ControlPID="0",
        ControlGroup="/system.slice/" + unit,
        pid_stat="123 (peer) " + " ".join(["S"] + ["0"] * 18 + ["1"]),
    )
    proof = dict(
        identity=dict(pid=123),
        evidence=dict(
            before=deepcopy(state),
            namespaces=dict(net=[5, 20], mnt=[5, 21]),
            binfmt_before={"status": 100},
        ),
    )
    if fault == "pid":
        state["MainPID"] = "124"
    monkeypatch.setattr(c.LAB, "unit_snapshot", lambda name: state)
    monkeypatch.setattr(c.G, "boot", lambda: "wrong" if fault == "boot" else BOOT)
    monkeypatch.setattr(
        c.p.cg,
        "_kernel_text",
        lambda *a: "1 (systemd) " + " ".join(["S"] + ["0"] * 18 + ["1"]),
    )
    monkeypatch.setattr(
        c,
        "os",
        SimpleNamespace(
            stat=lambda path: SimpleNamespace(
                st_dev=5,
                st_ino=99
                if fault == "namespace"
                else 20
                if path.endswith("net")
                else 21,
            )
        ),
    )
    monkeypatch.setattr(
        c.p,
        "binfmt_metadata",
        lambda pid, evidence: evidence.update(status=999 if fault == "binfmt" else 100),
    )
    if fault is None:
        c._live_targets(proof, BOOT, tmp_path, "after")
    else:
        with pytest.raises(AssertionError, match="known-live"):
            c._live_targets(proof, BOOT, tmp_path, "after")
    retained = json.loads((tmp_path / "after-live-targets.json").read_bytes())
    assert retained["state"] == state and retained["boot"] == (
        "wrong" if fault == "boot" else BOOT
    )


def test_reused_descriptor_is_not_closed_as_an_old_namespace_handle():
    fd = os.open(os.devnull, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        with pytest.raises(AssertionError, match="reused"):
            c._close_namespace_fd(fd, info.st_dev, info.st_ino + 1)
        assert os.fstat(fd).st_ino == info.st_ino
    finally:
        os.close(fd)


@pytest.mark.parametrize("split", [False, True])
def test_ready_overflow_retains_exact_consumed_prefix_and_keeps_stdin_open(
    tmp_path, split
):
    prefix = b'{"kind":"ready","payload":"'
    data = prefix + b"x" * 20000 + b'"}\n'
    if split:
        script = (
            "import sys,time;sys.stdout.buffer.write("
            + repr(prefix)
            + ");sys.stdout.buffer.flush();time.sleep(.02);sys.stdout.buffer.write("
            + repr(data[len(prefix) :])
            + ");sys.stdout.buffer.flush();time.sleep(30)"
        )
    else:
        script = (
            "import sys,time;sys.stdout.buffer.write("
            + repr(data)
            + ");sys.stdout.buffer.flush();time.sleep(30)"
        )
    child = process(script)
    try:
        with pytest.raises(AssertionError, match="oversized ready"):
            c._receive_ready(child, tmp_path / "ready.raw")
        assert (tmp_path / "ready.raw").read_bytes() == data[:16385]
        assert not child.stdin.closed
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


def test_first_oversized_ready_read_is_appended_before_size_rejection(
    tmp_path, monkeypatch
):
    consumed = b"x" * 16385
    monkeypatch.setattr(c.select, "select", lambda *a: ([42], [], []))
    monkeypatch.setattr(c.os, "read", lambda fd, amount: consumed)
    source = SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 42))
    with pytest.raises(AssertionError, match="oversized ready"):
        c._receive_ready(source, tmp_path / "first.raw")
    assert (tmp_path / "first.raw").read_bytes() == consumed


def test_controller_reaps_actual_stuck_owned_client_after_ready_and_drain_failures(
    tmp_path, monkeypatch
):
    # This is an ordinary private test child, not a hardened actor/systemd unit.
    real_ready = c._ready
    real_exchange = c._exchange
    output, events, instances = fixture(tmp_path, monkeypatch)
    children = []
    data = b"x" * 20000

    def launch(mode, path):
        assert mode == "peer"  # Oversize READY must prevent launching the probe.
        script = (
            "import signal,sys,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);sys.stdout.buffer.write("
            + repr(data)
            + ");sys.stdout.buffer.flush();time.sleep(30)"
        )
        child = process(script)
        children.append(child)
        return child

    monkeypatch.setattr(c, "_launch", launch)
    monkeypatch.setattr(c, "_ready", real_ready)
    monkeypatch.setattr(c, "_exchange", real_exchange)
    try:
        with pytest.raises(AssertionError, match="oversized ready"):
            c.run(output)
        child = children[0]
        # Acceptance assertions occur BEFORE emergency test-finally cleanup.
        assert child.returncode is not None
        with pytest.raises(ChildProcessError):
            os.waitpid(child.pid, os.WNOHANG)
        proof = json.loads((output / "peer-client-reap.json").read_bytes())
        assert (
            proof["pid"] == child.pid
            and proof["reaped"] is True
            and proof["forced"] is True
        )
        assert "kill" in [row["operation"] for row in proof["steps"]]
        assert proof["errors"]  # Forced reap can NEVER enable namespace deletion.
        assert "namespace-close" not in events and "all-invariants" in events
        assert not (output / "final-result.json").exists()
        assert (output / "peer-ready.raw").read_bytes() == data[:16385]
        assert all(
            stream.closed for stream in (child.stdin, child.stdout, child.stderr)
        )
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait()
            for stream in (child.stdin, child.stdout, child.stderr):
                stream.close()
