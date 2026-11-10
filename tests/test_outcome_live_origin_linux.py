"""Offline real normal-core -> private stream -> separate-UID signer tests.

No tc/nft, live service, model or external socket is enabled by these tests.
"""

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time

import pytest

pytest.importorskip("cryptography")
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root required for actual live-origin UIDs",
)
from test_outcome_input_auth_linux import (
    Fixture,
    Child,
    ROOT,
    register_origin,
    append_raw,
)
from test_outcome_live_origin import frame
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, _json


def register_live(f):
    register_origin(f)
    r = dict(
        schema_version="outcome-live-origin-registration/v1",
        mode="live-core",
        **{
            k: f.p.data[k]
            for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key")
        },
        binary_path=str(f.binary),
        binary_sha256=hashlib.sha256(f.binary.read_bytes()).hexdigest(),
        launcher_uid=0,
        environment={
            "AZAZEL_EVE_PATH": str(f.raw),
            "AZAZEL_NORMALIZED_EVENT_LOG": str(f.root / "native-log"),
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(f.root / "native-ledger"),
            "AZAZEL_REDIRECT_POLICY_PATH": str(f.root / "absent-redirect.yaml"),
            "AZAZEL_PROTECTED_FLOWS_PATH": str(f.root / "absent-protected.yaml"),
            "AZAZEL_EVE_POLL_MS": "10",
            "AZAZEL_EVE_FROM_START": "0",
            "AZAZEL_FORWARD_AI": "0",
            "AZAZEL_FORWARD_LOG": "0",
            "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_DEFENSE_ENFORCE": "0",
            "AZAZEL_DEFENSE_DRY_RUN": "1",
        },
    )
    raw = _json(r)
    f.registration.write_bytes(raw)
    f.p = TrustPolicy(
        {
            **dict(f.p.data),
            "schema_version": "outcome-input-trust/v3",
            "origin_registration_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    f.policy_file.write_bytes(_json(dict(f.p.data)))


@pytest.fixture
def live():
    f = Fixture()
    try:
        register_live(f)
        yield f
    finally:
        f.clean()


class Run:
    def __init__(self, f):
        self.f = f
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "azazel_edge.outcome.input_live",
                "--policy",
                str(f.policy_file),
                "--registration",
                str(f.registration),
                "--private-key",
                str(f.pk),
                "--boot-ref",
                "live-test-boot",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py")),
        )

    def started(self):
        assert select.select([self.process.stdout], [], [], 15)[0], "launcher timeout"
        line = self.process.stdout.readline()
        assert json.loads(line) == {"core_started": True}, self.process.stderr.read()
        # The normal core logs startup after calculating its new-input offset.
        deadline = time.monotonic() + 15
        pending = bytearray()
        while time.monotonic() < deadline:
            if not select.select([self.process.stderr], [], [], 1)[0]:
                continue
            # Read the fd directly: TextIOWrapper can read ahead several log
            # lines, leaving select idle while the matching line is buffered.
            part = os.read(self.process.stderr.fileno(), 8192)
            if not part:
                break
            pending.extend(part)
            if b"azazel-edge-core started:" in pending:
                return
            assert len(pending) <= 32768, "unexpected startup log bound"
        raise AssertionError("real normal core did not start")

    def stop(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
        return self.process.wait(timeout=15)

    def close(self):
        try:
            self.stop()
        finally:
            self.process.stdout.close()
            self.process.stderr.close()


def events(f, minimum):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        data = f.source.read_bytes()
        if data.endswith(b"\n"):
            wires = [json.loads(line) for line in data.splitlines()]
            if len(wires) >= minimum:
                SourceVerifier(f.p).verify(data)
                return [w["event"] for w in wires]
        time.sleep(0.02)
    raise AssertionError("signed live capture did not arrive")


def children(run):
    return [
        int(p)
        for p in Path(f"/proc/{run.process.pid}/task/{run.process.pid}/children")
        .read_text()
        .split()
    ]


def test_real_normal_defense_path_signed_without_recalculation_and_witness_reopen(live):
    f = live
    f.start(initialize=True)
    observer = Child(f, True)
    assert observer.initial.get("ready")
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        assert len(events(f, 2)) == 2  # Pre-start raw input not replayed.
        append_raw(f)
        ev = events(f, 3)[2]
        assert ev["capture_origin"]["mode"] == "live-core"
        assert ev["capture_origin"]["kind"] == "decision_execution"
        assert ev["enforcement"]["executed_count"] == 0
        assert ev["enforcement"]["mode"] in ("disabled", "dry_run", "policy_gated")
        assert not ev["enforcement"]["metadata"].get("capture_only")
        assert ev["normalized"]["sid"] == 42
        assert run.stop() == 0
        all_events = events(f, 4)
        assert all_events[-1]["capture_origin"]["kind"] == "session_end"
    finally:
        run.close()
        observer.close()
    observer = Child(f)
    try:
        assert observer.initial.get("ready"), observer.initial
    finally:
        observer.close()
    append_raw(f)  # Absent producer/core interval stays excluded on restart.
    run = Run(f)
    try:
        run.started()
        events(f, 6)
        append_raw(f)
        events(f, 7)
        assert run.stop() == 0
        final = events(f, 8)
        assert [e["capture_origin"]["kind"] for e in final] == [
            "session_prepare",
            "session_start",
            "decision_execution",
            "session_end",
        ] * 2
        assert (
            final[0]["capture_origin"]["session_ref"]
            != final[4]["capture_origin"]["session_ref"]
        )
    finally:
        run.close()


@pytest.mark.parametrize(
    "fault",
    [
        "registration_missing",
        "registration_hash",
        "binary",
        "key",
        "legacy",
        "env_replay",
        "env_loader",
        "alias",
    ],
)
def test_unregistered_or_unverified_launch_never_starts_core(live, fault):
    f = live
    if fault == "registration_missing":
        f.registration.unlink()
    elif fault == "registration_hash":
        f.registration.write_bytes(f.registration.read_bytes() + b" ")
    elif fault == "binary":
        f.binary.write_bytes(b"\x7fELFbad")
    elif fault == "key":
        f.pk.write_bytes(b"x" * 32)
    elif fault == "legacy":
        d = dict(f.p.data)
        d["schema_version"] = "outcome-input-trust/v2"
        f.policy_file.write_bytes(_json(d))
    else:
        r = json.loads(f.registration.read_bytes())
        if fault == "env_replay":
            r["environment"]["AZAZEL_EVE_FROM_START"] = "1"
        elif fault == "env_loader":
            r["environment"]["LD_PRELOAD"] = "/untrusted"
        else:
            r["environment"]["AZAZEL_NORMALIZED_EVENT_LOG"] = str(f.source)
        raw = _json(r)
        f.registration.write_bytes(raw)
        d = dict(f.p.data)
        d["origin_registration_sha256"] = hashlib.sha256(raw).hexdigest()
        f.policy_file.write_bytes(_json(d))
    run = Run(f)
    try:
        stdout, stderr = run.process.communicate(timeout=15)
        assert run.process.returncode != 0 and "core_started" not in stdout
        assert f.source.read_bytes() == b""
        assert not (f.root / "native-ledger").exists()
    finally:
        run.close()


def test_signer_failure_leaves_core_running_and_blocks_automatic_new_session(live):
    f = live
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        kids = children(run)
        assert len(kids) == 2
        signer = next(
            pid
            for pid in kids
            if Path(f"/proc/{pid}/status").read_text().split("Uid:")[1].split()[0]
            == "1000"
        )
        os.kill(signer, signal.SIGKILL)
        time.sleep(0.2)
        assert run.process.poll() is None
        append_raw(f)
        assert run.stop() != 0
        before = f.source.read_bytes()
    finally:
        run.close()
    restarted = Run(f)
    try:
        stdout, stderr = restarted.process.communicate(timeout=15)
        assert restarted.process.returncode != 0 and "core_started" not in stdout
        assert f.source.read_bytes() == before
    finally:
        restarted.close()


def test_core_sigkill_never_fabricates_end_or_auto_continuation(live):
    f = live
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        core = next(
            pid
            for pid in children(run)
            if Path(f"/proc/{pid}/status").read_text().split("Uid:")[1].split()[0]
            == "0"
        )
        os.kill(core, signal.SIGKILL)
        assert run.process.wait(timeout=15) != 0
        before = f.source.read_bytes()
        assert SourceVerifier(f.p).verify(before)["seq"] == 2
    finally:
        run.close()
    restarted = Run(f)
    try:
        stdout, stderr = restarted.process.communicate(timeout=15)
        assert restarted.process.returncode != 0 and "core_started" not in stdout
        assert f.source.read_bytes() == before
    finally:
        restarted.close()


class Receiver:
    """Trusted-root protocol fault injector, not a real execution provider."""

    def __init__(self, f):
        self.channel, other = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "azazel_edge.outcome.input_live",
                "--policy",
                str(f.policy_file),
                "--registration",
                str(f.registration),
                "--private-key",
                str(f.pk),
                "--boot-ref",
                "injected-protocol",
                "--receive-fd",
                str(other.fileno()),
                "--session-ref",
                "a" * 32,
            ],
            pass_fds=(other.fileno(),),
            user=1000,
            group=1000,
            extra_groups=[],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py")),
        )
        other.close()
        assert select.select([self.process.stdout], [], [], 10)[0]
        assert (
            self.process.stdout.readline() == b'{"ready":true}\n'
        ), self.process.stderr.read()

    def send(self, wire):
        self.channel.sendall(_json(wire) + b"\n")

    def close_input(self):
        self.channel.close()

    def close(self):
        self.channel.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
        self.process.stderr.close()


@pytest.mark.parametrize(
    "fault",
    [
        "missing_start",
        "gap",
        "readonly",
        "replay",
        "partial",
        "oversize",
        "end_extra",
        "end_partial",
        "duplicate",
        "nonfinite",
    ],
)
def test_live_protocol_validation_failure_never_commits_clean_closure_or_reconnects(
    live, fault
):
    f = live
    receiver = Receiver(f)
    try:
        if fault == "missing_start":
            receiver.send(frame("decision_execution", 2))
        else:
            receiver.send(frame("session_start", 1))
            if fault == "gap":
                receiver.send(frame("decision_execution", 3))
            elif fault == "readonly":
                wire = frame("decision_execution", 2)
                wire["event"]["enforcement"]["metadata"]["capture_only"] = True
                receiver.send(wire)
            elif fault == "replay":
                receiver.send(frame("session_start", 1))
            elif fault == "partial":
                receiver.channel.sendall(b"{")
            elif fault == "oversize":
                try:
                    receiver.channel.sendall(b"x" * 65537)
                except BrokenPipeError:
                    pass
            elif fault in ("end_extra", "end_partial"):
                receiver.send(frame("session_end", 2))
                receiver.channel.sendall(b"{}\n" if fault == "end_extra" else b"{")
            elif fault == "duplicate":
                receiver.channel.sendall(b'{"seq":2,"seq":3}\n')
            elif fault == "nonfinite":
                wire = frame("decision_execution", 2)
                data = _json(wire).replace(b'"sid":1001', b'"sid":1e400')
                receiver.channel.sendall(data + b"\n")
        receiver.close_input()
        assert receiver.process.wait(timeout=10) != 0
        before = f.source.read_bytes()
        v = SourceVerifier(f.p)
        v.verify(before)
        assert not v.live_state.closed
        assert all(
            json.loads(line)["event"]["capture_origin"]["kind"] != "session_end"
            for line in before.splitlines()
        )
    finally:
        receiver.close()
    run = Run(f)
    try:
        stdout, stderr = run.process.communicate(timeout=15)
        assert run.process.returncode != 0 and "core_started" not in stdout
        assert f.source.read_bytes() == before
    finally:
        run.close()


def test_source_capacity_failure_preserves_real_core_progress(live):
    f = live
    r = json.loads(f.registration.read_bytes())
    r["environment"]["AZAZEL_FORWARD_LOG"] = "1"
    f.registration.write_bytes(_json(r))
    f.p = TrustPolicy(
        {
            **dict(f.p.data),
            "origin_registration_sha256": hashlib.sha256(_json(r)).hexdigest(),
            "input_max_records": 2,
        }
    )
    f.policy_file.write_bytes(_json(dict(f.p.data)))
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        append_raw(f)
        append_raw(f)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            path = f.root / "native-log"
            if path.exists() and len(path.read_bytes().splitlines()) >= 2:
                break
            time.sleep(0.02)
        else:
            raise AssertionError("defense stopped when signer filled")
        assert run.process.poll() is None
        assert run.stop() != 0
        assert len(f.source.read_bytes().splitlines()) == 2
    finally:
        run.close()


def test_actual_capture_fd_is_close_on_exec_and_uid_roles_remain_separate(live):
    f = live
    run = Run(f)
    try:
        run.started()
        events(f, 2)
        kids = children(run)
        assert len(kids) == 2
        core = next(
            pid
            for pid in kids
            if Path(f"/proc/{pid}/status").read_text().split("Uid:")[1].split()[0]
            == "0"
        )
        argv = Path(f"/proc/{core}/cmdline").read_bytes().decode().split("\x00")
        fd = argv[argv.index("--live-origin-fd") + 1]
        flags = next(
            line.split()[1]
            for line in Path(f"/proc/{core}/fdinfo/{fd}").read_text().splitlines()
            if line.startswith("flags:")
        )
        assert int(flags, 8) & os.O_CLOEXEC
        signer = next(pid for pid in kids if pid != core)
        assert (
            Path(f"/proc/{signer}/status").read_text().split("Uid:")[1].split()[:4]
            == ["1000"] * 4
        )
        append_raw(f)
        events(f, 3)
        assert run.stop() == 0
    finally:
        run.close()


def test_live_enrollment_candidate_is_public_readonly_and_new_scope_only(live):
    from azazel_edge.outcome.input_live_enroll import prepare

    f = live
    d = dict(f.p.data)
    d.pop("origin_registration_sha256")
    d["schema_version"] = "outcome-input-trust/v1"
    before = {
        p: p.read_bytes() for p in (f.registration, f.policy_file, f.source, f.pk)
    }
    candidate = prepare(
        TrustPolicy(d), f.binary, json.loads(f.registration.read_bytes())["environment"]
    )
    assert candidate["trust_policy"] == dict(f.p.data)
    assert all(path.read_bytes() == raw for path, raw in before.items())
    (f.root / "journal" / "unfinished").touch()
    with pytest.raises(OSError):
        prepare(TrustPolicy(d), f.binary, candidate["registration"]["environment"])


def test_live_core_boundary_withholds_cursor_then_recovery_loses_pending_window(live):
    from test_outcome_input_resume import event

    f = live
    f.start(initialize=True)
    observer = Child(f, True)
    assert observer.initial.get("ready"), observer.initial
    receiver = Receiver(f)
    try:
        events(f, 1)  # producer preparation, not a Rust execution record
        refused = observer.command("observe")
        assert refused.get("refused") and refused["status"]["input_records"] == 0
        observer.close()
        observer = Child(f)
        assert observer.initial.get("ready"), observer.initial
        receiver.send(frame("session_start", 1))
        events(f, 2)
        before = observer.initial["status"]["input_records"]
        refused = observer.command("observe")
        assert refused.get("refused") and refused["status"]["input_records"] == before
        observer.close()
        observer = Child(f)
        assert observer.initial.get("ready"), observer.initial
        wire = frame("decision_execution", 2)
        wire["event"]["normalized"]["ts"] = event()["normalized"]["ts"]
        receiver.send(wire)
        events(f, 3)
        assert observer.command("observe")["status"]["pending"] == 1
        receiver.send(frame("session_end", 3))
        receiver.close_input()
        assert receiver.process.wait(timeout=10) == 0
        events(f, 4)
        refused = observer.command("observe")
        assert refused.get("refused") and refused["status"]["pending"] == 1
        observer.kill()
        observer = Child(f)
        assert observer.initial.get("ready"), observer.initial
        status = observer.initial["status"]
        assert (
            status["pending"] == 0 and status["lost"] == 1 and status["committed"] == 0
        )
    finally:
        if observer is not None:
            observer.close()
        receiver.close()


def test_unprivileged_peer_cannot_open_a_signing_session(live):
    f = live
    script = r"""
import sys,socket
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_live import registration,receive
p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer')
r=registration(p,Path(sys.argv[2]))
one,two=socket.socketpair(socket.AF_UNIX,socket.SOCK_STREAM)
try:receive(p,r,Path(sys.argv[3]),'boot',one.detach(),'a'*32)
except OSError:print('denied')
else:raise AssertionError('unprivileged signing endpoint')
two.close()
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(f.policy_file),
            str(f.registration),
            str(f.pk),
        ],
        env=dict(os.environ, PYTHONPATH=str(ROOT) + ":" + str(ROOT / "py")),
        user=1000,
        group=1000,
        extra_groups=[],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "denied"
    assert f.source.read_bytes() == b""
