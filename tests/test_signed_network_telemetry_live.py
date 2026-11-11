"""Synthetic Root proof/config/roles; real private child pipes, no VM/LSM claim."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_live as live
from test_signed_network_telemetry_proof import identity, BOOT

SHA = "a" * 64


def worker_result(binding, actor):
    def position(n):
        return dict(offset=n, sha256="d" * 64)

    context = dict(
        identity=deepcopy(actor),
        kernel_boot_id=BOOT,
        boot_ref=live.init.plan.n.boot_reference(BOOT),
        signed_boot_ref=BOOT.replace("-", ""),
        scope_ref=binding["public_auth"]["scope_ref"],
        registration_sha256="f" * 64,
        policy_sha256=binding["policy_sha256"],
        policy_file_sha256=binding["policy_file_sha256"],
        source_start_position=position(100),
        clock_anchor=dict(monotonic_before_ns=10, epoch_ns=100, monotonic_after_ns=11),
    )
    terminal = dict(
        disposition="verified_terminal_control_stop",
        cursor_disposition="control_not_observed",
        cursor_missed=True,
        registration_sha256="f" * 64,
        session_ref="1" * 32,
        native_seq=3,
        source_position_before=position(100),
        source_position_after=position(200),
        signed_wire_sha256="b" * 64,
        signed_wire_bytes=100,
        decoded_record_sha256="c" * 64,
        decoded_record_bytes=80,
        pending_windows_lost=0,
        measurement_completed=False,
        resume_authorized=False,
    )
    state = {
        k: ("d" * 64 if k.endswith(("head", "sha256")) else 1)
        for k in (
            "journal_seq",
            "journal_head",
            "journal_size",
            "journal_sha256",
            "journal_device",
            "journal_inode",
            "source_seq",
            "source_head",
            "source_size",
            "source_sha256",
        )
    }
    state["source_size"] = 200
    return dict(
        context=context,
        terminal=terminal,
        witness_state=state,
        end_clock_anchor=dict(
            monotonic_before_ns=20, epoch_ns=200, monotonic_after_ns=21
        ),
        scope="real_observer_calls_and_terminal_control_not_measurement_success",
    )


def fixture(tmp_path, monkeypatch, fault=None):
    events = []
    children = []
    init = live.init
    monkeypatch.setattr(live.material, "SRC", Path("/opt/edge400-src"))
    current = dict(
        source_sha256={str(Path(live.role.SOURCE).relative_to(live.material.SRC)): SHA},
        role=live.role.ROLE,
    )
    monkeypatch.setattr(live.g, "guard", lambda: events.append("guard"))
    monkeypatch.setattr(live.g, "boot", lambda: BOOT)
    monkeypatch.setattr(live.proof.p, "_output", lambda output: None)

    def material(**kwargs):
        return deepcopy(current)

    monkeypatch.setattr(live.material, "verify_current", material)
    monkeypatch.setattr(
        live.material, "_read", lambda *a: b'{"public":"synthetic-policy"}'
    )
    public = dict(
        scope="public_root_config_continuity_only",
        scope_ref="synthetic-scope",
        origin_registration_sha256="f" * 64,
        trust_file_sha256="d" * 64,
        origin_file_sha256="e" * 64,
    )
    monkeypatch.setattr(init, "public_auth_binding", lambda: deepcopy(public))
    monkeypatch.setattr(
        init, "witness_binding", lambda *args: {"synthetic_stable_witness": True}
    )
    monkeypatch.setattr(init, "_namespace", lambda fd, expected: list(expected))
    monkeypatch.setattr(
        init,
        "prelaunch_unit_material",
        lambda mode, output: events.append("prelaunch:" + mode),
    )
    monkeypatch.setattr(init.scope, "_state", lambda unit: {})
    monkeypatch.setattr(
        init.scope, "_known_collected", lambda state: fault != "existing"
    )
    monkeypatch.setattr(live.lab.cg, "group_empty", lambda *args: True)
    binding, _ = init._current_binding(
        current=current,
        namespace=[5, 20],
        source_sha256=SHA,
        kernel=BOOT,
        output=tmp_path,
        phase="live-initial",
    )
    previous = identity()
    previous.update(pid=111, tgid=111)
    actor = identity()
    actor.update(pid=222, tgid=222)
    initialized = dict(
        initialization=dict(
            initialized_empty=True,
            identity=previous,
            kernel_boot_id=BOOT,
            boot_ref=init.plan.n.boot_reference(BOOT),
            policy_sha256=binding["policy_sha256"],
            policy_file_sha256=binding["policy_file_sha256"],
        ),
        binding=deepcopy(binding),
        proof=dict(
            ready=dict(identity=previous, mode="initialize", role=live.role.ROLE)
        ),
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
    )
    if fault == "initbinding":
        initialized["binding"]["public_auth"]["trust_file_sha256"] = "0" * 64
    if fault == "initfalse":
        initialized["initialization"]["initialized_empty"] = False
    if fault == "inittyped":
        initialized["initialization"]["identity"]["uid"] = 61002.0
    result = worker_result(binding, actor)
    if fault == "resultidentity":
        result["context"]["identity"]["pid"] = 999
    if fault == "terminaltyped":
        result["terminal"]["native_seq"] = True
    if fault == "terminalfalse":
        result["terminal"]["cursor_missed"] = False
    if fault == "witness":
        result["witness_state"]["source_size"] = 201
    if fault == "registration":
        result["terminal"]["registration_sha256"] = "0" * 64
    ready = dict(
        kind=live.role.READY_KIND,
        role=live.role.ROLE,
        mode="live",
        identity=deepcopy(actor),
        kernel_boot_id=BOOT,
        source=live.role.SOURCE,
        source_sha256=SHA,
    )
    final = b'{"partial"' if fault == "partial" else json.dumps(result).encode() + b"\n"
    if fault == "overflow":
        final = b"x" * 70000
    real_popen = subprocess.Popen

    def launch(argv, **kwargs):
        events.append("launch")
        assert argv == init.observer.role_argv("live", telemetry_lab_v2=True)
        assert kwargs["close_fds"] and kwargs["env"] == {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
        }
        # Synthetic public READY/result; real private original stdio. No LSM claim.
        script = (
            "import sys,select;sys.stdout.buffer.write("
            + repr(json.dumps(ready).encode() + b"\n")
            + ");sys.stdout.flush();r=select.select([sys.stdin],[],[],0.5)[0];v=sys.stdin.buffer.readline() if r else b'';sys.exit(7) if v!="
            + repr(live.role.GO)
            + " else None;sys.stdout.buffer.write("
            + repr(final)
            + ");sys.stdout.flush();"
            + ("sys.stderr.write('synthetic failure');" if fault == "stderr" else "")
            + ("sys.exit(2)" if fault == "exit" else "")
        )
        process = real_popen([sys.executable, "-I", "-B", "-c", script], **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(live.subprocess, "Popen", launch)

    def collect(mode, process, **kwargs):
        events.append("fullproof")
        raw = live.proof._receive_ready(process, tmp_path / "live-pre-api-ready.raw")
        parsed = live.proof.parse_ready(
            raw, mode, kernel_boot_id=BOOT, source_sha256=SHA
        )
        if fault == "proof":
            raise AssertionError("synthetic Root proof refusal")
        return dict(
            ready=parsed,
            effective=dict(unit=live.role.OBSERVER_UNIT),
            actor=dict(evidence=dict(before=dict(MainPID="222"))),
            metadata=dict(synthetic=True),
        )

    monkeypatch.setattr(live.proof, "collect_pre_api", collect)
    real_save = live.lab.save_json

    def save(path, value):
        if path.name == "live-verified-bundle.json":
            events.append("persist-proof")
            assert value["proof"]["ready"] == ready and value["binding"] == binding
            if fault == "persist":
                raise OSError("synthetic proof persistence refusal")
        if path.name == "live-cleanup.json" and fault == "cleanuppersist":
            raise OSError("synthetic cleanup receipt refusal")
        return real_save(path, value)

    monkeypatch.setattr(live.lab, "save_json", save)

    def cleanup(units, tracked):
        events.append("cleanup")
        assert units == (live.role.OBSERVER_UNIT,) and set(tracked) == set(units)
        return dict(errors=["synthetic unknown cgroup"] if fault == "cleanup" else [])

    monkeypatch.setattr(live.lab, "cleanup", cleanup)
    args = dict(
        abi_sha256="b" * 64,
        interpreter_sha256="c" * 64,
        source_sha256=SHA,
        expected_sources=current["source_sha256"],
        namespace_fd=99,
        namespace_identity=[5, 20],
        initialization=initialized,
    )
    return args, events, children, public


def test_real_private_pipe_session_persists_fullproof_and_only_status_is_public(
    tmp_path, monkeypatch
):
    args, events, children, _ = fixture(tmp_path, monkeypatch)
    with live.live(tmp_path, **args) as session:
        assert events.index("fullproof") < events.index("persist-proof")
        assert session.result is None and not (tmp_path / "live-result.json").exists()
        assert session.pid == children[0].pid and session.poll() in (None, 0)
        assert not any(
            hasattr(session, name)
            for name in ("stdin", "stdout", "stderr", "wait", "communicate", "process")
        )
    assert (
        session.result["terminal"]["terminal"]["disposition"]
        == "verified_terminal_control_stop"
    )
    assert (
        session.result["proof"]["ready"]["identity"]["pid"]
        != args["initialization"]["initialization"]["identity"]["pid"]
    )
    assert children[0].returncode == 0 and all(
        f.closed for f in (children[0].stdin, children[0].stdout, children[0].stderr)
    )
    assert (tmp_path / "live-terminal.stdout").read_bytes().startswith(b'{"context":')
    assert (
        session.result["authorizes_transition"]
        is session.result["experiment"]
        is session.result["production_admission"]
        is False
    )


@pytest.mark.parametrize(
    "fault", ["existing", "initbinding", "initfalse", "inittyped", "proof", "persist"]
)
def test_pre_go_failure_never_yields_or_publishes(tmp_path, monkeypatch, fault):
    args, events, children, _ = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, ValueError, OSError)):
        with live.live(tmp_path, **args):
            pytest.fail("invalid scope must not yield")
    assert not (tmp_path / "live-result.json").exists()
    if children:
        assert "cleanup" in events and children[0].poll() is not None
        assert (tmp_path / "live-cleanup-streams.stdout").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "partial",
        "overflow",
        "stderr",
        "exit",
        "resultidentity",
        "terminaltyped",
        "terminalfalse",
        "witness",
        "registration",
        "cleanup",
        "cleanuppersist",
    ],
)
def test_terminal_or_cleanup_failure_retains_originals_and_withholds(
    tmp_path, monkeypatch, fault
):
    args, events, children, _ = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, ValueError, OSError)):
        with live.live(tmp_path, **args) as session:
            pass
    assert session.result is None and not (tmp_path / "live-result.json").exists()
    assert (tmp_path / "live-terminal.stdout").exists() and (
        tmp_path / "live-terminal.stderr"
    ).exists()
    assert "cleanup" in events and children[0].poll() is not None
    if fault == "overflow":
        assert len((tmp_path / "live-terminal.stdout").read_bytes()) == 65537
    assert all(
        f.closed for f in (children[0].stdin, children[0].stdout, children[0].stderr)
    )


def test_outer_exception_stays_primary_and_no_terminal_success(tmp_path, monkeypatch):
    args, events, children, _ = fixture(tmp_path, monkeypatch, "cleanup")
    original = RuntimeError("outer durable input_ready or native stop failed")
    with pytest.raises(RuntimeError) as caught:
        with live.live(tmp_path, **args) as session:
            raise original
    assert caught.value is original and caught.value.__notes__
    assert session.result is None and not (tmp_path / "live-result.json").exists()
    assert "cleanup" in events and children[0].poll() is not None


def test_public_config_drift_after_go_withholds_success(tmp_path, monkeypatch):
    args, _, children, public = fixture(tmp_path, monkeypatch)
    with pytest.raises(AssertionError, match="binding changed"):
        with live.live(tmp_path, **args) as session:
            public["trust_file_sha256"] = "0" * 64
    assert session.result is None and children[0].poll() is not None
    assert (tmp_path / "live-terminal.stdout").exists() and not (
        tmp_path / "live-result.json"
    ).exists()


def test_material_source_map_must_pin_live_helper_actual_bytes():
    key = "tests/real_systemd/signed_network_telemetry_live.py"
    assert key in live.material.source_hashes()
    assert (
        live.material.source_hashes()[key]
        == hashlib.sha256(Path(live.__file__).read_bytes()).hexdigest()
    )


def test_launch_budget_stays_absolute40_and_raw_precedes_parse(tmp_path, monkeypatch):
    args, events, children, _ = fixture(tmp_path, monkeypatch)
    drain = live.init._drain
    parse = live._terminal

    def collect(process, output, deadline, prefix="initialization"):
        if prefix == "live-terminal":
            assert 0 < deadline - time.monotonic() <= live.role.RUNTIME_SECONDS == 40
        return drain(process, output, deadline, prefix)

    def typed(raw, verified, binding):
        assert (tmp_path / "live-terminal.stdout").read_bytes() == raw
        assert (tmp_path / "live-terminal.stderr").read_bytes() == b""
        assert (
            json.loads((tmp_path / "live-terminal-client.json").read_bytes())[
                "returncode"
            ]
            == 0
        )
        return parse(raw, verified, binding)

    monkeypatch.setattr(live.init, "_drain", collect)
    monkeypatch.setattr(live, "_terminal", typed)
    with live.live(tmp_path, **args):
        pass
    assert children[0].returncode == 0


@pytest.mark.parametrize("fault", ["drain", "reap", "pipe", "stop"])
def test_cleanup_attempts_continue_independently_and_no_result(
    tmp_path, monkeypatch, fault
):
    args, events, children, _ = fixture(tmp_path, monkeypatch)
    drain = live.init._drain
    reap = live.init._reap_client

    def fail_drain(process, output, deadline, prefix="initialization"):
        events.append("drain:" + prefix)
        if fault == "drain" and prefix == "live-terminal":
            # Exercise existing retention on an exhausted absolute budget.
            return drain(process, output, time.monotonic() - 1, prefix)
        return drain(process, output, deadline, prefix)

    def reaping(process):
        events.append("reap")
        result = reap(process)
        if fault == "reap":
            result["forced"] = True
        return result

    monkeypatch.setattr(live.init, "_drain", fail_drain)
    monkeypatch.setattr(live.init, "_reap_client", reaping)
    if fault == "stop":

        def failed_stop(*a):
            events.append("cleanup")
            raise OSError("synthetic stop/readback failure")

        monkeypatch.setattr(live.lab, "cleanup", failed_stop)
    with pytest.raises((AssertionError, OSError)):
        with live.live(tmp_path, **args) as session:
            if fault == "pipe":
                original = children[0].stdin.close

                def failed_close():
                    original()
                    raise OSError("synthetic one-pipe close failure")

                monkeypatch.setattr(children[0].stdin, "close", failed_close)
    assert session.result is None and not (tmp_path / "live-result.json").exists()
    assert (
        "cleanup" in events
        and "drain:live-cleanup-streams" in events
        and "reap" in events
    )
    assert children[0].poll() is not None
    assert children[0].stdout.closed and children[0].stderr.closed


def test_durable_fullbundle_directory_failure_never_sends_go(tmp_path, monkeypatch):
    args, events, children, _ = fixture(tmp_path, monkeypatch)
    fsync = live.os.fsync

    def refused_directory(fd):
        import stat

        if stat.S_ISDIR(live.os.fstat(fd).st_mode):
            raise OSError("synthetic directory persistence failure")
        return fsync(fd)

    monkeypatch.setattr(live.os, "fsync", refused_directory)
    with pytest.raises(OSError, match="directory persistence"):
        with live.live(tmp_path, **args):
            pytest.fail("GO must follow durable proof")
    assert children[0].returncode == 7  # Synthetic child received no exact GO.
    assert "cleanup" in events and not (tmp_path / "live-result.json").exists()
