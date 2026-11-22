"""Fixed native-accounting cases in the existing disposable native-AA lab.

This controller never provisions roles/policy, signs Source, repairs history or
supplies provider facts. Public exports retain the original bytes and failures.
"""

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import select
import signal
import subprocess
import sys
import time

PROTOCOL_SHA256 = "ddf6d2babb348e2d43307ec4c78cbd5d628778b14a273cb9d7e964f84c4fd445"
PROTOCOL_NAME = "native-accounting-protocol-v1.json"
ACTOR_FIELDS = (
    "pid",
    "ppid",
    "start_ticks",
    "uid",
    "gid",
    "groups",
    "apparmor_label",
    "cap_eff",
    "cap_prm",
    "cap_bnd",
    "cap_amb",
    "no_new_privs",
)
SOURCE_FIELDS = ("device", "inode", "owner_uid", "mode", "nlink")
CASES = ("normal-four", "restart-one", "interrupted-prefix")
READBACK_CASES = frozenset(
    (
        *CASES,
        "witness-stopped-close",
        "receiver-killed-prefix",
        "ingress-mixed",
        "ingress-partial-tail",
        "ingress-oversize",
        "ingress-duplicate-sid",
        "ingress-backlog-shed",
        "ingress-rename",
        "ingress-truncate",
        "ingress-same-inode-overwrite",
        "ingress-native-killed",
        "ingress-receiver-killed",
        "load-off",
        "load-on",
        "load-faulted",
        "fresh-controls",
        "fresh-interrupted",
    )
)
PUBLIC_FILES = frozenset(
    (
        "trust.json",
        "registration.json",
        "source.raw",
        "anchors.raw",
        "controller.json",
        "readback-source.raw",
        "protocol.json",
        "code-pins.json",
        "failure.json",
        "evaluation.json",
        "reader-binding.json",
    )
)
MAX_SOURCE = 8 * 1024 * 1024


def canonical(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        + b"\n"
    )


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def actor(pid):
    """Observe only existing proc permissions; unavailable facts remain null."""
    result = dict.fromkeys(ACTOR_FIELDS)
    result["pid"] = pid
    proc = Path("/proc") / str(pid)
    try:
        status = dict(
            line.split(":", 1)
            for line in (proc / "status").read_text().splitlines()
            if ":" in line
        )
        result.update(
            ppid=int(status["PPid"]),
            uid=int(status["Uid"].split()[1]),
            gid=int(status["Gid"].split()[1]),
            groups=[int(n) for n in status["Groups"].split()],
            no_new_privs=status["NoNewPrivs"].strip() == "1",
        )
        for name, key in (
            ("cap_eff", "CapEff"),
            ("cap_prm", "CapPrm"),
            ("cap_bnd", "CapBnd"),
            ("cap_amb", "CapAmb"),
        ):
            result[name] = int(status[key], 16)
    except (OSError, ValueError, KeyError):
        pass
    try:
        result["start_ticks"] = int(
            (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        )
    except (OSError, ValueError, IndexError):
        pass
    try:
        result["apparmor_label"] = (proc / "attr/apparmor/current").read_text().strip()
    except OSError:
        pass
    return result


def source_metadata(info, *, detailed=False):
    result = dict(
        device=info.st_dev,
        inode=info.st_ino,
        owner_uid=info.st_uid,
        mode=info.st_mode,
        nlink=info.st_nlink,
    )
    if detailed:
        result.update(
            size=info.st_size, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns
        )
    return result


def readonly_source(challenge):
    """Existing observer role: one O_RDONLY FD, no trust/key load or RPC."""
    from azazel_edge.outcome.confinement import enforce_capture

    enforce_capture("edge400-observer")
    if type(challenge) is not str or not re.fullmatch("[0-9a-f]{32}", challenge):
        raise OSError("fixed readback challenge required")
    own_identity = actor(os.getpid())
    print(
        json.dumps(
            dict(
                schema_version="edge-native-source-reader-bootstrap/v1",
                pid=os.getpid(),
                challenge=challenge,
                invocation_id=os.environ.get("INVOCATION_ID"),
                actor=own_identity,
            ),
            sort_keys=True,
        ),
        flush=True,
    )
    if (
        not select.select([sys.stdin], [], [], 20)[0]
        or sys.stdin.readline(128) != "GO " + challenge + "\n"
    ):
        raise OSError("readback permission timeout or mismatch")
    path = Path("/var/lib/edge400-systemd-lab/bundle/input")
    receipt = dict(
        actor=own_identity,
        source_before=None,
        source_after=None,
        access_mode=None,
        started_ns=time.monotonic_ns(),
        finished_ns=None,
        bytes_read=0,
        sha256=None,
        complete=False,
        errors=[],
    )
    raw = b""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            receipt["access_mode"] = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
            receipt["source_before"] = source_metadata(os.fstat(fd), detailed=True)
            chunks = []
            size = 0
            while size <= MAX_SOURCE:
                part = os.read(fd, min(65536, MAX_SOURCE + 1 - size))
                if not part:
                    receipt["complete"] = True
                    break
                chunks.append(part)
                size += len(part)
            raw = b"".join(chunks)
            if len(raw) > MAX_SOURCE:
                raise OSError("Source readback exceeds fixed bound")
            receipt["source_after"] = source_metadata(os.fstat(fd), detailed=True)
            receipt["bytes_read"] = len(raw)
            receipt["sha256"] = sha256(raw)
        finally:
            os.close(fd)
    except OSError as exc:
        receipt["complete"] = False
        receipt["errors"].append(str(exc))
    receipt["finished_ns"] = time.monotonic_ns()
    print(
        json.dumps(
            dict(receipt=receipt, source_base64=base64.b64encode(raw).decode()),
            sort_keys=True,
        ),
        flush=True,
    )


def observed_readback(g, role_command, case_id, files):
    """Root binds an owned transient role before releasing its public FD read."""
    assert case_id in READBACK_CASES
    challenge = secrets.token_hex(16)
    unit = "edge400-accounting-reader-" + case_id + "-" + challenge + ".service"
    command = role_command(
        "observer", "readonly-source", "--challenge", challenge, unit=unit
    )
    expected_command = [
        str(g.PYTHON.with_name("edge-observe")),
        "-I",
        str(g.SRC / "tests/real_systemd/role_probe.py"),
        "readonly-source",
        "--challenge",
        challenge,
    ]
    expected_argv = [arg.encode() for arg in expected_command]
    binding = dict(
        schema_version="edge-native-source-reader-binding/v1",
        unit=unit,
        challenge=challenge,
        bootstrap=None,
        unit_properties=None,
        actual_actor=None,
        command_verified=False,
        status="failure",
        error=None,
        runner_stderr=None,
        runner_stdout_base64=None,
        runner_stderr_base64=None,
        runner_stdout_bytes=None,
        runner_stderr_bytes=None,
        runner_stdout_truncated=None,
        runner_stderr_truncated=None,
        runner_returncode=None,
        cleanup=None,
    )
    process = None
    bootstrap_raw = b""
    drained = False

    def retain_output(stdout, stderr):
        stdout = bootstrap_raw + (stdout or b"")
        stderr = stderr or b""
        binding["runner_stdout_base64"] = base64.b64encode(stdout[:32768]).decode()
        binding["runner_stderr_base64"] = base64.b64encode(stderr[:32768]).decode()
        binding["runner_stdout_bytes"] = len(stdout)
        binding["runner_stderr_bytes"] = len(stderr)
        binding["runner_stdout_truncated"] = len(stdout) > 32768
        binding["runner_stderr_truncated"] = len(stderr) > 32768
        binding["runner_stderr"] = stderr[:32768].decode("utf-8", errors="replace")
        binding["runner_returncode"] = process.returncode

    try:
        prior = g.systemctl(
            "show", unit, "--property=LoadState", "--value", check=False
        ).stdout.strip()
        assert prior == "not-found", "existing transient unit refused"
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if not select.select([process.stdout], [], [], 20)[0]:
            raise OSError("reader bootstrap timeout")
        bootstrap_raw = process.stdout.readline(4097)
        if not bootstrap_raw:
            raise OSError("reader bootstrap EOF before identity binding")
        if len(bootstrap_raw) > 4096:
            raise OSError("reader bootstrap bound")
        bootstrap = json.loads(bootstrap_raw)
        binding["bootstrap"] = bootstrap
        assert set(bootstrap) == {
            "schema_version",
            "pid",
            "challenge",
            "invocation_id",
            "actor",
        }
        assert (
            bootstrap["schema_version"] == "edge-native-source-reader-bootstrap/v1"
            and bootstrap["challenge"] == challenge
        )
        raw = g.systemctl(
            "show", unit, "--property=MainPID", "--property=InvocationID"
        ).stdout
        properties = dict(
            line.split("=", 1) for line in raw.splitlines() if "=" in line
        )
        binding["unit_properties"] = properties
        pid = int(properties["MainPID"])
        assert type(bootstrap["pid"]) is int and bootstrap["pid"] == pid and pid > 1
        assert re.fullmatch("[0-9a-f]{32}", properties["InvocationID"])
        assert properties["InvocationID"] == bootstrap["invocation_id"]
        actual = actor(pid)
        binding["actual_actor"] = actual
        assert actual["uid"] == actual["gid"] == 61002
        assert type(actual["start_ticks"]) is int and actual["start_ticks"] > 0
        assert actual["apparmor_label"] == "edge400-observer (enforce)"
        assert (
            actual["cap_eff"]
            == actual["cap_prm"]
            == actual["cap_bnd"]
            == actual["cap_amb"]
            == 0
        )
        assert actual["no_new_privs"] is True and set(actual["groups"]) <= {61002}
        own = bootstrap["actor"]
        assert set(own) == set(ACTOR_FIELDS)
        assert all(
            own[key] == actual[key] for key in ACTOR_FIELDS if key != "start_ticks"
        )
        assert own["start_ticks"] is None or own["start_ticks"] == actual["start_ticks"]
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        assert cmdline == expected_argv
        binding["command_verified"] = True
        stdout, stderr = process.communicate(
            ("GO " + challenge + "\n").encode(), timeout=20
        )
        drained = True
        retain_output(stdout, stderr)
        assert process.returncode == 0, stderr
        assert len(stdout) <= (MAX_SOURCE * 4 // 3) + 65536
        result = json.loads(stdout)
        assert result["receipt"]["actor"] == own
        # This is the actual Root observation of the already-bound incarnation,
        # not a fabricated observer self-stat or an unbound reported PID.
        result["receipt"]["actor"] = actual
        binding["status"] = "verified_root_observed_role"
        return result
    except BaseException as exc:
        binding["error"] = dict(type=type(exc).__name__, message=str(exc))
        raise
    finally:
        if process is not None and not drained:
            # Stop only a unit whose actual MainPID still has this command and
            # fresh challenge. An untrusted bootstrap PID is never a target.
            if process.poll() is None:
                try:
                    owned_pid = int(
                        g.systemctl(
                            "show", unit, "--property=MainPID", "--value", check=False
                        ).stdout.strip()
                    )
                    assert owned_pid > 1
                    assert (
                        Path(f"/proc/{owned_pid}/cmdline")
                        .read_bytes()
                        .rstrip(b"\0")
                        .split(b"\0")
                        == expected_argv
                    )
                    g.systemctl("stop", unit, check=False)
                    binding["cleanup"] = "stopped_verified_owned_unit"
                except (OSError, ValueError, AssertionError) as exc:
                    binding["cleanup"] = "unverified_unit_not_stopped:" + str(exc)
            try:
                # The trusted reader independently expires its GO wait at20s.
                stdout, stderr = process.communicate(timeout=25)
                retain_output(stdout, stderr)
            except subprocess.TimeoutExpired as exc:
                retain_output(exc.output, exc.stderr)
                binding["error"] = binding["error"] or dict(
                    type="TimeoutExpired",
                    message="owned transient runner did not return after unit stop",
                )
        files["reader-binding.json"] = canonical(binding)


def checkpoint(g, raw):
    from azazel_edge.outcome.input_auth import SourceVerifier

    tip = SourceVerifier(g.fixture().p).verify(raw)
    return {name: tip[name] for name in ("seq", "head", "size", "sha256")}


def witness_boundary(raw):
    from azazel_edge.outcome.input_witness import digest

    if not raw:
        return None
    last = json.loads(raw.splitlines()[-1])
    state = last["state"]
    return dict(
        source_checkpoint={
            name: state["source_" + name] for name in ("seq", "head", "size", "sha256")
        },
        anchor_checkpoint=dict(
            counter=last["counter"],
            head=digest(last),
            size=len(raw),
            sha256=sha256(raw),
        ),
    )


def native_identity(pid):
    identity = actor(pid)
    identity["image"] = None
    try:
        fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            digest = hashlib.sha256()
            total = 0
            while True:
                part = os.read(fd, 65536)
                if not part:
                    break
                total += len(part)
                if total > 64 * 1024 * 1024:
                    raise OSError("native image read exceeds bound")
                digest.update(part)
            identity["image"] = dict(
                sha256=digest.hexdigest(),
                owner_uid=info.st_uid,
                mode=info.st_mode,
                nlink=info.st_nlink,
                seals=fcntl.fcntl(fd, fcntl.F_GET_SEALS),
            )
        finally:
            os.close(fd)
    except OSError:
        pass
    return identity


def process_receipt(g, native_pid):
    native = native_identity(native_pid)
    launcher = actor(native["ppid"]) if native["ppid"] else None
    receiver = None
    if launcher:
        children = (
            Path(f"/proc/{launcher['pid']}/task/{launcher['pid']}/children")
            .read_text()
            .split()
        )
        assert len(children) <= 16
        for child in children:
            current = actor(int(child))
            if current["uid"] == g.fixture().p.data["producer_uid"]:
                assert receiver is None, "multiple producer receiver actors"
                receiver = current
    return dict(native=native, launcher=launcher, receiver=receiver)


def wait_receipt(g):
    raw = g.systemctl(
        "show",
        g.UNIT,
        "--property=ActiveState",
        "--property=ExecMainCode",
        "--property=ExecMainStatus",
    ).stdout
    state = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    return dict(
        unit_state=state.get("ActiveState"),
        exec_main_code=int(state["ExecMainCode"]) if "ExecMainCode" in state else None,
        exec_main_status=int(state["ExecMainStatus"])
        if "ExecMainStatus" in state
        else None,
    )


def await_input_start(g):
    # Native start precedes the core's initial raw-EVE EOF calculation. Use the
    # current unit invocation's startup log only as a barrier, never as facts.
    invocation = g.systemctl(
        "show", g.UNIT, "--property=InvocationID", "--value"
    ).stdout.strip()
    assert re.fullmatch("[0-9a-f]{32}", invocation)
    g.wait_for(
        lambda: "azazel-edge-core started:"
        in g.command(
            "journalctl",
            "--quiet",
            "--no-pager",
            "--output=cat",
            "_SYSTEMD_INVOCATION_ID=" + invocation,
        ).stdout
    )


def _export(g, case_id, files):
    assert case_id in CASES and set(files) <= PUBLIC_FILES
    directory = g.BASE / "native-accounting-public" / case_id
    directory.mkdir(parents=True, exist_ok=False)
    for name, raw in files.items():
        if raw is not None:
            g.write(directory / name, raw)
    return directory


def _case(g, role_command, protocol, case, *, downtime_sid=None, close_lab=None):
    case_id = case["case_id"]
    raw_prefix = g.source()
    receipt = dict(
        schema_version="edge-native-source-accounting-controller/v1",
        case_id=case_id,
        protocol_sha256=PROTOCOL_SHA256,
        source_revision=None,
        core_image_sha256=None,
        registration_sha256=None,
        trust_sha256=None,
        boot_id=g.boot(),
        source_boot_ref=None,
        session_ref=None,
        source_identity=None,
        prefix_checkpoint=None,
        checkpoint=None,
        native=None,
        launcher=None,
        receiver=None,
        wait=None,
        reader=None,
        challenge_sids=case["challenge_sids"],
        observed_sids=[],
        excluded_sids=case.get("expected_excluded_sids", []),
        planned_activity_count=case.get("expected_activity_count", 1),
        witness_boundary=None,
        outcome="failure",
        local_finish_acknowledged=None,
    )
    files = {"protocol.json": protocol}
    failure = None
    try:
        receipt["prefix_checkpoint"] = checkpoint(g, raw_prefix)
        if close_lab is not None:
            close_lab.begin(case_id)
        if downtime_sid is not None:
            g.alert(downtime_sid)
        g.systemctl("start", g.UNIT)
        native_pid = (
            g.live()
        )  # Existing actual v4, signed start, native/receiver gates.
        receipt.update(process_receipt(g, native_pid))
        receipt["session_ref"] = g.events()[-1]["capture_origin"]["session_ref"]
        if close_lab is not None:
            close_lab.started(case_id, native_pid, receipt["session_ref"])
        await_input_start(g)
        for sid in case["challenge_sids"]:
            g.alert(sid)
            g.wait_for(lambda sid=sid: g.saw(sid))
        if case_id == "interrupted-prefix":
            os.kill(native_pid, signal.SIGKILL)
            g.wait_for(lambda: not g.Systemd().cores())
            g.wait_for(lambda: g.Systemd().snapshot()["ActiveState"] == "failed")
            receipt["wait"] = wait_receipt(g)
            if close_lab is not None:
                close_lab.stopped(case_id)
            before = g.source()
            if close_lab is None:
                g.failed_start(
                    "native-accounting-interrupted-connected-relaunch-refused"
                )
            else:
                close_lab.finalized(case_id)
                close_lab.refuse_restart(case_id)
            assert g.source() == before
        else:
            g.stop()
            if close_lab is not None:
                close_lab.stopped(case_id)
            g.observer()  # Existing exclusion/recovery advances protected boundary.
        if receipt["wait"] is None:
            receipt["wait"] = wait_receipt(g)
        source = g.source()
        receipt["checkpoint"] = checkpoint(g, source)
        selected = [
            json.loads(line)
            for line in source.splitlines()
            if json.loads(line)["event"].get("capture_origin", {}).get("session_ref")
            == receipt["session_ref"]
        ]
        boot_refs = {wire["boot_ref"] for wire in selected}
        assert len(boot_refs) == 1
        receipt["source_boot_ref"] = next(iter(boot_refs))
        assert receipt["source_boot_ref"] == receipt["boot_id"].replace("-", "")
        activity = [
            wire["event"]
            for wire in selected
            if wire["event"]["capture_origin"]["kind"]
            in ("decision_execution", "release")
        ]
        receipt["observed_sids"] = [
            event["normalized"]["sid"] for event in activity if "normalized" in event
        ]
        assert receipt["observed_sids"] == case["challenge_sids"]
        assert all(
            event["enforcement"]["executed_count"] == 0
            and event["enforcement"]["mode"] in ("disabled", "dry_run", "policy_gated")
            for event in activity
        )
        assert all(not g.saw(sid) for sid in receipt["excluded_sids"])
        terminal = selected[-1]["event"]
        if case_id == "interrupted-prefix":
            assert terminal["capture_origin"]["kind"] != "session_end"
        else:
            assert terminal["capture_origin"]["kind"] == "session_end"
            assert terminal["capture_lifecycle"]["counts"] == case["expected_counts"]
        identity = source_metadata((g.BUNDLE / "input").stat())
        receipt["source_identity"] = identity
        result = observed_readback(g, role_command, case_id, files)
        receipt["reader"] = result["receipt"]
        readback = base64.b64decode(result["source_base64"], validate=True)
        files["readback-source.raw"] = readback
        assert readback == source and receipt["reader"]["complete"]
        assert receipt["reader"]["source_before"] == receipt["reader"]["source_after"]
        receipt["outcome"] = (
            "interrupted" if case_id == "interrupted-prefix" else "clean"
        )
    except BaseException as exc:
        failure = exc
    finally:
        if failure is not None:
            # Existing units only; natural final writes remain evidence.
            g.systemctl("disable", g.UNIT, check=False)
            g.systemctl("stop", g.UNIT, g.WITNESS, check=False)
        # Fixed root-custodian paths only; no glob and no private-key export.
        for name, path in (
            ("trust.json", g.BUNDLE / "trust.json"),
            ("registration.json", g.BUNDLE / "origin.json"),
            ("source.raw", g.BUNDLE / "input"),
            ("anchors.raw", g.BUNDLE / "witness/anchors/anchors.journal"),
        ):
            try:
                files[name] = path.read_bytes()
            except OSError:
                files[name] = None
        try:
            revision = (g.SRC / "SOURCE_REVISION").read_text().strip()
            assert re.fullmatch("[0-9a-f]{40}", revision)
            receipt["source_revision"] = revision
            receipt["registration_sha256"] = sha256(files["registration.json"])
            receipt["trust_sha256"] = sha256(files["trust.json"])
            receipt["core_image_sha256"] = json.loads(files["registration.json"])[
                "binary_sha256"
            ]
            receipt["witness_boundary"] = witness_boundary(files["anchors.raw"])
            files["code-pins.json"] = canonical(
                dict(
                    source_revision=revision,
                    protocol_sha256=PROTOCOL_SHA256,
                    core_image_sha256=receipt["core_image_sha256"],
                )
            )
        except (OSError, AssertionError, ValueError, TypeError, KeyError) as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            receipt["outcome"] = "failure"
            files["failure.json"] = canonical(
                dict(
                    case_id=case_id,
                    exception_type=type(failure).__name__,
                    message=str(failure),
                )
            )
        files["controller.json"] = canonical(receipt)
        directory = _export(g, case_id, files)
    if failure is not None:
        raise failure
    from azazel_edge.benchmark.native_source_accounting import (
        evaluate_native_source_accounting,
    )

    expected = {
        name + "_sha256": sha256(files[filename])
        for name, filename in (
            ("trust", "trust.json"),
            ("registration", "registration.json"),
            ("source", "source.raw"),
            ("anchors", "anchors.raw"),
            ("controller", "controller.json"),
        )
    }
    result = evaluate_native_source_accounting(
        files["trust.json"],
        files["registration.json"],
        files["source.raw"],
        files["anchors.raw"],
        files["controller.json"],
        expected=expected,
    )
    g.write(directory / "evaluation.json", canonical(result))
    assert result["finite_accounting_verified"] is (case_id != "interrupted-prefix"), (
        result
    )
    if close_lab is not None:
        close_lab.finalized(
            case_id,
            reader=receipt["reader"],
            readback=readback,
            reader_binding=files.get("reader-binding.json"),
        )
    g.record(
        "native-accounting-" + case_id,
        public_directory=str(directory),
        finite_accounting_verified=result["finite_accounting_verified"],
        local_finish_acknowledged=None,
    )


def exercise(g, role_command, *, close_lab=None):
    protocol = (Path(__file__).with_name(PROTOCOL_NAME)).read_bytes()
    assert sha256(protocol) == PROTOCOL_SHA256
    declaration = json.loads(protocol)
    assert [case["case_id"] for case in declaration["cases"]] == list(CASES)
    # Existing earlier test sessions stay intact, outside these selected cohorts.
    g.stop()
    g.observer()
    try:
        for case in declaration["cases"]:
            if close_lab is not None and case["case_id"] == "interrupted-prefix":
                close_lab.witness_stopped_close()
            _case(
                g,
                role_command,
                protocol,
                case,
                downtime_sid=case.get("downtime_challenge_sid"),
                close_lab=close_lab,
            )
    except BaseException as exc:
        # Includes an annex qualification refusal after raw export. Stop only
        # these existing lab units; keep every original/checkpoint untouched.
        g.systemctl("disable", g.UNIT, check=False)
        g.systemctl("stop", g.UNIT, g.WITNESS, check=False)
        if close_lab is not None:
            close_lab.retain_failures(exc)
        raise


def finish(g):
    """Final interrupted history is an expected retained failure, never repaired."""
    before = g.source()
    g.systemctl("disable", g.UNIT)
    g.systemctl("stop", g.UNIT, g.WITNESS, check=False)
    assert g.source() == before and not g.source_closed()
    assert not g.Systemd().cores()
    g.record(
        "native-accounting-finished-disabled-retained-interrupted-history",
        source_sha256=sha256(before),
        final_counts=None,
        local_finish_acknowledged=None,
    )
