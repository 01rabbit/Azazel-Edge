"""Three frozen v4 finite-load arms under existing native-AA authority only."""

import base64
import copy
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time

import native_accounting as accounting
from native_close_receipts import stable_read
from finite_ingress import FiniteIngressLab, SystemdUnitClient, _BusError
from signed_network_recording import _clock_anchor
from azazel_edge.benchmark.finite_load_cost import (
    ARMS,
    FILES,
    PROTOCOL_SHA256,
    materialize_corpus,
    evaluate_finite_load_cost_case,
    evaluate_finite_load_cost_comparison,
)

PROTOCOL_NAME = "finite-load-cost-protocol-v1.json"
POLICY_PATH = (
    Path(__file__).resolve().parents[1] / "fixtures/signed_network_observer_policy.json"
)
HELPER = Path(__file__).with_name("finite_load_observer.py")
SIDE_FILES = dict(
    phase="observer-phase.raw",
    calls="observer-calls.raw",
    context="observer-context.raw",
    completion="observer-completion.json",
    journal="observer-journal.raw",
    outcomes="observer-outcomes.raw",
)
OUTPUT_LIMIT = 65536


def error_value(error):
    return dict(type=type(error).__name__, message=str(error)[:4096])


def stage_observer_config(g, nonce, raw):
    """Root-only runtime ancestors, exclusive immutable config, existing read grant."""
    from azazel_edge.outcome.input_auth import open_parent, read_regular

    assert re.fullmatch("[0-9a-f]{32}", nonce) and len(raw) <= 65536
    directory = g.PYTHON.parent.parent / "finite-load-configs"
    directory.mkdir(mode=0o555, exist_ok=True)
    info = directory.lstat()
    assert (
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == 0
        and stat.S_IMODE(info.st_mode) == 0o555
    )
    path = directory / ("load-" + nonce + "-config.json")
    parent, name = open_parent(path, trusted_owner=0)
    fd = None
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o444,
            dir_fd=parent,
        )
        remaining = memoryview(raw)
        while remaining:
            count = os.write(fd, remaining)
            assert count > 0
            remaining = remaining[count:]
        os.fsync(fd)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)
    assert read_regular(path, owner=0, mode=0o444, max_bytes=65536)[0] == raw
    return path


def root_identity(pid, bootstrap=None):
    """Root cross-PID observation; child clocks remain their actual reported clocks."""
    actual = accounting.actor(pid)
    domain = dict(
        time_namespace_device=None,
        time_namespace_inode=None,
        timens_offsets=None,
        established=False,
    )
    try:
        ns = Path(f"/proc/{pid}/ns/time").stat()
        offsets = [
            dict(clock=(v := line.split())[0], seconds=int(v[1]), nanoseconds=int(v[2]))
            for line in Path(f"/proc/{pid}/timens_offsets").read_text().splitlines()
        ]
        domain.update(
            time_namespace_device=ns.st_dev,
            time_namespace_inode=ns.st_ino,
            timens_offsets=offsets,
            established={v["clock"] for v in offsets} == {"monotonic", "boottime"}
            and all(v["seconds"] == v["nanoseconds"] == 0 for v in offsets),
        )
    except (OSError, ValueError, IndexError):
        pass
    resolutions = (
        bootstrap["clock_resolutions"]
        if bootstrap
        else {
            k: time.get_clock_info(k).resolution
            for k in ("monotonic", "process_time", "thread_time")
        }
    )
    return dict(
        pid=pid,
        start_ticks=actual["start_ticks"],
        native_tid=bootstrap["native_tid"] if bootstrap else threading.get_native_id(),
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        clock_domain=domain,
        clock_ticks_per_second=os.sysconf("SC_CLK_TCK"),
        clock_resolutions=resolutions,
    )


def resource(actor):
    if actor is None:
        return None
    result = dict(
        pid=actor["pid"],
        start_ticks=actor["start_ticks"],
        observed_ns=time.monotonic_ns(),
        stat=None,
        io=None,
        error=None,
    )
    try:
        assert accounting.actor(actor["pid"])["start_ticks"] == actor["start_ticks"]
        for name in ("stat", "io"):
            raw = Path(f"/proc/{actor['pid']}/{name}").read_text()
            assert len(raw.encode()) <= 16384
            result[name] = raw
        assert accounting.actor(actor["pid"])["start_ticks"] == actor["start_ticks"]
    except (OSError, AssertionError) as error:
        result["error"] = error_value(error)
    return result


class ObserverUnitClient(SystemdUnitClient):
    def call(self, method, unit):
        assert method in ("RefUnit", "UnrefUnit") and re.fullmatch(
            r"edge400-load-observer-[0-9a-f]{32}\.service", unit
        )
        error, reply = _BusError(), ctypes.c_void_p()
        try:
            rc = self.lib.sd_bus_call_method(
                self.bus,
                b"org.freedesktop.systemd1",
                b"/org/freedesktop/systemd1",
                b"org.freedesktop.systemd1.Manager",
                method.encode(),
                ctypes.byref(error),
                ctypes.byref(reply),
                b"s",
                ctypes.c_char_p(unit.encode()),
            )
            self.checked(
                method,
                rc,
                error.name.decode(errors="replace")[:4096] if error.name else None,
                error.message.decode(errors="replace")[:4096]
                if error.message
                else None,
            )
        finally:
            if reply:
                self.lib.sd_bus_message_unref(reply)
            self.lib.sd_bus_error_free(ctypes.byref(error))


class BoundedDrain:
    """Drain one private pipe concurrently; count all bytes, keep bounded original prefix."""

    def __init__(self, pipe, name, limit=OUTPUT_LIMIT):
        self.pipe, self.name, self.limit = pipe, name, limit
        self.prefix = bytearray()
        self.count, self.eof, self.error = 0, False, None
        self.first_line = None
        self.ready = threading.Event()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            while True:
                block = os.read(self.pipe.fileno(), 4096)
                if not block:
                    with self.lock:
                        self.eof = True
                    break
                with self.lock:
                    self.count += len(block)
                    self.prefix.extend(block[: max(0, self.limit - len(self.prefix))])
                    if self.first_line is None:
                        end = self.prefix.find(b"\n")
                        if end >= 0:
                            self.first_line = bytes(self.prefix[: end + 1])
                            self.ready.set()
                        elif len(self.prefix) > 16384:
                            self.error = error_value(
                                ValueError("bootstrap line exceeds bound")
                            )
                            self.ready.set()
        except BaseException as error:
            with self.lock:
                self.error = error_value(error)
        finally:
            self.ready.set()

    def snapshot(self):
        with self.lock:
            return bytes(self.prefix), self.count, self.eof, self.error


class ObserverProcess:
    def __init__(
        self, g, role_command, *, config=None, config_sha256=None, create=False
    ):
        self.g, self.client, self.process = g, None, None
        self.referenced = False
        challenge = secrets.token_hex(16)
        unit = "edge400-load-observer-" + challenge + ".service"
        self.receipt = dict(
            unit=unit,
            challenge=challenge,
            bootstrap=None,
            unit_properties=None,
            actor=None,
            identity=None,
            command_verified=False,
            started_ns=time.monotonic_ns(),
            ready_ns=None,
            stop_requested_ns=None,
            signal=None,
            signal_target=None,
            finished_ns=None,
            runner_returncode=None,
            exit=None,
            stdout_bytes=None,
            stderr_bytes=None,
            stdout_truncated=None,
            stderr_truncated=None,
            sidecars=dict.fromkeys(SIDE_FILES),
            stdout_eof=None,
            stderr_eof=None,
            drain_errors=[],
            fault_boundary=None,
            error=None,
        )
        self.stdout, self.stderr, self.bootstrap_raw = b"", b"", b""
        self.drains = {}
        args = ["--challenge", challenge]
        if config is not None:
            args += ["--config", str(config), "--config-sha256", config_sha256]
        if create:
            args += ["--create"]
        command = role_command("observer", "finite-load", *args, unit=unit)
        expected = [
            str(g.PYTHON.with_name("edge-observe")),
            "-I",
            str(g.SRC / "tests/real_systemd/role_probe.py"),
            "finite-load",
            *args,
        ]
        self.expected_argv = [v.encode() for v in expected]
        try:
            prior = g.systemctl(
                "show", unit, "--property=LoadState", "--value", check=False
            ).stdout.strip()
            assert prior == "not-found"
            self.process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.drains = {
                "stdout": BoundedDrain(self.process.stdout, "stdout"),
                "stderr": BoundedDrain(self.process.stderr, "stderr"),
            }
            assert self.drains["stdout"].ready.wait(20), "observer bootstrap timeout"
            self.bootstrap_raw = self.drains["stdout"].first_line
            assert (
                self.bootstrap_raw is not None
                and 0 < len(self.bootstrap_raw) <= 16384
                and self.bootstrap_raw.endswith(b"\n")
            ), "observer bootstrap EOF/bound"
            boot = json.loads(self.bootstrap_raw)
            self.receipt["bootstrap"] = boot
            assert set(boot) == {
                "schema_version",
                "pid",
                "challenge",
                "invocation_id",
                "actor",
                "native_tid",
                "clock_resolutions",
            }
            assert (
                boot["schema_version"] == "edge-finite-load-observer-bootstrap/v1"
                and boot["challenge"] == challenge
            )
            props = self.properties("MainPID", "InvocationID")
            self.receipt["unit_properties"] = props
            pid = int(props["MainPID"])
            assert (
                pid > 1
                and boot["pid"] == pid
                and boot["invocation_id"] == props["InvocationID"]
            )
            assert re.fullmatch("[0-9a-f]{32}", props["InvocationID"])
            assert (
                Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                == self.expected_argv
            )
            actor = accounting.actor(pid)
            self.receipt["actor"] = actor
            assert actor["uid"] == actor["gid"] == 61002 and actor["start_ticks"] > 0
            assert (
                actor["apparmor_label"] == "edge400-observer (enforce)"
                and actor["no_new_privs"] is True
            )
            assert actor["cap_eff"] == actor["cap_prm"] == actor["cap_bnd"] == actor[
                "cap_amb"
            ] == 0 and set(actor["groups"]) <= {61002}
            assert all(
                v == actor[k] for k, v in boot["actor"].items() if k != "start_ticks"
            )
            assert boot["actor"]["start_ticks"] in (None, actor["start_ticks"])
            identity = root_identity(pid, boot)
            self.receipt.update(identity=identity, command_verified=True)
            self.client = ObserverUnitClient()
            self.client.open()
            self.client.call("RefUnit", unit)
            self.referenced = True
            self.process.stdin.write(
                accounting.canonical(
                    dict(
                        schema_version="edge-finite-load-observer-go/v1",
                        challenge=challenge,
                        identity=identity,
                    )
                )
            )
            self.process.stdin.flush()
            self.receipt["ready_ns"] = time.monotonic_ns()
        except BaseException as error:
            self.receipt["error"] = error_value(error)
            error.observer_process = self
            raise

    def properties(self, *names):
        raw = self.g.systemctl(
            "show", self.receipt["unit"], *["--property=" + n for n in names]
        ).stdout
        result = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
        assert set(result) == set(names)
        return result

    def signal(self, signum):
        target = accounting.actor(self.receipt["actor"]["pid"])
        assert target == self.receipt["actor"], "observer incarnation changed"
        self.receipt.update(
            signal_target=target, signal=signum, stop_requested_ns=time.monotonic_ns()
        )
        os.kill(target["pid"], signum)

    def retain_drains(self):
        for name in ("stdout", "stderr"):
            if name not in self.drains:
                continue
            raw, count, eof, error = self.drains[name].snapshot()
            setattr(self, name, raw)
            self.receipt[name + "_bytes"] = count
            self.receipt[name + "_truncated"] = count > OUTPUT_LIMIT
            self.receipt[name + "_eof"] = eof
            if error is not None and not any(
                v["stream"] == name for v in self.receipt["drain_errors"]
            ):
                self.receipt["drain_errors"].append(dict(stream=name, **error))

    def wait(self, timeout=20):
        try:
            self.process.wait(timeout=timeout)
            for drain in self.drains.values():
                drain.thread.join(5)
        finally:
            self.retain_drains()
            self.receipt["runner_returncode"] = self.process.returncode
        assert (
            self.receipt["stdout_eof"]
            and self.receipt["stderr_eof"]
            and not self.receipt["drain_errors"]
        ), "observer output drain incomplete"
        self.receipt["finished_ns"] = time.monotonic_ns()
        self.receipt["exit"] = self.properties(
            "ExecMainPID", "ExecMainCode", "ExecMainStatus", "Result"
        )
        assert int(self.receipt["exit"]["ExecMainPID"]) == self.receipt["actor"]["pid"]
        assert (
            not self.receipt["stdout_truncated"]
            and not self.receipt["stderr_truncated"]
        ), "observer diagnostic overflow"
        assert self.stdout.startswith(self.bootstrap_raw)
        return self.stdout[len(self.bootstrap_raw) :]

    def terminate_and_wait(self):
        """Stop only fixed-command owned transient unit; preserve before Unref."""
        if self.process is None:
            return
        if self.process.poll() is None:
            pid = int(self.properties("MainPID")["MainPID"])
            assert (
                pid > 1
                and Path(f"/proc/{pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                == self.expected_argv
            )
            self.g.systemctl("stop", self.receipt["unit"])
        if self.receipt["finished_ns"] is None:
            self.wait()

    def close(self, original=None):
        failure, trace = None, []
        if self.client is not None:
            try:
                if self.referenced:
                    self.client.call("UnrefUnit", self.receipt["unit"])
            except BaseException as error:
                failure = error
            finally:
                try:
                    self.client.close()
                except BaseException as error:
                    failure = failure or error
                trace = self.client.trace
                self.client = None
        if failure:
            self.receipt["error"] = self.receipt["error"] or error_value(failure)
        try:
            self.g.record(
                "finite-load-observer-reference-released",
                unit=self.receipt["unit"],
                methods=trace,
                error=error_value(failure) if failure else None,
                primary_error_preserved=original is not None,
            )
        except BaseException as error:
            failure = failure or error
            sys.stderr.write(
                accounting.canonical(
                    dict(
                        stage="observer-reference-trace",
                        methods=trace,
                        error=error_value(error),
                    )
                ).decode()
            )
        if failure and original is None:
            raise failure


def audit_role(g, role_command, create=False):
    actor, failure = None, None
    try:
        actor = ObserverProcess(g, role_command, create=create)
        out = actor.wait()
        assert (
            actor.process.returncode == 0
            and actor.receipt["exit"]["ExecMainCode"] == "1"
            and actor.receipt["exit"]["ExecMainStatus"] == "0"
        )
        status = json.loads(out)["status"]
        assert status["committed"] == 0
        return status, actor.receipt
    except BaseException as error:
        failure = error
        actor = actor or getattr(error, "observer_process", None)
        if actor is not None:
            try:
                actor.terminate_and_wait()
            except BaseException as cleanup:
                g.record("finite-load-audit-stop-failure", error=error_value(cleanup))
            g.record(
                "finite-load-audit-failure",
                receipt=actor.receipt,
                stdout_base64=base64.b64encode(actor.stdout).decode(),
                stderr_base64=base64.b64encode(actor.stderr).decode(),
            )
        raise
    finally:
        if actor is not None:
            actor.close(failure)


class FiniteLoadCostLab(FiniteIngressLab):
    def __init__(self, g, role_command):
        self.g, self.role_command, self.variant = g, role_command, "main"
        self.protocol_raw = Path(__file__).with_name(PROTOCOL_NAME).read_bytes()
        assert accounting.sha256(self.protocol_raw) == PROTOCOL_SHA256
        self.protocol = json.loads(self.protocol_raw)
        self.protocol_sha256 = PROTOCOL_SHA256
        self.allowed_case_ids = frozenset(ARMS)
        self.public_directory = "finite-load-cost-public"
        self.custody_schema = "outcome-live-close-custody/v3"
        self.cases = {
            arm: dict(action="normal_stop", custody_mode="live_parent_and_children")
            for arm in ARMS
        }
        self.contexts, self._case_manager_clients, self.results = {}, {}, []
        self.corpus, self.manifest = materialize_corpus()
        self.active_observer = None
        self.pre_audits = []

    def begin(self, case_id, *, previous_session=None):
        super().begin(case_id, previous_session=previous_session)
        context = self.contexts[case_id]
        context["ingress"]["protocol_sha256"] = PROTOCOL_SHA256
        context["files"]["corpus-manifest.json"] = accounting.canonical(self.manifest)
        anchor_before = _clock_anchor()
        context["load"] = dict(
            schema_version="edge-finite-load-controller/v1",
            case_id=case_id,
            protocol_sha256=PROTOCOL_SHA256,
            corpus_sha256=self.manifest["sha256"],
            session_ref=None,
            started_ns=time.monotonic_ns(),
            finished_ns=None,
            controller_identity=root_identity(os.getpid()),
            controller_anchors=dict(before=anchor_before, after=None),
            writer=None,
            observer=None,
            resources=dict.fromkeys(
                (
                    "native_before",
                    "native_after",
                    "receiver_before",
                    "receiver_after",
                    "observer_before",
                    "observer_after",
                )
            ),
            audits=copy.deepcopy(self.pre_audits),
            errors=[],
        )

    def configure_observer(self, context):
        directory = self.g.BUNDLE / "observer"
        nonce = context["controller"]["attempt_ref"]
        paths = dict(
            registration=str(self.g.BUNDLE / "origin.json"),
            trust=str(self.g.BUNDLE / "trust.json"),
            policy=str(POLICY_PATH),
        )
        paths.update(
            {
                key: str(directory / ("load-" + nonce + "-" + key))
                for key in SIDE_FILES
                if key != "journal"
            }
        )
        paths["journal"] = str(directory / "observations.journal")
        helper_raw = HELPER.read_bytes()
        metadata = dict(
            run_id=nonce,
            arm=context["controller"]["case_id"],
            role="observer",
            input_sha256=self.manifest["sha256"],
            code_sha256=accounting.sha256(helper_raw),
            core_sha256=context["controller"]["core_image_sha256"],
            interpreter_sha256=accounting.sha256(self.g.PYTHON.resolve().read_bytes()),
        )
        config = dict(
            schema_version="edge-finite-load-observer-config/v1",
            case_id=metadata["arm"],
            protocol_sha256=PROTOCOL_SHA256,
            corpus_sha256=self.manifest["sha256"],
            registration_sha256=context["controller"]["registration_sha256"],
            trust_sha256=context["controller"]["trust_sha256"],
            helper_sha256=accounting.sha256(helper_raw),
            paths=paths,
            metadata=metadata,
        )
        raw = accounting.canonical(config)
        path = stage_observer_config(self.g, nonce, raw)
        context["files"].update(
            {
                "observer-config.json": raw,
                "observer-policy.json": POLICY_PATH.read_bytes(),
            }
        )
        try:
            observer = ObserverProcess(
                self.g,
                self.role_command,
                config=path,
                config_sha256=accounting.sha256(raw),
            )
        except BaseException as error:
            observer = getattr(error, "observer_process", None)
            if observer is not None:
                context["observer_process"] = self.active_observer = observer
                context["load"]["observer"] = observer.receipt
            raise
        context["observer_process"] = observer
        context["load"]["observer"] = observer.receipt
        self.active_observer = observer
        context["load"]["resources"]["observer_before"] = resource(
            observer.receipt["actor"]
        )
        # Readiness means recovery completed and real call recording began, not
        # merely that Root released the process bootstrap.
        self.g.wait_for(
            lambda: Path(paths["calls"]).exists() and Path(paths["context"]).exists()
        )
        return observer

    def cursor_reached(self, context, marker):
        source = context["ingress"]["markers"][-1]
        offset = source["source_checkpoint"]["size"]

        def reached():
            try:
                raw, _ = stable_read(
                    self.g.BUNDLE / "observer/observations.journal", 8 * 1024 * 1024
                )
                rows = [json.loads(line) for line in raw.splitlines()]
                positions = [
                    r["data"]["position"] for r in rows if r["kind"] == "cursor"
                ]
                assert not positions or all(
                    p["offset"] <= len(self.g.source()) for p in positions
                )
                if not any(p["offset"] >= offset for p in positions):
                    return False
                anchors, _ = stable_read(
                    self.g.BUNDLE / "witness/anchors/anchors.journal", 8 * 1024 * 1024
                )
                boundary = accounting.witness_boundary(anchors)
                if boundary is None or boundary["source_checkpoint"]["size"] < offset:
                    return False
                if context["controller"]["case_id"] == "load-faulted":
                    context["files"]["observer-fault-anchors.raw"] = anchors
                    context["load"]["observer"]["fault_boundary"] = dict(
                        observed_ns=time.monotonic_ns(),
                        source_checkpoint=source["source_checkpoint"],
                        cursor_position=positions[-1],
                        journal_checkpoint=dict(
                            size=len(raw), sha256=accounting.sha256(raw)
                        ),
                        witness_sha256=accounting.sha256(anchors),
                        witness_boundary=boundary,
                    )
                return True
            except (OSError, ValueError, AssertionError):
                return False

        self.g.wait_for(reached)

    def paced_writer(self, context):
        raw = self.corpus
        receipt = dict(
            pid=os.getpid(),
            tid=None,
            fd=None,
            flags=None,
            before=None,
            after=None,
            started_ns=None,
            first_write_before_ns=None,
            marker_one_before_ns=None,
            final_nonalert_after_ns=None,
            finished_ns=None,
            joined_ns=None,
            written_bytes=0,
            nonalert_records=0,
            per_class=dict.fromkeys(("flow", "dns", "stats", "http"), 0),
            write_calls=0,
            fsync_completed=False,
            joined=False,
            sha256=None,
            error=None,
        )
        context["load"]["writer"] = receipt
        ingress = dict(
            stage="initial",
            pid=os.getpid(),
            tid=None,
            fd=None,
            flags=None,
            before=None,
            after=None,
            started_ns=None,
            finished_ns=None,
            offset_before=None,
            offset_after=None,
            requested_bytes=len(raw),
            written_bytes=0,
            write_calls=0,
            fsync_completed=False,
            joined=False,
            joined_ns=None,
            pause=None,
            resume=None,
            error=None,
        )
        context["ingress"]["writer"].append(ingress)

        def writer():
            digest, fd = hashlib.sha256(), None
            receipt.update(
                tid=threading.get_native_id(), started_ns=time.monotonic_ns()
            )
            try:
                fd = os.open(
                    self.eve_path(),
                    os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                receipt.update(
                    fd=fd,
                    flags=fcntl.fcntl(fd, fcntl.F_GETFL),
                    before=accounting.source_metadata(os.fstat(fd), detailed=True),
                )
                ingress["offset_before"] = os.lseek(fd, 0, os.SEEK_END)
                assert ingress["offset_before"] == 0
                assert all(
                    receipt["before"][k] == context["ingress"]["held_fd"]["object"][k]
                    for k in ("device", "inode", "owner_uid", "mode", "nlink")
                )
                receipt["first_write_before_ns"] = time.monotonic_ns()
                origin = receipt["first_write_before_ns"]
                for line in raw.splitlines(keepends=True):
                    event = json.loads(line)
                    nonalert = event["event_type"] != "alert"
                    deadline = origin + int(
                        (receipt["nonalert_records"] + (1 if nonalert else 0))
                        * 1e9
                        / 3000
                    )
                    delay = (deadline - time.monotonic_ns()) / 1e9
                    if delay > 0:
                        time.sleep(delay)
                    if not nonalert and event["alert"]["signature_id"] == 90232001:
                        receipt["marker_one_before_ns"] = time.monotonic_ns()
                    view = memoryview(line)
                    while view:
                        amount = os.write(fd, view)
                        assert amount > 0
                        digest.update(view[:amount])
                        receipt["written_bytes"] += amount
                        receipt["write_calls"] += 1
                        view = view[amount:]
                    if nonalert:
                        receipt["nonalert_records"] += 1
                        receipt["per_class"][event["event_type"]] += 1
                        if receipt["nonalert_records"] == 27004:
                            receipt["final_nonalert_after_ns"] = time.monotonic_ns()
                os.fsync(fd)
                receipt["fsync_completed"] = True
                ingress["offset_after"] = os.lseek(fd, 0, os.SEEK_CUR)
                receipt["after"] = accounting.source_metadata(
                    os.fstat(fd), detailed=True
                )
            except BaseException as error:
                receipt["error"] = error_value(error)
            finally:
                receipt["sha256"] = digest.hexdigest()
                if fd is not None:
                    os.close(fd)
                receipt["finished_ns"] = time.monotonic_ns()

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        return thread, receipt, ingress

    def collect_observer(self, context):
        observer = context.get("observer_process")
        if observer is None:
            return
        context["files"].update(
            {
                "observer-stdout.raw": observer.stdout,
                "observer-stderr.raw": observer.stderr,
            }
        )
        paths = json.loads(context["files"]["observer-config.json"])["paths"]
        for key, filename in SIDE_FILES.items():
            try:
                raw, meta = stable_read(
                    Path(paths[key]), 16384 if key == "context" else 4 * 1024 * 1024
                )
                context["files"][filename] = raw
                observer.receipt["sidecars"][key] = dict(
                    before=meta["object"],
                    after=meta["object"],
                    sha256=meta["sha256"],
                    size=len(raw),
                )
            except FileNotFoundError:
                pass
        context["load"]["resources"]["observer_after"] = resource(
            observer.receipt["actor"]
        )

    def run_audit(self, context, stage):
        started = time.monotonic_ns()
        status, receipt = audit_role(self.g, self.role_command)
        audit = dict(
            stage=stage,
            unit=receipt["unit"],
            actor=receipt["actor"],
            started_ns=started,
            finished_ns=time.monotonic_ns(),
            exit=receipt["exit"],
            error=receipt["error"],
        )
        context["load"]["audits"].append(audit)
        return status

    def case(self, case_id):
        g = self.g
        self.begin(case_id)
        context = self.contexts[case_id]
        thread, writer, ingress = None, None, None
        try:
            g.systemctl("start", g.UNIT)
            pid = g.live()
            self.started(case_id, pid, g.events()[-1]["capture_origin"]["session_ref"])
            context["load"]["session_ref"] = context["controller"]["session_ref"]
            accounting.await_input_start(g)
            for role in ("native", "receiver"):
                context["load"]["resources"][role + "_before"] = resource(
                    context["controller"]["actors"][role]
                )
            observer = (
                None if case_id == "load-off" else self.configure_observer(context)
            )
            thread, writer, ingress = self.paced_writer(context)
            if observer is not None:
                for marker in self.manifest["markers"]:
                    self.source_marker(
                        context,
                        dict(sid=marker["sid"], occurrence=1),
                        marker["end_offset"],
                    )
                    self.cursor_reached(context, marker)
                    if case_id == "load-faulted":
                        assert (
                            writer["first_write_before_ns"] is not None
                            and time.monotonic_ns()
                            < writer["first_write_before_ns"] + 6_000_000_000
                        ), "first-marker kill missed fixed second-marker deadline"
                        observer.signal(signal.SIGKILL)
                        observer.wait()
                        assert (
                            observer.receipt["exit"]["ExecMainCode"] == "2"
                            and observer.receipt["exit"]["ExecMainStatus"] == "9"
                        )
                        self.collect_observer(context)
                        break
            thread.join(110)
            writer["joined"] = not thread.is_alive()
            writer["joined_ns"] = time.monotonic_ns()
            for key in ingress.keys() & writer.keys():
                ingress[key] = copy.deepcopy(writer[key])
            assert writer["joined"] and writer["error"] is None, writer
            actual = self.snapshot(context, "eve-after-writer.raw")
            assert actual == self.corpus and writer["sha256"] == self.manifest["sha256"]
            if case_id != "load-on":
                for marker in self.manifest["markers"][
                    (1 if case_id == "load-faulted" else 0) :
                ]:
                    self.source_marker(
                        context,
                        dict(sid=marker["sid"], occurrence=1),
                        marker["end_offset"],
                    )
            if case_id == "load-on":
                observer.signal(signal.SIGTERM)
                observer.wait()
                assert (
                    observer.process.returncode == 0
                    and observer.receipt["exit"]["ExecMainCode"] == "1"
                    and observer.receipt["exit"]["ExecMainStatus"] == "0"
                )
                self.collect_observer(context)
            context["load"]["controller_anchors"]["after"] = _clock_anchor()
            for role in ("native", "receiver"):
                context["load"]["resources"][role + "_after"] = resource(
                    context["controller"]["actors"][role]
                )
            g.stop()
            self.stopped(case_id)
            self.run_audit(context, "post_window")
            self.finalized(case_id)
        except BaseException as error:
            context["load"]["errors"].append(dict(stage="case", **error_value(error)))
            raise
        finally:
            if thread is not None and thread.is_alive():
                thread.join(110)
            if context.get("observer_process") and context["exported"]:
                context["observer_process"].close()
                self.active_observer = None

    def export(self, case_id):
        context = self.contexts[case_id]
        assert not context["exported"]
        for name, held in (("eve-held-final.raw", True), ("eve-path-final.raw", False)):
            try:
                self.snapshot(context, name, held=held)
            except (OSError, AssertionError):
                pass
        ingress, control, load, files = (
            context[k] for k in ("ingress", "controller", "load", "files")
        )
        ingress["finished_ns"] = time.monotonic_ns()
        if context["eve_fd"] is not None:
            os.close(context["eve_fd"])
            context["eve_fd"] = None
            ingress["held_fd"]["closed_ns"] = time.monotonic_ns()
        files["ingress-controller.json"] = accounting.canonical(ingress)
        load["finished_ns"] = time.monotonic_ns()
        load["controller_anchors"]["after"] = _clock_anchor()
        files["load-controller.json"] = accounting.canonical(load)
        control["finished_ns"] = time.monotonic_ns()
        files["close-controller.json"] = accounting.canonical(control)
        files["actor-fd-custody.json"] = accounting.canonical(control["fd_custody"])
        files["code-pins.json"] = accounting.canonical(
            dict(
                source_revision=control["source_revision"],
                protocol_sha256=PROTOCOL_SHA256,
                core_image_sha256=control["core_image_sha256"],
            )
        )
        if files.get("anchors-after.raw"):
            files["witness-boundary.json"] = accounting.canonical(
                accounting.witness_boundary(files["anchors-after.raw"])
            )
        directory = self.g.BASE / self.public_directory / case_id
        directory.mkdir(parents=True, exist_ok=False)
        assert set(files) <= FILES
        for name, body in files.items():
            if body is not None:
                self.g.write(directory / name, body)
        context["exported"] = True
        artifacts = {name: files.get(name) for name in FILES}
        pins = {
            name: accounting.sha256(body) if body is not None else None
            for name, body in artifacts.items()
        }
        result = evaluate_finite_load_cost_case(artifacts, expected=pins)
        result["observer"] = evaluate_observer_originals(artifacts, pins)
        self.g.write(directory / "evaluation.json", accounting.canonical(result))
        self.results.append(result)
        if control["outcome"] == "failure":
            return
        assert result["finite"]["whole_input_complete"] is True, result
        assert result["load"]["status"] == result["intake"]["status"] == "qualified", (
            result
        )
        assert case_id != "load-on" or (
            result["observer"]["normal_completion"] is True
            and result["observer"]["clock"] is not None
            and result["observer"]["clock"]["status"] == "qualified"
        ), result
        assert (
            case_id != "load-faulted" or result["observer"]["fault_verified"] is True
        ), result
        context["analysis_accepted"] = True

    def exercise(self):
        g = self.g
        directory = g.BASE / self.public_directory
        directory.mkdir(mode=0o755, exist_ok=False)
        g.write(directory / "corpus-manifest.json", accounting.canonical(self.manifest))
        try:
            g.systemctl("start", g.UNIT)
            g.wait_for(lambda: len(g.Systemd().cores()) == 1)
            switch = g.Switch(g.BUNDLE)
            plan = switch.plan()
            assert switch.apply(plan, g.digest(plan))["status"] == "started"
            g.live()
            g.stop()
            start = time.monotonic_ns()
            _, receipt = audit_role(g, self.role_command)
            self.pre_audits.append(
                dict(
                    stage="warmup_before",
                    unit=receipt["unit"],
                    actor=receipt["actor"],
                    started_ns=start,
                    finished_ns=time.monotonic_ns(),
                    exit=receipt["exit"],
                    error=receipt["error"],
                )
            )
            for case_id in ARMS:
                self.case(case_id)
                self.release_case_reference(case_id)
            g.write(
                directory / "comparison.json",
                accounting.canonical(
                    evaluate_finite_load_cost_comparison(self.results)
                ),
            )
        except BaseException as error:
            if self.active_observer is not None:
                try:
                    self.active_observer.terminate_and_wait()
                    for context in self.contexts.values():
                        if context.get("observer_process") is self.active_observer:
                            self.collect_observer(context)
                except BaseException as cleanup:
                    g.record("load-observer-failure-cleanup", **error_value(cleanup))
            try:
                self.teardown_failure(error)
            finally:
                if self.active_observer is not None:
                    self.active_observer.close(error)
                    self.active_observer = None
            raise


def _rows(raw, schema, *, limit, max_rows, allow_partial=False):
    assert type(raw) is bytes and 0 < len(raw) <= limit
    cut = raw.rfind(b"\n") + 1
    prefix, tail = raw[:cut], raw[cut:]
    assert prefix and (allow_partial or not tail)
    lines = prefix.splitlines(keepends=True)
    assert len(lines) <= max_rows
    result, previous = [], "0" * 64
    for index, line in enumerate(lines, 1):
        value = json.loads(line)
        assert accounting.canonical(value) == line and set(value) == {
            "schema_version",
            "seq",
            "prev",
            "kind",
            "data",
        }
        assert (
            value["schema_version"] == schema
            and value["seq"] == index
            and value["prev"] == previous
        )
        result.append(value)
        previous = accounting.sha256(line)
    return (result, tail) if allow_partial else result


def _phase_facts(raw, *, metadata, identity, complete):
    rows, tail = _rows(
        raw,
        "edge-phase-timing-record/v1",
        limit=4 * 1024 * 1024,
        max_rows=4096,
        allow_partial=True,
    )
    assert rows[0]["kind"] == "header"
    header = rows[0]["data"]
    assert all(header[k] == v for k, v in metadata.items())
    assert all(header[k] == v for k, v in identity.items())
    footer = rows[-1]["kind"] == "end"
    closed = (
        footer
        and not tail
        and rows[-1]["data"].get("normal_return") is True
        and rows[-1]["data"].get("incomplete") is False
    )
    if complete:
        assert (
            closed
            and rows[-1]["data"]["normal_return"] is True
            and rows[-1]["data"]["incomplete"] is False
        )
    intents, facts = {}, {}
    for row in rows[1:-1] if footer else rows[1:]:
        data = row["data"]
        if row["kind"] == "intent":
            assert data["span_id"] not in intents
            intents[data["span_id"]] = data
        else:
            assert row["kind"] == "span" and data["span_id"] in intents
            intent = intents.pop(data["span_id"])
            assert all(
                data[k] == intent[k]
                for k in (
                    "span_id",
                    "parent_id",
                    "phase",
                    "event_kind",
                    "event_seq",
                    "operation",
                )
            )
            assert (
                data["outcome"] in ("returned", "raised")
                and data["native_tid"] == identity["native_tid"]
            )
            timing = {}
            for name, start, end in (
                ("wall_ns", "start_ns", "end_ns"),
                ("process_cpu_ns", "process_cpu_start_ns", "process_cpu_end_ns"),
                ("thread_cpu_ns", "thread_cpu_start_ns", "thread_cpu_end_ns"),
            ):
                assert (
                    type(data[start]) is int
                    and type(data[end]) is int
                    and 0 <= data[start] <= data[end]
                )
                timing[name] = data[end] - data[start]
            group = facts.setdefault(
                data["phase"],
                dict(
                    count=0, wall_ns=0, process_cpu_ns=0, thread_cpu_ns=0, max_wall_ns=0
                ),
            )
            group["count"] += 1
            for name in timing:
                group[name] += timing[name]
            group["max_wall_ns"] = max(group["max_wall_ns"], timing["wall_ns"])
    if complete:
        assert not intents
    return dict(
        scope="inclusive_actual_spans_not_additive",
        complete=closed and not intents,
        phases=facts,
        unfinished_spans=len(intents),
        partial_tail_bytes=len(tail),
        partial_tail_sha256=accounting.sha256(tail) if tail else None,
    )


def evaluate_observer_originals(artifacts, expected):
    """Re-decode original pinned bytes; stored evaluation never supplies authority."""
    from dataclasses import fields
    from azazel_edge.outcome.input_control_stop import ObserverControlStop
    from signed_network_recording import decode_calls
    from signed_network_clock import qualify_clock

    result = dict(
        status="withheld",
        normal_completion=None,
        fault_verified=None,
        clock=None,
        phase=None,
        error=None,
    )

    def original(name):
        raw = artifacts[name]
        assert type(raw) is bytes and accounting.sha256(raw) == expected[name], (
            name + ": original pin missing/differs"
        )
        return raw

    def data(name):
        raw = original(name)
        value = json.loads(raw)
        assert accounting.canonical(value) == raw
        return value

    try:
        assert set(artifacts) == set(expected) == FILES
        controller = data("load-controller.json")
        arm, observer = controller["case_id"], controller["observer"]
        if arm == "load-off":
            assert observer is None and all(
                artifacts[k] is None and expected[k] is None
                for k in FILES
                if k.startswith("observer-")
            )
            result["status"] = "absent"
            return result
        assert (
            arm in ("load-on", "load-faulted")
            and type(observer) is dict
            and observer["error"] is None
        )
        config = data("observer-config.json")
        assert (
            config["case_id"] == arm
            and config["protocol_sha256"]
            == controller["protocol_sha256"]
            == PROTOCOL_SHA256
        )
        assert (
            config["corpus_sha256"] == controller["corpus_sha256"]
            and config["registration_sha256"]
            == accounting.sha256(original("registration.json"))
            and config["trust_sha256"] == accounting.sha256(original("trust.json"))
        )
        identity, actor = observer["identity"], observer["actor"]
        assert observer["command_verified"] is True and observer["bootstrap"][
            "pid"
        ] == identity["pid"] == actor["pid"] == int(
            observer["unit_properties"]["MainPID"]
        )
        assert (
            observer["bootstrap"]["challenge"] == observer["challenge"]
            and observer["bootstrap"]["invocation_id"]
            == observer["unit_properties"]["InvocationID"]
        )
        assert (
            actor["uid"] == actor["gid"] == 61002
            and actor["no_new_privs"] is True
            and actor["apparmor_label"] == "edge400-observer (enforce)"
        )
        assert (
            actor["cap_eff"]
            == actor["cap_prm"]
            == actor["cap_bnd"]
            == actor["cap_amb"]
            == 0
        )
        assert identity["start_ticks"] == actor["start_ticks"] > 0
        for key, filename in SIDE_FILES.items():
            meta = observer["sidecars"][key]
            if artifacts[filename] is None:
                assert expected[filename] is None and meta is None
                continue
            raw = original(filename)
            assert (
                meta["before"] == meta["after"]
                and meta["size"] == len(raw) == meta["before"]["size"]
                and meta["sha256"] == accounting.sha256(raw)
            )
            assert meta["before"]["owner_uid"] == 61002
        original("observer-stdout.raw")
        original("observer-stderr.raw")
        assert not observer["stdout_truncated"] and not observer["stderr_truncated"]
        assert (
            observer["stdout_eof"] is True
            and observer["stderr_eof"] is True
            and observer["drain_errors"] == []
        )
        assert observer["stdout_bytes"] == len(
            artifacts["observer-stdout.raw"]
        ) and observer["stderr_bytes"] == len(artifacts["observer-stderr.raw"])
        assert observer["signal_target"] == actor
        assert (
            observer["started_ns"]
            <= observer["ready_ns"]
            <= observer["stop_requested_ns"]
            <= observer["finished_ns"]
        )
        assert int(observer["exit"]["ExecMainPID"]) == actor["pid"]
        result["phase"] = _phase_facts(
            original("observer-phase.raw"),
            metadata=config["metadata"],
            identity=identity,
            complete=arm == "load-on",
        )
        if arm == "load-faulted":
            assert (
                observer["signal"] == 9
                and observer["exit"]["ExecMainCode"] == "2"
                and observer["exit"]["ExecMainStatus"] == "9"
            )
            assert artifacts["observer-completion.json"] is None
            result["normal_completion"] = False
            result["fault_verified"] = False
            _verify_fault_boundary(controller, observer, original)
            result["fault_verified"] = True
            return result
        assert (
            observer["signal"] == 15
            and observer["runner_returncode"] == 0
            and observer["exit"]["ExecMainCode"] == "1"
            and observer["exit"]["ExecMainStatus"] == "0"
        )
        completion = data("observer-completion.json")
        assert (
            completion["schema_version"] == "edge-observer-normal-stop-completion/v1"
            and completion["identity"] == identity
            and completion["metadata"] == config["metadata"]
        )
        control = completion["control_stop"]
        genuine = ObserverControlStop(
            **{f.name: control[f.name] for f in fields(ObserverControlStop)}
        )
        assert genuine.to_dict() == control
        trust = json.loads(original("trust.json"))
        assert (
            control["scope_ref"] == trust["scope_ref"]
            and control["trust_sha256"] == config["trust_sha256"]
            and control["journal_boot_id"] == identity["boot_id"]
        )
        journal = original("observer-journal.raw")
        assert len(journal) == control["journal_bytes_after"]
        last = json.loads(journal.splitlines()[-1])
        assert last["seq"] == control["journal_sequence_after"]
        assert (
            last["sha256"] == control["journal_head_after"]
            and last["kind"] == "session_close"
        )
        previous = "0" * 64
        journal_rows = []
        for seq, line in enumerate(journal.splitlines(keepends=True), 1):
            row = json.loads(line)
            assert (
                set(row) == {"seq", "prev", "kind", "data", "sha256"}
                and accounting.canonical(row) == line
            )
            assert row["seq"] == seq and row["prev"] == previous
            unsigned = {k: v for k, v in row.items() if k != "sha256"}
            assert row["sha256"] == accounting.sha256(
                accounting.canonical(unsigned).rstrip(b"\n")
            )
            previous = row["sha256"]
            journal_rows.append(row)
        assert journal_rows[0]["kind"] == "header"
        positions = [
            row["data"]["position"] for row in journal_rows if row["kind"] == "cursor"
        ]
        assert positions and positions[-1] == control["input_position_after"]
        source = original("source-after.raw")
        assert (
            control["input_offset"] <= len(source)
            and accounting.sha256(source[: control["input_offset"]])
            == control["input_sha256"]
        )
        from azazel_edge.outcome.telemetry import (
            OutcomeTelemetryPolicy,
            persistence_context,
        )

        policy_value = json.loads(original("observer-policy.json"))
        policy = OutcomeTelemetryPolicy.from_mapping(
            policy_value, source_ref=config["paths"]["policy"]
        )
        assert completion["policy_context"] == dict(
            policy_sha256=accounting.sha256(
                accounting.canonical(policy_value).rstrip(b"\n")
            ),
            policy_source_ref=config["paths"]["policy"],
            policy_ref=policy.policy_ref,
        )
        assert control["journal_policy_sha256"] == accounting.sha256(
            persistence_context(policy, "lo", 0.05).encode()
        )
        for key in ("phase", "calls", "context"):
            raw = original(SIDE_FILES[key])
            assert completion["sidecars"][key] == dict(
                bytes=len(raw), sha256=accounting.sha256(raw)
            )
        calls = decode_calls(original("observer-calls.raw"))
        contexts = _rows(
            original("observer-context.raw"),
            "edge-load-clock-context/v1",
            limit=16384,
            max_rows=2,
        )
        assert (
            len(contexts) == 2
            and contexts[0]["kind"] == "begin"
            and contexts[1]["kind"] == "end"
            and contexts[1]["data"]["normal_return"] is True
        )
        assert (
            contexts[0]["data"]["identity"] == identity
            and contexts[0]["data"]["metadata"] == config["metadata"]
        )
        result["normal_completion"] = True
        root = controller["controller_identity"]
        assert (
            identity["clock_domain"]["established"] is True
            and root["clock_domain"]["established"] is True
            and identity["clock_domain"] == root["clock_domain"]
        )
        anchors = controller["controller_anchors"]
        result["clock"] = qualify_clock(
            kernel_boot_id=json.loads(original("close-controller.json"))["boot_id"],
            observer_boot_id=identity["boot_id"],
            controller_boot_id=root["boot_id"],
            observer_start=contexts[0]["data"]["anchor"],
            observer_end=contexts[1]["data"]["anchor"],
            controller_start=anchors["before"],
            controller_end=anchors["after"],
            recorded=calls,
        )
        if result["clock"]["status"] == "qualified":
            result["status"] = "qualified"
    except (
        AssertionError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        IndexError,
        OverflowError,
    ) as error:
        result["error"] = error_value(error)
    return result


def _verify_fault_boundary(controller, observer, original):
    from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
    from azazel_edge.benchmark.source_witness import _source_tips, _verify_anchors

    boundary = observer["fault_boundary"]
    assert set(boundary) == {
        "observed_ns",
        "source_checkpoint",
        "cursor_position",
        "journal_checkpoint",
        "witness_sha256",
        "witness_boundary",
    }
    writer = controller["writer"]
    assert (
        writer["marker_one_before_ns"]
        <= boundary["observed_ns"]
        <= observer["stop_requested_ns"]
        < writer["first_write_before_ns"] + 6_000_000_000
    )
    policy = TrustPolicy(json.loads(original("trust.json")))
    source = original("source-after.raw")
    SourceVerifier(policy).verify(source)
    tip = boundary["source_checkpoint"]
    assert SourceVerifier(policy).verify(source[: tip["size"]]) == tip
    selected = [
        json.loads(line)["event"]
        for line in source[: tip["size"]].splitlines()
        if json.loads(line)["event"].get("capture_origin", {}).get("session_ref")
        == controller["session_ref"]
        and "normalized" in json.loads(line)["event"]
    ]
    assert [e["normalized"]["sid"] for e in selected] == [90232001]
    marker = materialize_corpus()[1]["markers"][0]
    origin = selected[0]["ingress_origin"]
    assert origin["range_ref"] == controller["session_ref"] and all(
        origin[k] == marker[k] for k in ("start_offset", "end_offset", "raw_sha256")
    )
    position = boundary["cursor_position"]
    assert position == dict(offset=tip["size"], sha256=tip["sha256"])
    journal = original("observer-journal.raw")
    checkpoint = boundary["journal_checkpoint"]
    assert 0 < checkpoint["size"] <= len(journal)
    prefix = journal[: checkpoint["size"]]
    assert prefix.endswith(b"\n") and accounting.sha256(prefix) == checkpoint["sha256"]
    previous = "0" * 64
    rows = []
    for seq, line in enumerate(prefix.splitlines(keepends=True), 1):
        row = json.loads(line)
        assert (
            accounting.canonical(row) == line
            and row["seq"] == seq
            and row["prev"] == previous
        )
        assert row["sha256"] == accounting.sha256(
            accounting.canonical(
                {k: v for k, v in row.items() if k != "sha256"}
            ).rstrip(b"\n")
        )
        previous = row["sha256"]
        rows.append(row)
    assert rows[0]["kind"] == "header"
    assert any(
        r["kind"] == "cursor" and r["data"]["position"] == position for r in rows
    )
    anchors = original("observer-fault-anchors.raw")
    assert (
        len(anchors) <= 8 * 1024 * 1024
        and accounting.sha256(anchors) == boundary["witness_sha256"]
    )
    witness = boundary["witness_boundary"]
    st, at = witness["source_checkpoint"], witness["anchor_checkpoint"]
    assert accounting.witness_boundary(anchors) == witness and st["size"] >= tip["size"]
    assert _verify_anchors(policy, anchors, _source_tips(source), st) == at
    state = json.loads(anchors.splitlines()[-1])["state"]
    assert (
        state["journal_size"] <= len(prefix)
        and accounting.sha256(prefix[: state["journal_size"]])
        == state["journal_sha256"]
    )
    assert state["journal_seq"] >= next(
        r["seq"]
        for r in rows
        if r["kind"] == "cursor" and r["data"]["position"] == position
    )


def finish(g):
    """Close only this flavor's clean disposable lab; preserve all Source bytes."""
    from azazel_edge.outcome.input_auth import SourceVerifier

    before = g.source()
    verifier = SourceVerifier(g.fixture().p)
    tip = verifier.verify(before)
    assert verifier.live_state.closed is True, (
        "finite load finish requires clean Source history"
    )
    g.systemctl("disable", g.UNIT)
    g.systemctl("stop", g.UNIT, g.WITNESS)
    assert not g.Systemd().cores(), "native core remains after finite load teardown"
    for unit in (g.UNIT, g.WITNESS):
        state = g.systemctl(
            "show", unit, "--property=ActiveState", "--value"
        ).stdout.strip()
        assert state in ("inactive", "failed"), (unit, state)
    observers = g.systemctl(
        "list-units",
        "--all",
        "--no-legend",
        "--plain",
        "--no-pager",
        "edge400-load-observer-*.service",
    ).stdout
    assert len(observers.encode()) <= 65536, "owned observer inventory exceeds bound"
    for line in observers.splitlines():
        unit = line.split()[0]
        assert re.fullmatch(r"edge400-load-observer-[0-9a-f]{32}\.service", unit)
        properties = g.systemctl(
            "show", unit, "--property=MainPID", "--property=ActiveState"
        ).stdout
        values = dict(
            part.split("=", 1) for part in properties.splitlines() if "=" in part
        )
        assert values["MainPID"] == "0" and values["ActiveState"] in (
            "inactive",
            "failed",
        ), "owned observer remains live"
    after = g.source()
    assert after == before, "finite load teardown changed Source"
    final = SourceVerifier(g.fixture().p)
    assert final.verify(after) == tip and final.live_state.closed is True
    g.record(
        "finite-load-finished-disabled-retained-clean-history",
        source_sha256=accounting.sha256(before),
        source_checkpoint=tip,
        source_closed=True,
        active_native_cores=0,
        live_owned_observers=0,
    )
