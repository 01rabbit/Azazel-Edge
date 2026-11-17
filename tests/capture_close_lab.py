"""Finite TEST memfd mutator and separately executed read-only collector."""

import argparse
import fcntl
import hashlib
import json
import mmap
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = ROOT / "tests/fixtures/capture-close/v1/protocol.json"
PROTOCOL_SHA256 = "d89e6e78266cbe6af7cc0f24a8b78ce7560d98da3eeadc6ab3c1acdd7931620b"
CASES = ("clean", "explicit_loss", "abrupt_writer", "missing_loss_counter", "late_bypass", "seal_busy")
LIMIT = 1024 * 1024


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def new_gate_token():
    return secrets.token_hex(32)


def footer_ack_receipt(ack, started_ns, finished_ns):
    if ack is None:
        return None
    return dict(started_ns=started_ns, finished_ns=finished_ns, footer_sha256=ack["footer_sha256"])


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def boundary():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    caps = {name: status[name].strip() for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}
    if os.geteuid() == 0 or any(int(value, 16) for value in caps.values()) or status["NoNewPrivs"].strip() != "1":
        raise ValueError("ordinary UID, zero capabilities and NNP required")
    return dict(uid=os.geteuid(), gid=os.getegid(), groups=os.getgroups(), capabilities=caps, no_new_privileges=1)


def actor_identity(pid):
    base = Path("/proc") / str(pid)
    raw = (base / "stat").read_text()
    start = int(raw[raw.rfind(")") + 2:].split()[19])
    status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines() if ":" in line)
    namespace = (base / "ns/time").stat()
    offsets = []
    for line in (base / "timens_offsets").read_text().splitlines():
        clock, seconds, nanoseconds = line.split()
        offsets.append(dict(clock=clock, seconds=int(seconds), nanoseconds=int(nanoseconds)))
    domain = dict(time_namespace_device=namespace.st_dev, time_namespace_inode=namespace.st_ino,
                  timens_offsets=offsets, established={row["clock"] for row in offsets} == {"monotonic", "boottime"}
                  and all(row["seconds"] == row["nanoseconds"] == 0 for row in offsets))
    return dict(pid=pid, uid=int(status["Uid"].split()[0]), process_start_ticks=start,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(), clock_domain=domain)


def object_identity(fd):
    info = os.fstat(fd)
    return dict(device=info.st_dev, inode=info.st_ino, owner_uid=info.st_uid)


class AdmissionGate:
    """Trusted controller-only finite gate; never an upstream production count."""

    def __init__(self, plan, enrollment_closed):
        self.gate_id, self.token = plan["gate_id"], plan["gate_token"]
        self.enrollment_closed = enrollment_closed
        self.lock = threading.Lock()
        self.closed = False
        self.attempts = {row["id"]: dict(id=row["id"], decision="not_attempted",
            attempt_started_ns=None, attempt_finished_ns=None) for row in plan["attempts"]}
        self.C = None

    def attempt(self, identifier, gate_id, token):
        with self.lock:
            if not self.enrollment_closed():
                raise RuntimeError("admission before closed enrollment")
            if (gate_id, token) != (self.gate_id, self.token) or identifier not in self.attempts:
                raise ValueError("wrong gate/token/attempt")
            if self.attempts[identifier]["decision"] != "not_attempted":
                raise ValueError("duplicate finite attempt")
            start = time.monotonic_ns()
            admitted = not self.closed
            self.attempts[identifier] = dict(id=identifier, decision="admitted" if admitted else "rejected_closed",
                attempt_started_ns=start, attempt_finished_ns=time.monotonic_ns())
            return admitted

    def close(self, gate_id, token):
        with self.lock:
            if (gate_id, token) != (self.gate_id, self.token) or self.closed:
                raise ValueError("wrong or repeated gate close")
            start = time.monotonic_ns()
            self.closed = True
            self.C = dict(started_ns=start, finished_ns=time.monotonic_ns(), gate_id=self.gate_id,
                gate_token=self.token, admitted_ids=[identifier for identifier, row in self.attempts.items() if row["decision"] == "admitted"])
            return self.C


class SourceFrames:
    """Pinned synchronous append-only TEST frames; counters are claims to replay."""

    def __init__(self, fd, run_id, capture_id, case_id):
        self.fd, self.run_id, self.capture_id, self.case_id = fd, run_id, capture_id, case_id
        self.previous, self.last_seq, self.records = "0" * 64, None, 0

    def append(self, row):
        raw = wire(row)
        view = memoryview(raw)
        while view:
            written = os.write(self.fd, view)
            if written <= 0:
                raise OSError("capture write made no progress")
            view = view[written:]
        self.previous = sha(raw)
        return raw

    def data(self, job):
        if self.case_id == "explicit_loss" and job["id"] == "a07":
            return
        self.append(dict(schema_version="edge-capture-close-frame/v1", kind="data", run_id=self.run_id,
            capture_id=self.capture_id, attempt_id=job["id"], seq=job["seq"], payload_hex=job["payload_hex"],
            prev_sha256=self.previous))
        self.last_seq, self.records = job["seq"], self.records + 1

    def terminal(self):
        lost = ["a07"] if self.case_id == "explicit_loss" else []
        row = dict(schema_version="edge-capture-close-frame/v1", kind="terminal", run_id=self.run_id,
            capture_id=self.capture_id, last_seq=self.last_seq, declared_records=self.records,
            declared_lost=len(lost), lost_ids=lost, prev_sha256=self.previous)
        if self.case_id == "missing_loss_counter":
            del row["declared_lost"]
        return self.append(row)


def receive_command():
    raw = sys.stdin.buffer.readline(65537)
    if not raw or len(raw) > 65536 or not raw.endswith(b"\n"):
        raise ValueError("missing/overbound control command")
    result = json.loads(raw)
    if type(result) is not dict:
        raise ValueError("control object required")
    return result


def reply(value):
    sys.stdout.buffer.write(wire(value))
    sys.stdout.buffer.flush()


def source_worker(fd):
    boundary()
    reply(dict(kind="blocked", role="source", pid=os.getpid()))
    job = receive_command()
    if job.get("command") != "start" or job.get("case_id") not in CASES:
        raise ValueError("source start not enrolled")
    frames = SourceFrames(fd, job["run_id"], job["capture_id"], job["case_id"])
    jobs = job["jobs"]
    if len(jobs) != 16 or [row["id"] for row in jobs] != [f"a{index:02}" for index in range(16)]:
        raise ValueError("fixed source jobs differ")
    for row in jobs[:8]:
        frames.data(row)
    reply(dict(kind="prefix", role="source", pid=os.getpid()))
    drained = False
    while True:
        command = receive_command()
        if command.get("command") == "drain":
            if drained or job["case_id"] == "abrupt_writer":
                raise ValueError("unexpected drain")
            for row in jobs[8:]:
                frames.data(row)
            drained = True
            reply(dict(kind="drained"))
        elif command.get("command") == "bypass":
            if job["case_id"] != "late_bypass" or not drained:
                raise ValueError("unexpected bypass")
            frames.data(command["job"])
            reply(dict(kind="bypass_appended"))
        elif command.get("command") == "finish":
            if job["case_id"] == "abrupt_writer":
                os._exit(7)
            if not drained:
                raise ValueError("finish before drain")
            raw = frames.terminal()
            reply(dict(kind="footer", footer_sha256=sha(raw)))
            return
        else:
            raise ValueError("unknown source control")


def collector_worker(fd, output):
    boundary()
    reply(dict(kind="blocked", role="collector", pid=os.getpid()))
    command = receive_command()
    if command.get("command") != "collect":
        raise ValueError("collector GO missing")
    from azazel_edge.benchmark.capture_close_collection import collect_sealed_fd
    result = collect_sealed_fd(fd, expected_identity=command["object_identity"], maximum=LIMIT)
    save(output / "capture.raw", result["raw"])
    save(output / "collector.json", wire(result["receipt"]))
    reply(dict(kind="collected"))


class Actor:
    """One owned child with bounded concurrent control/stdout/stderr draining."""

    def __init__(self, role, fd, output, *, registry=None):
        environment = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "py"), str(ROOT / "tests")]),
                           PYTHONDONTWRITEBYTECODE="1")
        command = [sys.executable, str(Path(__file__).resolve()), "--role", role, "--fd", str(fd)]
        if role == "collector":
            command += ["--output", str(output)]
        self.role = role
        self.buffers = dict(stdout=bytearray(), stderr=bytearray())
        self.observed = dict(stdout=0, stderr=0)
        self.pending = bytearray()
        self.closed = False
        self.cleanup_errors = {}
        self.selector = selectors.DefaultSelector()
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=(fd,), env=environment, close_fds=True)
        except BaseException:
            self.selector.close()
            raise
        if registry is not None:
            registry.append(self)  # Own the child BEFORE any fallible registration.
        try:
            for name in self.buffers:
                pipe = getattr(self.process, name)
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, name)
        except BaseException:
            self.cleanup()
            raise

    def send(self, command):
        raw = wire(command)
        if len(raw) > 65536:
            raise ValueError("control command overbound")
        self.process.stdin.write(raw)
        self.process.stdin.flush()

    def pump(self, timeout=0.1):
        for key, _ in self.selector.select(timeout=timeout):
            try:
                raw = os.read(key.fd, 4096)
            except BlockingIOError:
                continue
            if not raw:
                self.selector.unregister(key.fileobj)
                continue
            name = key.data
            self.observed[name] += len(raw)
            room = 65536 - len(self.buffers[name])
            self.buffers[name].extend(raw[:max(0, room)])
            if name == "stdout":
                if len(self.pending) + len(raw) > 65536:
                    raise ValueError("actor response overbound")
                self.pending.extend(raw)

    def receive(self, kind):
        deadline = time.monotonic() + 30
        while True:
            end = self.pending.find(b"\n")
            if end >= 0:
                raw = bytes(self.pending[:end + 1])
                del self.pending[:end + 1]
                result = json.loads(raw)
                if result.get("kind") != kind:
                    raise ValueError("actor response kind differs")
                return result
            if time.monotonic() >= deadline:
                raise TimeoutError("actor response watchdog")
            if not self.selector.get_map():
                raise EOFError("actor exited before response")
            self.pump()

    def wait(self):
        started = time.monotonic_ns()
        deadline = time.monotonic() + 30
        while self.process.poll() is None and time.monotonic() < deadline:
            self.pump()
        if self.process.poll() is None:
            raise TimeoutError("owned actor wait watchdog")
        result = self.process.wait(timeout=1)
        while self.selector.get_map() and time.monotonic() < deadline:
            self.pump()
        return started, time.monotonic_ns(), result

    def cleanup(self):
        if self.closed:
            return

        def attempt(name, function):
            try:
                return function()
            except Exception as exc:
                self.cleanup_errors[name] = dict(type=type(exc).__name__, errno=getattr(exc, "errno", None))
                return None

        if self.process.poll() is None:
            attempt("kill", self.process.kill)
            attempt("wait", lambda: self.process.wait(timeout=30))
        def drain():
            for _ in range(20):
                if not self.selector.get_map():
                    break
                self.pump(timeout=0.01)
        attempt("drain", drain)
        self.closed = True  # Never retry descriptor numbers after close errors.
        attempt("selector_close", self.selector.close)
        for name in ("stdin", "stdout", "stderr"):
            attempt(name + "_close", getattr(self.process, name).close)

    def export(self, output):
        for name, raw in self.buffers.items():
            save(output / (self.role + "-" + name + ".raw"), bytes(raw))


def read_closed(path):
    import stat
    before = Path(path).lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        def version(info):
            return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns
        if not stat.S_ISREG(opened.st_mode) or not 0 <= opened.st_size <= LIMIT or version(before) != version(opened):
            raise ValueError("unsafe/overbound original")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) != opened.st_size or version(os.fstat(fd)) != version(opened) or version(Path(path).lstat()) != version(opened):
            raise ValueError("original changed while reading")
        return raw
    finally:
        os.close(fd)


def collect_case(outputdir, case_id, *, run_id, source_inventory_sha256):
    """One fresh finite object; no old Source/evaluator or authority changes."""
    if case_id not in CASES or sys.platform != "linux":
        raise ValueError("fixed Linux capture case required")
    output = Path(outputdir)
    own_boundary = boundary()
    errors, actors = {}, []
    writer = collector = gate = None
    wfd = rofd = None
    busy_mapping = None
    plan = enrollment = admission = terminal = None
    enrollment_closed = False
    safe = False
    controller = actor_identity(os.getpid())
    capture_id = "capture-" + uuid.uuid4().hex
    gate_id, token = "gate-" + uuid.uuid4().hex, new_gate_token()
    stage_facts = {}

    def stage(name, function):
        try:
            return function()
        except Exception as exc:
            errors[name] = dict(type=type(exc).__name__, errno=getattr(exc, "errno", None))
            return None

    def persist(name, value):
        if value is not None:
            stage("save_" + name, lambda: save(output / (name + ".json"), wire(value)))

    try:
        if sha(read_closed(PROTOCOL_PATH)) != PROTOCOL_SHA256:
            raise ValueError("frozen protocol changed")
        wfd = os.memfd_create("finite-controller-test-capture", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        held = object_identity(wfd)
        rofd = os.open(f"/proc/self/fd/{wfd}", os.O_RDONLY | os.O_CLOEXEC)
        if object_identity(rofd) != held or fcntl.fcntl(rofd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY:
            raise ValueError("read-only enrollment descriptor differs")
        writer = Actor("source", wfd, output, registry=actors)
        collector = Actor("collector", rofd, output, registry=actors)
        for actor in actors:
            blocked = actor.receive("blocked")
            if blocked.get("pid") != actor.process.pid or blocked.get("role") != actor.role:
                raise ValueError("actor blocked handshake identity differs")
        writer_identity, collector_identity = actor_identity(writer.process.pid), actor_identity(collector.process.pid)
        ids = [f"a{index:02}" for index in range(16)] + ["late0", "late1"]
        payloads = {identifier: wire(dict(data_kind="PREREGISTERED_TEST_FRAME", run_id=run_id,
            capture_id=capture_id, attempt_id=identifier)) for identifier in ids}
        attempts = [dict(id=identifier, seq=index, payload_sha256=sha(payloads[identifier]),
            payload_bytes=len(payloads[identifier]), phase="pre_C" if index < 16 else "late") for index, identifier in enumerate(ids)]
        jobs = {identifier: dict(id=identifier, seq=index, payload_hex=payloads[identifier].hex()) for index, identifier in enumerate(ids)}
        plan = dict(schema_version="edge-capture-close-plan/v1", run_id=run_id, capture_id=capture_id, case_id=case_id,
            protocol_sha256=PROTOCOL_SHA256, source_inventory_sha256=source_inventory_sha256,
            controller_identity=controller, writer_identity=writer_identity, collector_identity=collector_identity,
            object_identity=held, gate_id=gate_id, gate_token=token, attempts=attempts, maximum_bytes=LIMIT)
        save(output / "plan.json", wire(plan))  # Closed BEFORE fresh readback and any gate attempt.
        began = time.monotonic_ns()
        plan_raw, inventory_raw = read_closed(output / "plan.json"), read_closed(output / "source-inventory.json")
        if plan_raw != wire(plan) or sha(inventory_raw) != source_inventory_sha256:
            raise ValueError("closed enrollment originals differ")
        if (actor_identity(writer.process.pid) != writer_identity or actor_identity(collector.process.pid) != collector_identity
                or actor_identity(os.getpid()) != controller or object_identity(wfd) != held or object_identity(rofd) != held
                or writer.process.poll() is not None or collector.process.poll() is not None):
            raise ValueError("kernel enrollment changed before admission")
        enrollment = dict(schema_version="edge-capture-close-enrollment/v1", plan_sha256=sha(plan_raw),
            source_inventory_sha256=sha(inventory_raw), controller_identity=controller, writer_identity=writer_identity,
            collector_identity=collector_identity, object_identity=held, started_ns=began, finished_ns=time.monotonic_ns(),
            plan_bytes_read=len(plan_raw), source_inventory_bytes_read=len(inventory_raw))
        save(output / "enrollment.json", wire(enrollment))
        enrollment_closed = True
        gate = AdmissionGate(plan, lambda: enrollment_closed)
        for identifier in ids[:16]:
            if not gate.attempt(identifier, gate_id, token):
                raise ValueError("pre-close admission refused")
        stage("source_start", lambda: writer.send(dict(command="start", run_id=run_id, capture_id=capture_id,
            case_id=case_id, jobs=[jobs[identifier] for identifier in ids[:16]])))
        stage("source_prefix", lambda: writer.receive("prefix"))
        C = gate.close(gate_id, token)
        late_controls = []
        for identifier in ids[16:]:
            before_poll = time.monotonic_ns()
            before_return = writer.process.poll()
            started = time.monotonic_ns()
            if gate.attempt(identifier, gate_id, token):
                raise ValueError("closed gate admitted late control")
            finished = time.monotonic_ns()
            after_return = writer.process.poll()
            after_poll = time.monotonic_ns()
            late_controls.append(dict(id=identifier, gate_id=gate_id, gate_token=token,
                started_ns=started, finished_ns=finished, poll_before_ns=before_poll,
                poll_after_ns=after_poll, poll_before_returncode=before_return, poll_after_returncode=after_return))
        admission = dict(schema_version="edge-capture-close-admission/v1", run_id=run_id, capture_id=capture_id,
            controller_identity=controller, gate_id=gate_id, gate_token=token,
            attempts=list(gate.attempts.values()), C=C, late_controls=late_controls)
        save(output / "admission.json", wire(admission))
        if case_id != "abrupt_writer":
            stage("source_drain_send", lambda: writer.send(dict(command="drain")))
            stage("source_drain_ack", lambda: writer.receive("drained"))
        if case_id == "late_bypass":
            stage_facts["bypass_started_ns"] = time.monotonic_ns()
            stage("source_bypass_send", lambda: writer.send(dict(command="bypass", job=jobs["late0"])))
            stage("source_bypass_ack", lambda: writer.receive("bypass_appended"))
            stage_facts["bypass_finished_ns"] = time.monotonic_ns()
        stage("finish_permit", lambda: writer.send(dict(command="finish")))
        d_start = time.monotonic_ns()
        ack = stage("terminal_ack", lambda: writer.receive("footer"))
        d_finished = time.monotonic_ns()
        stage_facts["footer_ack_read"] = dict(started_ns=d_start, finished_ns=d_finished,
            acknowledgment_received=ack is not None, error=errors.get("terminal_ack"))
        D = footer_ack_receipt(ack, d_start, d_finished)
        w_start = time.monotonic_ns()
        waited = stage("writer_wait", writer.wait)
        if waited is None:
            stage("writer_forced_cleanup", writer.cleanup)
        W = dict(started_ns=w_start, finished_ns=time.monotonic_ns(), pid=writer.process.pid,
                 process_start_ticks=writer_identity["process_start_ticks"],
                 returncode=writer.process.returncode, waited=writer.process.returncode is not None)
        S = None
        if writer.process.returncode is not None:
            if case_id == "seal_busy":
                busy_mapping = mmap.mmap(wfd, 0, flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE)
            seals_before = fcntl.fcntl(wfd, fcntl.F_GET_SEALS)
            seal_started = time.monotonic_ns()
            seal_error, seal_result = None, "sealed"
            try:
                fcntl.fcntl(wfd, fcntl.F_ADD_SEALS, 15)
            except OSError as exc:
                seal_error, seal_result = exc.errno, "failed"
            seal_finished = time.monotonic_ns()
            S = dict(started_ns=seal_started, finished_ns=seal_finished, result=seal_result, errno=seal_error,
                seals_before=seals_before, seals_after=fcntl.fcntl(wfd, fcntl.F_GET_SEALS), object_identity=object_identity(wfd))
        post = dict(attempted=False, started_ns=None, finished_ns=None, bytes_written=None, errno=None)
        if S is not None and S["result"] == "sealed":
            post.update(attempted=True, started_ns=time.monotonic_ns())
            try:
                post["bytes_written"] = os.write(wfd, b"POST_SEAL_CONTROL_MUST_REFUSE")
            except OSError as exc:
                post["errno"] = exc.errno
            post["finished_ns"] = time.monotonic_ns()
        terminal = dict(schema_version="edge-capture-close-terminal/v1", run_id=run_id, capture_id=capture_id,
            controller_identity=controller, writer_identity=writer_identity, D=D, W=W, S=S, post_seal_write=post)
        save(output / "terminal.json", wire(terminal))
        stage("collector_GO", lambda: collector.send(dict(command="collect", object_identity=held)))
        stage("collector_ack", lambda: collector.receive("collected"))
        stage("collector_wait", collector.wait)
    except Exception as exc:
        errors["case"] = dict(type=type(exc).__name__, errno=getattr(exc, "errno", None))
    finally:
        # Partial references are never replaced; preserve each available sibling.
        if admission is None and plan is not None and gate is not None:
            admission = dict(schema_version="edge-capture-close-admission/v1", run_id=run_id, capture_id=capture_id,
                controller_identity=controller, gate_id=gate_id, gate_token=token,
                attempts=list(gate.attempts.values()), C=gate.C, late_controls=[])
        for name, value in (("plan", plan), ("enrollment", enrollment), ("admission", admission), ("terminal", terminal)):
            if value is not None and not (output / (name + ".json")).exists():
                persist(name, value)
        for actor in actors:
            stage(actor.role + "_cleanup", actor.cleanup)
            stage(actor.role + "_logs", lambda actor=actor: actor.export(output))
        safe = all(actor.process.returncode is not None and not actor.cleanup_errors for actor in actors)
        if busy_mapping is not None:
            stage("mapping_cleanup", busy_mapping.close)  # AFTER collector; never retry sealing.
        for name, fd in (("read_only", rofd), ("writer_alias", wfd)):
            if fd is not None:
                stage(name + "_close", lambda fd=fd: os.close(fd))
    expected = {}
    for key, name in (("plan", "plan.json"), ("enrollment", "enrollment.json"), ("admission", "admission.json"),
                      ("terminal", "terminal.json"), ("collector", "collector.json"), ("capture", "capture.raw")):
        if (output / name).exists():
            raw = stage("closed_" + key, lambda name=name: read_closed(output / name))
            expected[key + "_sha256"] = sha(raw) if raw is not None else None
        else:
            expected[key + "_sha256"] = None
    state = dict(schema_version="edge-capture-close-lab-state/v1", case_id=case_id, run_id=run_id,
        capture_id=capture_id, boundary=own_boundary, errors=errors, safe_to_continue=safe, stage_facts=stage_facts,
        actors={actor.role: dict(pid=actor.process.pid, returncode=actor.process.returncode,
            observed_bytes=actor.observed, retained_bytes={name: len(raw) for name, raw in actor.buffers.items()},
            stream_truncated={name: actor.observed[name] > len(raw) for name, raw in actor.buffers.items()},
            cleanup_errors=actor.cleanup_errors) for actor in actors},
        expected=expected, old_evaluations_modified=False)
    save(output / "case-state.json", wire(state))
    return dict(expected=expected, safe_to_continue=safe, actorfacts=state["actors"], errors=errors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("source", "collector"), required=True)
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.role == "source":
        source_worker(args.fd)
    else:
        if args.output is None:
            raise ValueError("collector forensic directory required")
        collector_worker(args.fd, args.output)


if __name__ == "__main__":
    main()
