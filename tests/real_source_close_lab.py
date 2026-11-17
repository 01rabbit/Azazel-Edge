"""Actual original signed Source mechanics for declared SYNTHETIC test origin.

Controller/witness Root, producer1000, cursor observer65534, Source-only reader61002.
No native enrollment, runtime modifications, Source seals or permission relaxation.
"""

import argparse
from copy import deepcopy
import json
import os
from pathlib import Path
import secrets
import selectors
import subprocess
import sys
import time
import uuid

from capture_close_lab import Actor as DrainActor, AdmissionGate, actor_identity, object_identity, read_closed, sha, wire

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "tests/fixtures/real-source-close/v1/protocol.json"
PROTOCOL_SHA256 = "4b8c23e3adf2b3f082cad016c4270ba845b33aeb25cc36fc155813ae2e3dd3e0"
CASES = ("clean", "explicit_loss", "abrupt_writer")
RAW_FILES = {"trust": "trust.json", "source": "source.raw", "anchors": "anchors.raw", "plan": "plan.json",
    "controller": "controller.json", "read": "collection.json"}
ARG_FILES = {"source_arguments": "source-arguments.json", "witness_arguments": "witness-arguments.json"}
EXTRAS = ("prefix-source.raw", "prefix-anchors.raw", "journal.raw", "case-state.json",
    "producer-stdout.raw", "producer-stderr.raw", "observer-stdout.raw", "observer-stderr.raw",
    "collector-stdout.raw", "collector-stderr.raw")


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        os.fchmod(fd, 0o644)  # Only this freshly created copy/forensic output.
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def role_boundary():
    values = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    return dict(identity=actor_identity(os.getpid()), gid=os.getegid(), groups=os.getgroups(),
        capabilities={k: values[k].strip() for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        no_new_privileges=int(values["NoNewPrivs"].strip()))


def bind_child_identity(pid, declared, controller, *, expected_uid, proc_root=Path("/proc"), boot_path=Path("/proc/sys/kernel/random/boot_id")):
    """No cross-UID namespace lookup; pinned child's SELF domain is a premise."""
    proof = dict(basis="TRUSTED_LAUNCHER_PINNED_WORKER_SELF_READ",
        cross_uid_namespace_lookup="NOT_ATTEMPTED",
        precollection_probe=dict(condition="different_UID_ns_time_follow", errno=13, outcome="EACCES",
            source="HISTORICAL_LOCAL_FEATURE_PROBE", date="2026-11-17",
            environment="cached_service_tests_image_Linux6.8_NOT_FRESH_CASE_OR_CI_OBSERVATION"),
        matched=False, reasons=[])
    actual = dict(pid=pid, uid=None, process_start_ticks=None, boot_id=None, clock_domain=None)
    try:
        base = proc_root / str(pid)
        raw = (base / "stat").read_text()
        actual["process_start_ticks"] = int(raw[raw.rfind(")") + 2:].split()[19])
        status = dict(line.split(":", 1) for line in (base / "status").read_text().splitlines() if ":" in line)
        uids = [int(value) for value in status["Uid"].split()]
        if len(uids) != 4 or any(value != expected_uid for value in uids):
            raise ValueError("child UID incarnation differs")
        actual["uid"] = uids[0]
        actual["boot_id"] = boot_path.read_text().strip()
        offsets = []
        for line in (base / "timens_offsets").read_text().splitlines():
            clock, seconds, nanoseconds = line.split()
            offsets.append(dict(clock=clock, seconds=int(seconds), nanoseconds=int(nanoseconds)))
        if type(declared) is not dict or any(wire(declared.get(key)) != wire(actual[key]) for key in ("pid", "uid", "process_start_ticks", "boot_id")):
            raise ValueError("pinned child self identity differs from independent proc facts")
        domain = controller.get("clock_domain")
        if (type(domain) is not dict or domain.get("established") is not True
                or wire(declared.get("clock_domain")) != wire(domain)
                or wire(offsets) != wire(domain.get("timens_offsets"))):
            raise ValueError("child self domain or independently read offsets unavailable or mismatched")
        actual["clock_domain"] = deepcopy(domain)
        proof["matched"] = True
    except Exception as exc:
        proof["reasons"].append(dict(type=type(exc).__name__, errno=getattr(exc, "errno", None)))
    return dict(identity=actual, clock_provenance=proof)


def recipe(case_id, *, session, registration_sha256):
    """Prospective TEST recipes; omissions never repair an actual native stream."""
    protocol = json.loads(read_closed(PROTOCOL))
    result = []
    for row in protocol["event_plan"]:
        seq = row["native_seq_loss" if case_id == "explicit_loss" else "native_seq_clean"]
        kind = row["kind"]
        if kind == "decision_execution":
            event = deepcopy(protocol["decision_template"])
            event["enforcement"]["trace_id"] = "SYNTHETIC-" + case_id + "-" + row["id"]
        else:
            event = dict(pipeline="rust_live_origin_v1", source="capture_producer" if kind == "session_prepare" else "rust_core",
                capture_lifecycle=dict(state={"session_prepare": "prepare", "session_start": "start", "session_end": "end"}[kind]))
        event["capture_origin"] = dict(schema_version="outcome-registered-origin/v2", registration_sha256=registration_sha256,
            mode="live-core", session_ref=session, seq=seq, kind=kind)
        result.append(dict(id=row["id"], kind=kind, native_seq=seq, event=event))
    return result


def command():
    raw = sys.stdin.buffer.readline(65537)
    if not raw or len(raw) > 65536 or not raw.endswith(b"\n"):
        raise ValueError("missing or overbound control")
    result = json.loads(raw)
    if type(result) is not dict:
        raise ValueError("control object required")
    return result


def reply(value):
    sys.stdout.buffer.write(wire(value))
    sys.stdout.buffer.flush()


def producer_worker(policy_path, key_path, boot):
    from azazel_edge.outcome.input_auth import SignedCaptureWriter, TrustPolicy
    p = TrustPolicy.from_file(policy_path, role="producer")
    writer = SignedCaptureWriter(p, key_path, boot_ref=boot)
    close_attempted = False
    try:
        reply(dict(kind="blocked", boundary=role_boundary()))
        work = command()
        if work["command"] != "start" or work["case_id"] not in CASES or len(work["events"]) != 8:
            raise ValueError("fixed source recipe required")
        for row in work["events"][:4]:
            writer.append(row["event"])
        reply(dict(kind="prefix"))
        if command() != {"command": "finish"}:
            raise ValueError("finish permission required")
        if work["case_id"] == "abrupt_writer":
            os._exit(7)
        for row in work["events"][4:]:
            if work["case_id"] == "explicit_loss" and row["id"] == "a04":
                continue
            writer.append(row["event"])
        started = time.monotonic_ns()
        close_attempted = True
        writer.close()
        closed = dict(started_ns=started, finished_ns=time.monotonic_ns(), returned=True)
        source_path = Path(p.data["source_path"])
        before = read_closed(source_path)
        post = dict(attempted=True, started_ns=time.monotonic_ns(), finished_ns=None,
            outcome=None, exception_type=None, source_unchanged=None)
        try:
            writer.append(work["events"][-1]["event"])
            post["outcome"] = "returned"
        except Exception as exc:
            post.update(outcome="raised", exception_type=type(exc).__name__)
        post["finished_ns"] = time.monotonic_ns()
        post["source_unchanged"] = read_closed(source_path) == before
        reply(dict(kind="closed", writer_close=closed, post_close_append=post))
    finally:
        if not close_attempted and writer.fd is not None:
            close_attempted = True
            writer.close()


def collector_worker(fd, output):
    from azazel_edge.benchmark.real_source_close_collection import collect_regular_source_fd
    reply(dict(kind="blocked", boundary=role_boundary()))
    work = command()
    if work["command"] != "read":
        raise ValueError("read permission required")
    denied = []
    for path in work["private_probes"]:
        try:
            probe = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except PermissionError:
            denied.append(True)
        else:
            os.close(probe)  # Never read private bytes, even unexpected access.
            denied.append(False)
    result = collect_regular_source_fd(fd, expected_identity=work["expected_identity"])
    # Own forensic output only; never mutate the held Source descriptor.
    save(output / "source.raw", result["raw"])
    save(output / "collection.json", wire(result["receipt"]))
    reply(dict(kind="collected", private_probes_denied=denied))


class Actor(DrainActor):
    """Reuse bounded concurrent pipe drain/cleanup, with explicit existing roles."""
    def __init__(self, role, *, uid, registry, arguments=(), fd=None):
        self.role, self.closed, self.cleanup_errors = role, False, {}
        self.buffers, self.observed = dict(stdout=bytearray(), stderr=bytearray()), dict(stdout=0, stderr=0)
        self.pending, self.selector = bytearray(), selectors.DefaultSelector()
        argv = ["setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
            "--reuid=" + str(uid), "--regid=" + str(uid), "--clear-groups", sys.executable,
            str(Path(__file__).resolve()), "--role", role, *map(str, arguments)]
        if fd is not None:
            argv += ["--fd", str(fd)]
        try:
            self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, pass_fds=() if fd is None else (fd,),
                env=dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "py"), str(ROOT / "tests")]), PYTHONDONTWRITEBYTECODE="1"))
        except BaseException:
            self.selector.close()
            raise
        registry.append(self)
        try:
            for name in self.buffers:
                pipe = getattr(self.process, name)
                os.set_blocking(pipe.fileno(), False)
                self.selector.register(pipe, selectors.EVENT_READ, name)
        except BaseException:
            self.cleanup()
            raise

    def receive_any(self):
        deadline = time.monotonic() + 30
        while True:
            end = self.pending.find(b"\n")
            if end >= 0:
                raw = bytes(self.pending[:end + 1])
                del self.pending[:end + 1]
                return json.loads(raw)
            if not self.selector.get_map():
                raise EOFError("actor output ended")
            if time.monotonic() >= deadline:
                raise TimeoutError("actor response watchdog")
            self.pump()

    def receive(self, kind):
        value = self.receive_any()
        if value.get("kind") != kind:
            raise ValueError("actor response kind differs")
        return value


def context(policy, session, boot):
    result = {k: policy.data[k] for k in ("scope_ref", "producer_ref", "stream_ref", "producer_public_key",
        "witness_public_key", "producer_uid", "observer_uid")}
    return dict(result, registration_sha256=policy.data["origin_registration_sha256"], session_ref=session, boot_ref=boot)


def collect_case(outputdir, case_id, *, run_id, source_inventory_sha256):
    """One fresh original Fixture; save available originals before cleanup."""
    from test_outcome_input_auth_linux import Fixture
    from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
    from source_witness_data import anchor_checkpoint
    if os.geteuid() != 0 or case_id not in CASES:
        raise ValueError("existing Root fixture authority/fixed case required")
    output = Path(outputdir)
    errors, actors, boundaries = {}, [], {}
    fixture = None
    held_fd = None
    plan = controller = source_args = witness_args = None
    producer = collector = observer = None
    prefix_selected = final_selected = None
    own = actor_identity(os.getpid())
    session, capture_id, gate_id, token = secrets.token_hex(16), "source-" + uuid.uuid4().hex, "gate-" + uuid.uuid4().hex, secrets.token_hex(32)
    stage_facts = dict(artifact_export_origins={})
    witness_backend_errors = []
    clock_provenance = {}

    def attempt(name, fn):
        try:
            return fn()
        except Exception as exc:
            errors[name] = dict(type=type(exc).__name__, errno=getattr(exc, "errno", None))
            return None

    def snapshot(path, name, *, origin="ROOT_CONTROLLER_ORIGINAL_READ_COPY"):
        raw = read_closed(path)
        save(output / name, raw)
        stage_facts["artifact_export_origins"][name] = origin
        return raw

    try:
        if sha(read_closed(PROTOCOL)) != PROTOCOL_SHA256:
            raise ValueError("frozen protocol changed")
        fixture = Fixture()
        # Declared TEST registration only, same mechanism as actual_prefix fixture.
        registration = sha(wire(dict(kind="SYNTHETIC_DECLARED_REGISTRATION", run_id=run_id, capture_id=capture_id)))
        fixture.p = TrustPolicy(dict(fixture.p.data, schema_version="outcome-input-trust/v3", origin_registration_sha256=registration))
        fixture.policy_file.write_bytes(wire(dict(fixture.p.data)))
        trust = snapshot(fixture.policy_file, "trust.json")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
        expected_context = context(fixture.p, session, boot)
        events = recipe(case_id, session=session, registration_sha256=registration)
        held_fd = os.open(fixture.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        source_object = object_identity(held_fd)
        fixture.start(initialize=True)
        observer = Actor("observer", uid=65534, registry=actors, arguments=("--policy", fixture.policy_file))
        observer_notice = observer.receive("blocked")
        boundaries["observer"] = observer_notice["boundary"]
        observed_binding = bind_child_identity(observer.process.pid, observer_notice["boundary"]["identity"], own, expected_uid=65534)
        clock_provenance["observer"] = observed_binding
        if not observed_binding["clock_provenance"]["matched"]:
            raise ValueError("observer bootstrap domain/incarnation unqualified")
        initial = observer.receive_any()
        if initial.get("ready") is not True:
            raise ValueError("original cursor observer failed startup")
        producer = Actor("producer", uid=1000, registry=actors,
            arguments=("--policy", fixture.policy_file, "--key", fixture.pk, "--boot", boot))
        forensic = fixture.root / "collector-forensic"
        forensic.mkdir(mode=0o700)
        os.chown(forensic, 61002, 61002)
        collector = Actor("collector", uid=61002, registry=actors, fd=held_fd, arguments=("--output", forensic))
        # Collector writes only own preexisting forensic output directory, separate from Source.
        for actor in (producer, collector):
            notice = actor.receive("blocked")
            boundaries[actor.role] = notice["boundary"]
            binding = bind_child_identity(actor.process.pid, notice["boundary"]["identity"], own,
                expected_uid=1000 if actor.role == "producer" else 61002)
            clock_provenance[actor.role] = binding
            if not binding["clock_provenance"]["matched"]:
                raise ValueError("actor bootstrap domain/incarnation unqualified")
        producer_identity = clock_provenance["producer"]["identity"]
        collector_identity = clock_provenance["collector"]["identity"]
        plan = dict(schema_version="edge-real-source-close-plan/v1", run_id=run_id, capture_id=capture_id, case_id=case_id,
            protocol_sha256=PROTOCOL_SHA256, source_inventory_sha256=source_inventory_sha256, trust_sha256=sha(trust),
            expected_context=expected_context, controller_identity=own, producer_identity=producer_identity,
            collector_identity=collector_identity, source_identity=source_object, gate_id=gate_id, gate_token=token,
            attempts=[dict(id=row["id"], kind=row["kind"], event_sha256=sha(wire(row["event"])), native_seq=row["native_seq"]) for row in events],
            late_ids=["late0", "late1"], maximum_bytes=1048576)
        save(output / "plan.json", wire(plan))
        started = time.monotonic_ns()
        plan_bytes, inventory = read_closed(output / "plan.json"), read_closed(output / "source-inventory.json")
        if sha(inventory) != source_inventory_sha256 or plan_bytes != wire(plan) or object_identity(held_fd) != source_object:
            raise ValueError("enrollment readback differs")
        if any(actor.process.poll() is not None for actor in (producer, collector)):
            raise ValueError("actor exited before admission")
        enrollment = dict(started_ns=started, finished_ns=time.monotonic_ns(), plan_sha256=sha(plan_bytes),
            plan_bytes_read=len(plan_bytes), source_inventory_sha256=sha(inventory), source_inventory_bytes_read=len(inventory), source_identity=source_object)
        gate_plan = dict(gate_id=gate_id, gate_token=token, attempts=[dict(id=row["id"]) for row in events] + [dict(id=x) for x in ("late0", "late1")])
        gate = AdmissionGate(gate_plan, lambda: True)
        for row in events:
            assert gate.attempt(row["id"], gate_id, token)
        producer.send(dict(command="start", case_id=case_id, events=events))
        producer.receive("prefix")
        prefix_start = time.monotonic_ns()
        # Exactly the existing cursor-only command, no collector begin/commit.
        for _ in range(4):
            observer.send(dict(op="cursoronly"))
            selected = observer.receive_any()
            if selected.get("refused") or selected.get("outcomes") != 0:
                raise ValueError("original witnessed cursor advance refused")
        prefix = snapshot(fixture.source, "prefix-source.raw")
        anchors = snapshot(fixture.anchors, "prefix-anchors.raw")
        prefix_tip = SourceVerifier(fixture.p).verify(prefix)
        prefix_anchor = anchor_checkpoint(anchors)
        if prefix_tip["seq"] != 4:
            raise ValueError("prefix selector did not observe exactly4")
        prefix_selected = dict(started_ns=prefix_start, finished_ns=time.monotonic_ns(), source_checkpoint=prefix_tip, anchor_checkpoint=prefix_anchor)
        witness_args = dict(expected_trust_sha256=sha(trust), expected_context=expected_context,
            expected_source_checkpoint=prefix_tip, expected_anchor_checkpoint=prefix_anchor)
        save(output / ARG_FILES["witness_arguments"], wire(witness_args))
        C = gate.close(gate_id, token)
        late_controls = []
        for identifier in ("late0", "late1"):
            before = time.monotonic_ns()
            before_rc = producer.process.poll()
            start = time.monotonic_ns()
            assert gate.attempt(identifier, gate_id, token) is False
            finish = time.monotonic_ns()
            after_rc = producer.process.poll()
            after = time.monotonic_ns()
            late_controls.append(dict(id=identifier, gate_id=gate_id, gate_token=token, started_ns=start, finished_ns=finish,
                poll_before_ns=before, poll_after_ns=after, poll_before_returncode=before_rc, poll_after_returncode=after_rc))
        producer.send(dict(command="finish"))
        closed = attempt("producer_closed_ack", lambda: producer.receive("closed"))
        w_start = time.monotonic_ns()
        attempt("producer_wait", producer.wait)
        W = dict(started_ns=w_start, finished_ns=time.monotonic_ns(), pid=producer.process.pid,
            process_start_ticks=producer_identity["process_start_ticks"], returncode=producer.process.returncode,
            waited=producer.process.returncode is not None)
        final_start = time.monotonic_ns()
        final_source = read_closed(fixture.source)
        final_tip = SourceVerifier(fixture.p).verify(final_source)
        final_selected = dict(started_ns=final_start, finished_ns=time.monotonic_ns(), source_checkpoint=final_tip)
        source_args = dict(expected_trust_sha256=sha(trust), expected_context=expected_context,
            expected_prefix_checkpoint=prefix_tip, expected_final_checkpoint=final_tip)
        save(output / ARG_FILES["source_arguments"], wire(source_args))
        controller = dict(schema_version="edge-real-source-close-controller/v1", run_id=run_id, capture_id=capture_id,
            controller_identity=own, producer_identity=producer_identity, gate_id=gate_id, gate_token=token, enrollment=enrollment,
            attempts=[dict(id=row["id"], decision=row["decision"], started_ns=row["attempt_started_ns"], finished_ns=row["attempt_finished_ns"]) for row in gate.attempts.values()],
            C=C, late_controls=late_controls, prefix_selection=prefix_selected, final_selection=final_selected,
            writer_close=closed["writer_close"] if closed else None,
            post_close_append=closed["post_close_append"] if closed else dict(attempted=False, started_ns=None, finished_ns=None, outcome=None, exception_type=None, source_unchanged=None),
            W=W, test_loss_ids=None if case_id == "abrupt_writer" else ["a04"] if case_id == "explicit_loss" else [])
        save(output / "controller.json", wire(controller))
        collector.send(dict(command="read", expected_identity=source_object,
            private_probes=[str(fixture.pk), str(fixture.wk), str(fixture.anchors), str(fixture.journal)]))
        collected = collector.receive("collected")
        stage_facts["collector_private_probes_denied"] = collected["private_probes_denied"]
        attempt("collector_wait", collector.wait)
        snapshot(forensic / "source.raw", "source.raw", origin="INDEPENDENT_COLLECTOR_FORENSIC_OUTPUT_ROOT_COPY")
        snapshot(forensic / "collection.json", "collection.json", origin="INDEPENDENT_COLLECTOR_RECEIPT_ROOT_COPY")
        observer.send(dict(op="close"))
        attempt("observer_wait", observer.wait)
        snapshot(fixture.anchors, "anchors.raw")
        snapshot(fixture.journal, "journal.raw")
    except Exception as exc:
        errors["case"] = dict(type=type(exc).__name__, errno=getattr(exc, "errno", None))
    finally:
        for actor in actors:
            attempt(actor.role + "_cleanup", actor.cleanup)
            attempt(actor.role + "_logs", lambda actor=actor: actor.export(output))
        if fixture is not None:
            attempt("witness_stop", fixture.halt)
            witness_backend_errors = [dict(type=type(exc).__name__, errno=getattr(exc, "errno", None)) for exc in fixture.errors]
            # Preserve all available original siblings on every partial failure.
            for path, name in ((fixture.source, "source.raw"), (fixture.anchors, "anchors.raw"), (fixture.journal, "journal.raw")):
                if not (output / name).exists() and path.exists():
                    attempt("preserve_" + name, lambda path=path, name=name: snapshot(path, name,
                        origin="ROOT_FALLBACK_ORIGINAL_READ_NOT_INDEPENDENT_COLLECTOR" if name == "source.raw" else "ROOT_CONTROLLER_ORIGINAL_READ_COPY"))
        if held_fd is not None:
            attempt("source_fd_close", lambda: os.close(held_fd))
        safe = all(actor.process.returncode is not None and not actor.cleanup_errors for actor in actors) and (
            fixture is None or (fixture.thread is None and not witness_backend_errors and "witness_stop" not in errors))
        # Original private fixture retained if anything is still live; never continue as healthy.
        if fixture is not None and safe:
            attempt("fixture_cleanup", fixture.clean)
            if "fixture_cleanup" in errors:
                safe = False
    expected = {}
    for key, name in {**RAW_FILES, **ARG_FILES}.items():
        raw = attempt("read_" + key, lambda name=name: read_closed(output / name)) if (output / name).exists() else None
        expected[key + "_sha256"] = sha(raw) if raw is not None else None
    state = dict(schema_version="edge-real-source-close-lab-state/v1", case_id=case_id, run_id=run_id,
        errors=errors, witness_backend_errors=witness_backend_errors, clock_provenance=clock_provenance, safe_to_continue=safe, boundary=role_boundary(), actor_boundaries=boundaries, stage_facts=stage_facts,
        actors={a.role: dict(pid=a.process.pid, returncode=a.process.returncode, cleanup_errors=a.cleanup_errors,
            observed_bytes=a.observed, retained_bytes={k: len(v) for k, v in a.buffers.items()},
            stream_truncated={k: a.observed[k] > len(v) for k, v in a.buffers.items()}) for a in actors}, expected=expected)
    save(output / "case-state.json", wire(state))
    return dict(expected=expected, safe_to_continue=safe, errors=errors, actorfacts=state["actors"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", choices=("producer", "collector", "observer"), required=True)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--key", type=Path)
    parser.add_argument("--boot")
    parser.add_argument("--fd", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.role == "producer":
        producer_worker(args.policy, args.key, args.boot)
    elif args.role == "collector":
        collector_worker(args.fd, args.output)
    else:
        from test_source_witness_linux import OBSERVER_WORKER
        reply(dict(kind="blocked", boundary=role_boundary()))
        # Unchanged existing observer body and original API; its cursor-only operation.
        sys.argv = [__file__, str(args.policy), "create"]
        exec(OBSERVER_WORKER, {"__name__": "__main__"})


if __name__ == "__main__":
    main()
