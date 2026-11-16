"""Fresh bounded 120%-quota file-load arms, never production or clock repair."""

from contextlib import ExitStack, contextmanager
from copy import deepcopy
import json
import os
import stat
from pathlib import Path
import sys
import threading
import time
import uuid
from unittest.mock import patch

import run_observer_phase_cost as phase
from observer_cost_helpers import process_sample, process_summary
from azazel_edge.service_objectives import so11_quota_load as quota
from azazel_edge.service_objectives.declarations import load_ingress_quotas
from azazel_edge.service_objectives.ingress_final_audit import FinalAudit
from azazel_edge.outcome import input_live
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.journal import _parse
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy
from azazel_edge.benchmark.benefit import manifest_digest

ORIGINAL = phase.original
ORIGIN_RUN_MODULE = sys.modules[ORIGINAL.Run.__module__]
MIN_DURATION_NS = 6_000_000_000
MAX_EVE_BYTES = 16 * 1024 * 1024
MAX_EVE_ROWS = 32768
CLOCK_CONTEXT_BYTES = 16384
CLOCK_FILES = (
    phase.WORKER,
    phase.RECORDER,
    "signed_network_load_clock.py",
    "signed_network_recording.py",
)


def policy_context(path):
    """Read the actual Root policy independently of all observer sidecars."""
    path = Path(path)
    payload = json.loads(read_original(path, 65536))
    source = str(path)
    return dict(
        policy_sha256=manifest_digest(payload),
        policy_source_ref=source,
        policy_ref=OutcomeTelemetryPolicy.from_mapping(
            payload, source_ref=source
        ).policy_ref,
    )


def recording_binding(artifacts, metadata, actual_policy_context):
    return dict(
        calls_sha256=artifacts["calls"]["sha256"] if artifacts.get("calls") else None,
        context_sha256=artifacts["context"]["sha256"]
        if artifacts.get("context")
        else None,
        policy_context=deepcopy(actual_policy_context),
        scope_pins=dict(metadata, role="observer"),
    )


def ingress_diagnostics(audit):
    diagnostic = audit.diagnostics.get("core_stderr", {})
    return dict(
        core_stderr={key: diagnostic.get(key) for key in ("sha256", "bytes", "error")}
    )


def public_trust_artifact(fixture):
    """Allow only existing public trust fields, never producer/witness secrets."""
    path = Path(fixture.policy_file)
    raw = read_original(path, 65536)
    if len(raw) > 65536:
        raise ValueError("public trust byte bound")
    policy = TrustPolicy(_parse(raw))
    if phase._wire(dict(policy.data)) != phase._wire(dict(fixture.p.data)):
        raise ValueError("public trust differs from actual fixture")
    private_parents = (fixture.pk.parent, fixture.wk.parent)
    for value in policy.data.values():
        if type(value) is str and any(
            value == str(parent) or value.startswith(str(parent) + "/")
            for parent in private_parents
        ):
            raise ValueError("private path cannot be exported as public trust")
    return dict(path=str(path), sha256=phase._sha(raw), bytes=len(raw), max_bytes=65536)


class StderrCapture:
    """One reader handover: startup tee, then sole FD drainer through EOF."""

    def __init__(self, path):
        self.path = Path(path)
        self.fd = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        self.bytes = 0
        self.error = None
        self.eof = False
        self.thread = None

    def append(self, raw):
        if self.error is not None:
            return
        try:
            if self.bytes + len(raw) > MAX_EVE_BYTES:
                raise ValueError("stderr byte bound")
            view = memoryview(raw)
            while view:
                count = os.write(self.fd, view)
                if count <= 0:
                    raise OSError("stderr capture write failure")
                view = view[count:]
            self.bytes += len(raw)
        except Exception as exc:
            self.error = self.error or type(exc).__name__

    def start(self, input_fd):
        def drain():
            try:
                while True:
                    raw = os.read(input_fd, 65536)
                    if not raw:
                        self.eof = True
                        return
                    self.append(raw)
            except Exception as exc:
                self.error = self.error or type(exc).__name__

        self.thread = threading.Thread(target=drain, daemon=True)
        self.thread.start()

    def finish(self):
        if self.thread is not None:
            self.thread.join(timeout=10)
        joined = self.thread is not None and not self.thread.is_alive()
        if not joined:
            self.error = self.error or "stderr drainer unjoined"
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError as exc:
                self.error = self.error or type(exc).__name__
            self.fd = None
        raw = self.path.read_bytes() if joined else None
        info = self.path.stat()
        return dict(
            complete=joined and self.eof and self.error is None,
            joined=joined,
            eof=self.eof,
            error=self.error,
            sha256=phase._sha(raw) if raw is not None else None,
            bytes=len(raw) if raw is not None else None,
            file_identity=dict(device=info.st_dev, inode=info.st_ino),
            coverage="mixed_launcher_native_from_start_to_EOF",
        )


def pid_view(pid):
    checked = time.monotonic_ns()
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return dict(
            disposition="present",
            start_ticks=int(fields[19]),
            checked_ns=checked,
            error=None,
        )
    except FileNotFoundError:
        return dict(
            disposition="absent", start_ticks=None, checked_ns=checked, error=None
        )
    except (OSError, ValueError, IndexError) as exc:
        return dict(
            disposition="unknown",
            start_ticks=None,
            checked_ns=checked,
            error=type(exc).__name__,
        )


def anchor():
    before = time.monotonic_ns()
    epoch = time.time_ns()
    return dict(
        monotonic_before_ns=before,
        epoch_ns=epoch,
        monotonic_after_ns=time.monotonic_ns(),
    )


def stage_v2(fixture, *, run_id, arm_id):
    if os.geteuid() != 0:
        raise RuntimeError("Root test bootstrap required")
    registration = json.loads(fixture.registration.read_bytes())
    phase._no_profiles(registration)
    if (
        registration.get("schema_version") != "outcome-live-origin-registration/v1"
        or fixture.p.data["schema_version"] != "outcome-input-trust/v3"
    ):
        raise ValueError("fresh unconfined v3 fixture required")
    bootstrap = fixture.root / "hostile-phase-bootstrap"
    bootstrap.mkdir(mode=0o755)
    blobs = {
        name: (phase.ROOT / "tests" / "real_systemd" / name).read_bytes()
        for name in CLOCK_FILES
    }
    for name, raw in blobs.items():
        with (bootstrap / name).open("xb") as stream:
            stream.write(raw)
        (bootstrap / name).chmod(0o444)
    journal = Path(fixture.p.data["journal_directory"])
    metadata = dict(
        run_id=run_id,
        arm=arm_id,
        input_sha256=phase.digest(ORIGINAL.TRANSCRIPT),
        code_sha256=phase._sha(b"\0".join(blobs[name] for name in CLOCK_FILES)),
        core_sha256=registration["binary_sha256"],
        interpreter_sha256=phase._sha(Path(sys.executable).resolve().read_bytes()),
    )
    traces = dict(
        signer=str(fixture.pk.parent / "hostile-phase-signer.jsonl"),
        observer=str(journal / "hostile-phase-observer.jsonl"),
        witness=str(fixture.wk.parent / "hostile-phase-witness.jsonl"),
    )
    config = dict(
        schema_version="edge-phase-timing-config/v2",
        metadata=metadata,
        registration_path=str(fixture.registration),
        policy_path=str(fixture.policy_file),
        traces=traces,
        worker_path=str(bootstrap / phase.WORKER),
        worker_sha256=phase._sha(blobs[phase.WORKER]),
        clock=dict(
            helper_path=str(bootstrap / CLOCK_FILES[2]),
            helper_sha256=phase._sha(blobs[CLOCK_FILES[2]]),
            recording_path=str(bootstrap / CLOCK_FILES[3]),
            recording_sha256=phase._sha(blobs[CLOCK_FILES[3]]),
            calls_path=str(journal / "hostile-clock-calls.jsonl"),
            context_path=str(journal / "hostile-clock-context.jsonl"),
        ),
    )
    path = bootstrap / "config.json"
    with path.open("xb") as stream:
        stream.write(phase._wire(config))
    path.chmod(0o444)
    bootstrap.chmod(0o555)
    return dict(
        config=config,
        config_path=path,
        config_sha256=phase._sha(phase._wire(config)),
        worker_path=bootstrap / phase.WORKER,
        traces={
            **traces,
            "controller": str(fixture.wk.parent / "hostile-phase-controller.jsonl"),
        },
    )


class MarkerFile:
    def __init__(self, path, state):
        self.path, self.state = path, state

    def __str__(self):
        return str(self.path)

    def __fspath__(self):
        return os.fspath(self.path)

    def __getattr__(self, name):
        return getattr(self.path, name)

    def open(self, *args, **kwargs):
        if args != ("ab",) or kwargs:
            raise ValueError("unexpected original marker file open")
        return MarkerStream(self.path.open(*args, **kwargs), self.state)


class MarkerStream:
    def __init__(self, stream, state):
        self.stream, self.state = stream, state

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def write(self, raw):
        index = len(self.state["marker_samples"])
        expected = (
            phase._wire(ORIGINAL.TRANSCRIPT[index])
            if index < len(ORIGINAL.TRANSCRIPT)
            else None
        )
        if raw != expected or self.state.get("pending_marker") is not None:
            raise ValueError("marker recipe/order differs from original")
        self.state["pending_marker"] = dict(
            start_monotonic_ns=time.monotonic_ns(), end_monotonic_ns=None
        )
        return self.stream.write(raw)


def finish_load(state):
    load = state["load"]
    if state.get("load_finished"):
        return
    start = load.window.get("window_start_monotonic_ns")
    if type(start) is not int:
        raise RuntimeError("actual writer start unavailable")
    while time.monotonic_ns() < start + MIN_DURATION_NS:
        if (
            load.error is not None
            or not load.is_alive()
            or load.stop.is_set()
            or state["run"].process.poll() is not None
        ):
            raise RuntimeError("writer or core stopped before minimum window")
        load.stop.wait(min(0.05, (start + MIN_DURATION_NS - time.monotonic_ns()) / 1e9))
    load.stop.set()
    load.join(timeout=10)
    joined = not load.is_alive()
    joined_ns = time.monotonic_ns() if joined else None
    if not joined:
        load.error = load.error or "writer join timeout"
    state["load_finished"] = True
    for role, pid in state["pids"].items():
        first = state["proc_samples"][role][0]
        state["proc_samples"][role].append(
            process_sample(pid, expected_start=first["start_ticks"])
        )
    time.sleep(int(state["quota"]["audit_interval_ms"]) / 1000.0 + 0.5)
    state["final_audit"].before_stop(
        state["fixture"].root, writer_joined=joined, writer_joined_ns=joined_ns
    )
    state["quota_load"].update(
        quota.observation(
            load,
            state["fixture"].root,
            1.2,
            core_started=True,
            core_alive_at_load_end=state["run"].process.poll() is None,
            pre_stop=state["final_audit"].pre.metadata,
        )
    )


@contextmanager
def hostile_arm(mode):
    state = dict(
        marker_samples=[],
        pending_marker=None,
        quota_load={},
        load=None,
        observer=None,
        stderr_capture=None,
        fixture=None,
        run=None,
        store_calls=0,
        load_finished=False,
        controller_start=anchor(),
        controller_end=None,
    )
    state["final_audit"] = FinalAudit(state["quota_load"])
    state["entry_source_sha256"] = phase._sha(Path(input_live.__file__).read_bytes())
    saved_register, saved_children, saved_run = (
        ORIGINAL.register_live,
        ORIGINAL.children,
        ORIGINAL.Run,
    )
    saved_store, saved_sample, saved_wait_observer = (
        ORIGINAL.store_bytes,
        ORIGINAL.process_sample,
        ORIGINAL.wait_observer,
    )

    def registered(fixture):
        result = saved_register(fixture)
        state["fixture"] = fixture
        state["initial_eve"] = fixture.raw.read_bytes()
        fixture.raw = MarkerFile(fixture.raw, state)
        return result

    def wait_observer(observer, fixture, count):
        result = saved_wait_observer(observer, fixture, count)
        state["observer"] = observer
        return result

    def children(run):
        result = saved_children(run)
        if state["load"] is None and sys.exc_info()[0] is None:
            state["run"] = run
            state["policy_context"] = policy_context(
                state["fixture"].root / "telemetry-policy.json"
            )
            points = {pid: process_sample(pid) for pid in result}
            if len(result) != 2 or any(
                point["start_ticks"] is None for point in points.values()
            ):
                raise RuntimeError("owned native/signer process identities unavailable")
            native = [
                pid
                for pid in result
                if int(
                    Path(f"/proc/{pid}/status")
                    .read_text()
                    .split("Uid:", 1)[1]
                    .split()[0]
                )
                == 0
            ]
            if len(native) != 1:
                raise RuntimeError("owned native role unavailable")
            state["native"] = native[0]
            state["native_start"] = points[native[0]]["start_ticks"]
            pids = dict(
                native=native[0], signer=next(pid for pid in result if pid != native[0])
            )
            if state["observer"] is not None:
                pids["observer"] = state["observer"].pid
            pids["controller"] = os.getpid()
            state["pids"] = pids
            state["proc_samples"] = {
                role: [process_sample(pid)] for role, pid in pids.items()
            }
            declaration = load_ingress_quotas()
            state["quota"] = declaration["quotas"][quota.SO11_INGRESS]
            state["load"] = quota.QuotaLoad(
                Path(str(state["fixture"].raw)), state["quota"]["value"] * 1.2
            )
            state["load"].start()
            quota._wait_warmup(state["load"])
        return result

    def sample(pid, *args, **kwargs):
        result = saved_sample(pid, *args, **kwargs)
        if state["pending_marker"] is not None:
            state["pending_marker"]["end_monotonic_ns"] = time.monotonic_ns()
            state["marker_samples"].append(state["pending_marker"])
            state["pending_marker"] = None
        return result

    def store(root):
        state["store_calls"] += 1
        if state["store_calls"] == 2:
            finish_load(state)
            if mode == "on":
                ORIGINAL.require_observer(state["observer"], state["fixture"], 5)
            elif mode == "faulted":
                ORIGINAL.require_observer(
                    state["observer"], state["fixture"], 3, exit_code=-9
                )
        return saved_store(root)

    class LoadedRun(saved_run):
        def started(self):
            capture = StderrCapture(state["fixture"].root / "core.stderr")
            state["stderr_capture"] = capture
            run_module = ORIGIN_RUN_MODULE
            real_os = run_module.os
            original_fd = self.process.stderr.fileno()

            def read(fd, maximum):
                raw = real_os.read(fd, maximum)
                if fd == original_fd:
                    capture.append(raw)
                return raw

            with patch.object(
                run_module, "os", phase.ForwardingModule(real_os, read=read)
            ):
                result = super().started()
            capture.start(original_fd)
            state["launcher_identity"] = process_sample(self.process.pid)
            return result

        def stop(self):
            if not state["load_finished"] or state["final_audit"].finished:
                return super().stop()
            requested = self.process.poll() is None
            requested_ns = time.monotonic_ns()
            before = pid_view(state["native"])
            code = super().stop()
            launcher_exited_ns = time.monotonic_ns()
            after = pid_view(state["native"])
            gone = (
                before["start_ticks"] == state["native_start"]
                and before["disposition"] == "present"
                and after["disposition"] == "absent"
            )
            capture = state["stderr_capture"].finish()
            state["stderr_facts"] = capture
            provenance = dict(
                process_role="launcher",
                native_exit_basis="trusted_launcher_conjunctive_return",
                native_exit_independently_waited=False,
                entry_source_sha256=state["entry_source_sha256"],
                launcher=dict(
                    pid=self.process.pid,
                    start_ticks=state["launcher_identity"]["start_ticks"],
                    requested_ns=requested_ns,
                    exited_ns=launcher_exited_ns,
                    returncode=code,
                    exit_confirmed=self.process.poll() == code,
                ),
                native=dict(
                    pid=state["native"],
                    start_ticks=state["native_start"],
                    before_stop_start_ticks=before["start_ticks"],
                    before_stop=before,
                    after_stop_disposition=after["disposition"],
                    after_stop=after,
                    checked_ns=after["checked_ns"],
                ),
                stderr_capture=capture,
            )
            stop = dict(
                requested=requested,
                forced=False,
                returncode=code,
                exit_confirmed=code == 0 and self.process.poll() == 0 and gone,
                error=None
                if gone and capture["complete"]
                else "native or stderr closure unconfirmed",
                requested_ns=requested_ns,
                exited_ns=launcher_exited_ns,
                **provenance,
            )
            state["native_exit"] = provenance
            state["final_audit"].finish(state["fixture"].root, stop)
            diagnostic = state["final_audit"].diagnostics.get("core_stderr", {})
            capture.update(
                diagnostic_sha256=diagnostic.get("sha256"),
                diagnostic_bytes=diagnostic.get("bytes"),
            )
            return code

    with ExitStack() as stack:
        for name, replacement in dict(
            register_live=registered,
            children=children,
            Run=LoadedRun,
            store_bytes=store,
            process_sample=sample,
            wait_observer=wait_observer,
        ).items():
            stack.enter_context(patch.object(ORIGINAL, name, replacement))
        try:
            yield state
        finally:
            state["controller_end"] = anchor()
            load = state["load"]
            if load is not None and load.is_alive():
                load.stop.set()
                load.join(timeout=10)
                if load.is_alive():
                    load.error = load.error or "cleanup writer join timeout"
            capture = state["stderr_capture"]
            if capture is not None and capture.fd is not None:
                state["stderr_facts"] = capture.finish()


def read_original(path, maximum):
    """Bounded original-file read, with no symlink, FIFO or mutation fallback."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("unsafe original file")
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        fields = (
            "st_dev",
            "st_ino",
            "st_uid",
            "st_gid",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        expected = tuple(getattr(before, key) for key in fields)
        if any(
            tuple(getattr(info, key) for key in fields) != expected
            for info in (os.fstat(fd), Path(path).lstat())
        ):
            raise ValueError("original file changed during read")
        return bytes(raw)
    finally:
        os.close(fd)


def _artifact(path, maximum):
    path = Path(path)
    try:
        raw = read_original(path, maximum)
    except FileNotFoundError:
        return None
    return dict(
        path=str(path), sha256=phase._sha(raw), bytes=len(raw), max_bytes=maximum
    )


def run(*, keep=True):
    from observer_hostile_cost_analysis import (
        analyze_run,
        evaluate_clock,
        recount_eve as verify_eve,
    )
    from real_systemd.signed_network_phase_recording import _identity

    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("disposable Linux Root required")
    fixtures, arms = [], []
    run_id = uuid.uuid4().hex
    state = phase_state = None
    arm_id = None
    try:
        for arm_id in phase.ARM_ORDER:
            mode = arm_id.split("_", 1)[1]
            instrumented = arm_id.startswith("instrumented_")
            phase_state = None
            with ExitStack() as stack:
                if instrumented:
                    stack.enter_context(patch.object(phase, "stage", stage_v2))
                    phase_state = stack.enter_context(
                        phase.instrumented_arm(run_id=run_id, arm_id=arm_id)
                    )
                state = stack.enter_context(hostile_arm(mode))
                report = ORIGINAL.arm(mode, fixtures=fixtures)
            phases, artifacts = (
                phase._reports(phase_state, mode, report) if instrumented else ({}, {})
            )
            fixture = state["fixture"]
            clocks = phase_state["staged"]["config"]["clock"] if instrumented else {}
            clock_artifacts = (
                {
                    name: _artifact(
                        clocks[name + "_path"],
                        CLOCK_CONTEXT_BYTES if name == "context" else phase.MAX_BYTES,
                    )
                    for name in ("calls", "context")
                }
                if instrumented
                else {}
            )
            retained = dict(
                eve=_artifact(Path(str(fixture.raw)), MAX_EVE_BYTES),
                source=_artifact(fixture.source, 2 * 1024 * 1024),
                audit=_artifact(fixture.root / "ingress-audit.jsonl", MAX_EVE_BYTES),
                trust=public_trust_artifact(fixture),
            )
            if (
                state["final_audit"].pre is not None
                and state["final_audit"].pre.raw is not None
            ):
                pre_path = fixture.root / "hostile-ingress-pre-stop.raw"
                with pre_path.open("xb") as stream:
                    stream.write(state["final_audit"].pre.raw)
                retained["audit_pre_stop"] = _artifact(pre_path, MAX_EVE_BYTES)
            checks = phase.phase_checks(phases, mode) if instrumented else {}
            clock_report = None
            controller_identity = _identity()
            if instrumented and mode != "off":

                def read_clock(name):
                    descriptor = clock_artifacts.get(name)
                    return (
                        read_original(descriptor["path"], descriptor["max_bytes"])
                        if descriptor is not None
                        else None
                    )

                expected = dict(
                    phase_state["staged"]["config"]["metadata"], role="observer"
                )
                final_observer = report["processes"]["observer"]["final"]
                expected.update(
                    pid=final_observer["pid"],
                    start_ticks=final_observer["start_ticks"],
                    boot_id=controller_identity["boot_id"],
                )
                actual_policy_context = policy_context(
                    fixture.root / "telemetry-policy.json"
                )
                if actual_policy_context != state["policy_context"]:
                    raise ValueError("actual Root telemetry policy changed")
                binding = recording_binding(
                    clock_artifacts,
                    phase_state["staged"]["config"]["metadata"],
                    actual_policy_context,
                )
                clock_report = evaluate_clock(
                    calls_raw=read_clock("calls"),
                    context_raw=read_clock("context"),
                    expected=expected,
                    controller_start=state["controller_start"],
                    controller_end=state["controller_end"],
                    kernel_boot_id=controller_identity["boot_id"],
                    controller_boot_id=controller_identity["boot_id"],
                    controller_clock_domain=controller_identity["clock_domain"],
                    recording_binding=binding,
                )
            raw_eve = read_original(Path(str(fixture.raw)), MAX_EVE_BYTES)
            eve_evidence = verify_eve(
                raw_eve,
                prefix=state["initial_eve"],
                marker_lines=[phase._wire(row) for row in ORIGINAL.TRANSCRIPT],
            )
            arm = dict(
                arm_id=arm_id,
                mode=mode,
                instrumented=instrumented,
                original_cost_report=report,
                phase_reports=phases,
                phase_artifacts=artifacts,
                quota_load=deepcopy(state["quota_load"]),
                marker_samples=deepcopy(state["marker_samples"]),
                eve_evidence=eve_evidence,
                clock_artifacts=clock_artifacts,
                clock_report=clock_report,
                clock_context=dict(
                    controller_start=state["controller_start"],
                    controller_end=state["controller_end"],
                    controller_boot_id=Path("/proc/sys/kernel/random/boot_id")
                    .read_text()
                    .strip(),
                ),
                raw_artifacts=retained,
                exit_provenance=state.get("native_exit"),
                stderr_capture=state.get("stderr_facts"),
                ingress_diagnostics=ingress_diagnostics(state["final_audit"]),
                hostile_process_metrics={
                    role: process_summary(points, report["ticks_per_second"])
                    for role, points in state["proc_samples"].items()
                },
                **checks,
            )
            if instrumented:
                config = phase_state["staged"]["config"]
                arm["bootstrap_provenance"] = dict(
                    metadata=deepcopy(config["metadata"]),
                    config_sha256=phase_state["staged"]["config_sha256"],
                    worker_sha256=config["worker_sha256"],
                    clock_helper_sha256=config["clock"]["helper_sha256"],
                    recording_helper_sha256=config["clock"]["recording_sha256"],
                )
            arms.append(arm)
        if (
            len({arm["original_cost_report"]["semantic_sha256"] for arm in arms}) != 1
            or len({arm["original_cost_report"]["input_sha256"] for arm in arms}) != 1
        ):
            raise RuntimeError("six-arm original marker parity differs")
        for arm in arms:
            if arm["instrumented"]:
                arm["functional_phase_gate"] = phase.functional_phase_gate(
                    arm, six_arm_semantic_parity=True
                )
        result = analyze_run(arms)
        result["original_arm_inputs"] = arms
        result["preserved_fixtures"] = [str(fixture.root) for fixture in fixtures]
        return result
    except BaseException as exc:
        if (
            state
            and state.get("fixture") is not None
            and arm_id not in [arm["arm_id"] for arm in arms]
        ):
            fixture = state["fixture"]
            partial = dict(
                arm_id=arm_id,
                original_cost_report=None,
                quota_load=deepcopy(state["quota_load"]),
                marker_samples=deepcopy(state["marker_samples"]),
                raw_artifacts={},
                phase_artifacts={},
                clock_artifacts={},
            )
            for name, path, limit in (
                ("eve", Path(str(fixture.raw)), MAX_EVE_BYTES),
                ("source", fixture.source, 2 * 1024 * 1024),
                ("audit", fixture.root / "ingress-audit.jsonl", MAX_EVE_BYTES),
            ):
                try:
                    partial["raw_artifacts"][name] = _artifact(path, limit)
                except Exception as read_error:
                    partial[name + "_read_error"] = type(read_error).__name__
            try:
                partial["raw_artifacts"]["trust"] = public_trust_artifact(fixture)
            except Exception as read_error:
                partial["trust_read_error"] = type(read_error).__name__
            if phase_state and phase_state.get("staged"):
                staged = phase_state["staged"]
                for role, path in staged["traces"].items():
                    try:
                        partial["phase_artifacts"][role] = _artifact(
                            path, phase.MAX_BYTES
                        )
                    except Exception as read_error:
                        partial[role + "_read_error"] = type(read_error).__name__
                for name in ("calls", "context"):
                    try:
                        partial["clock_artifacts"][name] = _artifact(
                            staged["config"]["clock"][name + "_path"],
                            CLOCK_CONTEXT_BYTES
                            if name == "context"
                            else phase.MAX_BYTES,
                        )
                    except Exception as read_error:
                        partial[name + "_read_error"] = type(read_error).__name__
            arms.append(partial)
        exc.hostile_cost_partial_report = dict(
            schema_version="edge-hostile-phase-cost-failure/v1",
            arms=arms,
            blocker=type(exc).__name__,
            preserved_fixtures=[str(fixture.root) for fixture in fixtures],
        )
        raise


def export_public(result, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    with (output_dir / "report.json").open("xb") as stream:
        stream.write(phase._wire(result))
    for arm in result.get("original_arm_inputs", result["arms"]):
        if arm["arm_id"] not in phase.ARM_ORDER:
            raise ValueError("unknown public arm")
        for group in ("phase_artifacts", "clock_artifacts", "raw_artifacts"):
            for name, descriptor in arm.get(group, {}).items():
                if descriptor is None:
                    continue
                allowed = {
                    "phase_artifacts": {"signer", "observer", "witness", "controller"},
                    "clock_artifacts": {"calls", "context"},
                    "raw_artifacts": {
                        "eve",
                        "source",
                        "audit",
                        "audit_pre_stop",
                        "trust",
                    },
                }
                if name not in allowed[group]:
                    raise ValueError("unlisted public artifact")
                maximum = descriptor.get("max_bytes", phase.MAX_BYTES)
                with Path(descriptor["path"]).open("rb") as stream:
                    raw = stream.read(maximum + 1)
                if (
                    len(raw) > maximum
                    or len(raw) != descriptor["bytes"]
                    or phase._sha(raw) != descriptor["sha256"]
                ):
                    raise ValueError("public artifact changed or oversized")
                with (
                    output_dir / (arm["arm_id"] + "-" + group + "-" + name + ".raw")
                ).open("xb") as stream:
                    stream.write(raw)
