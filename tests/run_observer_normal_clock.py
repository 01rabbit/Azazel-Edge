"""Prospective normal-stop profile composed with the unchanged #610 load lab."""

from contextlib import contextmanager, ExitStack
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import sys
import uuid
from unittest.mock import patch

import run_observer_hostile_cost as load
import run_observer_phase_cost as phase
from observer_cost_helpers import process_sample
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy, persistence_context

ROOT = Path(__file__).resolve().parents[1]
FILES = (*load.CLOCK_FILES, "signed_network_normal_stop.py")
MAX_COMPLETION = 65536
MAX_REQUEST = 16384


def stage_v3(fixture, *, run_id, arm_id, profile=None):
    """Fresh Root-readonly test code, with no enforcing-profile fallback."""
    if os.geteuid() != 0:
        raise RuntimeError("isolated Root test bootstrap required")
    registration = json.loads(fixture.registration.read_bytes())
    phase._no_profiles(registration)
    if (
        registration.get("schema_version") != "outcome-live-origin-registration/v1"
        or fixture.p.data["schema_version"] != "outcome-input-trust/v3"
    ):
        raise ValueError("fresh existing unconfined v3 fixture required")
    profile = profile or (
        "phase_and_clock" if arm_id.startswith("instrumented_") else "stop_only"
    )
    if profile not in ("stop_only", "phase_and_clock") or arm_id not in phase.ARM_ORDER:
        raise ValueError("unknown explicit normal-stop profile or arm")
    if profile == "stop_only" and arm_id not in ("original_on", "original_faulted"):
        raise ValueError("stop-only requires a declared baseline observer")
    if profile == "phase_and_clock" and not arm_id.startswith("instrumented_"):
        raise ValueError("instrumented arm required")
    directory = fixture.root / "normal-clock-bootstrap"
    directory.mkdir(mode=0o755)
    blobs = {
        name: (ROOT / "tests" / "real_systemd" / name).read_bytes() for name in FILES
    }
    for name, raw in blobs.items():
        with (directory / name).open("xb") as stream:
            stream.write(raw)
        (directory / name).chmod(0o444)
    journal = Path(fixture.p.data["journal_directory"])
    metadata = dict(
        run_id=run_id,
        arm=arm_id,
        input_sha256=phase.digest(load.ORIGINAL.TRANSCRIPT),
        code_sha256=phase._sha(b"\0".join(blobs[name] for name in FILES)),
        core_sha256=registration["binary_sha256"],
        interpreter_sha256=phase._sha(Path(sys.executable).resolve().read_bytes()),
    )
    traces = dict(
        signer=str(fixture.pk.parent / "normal-phase-signer.jsonl"),
        observer=str(journal / "normal-phase-observer.jsonl"),
        witness=str(fixture.wk.parent / "normal-phase-witness.jsonl"),
    )
    config = dict(
        schema_version="edge-phase-timing-config/v3",
        metadata=metadata,
        registration_path=str(fixture.registration),
        policy_path=str(fixture.policy_file),
        traces=traces,
        worker_path=str(directory / phase.WORKER),
        worker_sha256=phase._sha(blobs[phase.WORKER]),
        clock=dict(
            helper_path=str(directory / FILES[2]),
            helper_sha256=phase._sha(blobs[FILES[2]]),
            recording_path=str(directory / FILES[3]),
            recording_sha256=phase._sha(blobs[FILES[3]]),
            calls_path=str(journal / "normal-clock-calls.jsonl"),
            context_path=str(journal / "normal-clock-context.jsonl"),
        ),
        normal_stop=dict(
            helper_path=str(directory / FILES[4]),
            helper_sha256=phase._sha(blobs[FILES[4]]),
            profile=profile,
            receipt_path=str(journal / "normal-stop-completion.json"),
        ),
    )
    path = directory / "config.json"
    with path.open("xb") as stream:
        stream.write(phase._wire(config))
    path.chmod(0o444)
    directory.chmod(0o555)
    return dict(
        config=config,
        config_path=path,
        config_sha256=phase._sha(phase._wire(config)),
        worker_path=directory / phase.WORKER,
        traces={
            **traces,
            "controller": str(fixture.wk.parent / "normal-phase-controller.jsonl"),
        },
    )


class RequestedObserver:
    """Same original operations; Root send/wait brackets never become observer time."""

    def __init__(self, process, entry):
        self.process, self.entry = process, entry
        self.entry["observer_initial"] = process_sample(process.pid)
        self.entry["requests"] = []
        self.entry["wait_result"] = None

    def __getattr__(self, name):
        return getattr(self.process, name)

    def terminate(self):
        before = load.anchor()
        result = self.process.terminate()
        after = load.anchor()
        self.entry["requests"].append(
            dict(
                signal=int(signal.SIGTERM),
                pid=self.process.pid,
                start_ticks=self.entry["observer_initial"].get("start_ticks"),
                before=before,
                after=after,
                delivery_time=None,
            )
        )
        return result

    def wait(self, *args, **kwargs):
        result = self.process.wait(*args, **kwargs)
        if self.entry["wait_result"] is None:
            self.entry["wait_result"] = dict(
                pid=self.process.pid,
                start_ticks=self.entry["observer_initial"].get("start_ticks"),
                returncode=result,
                after=load.anchor(),
                view=load.pid_view(self.process.pid),
            )
        return result


@contextmanager
def normal_profile(run_id, *, controller_identity=None):
    """Compose caller-module bindings; no shared stdlib monkeypatch or workload copy."""
    saved_arm, saved_stage = load.hostile_arm, load.stage_v2
    entries, staged_by_root = {}, {}
    order = iter(phase.ARM_ORDER)

    def stage(fixture, *, run_id, arm_id):
        result = stage_v3(fixture, run_id=group_id, arm_id=arm_id)
        staged_by_root[str(fixture.root)] = result
        return result

    group_id = run_id

    @contextmanager
    def arm(mode):
        arm_id = next(order)
        if arm_id.split("_", 1)[1] != mode:
            raise ValueError("fixed arm order changed")
        entry = entries[arm_id] = dict(
            arm_id=arm_id, controller_identity=deepcopy(controller_identity)
        )
        with saved_arm(mode) as state:
            entry["state"] = state
            real_register, real_subprocess = (
                load.ORIGINAL.register_live,
                load.ORIGINAL.subprocess,
            )

            def registered(fixture):
                result = real_register(fixture)
                staged = staged_by_root.get(str(fixture.root))
                if mode != "off" and not arm_id.startswith("instrumented_"):
                    staged = stage_v3(
                        fixture, run_id=group_id, arm_id=arm_id, profile="stop_only"
                    )
                    staged_by_root[str(fixture.root)] = staged
                entry["staged"] = staged
                return result

            def popen(argv, *args, **kwargs):
                original_observer = isinstance(argv, list) and argv[:3] == [
                    sys.executable,
                    "-m",
                    phase.OBSERVER,
                ]
                worker_observer = (
                    isinstance(argv, list)
                    and "--role" in argv
                    and argv[argv.index("--role") + 1] == "observer"
                )
                if original_observer and not arm_id.startswith("instrumented_"):
                    staged = entry["staged"]
                    argv = phase.worker_command(
                        argv,
                        role="observer",
                        **{
                            k: staged[k]
                            for k in ("config_path", "config_sha256", "worker_path")
                        },
                    )
                process = real_subprocess.Popen(argv, *args, **kwargs)
                return (
                    RequestedObserver(process, entry)
                    if original_observer or worker_observer
                    else process
                )

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(load.ORIGINAL, "register_live", registered)
                )
                stack.enter_context(
                    patch.object(
                        load.ORIGINAL,
                        "subprocess",
                        phase.ForwardingModule(real_subprocess, Popen=popen),
                    )
                )
                yield state

    try:
        with (
            patch.object(load, "stage_v2", stage),
            patch.object(load, "hostile_arm", arm),
        ):
            yield entries
    finally:
        # saved_stage is deliberately unchanged; patch restores the exact binding.
        assert load.stage_v2 is saved_stage


def _metadata(path):
    info = Path(path).lstat()
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid)


def collect_control(entry, original):
    """Read only stopped scope originals; absent fault completion stays absent."""
    state, staged = entry["state"], entry.get("staged")
    fixture = state["fixture"]
    artifacts, errors = {}, {}

    def retain(name, operation):
        try:
            return operation()
        except Exception as exc:
            errors[name] = type(exc).__name__
            return None

    if staged is not None:
        artifacts["completion"] = retain(
            "completion",
            lambda: load._artifact(
                staged["config"]["normal_stop"]["receipt_path"], MAX_COMPLETION
            ),
        )
    request = dict(
        schema_version="edge-observer-stop-request/v1",
        arm_id=entry["arm_id"],
        requests=entry.get("requests", []),
        wait_result=entry.get("wait_result"),
        observer_initial=entry.get("observer_initial"),
        controller_identity=entry.get("controller_identity"),
    )
    request_path = fixture.wk.parent / "normal-stop-request.json"

    def request_artifact():
        if request_path.exists():
            if load.read_original(request_path, MAX_REQUEST) != phase._wire(request):
                raise ValueError("previous request evidence differs; no repair")
        else:
            with request_path.open("xb") as stream:
                stream.write(phase._wire(request))
        return load._artifact(request_path, MAX_REQUEST)

    artifacts["request"] = retain("request", request_artifact)
    if original["mode"] != "off":
        artifacts["journal"] = retain(
            "journal", lambda: load._artifact(fixture.journal, phase.MAX_BYTES)
        )
        artifacts["anchors"] = retain(
            "anchors", lambda: load._artifact(fixture.anchors, phase.MAX_BYTES)
        )
    metadata = dict(staged["config"]["metadata"], role="observer") if staged else None

    def journal_policy():
        objective = OutcomeTelemetryPolicy.from_file(
            fixture.root / "telemetry-policy.json"
        )
        return phase._sha(persistence_context(objective, "lo", 0.05).encode())

    return dict(
        artifacts=artifacts,
        collection_errors=errors,
        expected_metadata=metadata,
        request_record=request,
        profile=staged["config"]["normal_stop"]["profile"] if staged else None,
        source_identity=retain("source_identity", lambda: _metadata(fixture.source)),
        journal_identity=retain("journal_identity", lambda: _metadata(fixture.journal))
        if original["mode"] != "off"
        else None,
        policy_context=deepcopy(state.get("policy_context")),
        expected_journal_policy_sha256=retain("journal_policy", journal_policy),
    )


def run():
    from observer_normal_stop_analysis import evaluate_run
    from real_systemd.signed_network_phase_recording import _identity

    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("disposable offline Linux Root required")
    entries = {}
    result = None
    try:
        # The controller identity is a separate current-process observation.
        identity = _identity()
        with normal_profile(uuid.uuid4().hex, controller_identity=identity) as entries:
            result = load.run(keep=True)
        originals = result["original_arm_inputs"]
        for original in originals:
            entry = entries[original["arm_id"]]
            entry["controller_identity"] = identity
            original["normal_stop"] = collect_control(entry, original)
        return evaluate_run(result)
    except BaseException as exc:
        old = result or getattr(exc, "hostile_cost_partial_report", None)
        partial = dict(
            schema_version="edge-observer-normal-stop-failure/v1",
            blocker=type(exc).__name__,
            original_load_evaluation=old,
        )
        controls = {}
        for arm_id, entry in entries.items():
            retained = next(
                (
                    arm.get("normal_stop")
                    for arm in (old or {}).get("original_arm_inputs", [])
                    if arm.get("arm_id") == arm_id
                ),
                None,
            )
            if retained is not None:
                controls[arm_id] = retained
                continue
            try:
                controls[arm_id] = collect_control(
                    entry, dict(mode=arm_id.split("_", 1)[1])
                )
            except Exception as collection_error:
                controls[arm_id] = dict(error=type(collection_error).__name__)
        partial["control_evidence"] = controls
        exc.normal_stop_partial_report = partial
        raise


def export_public(result, output_dir):
    """Allowlisted originals only, with no private keys/config/bootstrap export."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    with (output / "report.json").open("xb") as stream:
        stream.write(phase._wire(result))
    base = result.get("original_load_evaluation") or {}
    arms = base.get("original_arm_inputs", base.get("arms", []))
    controls = result.get("control_evidence", {})
    # A scope may fail before the old driver's arm append. Its already retained
    # control originals still belong to this assigned trial and must survive.
    retained_ids = {arm["arm_id"] for arm in arms}
    arms = list(arms) + [
        dict(arm_id=arm_id) for arm_id in controls if arm_id not in retained_ids
    ]
    for arm in arms:
        if arm["arm_id"] not in phase.ARM_ORDER:
            raise ValueError("unlisted arm")
        groups = {
            key: arm.get(key, {})
            for key in ("raw_artifacts", "phase_artifacts", "clock_artifacts")
        }
        groups["control_artifacts"] = arm.get(
            "normal_stop", controls.get(arm["arm_id"], {})
        ).get("artifacts", {})
        allowed = dict(
            raw_artifacts={"eve", "source", "audit", "audit_pre_stop", "trust"},
            phase_artifacts={"controller", "signer", "observer", "witness"},
            clock_artifacts={"calls", "context"},
            control_artifacts={"completion", "request", "journal", "anchors"},
        )
        for group, descriptors in groups.items():
            for name, descriptor in descriptors.items():
                if name not in allowed[group]:
                    raise ValueError("unlisted public artifact")
                if descriptor is None:
                    continue
                maximum = descriptor.get("max_bytes", phase.MAX_BYTES)
                raw = load.read_original(descriptor["path"], maximum)
                if (
                    len(raw) != descriptor["bytes"]
                    or phase._sha(raw) != descriptor["sha256"]
                    or len(raw) > maximum
                ):
                    raise ValueError("original artifact changed")
                with (
                    output / (arm["arm_id"] + "-" + group + "-" + name + ".raw")
                ).open("xb") as stream:
                    stream.write(raw)
