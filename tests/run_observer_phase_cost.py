"""Opt-in six-arm offline phase pilot using the unchanged observer-cost arms."""

import argparse
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
from unittest.mock import patch

import run_observer_cost as original
from observer_cost_helpers import digest, process_sample, process_summary
from azazel_edge.benchmark.timing_cost_attribution import (
    ARM_ORDER,
    MAX_BYTES,
    analyze_cost_arms,
    analyze_trace,
)

ROOT = Path(__file__).resolve().parents[1]
WORKER = "signed_network_phase_worker.py"
RECORDER = "signed_network_phase_recording.py"
LAUNCHER = "azazel_edge.outcome.input_live"
OBSERVER = "azazel_edge.outcome.telemetry"
LAUNCH_OPTIONS = ("--policy", "--registration", "--private-key", "--boot-ref")
OBSERVER_OPTIONS = (
    "--input",
    "--output",
    "--policy",
    "--interface",
    "--poll-seconds",
    "--sample-interval-seconds",
    "--journal-directory",
    "--journal-scope",
    "--journal-boot-id",
    "--journal-max-bytes",
    "--journal-resume-input",
    "--input-auth-policy",
)
REQUIRED_PHASES = {
    "signer": (
        "input_receive",
        "native_frame_validation",
        "source_append",
        "source_sign",
        "source_verify",
    ),
    "witness": ("witness_request", "witness_append", "witness_sign"),
    "observer": (
        "input_snapshot",
        "source_verify",
        "witness_rpc",
        "observation",
        "journal_append",
    ),
    "controller": ("controller_wait", "source_closure_wait"),
}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _wire(value):
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
        + b"\n"
    )


class ForwardingModule:
    """Override a binding on one caller module, never the shared stdlib object."""

    def __init__(self, module, **bindings):
        self.module, self.bindings = module, bindings

    def __getattr__(self, name):
        return (
            self.bindings[name] if name in self.bindings else getattr(self.module, name)
        )


def _original_arguments(argv, module, options):
    if type(argv) is not list or argv[:3] != [sys.executable, "-m", module]:
        raise ValueError("unexpected original process command")
    args, offset = argv[3:], 0
    for option in options:
        if offset >= len(args) or args[offset] != option:
            raise ValueError("unexpected original option shape")
        offset += 1
        if option != "--journal-resume-input":
            if offset >= len(args) or type(args[offset]) is not str:
                raise ValueError("missing original option value")
            offset += 1
    if offset != len(args):
        raise ValueError("extra original process arguments")
    return list(args)


def worker_command(argv, *, role, config_path, config_sha256, worker_path):
    module, options = (
        (LAUNCHER, LAUNCH_OPTIONS)
        if role == "launcher"
        else (OBSERVER, OBSERVER_OPTIONS)
    )
    if role not in ("launcher", "observer"):
        raise ValueError("unsupported harness worker role")
    args = _original_arguments(argv, module, options)
    return [
        argv[0],
        str(worker_path),
        "--role",
        role,
        "--config",
        str(config_path),
        "--config-sha256",
        config_sha256,
        "--",
        *args,
    ]


def _no_profiles(value):
    if type(value) is dict:
        for key, child in value.items():
            if "profile" in key.lower():
                raise ValueError("profile-declared registration cannot be instrumented")
            _no_profiles(child)
    elif type(value) is list:
        for child in value:
            _no_profiles(child)


def stage(fixture, *, run_id, arm_id):
    """Root-stage test code, using only existing private role directories for traces."""
    if os.geteuid() != 0:
        raise RuntimeError("Root test bootstrap required")
    registration = json.loads(fixture.registration.read_bytes())
    _no_profiles(registration)
    if (
        registration.get("schema_version") != "outcome-live-origin-registration/v1"
        or fixture.p.data["schema_version"] != "outcome-input-trust/v3"
    ):
        raise ValueError("only existing fresh v3 cost-lab profile is supported")
    bootstrap = fixture.root / "phase-bootstrap"
    bootstrap.mkdir(mode=0o755)
    payloads = {
        name: (ROOT / "tests" / "real_systemd" / name).read_bytes()
        for name in (WORKER, RECORDER)
    }
    for name, raw in payloads.items():
        path = bootstrap / name
        with path.open("xb") as stream:
            stream.write(raw)
        path.chmod(0o444)
    worker = bootstrap / WORKER
    metadata = dict(
        run_id=run_id,
        arm=arm_id,
        input_sha256=digest(original.TRANSCRIPT),
        code_sha256=_sha(payloads[WORKER] + b"\0" + payloads[RECORDER]),
        core_sha256=registration["binary_sha256"],
        interpreter_sha256=_sha(Path(sys.executable).resolve().read_bytes()),
    )
    traces = dict(
        signer=str(fixture.pk.parent / "phase-signer.jsonl"),
        observer=str(
            Path(fixture.p.data["journal_directory"]) / "phase-observer.jsonl"
        ),
        witness=str(fixture.wk.parent / "phase-witness.jsonl"),
    )
    config = dict(
        schema_version="edge-phase-timing-config/v1",
        metadata=metadata,
        registration_path=str(fixture.registration),
        policy_path=str(fixture.policy_file),
        traces=traces,
        worker_path=str(worker),
        worker_sha256=_sha(payloads[WORKER]),
    )
    config_path = bootstrap / "config.json"
    with config_path.open("xb") as stream:
        stream.write(_wire(config))
    config_path.chmod(0o444)
    bootstrap.chmod(0o555)
    return dict(
        config=config,
        config_path=config_path,
        config_sha256=_sha(_wire(config)),
        worker_path=worker,
        traces={
            **traces,
            "controller": str(fixture.wk.parent / "phase-controller.jsonl"),
        },
    )


class ObservedProcess:
    def __init__(self, process, recorder):
        self.process, self.recorder = process, recorder

    def __getattr__(self, name):
        return getattr(self.process, name)

    def wait(self, *args, **kwargs):
        return self.recorder.call(
            "observer_stop_wait", self.process.wait, *args, operation="wait", **kwargs
        )


@contextmanager
def instrumented_arm(*, run_id, arm_id):
    """Hooks live on the imported lab modules and are restored on every exit."""
    from real_systemd.signed_network_phase_recording import (
        PhaseRecording,
        record_witness,
    )

    state = dict(
        staged=None,
        controller=None,
        witness=None,
        proc_samples=[],
        store_calls=0,
        boot_id=None,
    )
    saved_register, saved_run = original.register_live, original.Run
    saved_store, saved_wait, saved_events = (
        original.store_bytes,
        original.wait,
        original.events,
    )
    saved_subprocess = original.subprocess
    run_module = sys.modules[saved_run.__module__]
    with ExitStack() as stack:

        def registered(fixture):
            result = saved_register(fixture)
            staged = stage(fixture, run_id=run_id, arm_id=arm_id)
            state["staged"] = staged
            state["boot_id"] = (
                Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            )
            metadata = staged["config"]["metadata"]
            state["controller"] = PhaseRecording(
                staged["traces"]["controller"],
                metadata={**metadata, "role": "controller"},
            )
            state["witness"] = PhaseRecording(
                staged["traces"]["witness"], metadata={**metadata, "role": "witness"}
            )
            stack.enter_context(record_witness(state["witness"]))
            return result

        def command(argv, role):
            if state["staged"] is None:
                raise RuntimeError("phase worker was not staged")
            return worker_command(
                argv,
                role=role,
                **{
                    name: state["staged"][name]
                    for name in ("config_path", "config_sha256", "worker_path")
                },
            )

        class PhaseRun(saved_run):
            def __init__(self, fixture):
                real = run_module.subprocess

                def popen(argv, *args, **kwargs):
                    return real.Popen(command(argv, "launcher"), *args, **kwargs)

                with patch.object(
                    run_module, "subprocess", ForwardingModule(real, Popen=popen)
                ):
                    super().__init__(fixture)

            def stop(self):
                return state["controller"].call(
                    "source_closure_wait", super().stop, operation="wait"
                )

        def observer_popen(argv, *args, **kwargs):
            process = saved_subprocess.Popen(command(argv, "observer"), *args, **kwargs)
            return ObservedProcess(process, state["controller"])

        def store(root):
            if state["store_calls"] == 0:
                state["proc_samples"].append(process_sample(os.getpid()))
            result = saved_store(root)
            state["store_calls"] += 1
            if state["store_calls"] == 2:
                points = state["proc_samples"]
                points.append(
                    process_sample(os.getpid(), expected_start=points[0]["start_ticks"])
                )
            return result

        def wait(*args, **kwargs):
            return state["controller"].call(
                "controller_wait",
                saved_wait,
                *args,
                operation="poll_detection",
                **kwargs,
            )

        def events(*args, **kwargs):
            return state["controller"].call(
                "controller_wait",
                saved_events,
                *args,
                operation="signed_source_detection",
                **kwargs,
            )

        for name, replacement in dict(
            register_live=registered,
            Run=PhaseRun,
            subprocess=ForwardingModule(saved_subprocess, Popen=observer_popen),
            store_bytes=store,
            wait=wait,
            events=events,
        ).items():
            stack.enter_context(patch.object(original, name, replacement))
        normal = False
        try:
            yield state
            normal = True
        finally:
            for name in ("controller", "witness"):
                if state[name] is not None:
                    state[name].close(normal_return=normal)


def _reports(state, mode, original_cost_report=None):
    reports, artifacts = {}, {}
    staged = state["staged"]
    metadata = staged["config"]["metadata"]
    for role, path in staged["traces"].items():
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            artifacts[role] = dict(path=path, sha256=_sha(raw), bytes=len(raw))
        except FileNotFoundError:
            raw, artifacts[role] = None, None
        expected = {**metadata, "role": role}
        processes = (original_cost_report or {}).get("processes", {})
        final = processes.get(role, {}).get("final")
        if role in ("controller", "witness") and state.get("proc_samples"):
            final = state["proc_samples"][0]
        if (
            final
            and type(final.get("pid")) is int
            and type(final.get("start_ticks")) is int
            and state.get("boot_id")
        ):
            expected.update(
                pid=final["pid"],
                start_ticks=final["start_ticks"],
                boot_id=state["boot_id"],
            )
        reports[role] = analyze_trace(raw, expected=expected)
        recorder = state.get(role) if role in ("controller", "witness") else None
        if recorder is not None and recorder.incomplete:
            reports[role]["status"] = "partial_prefix"
            reports[role]["normal_return_confirmed"] = False
            reports[role]["reasons"].append("external_recorder_incomplete")
            for phase in reports[role]["phases"].values():
                phase["coverage"] = "partial_prefix"
        if role == "observer" and mode == "off":
            reports[role]["reasons"].append("observer_absent_in_off_arm")
    return reports, artifacts


def phase_checks(reports, mode):
    missing = []
    for role, phases in REQUIRED_PHASES.items():
        if role == "observer" and mode == "off":
            continue
        required = phases + (
            ("observer_stop_wait",) if role == "controller" and mode != "off" else ()
        )
        for phase in required:
            if role == "witness" and phase == "witness_request" and mode == "off":
                continue
            statistics = (
                reports.get(role, {}).get("phases", {}).get(phase, {}).get("elapsed_ns")
            )
            if not statistics or statistics.get("observed_calls", 0) < 1:
                missing.append(role + "." + phase)
    roles = ("signer", "witness", "controller") + (
        ("observer",) if mode != "off" else ()
    )
    partial = any(
        not reports.get(role, {}).get("normal_return_confirmed", False)
        for role in roles
    )
    invalid = [
        role
        for role in roles
        if any(
            reason != "normal_return_not_recorded"
            for reason in reports.get(role, {}).get("reasons", [])
        )
    ]
    return dict(
        phase_collection_status="incomplete"
        if missing or invalid
        else "required_phase_calls_observed",
        missing_required_phase_calls=missing,
        invalid_phase_trace_roles=invalid,
        phase_trace_status="partial_or_unavailable" if partial else "complete",
    )


def functional_phase_gate(arm, *, six_arm_semantic_parity):
    """Recognize one planned fault prefix without completing its missing timing."""
    rejected = dict(accepted=False, status="incomplete_required_phase_evidence")
    if six_arm_semantic_parity is not True or arm.get("instrumented") is not True:
        return rejected
    phases, mode = arm.get("phase_reports", {}), arm.get("mode")
    checks = phase_checks(phases, mode)
    if (
        checks["phase_collection_status"] == "required_phase_calls_observed"
        and arm.get("phase_collection_status") == "required_phase_calls_observed"
    ):
        return dict(accepted=True, status="required_phase_calls_observed")
    if (
        arm.get("arm_id") != "instrumented_faulted"
        or mode != "faulted"
        or arm.get("phase_collection_status") != "incomplete"
        or arm.get("missing_required_phase_calls") != ["observer.observation"]
        or checks["missing_required_phase_calls"] != ["observer.observation"]
        or arm.get("invalid_phase_trace_roles") != []
        or checks["invalid_phase_trace_roles"] != []
    ):
        return rejected
    report = arm.get("original_cost_report", {})
    for key, expected in dict(
        observer_input_records=3,
        observer_exit=-9,
        observer_unprocessed_decisions=2,
        expected_decisions=3,
        native_decisions=3,
        signed_decisions=3,
    ).items():
        if type(report.get(key)) is not int or report[key] != expected:
            return rejected
    observer = phases.get("observer", {})
    if (
        observer.get("status") != "partial_prefix"
        or observer.get("normal_return_confirmed") is not False
        or observer.get("reasons") != ["normal_return_not_recorded"]
    ):
        return rejected
    observation = observer.get("phases", {}).get("observation", {})
    if any(
        observation.get(key) is not None
        for key in ("elapsed_ns", "process_cpu_ns", "thread_cpu_ns")
    ):
        return rejected
    intents = observer.get("pending_span_intents")
    if type(intents) is not list:
        return rejected
    by_id = {}
    for intent in intents:
        if type(intent) is not dict or set(intent) != {"span_id", "parent_id", "phase"}:
            return rejected
        identifier, parent = intent["span_id"], intent["parent_id"]
        if (
            type(identifier) is not int
            or identifier < 1
            or identifier in by_id
            or not (parent is None or type(parent) is int and parent > 0)
        ):
            return rejected
        by_id[identifier] = intent
    pending = observer.get("pending_spans")
    if type(pending) is not list or sorted(by_id) != pending:
        return rejected
    completed = observer.get("complete_spans", [])
    if any(span.get("phase") == "observation" for span in completed):
        return rejected
    for span in completed:
        if span.get("phase") != "journal_fsync" or span.get("outcome") != "returned":
            continue
        append = by_id.get(span.get("parent_id"), {})
        outer = by_id.get(append.get("parent_id"), {})
        if (
            append.get("phase") == "journal_append"
            and outer.get("phase") == "observation"
            and outer.get("parent_id") is None
        ):
            return dict(
                accepted=True, status="intended_fault_interruption_prefix_observed"
            )
    return rejected


def run(*, keep=False):
    fixtures, arms, progress = [], [], {}
    try:
        return _run(keep=keep, fixtures=fixtures, arms=arms, progress=progress)
    except BaseException as exc:
        partial = dict(
            schema_version="edge-observer-phase-cost-failure/v1",
            status="failed",
            arms=deepcopy(arms),
            blocker=type(exc).__name__,
            preserved_fixtures=[str(fixture.root) for fixture in fixtures],
        )
        state = progress.get("state")
        if state and state.get("staged"):
            try:
                reports, artifacts = _reports(state, progress["mode"])
                partial["active_arm"] = dict(
                    arm_id=progress["arm_id"],
                    phase_reports=reports,
                    phase_artifacts=artifacts,
                )
            except Exception as trace_exc:
                partial["active_trace_blocker"] = type(trace_exc).__name__
        exc.phase_cost_preserved_fixtures = partial["preserved_fixtures"]
        exc.phase_cost_partial_report = partial
        raise


def _run(*, keep, fixtures, arms, progress):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("isolated Linux Root required")
    run_id = uuid.uuid4().hex
    for arm_id in ARM_ORDER:
        instrumented = arm_id.startswith("instrumented_")
        mode = arm_id.split("_", 1)[1]
        progress.update(arm_id=arm_id, mode=mode, state=None)
        if instrumented:
            with instrumented_arm(run_id=run_id, arm_id=arm_id) as state:
                progress["state"] = state
                report = original.arm(mode, fixtures=fixtures)
            phases, artifacts = _reports(state, mode, report)
            controller = process_summary(
                state["proc_samples"], report["ticks_per_second"]
            )
            controller["scope"] = "mixed_controller_harness_witness_and_instrumentation"
            checks = phase_checks(phases, mode)
        else:
            report = original.arm(mode, fixtures=fixtures)
            phases, artifacts, controller = {}, {}, None
            checks = dict(
                phase_collection_status="not_instrumented",
                missing_required_phase_calls=[],
                phase_trace_status="not_instrumented",
            )
        arms.append(
            dict(
                arm_id=arm_id,
                mode=mode,
                instrumented=instrumented,
                original_cost_report=report,
                phase_reports=phases,
                phase_artifacts=artifacts,
                controller_process_metrics=controller,
                **checks,
            )
        )
    if (
        len({arm["original_cost_report"]["input_sha256"] for arm in arms}) != 1
        or len({arm["original_cost_report"]["semantic_sha256"] for arm in arms}) != 1
    ):
        raise RuntimeError(
            "six-arm exact input/decision parity failed; all fixtures retained"
        )
    result = analyze_cost_arms(arms)
    for arm in result["arms"]:
        if arm["instrumented"]:
            arm["functional_phase_gate"] = functional_phase_gate(
                arm, six_arm_semantic_parity=result["six_arm_semantic_parity"]
            )
    result["functional_phase_status"] = (
        "functional_phase_evidence_observed"
        if all(
            arm.get("functional_phase_gate", {}).get("accepted") is True
            for arm in result["arms"]
            if arm["instrumented"]
        )
        else "incomplete"
    )
    instrumented = [arm for arm in arms if arm["instrumented"]]
    result["phase_collection_status"] = (
        "required_phase_calls_observed"
        if all(
            arm["phase_collection_status"] == "required_phase_calls_observed"
            for arm in instrumented
        )
        else "incomplete"
    )
    result["preserved_fixtures"] = [str(fixture.root) for fixture in fixtures]
    result["provenance"] = dict(
        run_id=run_id,
        fixed_order=list(ARM_ORDER),
        source_head=_source_identity(),
        python=sys.version,
        controller_poll_ns=20_000_000,
        native_poll_ns=10_000_000,
        observer_poll_ns=50_000_000,
        sample_interval_ns=50_000_000,
        trace_row_bound=4096,
        trace_byte_bound=MAX_BYTES,
    )
    result["limitations"] = [
        "fixed sequential three-alert functional pilot; descriptive costs only",
        "instrumented arm costs include test bootstrap and trace writes",
        "witness shares controller process; only witness thread CPU is separately observed",
        "controller polling is upper detection wait, not exact event-edge timing",
        "empty stale policy exercises no-op finalization calls; active deadline wait unmeasured",
        "original signals preserved; terminated observers may retain incomplete valid trace prefixes",
        "5ms, 98percent and 1.2x gates unchanged; no causal or production qualification",
    ]
    if not keep and all(
        arm["phase_collection_status"] == "required_phase_calls_observed"
        and arm["phase_trace_status"] == "complete"
        for arm in instrumented
    ):
        for fixture in fixtures:
            fixture.clean()
        result["preserved_fixtures"] = []
    return result


def export_public(result, output_dir):
    """Export only the report and exact declared bounded role trace originals."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    exported = deepcopy(result)
    items = list(exported.get("arms", []))
    if exported.get("active_arm"):
        items.append(exported["active_arm"])
    # Write the original result first so an export failure still retains its blocker.
    with (output_dir / "report.json").open("xb") as stream:
        stream.write(_wire(exported))
    for arm in items:
        arm_id = arm["arm_id"]
        if arm_id not in ARM_ORDER:
            raise ValueError("undeclared export arm")
        for role, descriptor in arm.get("phase_artifacts", {}).items():
            if role not in ("signer", "observer", "witness", "controller"):
                raise ValueError("undeclared export role")
            if descriptor is None:
                continue
            with Path(descriptor["path"]).open("rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
            if (
                len(raw) > MAX_BYTES
                or len(raw) != descriptor["bytes"]
                or _sha(raw) != descriptor["sha256"]
            ):
                raise ValueError("role trace changed or exceeds export bound")
            target = output_dir / (arm_id + "-" + role + ".jsonl")
            with target.open("xb") as stream:
                stream.write(raw)
    return output_dir


def _source_identity():
    try:
        completed = original.subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, original.subprocess.SubprocessError):
        return None
    return completed.stdout.strip() if completed.returncode == 0 else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-isolated-linux-root", action="store_true", required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("new report path required before trial")
    result = run(keep=True)
    with args.output.open("xb") as stream:
        stream.write(_wire(result))
    print(
        json.dumps(
            dict(
                report=str(args.output),
                six_arm_semantic_parity=result["six_arm_semantic_parity"],
            )
        )
    )


if __name__ == "__main__":
    main()
