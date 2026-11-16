"""SYNTHETIC nonempty windows using original collector/close calls, never native APPLIED."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import threading

import pytest

from azazel_edge.benchmark.timing_cost_attribution import analyze_trace
from azazel_edge.outcome import input_resume, telemetry
from azazel_edge.outcome.journal import NAME, _json
from test_outcome_control_stop import Lab
from test_outcome_telemetry_g3 import rust_event
from real_systemd import signed_network_phase_recording as recording

EVIDENCE = "SYNTHETIC_RECORDED_TEST_ONLY"
PREMISE = "synthetic_fixture_not_observed_native_action"
BOOT = "00000000-0000-4000-8000-000000000001"
PROTOCOL = Path(__file__).parent / "fixtures/window-cost-completion/v1/protocol.json"
MAX_ARTIFACT = 4 * 1024 * 1024


def wire(value):
    return _json(value) + b"\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _descriptor(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("synthetic artifact symlink")
    with path.open("rb") as stream:
        raw = stream.read(MAX_ARTIFACT + 1)
    if len(raw) > MAX_ARTIFACT:
        raise ValueError("synthetic artifact exceeds bound")
    return dict(path=str(path), sha256=sha(raw), bytes=len(raw))


def _identity():
    # Explicit SYNTHETIC process incarnation/domain, including on non-Linux hosts.
    return dict(
        pid=os.getpid(),
        start_ticks=1,
        native_tid=threading.get_native_id(),
        boot_id=BOOT,
        clock_domain=dict(
            time_namespace_device=None,
            time_namespace_inode=None,
            timens_offsets=None,
            established=False,
        ),
        clock_ticks_per_second=100,
        clock_resolutions=dict(monotonic=1e-9, process_time=1e-9, thread_time=1e-9),
    )


def _case(work, recipe):
    identifier = recipe["id"]
    directory = Path(work) / identifier
    directory.mkdir(mode=0o700)
    phase_path = directory / "phase.jsonl"
    event = rust_event(
        ts=datetime.fromtimestamp(110, timezone.utc).isoformat(), trace=identifier
    )
    event_raw = wire(event)
    metadata = dict(
        run_id="synthetic-window-cases",
        arm="instrumented_on",
        role="observer",
        input_sha256=sha(event_raw),
        code_sha256=sha(Path(__file__).read_bytes()),
        core_sha256="0" * 64,
        interpreter_sha256=sha(Path(sys.executable).resolve().read_bytes()),
    )
    receipt = None
    outcomes = []
    callback_log = []
    error = None
    with pytest.MonkeyPatch.context() as patches:
        lab = Lab(directory, patches)
        lab.policy_file.write_bytes(
            wire(
                dict(
                    schema_version=telemetry.POLICY_SCHEMA_VERSION,
                    policy_version="SYNTHETIC-window-fixture",
                    actions={
                        "throttle": dict(
                            metric="source_ip_event_rate_hz",
                            direction="decrease",
                            target_or_range={},
                            observation_window=dict(pre_seconds=3.0, post_seconds=3.0),
                            guardrails=[],
                        )
                    },
                )
            )
        )
        original_collector = input_resume.OutcomeTelemetryCollector

        class RetainedCollector(original_collector):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                lab.collector = self

        patches.setattr(input_resume, "OutcomeTelemetryCollector", RetainedCollector)
        patches.setattr(recording, "_identity", _identity)
        recorder = recording.PhaseRecording(
            phase_path,
            metadata=metadata,
            max_rows=6 if identifier == "recording_failure_prefix" else 4096,
        )

        def stop_after_synthetic_case():
            collector = lab.collector
            for epoch in (107.0, 108.0, 109.0):
                collector.record_sample(epoch=epoch)
            accepted = collector.observe_event(event, observed_epoch=110.0)
            callback_log.append(
                dict(operation="observe_event", returned=accepted, supplied_epoch=110.0)
            )
            if identifier == "duplicate_does_not_reopen":
                duplicate = collector.observe_event(event, observed_epoch=110.1)
                callback_log.append(
                    dict(
                        operation="duplicate_observe_event",
                        returned=duplicate,
                        supplied_epoch=110.1,
                    )
                )
            before = collector.finalize_due(epoch=112.999)
            callback_log.append(
                dict(
                    operation="finalize_before_deadline",
                    returned_count=len(before),
                    supplied_epoch=112.999,
                )
            )
            if identifier in (
                "expiry_commit",
                "duplicate_does_not_reopen",
                "commit_failure_loss",
                "recording_failure_prefix",
            ):
                for epoch in (110.5, 111.5, 112.5, 113.0):
                    collector.record_sample(epoch=epoch)
                if identifier == "commit_failure_loss":

                    def failed_commit(record):
                        raise OSError("SYNTHETIC injected commit unavailability")

                    patches.setattr(lab.journal, "commit_outcome", failed_commit)
                returned = collector.finalize_due(epoch=113.0)
                callback_log.append(
                    dict(
                        operation="finalize_at_deadline",
                        returned_count=len(returned),
                        supplied_epoch=113.0,
                    )
                )
                outcomes.extend(record.to_dict() for record in returned)
            if identifier == "witness_close_failure":
                lab.close_fault = "write"
            return True

        try:
            with recording.record_observer(recorder):
                receipt = lab.run(stop_after_synthetic_case)
        except (OSError, ValueError, TypeError) as exc:
            if not hasattr(lab, "journal"):
                raise
            error = type(exc).__name__
        finally:
            recorder.close(normal_return=error is None)
        status = deepcopy(lab.journal.status())
        phase_raw = phase_path.read_bytes()
        phase_report = analyze_trace(phase_raw, expected=metadata)
        if recorder.incomplete:
            phase_report["status"] = "partial_prefix"
            phase_report["normal_return_confirmed"] = False
            phase_report["reasons"].append("external_recorder_incomplete")
        control = receipt.to_dict() if receipt is not None else None
        observations = dict(
            callback_log=callback_log,
            outcomes=outcomes,
            control_receipt=control,
            exception_type=error,
            final_journal_status=status,
            recorder_incomplete=recorder.incomplete,
            api_calls=list(lab.calls),
            synthetic_deadline_epoch=113.0,
            policy_source_ref=str(lab.policy_file),
        )
    files = dict(
        event=event_raw,
        policy=lab.policy_file.read_bytes(),
        observations=wire(observations),
    )
    for name, raw in files.items():
        target = directory / (name + ".json")
        with target.open("xb") as stream:
            stream.write(raw)
    artifacts = {name: _descriptor(directory / (name + ".json")) for name in files}
    artifacts.update(
        journal=_descriptor(lab.folder / NAME), phase=_descriptor(phase_path)
    )
    return dict(
        id=identifier,
        evidence_kind=EVIDENCE,
        applied_premise=PREMISE,
        expected_lifecycle=recipe["expected_lifecycle"],
        artifacts=artifacts,
        raw_sha256={
            name: descriptor["sha256"] for name, descriptor in artifacts.items()
        },
        phase_pins=metadata,
        phase_report=phase_report,
        process_metrics=None,
        observations=observations,
    )


def run_synthetic_window_cases(work):
    """Record fresh independent SYNTHETIC cases; never run an actual core/provider."""
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    protocol = json.loads(PROTOCOL.read_bytes())
    cases, blockers = [], []
    for recipe in protocol["cases"]:
        try:
            case = _case(work, recipe)
        except Exception as exc:
            identifier = recipe["id"]
            directory = work / identifier
            artifacts, collection_errors = {}, {}
            # Only declared PUBLIC synthetic outputs, never recursive traversal.
            paths = dict(event=directory / "event.json", policy=directory / "policy.json",
                         observations=directory / "observations.json", journal=directory / "journal" / NAME,
                         phase=directory / "phase.jsonl")
            for name, path in paths.items():
                try:
                    artifacts[name] = _descriptor(path)
                except (OSError, ValueError, TypeError) as read_error:
                    collection_errors[name] = type(read_error).__name__
            case = dict(id=identifier, evidence_kind=EVIDENCE, applied_premise=PREMISE,
                        expected_lifecycle=recipe["expected_lifecycle"],
                        case_error=type(exc).__name__, artifacts=artifacts,
                        raw_sha256={name: value["sha256"] for name, value in artifacts.items()},
                        collection_errors=collection_errors)
            blockers.append("synthetic_case_failed_" + identifier + "_" + type(exc).__name__)
        cases.append(case)
    result = dict(
        schema_version="edge-synthetic-window-lifecycle/v1",
        data_kind="SYNTHETIC",
        protocol_sha256=sha(PROTOCOL.read_bytes()),
        cases=cases,
        blockers=blockers,
    )
    with (work / "manifest.json").open("xb") as stream:
        stream.write(wire(result))
    return result
