"""End-to-end golden replay for Outcome-as-Evidence (G5).

Replays a *recorded* timeline through the existing evidence path

    Decision -> Execution -> Mechanism -> Release -> Outcome -> Effect

and returns a deterministic transcript that tests compare with a golden file.

Replay boundary (locked):

- input is data only: recorded Rust event-engine / release-engine records,
  recorded procfs telemetry samples and recorded read-only tc/nft readback;
- no subprocess, no socket, no procfs read, no wall clock, no file write;
- nothing here can decide, execute, retry, release or authorize an action. The
  recorded Rust ``defense``/``enforcement`` objects are evidence, not re-decided;
- the per-boot collector is discarded at a recorded restart, exactly like the
  live process; Outcome identity/deduplication across restarts uses
  :class:`OutcomeIdentityLedger`, whose state is carried through a JSON round
  trip to prove it survives a restart.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .adapter import from_rust_event
from .assessment import assess_tactical_effect
from .contracts import (
    ActionExecutionReceipt,
    ActionLifecycle,
    AppliedMechanism,
    ExecutionStatus,
    MechanismStatus,
    TacticalEffectAssessment,
)
from .outcome_identity import OutcomeIdentityLedger, outcome_identity_key
from .ownership import verify_mechanism_postcondition
from .postcondition import ReadOnlyCommandResult, _is_allowed_read_only_query
from .release_evidence import from_rust_release_event, reconcile_release_evidence
from .replay import ReplayExecutionProvider
from .telemetry import OutcomeTelemetryCollector, OutcomeTelemetryPolicy, TelemetrySample

INPUT_SCHEMA_VERSION = "outcome-golden-replay-input/v1"
RESULT_SCHEMA_VERSION = "outcome-golden-replay-result/v1"
_RELEASE_PIPELINE = "rust_release_engine_v1"


class GoldenReplayError(RuntimeError):
    """The recorded fixture is inconsistent. Never swallowed by evidence code."""


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _epoch(step: Mapping[str, Any]) -> float:
    value = step.get("epoch")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise GoldenReplayError(f"step requires a non-negative numeric epoch: {step.get('op')!r}")
    return float(value)


class RecordedTelemetrySource:
    """Telemetry source that only returns the recorded sample for the exact epoch."""

    def __init__(self) -> None:
        self._next: TelemetrySample | None = None

    def load(self, sample: TelemetrySample) -> None:
        self._next = sample

    def sample(self, *, interface: str, epoch: float) -> TelemetrySample:
        recorded, self._next = self._next, None
        if recorded is None or recorded.epoch != epoch or recorded.interface != interface:
            raise GoldenReplayError("collector requested a sample that was not recorded")
        return recorded


class RecordedProbeRunner:
    """Read-only runner that returns recorded tc/nft readback; it never runs a process."""

    def __init__(self, results: Sequence[Mapping[str, Any]]) -> None:
        self._results: dict[tuple[str, ...], ReadOnlyCommandResult] = {}
        for raw in results:
            argv = tuple(str(value) for value in raw.get("argv") or ())
            if not _is_allowed_read_only_query(argv):
                raise GoldenReplayError(f"recorded probe is outside the read-only allowlist: {argv!r}")
            stdout = raw.get("stdout_json")
            self._results[argv] = ReadOnlyCommandResult(
                argv=argv,
                returncode=int(raw.get("returncode", 0)),
                stdout=json.dumps(stdout, separators=(",", ":")) if stdout is not None else str(raw.get("stdout") or ""),
                stderr=str(raw.get("stderr") or ""),
            )
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_seconds: float) -> ReadOnlyCommandResult:
        args = tuple(str(value) for value in argv)
        self.calls.append(args)
        if args not in self._results:
            raise GoldenReplayError(f"probe readback was not recorded: {args!r}")
        return self._results[args]


@dataclass
class _DecisionTrace:
    decision_id: str
    first_boot: str
    action: str
    stages: dict[str, Any]
    execution: ActionExecutionReceipt
    mechanism: AppliedMechanism
    mechanism_for_assessment: AppliedMechanism
    deliveries: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        stages = dict(self.stages)
        stages["execution_final"] = self.execution.to_dict()
        stages["mechanism_final"] = self.mechanism.to_dict()
        return {
            "decision_id": self.decision_id,
            "first_boot": self.first_boot,
            "action": self.action,
            "deliveries": list(self.deliveries),
            "notes": list(self.notes),
            "stages": stages,
        }


def _decision_stage(event: Mapping[str, Any], decision_id: str) -> dict[str, Any]:
    defense = event.get("defense") if isinstance(event.get("defense"), Mapping) else {}
    normalized = event.get("normalized") if isinstance(event.get("normalized"), Mapping) else {}
    return {
        "decision_id": decision_id,
        "authority": "recorded_rust_decide_defense",
        "action": str(defense.get("action") or ""),
        "target": defense.get("target"),
        "policy_reason": defense.get("policy_reason"),
        "decided_at": str(normalized.get("ts") or ""),
    }


def _sample(step: Mapping[str, Any], *, interface: str, boot: str) -> TelemetrySample:
    epoch = _epoch(step)
    coverage = step.get("coverage") or {
        "proc_net_dev": True,
        "proc_loadavg": True,
        "proc_meminfo": True,
        "proc_uptime": True,
    }
    return TelemetrySample(
        epoch=epoch,
        observed_at=_iso(epoch),
        interface=interface,
        network=dict(step.get("network") or {}),
        system=dict(step.get("system") or {}),
        coverage=dict(coverage),
        evidence_ref=str(step.get("evidence_ref") or f"recorded-sample:{boot}:{epoch:.3f}"),
    )


def _stable_effect_id(assessment: TacticalEffectAssessment) -> str:
    raw = "\x1f".join((assessment.outcome_id, assessment.objective_id, assessment.tactical_effect))
    return f"effect-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def run_golden_replay(fixture: Mapping[str, Any]) -> dict[str, Any]:
    """Replay a recorded fixture and return the deterministic transcript."""

    if fixture.get("schema_version") != INPUT_SCHEMA_VERSION:
        raise GoldenReplayError("unsupported golden replay input schema")
    interface = str(fixture.get("interface") or "")
    sample_interval = float(fixture.get("sample_interval_seconds") or 1.0)
    policy = OutcomeTelemetryPolicy.from_mapping(fixture["policy"], source_ref="golden-replay")
    tactical_effects = {str(k).lower(): str(v) for k, v in (fixture.get("tactical_effects") or {}).items()}
    max_identities = int(fixture.get("max_outcome_identities") or 4096)

    traces: dict[str, _DecisionTrace] = {}
    ledger_state = OutcomeIdentityLedger(max_identities=max_identities).to_dict()
    admissions: list[dict[str, Any]] = []
    restart_gaps: list[dict[str, Any]] = []
    rejected_inputs: list[dict[str, Any]] = []
    activity_only = 0
    redelivered_windows = 0
    boots_seen: list[str] = []

    for boot_index, boot in enumerate(fixture.get("boots") or ()):
        boot_id = str(boot.get("boot") or f"boot-{boot_index + 1}")
        if boot_id in boots_seen:
            raise GoldenReplayError("boot ids must be unique")
        boots_seen.append(boot_id)
        # A restart loses all in-memory collector state; only the durable
        # ledger state (round-tripped through JSON) survives.
        ledger = OutcomeIdentityLedger.from_mapping(
            json.loads(json.dumps(ledger_state)), max_identities=max_identities
        )
        source = RecordedTelemetrySource()
        collector = OutcomeTelemetryCollector(
            source=source,
            policy=policy,
            interface=interface,
            sample_interval_seconds=sample_interval,
        )

        for step in boot.get("steps") or ():
            op = str(step.get("op") or "")
            epoch = _epoch(step)
            if op == "sample":
                sample = _sample(step, interface=interface, boot=boot_id)
                source.load(sample)
                if collector.record_sample(epoch=epoch) is None:
                    raise GoldenReplayError("recorded sample was rejected by the collector")
            elif op == "event":
                event = step.get("event")
                if not isinstance(event, Mapping):
                    raise GoldenReplayError("event step requires an event object")
                if str(event.get("pipeline") or "") == _RELEASE_PIPELINE:
                    _replay_release(event, traces, rejected_inputs, boot_id)
                else:
                    activity_only += _replay_decision(event, traces, rejected_inputs, boot_id)
                collector.observe_event(event, observed_epoch=epoch)
            elif op == "probe":
                trace = traces.get(str(step.get("decision_id") or ""))
                if trace is None:
                    raise GoldenReplayError("probe step references an unknown decision")
                runner = RecordedProbeRunner(step.get("results") or ())
                if not _initial_postcondition_transition(trace):
                    # G1a only performs the first UNVERIFIED+ACTIVE transition;
                    # a later probe never re-opens observed/released state.
                    trace.notes.append(f"{boot_id}:probe_not_initial_transition_ignored")
                    continue
                verified = verify_mechanism_postcondition(
                    execution=trace.execution,
                    mechanism=trace.mechanism,
                    runner=runner,
                    observed_at=str(step.get("observed_at") or _iso(epoch)),
                )
                trace.stages["mechanism_postcondition"] = verified.to_dict()
                trace.mechanism = verified
                trace.mechanism_for_assessment = verified
            elif op == "finalize":
                for outcome in collector.finalize_due(epoch=epoch):
                    admission = ledger.admit(outcome)
                    admissions.append({"boot": boot_id, "decision_id": outcome.decision_id, **admission.to_dict()})
                    trace = traces.get(outcome.decision_id)
                    if trace is None:
                        raise GoldenReplayError("outcome produced for an unknown decision")
                    if not admission.counted:
                        trace.notes.append(f"{boot_id}:outcome_{admission.status.value}")
                        continue
                    objective = policy.objective_for(trace.action, outcome.decision_id)
                    if objective is None or objective.objective_id != outcome.objective_id:
                        raise GoldenReplayError("outcome objective is not the policy objective")
                    if trace.first_boot != boot_id:
                        # Current G3 semantics: a record re-delivered after a
                        # restart opens a window at the new receipt time. The
                        # ledger only dedups identities already admitted, so
                        # an Outcome lost at restart is admitted here with
                        # post-restart telemetry. Flag it; do not hide it.
                        trace.notes.append(f"{boot_id}:outcome_window_from_post_restart_redelivery")
                        redelivered_windows += 1
                    trace.stages["objective"] = objective.to_dict()
                    trace.stages["outcome"] = outcome.to_dict()
                    trace.stages["outcome_identity_key"] = admission.identity_key
                    effect = assess_tactical_effect(
                        mechanism=trace.mechanism_for_assessment,
                        objective=objective,
                        outcome=outcome,
                        tactical_effect=tactical_effects.get(trace.action, "UNSPECIFIED"),
                    )
                    effect = replace(effect, effect_assessment_id=_stable_effect_id(effect))
                    trace.stages["effect"] = effect.to_dict()
            else:
                raise GoldenReplayError(f"unsupported replay step: {op!r}")

        for execution_id, pending in sorted(collector.pending.items()):
            restart_gaps.append(
                {
                    "boot": boot_id,
                    "decision_id": pending.decision_id,
                    "execution_id": execution_id,
                    "outcome_identity_key": outcome_identity_key(
                        execution_id=execution_id, objective_id=pending.objective.objective_id
                    ),
                    "reason": "pending_observation_lost_at_restart",
                }
            )
            trace = traces.get(pending.decision_id)
            if trace is not None:
                trace.notes.append(f"{boot_id}:pending_observation_lost_at_restart")
        ledger_state = ledger.to_dict()

    for trace in traces.values():
        trace.stages.setdefault("outcome", None)
        trace.stages.setdefault("effect", None)

    replay_provider = ReplayExecutionProvider.from_records(trace.execution for trace in traces.values())
    counted = sum(1 for item in admissions if item["status"] == "admitted")
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "fixture_id": str(fixture.get("fixture_id") or ""),
        "boots": boots_seen,
        "decisions": [trace.to_dict() for trace in traces.values()],
        "outcome_admissions": admissions,
        "outcome_ledger": ledger_state,
        "restart_gaps": restart_gaps,
        "rejected_inputs": rejected_inputs,
        "summary": {
            "decisions": len(traces),
            "activity_only_events": activity_only,
            "outcomes_produced": len(admissions),
            "outcomes_counted": counted,
            "outcomes_counted_from_post_restart_redelivery": redelivered_windows,
            "replay_execution_records": len(replay_provider.records),
        },
    }


def _initial_postcondition_transition(trace: _DecisionTrace) -> bool:
    return (
        trace.execution.status is ExecutionStatus.APPLIED
        and trace.execution.lifecycle is ActionLifecycle.ACTIVE
        and trace.mechanism.status is MechanismStatus.UNVERIFIED
    )


def _replay_decision(
    event: Mapping[str, Any],
    traces: dict[str, _DecisionTrace],
    rejected_inputs: list[dict[str, Any]],
    boot_id: str,
) -> int:
    try:
        bundle = from_rust_event(event)
    except (TypeError, ValueError) as exc:
        rejected_inputs.append({"boot": boot_id, "kind": "rust_event", "error": type(exc).__name__})
        return 0
    if bundle.execution.action_kind == "observe":
        # Activity-only evidence: consumed by the collector for pre/post
        # windows, not a disruptive decision under replay.
        return 1
    decision_id = bundle.execution.decision_id
    existing = traces.get(decision_id)
    if existing is not None:
        existing.deliveries.append(boot_id)
        if existing.stages["execution"] != bundle.execution.to_dict():
            existing.notes.append(f"{boot_id}:conflicting_redelivery_ignored")
        else:
            existing.notes.append(f"{boot_id}:identical_redelivery_ignored")
        return 0
    traces[decision_id] = _DecisionTrace(
        decision_id=decision_id,
        first_boot=boot_id,
        action=bundle.execution.action_kind,
        stages={
            "decision": _decision_stage(event, decision_id),
            "correlation": {
                "incident_id": bundle.correlation.incident_id,
                "decision_id": bundle.correlation.decision_id,
                "action_id": bundle.correlation.action_id,
                "execution_id": bundle.correlation.execution_id,
                "mechanism_id": bundle.correlation.mechanism_id,
            },
            "execution": bundle.execution.to_dict(),
            "mechanism": bundle.mechanism.to_dict(),
            "mechanism_postcondition": None,
            "release": [],
        },
        execution=bundle.execution,
        mechanism=bundle.mechanism,
        mechanism_for_assessment=bundle.mechanism,
        deliveries=[boot_id],
    )
    return 0


def _replay_release(
    event: Mapping[str, Any],
    traces: dict[str, _DecisionTrace],
    rejected_inputs: list[dict[str, Any]],
    boot_id: str,
) -> None:
    try:
        release = from_rust_release_event(event)
    except (TypeError, ValueError) as exc:
        rejected_inputs.append({"boot": boot_id, "kind": "release_event", "error": type(exc).__name__})
        return
    trace = traces.get(release.decision_id)
    if trace is None:
        rejected_inputs.append({"boot": boot_id, "kind": "release_event", "error": "unknown_decision"})
        return
    record: dict[str, Any] = {"boot": boot_id, "evidence": release.to_dict()}
    try:
        execution, mechanism = reconcile_release_evidence(
            execution=trace.execution, mechanism=trace.mechanism, release=release
        )
    except ValueError as exc:
        record["reconciliation"] = f"rejected:{exc}"
    else:
        changed = execution.status is not trace.execution.status
        record["reconciliation"] = "released" if changed else "no_change"
        trace.execution, trace.mechanism = execution, mechanism
    trace.stages["release"].append(record)
