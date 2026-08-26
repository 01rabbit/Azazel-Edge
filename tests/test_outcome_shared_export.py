from __future__ import annotations

from dataclasses import replace

import pytest

from azazel_edge.outcome.adapter import from_rust_event
from azazel_edge.outcome.contracts import (
    AppliedMechanism,
    EffectAssessmentStatus,
    EffectObjective,
    ExecutionStatus,
    MechanismKind,
    MechanismStatus,
    OutcomeAssessment,
    OutcomeRecord,
    TacticalEffectAssessment,
)
from azazel_edge.outcome.shared_export import (
    SharedOutcomeExportError,
    assessment_to_shared_v0,
    execution_to_shared_v0,
    mechanism_to_shared_v0,
    outcome_to_shared_v0,
)


def rust_event(action: str = "throttle") -> dict:
    commands = {
        "throttle": ["tc qdisc replace dev br0 root tbf rate 256kbit burst 32kbit latency 1000ms"],
        "redirect": ["nft insert rule inet azazel_edge prerouting ip saddr 10.0.0.8 tcp dport 22 redirect to 12222"],
    }
    return {
        "normalized": {
            "ts": "2026-08-26T00:00:00Z",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {"action": action, "target": "10.0.0.8", "policy_reason": "test"},
        "enforcement": {
            "mode": "enforced",
            "trace_id": "trace-test-1",
            "selected_action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
            "command_plan": commands.get(action, []),
            "rollback_plan": [],
            "executed_count": 1,
            "failed_count": 0,
            "errors": [],
            "result": "applied",
            "metadata": {},
        },
        "pipeline": "rust_event_engine_v1",
    }


def test_execution_export_is_shared_fact_not_effect_claim():
    bundle = from_rust_event(rust_event())
    payload = execution_to_shared_v0(bundle.correlation, bundle.execution, producer_node="edge-1")
    assert payload["schema_version"] == "outcome-execution/v0.1"
    assert payload["trace_id"] == "trace-test-1"
    assert payload["status"] == "applied"
    assert "effect_class" not in payload
    assert "tactical_effect" not in payload
    assert "command_plan" not in payload


def test_expired_execution_fails_closed_until_shared_contract_can_represent_it():
    bundle = from_rust_event(rust_event())
    expired = replace(bundle.execution, status=ExecutionStatus.EXPIRED)
    with pytest.raises(SharedOutcomeExportError, match="not representable"):
        execution_to_shared_v0(bundle.correlation, expired, producer_node="edge-1")


def test_mechanism_export_preserves_mechanism_not_tactical_effect():
    bundle = from_rust_event(rust_event())
    observed = replace(
        bundle.mechanism,
        status=MechanismStatus.OBSERVED,
        observed_parameters={"verification_basis": "independent_postcondition"},
    )
    payload = mechanism_to_shared_v0(bundle.correlation, observed, producer_node="edge-1")
    assert payload["mechanism_kind"] == "traffic_shaping"
    assert payload["status"] == "observed"
    assert "tactical_effect" not in payload


def test_internal_route_change_is_downgraded_to_unknown_not_invented():
    bundle = from_rust_event(rust_event())
    route = AppliedMechanism(
        mechanism_id=bundle.correlation.mechanism_id,
        execution_id=bundle.correlation.execution_id,
        decision_id=bundle.correlation.decision_id,
        mechanism_kind=MechanismKind.ROUTE_CHANGE,
        scope={"scope_kind": "route"},
        observed_parameters={},
        status=MechanismStatus.UNVERIFIED,
        observed_at="2026-08-26T00:00:01Z",
    )
    payload = mechanism_to_shared_v0(bundle.correlation, route, producer_node="edge-1")
    assert payload["mechanism_kind"] == "unknown"
    assert payload["limitations"] == ["internal_route_change_not_representable_in_shared_v0.1"]


def test_mechanism_free_form_cannot_smuggle_provider_command_or_tactical_claim():
    bundle = from_rust_event(rust_event())
    for field in ("provider-command", "effect_class", "tactical-effect", "success-rate"):
        unsafe = replace(bundle.mechanism, observed_parameters={"nested": {field: "value"}})
        with pytest.raises(SharedOutcomeExportError):
            mechanism_to_shared_v0(bundle.correlation, unsafe, producer_node="edge-1")


def _objective(decision_id: str) -> EffectObjective:
    return EffectObjective(
        decision_id=decision_id,
        metric="connection_latency_ms",
        direction="increase",
        target_or_range={"minimum_delta": 500},
        observation_window={"seconds": 30},
        policy_version="policy-v1",
        objective_id="objective-1",
    )


def _outcome(bundle, objective: EffectObjective) -> OutcomeRecord:
    return OutcomeRecord(
        incident_id=bundle.correlation.incident_id,
        decision_id=bundle.correlation.decision_id,
        execution_id=bundle.correlation.execution_id,
        mechanism_id=bundle.correlation.mechanism_id,
        objective_id=objective.objective_id,
        observation_window={
            "start": "2026-08-26T00:00:01Z",
            "end": "2026-08-26T00:00:31Z",
        },
        baseline_metrics={"connection_latency_ms": 100},
        post_metrics={"connection_latency_ms": 900},
        adversary_response={"retry_interval_ms": 1200},
        asset_impact={},
        noc_impact={"impact_score": 0},
        resource_impact={"cpu_delta": 0.1},
        operator_override={},
        termination_reason="window_complete",
        assessment=OutcomeAssessment.EFFECTIVE,
        telemetry_coverage={"baseline": 1.0, "post": 1.0},
        confounders=({"code": "source_ip_is_not_actor_identity"},),
        evidence_refs=("outcome:evidence:1",),
        observed_at="2026-08-26T00:00:31Z",
        outcome_id="outcome-1",
    )


def test_outcome_export_keeps_causality_and_tactical_verdict_out_of_fact_payload():
    bundle = from_rust_event(rust_event())
    objective = _objective(bundle.correlation.decision_id)
    outcome = _outcome(bundle, objective)
    correlation = replace(bundle.correlation, objective_id=objective.objective_id, outcome_id=outcome.outcome_id)
    payload = outcome_to_shared_v0(correlation, outcome, producer_node="edge-1")
    assert payload["schema_version"] == "outcome-observation/v0.1"
    assert payload["observation_values"]["baseline_metrics"]["connection_latency_ms"] == 100
    assert "causal_support" not in payload["observation_values"]
    assert "assessment" not in payload["observation_values"]
    assert payload["confounders"] == ["source_ip_is_not_actor_identity"]


def _assessment(bundle, objective: EffectObjective, outcome: OutcomeRecord) -> TacticalEffectAssessment:
    return TacticalEffectAssessment(
        outcome_id=outcome.outcome_id,
        mechanism_id=bundle.correlation.mechanism_id,
        objective_id=objective.objective_id,
        tactical_effect="DELAY",
        assessment=EffectAssessmentStatus.INCONCLUSIVE,
        confidence=None,
        reason_code="causal_support_inconclusive",
        evidence_refs=("outcome:evidence:1",),
        effect_assessment_id="effect-1",
    )


def test_tactical_assessment_exports_only_as_non_executable_assessment():
    bundle = from_rust_event(rust_event())
    objective = _objective(bundle.correlation.decision_id)
    outcome = _outcome(bundle, objective)
    assessment = _assessment(bundle, objective, outcome)
    correlation = replace(
        bundle.correlation,
        objective_id=objective.objective_id,
        outcome_id=outcome.outcome_id,
        effect_assessment_id=assessment.effect_assessment_id,
    )
    payload = assessment_to_shared_v0(
        correlation, assessment, objective, outcome, producer_node="edge-1"
    )
    assert payload["tactical_effect"] == "delay"
    assert payload["assessment"] == "inconclusive"
    assert payload["executable"] is False
    assert payload["policy_ref"].endswith(":policy-v1")
    assert payload["observed_at"] == outcome.observed_at


def test_tactical_assessment_rejects_different_linked_outcome():
    bundle = from_rust_event(rust_event())
    objective = _objective(bundle.correlation.decision_id)
    outcome = _outcome(bundle, objective)
    assessment = _assessment(bundle, objective, outcome)
    correlation = replace(
        bundle.correlation,
        objective_id=objective.objective_id,
        outcome_id=outcome.outcome_id,
        effect_assessment_id=assessment.effect_assessment_id,
    )
    other = replace(outcome, outcome_id="outcome-other")
    with pytest.raises(SharedOutcomeExportError, match="different outcome"):
        assessment_to_shared_v0(
            correlation, assessment, objective, other, producer_node="edge-1"
        )
