from __future__ import annotations

import unittest

from azazel_edge.outcome import (
    AppliedMechanism,
    CausalSupport,
    EffectAssessmentStatus,
    EffectObjective,
    MechanismKind,
    MechanismStatus,
    OutcomeAssessment,
    OutcomeRecord,
    assess_tactical_effect,
)


class TacticalEffectGuardrailTests(unittest.TestCase):
    def _mechanism(self) -> AppliedMechanism:
        return AppliedMechanism(
            mechanism_id="mechanism-test",
            execution_id="execution-test",
            decision_id="decision-test",
            mechanism_kind=MechanismKind.TRAFFIC_SHAPING,
            scope={"scope_kind": "interface_root_qdisc", "interface": "br0"},
            observed_parameters={"verification_basis": "fixture_postcondition"},
            status=MechanismStatus.OBSERVED,
            observed_at="2026-08-26T00:00:01Z",
            evidence_refs=("evidence:mechanism",),
            producer="test_fixture",
        )

    def _objective(self, guardrail: dict) -> EffectObjective:
        return EffectObjective(
            decision_id="decision-test",
            metric="connection_latency_ms",
            direction="increase",
            target_or_range={"minimum_delta": 500},
            observation_window={"seconds": 30},
            guardrails=(guardrail,),
            policy_version="test-v1",
            objective_id="objective-test",
        )

    def _outcome(self, objective: EffectObjective, *, noc_impact: dict) -> OutcomeRecord:
        return OutcomeRecord(
            incident_id="incident-test",
            decision_id="decision-test",
            execution_id="execution-test",
            mechanism_id="mechanism-test",
            objective_id=objective.objective_id,
            observation_window={"seconds": 30},
            baseline_metrics={"connection_latency_ms": 100},
            post_metrics={"connection_latency_ms": 900},
            adversary_response={},
            asset_impact={},
            noc_impact=noc_impact,
            resource_impact={},
            operator_override={},
            termination_reason="window_complete",
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
            telemetry_coverage={"baseline": 1.0, "post": 1.0},
            confounders=(),
            evidence_refs=("evidence:before", "evidence:after", "evidence:noc"),
            outcome_id="outcome-test",
        )

    def test_guardrail_pass_allows_supported_delay(self) -> None:
        objective = self._objective(
            {"source": "noc_impact", "metric": "impact_score", "max": 20}
        )
        outcome = self._outcome(objective, noc_impact={"impact_score": 10})
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.SUPPORTED)

    def test_guardrail_violation_blocks_supported_delay(self) -> None:
        objective = self._objective(
            {"source": "noc_impact", "metric": "impact_score", "max": 20}
        )
        outcome = self._outcome(objective, noc_impact={"impact_score": 30})
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.UNSUPPORTED)
        self.assertEqual(result.reason_code, "policy_guardrail_violated")

    def test_missing_guardrail_evidence_is_inconclusive(self) -> None:
        objective = self._objective(
            {"source": "noc_impact", "metric": "impact_score", "max": 20}
        )
        outcome = self._outcome(objective, noc_impact={})
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "guardrail_evidence_missing_or_invalid")

    def test_ambiguous_guardrail_contract_is_inconclusive(self) -> None:
        objective = self._objective(
            {"source": "noc_impact", "metric": "impact_score", "min": 0, "max": 20}
        )
        outcome = self._outcome(objective, noc_impact={"impact_score": 10})
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
