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


class EpistemicFailClosedTests(unittest.TestCase):
    def _objective(self) -> EffectObjective:
        return EffectObjective(
            decision_id="decision-epistemic",
            metric="connection_latency_ms",
            direction="increase",
            target_or_range={"minimum_delta": 100},
            observation_window={"seconds": 30},
            policy_version="policy-epistemic-v1",
            objective_id="objective-epistemic",
        )

    def _mechanism(self) -> AppliedMechanism:
        return AppliedMechanism(
            mechanism_id="mechanism-epistemic",
            execution_id="execution-epistemic",
            decision_id="decision-epistemic",
            mechanism_kind=MechanismKind.TRAFFIC_SHAPING,
            scope={"scope_kind": "interface_root_qdisc", "interface": "br0"},
            observed_parameters={"verification_basis": "fixture_postcondition"},
            status=MechanismStatus.OBSERVED,
            observed_at="2026-08-26T00:00:01Z",
            evidence_refs=("evidence:mechanism",),
        )

    def _outcome(self, *, coverage: dict, confounders: tuple[dict, ...]) -> OutcomeRecord:
        objective = self._objective()
        return OutcomeRecord(
            incident_id="incident-epistemic",
            decision_id="decision-epistemic",
            execution_id="execution-epistemic",
            mechanism_id="mechanism-epistemic",
            objective_id=objective.objective_id,
            observation_window={"seconds": 30},
            baseline_metrics={"connection_latency_ms": 100},
            post_metrics={"connection_latency_ms": 500},
            adversary_response={},
            asset_impact={},
            noc_impact={},
            resource_impact={},
            operator_override={},
            termination_reason="window_complete",
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
            telemetry_coverage=coverage,
            confounders=confounders,
            evidence_refs=("evidence:before", "evidence:after"),
            outcome_id="outcome-epistemic",
        )

    def test_missing_or_zero_coverage_cannot_support_delay(self) -> None:
        objective = self._objective()
        outcome = self._outcome(coverage={"baseline": 1.0, "post": 0.0}, confounders=())
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "telemetry_coverage_missing_or_insufficient")

    def test_unresolved_confounder_cannot_support_delay(self) -> None:
        objective = self._objective()
        outcome = self._outcome(
            coverage={"baseline": 1.0, "post": 1.0},
            confounders=({"kind": "operator_intervention", "resolved": False},),
        )
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "unresolved_confounders")


if __name__ == "__main__":
    unittest.main()
