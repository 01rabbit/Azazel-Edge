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
    ReplayExecutionForbidden,
    ReplayExecutionProvider,
    ShadowMode,
    ShadowOutcomeObserver,
    assess_tactical_effect,
    from_rust_event,
)


def rust_event(
    *,
    action: str = "throttle",
    mode: str = "enforced",
    result: str = "applied",
    executed_count: int = 1,
    failed_count: int = 0,
) -> dict:
    commands = {
        "throttle": ["tc qdisc replace dev br0 root tbf rate 256kbit burst 32kbit latency 1000ms"],
        "redirect": ["nft insert rule inet azazel_edge prerouting ip saddr 10.0.0.8 tcp dport 22 redirect to 12222"],
        "isolate": ["nft insert rule inet azazel_edge input ip saddr 10.0.0.8 drop"],
    }
    rollback = {
        "throttle": ["tc qdisc del dev br0 root"],
        "redirect": ["nft delete rule inet azazel_edge prerouting ip saddr 10.0.0.8 tcp dport 22 redirect to 12222"],
        "isolate": ["nft delete rule inet azazel_edge input ip saddr 10.0.0.8 drop"],
    }
    return {
        "normalized": {
            "ts": "2026-08-26T00:00:00Z",
            "src_ip": "10.0.0.8",
            "dst_ip": "10.0.0.1",
            "target_port": 22,
            "sid": 1001,
        },
        "defense": {
            "action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
        },
        "enforcement": {
            "mode": mode,
            "trace_id": "trace-test-1",
            "selected_action": action,
            "target": "10.0.0.8",
            "policy_reason": "test",
            "command_plan": commands.get(action, []),
            "rollback_plan": rollback.get(action, []),
            "executed_count": executed_count,
            "failed_count": failed_count,
            "errors": [],
            "result": result,
            "metadata": {},
        },
        "pipeline": "rust_event_engine_v1",
    }


class RustAdapterTests(unittest.TestCase):
    def test_throttle_is_traffic_shaping_not_tactical_delay(self) -> None:
        bundle = from_rust_event(rust_event())
        self.assertEqual(bundle.mechanism.mechanism_kind, MechanismKind.TRAFFIC_SHAPING)
        self.assertEqual(bundle.mechanism.scope["scope_kind"], "interface_root_qdisc")
        self.assertEqual(bundle.mechanism.scope["interface"], "br0")
        self.assertNotEqual(bundle.mechanism.mechanism_kind.value, "DELAY")
        self.assertEqual(bundle.execution.status.value, "applied")
        self.assertEqual(bundle.mechanism.status.value, "unverified")

    def test_dry_run_is_never_marked_applied(self) -> None:
        bundle = from_rust_event(
            rust_event(mode="dry_run", result="planned_not_applied", executed_count=0)
        )
        self.assertEqual(bundle.execution.status.value, "unverified")
        self.assertEqual(bundle.mechanism.status.value, "unverified")

    def test_policy_gate_is_rejected(self) -> None:
        bundle = from_rust_event(
            rust_event(mode="policy_gated", result="planned_not_applied", executed_count=0)
        )
        self.assertEqual(bundle.execution.status.value, "rejected")
        self.assertEqual(bundle.mechanism.status.value, "not_observed")

    def test_partial_failure_is_not_claimed_as_observed_success(self) -> None:
        event = rust_event(result="partial_failure", executed_count=1, failed_count=1)
        event["enforcement"]["errors"] = ["test failure"]
        bundle = from_rust_event(event)
        self.assertEqual(bundle.execution.status.value, "partial")
        self.assertEqual(bundle.mechanism.status.value, "disputed")
        self.assertEqual(bundle.execution.error_code, "provider_command_failure")

    def test_single_failed_command_is_failed_not_partial(self) -> None:
        event = rust_event(result="partial_failure", executed_count=0, failed_count=1)
        event["enforcement"]["errors"] = ["test failure"]
        bundle = from_rust_event(event)
        self.assertEqual(bundle.execution.status.value, "failed")
        self.assertEqual(bundle.mechanism.status.value, "not_observed")


class TacticalEffectTests(unittest.TestCase):
    def _objective(self) -> EffectObjective:
        return EffectObjective(
            decision_id="trace-test-1",
            metric="connection_latency_ms",
            direction="increase",
            target_or_range={"minimum_delta": 500},
            observation_window={"seconds": 30},
            guardrails=({"metric": "noc_impact", "max": 20},),
            policy_version="test-v1",
            objective_id="objective-test-1",
        )

    def _mechanism(self, *, status: MechanismStatus = MechanismStatus.OBSERVED) -> AppliedMechanism:
        return AppliedMechanism(
            mechanism_id="mechanism-test",
            execution_id="execution-test",
            decision_id="trace-test-1",
            mechanism_kind=MechanismKind.TRAFFIC_SHAPING,
            scope={"scope_kind": "interface_root_qdisc", "interface": "br0"},
            observed_parameters={"verification_basis": "fixture_postcondition"},
            status=status,
            observed_at="2026-08-26T00:00:01Z",
            evidence_refs=("evidence:mechanism",),
            producer="test_fixture",
        )

    def _make_outcome(
        self,
        objective: EffectObjective,
        *,
        assessment: OutcomeAssessment,
        causal_support: CausalSupport = CausalSupport.INCONCLUSIVE,
        before: float = 120,
        after: float = 2200,
        evidence_refs: tuple[str, ...] = ("evidence:before", "evidence:after"),
    ) -> OutcomeRecord:
        return OutcomeRecord(
            incident_id="incident-test",
            decision_id="trace-test-1",
            execution_id="execution-test",
            mechanism_id="mechanism-test",
            objective_id=objective.objective_id,
            observation_window={"seconds": 30},
            baseline_metrics={"connection_latency_ms": before},
            post_metrics={"connection_latency_ms": after},
            adversary_response={},
            asset_impact={},
            noc_impact={},
            resource_impact={},
            operator_override={},
            termination_reason="window_complete",
            assessment=assessment,
            causal_support=causal_support,
            telemetry_coverage={"baseline": 1.0, "post": 1.0},
            confounders=(),
            evidence_refs=evidence_refs,
            outcome_id="outcome-test",
        )

    def test_unverified_mechanism_cannot_support_delay(self) -> None:
        objective = self._objective()
        outcome = self._make_outcome(
            objective,
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
        )
        result = assess_tactical_effect(
            mechanism=self._mechanism(status=MechanismStatus.UNVERIFIED),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "mechanism_postcondition_not_observed")

    def test_requested_throttle_does_not_prove_delay_when_outcome_inconclusive(self) -> None:
        objective = self._objective()
        outcome = self._make_outcome(objective, assessment=OutcomeAssessment.INCONCLUSIVE)
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)

    def test_time_increase_without_causal_support_remains_inconclusive(self) -> None:
        objective = self._objective()
        outcome = self._make_outcome(
            objective,
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.INCONCLUSIVE,
        )
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)
        self.assertEqual(result.reason_code, "causal_support_inconclusive")

    def test_delay_requires_observed_mechanism_effective_outcome_and_causal_support(self) -> None:
        objective = self._objective()
        outcome = self._make_outcome(
            objective,
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
        )
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.SUPPORTED)

    def test_delay_below_policy_delta_is_unsupported(self) -> None:
        objective = self._objective()
        outcome = self._make_outcome(
            objective,
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
            before=120,
            after=400,
        )
        result = assess_tactical_effect(
            mechanism=self._mechanism(),
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.UNSUPPORTED)

    def test_missing_evidence_cannot_support_effect(self) -> None:
        objective = self._objective()
        mechanism = self._mechanism()
        mechanism = AppliedMechanism(
            mechanism_id=mechanism.mechanism_id,
            execution_id=mechanism.execution_id,
            decision_id=mechanism.decision_id,
            mechanism_kind=mechanism.mechanism_kind,
            scope=mechanism.scope,
            observed_parameters=mechanism.observed_parameters,
            status=mechanism.status,
            observed_at=mechanism.observed_at,
            evidence_refs=(),
            producer=mechanism.producer,
        )
        outcome = self._make_outcome(
            objective,
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
            evidence_refs=(),
        )
        result = assess_tactical_effect(
            mechanism=mechanism,
            objective=objective,
            outcome=outcome,
            tactical_effect="DELAY",
        )
        self.assertEqual(result.assessment, EffectAssessmentStatus.INCONCLUSIVE)

    def test_correlation_mismatch_is_rejected(self) -> None:
        objective = self._objective()
        outcome = self._make_outcome(
            objective,
            assessment=OutcomeAssessment.EFFECTIVE,
            causal_support=CausalSupport.SUPPORTED,
        )
        wrong = AppliedMechanism(
            mechanism_id="other-mechanism",
            execution_id="execution-test",
            decision_id="trace-test-1",
            mechanism_kind=MechanismKind.TRAFFIC_SHAPING,
            scope={},
            observed_parameters={},
            status=MechanismStatus.OBSERVED,
            observed_at="2026-08-26T00:00:01Z",
            evidence_refs=("evidence:mechanism",),
        )
        with self.assertRaises(ValueError):
            assess_tactical_effect(
                mechanism=wrong,
                objective=objective,
                outcome=outcome,
                tactical_effect="DELAY",
            )


class AuthorityBoundaryTests(unittest.TestCase):
    def test_replay_provider_cannot_execute_live_action(self) -> None:
        bundle = from_rust_event(rust_event())
        replay = ReplayExecutionProvider.from_records([bundle.execution])
        self.assertEqual(len(replay.records_for_decision(bundle.execution.decision_id)), 1)
        with self.assertRaises(ReplayExecutionForbidden):
            replay.execute({"action": "throttle"})

    def test_observer_off_produces_no_record(self) -> None:
        observer = ShadowOutcomeObserver(ShadowMode.OFF)
        self.assertIsNone(observer.observe(rust_event()))

    def test_observer_shadow_record_contains_no_effect_claim(self) -> None:
        observer = ShadowOutcomeObserver(ShadowMode.SHADOW_RECORD)
        record = observer.observe(rust_event())
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["observer_mode"], "shadow_record")
        self.assertIsNone(record["effect_assessment"])


if __name__ == "__main__":
    unittest.main()
