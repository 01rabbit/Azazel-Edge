from __future__ import annotations

from typing import Any

from .contracts import (
    AppliedMechanism,
    CausalSupport,
    EffectAssessmentStatus,
    EffectObjective,
    MechanismKind,
    MechanismStatus,
    OutcomeAssessment,
    OutcomeRecord,
    TacticalEffectAssessment,
)


_TIME_METRICS = {
    "connection_latency_ms",
    "completion_time_ms",
    "request_duration_ms",
    "time_to_next_action_ms",
}


def assess_tactical_effect(
    *,
    mechanism: AppliedMechanism,
    objective: EffectObjective,
    outcome: OutcomeRecord,
    tactical_effect: str,
) -> TacticalEffectAssessment:
    """Deterministically assess whether evidence supports a tactical effect.

    Tactical support is fail-closed: the mechanism must be independently observed,
    correlation must be exact, and the outcome must carry explicit causal support.
    A requested throttle or provider command success alone can never become ``DELAY``.
    """

    effect = tactical_effect.upper().strip()
    refs = tuple(dict.fromkeys((*mechanism.evidence_refs, *outcome.evidence_refs)))

    if objective.decision_id != outcome.decision_id:
        raise ValueError("objective/outcome decision correlation mismatch")
    if objective.objective_id != outcome.objective_id:
        raise ValueError("objective/outcome objective correlation mismatch")
    if mechanism.decision_id != outcome.decision_id:
        raise ValueError("mechanism/outcome decision correlation mismatch")
    if mechanism.mechanism_id != outcome.mechanism_id:
        raise ValueError("mechanism/outcome mechanism correlation mismatch")

    if mechanism.status is not MechanismStatus.OBSERVED:
        return _inconclusive(objective, outcome, effect, refs, "mechanism_postcondition_not_observed")

    if outcome.assessment is OutcomeAssessment.INCONCLUSIVE:
        return _inconclusive(objective, outcome, effect, refs, "outcome_inconclusive")

    if not refs:
        return _inconclusive(objective, outcome, effect, (), "missing_evidence_refs")

    if outcome.causal_support is CausalSupport.INCONCLUSIVE:
        return _inconclusive(objective, outcome, effect, refs, "causal_support_inconclusive")
    if outcome.causal_support is CausalSupport.UNSUPPORTED:
        return _unsupported(objective, outcome, effect, refs, "causal_support_unsupported")

    if effect == "DELAY":
        if mechanism.mechanism_kind is not MechanismKind.TRAFFIC_SHAPING:
            return _unsupported(objective, outcome, effect, refs, "delay_requires_traffic_shaping_mechanism")
        if objective.metric not in _TIME_METRICS or objective.direction != "increase":
            return _inconclusive(objective, outcome, effect, refs, "delay_requires_time_metric_increase_objective")
        before = _number(outcome.baseline_metrics.get(objective.metric))
        after = _number(outcome.post_metrics.get(objective.metric))
        if before is None or after is None:
            return _inconclusive(objective, outcome, effect, refs, "delay_metric_missing")
        if outcome.assessment in {OutcomeAssessment.EFFECTIVE, OutcomeAssessment.PARTIALLY_EFFECTIVE} and after > before:
            target = _number(objective.target_or_range.get("minimum_delta"))
            delta = after - before
            if target is not None and delta < target:
                return _unsupported(objective, outcome, effect, refs, "delay_delta_below_policy_target")
            return TacticalEffectAssessment(
                outcome_id=outcome.outcome_id,
                mechanism_id=outcome.mechanism_id,
                objective_id=objective.objective_id,
                tactical_effect=effect,
                assessment=EffectAssessmentStatus.SUPPORTED,
                confidence=0.75 if outcome.assessment is OutcomeAssessment.PARTIALLY_EFFECTIVE else 0.9,
                reason_code="observed_mechanism_time_metric_increased_with_explicit_causal_support",
                evidence_refs=refs,
            )
        return _unsupported(objective, outcome, effect, refs, "time_metric_did_not_support_delay")

    # v1 deliberately implements no generic "effective => tactical effect" shortcut.
    # DIVERSION/CONTAINMENT/FRICTION need their own evidence rules before they can be
    # supported. Until then, they remain inconclusive rather than being inferred from
    # an action name or a caller-supplied outcome label.
    return _inconclusive(objective, outcome, effect, refs, "tactical_effect_rule_not_implemented")


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _unsupported(
    objective: EffectObjective,
    outcome: OutcomeRecord,
    effect: str,
    refs: tuple[str, ...],
    reason: str,
) -> TacticalEffectAssessment:
    return TacticalEffectAssessment(
        outcome_id=outcome.outcome_id,
        mechanism_id=outcome.mechanism_id,
        objective_id=objective.objective_id,
        tactical_effect=effect,
        assessment=EffectAssessmentStatus.UNSUPPORTED,
        confidence=0.9,
        reason_code=reason,
        evidence_refs=refs,
    )


def _inconclusive(
    objective: EffectObjective,
    outcome: OutcomeRecord,
    effect: str,
    refs: tuple[str, ...],
    reason: str,
) -> TacticalEffectAssessment:
    return TacticalEffectAssessment(
        outcome_id=outcome.outcome_id,
        mechanism_id=outcome.mechanism_id,
        objective_id=objective.objective_id,
        tactical_effect=effect,
        assessment=EffectAssessmentStatus.INCONCLUSIVE,
        confidence=0.0,
        reason_code=reason,
        evidence_refs=refs,
    )
