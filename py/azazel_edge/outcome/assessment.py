from __future__ import annotations

from typing import Any, Mapping

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

_GUARDRAIL_SOURCES = {
    "post_metrics",
    "noc_impact",
    "resource_impact",
    "asset_impact",
}


def assess_tactical_effect(
    *,
    mechanism: AppliedMechanism,
    objective: EffectObjective,
    outcome: OutcomeRecord,
    tactical_effect: str,
) -> TacticalEffectAssessment:
    """Deterministically assess whether evidence supports a tactical effect objective.

    Tactical support is fail-closed: the mechanism must be independently observed,
    correlation must be exact, the outcome must carry explicit causal support, and
    any policy-owned guardrails attached to the objective must be evaluable and pass.
    A requested throttle or provider command success alone can never become ``DELAY``.

    v1 deliberately emits no numeric confidence because no calibration corpus exists.
    ``confidence=None`` is the honest representation until calibration is proven.
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

    guardrail_result = _evaluate_guardrails(objective.guardrails, outcome)
    if guardrail_result is None:
        return _inconclusive(objective, outcome, effect, refs, "guardrail_evidence_missing_or_invalid")
    if guardrail_result is False:
        return _unsupported(objective, outcome, effect, refs, "policy_guardrail_violated")

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
                confidence=None,
                reason_code="observed_mechanism_time_metric_increased_with_explicit_causal_support",
                evidence_refs=refs,
            )
        return _unsupported(objective, outcome, effect, refs, "time_metric_did_not_support_delay")

    # v1 deliberately implements no generic "effective => tactical effect" shortcut.
    # DIVERSION/CONTAINMENT/FRICTION need their own evidence rules before they can be
    # supported. Until then, they remain inconclusive rather than being inferred from
    # an action name or a caller-supplied outcome label.
    return _inconclusive(objective, outcome, effect, refs, "tactical_effect_rule_not_implemented")


def _evaluate_guardrails(
    guardrails: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | Any,
    outcome: OutcomeRecord,
) -> bool | None:
    """Evaluate a deliberately small v1 numeric guardrail contract.

    Guardrails are policy-owned and use an explicit source so assessment never guesses
    which impact map a metric belongs to. Example::

        {"source": "noc_impact", "metric": "impact_score", "max": 20}

    Exactly one of ``min`` or ``max`` must be present. Missing, malformed, or
    non-numeric evidence returns ``None`` (inconclusive), never pass.
    """

    if not guardrails:
        return True
    source_maps: dict[str, Mapping[str, Any]] = {
        "post_metrics": outcome.post_metrics,
        "noc_impact": outcome.noc_impact,
        "resource_impact": outcome.resource_impact,
        "asset_impact": outcome.asset_impact,
    }
    for raw in guardrails:
        if not isinstance(raw, Mapping):
            return None
        source = str(raw.get("source") or "")
        metric = str(raw.get("metric") or "")
        if source not in _GUARDRAIL_SOURCES or not metric:
            return None
        has_min = "min" in raw
        has_max = "max" in raw
        if has_min == has_max:
            return None
        observed = _number(source_maps[source].get(metric))
        threshold = _number(raw.get("min") if has_min else raw.get("max"))
        if observed is None or threshold is None:
            return None
        if has_min and observed < threshold:
            return False
        if has_max and observed > threshold:
            return False
    return True


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
        confidence=None,
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
        confidence=None,
        reason_code=reason,
        evidence_refs=refs,
    )
