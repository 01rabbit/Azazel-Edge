from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from .contracts import (
    ActionExecutionReceipt,
    AppliedMechanism,
    Correlation,
    EffectObjective,
    ExecutionStatus,
    MechanismKind,
    OutcomeRecord,
    TacticalEffectAssessment,
)


class SharedOutcomeExportError(ValueError):
    pass


_MECHANISM_MAP = {
    MechanismKind.TRAFFIC_SHAPING: "traffic_shaping",
    MechanismKind.REDIRECTION: "redirection",
    MechanismKind.ISOLATION: "isolation",
    MechanismKind.NOTIFICATION: "notification",
    MechanismKind.OBSERVATION_ONLY: "observation_only",
    MechanismKind.UNKNOWN: "unknown",
}
_EXECUTION_STATUS_MAP = {
    ExecutionStatus.UNVERIFIED: "unverified",
    ExecutionStatus.APPLIED: "applied",
    ExecutionStatus.PARTIAL: "partial",
    ExecutionStatus.REJECTED: "rejected",
    ExecutionStatus.FAILED: "failed",
    ExecutionStatus.RELEASED: "released",
}
_TACTICAL_EFFECTS = {"delay", "divert", "containment", "isolation", "observe", "restore"}
_BANNED_FACT_KEYS = {
    "execute",
    "execution_command",
    "provider_command",
    "command",
    "commands",
    "approve",
    "approval",
    "override",
    "arbiter_override",
    "auto_execute",
    "select_action",
    "selected_action",
    "model_recommendation",
    "attacker_belief",
    "success",
    "successful",
    "effect_class",
    "tactical_effect",
}
_MAX_DEPTH = 6
_MAX_MAP = 64
_MAX_SEQUENCE = 128
_MAX_STRING = 2048


def _normalized_key(raw: str) -> str:
    value = "".join(ch.lower() if ch.isalnum() else "_" for ch in raw.strip())
    while "__" in value:
        value = value.replace("__", "_")
    return value.strip("_")


def _forbidden_key(raw: str) -> bool:
    key = _normalized_key(raw)
    return (
        key in _BANNED_FACT_KEYS
        or "provider_command" in key
        or key.endswith("_command")
        or key.startswith("command_")
        or key.startswith("success_")
        or key.endswith("_success")
        or "attacker_belief" in key
        or "model_recommendation" in key
        or "effect_class" in key
        or "tactical_effect" in key
    )


def _safe_fact_value(value: Any, *, depth: int = 0) -> Any:
    if depth > _MAX_DEPTH:
        raise SharedOutcomeExportError("shared fact exceeds maximum nesting depth")
    if isinstance(value, str):
        if len(value) > _MAX_STRING:
            raise SharedOutcomeExportError("shared fact contains oversized string")
        return value
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, Mapping):
        if len(value) > _MAX_MAP:
            raise SharedOutcomeExportError("shared fact map exceeds maximum item count")
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise SharedOutcomeExportError("shared fact map keys must be strings")
            if _forbidden_key(key):
                raise SharedOutcomeExportError(f"forbidden authority/tactical field in shared fact: {key}")
            result[key] = _safe_fact_value(child, depth=depth + 1)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > _MAX_SEQUENCE:
            raise SharedOutcomeExportError("shared fact sequence exceeds maximum item count")
        return [_safe_fact_value(child, depth=depth + 1) for child in value]
    raise SharedOutcomeExportError(f"unsupported shared fact value: {type(value).__name__}")


def _trace_id(correlation: Correlation) -> str:
    value = correlation.reasoning_trace_id or correlation.incident_id
    if not value:
        raise SharedOutcomeExportError("shared export requires a trace identifier")
    return value


def _require_correlation(correlation: Correlation, *, decision_id: str, execution_id: str) -> None:
    if correlation.decision_id != decision_id:
        raise SharedOutcomeExportError("decision correlation mismatch")
    if correlation.execution_id != execution_id:
        raise SharedOutcomeExportError("execution correlation mismatch")


def execution_to_shared_v0(
    correlation: Correlation,
    receipt: ActionExecutionReceipt,
    *,
    producer_node: str,
) -> dict[str, Any]:
    _require_correlation(correlation, decision_id=receipt.decision_id, execution_id=receipt.execution_id)
    status = _EXECUTION_STATUS_MAP.get(receipt.status)
    if status is None:
        raise SharedOutcomeExportError(f"execution status is not representable in shared v0.1: {receipt.status.value}")
    if not producer_node.strip():
        raise SharedOutcomeExportError("producer_node is required")
    return {
        "schema_version": "outcome-execution/v0.1",
        "producer_product": "azazel-edge",
        "producer_node": producer_node,
        "trace_id": _trace_id(correlation),
        "decision_ref": receipt.decision_id,
        "execution_ref": receipt.execution_id,
        "action": receipt.action_kind,
        "status": status,
        "observed_at": receipt.completed_at or receipt.started_at or receipt.requested_at,
        "release_ref": receipt.release_ref or None,
        "evidence_refs": list(receipt.provider_evidence_refs),
        "authority_class": "producer_execution_fact",
    }


def mechanism_to_shared_v0(
    correlation: Correlation,
    mechanism: AppliedMechanism,
    *,
    producer_node: str,
) -> dict[str, Any]:
    _require_correlation(correlation, decision_id=mechanism.decision_id, execution_id=mechanism.execution_id)
    if correlation.mechanism_id != mechanism.mechanism_id:
        raise SharedOutcomeExportError("mechanism correlation mismatch")
    limitations: list[str] = []
    mechanism_kind = _MECHANISM_MAP.get(mechanism.mechanism_kind)
    if mechanism_kind is None:
        if mechanism.mechanism_kind is MechanismKind.ROUTE_CHANGE:
            mechanism_kind = "unknown"
            limitations.append("internal_route_change_not_representable_in_shared_v0.1")
        else:
            raise SharedOutcomeExportError("unknown internal mechanism kind")
    observed_parameters = _safe_fact_value(mechanism.observed_parameters)
    if not isinstance(observed_parameters, dict):
        raise SharedOutcomeExportError("mechanism observed_parameters must remain a mapping")
    return {
        "schema_version": "outcome-mechanism/v0.1",
        "observation_id": mechanism.mechanism_id,
        "producer_product": "azazel-edge",
        "producer_node": producer_node,
        "trace_id": _trace_id(correlation),
        "decision_ref": mechanism.decision_id,
        "execution_ref": mechanism.execution_id,
        "mechanism_kind": mechanism_kind,
        "status": mechanism.status.value,
        "observed_parameters": observed_parameters,
        "observed_at": mechanism.observed_at,
        "evidence_refs": list(mechanism.evidence_refs),
        "limitations": limitations,
        "authority_class": "producer_mechanism_fact",
    }


def _confounder_strings(confounders: Sequence[Mapping[str, Any]]) -> list[str]:
    result: list[str] = []
    for item in confounders:
        safe = _safe_fact_value(item)
        if not isinstance(safe, dict):
            raise SharedOutcomeExportError("confounder must remain a mapping")
        label = safe.get("code") or safe.get("kind") or safe.get("name")
        if isinstance(label, str) and label.strip():
            result.append(label.strip())
        else:
            result.append(json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    return result


def outcome_to_shared_v0(
    correlation: Correlation,
    outcome: OutcomeRecord,
    *,
    producer_node: str,
) -> dict[str, Any]:
    _require_correlation(correlation, decision_id=outcome.decision_id, execution_id=outcome.execution_id)
    if correlation.mechanism_id != outcome.mechanism_id:
        raise SharedOutcomeExportError("outcome mechanism correlation mismatch")
    if correlation.objective_id and correlation.objective_id != outcome.objective_id:
        raise SharedOutcomeExportError("outcome objective correlation mismatch")

    values = {
        "baseline_metrics": _safe_fact_value(outcome.baseline_metrics),
        "post_metrics": _safe_fact_value(outcome.post_metrics),
        "adversary_response": _safe_fact_value(outcome.adversary_response),
        "asset_impact": _safe_fact_value(outcome.asset_impact),
        "noc_impact": _safe_fact_value(outcome.noc_impact),
        "operator_override": _safe_fact_value(outcome.operator_override),
        "termination_reason": outcome.termination_reason,
    }
    telemetry = _safe_fact_value(outcome.telemetry_coverage)
    resource_impact = _safe_fact_value(outcome.resource_impact)
    if not isinstance(telemetry, dict) or not isinstance(resource_impact, dict):
        raise SharedOutcomeExportError("outcome coverage/resource impact must be mappings")
    return {
        "schema_version": "outcome-observation/v0.1",
        "observation_id": outcome.outcome_id,
        "producer_product": "azazel-edge",
        "producer_node": producer_node,
        "trace_id": _trace_id(correlation),
        "decision_ref": outcome.decision_id,
        "execution_ref": outcome.execution_id,
        "mechanism_observation_ref": outcome.mechanism_id,
        "subject_ref": None,
        "window_start": str(outcome.observation_window.get("start") or outcome.observed_at),
        "window_end": str(outcome.observation_window.get("end") or outcome.observed_at),
        "phase": "after",
        "observation_class": "edge_outcome_record",
        "observation_values": values,
        "telemetry_coverage": telemetry,
        "confounders": _confounder_strings(outcome.confounders),
        "resource_impact": resource_impact,
        "evidence_refs": list(outcome.evidence_refs),
        "observed_at": outcome.observed_at,
        "authority_class": "producer_outcome_fact",
    }


def assessment_to_shared_v0(
    correlation: Correlation,
    assessment: TacticalEffectAssessment,
    objective: EffectObjective,
    *,
    producer_node: str,
) -> dict[str, Any]:
    if correlation.effect_assessment_id and correlation.effect_assessment_id != assessment.effect_assessment_id:
        raise SharedOutcomeExportError("effect assessment correlation mismatch")
    if correlation.outcome_id and correlation.outcome_id != assessment.outcome_id:
        raise SharedOutcomeExportError("assessment outcome correlation mismatch")
    if correlation.mechanism_id != assessment.mechanism_id:
        raise SharedOutcomeExportError("assessment mechanism correlation mismatch")
    if assessment.objective_id != objective.objective_id:
        raise SharedOutcomeExportError("assessment objective does not match objective")
    if objective.decision_id != correlation.decision_id:
        raise SharedOutcomeExportError("objective decision does not match correlation")
    tactical_effect = assessment.tactical_effect.lower()
    if tactical_effect not in _TACTICAL_EFFECTS:
        raise SharedOutcomeExportError("tactical effect is not representable in shared v0.1")
    return {
        "schema_version": "tactical-effect-assessment/v0.1",
        "assessment_id": assessment.effect_assessment_id,
        "producer_product": "azazel-edge",
        "producer_node": producer_node,
        "trace_id": _trace_id(correlation),
        "decision_ref": correlation.decision_id,
        "execution_ref": correlation.execution_id,
        "mechanism_observation_ref": assessment.mechanism_id,
        "outcome_observation_refs": [assessment.outcome_id],
        "tactical_effect": tactical_effect,
        "assessment": assessment.assessment.value,
        "evaluator": assessment.producer,
        "policy_ref": f"effect-objective:{objective.objective_id}:{objective.policy_version}",
        "evidence_refs": list(assessment.evidence_refs),
        "limitations": [assessment.reason_code] if assessment.assessment.value == "inconclusive" else [],
        "observed_at": outcome_time_hint(assessment, objective),
        "executable": False,
        "authority_class": "producer_assessment_fact",
    }


def outcome_time_hint(assessment: TacticalEffectAssessment, objective: EffectObjective) -> str:
    """Return a deterministic descriptive time without inventing a fresh event time."""

    window_end = objective.observation_window.get("end")
    if isinstance(window_end, str) and window_end.strip():
        return window_end
    window_start = objective.observation_window.get("start")
    if isinstance(window_start, str) and window_start.strip():
        return window_start
    raise SharedOutcomeExportError(
        f"assessment {assessment.effect_assessment_id} lacks a grounded observation timestamp"
    )
