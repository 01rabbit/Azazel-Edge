from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence
from uuid import uuid4


SCHEMA_VERSION = "outcome-as-evidence/v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


class ExecutionStatus(str, Enum):
    UNVERIFIED = "unverified"
    APPLIED = "applied"
    PARTIAL = "partial"
    REJECTED = "rejected"
    FAILED = "failed"
    EXPIRED = "expired"
    RELEASED = "released"


class MechanismKind(str, Enum):
    TRAFFIC_SHAPING = "TRAFFIC_SHAPING"
    ROUTE_CHANGE = "ROUTE_CHANGE"
    REDIRECTION = "REDIRECTION"
    ISOLATION = "ISOLATION"
    NOTIFICATION = "NOTIFICATION"
    OBSERVATION_ONLY = "OBSERVATION_ONLY"
    UNKNOWN = "UNKNOWN"


class MechanismStatus(str, Enum):
    OBSERVED = "observed"
    NOT_OBSERVED = "not_observed"
    UNVERIFIED = "unverified"
    RELEASED = "released"
    STALE = "stale"
    DISPUTED = "disputed"


class OutcomeAssessment(str, Enum):
    EFFECTIVE = "effective"
    PARTIALLY_EFFECTIVE = "partially_effective"
    INEFFECTIVE = "ineffective"
    HARMFUL = "harmful"
    INCONCLUSIVE = "inconclusive"


class EffectAssessmentStatus(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


class CausalSupport(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    INCONCLUSIVE = "inconclusive"


class ActionLifecycle(str, Enum):
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    RELEASED = "released"
    EXPIRED = "expired"
    FAILED = "failed"


class ShadowMode(str, Enum):
    OFF = "off"
    SHADOW_RECORD = "shadow_record"
    SHADOW_ASSESS = "shadow_assess"


@dataclass(frozen=True)
class Correlation:
    incident_id: str
    decision_id: str
    action_id: str
    execution_id: str
    mechanism_id: str
    objective_id: str = ""
    outcome_id: str = ""
    effect_assessment_id: str = ""
    reasoning_trace_id: str = ""

    def __post_init__(self) -> None:
        required = {
            "incident_id": self.incident_id,
            "decision_id": self.decision_id,
            "action_id": self.action_id,
            "execution_id": self.execution_id,
            "mechanism_id": self.mechanism_id,
        }
        missing = [name for name, value in required.items() if not str(value).strip()]
        if missing:
            raise ValueError(f"missing correlation fields: {', '.join(missing)}")


@dataclass(frozen=True)
class ActionExecutionReceipt:
    incident_id: str
    decision_id: str
    action_id: str
    execution_id: str
    action_kind: str
    provider: str
    scope: Mapping[str, Any]
    requested_parameters: Mapping[str, Any]
    applied_parameters: Mapping[str, Any]
    status: ExecutionStatus
    requested_at: str
    started_at: str
    completed_at: str
    expires_at: str = ""
    reversible: bool = False
    release_ref: str = ""
    error_code: str = ""
    provider_evidence_refs: Sequence[str] = field(default_factory=tuple)
    producer: str = "azazel_edge.outcome"
    schema_version: str = SCHEMA_VERSION
    lifecycle: ActionLifecycle = ActionLifecycle.ACTIVE
    superseded_by_decision_id: str = ""
    idempotency_key: str = ""
    provider_sequence: str = ""

    def __post_init__(self) -> None:
        required = (
            self.incident_id,
            self.decision_id,
            self.action_id,
            self.execution_id,
            self.action_kind,
            self.provider,
            self.requested_at,
        )
        if any(not str(value).strip() for value in required):
            raise ValueError("execution receipt requires incident/decision/action/execution ids, action_kind, provider, requested_at")
        if self.lifecycle is ActionLifecycle.SUPERSEDED and not self.superseded_by_decision_id:
            raise ValueError("superseded receipt requires superseded_by_decision_id")

    def to_dict(self) -> dict[str, Any]:
        return _enum_dict(asdict(self))


@dataclass(frozen=True)
class AppliedMechanism:
    mechanism_id: str
    execution_id: str
    decision_id: str
    mechanism_kind: MechanismKind
    scope: Mapping[str, Any]
    observed_parameters: Mapping[str, Any]
    status: MechanismStatus
    observed_at: str
    expires_at: str = ""
    reversible: bool = False
    evidence_refs: Sequence[str] = field(default_factory=tuple)
    producer: str = "azazel_edge.outcome"
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not all((self.mechanism_id, self.execution_id, self.decision_id, self.observed_at)):
            raise ValueError("mechanism requires mechanism/execution/decision ids and observed_at")

    def to_dict(self) -> dict[str, Any]:
        return _enum_dict(asdict(self))


@dataclass(frozen=True)
class EffectObjective:
    decision_id: str
    metric: str
    direction: str
    target_or_range: Mapping[str, Any]
    observation_window: Mapping[str, Any]
    guardrails: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    policy_version: str = "unversioned"
    objective_id: str = field(default_factory=lambda: _id("objective"))
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not all((self.objective_id, self.decision_id, self.metric, self.direction)):
            raise ValueError("objective requires objective_id, decision_id, metric and direction")
        if self.direction not in {"increase", "decrease", "within", "observe"}:
            raise ValueError(f"unsupported objective direction: {self.direction}")

    def to_dict(self) -> dict[str, Any]:
        return _enum_dict(asdict(self))


@dataclass(frozen=True)
class OutcomeRecord:
    incident_id: str
    decision_id: str
    execution_id: str
    mechanism_id: str
    objective_id: str
    observation_window: Mapping[str, Any]
    baseline_metrics: Mapping[str, Any]
    post_metrics: Mapping[str, Any]
    adversary_response: Mapping[str, Any]
    asset_impact: Mapping[str, Any]
    noc_impact: Mapping[str, Any]
    resource_impact: Mapping[str, Any]
    operator_override: Mapping[str, Any]
    termination_reason: str
    assessment: OutcomeAssessment = OutcomeAssessment.INCONCLUSIVE
    causal_support: CausalSupport = CausalSupport.INCONCLUSIVE
    telemetry_coverage: Mapping[str, Any] = field(default_factory=dict)
    confounders: Sequence[Mapping[str, Any]] = field(default_factory=tuple)
    evidence_refs: Sequence[str] = field(default_factory=tuple)
    observed_at: str = field(default_factory=utc_now)
    producer: str = "azazel_edge.outcome"
    outcome_id: str = field(default_factory=lambda: _id("outcome"))
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        required = (
            self.outcome_id,
            self.incident_id,
            self.decision_id,
            self.execution_id,
            self.mechanism_id,
            self.objective_id,
            self.observed_at,
        )
        if any(not str(value).strip() for value in required):
            raise ValueError("outcome requires complete correlation and observed_at")

    def to_dict(self) -> dict[str, Any]:
        return _enum_dict(asdict(self))


@dataclass(frozen=True)
class TacticalEffectAssessment:
    outcome_id: str
    mechanism_id: str
    objective_id: str
    tactical_effect: str
    assessment: EffectAssessmentStatus
    confidence: float
    reason_code: str
    evidence_refs: Sequence[str]
    producer: str = "azazel_edge.outcome"
    effect_assessment_id: str = field(default_factory=lambda: _id("effect"))
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        required = (
            self.effect_assessment_id,
            self.outcome_id,
            self.mechanism_id,
            self.objective_id,
            self.tactical_effect,
            self.reason_code,
        )
        if any(not str(value).strip() for value in required):
            raise ValueError("effect assessment requires complete correlation and reason_code")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return _enum_dict(asdict(self))


@dataclass(frozen=True)
class ShadowRecordBundle:
    correlation: Correlation
    execution: ActionExecutionReceipt
    mechanism: AppliedMechanism

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "correlation": asdict(self.correlation),
            "execution": self.execution.to_dict(),
            "mechanism": self.mechanism.to_dict(),
        }


def _enum_dict(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {k: _enum_dict(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_enum_dict(v) for v in value]
    return value
