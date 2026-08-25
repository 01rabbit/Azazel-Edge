"""Outcome-as-Evidence v1 shadow contracts.

This package is deliberately non-authoritative. Live defensive execution remains in
the existing Rust event-engine enforcement path.
"""

from .adapter import from_rust_event
from .assessment import assess_tactical_effect
from .contracts import (
    ActionExecutionReceipt,
    ActionLifecycle,
    AppliedMechanism,
    Correlation,
    EffectAssessmentStatus,
    EffectObjective,
    ExecutionStatus,
    MechanismKind,
    MechanismStatus,
    OutcomeAssessment,
    OutcomeRecord,
    ShadowMode,
    ShadowRecordBundle,
    TacticalEffectAssessment,
)
from .observer import ShadowOutcomeObserver
from .replay import ReplayExecutionForbidden, ReplayExecutionProvider

__all__ = [
    "ActionExecutionReceipt",
    "ActionLifecycle",
    "AppliedMechanism",
    "Correlation",
    "EffectAssessmentStatus",
    "EffectObjective",
    "ExecutionStatus",
    "MechanismKind",
    "MechanismStatus",
    "OutcomeAssessment",
    "OutcomeRecord",
    "ReplayExecutionForbidden",
    "ReplayExecutionProvider",
    "ShadowMode",
    "ShadowOutcomeObserver",
    "ShadowRecordBundle",
    "TacticalEffectAssessment",
    "assess_tactical_effect",
    "from_rust_event",
]
