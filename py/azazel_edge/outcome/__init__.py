"""Outcome-as-Evidence v1 shadow contracts.

This package is deliberately non-authoritative. Live defensive execution and release
remain in the existing Rust event-engine control plane.
"""

from .adapter import from_rust_event
from .assessment import assess_tactical_effect
from .contracts import (
    ActionExecutionReceipt,
    ActionLifecycle,
    AppliedMechanism,
    CausalSupport,
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
from .ownership import expected_ownership, verify_mechanism_postcondition
from .postcondition import (
    ReadOnlyCommandRejected,
    ReadOnlyCommandResult,
    SubprocessReadOnlyRunner,
)
from .release_evidence import (
    ReleaseEvidenceRecord,
    ReleaseEvidenceStatus,
    from_rust_release_event,
    reconcile_release_evidence,
)
from .replay import ReplayExecutionForbidden, ReplayExecutionProvider

__all__ = [
    "ActionExecutionReceipt",
    "ActionLifecycle",
    "AppliedMechanism",
    "CausalSupport",
    "Correlation",
    "EffectAssessmentStatus",
    "EffectObjective",
    "ExecutionStatus",
    "MechanismKind",
    "MechanismStatus",
    "OutcomeAssessment",
    "OutcomeRecord",
    "ReadOnlyCommandRejected",
    "ReadOnlyCommandResult",
    "ReleaseEvidenceRecord",
    "ReleaseEvidenceStatus",
    "ReplayExecutionForbidden",
    "ReplayExecutionProvider",
    "ShadowMode",
    "ShadowOutcomeObserver",
    "ShadowRecordBundle",
    "SubprocessReadOnlyRunner",
    "TacticalEffectAssessment",
    "assess_tactical_effect",
    "expected_ownership",
    "from_rust_event",
    "from_rust_release_event",
    "reconcile_release_evidence",
    "verify_mechanism_postcondition",
]
