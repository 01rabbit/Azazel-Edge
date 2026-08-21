"""Edge-side MITRE Engage-aligned engagement candidates (Azazel-Edge#319).

Deterministic mapping from validated evidence + the Action Arbiter's decision to
a bounded, explainable ``EngagementCandidate`` (Azazel-Fabric#8), plus an
arbiter-authority reconciliation that can only *reduce* an engagement, never
escalate it. This layer is additive and advisory: it never executes an action,
never overrides the arbiter, and is a no-op when the feature is disabled or the
Fabric engagement contracts are absent.
"""

from azazel_edge.engagement.candidate import (
    ACTION_TO_ACTIVITY,
    EngagementDisabled,
    build_engagement_candidate,
    engagement_available,
    evaluate_engagement,
    engagement_event,
)

__all__ = [
    "ACTION_TO_ACTIVITY",
    "EngagementDisabled",
    "build_engagement_candidate",
    "engagement_available",
    "evaluate_engagement",
    "engagement_event",
]
