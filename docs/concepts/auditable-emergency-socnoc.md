# Auditable Emergency SOC/NOC

## Purpose
Define an emergency-oriented concept profile for shelter and field operations where non-specialist teams can operate safely while preserving post-incident auditability.

## Operational Assumption
- Deterministic path remains authoritative for first-minute triage.
- AI remains advisory and is always governed.
- Every selected action must include explanation, rejected alternatives, and release condition.

## Target Environment
- Evacuation shelters
- Temporary field hospitals
- Volunteer-operated emergency communication networks

## Core Capabilities
| Capability | Status | Notes |
|---|---|---|
| Decision Explanation with deterministic rationale | Implemented | `why_chosen`, `why_not_others`, `operator_wording` are generated in runtime path. |
| Audit trace continuity with `trace_id` | Implemented | Evidence-to-action-to-notification continuity is preserved. |
| Rejected alternatives and release condition capture | Implemented | Action-level trace includes rejected actions and release condition metadata. |
| Operator handoff evidence bundle | Planned | Scenario and packaging improvements are still ongoing. |

## Demo Narrative
This profile prioritizes trust in operation after deployment: why the system chose an action, what alternatives were rejected, and what condition should release the control.

## Relationship to Core Architecture
This concept is built on the standard deterministic path (Tactical Engine -> Evidence Plane -> NOC/SOC Evaluator -> Action Arbiter -> Decision Explanation -> Notification/AI Assist -> Audit Logger).

## What This Concept Is Not
- Not an AI-autonomous response model
- Not a cloud-dependent compliance service
- Not a replacement for specialist review

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Evidence Model](../architecture/evidence-model.md)
- [Local AI Triage](../architecture/local-ai-triage.md)
- [Auditable Profile Translation Matrix](auditable-profile-diff.md)
