# Deterministic Edge Decision Support

## Purpose
Describe the operational profile centered on reproducible, policy-based
decision support for constrained SOC/NOC operations in small, temporary, and
rapidly deployed networks.

## Operational Assumption
- The deterministic path is primary.
- Evaluator outputs and Action Arbiter decisions must be explainable and traceable.
- Optional integrations must not change core decision authority.

## Target Environment
- Constrained SOC/NOC teams
- Small or temporary field networks
- Rapidly deployed local environments
- Teams working under unstable connectivity and limited personnel
- Incident response training environments
- Edge deployments requiring predictable operator handoff

## Core Capabilities
| Capability | Status | Notes |
|---|---|---|
| NOC/SOC split deterministic evaluation | Implemented | NOC and SOC evaluators are separate modules. |
| Bounded action set (`observe/notify/throttle/redirect/isolate`) | Implemented | Action Arbiter uses explicit bounded actions. |
| Decision explanation fields | Implemented | Includes rationale and rejected alternatives. |
| Policy-driven threshold tuning | Implemented | SOC policy profiles and dry-run tooling exist. |

## Demo Narrative
This profile demonstrates stable and repeatable edge decision support where the
same evidence and policy produce a predictable action and explanation. In the
normal live path, Tactical Engine performs first-minute triage and the Evidence
Plane plus deterministic evaluators add second-pass context. For booth
demonstrations such as Black Hat USA 2026, deterministic replay can be used as
a presentation-stability technique, but it does not replace normal live
operation.

## Relationship to Core Architecture
This concept is a direct expression of the core Decision Loop and Evidence
Model, with emphasis on policy consistency, audit traceability, bounded action
selection, and operator-visible explanation.

## What This Concept Is Not
- Not AI-first threat adjudication
- Not opaque score generation
- Not a cloud SOC replacement
- Not autonomous AI defense
- Not event-specific branching of the codebase

## Public Arsenal Cross-Reference
- [Black Hat USA 2026](../arsenal/blackhat-usa-2026.md)
- [BHUSA 2026 Booth Message](../arsenal/bhusa-2026-booth-message.md)

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Evidence Model](../architecture/evidence-model.md)
- [Deception Routing](../architecture/deception-routing.md)
