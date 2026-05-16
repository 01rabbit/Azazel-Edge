# Deterministic Edge Decision Support

## Purpose
Describe the operational profile centered on reproducible, policy-based decision support for constrained SOC/NOC operations.

## Operational Assumption
- The deterministic path is primary.
- Evaluator outputs and Action Arbiter decisions must be explainable and traceable.
- Optional integrations must not change core decision authority.

## Target Environment
- Constrained SOC/NOC teams
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
This profile demonstrates stable and repeatable edge decision support where the same evidence and policy produce a predictable action and explanation.

## Relationship to Core Architecture
This concept is a direct expression of the core Decision Loop and Evidence Model, with emphasis on policy consistency and audit traceability.

## What This Concept Is Not
- Not AI-first threat adjudication
- Not opaque score generation
- Not event-specific branching of the codebase

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Evidence Model](../architecture/evidence-model.md)
- [Deception Routing](../architecture/deception-routing.md)
