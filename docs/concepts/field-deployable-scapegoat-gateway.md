# Field-Deployable Scapegoat Gateway

## Purpose
Define a concept profile for rapid deployment of an edge SOC/NOC gateway that can use deception-assisted response in constrained field networks.

## Operational Assumption
- Deployment speed and operational clarity are critical.
- Deterministic policy selects whether to observe, throttle, redirect, or isolate.
- Deception routing is controlled, bounded, and reviewable.

## Target Environment
- Event and venue networks
- Critical infrastructure edge segments
- Mobile or temporary command-post deployments

## Core Capabilities
| Capability | Status | Notes |
|---|---|---|
| Rapid edge gateway setup on Raspberry Pi | Implemented | Installer and deployment guides exist for constrained runtime. |
| Deception-assisted redirect path | Implemented | OpenCanary redirect integration exists in current stack. |
| Reversible action posture for incident handling | Implemented | Action model is bounded and operator-visible. |
| Incident evidence bundle export workflow | Conceptual | Unified field-operator bundle workflow is not fully formalized. |

## Demo Narrative
This profile demonstrates how a single edge node can stabilize first-response operations, surface deterministic decisions, and optionally use redirect/deception to reduce immediate exposure.

## Relationship to Core Architecture
This concept reuses the same Decision Loop and Evidence Model while emphasizing Deception Routing behavior for constrained deployments.

## What This Concept Is Not
- Not autonomous active defense
- Not a promise of complete attack prevention
- Not a separate regional fork

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Deception Routing](../architecture/deception-routing.md)
- [Evidence Model](../architecture/evidence-model.md)
