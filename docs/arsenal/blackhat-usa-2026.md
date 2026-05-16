# Black Hat USA 2026

## Public Title
Azazel-Edge: Deterministic Edge Decision Support for Constrained SOC/NOC Operations

## Concept Profile
Deterministic Edge Decision Support

## Focus
Present reproducible deterministic scoring and policy-based action selection for constrained SOC/NOC operations.

## Demo Scope
- Deterministic evaluator split (NOC/SOC)
- Explicit bounded action arbitration
- Operator-visible explanation and audit context

## Core Capabilities Demonstrated
| Capability | Status | Notes |
|---|---|---|
| Split NOC/SOC deterministic evaluation | Implemented | Separate evaluation stages feed one arbiter. |
| Bounded action selection | Implemented | Uses explicit action classes only. |
| Policy-aware decision traceability | Implemented | Includes why-chosen and why-not-others context. |

## Relationship to Mainline Azazel-Edge
This Arsenal appearance demonstrates one operational profile of the same Azazel-Edge core platform. Regional presentation focus does not imply a separate codebase.

## Related Concept Profile
- [Deterministic Edge Decision Support](../concepts/deterministic-edge-decision-support.md)

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Deception Routing](../architecture/deception-routing.md)
- [Evidence Model](../architecture/evidence-model.md)
