# Black Hat USA 2026

## Public Title
Azazel-Edge: Deterministic Edge Decision Support for Constrained SOC/NOC Operations

## Public Session
- Presenter: Makoto "Mr. Rabbit" SUGITA
- Date: Wednesday, August 5, 2026
- Time: 10:10am-11:10am
- Location: Arsenal Station 4, Business Hall
- Track: Network

## Public Summary
Azazel-Edge is presented as a deterministic edge decision appliance for small,
temporary, and rapidly deployed networks where operators face limited
infrastructure, limited personnel, unstable connectivity, and little time to
decide. The live path performs first-minute Tactical triage, then the Evidence
Plane, separate NOC/SOC evaluators, and the Action Arbiter add bounded,
inspectable second-pass context.

## Concept Profile
Deterministic Edge Decision Support

## Focus
Present reproducible deterministic scoring and policy-based action selection for
constrained SOC/NOC operations without implying cloud SOC replacement,
autonomous AI control, or a separate product line.

## Demo Scope
- Deterministic evaluator split (NOC/SOC)
- Explicit bounded action arbitration
- Operator-visible explanation and audit context
- Replay-based booth stability for a short public session

## Core Capabilities Demonstrated
| Capability | Status | Notes |
|---|---|---|
| Split NOC/SOC deterministic evaluation | Implemented | Separate evaluation stages feed one arbiter. |
| Bounded action selection | Implemented | Uses explicit action classes only. |
| Policy-aware decision traceability | Implemented | Includes why-chosen and why-not-others context. |
| Optional AI operator assist | Implemented | Bounded to operator support and not part of core action authority. |

## Live Path vs Booth Demonstration
- Normal operation: Tactical Engine performs first-minute triage on live events,
  then deterministic evaluators and the Action Arbiter add second-pass context.
- Booth demonstration: deterministic replay is preferred for presentation
  stability and does not replace the normal live Tactical first-pass path.

## Presenter Note
- Short booth message: [BHUSA 2026 Booth Message](bhusa-2026-booth-message.md)
- Canonical talk track: [BHUSA 2026 Talk Track](bhusa-2026-talk-track.md)

## Relationship to Mainline Azazel-Edge
This Arsenal appearance demonstrates one operational profile of the same Azazel-Edge core platform. Regional presentation focus does not imply a separate codebase.

## Related Concept Profile
- [Deterministic Edge Decision Support](../concepts/deterministic-edge-decision-support.md)
- [Arsenal Demo Profile](../ARSENAL_DEMO_PROFILE.md)

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Deception Routing](../architecture/deception-routing.md)
- [Evidence Model](../architecture/evidence-model.md)
