# Deception Routing

## Scope
This document describes how Azazel-Edge uses bounded, policy-driven routing choices when suspicious activity is observed.

## Decision Modes
- Observe: record and continue monitoring when risk is below active-control thresholds.
- Throttle: reduce traffic pace when service continuity is preferred over immediate isolation.
- Redirect: move selected traffic toward prepared decoy surfaces when mapping and safety checks permit.
- Isolate: apply strongest containment posture when risk and policy require it.

## OpenCanary Role
Prepared decoy services (for example OpenCanary) support redirect scenarios. Decoys are pre-positioned so constrained edge nodes can use deception routing without dynamic heavy provisioning.

## Blocking vs Delaying vs Redirecting
- Blocking/isolation: stop or contain connectivity to reduce immediate exposure.
- Delaying/throttling: preserve partial service while reducing attack velocity.
- Redirecting: preserve visibility and reduce direct asset exposure by diverting specific flows.

## Safety Constraints and Release Conditions
| Control | Status | Notes |
|---|---|---|
| Policy-gated action selection | Implemented | Arbiter selects only bounded actions. |
| Dry-run-first enforcement model | Implemented | Enforce mode is guarded by runtime configuration. |
| Redirect eligibility constraints | Implemented | Redirect path requires prepared mapping and runtime support. |
| Automated release-condition orchestration | Planned | Formal multi-condition release automation is not fully generalized. |

## Related Documents
- [Decision Loop](decision-loop.md)
- [SOC Policy Guide](../SOC_POLICY_GUIDE.md)
- [Concept: Field-Deployable Scapegoat Gateway](../concepts/field-deployable-scapegoat-gateway.md)
