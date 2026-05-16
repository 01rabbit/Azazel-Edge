# Decision Loop

## Scope
This document describes the stable deterministic path used by Azazel-Edge to convert edge telemetry into explicit operator-facing actions.

## Pipeline
1. Event input (for example Suricata EVE and local probes) is received.
2. Inputs are normalized into Evidence Plane records.
3. NOC and SOC evaluators score state deterministically.
4. Policy thresholds are applied.
5. Action Arbiter selects one bounded action.
6. Decision Explanation is generated with rationale and alternatives.
7. Notification and optional AI assist are executed post-decision.
8. Audit logging records the full trace.

## Stable Components
| Component | Status | Notes |
|---|---|---|
| Evidence normalization | Implemented | Evidence Plane schema and bus are part of runtime baseline. |
| Deterministic evaluators | Implemented | NOC and SOC remain separate evaluators. |
| Policy-based action selection | Implemented | Arbiter action set is bounded. |
| Reversible control posture | Implemented | Actions are explicit and operator-reviewable. |
| Reproducibility metadata (`config hash`) | Planned | Partial support exists; full packaging across all outputs is still maturing. |

## Safety Constraints
- Deterministic path remains authoritative.
- AI assist is optional and invoked only after deterministic decision stages.
- Fail-closed defaults are retained for protected API behavior.

## Related Documents
- [P0 Runtime Architecture](../P0_RUNTIME_ARCHITECTURE.md)
- [Evidence Model](evidence-model.md)
- [Local AI Triage](local-ai-triage.md)
