# Black Hat Asia 2026

## Public Title
Azazel-Pi: Offline Edge-AI SOC/NOC Gateway with Mock-LLM Scoring and Ollama Fallback

## Concept Profile
Offline Edge-AI SOC/NOC

## Focus
Demonstrate offline-capable edge SOC/NOC decision support on constrained hardware with deterministic control path and optional local AI assist.

## Demo Scope
- Deterministic evidence-to-action flow
- Replay-safe demonstration mode
- Optional local advisory path when available

## Core Capabilities Demonstrated
| Capability | Status | Notes |
|---|---|---|
| Deterministic NOC/SOC evaluation | Implemented | Core evaluators and arbiter path. |
| Decision explanation and trace fields | Implemented | Includes selected action rationale and alternatives. |
| Optional local AI advisory fallback | Implemented | Bounded by governance; not authoritative. |

## Relationship to Mainline Azazel-Edge
This Arsenal appearance demonstrates one operational profile of the same Azazel-Edge core platform. It does not represent a separate long-term fork.

## Related Concept Profile
- [Offline Edge-AI SOC/NOC](../concepts/offline-edge-ai-socnoc.md)

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Local AI Triage](../architecture/local-ai-triage.md)
- [Evidence Model](../architecture/evidence-model.md)
