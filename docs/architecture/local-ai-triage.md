# Local AI Triage

## Scope
This document defines the optional local AI assist role in Azazel-Edge.

## Design Position
- Local-first operation is the default design goal.
- Cloud dependency is not required for core deterministic behavior.
- AI assist is governed and secondary to deterministic evaluators and arbiter.

## Supported Uses
- Summarization of deterministic outputs
- Operator-facing explanation support
- Triage hints and candidate next checks
- Runbook suggestion support

## Boundaries
| Boundary | Status | Notes |
|---|---|---|
| AI assist through governance entrypoint | Implemented | Governed path is required for in-scope AI calls. In the running services only the M.I.O. cognitive core's model adapter calls it; the agent's analyst, ops-coach and manual-query calls are out of scope by contract and record `in_scope=false` ([AI Operation Guide](../AI_OPERATION_GUIDE.md) §3.1). |
| Output type limits (`advice/summary/candidate`) | Implemented | Governance constraints are explicit. |
| AI as final action authority | Not allowed | Action decisions stay in deterministic control path: the Rust core decides before the agent receives the event. |
| Broad autonomous execution | Not allowed | Controlled execution requires explicit approval design. |

## Limitations
- AI response quality depends on local model/runtime availability.
- AI downtime must not block deterministic operation.
- High-cost models are not default for constrained co-located Raspberry Pi deployments.

Component authority (decide, enforce, advise, display, audit) and the
degradation ladder are in the [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

## Related Documents
- [M.I.O. Cognitive Plane](mio-cognitive-plane.md)
- [AI Operation Guide](../AI_OPERATION_GUIDE.md)
- [P0 Runtime Architecture](../P0_RUNTIME_ARCHITECTURE.md)
- [Decision Loop](decision-loop.md)
