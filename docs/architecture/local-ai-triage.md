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
| AI assist through governance entrypoint | Implemented | Governed path is required for in-scope AI calls. |
| Output type limits (`advice/summary/candidate`) | Implemented | Governance constraints are explicit. |
| AI as final action authority | Not allowed | Action decisions stay in deterministic control path. |
| Broad autonomous execution | Not allowed | Controlled execution requires explicit approval design. |

## Limitations
- AI response quality depends on local model/runtime availability.
- AI downtime must not block deterministic operation.
- High-cost models are not default for constrained co-located Raspberry Pi deployments.

## Related Documents
- [AI Operation Guide](../AI_OPERATION_GUIDE.md)
- [P0 Runtime Architecture](../P0_RUNTIME_ARCHITECTURE.md)
- [Decision Loop](decision-loop.md)
