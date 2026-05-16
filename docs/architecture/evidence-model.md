# Evidence Model

## Scope
This document describes how Azazel-Edge keeps compact, reviewable evidence for deterministic SOC/NOC decision support.

## Evidence Objects
- Event records: normalized telemetry inputs with source and trace correlation.
- Decision logs: evaluator and arbiter outputs with selected action rationale.
- Action records: operator-facing control intent and resulting state changes.
- Incident bundles: grouped evidence context for handoff or review.

## Auditability
Evidence records are designed to preserve traceability from observed input to selected action and explanation. `trace_id` continuity is required across stages.

## Raw Logs vs Compact Evidence
- Raw logs preserve original upstream detail and transport context.
- Compact evidence normalizes key fields for reproducible deterministic evaluation and operator review.

## Export Model
| Capability | Status | Notes |
|---|---|---|
| Normalized evidence records | Implemented | Evidence Plane schemas and buses exist in runtime modules. |
| Decision explanation records | Implemented | Explanation fields are part of deterministic path expectations. |
| Audit log event stream | Implemented | Baseline audit logger is included in runtime. |
| Unified incident bundle package format | Planned | Partial export paths exist; unified operator package remains in progress. |

## Related Documents
- [Decision Loop](decision-loop.md)
- [P0 Runtime Architecture](../P0_RUNTIME_ARCHITECTURE.md)
- [Concept: Auditable Edge SOC/NOC](../concepts/auditable-edge-socnoc.md)
