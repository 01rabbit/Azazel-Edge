# Auditable Edge SOC/NOC

## Purpose
Define a concept profile for privacy-sensitive and regulated operations where explainability, traceability, and reversible controls are prioritized.

## Operational Assumption
- Every response decision should be reviewable from recorded evidence.
- Audit records must preserve deterministic path context.
- AI assist must remain governed and secondary.

## Target Environment
- Privacy-sensitive organizations
- Regulated operational environments
- Teams requiring post-incident review and accountability

## Core Capabilities
| Capability | Status | Notes |
|---|---|---|
| Deterministic action decisions with rationale | Implemented | Decision explanation fields are required in core path. |
| Audit logging with `trace_id` correlation | Implemented | Audit logger is part of runtime baseline. |
| Structured evidence export for external review | Planned | Existing exports exist in parts of stack; unified profile-level packaging remains planned. |
| Reproducibility metadata (`config hash` alignment) | Planned | Policy/hash references exist; broader reproducibility packaging is not yet complete. |

## Demo Narrative
This profile focuses on showing how operators can justify decisions using deterministic outputs, explanation fields, and audit traces rather than relying on opaque automation.

## Relationship to Core Architecture
The profile depends on Decision Loop determinism, Evidence Model consistency, and AI governance boundaries.

## What This Concept Is Not
- Not a guarantee of legal compliance by itself
- Not full governance automation
- Not a future event acceptance claim

## Related Architecture Documents
- [Decision Loop](../architecture/decision-loop.md)
- [Evidence Model](../architecture/evidence-model.md)
- [Local AI Triage](../architecture/local-ai-triage.md)
