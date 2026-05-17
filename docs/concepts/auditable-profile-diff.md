# Auditable Profile Translation Matrix

## Purpose
Provide a neutral mapping between the two auditable concept profiles so teams can reuse one deterministic core while changing only operational framing.

## Shared Auditable Core
- Deterministic action selection remains primary
- Decision Explanation includes reason, rejected alternatives, and release condition
- Audit trace continuity is preserved with `trace_id`
- AI assist remains advisory and governed

## Profile Translation Table

| Dimension | Auditable Emergency SOC/NOC | Auditable Edge SOC/NOC |
|---|---|---|
| Primary operator context | Time-critical emergency operations with mixed operator skill | Privacy-sensitive and regulated routine operations |
| Typical deployment posture | Temporary or rapidly assembled local networks | Stable local environments requiring accountability |
| Primary message | Operate safely under pressure with reviewable decisions | Operate accountably with explainable deterministic decisions |
| Emphasized artifacts | Handoff evidence, release condition clarity, rejected alternatives | Traceability, policy reproducibility, external review readiness |
| Policy tendency | Conservative reversible controls under uncertain field conditions | Conservative controls aligned with compliance-oriented review |
| AI wording style | Minimize ambiguity for non-specialist handoff | Minimize ambiguity for auditor and reviewer interpretation |

## Implementation Guidance
- Keep one runtime path and one evaluator/arbiter logic.
- Express differences through profile metadata, scenario packs, and operator-facing wording.
- Avoid introducing event- or venue-specific profile IDs in runtime logic.
