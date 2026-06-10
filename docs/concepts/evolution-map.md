# Azazel-Edge Evolution Map

Azazel-Edge is maintained as a single core platform.
Each concept profile demonstrates a different operational assumption,
deployment model, and security value.

## Concept Profiles

| Concept | Focus | Typical Scenario | Status |
|---|---|---|---|
| Offline Edge-AI SOC/NOC | Offline operation, local analysis, compact edge demo | Isolated or network-constrained environments | Demonstrated |
| Deterministic Edge Decision Support | Reproducible scoring and policy-based response | Constrained SOC/NOC operations | Demonstrated |
| Auditable Emergency SOC/NOC | Explainable emergency operations, operator handoff, traceability | Shelter and field emergency networks with non-specialist operators | Concept profile |
| Auditable Edge SOC/NOC | Explanation, audit trail, reversible controls | Privacy-sensitive or regulated environments | Concept profile |
| Field-Deployable Scapegoat Gateway | Rapid deployment, deception, evidence export | Event, field, and critical infrastructure networks | Concept profile |

## Public Arsenal Demonstrations

| Event | Concept | Public Title |
|---|---|---|
| Black Hat Asia 2026 | Offline Edge-AI SOC/NOC | Azazel-Pi: Offline Edge-AI SOC/NOC Gateway with Mock-LLM Scoring and Ollama Fallback |
| Black Hat USA 2026 | Deterministic Edge Decision Support | Azazel-Edge: Deterministic Edge Decision Support for Constrained SOC/NOC Operations |

## CFP Candidates (Not Accepted)

| Target Event | Concept | Status |
|---|---|---|
| Black Hat Europe (candidate) | Auditable Edge SOC/NOC | CFP draft only — not accepted, not scheduled. See [CFP draft](../cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md). |

## Design Principle

The repository should not be forked for each regional presentation.
Regional differences should be represented as concept profiles, demo scenarios, configuration profiles, and documentation.

## Evolution Line

- `Deployable` emphasis: prove that constrained edge SOC/NOC can be launched and operated locally.
- `Auditable` emphasis: prove that selected actions are explainable, reviewable, and traceable after deployment.

## Related Concept Documents
- [Offline Edge-AI SOC/NOC](offline-edge-ai-socnoc.md)
- [Deterministic Edge Decision Support](deterministic-edge-decision-support.md)
- [Auditable Emergency SOC/NOC](auditable-emergency-socnoc.md)
- [Auditable Edge SOC/NOC](auditable-edge-socnoc.md)
- [Auditable Profile Translation Matrix](auditable-profile-diff.md)
- [Field-Deployable Scapegoat Gateway](field-deployable-scapegoat-gateway.md)
