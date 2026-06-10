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

## Canonical decision-explanation schema (v2)

Records are produced by `DecisionExplainer.explain()` in
`py/azazel_edge/explanations/decision.py` and written in JSONL format to:

```
/var/log/azazel-edge/decision-explanations.jsonl
```

Status: **Implemented**

| Field | Type | Meaning |
|---|---|---|
| `ts` | str | ISO 8601 timestamp (UTC, second precision) of when the explanation was generated. |
| `trace_id` | str | Correlation identifier threaded from the upstream event through the Python pipeline. |
| `format_version` | str | Schema version; always `"v2"` for records produced by the current explainer. |
| `selected_action` | str | The action chosen by the arbiter (e.g. `redirect`, `notify`, `isolate`). |
| `reason` | str | Machine-readable reason code for the chosen action. |
| `rejected_actions` | list[str] | Names of the alternative actions that were evaluated and not chosen. |
| `release_condition` | str | Condition under which the applied control should be lifted. |
| `policy_profile` | str | Identifier of the policy version that governed this decision. |
| `config_hash` | str | Hash of the active policy/config at decision time (e.g. `sha256:…`). |
| `why_chosen` | dict | Structured rationale: NOC/SOC states, attack candidates, TI matches, runbook support, client impact, affected scope, and other context used to support the selected action. |
| `why_not_others` | list[dict] | Per-alternative rejection records, each carrying `action` and `reason`. |
| `evidence_ids` | list | IDs of the evidence artefacts that were used to support the decision. |
| `next_checks` | list | Recommended follow-up checks for the operator, derived deterministically from action and state. |
| `operator_wording` | str | Human-readable summary sentence for operator review. |
| `machine` | dict | Raw machine context snapshot: `noc_summary`, `soc_summary`, and the full `arbiter` dict. |
| `trust_capsule` | dict | Integrity capsule signed with HMAC-SHA256; carries `trace_id`, `action`, `confidence`, `evidence_ids`, `hmac_sig`, `ai_contributed`, and `ai_advice_hash`. |

### Tactics-engine DecisionLogger (distinct engine-trace stream)

`DecisionLogger` (in `py/azazel_edge/tactics_engine/decision_logger.py`) writes a
**separate, low-level internal engine/scoring trace** to:

```
/opt/azazel-edge/logs/tactics_engine/decision_explanations.jsonl
```

Its records carry the following fields:

| Field | Notes |
|---|---|
| `ts` | ISO 8601 timestamp of the scoring turn. |
| `decision_id` | UUID generated per turn. |
| `engine` | Dict with `name` and `version` of the Tactics Engine. |
| `config_hash` | Hash of the active engine config. |
| `inputs_snapshot` | Source label, event digest, and minimal raw event data. |
| `features` | Feature vector extracted by the judge for this turn. |
| `state_before` | State/suspicion/risk snapshot before the turn. |
| `score_delta` | Suspicion add and decay values applied this turn. |
| `constraints_triggered` | List of constraint names that fired (e.g. `cooldown_hit`). |
| `chosen` | List of chosen transitions or actions with detail dicts. |
| `state_after` | State/suspicion/risk snapshot after the turn. |
| `parse_errors` | Count of parse failures encountered during the turn. |

This stream is a **distinct stream** from the canonical v2 explanation record.
It is a low-level internal engine/scoring trace, not the operator-facing decision
record.  It intentionally omits `rejected_actions` and `release_condition`
because those fields belong to the canonical operator decision record (the v2
explanation), which does carry them.  The two streams must not be conflated.

### trace_id expectations

Within the Python pipeline, the same `trace_id` value appears on the v2
explanation record and on the related `P0AuditLogger` chain records (each audit
record carries `trace_id` as a top-level field).  Tests in
`tests/test_decision_explanation_schema_v1.py` confirm this continuity for the
Python-internal path.

**Limitation (Prototype gap):** Automatic threading of `trace_id` from the
Rust core into the Python pipeline is **not verified** and has no integration
test.  The Rust-core → Python `trace_id` handoff is a known gap; do not assume
it works end-to-end until an integration test is in place.

Status of Rust → Python trace_id threading: **Prototype**

## Related Documents
- [Decision Loop](decision-loop.md)
- [P0 Runtime Architecture](../P0_RUNTIME_ARCHITECTURE.md)
- [Concept: Auditable Edge SOC/NOC](../concepts/auditable-edge-socnoc.md)
