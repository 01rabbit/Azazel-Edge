<!--
Register with:
gh issue create \
  --title "[CFP] Normalize decision-explanation JSONL schema" \
  --body-file docs/issues/auditable-edge-socnoc/02-normalize-decision-explanation-jsonl.md \
  --label "auditable-edge-socnoc-cfp" --label "documentation" --label "testing"
-->

## Summary

Document the `DecisionExplainer` v2 JSONL record as the canonical
decision-explanation schema, define its relationship to the second
decision-explanation stream (the tactics-engine `DecisionLogger`), add a
schema-validation helper plus test, and make trace_id presence and threading
expectations across streams explicit.

## Rationale

There are currently two decision-explanation JSONL writers with different schemas:

- **Canonical (v2):** `DecisionExplainer` writes to
  `/var/log/azazel-edge/decision-explanations.jsonl` with fields including `ts`,
  `trace_id`, `format_version`, `selected_action`, `reason`, `rejected_actions`,
  `release_condition`, `policy_profile`, `config_hash`, `why_chosen`,
  `why_not_others`, `evidence_ids`, `next_checks`, `operator_wording`, `machine`,
  and `trust_capsule` (with `hmac_sig`).
- **Tactics-engine:** `DecisionLogger` writes to
  `/opt/azazel-edge/logs/tactics_engine/decision_explanations.jsonl` with fields
  `ts`, `decision_id`, `engine`, `config_hash`, `inputs_snapshot`, `features`,
  `state_before`, `score_delta`, `constraints_triggered`, `chosen`, `state_after`,
  `parse_errors`. It has no rejected-alternatives or release-condition fields.

Reviewers should not have to reverse-engineer which record is authoritative.
trace_id threading is a known Prototype gap: the Rust core computes its own
trace_id, and automatic end-to-end threading into the Python pipeline is not
verified and has no integration test.

## Tasks

- [ ] Document the v2 record as the canonical decision-explanation schema (field
      names, types, meaning, and the canonical output path).
- [ ] Document the tactics-engine `DecisionLogger` schema and explicitly decide its
      relationship to the canonical schema: either map its fields onto the canonical
      record or mark it as a distinct internal engine-trace stream (and say why it
      omits rejected-alternatives / release-condition).
- [ ] Add a schema-validation helper that checks a v2 record against the documented
      schema (required keys, types) and a pytest exercising it on a generated record.
- [ ] Record trace_id expectations across streams: within the Python pipeline the
      same trace_id should appear on the explanation and the related audit records.
- [ ] For the Rust core -> Python boundary, add an integration test for automatic
      trace_id threading, or, if it cannot be made to pass yet, record the gap as a
      documented limitation labeled Prototype (do not claim it works).

## Acceptance Criteria

- [ ] A schema document names the v2 record as canonical and lists every field.
- [ ] The tactics-engine schema relationship is explicitly documented (mapped or
      scoped as distinct), including why it lacks rejected-alternatives / release-
      condition fields.
- [ ] A schema-validation helper exists and a pytest validates a generated v2 record.
- [ ] trace_id continuity within the Python pipeline is asserted by a test, OR the
      threading gap is documented as Prototype with no overstated claim.

## Files Likely Affected

- `py/azazel_edge/explanations/decision.py` (canonical v2 writer; reference)
- tactics-engine `DecisionLogger` module (second stream; reference / mapping)
- `docs/architecture/evidence-model.md` (schema documentation cross-reference)
- `tests/test_decision_explanation_v2.py` style (new schema-validation test)
- `docs/roadmaps/auditable-edge-socnoc-cfp-roadmap.md`

## Dependencies

Depends on Issue 01 (field inventory). Feeds Issues 03 and 04, which extend the
non-canonical streams, and Issue 05, whose review walk uses only the canonical
record.

## Risk

Medium. The schema duality is genuine and is the most likely thing to confuse a
reviewer; if it is mis-documented the submission claims could be undercut. Risk is
bounded by keeping the v2 record clearly canonical and being candid about the
tactics-engine stream and the Prototype trace_id threading gap.
