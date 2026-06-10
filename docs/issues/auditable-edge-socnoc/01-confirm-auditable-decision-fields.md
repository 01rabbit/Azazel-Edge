<!--
Register with:
gh issue create \
  --title "[CFP] Confirm current auditable decision fields" \
  --body-file docs/issues/auditable-edge-socnoc/01-confirm-auditable-decision-fields.md \
  --label "auditable-edge-socnoc-cfp" --label "testing" --label "audit"
-->

## Summary

Turn the 2026-06-10 code audit of the auditable decision fields into a durable,
repeatable verification artifact: a documented field inventory for the v2
decision-explanation record and the Action Arbiter output, plus a pytest that
asserts the required auditable fields are present in a generated explanation
record.

Status note: on 2026-06-10 the required fields were verified present in
`DecisionExplainer` v2 output and `ActionArbiter` output. This issue does not add
new fields; it makes that verification automatic so the claim cannot silently
regress before submission.

## Rationale

The CFP draft and paper claim that each decision records its selected action,
rejected alternatives, a release condition, the active policy profile, a config
hash, a trace id, consulted evidence ids, and operator-facing wording. A one-time
manual audit is not durable. A focused test keeps the submission claim honest and
makes the field set the demo walk depends on resistant to regression.

## Tasks

- [ ] Document a field inventory for the v2 explanation record (from
      `py/azazel_edge/explanations/decision.py`) and the arbiter output (from
      `py/azazel_edge/arbiter/action.py`), noting which field name appears on which
      record (e.g. `rejected_alternatives` on the arbiter, `rejected_actions` /
      `why_not_others` on the explanation).
- [ ] Add a pytest that generates an explanation record from a representative
      decision and asserts presence (and basic type) of: `selected_action`,
      `rejected_actions` (and arbiter `rejected_alternatives`), `release_condition`,
      `policy_profile`, `config_hash`, `trace_id`, `evidence_ids`, and
      `operator_wording`.
- [ ] Assert the record carries `format_version` `v2`.
- [ ] Record in the test docstring that this codifies the 2026-06-10 audit.

## Acceptance Criteria

- [ ] A documented field inventory exists (in the test module docstring and/or a
      docs note) listing each required field and its source record.
- [ ] A new pytest fails if any of the listed required fields is missing from a
      freshly generated explanation record.
- [ ] The test passes against current code with no production-code change required.
- [ ] The test asserts `format_version == "v2"`.

## Files Likely Affected

- `py/azazel_edge/explanations/decision.py` (read-only reference)
- `py/azazel_edge/arbiter/action.py` (read-only reference)
- `tests/` (new test, e.g. `tests/test_decision_explanation_fields_v1.py`)
- `docs/roadmaps/auditable-edge-socnoc-cfp-roadmap.md` (cross-reference)

## Dependencies

None. This is the first issue in the implementation order; Issues 02-06 build on
the field set confirmed here.

## Risk

Low. Read-only verification plus a new test; no production behavior changes. The
only risk is encoding the field set incorrectly, mitigated by asserting against
real generated output rather than a hand-written fixture.
