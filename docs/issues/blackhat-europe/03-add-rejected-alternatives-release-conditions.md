<!--
Register with:
gh issue create \
  --title "[BHEU] Add rejected alternatives and release conditions where missing" \
  --body-file docs/issues/blackhat-europe/03-add-rejected-alternatives-release-conditions.md \
  --label "blackhat-europe" --label "audit" --label "testing"
-->

## Summary

The main Action Arbiter decision path already records rejected alternatives and a
release condition for every decision. This issue audits the *other*
decision-bearing streams, adds those fields where they make operational sense, and
documents a deliberate reason where a stream intentionally omits them.

## Rationale

`ActionArbiter` (`py/azazel_edge/arbiter/action.py`) emits `rejected_alternatives`
(action + reason pairs) and a `release_condition` string, surfaced in the v2
explanation as `rejected_actions` / `why_not_others` and `release_condition`. This
is the headline differentiator in the CFP draft.

Other streams that record decisions do not all carry these fields:

- The tactics-engine `DecisionLogger` record has no rejected-alternatives or
  release-condition fields.
- The OpenCanary redirect path (`py/azazel_edge/opencanary_redirect.py`) records
  redirect decisions to state JSON, JSONL, and the audit chain; its records need
  checking for these fields.

Consistency here is what lets a reviewer trust that "the decision space is
visible" applies wherever a decision is recorded, not only on the primary path.

## Tasks

- [ ] State explicitly (in the schema doc) that the main arbiter path already
      carries both `rejected_alternatives` and `release_condition`.
- [ ] Enumerate every stream that records an action or decision (at minimum: the
      v2 explanation, the tactics-engine `DecisionLogger`, the OpenCanary redirect
      records, and any action-decision records in the audit chain).
- [ ] For each stream, verify whether rejected-alternatives and release-condition
      information is present.
- [ ] Where the fields make sense and are missing (e.g. the redirect record should
      carry the arbiter's release condition), add them, sourced from the arbiter
      output rather than recomputed.
- [ ] Where a stream intentionally omits them (e.g. a low-level engine trace),
      document the reason in the schema doc.
- [ ] Add or extend a test asserting the fields are present on each stream that is
      supposed to carry them.

## Acceptance Criteria

- [ ] A per-stream table records, for each decision-bearing stream, whether it
      carries rejected-alternatives and release-condition fields and why.
- [ ] Streams that should carry the fields and previously did not now do, with the
      values sourced from the arbiter output.
- [ ] A test asserts presence of these fields on each stream expected to carry them.
- [ ] No stream silently lacks the fields without a documented justification.

## Files Likely Affected

- `py/azazel_edge/arbiter/action.py` (source of truth; reference)
- `py/azazel_edge/opencanary_redirect.py` (redirect records; likely extended)
- tactics-engine `DecisionLogger` module (document omission or extend)
- `py/azazel_edge/audit/logger.py` (action-decision records; reference)
- `docs/architecture/evidence-model.md` (per-stream documentation)
- `tests/` (field-presence assertions)

## Dependencies

Depends on Issue 02 (stream inventory and canonical schema). Related to Issue 04,
which performs the same per-stream audit for `config_hash` / `policy_profile`.

## Risk

Medium. Editing the redirect path touches a decision-recording code path; changes
must add fields only and must not alter which decision is recorded or trigger any
enforcement (enforcement stays off by default). Tamper-evident chain behavior must
remain intact.
