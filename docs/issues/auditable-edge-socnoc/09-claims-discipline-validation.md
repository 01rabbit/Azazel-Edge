<!--
Register with:
gh issue create \
  --title "[CFP] Claims-discipline validation" \
  --body-file docs/issues/auditable-edge-socnoc/09-claims-discipline-validation.md \
  --label "auditable-edge-socnoc-cfp" --label "testing" --label "documentation"
-->

## Summary

Add an automated check (a validation script or pytest, e.g.
`tests/test_claims_discipline_v1.py`) that fails on forbidden hype phrasing in
README and docs, on any "Black Hat Europe" reference inside `docs/arsenal/`, and on
any file matching `auditable-edge-socnoc-cfp-*.md` inside `docs/arsenal/`. Optionally wire it
into CI (noting that CI changes need review).

## Rationale

The submission and supporting docs must stay sober and must not imply acceptance.
Manual review is error-prone, especially while abstracts are trimmed to fit
submission-form limits (Issue 07). An automated check makes the discipline
enforceable and repeatable, and guards the rule that CFP material must not appear
under `docs/arsenal/` before acceptance.

## Tasks

- [ ] Add a check that scans `README.md` and `docs/` and fails on forbidden hype
      phrases (case-insensitive): "world's first", "military-grade", "unbreakable",
      "guaranteed protection", "autonomous AI defender", and close variants. Exclude
      the check's own forbidden-phrase list from matching itself.
- [ ] Add a check that fails if any file under `docs/arsenal/` contains a
      "Black Hat Europe" reference (pre-acceptance guard).
- [ ] Add a check that fails if any file matching `docs/arsenal/auditable-edge-socnoc-cfp-*.md`
      exists (pre-acceptance guard).
- [ ] Implement as a pytest (e.g. `tests/test_claims_discipline_v1.py`) and/or a
      runnable script, so it works locally and in the validation grep set.
- [ ] Optionally wire into CI; note in the issue/PR that CI configuration changes
      require human review (per repository policy).
- [ ] Verify the check fails on a seeded violation and passes on the current tree.

## Acceptance Criteria

- [ ] The check fails when a forbidden hype phrase is present in README or docs.
- [ ] The check fails when `docs/arsenal/` contains a "Black Hat Europe" reference.
- [ ] The check fails when a `docs/arsenal/auditable-edge-socnoc-cfp-*.md` file exists.
- [ ] The check passes against the current repository state.
- [ ] A seeded-violation test demonstrates each failure path.

## Files Likely Affected

- `tests/test_claims_discipline_v1.py` (new) and/or a script under `bin/` or `tools/`
- `README.md`, `docs/` (scanned, not modified by the check)
- CI configuration (optional; requires human review)

## Dependencies

Independent of Issues 01-06; used by Issue 07 (claims/safety sign-off) and listed
in the roadmap's validation grep set. Should land before submission text is
finalized.

## Risk

Low. The check is read-only over the tree. The main risk is false positives from
overly broad patterns; mitigated by scoping phrases tightly and excluding the
check's own phrase list.
