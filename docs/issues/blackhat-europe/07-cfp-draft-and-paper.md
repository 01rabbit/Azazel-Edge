<!--
Register with:
gh issue create \
  --title "[BHEU] CFP draft and paper" \
  --body-file docs/issues/blackhat-europe/07-cfp-draft-and-paper.md \
  --label "blackhat-europe" --label "documentation"
-->

## Summary

Track the CFP submission draft and the supporting paper for the Auditable Edge
SOC/NOC profile. The bulk of this work is already done in this branch (commit
ff8ef98). This issue records what landed and lists only the genuinely remaining
pre-submission tasks.

## Rationale

A reviewable submission needs a CFP draft and a backing paper whose every claim
matches repository state. Most of that exists. What remains is review and fitting,
not authoring: a claims/safety sign-off, fitting the abstracts to the actual Black
Hat submission-form character limits, and a final proofread before submission.

## Tasks

Already done (commit ff8ef98), recorded for traceability:

- [x] CFP draft written: `docs/cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md`.
- [x] Paper written: `docs/papers/auditable-edge-socnoc-europe.md`.
- [x] `docs/INDEX.md` "CFP Drafts and Papers" section added.
- [x] README links added.
- [x] Evolution-map "CFP Candidates (Not Accepted)" section added.
- [x] Concept-doc planning links added
      (`docs/concepts/auditable-edge-socnoc.md`).
- [x] CHANGELOG entry added.

Remaining:

- [ ] Claims/safety review sign-off: confirm no forbidden hype phrasing, that every
      Implemented/Prototype/Planned label matches ground truth, and that AI-advisory
      / enforcement-off-by-default boundaries are stated accurately. (Use the Issue
      09 check.)
- [ ] Fit the short and detailed abstracts to the actual Black Hat Europe Arsenal
      submission-form character limits, without introducing new claims.
- [ ] Final proofread of the CFP draft and paper before submission.

## Acceptance Criteria

- [ ] A recorded claims/safety sign-off exists (e.g. a checked item or note) for the
      CFP draft and paper.
- [ ] Abstract variants exist that fit the submission-form character limits and
      contain no claims absent from the full draft.
- [ ] A final proofread pass is completed and noted.
- [ ] The CFP draft remains outside `docs/arsenal/` and continues to state that no
      acceptance is implied.

## Files Likely Affected

- `docs/cfp/blackhat-europe-arsenal-auditable-edge-socnoc.md`
- `docs/papers/auditable-edge-socnoc-europe.md`

## Dependencies

Depends on Issue 09 (claims-discipline check) for the sign-off, and reflects the
status established by Issues 01-06.

## Risk

Low. Remaining work is review and fitting on already-landed documents. The main
risk is over-claiming when trimming abstracts to fit limits; mitigated by running
the Issue 09 check on the final text.
