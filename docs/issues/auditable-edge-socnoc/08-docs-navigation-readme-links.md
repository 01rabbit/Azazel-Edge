<!--
Register with:
gh issue create \
  --title "[CFP] Docs navigation / README links" \
  --body-file docs/issues/auditable-edge-socnoc/08-docs-navigation-readme-links.md \
  --label "auditable-edge-socnoc-cfp" --label "documentation"
-->

## Summary

Track documentation navigation for the candidate CFP material. Most navigation
links landed in this branch (commit ff8ef98). This issue records what is done and
covers the remaining task: registering this roadmap and the issues directory in
`docs/INDEX.md` and the concept doc, while keeping any README addition minimal.

## Rationale

The CFP draft, paper, and their entry points are already linked from README, the
INDEX, the evolution map, and the concept doc. The newly added planning artifacts
(this roadmap and the `docs/issues/auditable-edge-socnoc/` directory) are not yet
discoverable from the INDEX or the concept doc, so a reader cannot navigate to the
plan from the canonical entry points.

## Tasks

Already done (commit ff8ef98), recorded for traceability:

- [x] README links to the CFP draft and paper.
- [x] `docs/INDEX.md` "CFP Drafts and Papers" section.
- [x] Evolution-map "CFP Candidates (Not Accepted)" section.
- [x] Concept-doc planning links.

Remaining:

- [x] Register `docs/roadmaps/auditable-edge-socnoc-cfp-roadmap.md` in
      `docs/INDEX.md` (appropriate section, with the no-acceptance framing).
- [x] Reference the roadmap and the `docs/issues/auditable-edge-socnoc/` directory from
      `docs/concepts/auditable-edge-socnoc.md` "Related Planning Documents".
- [ ] Keep the issues directory `README.md` minimal (what the dir is + how to
      register issues with `gh`); do not duplicate issue bodies elsewhere.
- [ ] Final navigation pass: confirm all relative links resolve from the rendered
      docs site as well as from the repository view.

## Acceptance Criteria

- [ ] `docs/INDEX.md` links to the roadmap.
- [ ] The concept doc references the roadmap and the issues directory.
- [ ] The issues directory `README.md` remains minimal and accurate.
- [ ] No new top-level README clutter; any README change is minimal.
- [ ] Navigation continues to state that no Black Hat acceptance is implied.

## Files Likely Affected

- `docs/INDEX.md`
- `docs/concepts/auditable-edge-socnoc.md`
- `docs/issues/auditable-edge-socnoc/README.md`

## Dependencies

Depends on the roadmap and issues directory existing (this task set). Reflects the
documents produced under Issue 07.

## Risk

Low. Navigation-only edits to existing index and concept documents. Risk is limited
to broken relative links; mitigated by verifying the paths resolve.
