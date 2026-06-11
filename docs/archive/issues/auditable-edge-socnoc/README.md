# Auditable Edge SOC/NOC Issue Drafts

Archived issue drafts for the completed Auditable Edge SOC/NOC CFP-readiness workstream.
These files remain as historical planning artifacts and traceability records.
Nothing here implies acceptance, scheduling, or review by any event.

These are source-controlled issue bodies, not registered issues. Each file is a
self-contained issue body with a suggested `gh` registration command in an HTML
comment at the top.

## Register an issue with gh

Each file's header comment gives the exact command. The general form is:

```sh
gh issue create \
  --title "[CFP] <title>" \
  --body-file docs/archive/issues/auditable-edge-socnoc/NN-<slug>.md \
  --label "auditable-edge-socnoc-cfp" --label "<documentation|demo|tooling|testing|audit>"
```

Create the `auditable-edge-socnoc-cfp` label once if it does not exist:

```sh
gh label create auditable-edge-socnoc-cfp --description "candidate CFP readiness for the Auditable Edge SOC/NOC profile" --color "5319e7"
```

## Files

- `01-confirm-auditable-decision-fields.md`
- `02-normalize-decision-explanation-jsonl.md`
- `03-add-rejected-alternatives-release-conditions.md`
- `04-config-hash-policy-profile-traceability.md`
- `05-audit-trace-viewer-cli-review-path.md`
- `06-europe-demo-auditable-edge-socnoc.md`
- `07-cfp-draft-and-paper.md`
- `08-docs-navigation-readme-links.md`
- `09-claims-discipline-validation.md`
- `10-arsenal-demo-dry-run-checklist.md`

See the roadmap: `docs/archive/roadmaps/auditable-edge-socnoc-cfp-roadmap.md`.
