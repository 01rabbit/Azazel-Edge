# Black Hat Europe Issue Drafts

This directory holds issue drafts for making the Auditable Edge SOC/NOC concept
profile CFP-submission-ready and demo-ready for a Black Hat Europe Arsenal
application. Nothing here implies acceptance, scheduling, or review by Black Hat.

These are source-controlled issue bodies, not registered issues. Each file is a
self-contained issue body with a suggested `gh` registration command in an HTML
comment at the top.

## Register an issue with gh

Each file's header comment gives the exact command. The general form is:

```sh
gh issue create \
  --title "[BHEU] <title>" \
  --body-file docs/issues/blackhat-europe/NN-<slug>.md \
  --label "blackhat-europe" --label "<documentation|demo|tooling|testing|audit>"
```

Create the `blackhat-europe` label once if it does not exist:

```sh
gh label create blackhat-europe --description "Black Hat Europe Arsenal CFP readiness" --color "5319e7"
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

See the roadmap: `docs/roadmaps/blackhat-europe-auditable-edge-socnoc-roadmap.md`.
