<!--
Register with:
gh issue create \
  --title "[CFP] Audit trace viewer / CLI review path" \
  --body-file docs/issues/auditable-edge-socnoc/05-audit-trace-viewer-cli-review-path.md \
  --label "auditable-edge-socnoc-cfp" --label "tooling" --label "documentation"
-->

## Summary

Add a read-only, operator-facing review command that walks a decision through its
explanation record and the hash-chained audit log, give it a reviewer-friendly
output suited to the Arsenal demo, and document the review path. Build on the
existing review surfaces; do not add any write or enforcement capability.

## Rationale

Review surfaces already exist: Web API endpoints (`/api/triage/audit`,
`/api/demo/explanation/latest`), a unified CLI, and a TUI. What is missing is a
single command that performs the decision -> explanation -> audit-chain walk a
reviewer cares about: show the latest (or a selected) decision explanation, then
verify the audit chain and surface the chain status. This is the live portion of
the demo's "explanation review" and "audit chain review" steps and should be
read-only.

## Tasks

- [ ] Add a read-only review subcommand to the unified CLI that:
      - prints the latest (or a `--trace-id` selected) v2 explanation record fields
        relevant to review (`selected_action`, `rejected_actions` / `why_not_others`,
        `release_condition`, `policy_profile`, `config_hash`, `trace_id`,
        `evidence_ids`, `operator_wording`);
      - runs `verify_chain` over the audit log and reports OK or the first mismatch
        position.
- [ ] Ensure the command performs no writes, no policy changes, and no enforcement.
- [ ] Provide a compact, reviewer-friendly output mode suitable for a booth screen.
- [ ] Document the review path (command usage and the decision -> explanation ->
      audit walk) in the demo guide / review documentation.
- [ ] Add a test for the command's read-only behavior and chain-status reporting,
      including the case where a tampered record is detected.

## Acceptance Criteria

- [ ] A documented read-only CLI subcommand exists that shows a decision
      explanation and verifies the audit chain.
- [ ] The command makes no writes and cannot trigger enforcement (verified by test
      and/or by construction).
- [ ] The command reports chain OK and reports the first mismatch on a tampered log.
- [ ] The review path is documented end to end for demo use.

## Files Likely Affected

- unified CLI entry (e.g. `bin/azazel-edge-*` and the CLI module under
  `py/azazel_edge/`)
- `py/azazel_edge/audit/logger.py` (`verify_chain`; reference)
- `py/azazel_edge/explanations/decision.py` (record source; reference)
- `docs/DEMO_GUIDE.md`, `docs/ARSENAL_DEMO_PROFILE.md` (review-path documentation)
- `tests/` (read-only behavior and chain-status test)

## Dependencies

Depends on Issues 01 and 02 (confirmed fields and canonical schema) and benefits
from Issues 03-04 (consistent fields across streams). Used by Issue 06's demo walk
and rehearsed in Issue 10.

## Risk

Low. The command is read-only by design. The only risk is accidental coupling to a
write path; mitigated by asserting read-only behavior in tests and keeping the
command on the verification / display code paths only.
