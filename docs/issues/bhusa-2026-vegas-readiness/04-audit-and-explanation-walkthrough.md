# BHUSA 2026: audit and explanation walkthrough

Parent roadmap: #283

## Purpose

Make the explanation and audit path presentation-ready so the Arsenal demo can prove that Azazel-Edge records selected evidence, rejected alternatives, and structured explanation.

## Why this matters

The public Arsenal description emphasizes an explicit and auditable local decision loop. The demo must show not only that an action was selected, but also why it was selected, why other actions were rejected, and how the trace can be reviewed without mutating state.

## Tasks

- [ ] Verify `bin/azazel-edge-audit-review --compact` works after the selected replay scenario.
- [ ] Verify full formatted audit review output for deeper booth conversations.
- [ ] Verify JSON output for machine-readable inspection if asked.
- [ ] Confirm the explanation record includes `trace_id`, selected action, rejected actions, `why_not_others`, release condition, policy profile, config hash, evidence IDs, and operator wording.
- [ ] Confirm the audit chain verification reports OK for the selected scenario.
- [ ] Prepare a short script explaining hash-chained audit verification without overstating tamper-proof guarantees.
- [ ] Add one sample booth transcript showing replay command followed by compact audit review.
- [ ] Add a negative/failure note: what to say if audit verification reports mismatch.
- [ ] Ensure the command remains read-only and no control-plane state is modified.

## Acceptance criteria

- The audit walkthrough can be completed in under 2 minutes after the replay demo.
- The compact output is legible on a booth laptop screen.
- The full output supports detailed technical questions.
- The walkthrough proves the accepted claim: selected evidence, rejected alternatives, and structured explanation are recorded.
- The documentation clearly states the audit review command is read-only.

## References

- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/arsenal/bhusa-2026-audit-walkthrough.md`
- `bin/azazel-edge-audit-review`
- `tests/test_audit_review_v1.py`
- `py/azazel_edge/explanations/decision.py`
- `py/azazel_edge/audit/logger.py`
