<!--
Register with:
gh issue create \
  --title "[BHEU] Arsenal demo dry-run checklist" \
  --body-file docs/issues/blackhat-europe/10-arsenal-demo-dry-run-checklist.md \
  --label "blackhat-europe" --label "demo"
-->

## Summary

Track a final pre-submission and pre-event rehearsal of the Auditable Edge SOC/NOC
demo: a full offline run on Raspberry Pi-class hardware, a fallback drill, timing,
and reviewer Q&A preparation including honest answers about Prototype and Planned
items and enforcement-off-by-default.

## Rationale

The demo is offline deterministic replay on constrained hardware. A rehearsal that
exercises the whole package on the target device de-risks the booth experience and
ensures the team can answer reviewer questions candidly. This is a tracking
checklist, not a code change.

## Tasks

- [ ] Run `bin/azazel-edge-demo run auditable_edge_socnoc` fully offline on the
      target Raspberry Pi-class device; confirm `deterministic_replay` and
      `ai_used = false`.
- [ ] Walk the v2 explanation fields on-device (`selected_action`,
      `rejected_actions` / `why_not_others`, `release_condition`, `policy_profile`,
      `config_hash`, `trace_id`, `evidence_ids`, `operator_wording`).
- [ ] Run the audit-chain verification and demonstrate a tampered record breaking
      the chain.
- [ ] Run the SOC policy dry-run (`bin/azazel-soc-policy-dry-run`) comparing two
      profiles; confirm reported policy hash and would-be decisions.
- [ ] Exercise the read-only review command (Issue 05).
- [ ] Perform a fallback drill: confirm replay-only mode with no live telemetry and
      no live enforcement, and a quick recovery if anything fails mid-demo.
- [ ] Time the full walk and trim to the booth slot.
- [ ] Prepare reviewer Q&A: honest framing of Prototype items (Rust->Python trace_id
      threading, runtime profile switching, live nft/tc enforcement) and Planned
      items (full reproducibility packaging, unified evidence bundle, automated
      release-condition orchestration), and confirm enforcement is off by default.
- [ ] Confirm the optional local-AI-assist aside (if shown) stays advisory and
      audited, and never changes a decision.

## Acceptance Criteria

- [ ] A completed offline rehearsal on Raspberry Pi-class hardware is recorded.
- [ ] The fallback drill passed (replay-only, no live enforcement).
- [ ] The full walk fits the intended booth timing.
- [ ] A reviewer Q&A note exists with honest Prototype/Planned answers and the
      enforcement-off-by-default statement.
- [ ] No step required or enabled live network enforcement.

## Files Likely Affected

- None (rehearsal / tracking). May reference `docs/DEMO_GUIDE.md` and
  `docs/ARSENAL_DEMO_PROFILE.md`.

## Dependencies

Depends on Issue 06 (the scenario), Issue 05 (review command), and Issues 01-04
(verified, consistent fields). Run last in the implementation order.

## Risk

Low. A rehearsal exercise. The main operational risk is accidentally enabling live
enforcement during the run; mitigated by keeping `AZAZEL_DEFENSE_ENFORCE` off and
confirming replay-only mode as an explicit checklist item.
