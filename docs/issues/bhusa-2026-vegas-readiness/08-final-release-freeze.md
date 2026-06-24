# BHUSA 2026: final release freeze and no-risk rule

Parent roadmap: #283

## Purpose

Define the final stabilization rule before Vegas so the accepted Arsenal demonstration is not destabilized by late-stage feature work.

## Freeze principle

Before the Arsenal session, prioritize repeatability, documentation accuracy, and operator-visible explanation over new capability. Late changes must not alter the deterministic core story unless they fix a clear demo blocker.

## Tasks

- [ ] Define a final demo branch or tag candidate.
- [ ] Define what changes are allowed after freeze: docs fixes, script notes, deterministic replay bug fixes, UI text fixes, and booth runbook corrections.
- [ ] Define what changes are not allowed after freeze: large refactors, new integrations, autonomous AI behavior, CTI sensorization, or broad architecture changes.
- [ ] Run the selected replay scenario and audit review on the freeze candidate.
- [ ] Archive exact commands, expected output snippets, and fallback commands.
- [ ] Confirm the README and docs still state that Azazel-Edge is not a production SIEM replacement and not an autonomous AI defender.
- [ ] Confirm all optional integrations are clearly optional.
- [ ] Confirm there is an offline fallback copy of the demo docs.

## Acceptance criteria

- There is a known-good branch/tag/commit for the Vegas demo.
- All final booth commands are documented.
- The selected replay and audit review run successfully on the target device.
- Any post-freeze change has a narrow justification tied to demo correctness or stability.
- The demo remains aligned with the public Arsenal title and description.

## References

- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/arsenal/blackhat-usa-2026.md`
- `docs/arsenal/bhusa-2026-freeze-candidate.md`
- `docs/arsenal/bhusa-2026-final-command-sheet.md`
- `docs/RELEASE_VERIFICATION_GUIDE.md`
- `docs/CHANGELOG.md`
