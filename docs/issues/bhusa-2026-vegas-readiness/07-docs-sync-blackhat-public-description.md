# BHUSA 2026: sync repository docs with public Black Hat description

Parent roadmap: #283

## Purpose

Update repository-facing documentation so the public Black Hat Arsenal description is accurately reflected in the project docs without over-claiming implementation scope.

## Public description points to preserve

- Azazel-Edge is a deterministic edge decision appliance for small, temporary, and rapidly deployed networks.
- Target constraints include limited infrastructure, limited personnel, unstable connectivity, and little time to decide.
- The local decision loop evaluates NOC reliability and SOC threat context separately.
- The Action Arbiter resolves evaluations deterministically.
- Selected evidence, rejected alternatives, and structured explanation are recorded.
- Tactical Engine performs first-minute triage in the live path.
- Evidence Plane and deterministic evaluators add second-pass context.
- Optional AI assistance is bounded to operator support.
- Replay is used for demonstration stability only and does not replace live Tactical first-pass operation.

## Tasks

- [ ] Update `docs/arsenal/blackhat-usa-2026.md` with date, time, station, track, public title, and concise abstract summary.
- [ ] Update `docs/ARSENAL_DEMO_PROFILE.md` to include the replay-vs-live boundary statement.
- [ ] Update or cross-link `docs/concepts/deterministic-edge-decision-support.md` so the concept profile mirrors the accepted public description.
- [ ] Ensure README Arsenal section points to the correct USA 2026 page and does not imply a separate codebase.
- [ ] Add a short `BHUSA 2026 booth message` section or linked note for presenter use.
- [ ] Verify all references avoid claims of autonomous AI defense, full SIEM replacement, or cloud SOC replacement.

## Acceptance criteria

- Repository docs match the public Black Hat Arsenal page content supplied for the accepted session.
- The docs preserve the accepted theme and do not rebrand the talk.
- Replay-only demonstration is documented as a booth technique, not as the normal live operation model.
- AI assistance is consistently described as optional operator support outside core action selection.

## References

- `README.md`
- `docs/arsenal/blackhat-usa-2026.md`
- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/concepts/deterministic-edge-decision-support.md`
