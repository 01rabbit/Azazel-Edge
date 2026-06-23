# BHUSA 2026: booth rehearsal and failure runbook

Parent roadmap: #283

## Purpose

Create a Vegas-ready rehearsal and failure runbook for Arsenal Station 4 so the presentation remains stable under booth constraints.

Public session:

- Date: Wednesday, August 5
- Time: 10:10am-11:10am
- Location: Arsenal Station 4, Business Hall
- Track: Network

## Tasks

- [ ] Prepare pre-demo boot checklist for the target device.
- [ ] Prepare service health checklist for `azazel-edge-web`, `azazel-edge-control-daemon`, `azazel-edge-core`, and `azazel-edge-opencanary` where applicable.
- [ ] Prepare deterministic replay checklist.
- [ ] Prepare audit review checklist.
- [ ] Prepare Web UI fallback to CLI and JSON logs.
- [ ] Prepare live-assisted fallback to replay-only.
- [ ] Prepare no-network operation checklist.
- [ ] Prepare no-AI operation checklist.
- [ ] Prepare reset procedure between visitors.
- [ ] Prepare final booth laptop layout: browser, terminal, notes, and backup files.
- [ ] Prepare one offline copy of key docs and commands.
- [ ] Run at least three full rehearsals using the final booth script.
- [ ] Record actual run time for 90-second, 5-minute, and full walkthrough variants.

## Acceptance criteria

- The booth demo can run with no Internet dependency.
- The deterministic replay path is available as final fallback.
- A failed optional component does not stop the core explanation.
- The presenter can recover or switch paths without editing code during the session.
- The full rehearsal proves the accepted Arsenal story: deterministic edge decision support, separate NOC/SOC evaluation, bounded arbitration, structured explanation, and auditability.

## References

- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/arsenal/blackhat-usa-2026.md`
- `bin/azazel-edge-demo`
- `bin/azazel-edge-audit-review`
