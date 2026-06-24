# BHUSA 2026: live Tactical first-pass boundary and fallback

Parent roadmap: #283

## Purpose

Clarify and test the boundary between the normal live Tactical first-pass path and the Arsenal deterministic replay path.

The public description states that the live path is layered: Tactical Engine performs first-minute triage on time-sensitive security events, then Evidence Plane and deterministic evaluators add second-pass context. The Arsenal replay path is for demonstration only and must not be presented as replacing the live Tactical path.

## Tasks

- [ ] Document the live Tactical first-pass path in the Vegas demo notes.
- [ ] Document the deterministic replay path as the preferred booth demonstration path.
- [ ] Add a clear diagram or table contrasting normal operation vs Arsenal replay demonstration.
- [ ] Verify a live-assisted path only if it can fall back immediately to replay-only mode.
- [ ] Define exact conditions for abandoning live-assisted demo during booth operation.
- [ ] Confirm Suricata failure fallback: switch to replay-only.
- [ ] Confirm OpenCanary failure fallback: continue replay without redirect execution path.
- [ ] Confirm network instability fallback: run local replay scenarios only.
- [ ] Confirm Ollama or AI failure fallback: continue deterministic core story.
- [ ] Ensure no public demo claim implies replay is normal-operation replacement.

## Acceptance criteria

- Normal operation and Arsenal demonstration are clearly separated in documentation and talk track.
- The fallback decision can be made quickly during booth operation without technical debate.
- The deterministic replay path remains the final fallback.
- The demo can still support the public Arsenal claims without live packet generation.
- Optional AI and optional integrations can fail without damaging the core demonstration.

## References

- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/arsenal/bhusa-2026-live-boundary.md`
- `docs/arsenal/blackhat-usa-2026.md`
- `docs/architecture/decision-loop.md`
- `py/azazel_edge/`
- `rust/azazel-edge-core/`
