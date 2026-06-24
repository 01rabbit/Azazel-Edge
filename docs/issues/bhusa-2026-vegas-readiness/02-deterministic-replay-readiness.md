# BHUSA 2026: deterministic replay readiness

Parent roadmap: #283

## Purpose

Make the deterministic replay path booth-safe for the short Arsenal session while preserving the statement that replay is for demonstration only and does not replace the live Tactical first-pass path used in normal operation.

## Why this matters

The public Arsenal description emphasizes inspectable deterministic replay so evaluator outputs, arbitration logic, and explanation remain stable in a short Arsenal session. This must be demonstrable without relying on opaque live-only telemetry.

## Tasks

- [ ] Define one primary replay scenario for the booth and avoid changing it during final rehearsal.
- [ ] Verify the scenario through `bin/azazel-edge-demo run <scenario>` on the target Raspberry Pi-class device.
- [ ] Confirm the scenario emits stable evidence IDs, evaluator outputs, selected action, rejected alternatives, explanation, and audit records.
- [ ] Confirm `deterministic_replay` is visible in output or audit context where applicable.
- [ ] Confirm AI is either disabled or clearly marked as optional support for the replay path.
- [ ] Add a compact replay command sequence to `docs/ARSENAL_DEMO_PROFILE.md` or a linked Vegas-specific runbook.
- [ ] Ensure the replay path does not require Internet access, cloud APIs, or booth network reliability.
- [ ] Add or update tests that protect replay determinism for the chosen scenario.
- [ ] Document fallback from live-assisted demo to replay-only demo.

## Acceptance criteria

- The replay demo can be run at least 5 consecutive times without manual cleanup beyond documented reset steps.
- The same replay input produces the same action decision under the same policy profile.
- The explanation and audit review path can be shown immediately after replay.
- The demo output clearly supports the accepted Arsenal story: deterministic evaluator outputs, arbitration logic, and explanation are stable and inspectable.
- Documentation states that replay is for demonstration only and does not replace normal live Tactical first-pass operation.

## References

- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/arsenal/bhusa-2026-replay-runbook.md`
- `docs/arsenal/blackhat-usa-2026.md`
- `docs/concepts/deterministic-edge-decision-support.md`
- `bin/azazel-edge-demo`
