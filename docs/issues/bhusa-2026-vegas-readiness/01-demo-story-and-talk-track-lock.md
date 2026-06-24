# BHUSA 2026: lock demo story and talk track

Parent roadmap: #283

## Purpose

Lock the Vegas Arsenal story so the booth presentation matches the public Black Hat Arsenal description:

> Deterministic Edge Decision Support for Constrained SOC/NOC Operations

The talk track must make clear that Azazel-Edge is a deterministic edge decision appliance for small, temporary, and rapidly deployed networks where defenders operate with limited infrastructure, limited personnel, unstable connectivity, and little time to decide.

## Public message to preserve

- Azazel-Edge evaluates NOC reliability and SOC threat context separately.
- A deterministic action arbiter resolves those evaluations into bounded actions.
- The system records selected evidence, rejected alternatives, and structured explanation.
- Optional AI assistance supports operator explanation, triage guidance, and runbook review only.
- AI does not participate in the core action-selection mechanism.
- Deterministic replay is used for Arsenal demonstration stability.
- Replay does not replace the live Tactical first-pass path used in normal operation.

## Tasks

- [ ] Write a 60-minute booth outline for Arsenal Station 4, Business Hall.
- [ ] Write a 5-minute compressed walkthrough for busy booth traffic.
- [ ] Write a 90-second elevator version for quick visitors.
- [ ] Add one canonical diagram that maps: Tactical Engine -> Evidence Plane -> NOC/SOC Evaluators -> Action Arbiter -> Decision Explanation -> Audit Review.
- [ ] Add explicit language distinguishing replay-only demonstration from the normal live Tactical first-pass path.
- [ ] Remove or downplay language that implies cloud SOC replacement, autonomous AI defense, or full CTI platformization before Vegas.
- [ ] Cross-check README, `docs/arsenal/blackhat-usa-2026.md`, `docs/ARSENAL_DEMO_PROFILE.md`, and slide/talk notes for consistent wording.

## Acceptance criteria

- A visitor can understand the core contribution in under 90 seconds.
- The 5-minute version demonstrates the deterministic loop without introducing optional integrations first.
- The full walkthrough shows NOC/SOC separation, bounded arbitration, explanation, rejected alternatives, and audit traceability.
- The wording matches the accepted public Arsenal title and description.
- No material claims exceed repository-backed implementation.

## References

- `docs/arsenal/blackhat-usa-2026.md`
- `docs/arsenal/bhusa-2026-booth-message.md`
- `docs/arsenal/bhusa-2026-talk-track.md`
- `docs/ARSENAL_DEMO_PROFILE.md`
- `docs/concepts/deterministic-edge-decision-support.md`
- `docs/P0_RUNTIME_ARCHITECTURE.md`
