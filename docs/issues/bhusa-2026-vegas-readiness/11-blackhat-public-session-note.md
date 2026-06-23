# Black Hat USA 2026 public session note

This note preserves the public-facing session details used to derive the Vegas readiness sub-issues.

- Title: Azazel-Edge: Deterministic Edge Decision Support for Constrained SOC/NOC Operations
- Presenter: Makoto "Mr. Rabbit" SUGITA
- Date: Wednesday, August 5
- Time: 10:10am-11:10am
- Location: Arsenal Station 4, Business Hall
- Track: Network

## Core public description distilled for implementation planning

Azazel-Edge is a deterministic edge decision appliance for constrained local networks. It separates NOC reliability evaluation from SOC threat-context evaluation, resolves them through a deterministic action arbiter, and records selected evidence, rejected alternatives, and structured explanation.

The live path is layered: Tactical Engine handles first-minute triage, then Evidence Plane and deterministic evaluators add second-pass context. Optional AI assistance is bounded to operator support and does not participate in core action selection.

The Arsenal demo uses deterministic replay for stable inspection in a short session. Replay is for demonstration only and does not replace the live Tactical first-pass path.
