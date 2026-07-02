# Azazel-Edge Demo Guide

Last updated: 2026-07-02

## Purpose

Azazel-Edge has two distinct ways to show how the system behaves, and they are
kept deliberately separate so there is never a "is the demo faked?" question:

1. **Deterministic offline scenario replay** — fabricates evidence in-process
   and runs it through the real decision pipeline (NOC/SOC evaluation,
   Action Arbiter, Decision Explanation, hash-chained audit log) without
   touching live runtime state. Used for reproducible verification,
   rehearsal, and Black Hat Arsenal (BHUSA) freeze artifacts.
2. **Live dashboard demo with fabricated EVE traffic** — `bin/azazel-edge-dummy-eve`
   writes fabricated Suricata EVE alerts into `eve.json`. The real pipeline
   (Rust core -> AI agent -> control daemon) ingests and processes them like
   any other event, and the result is shown on the **real, operational
   dashboard** — there is no separate demo screen or overlay.

In live operation, Azazel-Edge uses a layered path:

1. Tactical Engine performs first-minute triage
2. Evidence Plane and deterministic evaluators add second-pass context
3. AI remains supplemental for explanation and operator help

Both demo paths exercise this same pipeline; neither path adds a parallel
"presentation only" surface. Fabricated dummy-eve traffic also doubles as
system test input, since it flows through the identical processing path as
real traffic.

## What the Demos Prove

- Azazel-Edge does not rely on AI for the primary decision path
- NOC and SOC are evaluated separately before action selection
- Actions remain explicit, reviewable, and auditable
- Scenario replay results can be shown without contaminating live runtime state
- Live dummy-eve demos are processed by the same pipeline operators see in
  production — nothing is faked in a separate view

## Available Scenarios

- `mixed_correlation_demo`
  - Main showcase scenario
  - Cross-source evidence with correlation, explanation, and action selection
- `noc_degraded_demo`
  - Operations-focused scenario
  - Poor path health and degraded device state
- `soc_redirect_demo`
  - Security-focused scenario
  - High-confidence SOC path with reversible control discussion

## Recommended Scenario Order

1. `mixed_correlation_demo`
2. `noc_degraded_demo`
3. `soc_redirect_demo`

If you only show one scenario, use `mixed_correlation_demo`.

For BHUSA 2026, treat `mixed_correlation_demo` as the frozen primary booth
scenario unless a clear demo blocker requires replacement.

## Prerequisites

Confirm the following before starting:

- `bin/azazel-edge-scenario-replay list` succeeds
- `bin/azazel-edge-scenario-replay run mixed_correlation_demo` succeeds
- Web UI returns `status=ok` from `/health`
- Dashboard loads at `http://127.0.0.1:8084/` (or the configured HTTPS front)
- `ops-comm` is reachable if you want to demonstrate M.I.O. guidance

## Quick Start

### Deterministic Audit Replay (offline, reproducible)

List scenarios:

```bash
bin/azazel-edge-scenario-replay list
```

Run a scenario:

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo
```

BHUSA 2026 compact booth path:

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo
bin/azazel-edge-audit-review --compact
```

This path writes reproducible artifacts to
`/tmp/azazel-edge-demo-explanations.jsonl` and
`/tmp/azazel-edge-demo-triage-audit.jsonl`, and uses trace ids like
`demo:mixed_correlation_demo`. It does not touch the live dashboard.

### Live Dashboard Demo (fabricated EVE traffic, real pipeline)

Staged attack flow, visible on the real dashboard:

```bash
bin/azazel-edge-dummy-eve flow
```

Background benign noise with periodic attack bursts (good for a running booth):

```bash
bin/azazel-edge-dummy-eve stream --attack-every 60
```

Open the real, operational dashboard to watch results arrive:

- Dashboard: `http://127.0.0.1:8084/` (or `https://172.16.0.254/` if HTTPS
  front-end is configured)
- Ops workspace: `/ops-comm`

There is no separate demo page or overlay — `dummy-eve` writes into
`eve.json`, the Rust core parses it, the AI agent and control daemon process
it exactly as they would real Suricata alerts, and the outcome appears on the
same dashboard operators use in production.

## What to Show on Screen

Focus on these sections:

1. `Current Mission`
2. `SOC / NOC Split Board`
3. `Immediate Action`
4. `Threat Evidence Summary`
5. `NOC Focus`
6. `Operator Wording`
7. `Next Checks`
8. `Chosen Evidence`
9. `Rejected Alternatives`

Avoid starting with raw JSON. Use the summary cards first.

## Suggested Talk Track

### Short Version

```text
Azazel-Edge separates NOC and SOC evaluation, chooses an explicit action, records why it was selected, and can replay that path deterministically for reproducibility -- or show it live against fabricated traffic on the same dashboard operators use day to day.
```

### If Asked About AI

```text
AI is assistive here. In live operation, Tactical Engine still handles the first-minute pass. The scenario replay exercises the deterministic second-pass evaluation path; the live dummy-eve demo exercises the full pipeline end to end.
```

### If Asked Whether This Is Live

```text
The scenario replay is a deterministic, offline path designed for reproducibility -- it does not touch the live dashboard. The dummy-eve demo is live: it fabricates Suricata-format alerts, but the entire downstream pipeline and dashboard are the real production system.
```

## M.I.O. Demonstration

After running a scenario or a dummy-eve flow, continue in one of these ways:

### Dashboard

- Use `Ask about this`
- Show how M.I.O. explains the current action and next checks

### `ops-comm`

- Open `Triage Navigator` or direct ask
- Ask for:
  - the current concern
  - the reason the action was selected
  - the next operator check

### Mattermost

Example:

```text
/mio Explain why this scenario selected throttle and what should be checked next.
```

## Troubleshooting

### Scenario replay fails on the CLI

Re-run with `--format text` for a compact human-readable summary:

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo --format text
```

Check that the audit and explanation artifact paths are writable
(`/tmp/azazel-edge-demo-explanations.jsonl`,
`/tmp/azazel-edge-demo-triage-audit.jsonl`, or their
`AZAZEL_DEMO_EXPLANATIONS_PATH` / `AZAZEL_DEMO_AUDIT_PATH` overrides).

### dummy-eve events do not appear on the dashboard

Check:

- `bin/azazel-edge-dummy-eve` is writing to the same `eve.json` path the Rust
  core is configured to read (`--eve-path`, or `$AZAZEL_EVE_PATH`)
- `azazel-edge-core`, `azazel-edge-ai-agent`, and `azazel-edge-control-daemon`
  are all running
- the Web UI was started from the repository root and reaches `/health`

### You need to reset between demo runs

```bash
bin/azazel-edge-scenario-replay clear
```

This removes the deterministic replay artifacts only; it has no effect on
the live dashboard or dummy-eve output.

## Audit Review (read-only)

After a scenario run, use `bin/azazel-edge-audit-review` to walk the decision
through its v2 explanation record and verify the hash-chained audit log.
The command is read-only; it makes no writes and no policy changes.

```bash
bin/azazel-edge-audit-review --compact
```

See [Arsenal Demo Profile — Section 8](ARSENAL_DEMO_PROFILE.md) for full usage,
exit codes, and the read-only contract.

BHUSA-specific replay procedure:
- [BHUSA 2026 Replay Runbook](arsenal/bhusa-2026-replay-runbook.md)
- [BHUSA 2026 Live Boundary](arsenal/bhusa-2026-live-boundary.md)
- [BHUSA 2026 Booth Runbook](arsenal/bhusa-2026-booth-runbook.md)
- [BHUSA 2026 Freeze Candidate](arsenal/bhusa-2026-freeze-candidate.md)
- [BHUSA 2026 Final Command Sheet](arsenal/bhusa-2026-final-command-sheet.md)

## Related Documents

- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
- [Arsenal Demo Profile](docs/ARSENAL_DEMO_PROFILE.md)
