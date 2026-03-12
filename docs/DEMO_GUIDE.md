# Azazel-Edge Demo Guide

Last updated: 2026-03-12

## Purpose

Azazel-Edge includes a deterministic demo pack for showing how the system behaves without polluting live runtime state.

A demo replay shows this path:

1. Evidence is normalized into a shared model
2. NOC and SOC are evaluated separately
3. Action Arbiter selects an explicit action
4. Decision Explanation records why that action won
5. Dashboard, `ops-comm`, TUI, and EPD can reflect the replay through a temporary demo overlay

The demo pack is a replay path. It is not live telemetry injection.

## What the Demo Proves

- Azazel-Edge does not rely on AI for the primary decision path
- NOC and SOC are evaluated separately before action selection
- Actions remain explicit, reviewable, and auditable
- Demo results can be shown without contaminating live control state

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

## Prerequisites

Confirm the following before starting:

- `bin/azazel-edge-demo list` succeeds
- `bin/azazel-edge-demo run mixed_correlation_demo` succeeds
- Web UI returns `status=ok` from `/health`
- Dashboard can load `/api/demo/scenarios`
- `ops-comm` is reachable if you want to demonstrate M.I.O. guidance

## Quick Start

### CLI

List scenarios:

```bash
bin/azazel-edge-demo list
```

Run a scenario:

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

### Web UI

Open:

- Dashboard: `https://172.16.0.254/`
- Ops workspace: `https://172.16.0.254/ops-comm`

In the dashboard:

1. Open `Scenario Replay`
2. Select a scenario
3. Click `Run Demo`
4. Review the overlay result cards
5. Click `Clear Demo Overlay` when finished

## What Changes During a Demo

When a demo runs, the system applies a temporary overlay to presentation surfaces.

Affected surfaces:

- Dashboard
- `ops-comm`
- TUI
- EPD

The demo overlay changes presentation only. It does not replace the live control plane as the source of truth.

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
Azazel-Edge separates NOC and SOC evaluation, chooses an explicit action, records why it was selected, and can replay that path without contaminating live runtime state.
```

### If Asked About AI

```text
AI is assistive here. The primary decision path in the demo is deterministic.
```

### If Asked Whether This Is Live

```text
No. This is a deterministic replay path designed for reproducibility. The live operator surfaces exist separately.
```

## M.I.O. Demonstration

After running a scenario, continue in one of these ways:

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
/mio Explain why this demo selected throttle and what should be checked next.
```

## Web API

List scenarios:

```bash
curl -sS -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/scenarios | jq
```

Run a scenario:

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/run/mixed_correlation_demo | jq
```

Clear the overlay:

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/overlay/clear | jq
```

Read the latest overlay state:

```bash
curl -sS -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/overlay | jq
```

## Troubleshooting

### `Scenario Replay` is empty

Check:

- `/api/demo/scenarios`
- whether the Web UI was started from the repository root

### Scenario replay fails in Web UI

Run the same scenario in CLI:

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

If CLI works, the replay path is healthy and the problem is in the web layer.

### Demo overlay does not clear

Use:

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/overlay/clear | jq
```

Then refresh the dashboard.

### You need to fall back to CLI-only demo

That is valid. The replay runner uses the same deterministic scenario pack.

## Related Documents

- [AI operation guide](docs/AI_OPERATION_GUIDE.md)
- [M.I.O. persona profile](docs/MIO_PERSONA_PROFILE.md)
- [P0 runtime architecture](docs/P0_RUNTIME_ARCHITECTURE.md)
