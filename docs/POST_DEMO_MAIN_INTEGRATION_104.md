# Post-Demo Main Integration Boundary (#104)

Last updated: 2026-07-02

## Scope

This document fixes the permanent boundary for post-demo mainline integration work.

- In scope: features that remain useful for day-to-day operator workflow.
- Out of scope: booth/exhibition-only compositions (for example, Blackhat Arsenal-specific UI flow).

## Status update (2026-07-02)

The dedicated demo web page (`/demo`), the `/api/demo/*` endpoints, the
dashboard "demo overlay", `py/azazel_edge/demo/`, `demo_overlay.py`, and
`bin/azazel-edge-demo` described below have all been **removed**. They are
kept here only as a historical record of the earlier boundary decision.
Current architecture:

- Deterministic offline replay (verification/rehearsal/freeze tooling) lives
  in `py/azazel_edge/scenario_replay.py` with CLI
  `bin/azazel-edge-scenario-replay` (`list` / `run <scenario_id>` / `clear`).
  Its JSON output contract and artifact paths
  (`/tmp/azazel-edge-demo-explanations.jsonl`,
  `/tmp/azazel-edge-demo-triage-audit.jsonl`, trace ids like
  `demo:mixed_correlation_demo`, scenario ids like `mixed_correlation_demo`)
  are unchanged from the prior CLI for freeze reproducibility.
- Live demos now use `bin/azazel-edge-dummy-eve`
  (`py/azazel_edge/dummy_eve.py`), which fabricates Suricata EVE alerts into
  `eve.json`. The real pipeline (Rust core -> AI agent -> control daemon)
  processes them and the result is shown on the real, operational dashboard
  — there is no separate demo screen.

See [Demo Guide](DEMO_GUIDE.md) and [Arsenal Demo Profile](ARSENAL_DEMO_PROFILE.md)
for the current instructions.

## Classification (historical, at time of #104)

### Keep As Permanent (mainline) — superseded, see status update above

- Deterministic replay surface:
  - Web route: `/demo`
  - APIs: `/api/demo/*`
  - Template: `azazel_edge_web/templates/demo.html`
  - Overlay pipeline: `py/azazel_edge/demo_overlay.py`
  - CLI entry: `bin/azazel-edge-demo`
- Operator continuity surfaces:
  - `index.html`, `ops_comm.html`
  - `app.js`, `ops_comm.js`, `style.css`, `ops_comm.css`
- Runtime deployment and sync checks for the permanent files above.

### Exhibition-only (excluded from mainline operation)

- Blackhat Arsenal booth composition and related look/stage behavior.
- Any `arsenal-demo`-specific route/template/static set.

Policy:
- Keep exhibition-only composition outside normal production/runtime assumptions.
- Do not make installer/runtime sync depend on exhibition-only assets.

### Retired / not adopted

- The `/demo` web route, `/api/demo/*` endpoints, `demo.html` template,
  `demo_overlay.py`, and `bin/azazel-edge-demo` CLI (all listed as
  "permanent" above) were retired; see the status update at the top of this
  document.

## Runtime Alignment Rules

Permanent operator-facing files must be aligned across:

1. Repository source
2. Installer deployment target (`/opt/azazel-edge`)
3. Runtime sync verification (`installer/internal/verify_runtime_sync.sh`)

The demo-page-specific alignment requirement that used to apply to
`azazel_edge_web/templates/demo.html` no longer applies, since that template
was removed along with the rest of the demo web surface.

## Acceptance Checkpoints

- Repo-to-runtime diff is explainable for operator-facing surfaces.
- No accidental "exists in repo but not deployed" gap for permanent assets.
- Exhibition-only boundary is explicit and does not leak into runtime assumptions.
