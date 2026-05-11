# Post-Demo Main Integration Boundary (#104)

Last updated: 2026-05-11

## Scope

This document fixes the permanent boundary for post-demo mainline integration work.

- In scope: features that remain useful for day-to-day operator workflow.
- Out of scope: booth/exhibition-only compositions (for example, Blackhat Arsenal-specific UI flow).

## Classification

### Keep As Permanent (mainline)

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

- None newly retired in this pass.
- If a file is removed from permanent scope later, update this document and runtime sync list together.

## Runtime Alignment Rules

Permanent web/demo files must be aligned across:

1. Repository source
2. Installer deployment target (`/opt/azazel-edge`)
3. Runtime sync verification (`installer/internal/verify_runtime_sync.sh`)

Minimum required permanent demo alignment:

- `azazel_edge_web/templates/demo.html` must be installed by `install_migrated_tools.sh`.
- `azazel_edge_web/templates/demo.html` must be monitored by `verify_runtime_sync.sh`.

## Acceptance Checkpoints

- Repo-to-runtime diff is explainable for demo-related surfaces.
- No accidental "exists in repo but not deployed" gap for permanent demo assets.
- Exhibition-only boundary is explicit and does not leak into runtime assumptions.
