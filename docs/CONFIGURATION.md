# Configuration Reference

This document is the configuration entry point for Azazel-Edge.

## Runtime Configuration Layers

- Runtime defaults and environment files under `/etc/default/azazel-edge-*`
- Deterministic SOC policy files under `config/soc_policy*.yaml`
- Concept-to-profile mapping under `concept_profiles/*.yaml`
- Installer toggles under `installer/internal/*.sh`

## Key Configuration Domains

- Authentication and fail-closed posture
- SOC/NOC policy thresholds
- AI assist thresholds and resource guardrails
- Demo replay and overlay behavior
- Aggregator and optional integration toggles

## Authoritative Documents

- AI-related runtime tuning: [AI Operation Guide](AI_OPERATION_GUIDE.md)
- SOC threshold and redirect policy controls: [SOC Policy Guide](SOC_POLICY_GUIDE.md)
- Deployment profile intent and scope: [Deployment Profiles](DEPLOYMENT_PROFILES.md)
- Socket/runtime permission posture: [Post-demo Socket Permission Model (#105)](POST_DEMO_SOCKET_PERMISSION_MODEL_105.md)
- Concept-profile mapping layer: [../concept_profiles/README.md](../concept_profiles/README.md)

## EPD Web Preview

The "EPD on Web" routes (`/api/epd`, `/api/epd/preview.png`, `/dev/epd`; see
[API Reference](API_REFERENCE.md)) read the e-paper runtime state. On hardware
these live under `/run/azazel-edge/`. For dev hosts without the panel, the
runtime directory can be redirected via environment variables (following the
same `AZAZEL_*` path-override precedent used elsewhere in `azazel_edge_web/app.py`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `AZAZEL_EPD_RUNTIME_DIR` | `/run/azazel-edge` | Base dir for both EPD state files below |
| `AZAZEL_EPD_STATE_PATH` | `$AZAZEL_EPD_RUNTIME_DIR/epd_state.json` | Explicit override for the desired-frame input |
| `AZAZEL_EPD_LAST_RENDER_PATH` | `$AZAZEL_EPD_RUNTIME_DIR/epd_last_render.json` | Explicit override for the last-drawn-frame record |
| `DISPLAY_ROTATION_DEG` | `180` | Panel orientation compensation applied before preview/display (read by the renderer) |

These paths intentionally track the edge-tier runtime name regardless of
`AZAZEL_PATH_SCHEMA`, matching the EPD renderer and orchestrator.

## Implementation Sources

- Policy loader: `py/azazel_edge/policy.py`
- AI governance entrypoint: `py/azazel_edge/ai_governance.py`
- Installer scripts: `installer/internal/`

## Operational Note

Use deployment-appropriate profiles and validate changes in a dry-run or test environment before production field use.
