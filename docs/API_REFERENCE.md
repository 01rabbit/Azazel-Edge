# API Reference

This document is the API entry point for Azazel-Edge.

Detailed endpoint behavior is intentionally split by operational context to avoid stale duplication.

## Primary API Surfaces

- State and dashboard APIs
- Control and mode APIs
- SoT and trust update APIs
- Triage APIs
- Runbook proposal/review/act APIs
- Demo replay APIs
- AI ask/capability APIs

## Authoritative Sources

- Web/API implementation: `azazel_edge_web/app.py`
- Deterministic runtime architecture: [P0 Runtime Architecture](P0_RUNTIME_ARCHITECTURE.md)
- Demo API and replay semantics: [Demo Guide](DEMO_GUIDE.md)
- AI-assist API behavior: [AI Operation Guide](AI_OPERATION_GUIDE.md)
- Post-demo route boundaries: [Post-demo Main Integration Boundary (#104)](POST_DEMO_MAIN_INTEGRATION_104.md)

## Authentication and Authorization

- Protected API routes are fail-closed by default.
- Role/token and optional mTLS controls are documented in:
  - [Configuration Reference](CONFIGURATION.md)
  - [Post-demo Socket Permission Model (#105)](POST_DEMO_SOCKET_PERMISSION_MODEL_105.md)

## EPD Web Preview APIs

"EPD on Web" exposes what the physical Waveshare 2.13" e-paper panel shows, plus
a pixel-parity PNG produced by the real renderer. These endpoints are advisory
and **read-only** — they never drive the hardware. Implementation lives in
`azazel_edge_web/app.py`; the frame logic is imported from
`py/azazel_edge_epd_mode_refresh.py` and the renderer from `py/azazel_edge_epd.py`.

Authentication: all three routes are token-gated at the **viewer** role (same
token/role/mTLS pipeline as other read-only `/api` routes; see
[Configuration Reference](CONFIGURATION.md)). Unauthorized requests fail closed
with the standard `{"ok": false, "error": "Unauthorized"}` shape and a `403`.

### GET /api/epd

Describes the panel state. No parameters.

Response `200` (JSON):

| field | meaning |
| --- | --- |
| `ok` | always `true` on success |
| `mode` | gateway mode from `epd_state.json` (`portal`/`shield`/`scapegoat`/…) |
| `state` | effective panel render state (`normal`/`warning`/`danger`/`stale`) |
| `panel` | the effective render spec the panel shows |
| `panel_source` | `last_render` (physically drawn frame), `desired` (computed from `epd_state.json`), or `fallback` |
| `desired` | render spec computed by the imported desired-render logic |
| `epd_state` | raw contents of `epd_state.json` (`{}` if absent) |
| `last_render` | render spec from `epd_last_render.json` (`{}` if absent) |
| `renderer_available` | whether the PIL renderer imported successfully |
| `note` | short human-readable explanation of `panel_source` |

The panel spec prefers the last physically drawn frame
(`epd_last_render.json`) for true parity, then the desired frame, then a visible
`WARNING` fallback. This endpoint reads files only and never fails on missing
state (absent files yield empty objects, not errors).

### GET /api/epd/preview.png

Renders the effective panel frame in-memory (pick renderer function by state →
`apply_display_rotation` → composite black+red layers into RGB, exactly like the
CLI's `save_preview()`), returned as `image/png`. No parameters.

- Success: `200`, `Content-Type: image/png`.
- Fail-closed: `503` JSON `{"ok": false, "error": "<reason>"}` when the renderer
  or its assets are unavailable. Reasons: `epd_renderer_unavailable`,
  `epd_font_missing`, `epd_icon_missing`, `epd_render_failed`. No stack traces
  are leaked to the client. Fonts (`fonts/`) and icons (`icons/epd/`) are
  resolved relative to the renderer's repo root, matching the EPD CLI.

### GET /dev/epd

Self-contained dark-themed dev page (inline HTML, no template/static assets)
that shows `preview.png` (refreshed ~5s with a cache-busting query) and polls
`/api/epd` (~2s) for `mode`/`state`/`source`/`note`. Token-gated at the viewer
role; pass `?token=…`, which the page propagates to its API/image requests.

## Compatibility Note

API contract details evolve with implementation.
For release-specific behavior, consult:
- [Changelog](CHANGELOG.md)
- [Release Verification Guide](RELEASE_VERIFICATION_GUIDE.md)
