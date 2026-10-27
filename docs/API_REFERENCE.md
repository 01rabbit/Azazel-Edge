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

## State API — shared Fabric StatusView

### GET /api/state

Returns the current runtime state (the control-plane / `ui_snapshot.json`
payload) plus `monitoring`, `mode`, and `mode_runtime`. (The `portal_viewer`
field was removed with the portal viewer, Edge#477.)

As of Phase 3 of the [Edge adapter plan](AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md),
the response additionally carries a **`status_view`** key: the shared
[Azazel-Fabric](https://github.com/01rabbit/Azazel-Fabric)
`azazel_fabric.view.StatusView` projection of the current snapshot, emitted
alongside `ui_snapshot.json` as `ui_status_view.json`.

- `status_view` is a `StatusView` object (`product`, `mode`, `posture`,
  `headline`, `reasons`, `operator_wording`, `health[]`, `evidence_ids[]`, and
  the full snapshot under `product_view.edge_snapshot`).
- `status_view` is **`null`** when the `azazel_fabric` package is not installed,
  or the view has not been written yet — the key is always present. All existing
  `/api/state` fields are unchanged; this key is purely additive and never gates
  Edge behavior.

## Dashboard Bundle API

### GET /api/dashboard/bundle

One-request snapshot for the WebUI dashboard poll. Aggregates the per-panel
dashboard payloads the frontend previously fetched with ~11 parallel requests
per tick, so a poll either fully succeeds or fully fails and the heavy
evidence build can no longer starve `/api/state` behind a busy worker.

Auth: token required (`viewer` or higher), same as the per-panel endpoints.

Query parameters:

- `session_id` — operator-progress / handoff scope (same as
  `/api/operator-progress` and `/api/dashboard/handoff`)
- `audience` (default `professional`), `surface` (default `dashboard`) —
  forwarded to the actions payload builder
- `trends_limit` (default `60`) — forwarded to the trends payload builder

Response keys (each matching the corresponding per-panel endpoint's shape):

| Key | Same shape as |
| --- | --- |
| `summary` | `GET /api/dashboard/summary` |
| `actions` | `GET /api/dashboard/actions` |
| `health` | `GET /api/dashboard/health` |
| `evidence` | `GET /api/dashboard/evidence` |
| `trends` | `GET /api/dashboard/trends` |
| `state` | `GET /api/state` (including `status_view`) |
| `topolite_seed_mode` | `GET /api/topolite/seed-mode` |
| `mattermost` | `GET /api/mattermost/status` |
| `operator_progress_state` | `GET /api/operator-progress` (`operator`+ role only, else `null`) |
| `handoff_brief_pack` | `GET /api/dashboard/handoff` (`operator`+ role only, else `null`) |
| `activity` | bundle-only: deterministic time-bucketed alert activity (below) |
| `decision_focus` | `GET /api/booth-focus` (v2 decision-explanation projection) |
| `decision_traces` | `GET /api/decision-trace` for the decisions of the alerts in `evidence.recent_alerts` (one per decision, at most 16) |

`decision_focus` additionally carries a `domains` key (also present on
`GET /api/booth-focus`): per-jurisdiction evaluator rationale from the same
v2 explanation record — `domains.noc` / `domains.soc`, each
`{status, reasons[]}` (up to 4 reasons). This is the "why this state" story
rendered on the SOC/NOC focus screens alongside `decision.why_not_others`,
`decision.release_condition`, and the `audit` trace/policy/config refs.

`activity` re-aggregates the tailed AI event log through the same
`_normalize_alert_event` normalizer and risk bands as the alert queues —
no new data source, no new judgment logic:

- `h1` — last 60 min in 30 × 2-min buckets; `h6` — last 6 h in 18 × 20-min
  buckets. Each bucket is `{normal, watch, critical}` counts; each window
  also reports `events` (total rows) and `signals` (watch+critical rows).
- `thresholds` — the `now`/`watch` risk thresholds used for banding.

Note: alert-queue `items` caps were raised from 5 to 12 per band (8 for
escalation candidates) so the SOC workspace triage table can render them
directly; `count` fields are unchanged.

The role-gated keys are always present; a `viewer` caller receives `null` for
both so the response shape stays stable. All per-panel endpoints remain
available unchanged.

## Decision Trace API (#341)

Read-only, decision-level trace: for each core decision, the v2 decision
explanation the AI agent writes (`decision-explanations.jsonl`, `.1` after a
rotation) and the `action_decision` record of the core decision chain
(`core-decision-audit.jsonl`, `.1` after a rotation; P0 decisions only), both
under `/var/log/azazel-edge/ai`, joined by `trace_id`. The explanation fields
and the chain verdict are those of `azazel-edge-audit-review --json`
(`audit_review.record_review`, `audit_review.verify_audit_chain`,
`audit_review.chain_review`), so the Web UI and the CLI never disagree.

### GET /api/decision-trace?trace_id=<id>[&trace_id=<id>...]

Auth: token required, `viewer` or higher (no new role). `GET` only; at most
16 ids (`400 too_many_trace_ids`), each `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`
(`400 invalid_trace_id`); none: `400 trace_id_required`. `Cache-Control:
no-store`.

Response: `format` (`azazel-edge/decision-trace/v1`), `read_only: true`,
`generated_at`, `sources`, `traces`, `limits`.

- `sources.explanations`: `state` (`present` / `missing` / `unreadable`),
  `files` (names read, oldest first), `unparsed_lines`, `truncated`.
- `sources.chain`: the `chain` object of `audit_review --json` (`ok`,
  `verified`, `entries`, `error`, `scope`, `genesis_retained`, `files`,
  `chain_id`, `meaning`, `limits`) plus `state` (`present` / `missing` /
  `unreadable`). A missing or empty chain is `scope: empty`, `verified:
  false`, never a verified chain.
- `traces[]`, one per requested decision:
  - `explanation`: `status` `found` with the `audit_review --json` fields
    (`selected_action`, `release_condition`, `why_not_others`,
    `evidence_ids`, `schema_valid`, `capsule_signature_state`, …) and
    `segment` (`active`, or `rotated` for the `.1` file), `records` (how many
    records carry the id), `reason`, `applied_state`, `not_applied` (the
    `NOT APPLIED` label of an action the core did not apply);
    `not_found` (no explanation with this id in the retained files;
    `rotated_file_present` says whether older ones may have been rotated
    out); `source_unreadable`.
  - `chain_record`: `status` `found` with `ts`, `kind`, `action`,
    `decided_action`, `effective_action`, `enforcement_mode`,
    `enforcement_result`, `enforce_dry_run`, `recorded_by`,
    `reconcile_stale`, `event_ts`, `sid`, `severity`, `segment`, `file`,
    `position` and `integrity`: `verified` (the whole retained chain
    verifies), `failed_here` (verification failed at this record: rewritten,
    or a record before it removed or reordered) or `not_verified` (the chain
    failed elsewhere); `not_found` (the chain holds P0 decisions only, and
    records rotated out are gone); `changed` (the file changed while it was
    read); `source_unreadable`. Not copied: the core event key, the core's
    own trace id, the target address, the agent's receive stamps.
  - `consistency.action_matches`: when both are found, whether the
    explanation's `selected_action` is the chain record's `action`.

A trace exists only for a decision. `evidence.recent_alerts[].decision_trace_id`
(dashboard evidence and bundle) is set only when the alert's event is a core
decision event (the id the agent gives that decision, from
`core_decisions.core_decision_payload`); every other alert has `""` and no
trace. Alerts of one decision share its one trace. The SENTINEL console's
Evidence drawer shows the trace of the selected alert's decision, or `—`,
and the DECISIONS view lists one row per decision (text only).

### GET /api/decision-trace/export?trace_id=<id>[&trace_id=<id>...]

The same report as a JSON attachment (`Content-Disposition: attachment;
filename="decision-trace-<UTC time>.json"`), for the audit record or report
of one incident: pass the decisions of the incident. Same auth and limits.
The console's EXPORT JSON button saves the report it shows (the bundle's
`decision_traces`) without another request.

Neither endpoint writes, decides, enforces or notifies. Not checked on a
device (container only).

## Control Actions API
## Control Actions API

### `POST /api/action/<action>` and `POST /api/action`

`responder` role or higher. `POST /api/action/<action>` answers the result
as JSON (200 on success, 500 on failure, 404 for an action not listed
below); `POST /api/action` takes `{"action": "<action>"}` and answers
`{status, message}` (403 for an action not listed below).

Actions: `refresh`, `reprobe`, `details`, `disconnect`, `wifi_scan`,
`wifi_connect`, `shutdown`, `reboot`, `mode_set`, `mode_status`, `mode_get`,
`mode_portal`, `mode_shield`, `mode_scapegoat`, `sot_trust_client`. Each is
sent to the control daemon. `disconnect` is the daemon's fixed
`uplink_disconnect` (no parameters; the daemon sets its own configured uplink
down and returns its failure as a failure).

Removed (Edge#477): `contain`, `release` and `stage_open`, which went only
to a port 8082 "status API" that nothing serves on an Edge (it is
Azazel-Gadget's, on the gadget itself), and the portal viewer
(`GET /api/portal-viewer`, `POST /api/portal-viewer/open`, the daemon's
`portal_viewer_open`), whose unit is not shipped. The Web UI no longer
sends anything to port 8082.

## Mattermost bridge when Mattermost is not configured

Mattermost counts as configured when the Web UI has a bot token with a
channel id (`bot_api`) or a webhook URL (`webhook`); the provisioning step
writes them only when Mattermost is installed. Without either (Edge#477):

- `POST /api/mattermost/message` (when sending), `POST /api/dashboard/handoff`
  with `target: mattermost` and `GET /api/mattermost/messages` answer **503**
  with `{"ok": false, "error": "mattermost_not_configured", "not_configured": true, "message": …}`
  (they used to answer 500 / 502 like any failure);
- `GET /api/mattermost/status` and the bundle's `mattermost` key carry
  `configured: false`, `reachable: false` and empty `open_url` / `base_url`;
  no reachability ping is sent;
- the `mattermost` links in the dashboard payloads are empty, and the
  dashboard and Ops Comm pages show no "Open Mattermost" link.

A configured Mattermost that fails is still a failure (500, handoff 502).

## Compatibility Note

API contract details evolve with implementation.
For release-specific behavior, consult:
- [Changelog](CHANGELOG.md)
- [Release Verification Guide](RELEASE_VERIFICATION_GUIDE.md)
