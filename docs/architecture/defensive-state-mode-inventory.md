# Legacy `mode` inventory for the Defensive State migration (#390 stage 0)

Tracking: #390 (parent #379; doctrine Azazel#62); context #340, #343, #515  
Status: inventory only. **No code, API, UI, unit or installer change.**  
Last updated: 2026-10-28

#379 makes the five **Defensive States** (`OBSERVE`, `NOTIFY`, `THROTTLE`,
`REDIRECT`, `ISOLATE`) the one outward answer to "what is Edge doing now?",
and asks for every `mode` usage to be inventoried and classified first
(implementation step 1 and 2). This page is that inventory. It decides
nothing; the decisions it surfaces are listed in §7 for the owner.

The main subject is the **legacy concept mode** `portal` / `shield` /
`scapegoat` (`current_mode`, `mode.json`, `/api/mode`, the `mode_*` control
actions). Every other key that is called `mode` but means something else is
listed in §4, so that a later rename does not catch them by accident.

## 0. How this was gathered, and what it is not

- **Static reading** of `py/`, `azazel_edge_web/`, `bin/`, `rust/`,
  `installer/`, `systemd/`, `tools/`, `tests/` and `docs/` (without
  `docs/archive/`) at main `1cefe66`. Line numbers are those of that
  commit and will drift; each row also names a search anchor.
- `docs/archive/` has no legacy-mode hit and was not read further.
- Nothing was run on a device. Where a row says what happens at runtime, it
  is what the code says, not an observation.
- `tests/test_defensive_state_mode_inventory_v1.py` holds the completeness
  of the file list (§8). It does not check line numbers.

## 1. What the inventory shows

1. **The legacy mode has no enforcement effect.** `ModeManager.set_mode`
   (`py/azazel_edge_control/mode_manager.py`) writes `mode.json`, writes
   `/run/azazel-edge/epd_state.json`, and starts
   `azazel-edge-epd-refresh.service`. That is all. It does not touch
   nftables, tc, the Rust core or the arbiter. The core never names
   `mode.json` (held by `tests/test_mio_cognitive_plane_authority_v1.py`,
   `NOT_READ_BY_CORE`), and the arbiter's action table is the five
   Defensive States (held by `tests/test_defensive_state_vocabulary.py`).
   So the "enforcement" class below (ENF) is the authority to **change a
   label and an e-paper screen**, not to change traffic.
2. **Absence is turned into `shield` in eleven places** (L01, L12, L17,
   L18, L19, L22, L30, L35, L36, L38, L45 below). When no `mode.json` exists — and no
   installer or unit writes one, and nothing calls `mode_apply_default` —
   the daemon answers `ok: true` with `shield`, `requested_by: "init"`.
   When the daemon does not answer, `get_mode_state()` answers `ok: false`
   but still `shield`, and `/api/dashboard/summary` drops the `ok` flag. A
   reader of the summary cannot tell a chosen `shield` from none at all.
   This is the #515 finding (§6).
3. **The legacy mode is shown in Defensive State slots.** SENTINEL's
   CONTROL tier, *Active control*, the decision card's *Applied*, the
   NOC path's Azazel-Edge hop and the in-box Deception node all fall back to
   (or derive from) `current_mode` (L23–L30). With the server default this
   means `SHIELD` in green, `Applied: YES`, and a Deception `STANDBY`,
   whatever the arbiter is doing.
4. **Two role boundaries for one write.** `POST /api/mode` needs `admin`
   (L07). `POST /api/action/mode_portal|mode_shield|mode_scapegoat` (and
   `POST /api/action` with that action) needs only `responder`, and reaches
   the same daemon handler (L06, L04). No test covers the second path.
5. **The audit record is weak.** `requested_by` is whatever the caller
   sends (body of `POST /api/mode`, params on the socket); `config_hash` is
   the SHA-256 of the mode *name*, not of any configuration; and
   `recent_mode_changes` holds only the current record, not a history
   (L13, L14).
6. **It leaves the device in three ways:** the HTTP APIs (L32–L40), the
   handoff brief that can be posted to Mattermost as `mode=SHIELD` (L39),
   and the control-socket snapshot (L41). It is **not** passed to M.I.O. or
   the AI agent as structured context: `/api/ai/ask` forwards only the
   caller's `context`, and no runtime caller builds a SituationFrame from
   it. The Fabric `StatusView` (L42) defaults to `unknown` and projects the
   agent's snapshot, which carries no `mode` key, so as far as static
   reading shows it always says `unknown`.

## 2. Classes used

#390 names the target terms (from #379) but not a use classification, so
each row has two columns:

**Use class** (what the site does with the legacy mode):

| Code | Meaning |
| --- | --- |
| `ENF` | Enforcement / control meaning: validates, changes, stores or gates the value, or is the authority to do so. (None of these reaches traffic, see §1.1.) |
| `DSP` | Display only: puts the value, or something derived from it, in front of an operator (web, TUI, e-paper). |
| `AUD` | Record / audit: a persisted record of the value or its change, or a drift/timeline entry. |
| `EXT` | Leaves the process outward: HTTP API, control socket, Mattermost, Fabric projection, AI. |
| `GRD` | An existing guard that already holds part of the separation. |

**Target term** (#379, "Required terminology separation"): the term the
site should use once migrated — *Defensive State*, *Threat Level*, *Policy
Profile*, *AI Runtime Tier*, *Workspace/View*, *Engagement/Deception
State*, *Presentation State* — or **Legacy concept** where the site is
about the portal/shield/scapegoat value itself and #379 gives it no
canonical meaning (decision-loop.md: no mapping to the five is defined,
deliberately).

## 3. Inventory — the legacy concept mode

### 3.1 Runtime: control daemon, mode store, Web UI backend

| # | File:line | Anchor | Use | Class | Target term | Migration note |
| --- | --- | --- | --- | --- | --- | --- |
| L01 | `py/azazel_edge_control/mode_manager.py:17` | `MODE_CHOICES`, `DEFAULT_MODE` | The three values; default `shield`. | ENF | Legacy concept | The default is the root of §1.2. Changing it changes every API below. |
| L02 | `py/azazel_edge_control/mode_manager.py:100` | `def set_mode` | Writes `mode.json`, `epd_state.json`, starts the EPD refresh unit. `dry_run` returns from/to only. | ENF | Legacy concept | No traffic effect; a rename must not give it one (#379 "no unreviewed enforcement change"). |
| L03 | `py/azazel_edge_control/mode_manager.py:135` | `def apply_default` | Resets to `shield`. | ENF | Legacy concept | Only reachable as the daemon's `mode_apply_default`; no unit or installer sends it. |
| L04 | `py/azazel_edge_control/daemon.py:2348` | `mode_set", "mode_portal"` | Socket handler for `mode_set` / `mode_portal` / `mode_shield` / `mode_scapegoat`; 1 req / 2 s; `requested_by`, `dry_run` from params. | ENF | Legacy concept | Removing it breaks the TUI menu (L20) and both web paths (L06, L07). |
| L05 | `py/azazel_edge_control/daemon.py:2362` | `mode_apply_default` | Socket handler; root-only in practice (not in `WEB_UI_ACTIONS`). | ENF | Legacy concept | — |
| L06 | `py/azazel_edge_control/daemon.py:141` and `azazel_edge_web/app.py:504` | `WEB_UI_ACTIONS`, `ALLOWED_ACTIONS` | The `azazel-web` peer may send `mode_*`; `POST /api/action[/<action>]` forwards them at **responder** (`app.py:6665`, `6693`). | ENF | Legacy concept | Role mismatch with L07 (§1.4, §7 D4). Both lists are pinned by #471 tests (T03). |
| L07 | `azazel_edge_web/app.py:5375` | `def api_mode_set` | `POST /api/mode`, **admin**; `requested_by` from the body, default `webui`. | ENF / EXT | Legacy concept | #340: must not be re-promoted as an operator contract. Deprecation is §7 D2. |
| L08 | `py/azazel_edge/path_schema.py:137` and `azazel_edge_web/app.py:142` | `mode_state_candidates` | Where `mode.json` lives (`/etc/azazel`, `/etc/azazel-edge`, legacy `/etc/azazel-zero`). | ENF | Legacy concept | Also a config-drift target (L15). |
| L09 | `py/azazel_edge_control/daemon.py:45`, `:70` | `MODE_MANAGER = ModeManager` | The daemon's single mode store. | ENF | Legacy concept | — |
| L10 | `py/azazel_edge/cli_unified_textual.py:285` | `"Mode: Shield"` | Textual TUI menu sends `mode_portal` / `mode_shield` / `mode_scapegoat` over the control socket. | ENF | Legacy concept | An operator control outside the web RBAC. |
| L11 | `azazel_edge_web/static/app.js:2871` (`:440`) and `azazel_edge_web/templates/index.html:1173` | `function switchMode`, `modeScapegoatBtn` | Legacy dashboard *Gateway Controls*: three buttons, confirm dialog, `POST /api/mode` with `requested_by: 'dashboard'`. | ENF / DSP | Legacy concept | The control #340 says not to resurrect in SENTINEL; it still exists in the dashboard part of `index.html` (served at `/`, beside the SENTINEL console; driven by `app.js`). |
| L12 | `py/azazel_edge_control/mode_manager.py:38` | `def _read_state`, `def status` | No file → `shield`, `requested_by: "init"`, and `status()` says `ok: true`. | AUD | Legacy concept | §1.2: the daemon reports a default as a fact. |
| L13 | `py/azazel_edge_control/mode_manager.py:116` | `config_hash = "sha256:"` | The record: `current_mode`, `last_change`, `requested_by` (caller-supplied), `config_hash` (hash of the mode name). | AUD | Legacy concept | §1.5. A Defensive State record must not inherit `config_hash` under that name. |
| L14 | `azazel_edge_web/app.py:2482` | `def _recent_mode_changes` | Builds "recent changes" from the current record only (0 or 1 entry). | AUD | Legacy concept | Not a history; the UI calls it one (L29). |
| L15 | `py/azazel_edge/config_drift.py:83`, `:192` | `'current_mode':`, `mode_state_candidates()` | `policy_markers.current_mode` in the health/config snapshot; `mode.json` is a drift target. | AUD | Policy Profile? (owner) | A mode switch reads as config drift. Where `policy_markers` should point after migration is §7 D6. |
| L16 | `py/azazel_edge_control/mode_manager.py:59` | `def _write_epd_state` | `epd_state.json` gets `mode`, `requested_by`, `mode_last_change`. | AUD | Legacy concept | Read by the EPD (L35) and `/api/epd` (L40). |

### 3.2 Display

| # | File:line | Anchor | Use | Class | Target term | Migration note |
| --- | --- | --- | --- | --- | --- | --- |
| L17 | `py/azazel_edge/snapshot_model.py:90`, `:175` | `"current_mode": "shield"` | TUI snapshot model: absent → `shield`. | DSP | Legacy concept | Same false default as L01, on the TUI side. |
| L18 | `py/azazel_edge/cli_unified.py:809`, `:976` | `mode_label =`, `'Mode:'` | Curses TUI header `Mode: SHIELD` (default `shield`). | DSP | Defensive State (header slot) | The header slot answers "what is Edge doing", so it is the natural Defensive State slot. |
| L19 | `py/azazel_edge/cli_unified_textual.py:357`, `:450` | `mode_name =`, `Mode: {` | Textual TUI mode display (default `shield`). | DSP | Defensive State (header slot) | As L18. |
| L20 | `azazel_edge_web/static/app.js:2114` | `title: 'Azazel-Edge', state:` | Legacy dashboard NOC path hop shows the mode, tone always `status-safe`. | DSP | Defensive State | Green regardless of value. |
| L21 | `azazel_edge_web/static/app.js:2193` and `azazel_edge_web/templates/index.html:485` | `stripMode` | Command strip *Mode*. | DSP | Defensive State | — |
| L22 | `azazel_edge_web/static/app.js:2552`, `:2584`, `:2861` | `modeLastChange`, `action_board_control_details_summary`, `updateControlButtons` | Last change / requested by; summary `Mode {mode}` (default `SHIELD`; `shield` = safe tone, `scapegoat` = caution); button `aria-pressed` (default `shield`). | DSP | Legacy concept | Tone semantics of legacy values would have no counterpart. |
| L23 | `azazel_edge_web/static/sentinel.js:250` | `var modeTone = toneOf(mode.current_mode)` | SENTINEL pipeline **04 CONTROL** = mode; any non-watch/critical value is `is-ok`. | DSP | Defensive State | The slot is meant to be the Defensive State; today it is the legacy label in green. |
| L24 | `azazel_edge_web/static/sentinel.js:469` | `consoleControlWord`, `consoleControlMode` | *Active control* word falls back to the mode when no decision record; sub-line shows the mode. | DSP | Defensive State | Mixed vocabularies in one field (`THROTTLE` or `SHIELD`). |
| L25 | `azazel_edge_web/static/sentinel.js:504` | `['Applied', (action \|\| mode.current_mode)` | Decision card *Applied: YES* when only a mode is present. | DSP | Defensive State (applied status) | With the server default this is always `YES`. |
| L26 | `azazel_edge_web/static/sentinel.js:518` | `audit.policy_profile \|\| mode.current_mode` | Audit *Policy* falls back to the mode. | DSP | Policy Profile | A Policy Profile slot showing a legacy mode. |
| L27 | `azazel_edge_web/static/sentinel.js:807` | `['Active control', action \|\|` | NOC traffic control *Active control* falls back to the mode, then `OBSERVE`. | DSP | Defensive State | #515 changes the last fallback to `UNKNOWN`; the mode fallback stays. |
| L28 | `azazel_edge_web/static/sentinel.js:891` | `upper(mode, 'OBSERVE')` | NOC path hop *Azazel-Edge* = mode, else `OBSERVE`, always green. | DSP | Defensive State | #515 makes absence `UNKNOWN`; present (incl. server default) stays green. |
| L29 | `azazel_edge_web/static/sentinel.js:1153`, `:1199` | `recent_mode_changes` | Evidence tier rows `mode → shield`. | DSP | Legacy concept | Shows the single record of L14 as a timeline. |
| L30 | `azazel_edge_web/static/sentinel.js:1380` | `var decActive = (mode.current_mode === 'scapegoat'` | In-box Deception node: `scapegoat`/`portal` → `ENGAGED`, else `STANDBY` (green); `Mode: SHIELD`. | DSP | Engagement/Deception State | Deception lifecycle derived from a label with no enforcement effect. #515 makes absence `UNKNOWN`. |
| L31 | `azazel_edge_web/static/sentinel.js:1429` | `configGroup('Control mode'` | *Control mode* group: current mode, last change, requested by, and `Policy mode` (= AI `policy_mode`, see O04). | DSP | Legacy concept / AI Runtime Tier | One group mixes a legacy label and the AI runtime tier under "Policy". |
| L32 | `azazel_edge_web/templates/index.html:754` and `py/azazel_edge/i18n.py:88`, `:1095` | `dashboard.no_mode_change` | First-minute instruction "Do not change mode …". | DSP | Legacy concept | Text only. |
| L33 | `azazel_edge_web/templates/index.html:1171` and `azazel_edge_web/static/style.css:2651` | `gateway_controls`, `#modePortalBtn` | *Gateway Controls* card, button styles. | DSP | Legacy concept | Goes with L11. |
| L34 | `azazel_edge_web/static/touch.js:341` | `The legacy concept mode (portal/shield/scapegoat) is deliberately not` | Touch console: not shown, not offered (#340); reads `mode_runtime.ok` only. | DSP | — (already compliant) | Held by T07. |

### 3.3 E-paper

| # | File:line | Anchor | Use | Class | Target term | Migration note |
| --- | --- | --- | --- | --- | --- | --- |
| L35 | `py/azazel_edge_epd_mode_refresh.py:45`, `:141`, `:253` | `def _fallback_epd_state`, `def _desired_render_spec`, `--mode-label` | No `epd_state.json` → `shield`; `portal`/`shield`/`scapegoat` → normal screen with the mode label; `switching`/`failed` states; label passed to the renderer. | DSP | Defensive State (panel headline) | The physical panel is #379 item 6 ("UI/TUI/e-paper display the canonical Defensive State"). |
| L36 | `py/azazel_edge_epd.py:378`, `:431`, `:841` | `mode_label: str = "SHIELD"` | Renderer default label `SHIELD`. | DSP | Defensive State (panel headline) | Third independent `shield` default. |
| L37 | `systemd/azazel-edge-epd-refresh.service`, `systemd/azazel-edge-epd-refresh.timer`, `bin/azazel-edge-epd-refresh` | `azazel_edge_epd_mode_refresh.py` | Unit and wrapper started by `set_mode` (L02) and by the timer. | DSP | — | Unit names carry "mode" only through the module name. |

### 3.4 Outward: API, socket, Mattermost, Fabric

| # | File:line | Anchor | Use | Class | Target term | Migration note |
| --- | --- | --- | --- | --- | --- | --- |
| L38 | `azazel_edge_web/app.py:4210` | `def get_mode_state` | Daemon `mode_status`, else `mode.json`, else `ok: false` **with** `current_mode: "shield"` (`:4226`, `:4239`). | EXT | Legacy concept | The source of every API row below. §1.2. |
| L39 | `azazel_edge_web/app.py:3109` | `f"mode={` | Handoff `current_posture` = `mode=SHIELD \| risk=… \| path=… \| internet=…`, in `brief_text`, the ops-comm URL, and `POST /api/dashboard/handoff` with target `mattermost`. | EXT | Defensive State | Leaves the device as text; a rename changes what a human reads in Mattermost. |
| L40 | `azazel_edge_web/app.py:5570` | `"mode": str((state_payload or {}).get("mode"` | `GET /api/epd` returns the EPD's `mode` (default `unknown`). | EXT | Defensive State (panel) | Documented in `API_REFERENCE.md` (D01). |
| L41 | `py/azazel_edge_control/daemon.py:1903` (`:2084`, `:2206`) | `def _snapshot_payload_from_file` | `get_snapshot` / `watch_snapshot` replies carry `snapshot.mode` (not persisted). | EXT | Legacy concept | Socket contract of #471 stage 1. |
| L42 | `py/azazel_edge/fabric_view.py:48`, `:103` | `UNKNOWN_MODE_NAME` | Fabric `StatusView.mode` = `ModeState(name=…)`; absent → `unknown` (no longer `shield`). | EXT | Defensive State (cross-product) | Already fixed for absence. The field name `mode` belongs to Fabric's schema (Fabric#14). |
| L43 | `azazel_edge_web/app.py:5366` | `def api_mode_get` | `GET /api/mode` (viewer). | EXT | Legacy concept | Not in `API_REFERENCE.md`. §7 D2. |
| L44 | `azazel_edge_web/app.py:4950` | `state["mode_runtime"] = mode_state` | `GET /api/state` adds `mode` and `mode_runtime`. | EXT | Legacy concept | Also `/api/state/stream` (`:5285`, `:5302`) and `/api/dashboard/bundle` (`:6320`). |
| L45 | `azazel_edge_web/app.py:2673`, `:2705`, `:2897` | `"current_mode": str(mode.get("current_mode") or "shield")` | `/api/dashboard/summary`: `mode.current_mode` and `command_strip.current_mode` (both default `shield`, no `ok`/`source`), `timestamps.mode_last_change`. | EXT | Defensive State (command strip) / Legacy concept | The two defaults the #515 PR names. |
| L46 | `azazel_edge_web/app.py:3398`, `:3259` | `"recent_mode_changes":`, `"title": f"Mode -> ` | `/api/dashboard/evidence.recent_mode_changes`; `decision_changes` entries of kind `mode`. | EXT / AUD | Legacy concept | A "decision change" that no decision made. |

### 3.5 Docs

| # | File:line | Anchor | Use | Class | Target term | Migration note |
| --- | --- | --- | --- | --- | --- | --- |
| D01 | `docs/API_REFERENCE.md:54`, `:94`, `:280` | `gateway mode from`, `mode_runtime`, `mode_portal` | Documents `/api/epd` `mode`, `/api/state` `mode`/`mode_runtime`, the `mode_*` actions. `/api/mode` itself is undocumented. | EXT | Legacy concept | Update with any API change. |
| D02 | `docs/architecture/sentinel-decision-console.md:76` | `CONTROL \| \`mode.current_mode\`` | States that CONTROL is the legacy mode. | DSP | Defensive State | Goes with L23. |
| D03 | `docs/architecture/privilege-inventory.md:135`, `:177`, `:369`, `:777` | `mode.json`, `mode_set` | Files, socket actions and the `azazel-web` allowed list. | ENF | Legacy concept | Tests read this page (T03). |
| D04 | `docs/TOUCH_CONSOLE_KIOSK.md:39`, `:82`, `:171` | `mode_status`, `legacy concept mode` | Touch console uses `mode_status` only as a liveness probe; mode not shown. | DSP | — (compliant) | — |
| D05 | `docs/POST_DEMO_SOCKET_PERMISSION_MODEL_105.md:128` | `/api/mode` | Lists `/api/mode` as a control path to check. | ENF | Legacy concept | Historical checklist. |
| D06 | `docs/architecture/decision-loop.md:66` | `Four concepts have historically been described as a "mode"` | The canonical statement: five states, separate concepts, absence is not a state, no mapping from legacy names. | GRD | — | This page extends it; it does not change it. |
| D07 | `docs/architecture/azazel_edge_arch.html:1602` | `scapegoat gateway engaged` | Replay description uses the legacy name for a REDIRECT. | DSP | Defensive State (`REDIRECT`) | Wording only. |
| D08 | `refactor-instructions.md:294` | `mode_manager.py:20,36` | Hard-coded paths in `mode_manager.py`. | ENF | Legacy concept | Historical refactor note. |

### 3.6 Tests, installer

| # | File:line | Anchor | Use | Class | Target term | Migration note |
| --- | --- | --- | --- | --- | --- | --- |
| T01 | `tests/test_dashboard_data_contract.py:76`, `:355`, `:941`, `:1289` | `"current_mode": "shield"`, `modeScapegoatBtn` | Pins `summary.mode.current_mode`, `recent_mode_changes`, and the Scapegoat button. | EXT | Legacy concept | Will fail on any rename or removal; update together. |
| T02 | `tests/test_api_auth_rbac_v1.py:76` | `"/api/mode"` | `POST /api/mode` needs admin. | ENF | Legacy concept | Nothing pins the responder path of L06. |
| T03 | `tests/test_web_non_root_stage1_v1.py:119`, `:127`, `:141`, `:191`, `:213`; `tests/test_web_non_root_stage1_linux_root_v1.py:106`, `:116` | `mode_status`, `mode_apply_default` | Socket peer authorization of `mode_*` (#471). | ENF | Legacy concept | Removing actions changes the #471 contract. |
| T04 | `tests/test_epd_web_api_v1.py:65`–`:140` | `"mode_label": "SHIELD"` | `/api/epd` `mode` and render spec. | EXT | Legacy concept | — |
| T05 | `tests/test_phase5_operational_hardening.py:272`, `:297`, `:321`, `:352`; `tests/test_pi5_platform_layer_v1.py:217` | `_desired_render_spec({"mode": "shield"` | EPD render from `shield`/`failed`. | DSP | Legacy concept | — |
| T06 | `tests/sentinel_console_logic.test.js:80`, `:83`, `:96`; `tests/touch_console_logic.test.js:96`, `:131`, `:172` | `current_mode: 'shield'` | JS fixtures carry a mode. | DSP | Legacy concept | — |
| T07 | `tests/test_touch_console_v1.py:234` | `no Portal/Shield/Scapegoat control or display` | Touch console must not show or send the mode. | GRD | — | Model for a SENTINEL guard later. |
| T08 | `tests/test_defensive_state_vocabulary.py:37` | `LEGACY_NAMES` | Five states; control class ≠ state; Fabric projection never defaults to a legacy name. | GRD | — | — |
| T09 | `tests/test_mio_cognitive_plane_authority_v1.py:75` | `"mode.json",` | The core never names `mode.json`. | GRD | — | The evidence for §1.1. |
| T10 | `tests/test_mio_cognitive_shadow_core.py:49` | `current_defensive_state="shield"` | A SituationFrame rejects `shield` as a Defensive State. | GRD | — | — |
| T11 | `tests/test_noc_link_reevaluation_v1.py:454`; `tests/test_agent_non_root_stage2_v1.py:226` | `MODE_MANAGER, 'status'`, `"mode": {"current_mode": "forged"}` | Patches the mode store; a forged snapshot carrying a mode. | EXT | Legacy concept | — |
| I01 | `installer/internal/install_migrated_tools.sh:189`, `:206`, `:277`, `:304`, `:450`; `installer/internal/verify_runtime_sync.sh:63`, `:68`, `:88` | `mode_manager.py`, `epd_mode_refresh` | Installs and verifies `mode_manager.py`, the EPD refresh module, wrapper and units. No installer writes `mode.json`. | ENF | Legacy concept | Removing modules needs installer and sync-list changes together. |

### 3.7 Counts

66 rows: 46 runtime (L01–L46), 8 docs (D01–D08), 11 tests (T01–T11) and
1 installer (I01). A row with two classes counts under the first.

| Class | Rows | Count |
| --- | --- | --- |
| ENF | L01–L11, D03, D05, D08, T02, T03, I01 | 17 |
| AUD | L12–L16 | 5 |
| DSP | L17–L37, D02, D04, D07, T05, T06 | 26 |
| EXT | L38–L46, D01, T01, T04, T11 | 13 |
| GRD | D06, T07, T08, T09, T10 | 5 |

Of the 46 runtime rows:

- **0** change traffic (§1.1).
- **11** turn an absent mode into `shield`: L01, L12, L17, L18, L19, L22,
  L30, L35, L36, L38, L45.
- **12** put the legacy value in a slot that answers "what is Edge doing"
  (L18, L19, L20, L21, L23, L24, L25, L27, L28), a Policy Profile slot
  (L26), a Deception state (L30) or an e-paper headline (L35).
- **1** is already compliant (L34, the touch console).

## 4. Other keys called `mode` (not the legacy concept mode)

These are not portal/shield/scapegoat. They are listed so that a migration
does not rename them by accident, and so each gets its #379 term.

| # | File:line | Values | What it is | Target term | Note |
| --- | --- | --- | --- | --- | --- |
| O01 | `py/azazel_edge/arbiter/action.py:29`–`:57` | `passive` / `human_loop` / `bounded_control` / `high_risk_control` | Control class of an action profile. | Control class (decision-loop.md) | Pinned by T08. Also "control mode" in `docs/papers/auditable-edge-socnoc-paper.md:143`, `:247`. |
| O02 | `py/azazel_edge/mio/contracts.py:112`, `py/azazel_edge/mio/handoff.py:164` | `disabled` / `dry_run` / `policy_gated` / `release_guard_failed` / `enforced` / `none` | How a current action was applied. | Applied status (not in #379's list) | Not a state; close to `applied_state`. |
| O03 | `rust/azazel-edge-core/src/main.rs:223`; `py/azazel_edge/explanations/live.py:167`, `:234`; `py/azazel_edge/notify/core_decisions.py:177`; `py/azazel_edge/outcome/adapter.py:40`, `:138`, `:224` | `dry_run`, … | `enforcement.mode` of a core decision; shown as `control_mode` and `enforcement_mode`, sent in core-decision notifications. | Applied status | `control_mode` here is a third meaning of "control". |
| O04 | `py/azazel_edge_ai/agent.py:316`, `:320`, `:865`; `azazel_edge_web/app.py:3468`; `azazel_edge_web/static/sentinel.js:1433`; `azazel_edge_web/static/app.js:3059` | `normal` / `degraded` | AI agent runtime policy (`policy_mode`), shown as "Policy mode" / "Policy:". | AI Runtime Tier | Labelled as policy; reads like a Policy Profile. |
| O05 | `azazel_edge_web/app.py:6252` | `shadow_only` | AI governance read-out. | AI Runtime Tier | — |
| O06 | `azazel_edge_web/app.py:215`, `:2497`, `:2688`, `:5975` | `live` / `synthetic` | TopoLite seed mode (data source, watermark). | Presentation State | — |
| O07 | `azazel_edge_web/app.py:4849`; `py/azazel_edge/scenario_replay.py:538`; `py/azazel_edge/bhusa_verify.py:204` | `deterministic_replay` / `live_test_input` | Provenance of the booth focus / replay record. | Presentation State | — |
| O08 | `py/azazel_edge/sensors/noc_monitor.py:639`, `:676`; `py/azazel_edge/evaluators/noc.py:449`; `py/azazel_edge_control/daemon.py:1323`, `:1377`; `azazel_edge_web/app.py:2871`; `azazel_edge_web/templates/index.html:982` | `utilization_known` / … | NOC capacity measurement method (shown under the label *Mode*). | Threat Level input (NOC) | Not a state. |
| O09 | `py/azazel_edge_control/daemon.py:383`, `:392`; `azazel_edge_web/app.py:2741` | `internal` / `external` | NOC monitoring scope. | Configuration | — |
| O10 | `py/azazel_edge_control/daemon.py:1606` | `stopped` / … | NOC link watcher status. | Component health | — |
| O11 | `azazel_edge_web/app.py:4640`–`:4689` | `bot_api` / `webhook` / `disabled` | Mattermost transport. | Integration transport | — |
| O12 | `py/azazel_edge/mio/evaluation.py:51`, `:144` | `pure_replay` | M.I.O. evaluation scenario kind. | Evaluation harness | — |
| O13 | `py/azazel_edge/bhusa_prep.py`, `py/azazel_edge/bhusa_issue_helper.py` | `ops-pack`, `apply`, … | CLI sub-mode of booth tooling. | Tooling | — |
| O14 | `py/azazel_edge/i18n.py:124`–`:138` (`dashboard.mode_layer*`) | Beginner / Professional | Legacy dashboard display layer. | Workspace/View | — |
| O15 | `bin/azazel-mio-shadow-replay:125`; `py/azazel_edge/mio/evaluation.py:69` | — | Replay fixtures default `current_defensive_state` to `OBSERVE` when absent. | Defensive State | Replay only; contrasts with "absence is not a state" (decision-loop.md). |
| O16 | `docs/CONFIGURATION.md:113` | `MODE=open` | `set_dev_remote_access.sh` access mode. | Configuration | — |

## 5. Out of scope

- **Concept branding.** "Cyber Scapegoat Gateway", "Field-Deployable
  Scapegoat Gateway" (`README.md`, `SECURITY.md`, `concept_profiles/`,
  `demos/concepts/`, `docs/concepts/`, `docs/cfp/`,
  `docs/architecture/deception-routing.md:31`, `docs/CHANGELOG.md`).
  decision-loop.md keeps legacy names permitted as concept branding.
- **Captive portal.** `captive_portal*`, the `portal_access` triage flow,
  `rb.user.portal-access-guide`, `install_captive_portal.sh`, Suricata and
  Sigma rules about fake portals. These are network observations and
  guidance, not the operational mode.
- `docs/archive/` (no hit).

## 6. The #515 finding: `shield` from absence, shown as green

PR #515 (SENTINEL i18n/a11y/JS tests, display only; merged after this
inventory was taken at `1cefe66`, so the line numbers above predate it) found, with its JS harness, that SENTINEL shows green or invented
values when data is missing, and changed `sentinel.js` so that an absent
mode is `UNKNOWN` (L27, L28, L30). It also found why that is not enough:

- `azazel_edge_web/app.py` fills `"shield"` when there is no mode, in the
  summary's `mode.current_mode` and `command_strip.current_mode` (L45),
  and `get_mode_state()` does the same on daemon failure (L38). The daemon
  itself reports `shield` with `ok: true` when `mode.json` is missing
  (L12), which on a device without a written `mode.json` is always.
- So in real operation a mode is almost always present, and the JS fix does
  not trigger. The Deception node stays a green `STANDBY` with
  `Mode: SHIELD`, the Azazel-Edge hop stays a green `SHIELD`, CONTROL is
  `is-ok`, and *Applied* is `YES` — a false green that no decision and no
  enforcement produced.
- Changing the server default changes API behaviour (T01 pins `shield`),
  so #515 left `app.py` unchanged and named it an owner decision. It is
  §7 D3 here.

## 7. Owner decisions (not decided here)

| # | Decision | Options seen | Bound by |
| --- | --- | --- | --- |
| D1 | Add a canonical `defensive_state` field? Where (`/api/state`, `/api/dashboard/summary`, the snapshot, the Fabric `StatusView`, the EPD state), from which source (the arbiter's/core's last selected action), and what absence is (`UNKNOWN`, `null`, or no key). | add next to `mode` (additive) / replace `mode` / Fabric-only | #379 steps 3–7; "absence is not a state"; no enforcement change. |
| D2 | Deprecate or remove `/api/mode` (GET and POST), the `mode_*` actions on `/api/action` and on the socket, the legacy dashboard buttons and the TUI menu. If deprecated, for how long, and is the EPD label kept as concept branding or replaced by the Defensive State. | keep as compatibility-only / deprecate with a date / remove | #340 (do not re-promote), #471 socket contract (T03), installer. |
| D3 | The server-side and renderer `shield` defaults (L01, L12, L17–L19, L22, L35, L36, L38, L45). | report `unknown` / omit the key / keep `shield` and mark `ok: false` + `source` | #515; T01 pins `shield`. |
| D4 | One role boundary for changing the mode: `admin` on `POST /api/mode` vs `responder` on `POST /api/action/mode_*`. | align to admin / align to responder / remove one path | No new authority may be added; aligning is a policy change. |
| D5 | What SENTINEL shows in the slots that today fall back to the mode (CONTROL, Active control, Applied, Azazel-Edge hop, Deception node, audit Policy). | Defensive State or `UNKNOWN` / keep legacy label beside it | #379 step 6; #340. |
| D6 | The audit fields: caller-supplied `requested_by`, `config_hash` of the mode name, `config_drift.policy_markers.current_mode`, and a history that holds one record. | keep as legacy / authenticated actor / drop | AUD rows L12–L16. |
| D7 | The handoff text `mode=…` that reaches Mattermost. | Defensive State / both / drop | L39. |
| D8 | Naming of the non-legacy `mode` keys in §4 (AI `policy_mode`, `control_mode`, capacity "Mode" label). | rename to #379 terms / leave | #379 step 8 (AI Runtime Tier, never `mode`). |

## 8. How this page is held

`tests/test_defensive_state_mode_inventory_v1.py` scans the code and test
directories for legacy-mode markers (`current_mode`, `/api/mode`, the
`mode_*` actions, `ModeManager`, `mode_state_candidates`, `mode.json`,
`recent_mode_changes`, `mode_last_change`, `mode_label`, `scapegoat`, a
quoted `shield`) and fails if a file that contains one is not named on this
page, or if a file named here no longer exists. It checks file names only:
line numbers drift and are not part of the check.
