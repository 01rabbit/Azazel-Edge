# SENTINEL Decision Console — Web UI Information Architecture

Status: implemented (2026-08-15). Applies to `azazel_edge_web/` (Flask + Jinja +
vanilla JS). This document describes the **presentation layer** only. It adds no
decision logic and changes no backend contract.

## Purpose

Re-skin the operator dashboard from a "generic SIEM dashboard" into a
**decision-support appliance** whose whole visual language makes the Azazel-Edge
decision path legible in seconds:

```
EVIDENCE → NOC / SOC EVALUATION → DETERMINISTIC DECISION → BOUNDED CONTROL → EXPLANATION → AUDIT
```

Design law: **Normal is quiet. Exceptions demand attention.** Color, text, and
shape all carry state (never color alone). AI (M.I.O.) is a subordinate,
post-decision assist — **AI authority: NONE**.

## What was added (and what was deliberately NOT touched)

This is a **progressive re-skin**, not a rewrite. The existing `index.html` DOM
is a de-facto contract (pinned by `tests/test_dashboard_data_contract.py`:
~110 element IDs / label strings, plus a forbidden-ID list). Every one of those
nodes is preserved. The console is layered on top:

| Added (new, additive) | File |
| --- | --- |
| Industrial design system + tier/pipeline styles | `static/sentinel.css` (loaded **after** `style.css`, overrides `:root` tokens) |
| 4-tier navigation controller + decision-pipeline renderer | `static/sentinel.js` (event-driven; no new polling) |
| Tier nav markup, `data-tier`/`data-op` attributes, decision-pipeline strip | `templates/index.html` (attributes + new nodes only; no node/ID removed) |
| One-line integration hook: `document.dispatchEvent('azazel:refresh', …)` | `static/app.js` (after each render) |

**Not touched:** all `/api/**` payloads, the deterministic evaluator/arbiter, the
audit trail, `auth.py`, `installer/`, `security/`, `systemd/`. No backend
behavior changed. (Edge#348 later added `sentinel.*` display strings to the i18n
catalog `py/azazel_edge/i18n.py`; see [i18n](#i18n).)

## Data flow

`app.js` keeps its single-flight 4s poll over the existing 11 endpoints. After a
successful render it dispatches `azazel:refresh` with `{summary, actions,
evidence, health, state}`. `sentinel.js` listens and updates the decision
pipeline + per-tier status dots. **No extra requests, no duplicate polling.**
Absent data renders as `UNKNOWN` — never fabricated, never silently green.

## 4-tier information architecture

Client-side tabs group the existing panels via `data-tier`. Tier visibility
composes with the pre-existing `data-audience` (temporary/professional) filter:
a panel shows only when **both** its tier is active and the audience policy
allows it. When an audience hides an entire tier, a note points to Professional
mode (`#sentinelTierEmpty`).

| Tier | Panels (data-tier) | Answers |
| --- | --- | --- |
| **OVERVIEW** | command-strip (Visual Baseline + heat), current-mission, temporary-mission, situation-board, action-board (decision/rejected/control), M.I.O. assist | "What is happening, why, what is Azazel doing, where's the basis?" |
| **OPERATIONS** | split-board (SOC \| NOC), client-identity (NOC), topolite-nav (NOC). Sub-filter `data-op`: SOC / NOC / BOTH | Threat evidence → response, and network/service health, kept separate |
| **EVIDENCE** | evidence-board (timeline/alert-queues/triage-audit), topolite-single-screen | Expert drill-down to verify the deterministic decision |
| **SYSTEM** | resource-guard (runtime health), aggregator (fleet) | Appliance health: queue, fallback, latency, stale gates, AI governance |

SOC vs NOC separation is enforced by the payload shape itself (`soc_focus` vs
`noc_focus` carry disjoint fields); the NOC surface never renders raw IDS
`sid`/`severity`/`src`/`dst`.

## Decision pipeline strip (SENSE → EVALUATE → DECIDE → CONTROL → AUDIT)

A always-visible status rail at the foot of the console, driven by deterministic
fields — a navigation/status component, not decoration:

| Stage | Source (deterministic) |
| --- | --- |
| SENSE | evidence intake count + `decision_path.first_pass_engine` (`tactical_scorer_v1`) |
| EVALUATE | `noc_focus.path_health.status` + `soc_focus.threat_level`; `decision_path.second_pass_status` |
| DECIDE | `normal_assurance.status` (arbitrated verdict: normal/watch/alert) |
| CONTROL | `mode.current_mode` (bounded, reversible) |
| AUDIT | recording state from evidence audit rows (full trace detail lives in the Evidence tier) |

The pipeline renders the decision **before and independently of** any AI text
(AI assist is step 7 of `decision-loop.md`, strictly post-decision).

## State model (reused, not reinvented)

| Console state | Driven by | Visual |
| --- | --- | --- |
| NORMAL | `normal_assurance.status == normal` | quiet; green reserved for verified-healthy |
| WATCH | `normal_assurance.status == watch` / `soc_focus.threat_level` elevated | amber on the decision surfaces only |
| CRITICAL | `normal_assurance.status == alert` / threat critical / `suricata_critical > 0` | red on the affected surfaces only; background never floods |
| STALE / UNKNOWN | `command_strip.stale_warning`, `health.stale_flags`, missing data | steel/gray; **never** shown as green NORMAL |

`status-neutral` maps to `--accent-steel` (unknown), guaranteeing stale/unknown
is never dressed as healthy — enforced by `tests/test_sentinel_console_v1.py`.

Edge#348's DOM harness found four bespoke surfaces that painted green, or
showed a made-up value, when their input was absent. They now render unknown
(display only; the payloads and decisions are unchanged): the NOC path strip's
Clients and Azazel-Edge hops (no client count / no mode), the NOC runtime
meters (no queue or LLM health → `—`), the interface-utilization meter (no
utilization), and the fleet's in-box Deception node (no mode → `UNKNOWN`, was a
green `STANDBY` and "Mode: SHIELD"). The traffic-control "Active control" row
no longer defaults to `OBSERVE` when neither a decision nor a mode is known.

These fixes are in `sentinel.js` only. The server fills a missing mode with
`shield` (`azazel_edge_web/app.py`, `mode.current_mode` of the summary), so a
mode is almost always present and the server-made default can still show as
STANDBY/SHIELD; changing that default is an API behaviour change for the owner
to decide. The traffic-control Effect (`visibility only`) and Enforcement
(`dry-run (advisory)`) rows still state a value when the action is unknown;
how enforcement state is shown is also left to the owner.

## Visual design system

`sentinel.css` overrides the base `:root` tokens toward an industrial
instrument: flat `#0B0E11` ground (no radial neon glow), hairline borders,
restrained radii (8/6/4px), a faint vertical grid, monospace for all numerics /
identifiers / timestamps, and a 5-color semantic palette (cyan=navigation,
green=verified-healthy, amber=watch, red=critical, steel=unknown/stale). No new
fonts, no CDN, no chart library — trend meters are CSS/SVG (the existing
`az-spark` sparklines), respecting Raspberry Pi constraints.

## Accessibility

Updated by Edge#348. Display only: no decision, enforcement or API change.

| Surface | Pattern | Keyboard |
| --- | --- | --- |
| Tier nav (OVERVIEW…SYSTEM) | Navigation, not a tab pattern: buttons in a `nav`, the active tier is `aria-current="page"`, roving `tabindex` (active `0`, others `-1`) | Arrow Left/Right **and** Up/Down (vertical sidebar), Home/End; focus moves with the tier. Arrows on the Ask M.I.O. link do nothing |
| SOC / NOC (Operations) | True WAI-ARIA tabs: `role="tablist"` → `role="tab"` with `aria-selected` + `aria-controls`; `sentinelSocConsole`/`sentinelNocConsole` are `role="tabpanel"` labelled by their tab | Arrow keys, Home/End; automatic activation |
| Evidence sub-views (TIMELINE…RAW DATA) | True tabs; each view is a `tabpanel` (lists are wrapped, so `ul` keeps its list role) | Same |
| System sub-views (RUNTIME…CONFIGURATION) | True tabs | Same |
| Range / triage-band filters | Toggle buttons with `aria-pressed` (filters, not views) | Tab + Enter/Space |
| Evidence timeline rows | `role="button"`, focusable | Enter/Space opens the detail |

- **Live region.** `#sentinelLiveRegion` (`role="status"`, `aria-live="polite"`,
  `aria-atomic`) announces a tier's state change once, e.g. "Status changed:
  SYSTEM: CRITICAL". The first observation after load and an unchanged 4 s poll
  are silent, so it never chatters.
- **Never color alone.** Tier dots carry SR text ` (UNKNOWN)` etc. plus a shape
  cue; each pipeline stage's accessible name ends with its state
  (`SENSE (WATCH)`); the CPU/MEM/DISK/TEMP tiles carry
  `aria-label="Disk 42% (OK)"`; the top-talker share bar has its percentage as
  SR text; evidence rows, triage bands and identity states have words.
- **Contrast (WCAG AA).** Every text and accent token in `sentinel.css`
  (`--text-main/dim/soft`, `--accent-cyan/green/amber/red/steel`) is ≥ 4.5:1 on
  every background token (`--bg-0/1/2`, `--bg-panel`, `--bg-panel-strong`,
  `--bg-inset`); the lowest pair is `--accent-red` on `--bg-2` at 4.67:1.
  `sentinel.css` sets no text color outside these tokens. Both are checked by
  `tests/test_sentinel_console_v1.py`. This is computed from the tokens, not
  measured on a screen.
- Visible focus rings; all motion respects `prefers-reduced-motion` (the console
  adds no blinking). Responsive down to phone width; the main screen never
  scrolls horizontally.
- **Touch console** (`/touch`): its tab bar already was a true tab pattern with
  roving `tabindex`, but had no arrow keys, so a keyboard could not reach the
  inactive tabs. Arrow keys and Home/End now move between tabs.

## i18n

Updated by Edge#348.

- **Operator-facing sentences** go through the catalog: `sentinel.*` keys in
  `py/azazel_edge/i18n.py` (JA and EN). `sentinel.js` reads the catalog that
  `index.html` injects (`window.AZAZEL_I18N`) with a small `tr(key, fallback,
  vars)`; a missing key, or a language without these keys (es/uk/tl), falls
  back to the English text in the code. Covered: empty states ("No recent
  evidence." …), the Managed-client talkers heading and its empty text, the
  External peers heading, the evidence count, the client roster summary, the
  fleet note, the tier-empty note, the QoS-planned note, the decisions note, the
  live-region sentence, and the tile names in the CPU/MEM/DISK/TEMP
  `aria-label`.
- **Product terms and state words stay fixed English** in every language:
  tier names, SOC/NOC, stage names, tab names, the visible tile labels
  (CPU/MEMORY/DISK/TEMPERATURE), field labels such as "Uplink", and state words
  (OK/WATCH/CRITICAL/UNKNOWN, VERIFIED, NOT APPLIED…). The decision-trace rows
  are not translated either: they are audit wording pinned by tests.
- `tests/test_i18n_catalog_consistency.py` keeps every `tr('key')` in
  `static/*.js` and the templates present in both JA and EN.
- Values from the API are written with `textContent` only; the catalog text is
  never parsed as markup.

## Bespoke consoles (target-design fidelity)

On top of the tier grouping, each tier renders a purpose-built console that
matches the target mockups, populated by `sentinel.js` from the same live
payloads (`app.js` adds `booth-focus` and `trends` to its single-flight poll and
passes them in the `azazel:refresh` detail):

- **Navigation** is a **left vertical sidebar** (OVERVIEW/OPERATIONS/EVIDENCE/
  SYSTEM) on desktop, collapsing to a top bar under 900px, with an
  "M.I.O. — AI authority: NONE" chip pinned at its foot. The command bar is
  compacted to a thin instrument bar (AZ-01 SENTINEL designation).
- **OVERVIEW** — Decision Console: System Posture + Active Control → NOC/SOC/
  DECISION triad → Why this decision / Rejected options → Recent evidence /
  Audit trail. (Trace/policy/config come from `booth-focus` when a decision
  record exists, else derived fields with `—` for the unknown trace.)
- **OPERATIONS** — SOC console (status + metrics + session risk sparkline + top
  evidence + evidence pipeline + threat categories) and NOC console (status +
  path/service/capacity/blast-radius), filtered by the SOC/NOC sub-nav.
- **EVIDENCE** — TIMELINE / EVIDENCE LIST / AUDIT TRAIL / RAW DATA sub-tabs with
  a click-to-inspect detail drawer (time/source/dest/protocol/severity/policy/
  rule/evidence/trace — absent fields show `—`, never fabricated).
- **SYSTEM** — RUNTIME (CPU/MEM/DISK/TEMP tiles — 0/absent renders as unknown,
  not green — plus uplink/services/core/AI-runtime and a resource-history
  sparkline), SERVICES, FLEET, CONFIGURATION sub-tabs.

The **preserved classic panels stay in the DOM** (contract) and are swapped in
behind a sidebar **"Show detailed panels"** toggle (`body.sentinel-fidelity`),
so no existing control or contract element is lost. Charts are hand-rolled
CSS/SVG sparklines — no chart library (Pi constraint).

## Tests

- `tests/test_sentinel_console_v1.py` — tier nav, SOC/NOC sub-filter, pipeline
  strip, `data-tier` grouping, asset wiring order, pinned-ID preservation,
  forbidden-ID absence, and the stale-≠-green + no-new-poll invariants; since
  Edge#348 also the tab patterns (tablist/tab/tabpanel wiring), the live
  region, `sentinel.*` keys present and translated in JA/EN, Japanese rendering
  with English product terms, and the WCAG AA token contrast.
- `tests/sentinel_console_logic.test.js` (node, run by CI and by the Python
  wrapper) — the pure logic (`computeConsoleState`, decision trace, DISK tile,
  managed talkers), and since Edge#348 a DOM harness: it mounts the console's
  real markup from `templates/index.html` into `tests/js_mini_dom.js` and runs
  the bespoke renderers. It asserts that they do not throw on empty, partial or
  odd payloads; that an empty payload paints nothing green (`is-ok`,
  `status-ok`, `tone-ok`) anywhere; that stale/down/unread stay off green; that
  data never becomes markup; tab ARIA state and Arrow/Home/End handling; the
  live region; and JA sentences with English product terms.
  `js_mini_dom.js` is a small dependency-free DOM, not jsdom: CI runs plain
  `node` with no `npm install`. It checks logic and ARIA state, not layout.
- `tests/touch_console_logic.test.js` — adds the tab-bar keyboard logic and the
  touch tab/tabpanel wiring.
- Existing `tests/test_dashboard_data_contract.py` (all pinned IDs/strings) and
  the i18n suites continue to pass unchanged.
