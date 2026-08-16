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
audit trail, `auth.py`, `installer/`, `security/`, `systemd/`, the i18n catalog
(`py/azazel_edge/i18n.py`). No backend behavior changed.

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

## Visual design system

`sentinel.css` overrides the base `:root` tokens toward an industrial
instrument: flat `#0B0E11` ground (no radial neon glow), hairline borders,
restrained radii (8/6/4px), a faint vertical grid, monospace for all numerics /
identifiers / timestamps, and a 5-color semantic palette (cyan=navigation,
green=verified-healthy, amber=watch, red=critical, steel=unknown/stale). No new
fonts, no CDN, no chart library — trend meters are CSS/SVG (the existing
`az-spark` sparklines), respecting Raspberry Pi constraints.

## Accessibility

Tier nav is a WAI-ARIA `tablist` with roving arrow-key navigation, visible
focus rings, `aria-selected`/`aria-pressed` state, and status conveyed by text +
shape as well as color. All motion respects `prefers-reduced-motion` (the
console adds no blinking). Responsive down to phone width via media queries; the
main screen never scrolls horizontally.

## i18n

New nav labels (OVERVIEW/OPERATIONS/EVIDENCE/SYSTEM, SOC/NOC) are intentional
English product terms (consistent with existing fixed-English headings such as
"Service Health", "NOC Focus"). No new `tr()` catalog keys are introduced, so
the JA/EN toggle and `tests/test_i18n_catalog_consistency.py` are unaffected.

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
  forbidden-ID absence, and the stale-≠-green + no-new-poll invariants.
- Existing `tests/test_dashboard_data_contract.py` (all pinned IDs/strings) and
  the i18n suites continue to pass unchanged.
