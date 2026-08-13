# SOC / NOC Workspace Design for the Command Dashboard

Status: Implemented (dashboard workspace toggle)
Parent roadmap: #283 (post-BHUSA dashboard polish)

## Why not "a SIEM dashboard"

The project doctrine is explicit: the Azazel-Edge WebUI is a **decision-support
display, not a generic SIEM dashboard** (see
`docs/issues/bhusa-2026-vegas-readiness/03-operator-decision-support-view.md`).
This document therefore borrows *design research* from SIEM/SOC/NOC dashboard
practice, and applies only what serves the deterministic decision-support
story: evidence → separate NOC/SOC evaluation → one bounded action →
explanation → audit.

## Research findings applied

1. **Role-specific views beat a single pane of glass.** Industry experience
   with "single pane of glass" monitoring reports data overload and alert
   fatigue when every audience shares one canvas; the recommendation is the
   *right* visibility per role, not total visibility. Azazel-Edge already has
   an audience axis (Professional/Temporary); this design adds an orthogonal
   *domain* axis (All/NOC/SOC) instead of building separate pages that would
   duplicate polling, auth, and i18n machinery.
2. **The 5-second rule and F-pattern.** Operators should reach the most
   important information within ~5 seconds; attention concentrates top-left.
   Both workspaces therefore keep the Command Strip (hero + heat cells) as the
   first block and promote their domain's primary object directly under it —
   the SOC's triage/evidence stack, the NOC's client/path/service stack.
3. **Alert-by-exception with severity lanes.** SOC dashboards should surface
   deviations (Critical/High/Medium/Low lanes) rather than streams. The
   deterministic `now / watch / backlog` alert queues and the SOC triage queue
   are the Azazel-Edge equivalent of severity lanes, so the SOC workspace
   auto-opens the SOC/NOC split details and the Evidence & Timeline fold that
   contain them.
4. **NOC wallboards are read by color, not text.** NOC guidance emphasizes
   glanceability: status colors legible at distance, minimal prose, alarm
   panels adjacent to health panels. The NOC workspace therefore leads with
   tile/chip-based panels (client identity tiles, service chips, path facts,
   capacity) and drops the SOC's prose-heavy evidence audit column entirely.
5. **Triage console vs. management layer.** SOC metric guidance distinguishes
   the analyst triage console from the lead's metric overview. The workspace
   design keeps triage-relevant state (queues, evidence, decision trust) in
   the SOC workspace and leaves long-horizon metrics (AI governance rates,
   trend snapshots) in the shared Runtime/Evidence blocks.

Sources consulted (2026-08): SearchInform SIEM dashboard/alert-fatigue best
practices, Activu SOC dashboard checklists, DPS Telecom & ExterNetworks NOC
design guides, Craft Wall NOC/SOC video-wall reference architectures, SquaredUp
/ Checkly single-pane-of-glass critiques, FanRuan & Prophet Security SOC
KPI/workflow articles, and the widely cited 5-second-rule / F-pattern dashboard
design principles (Luzmo, InfluxData, Sisense).

## The workspace axis

`body[data-workspace]` ∈ `simple` (default) | `all` | `noc` | `soc`, persisted
in `localStorage` and overridable via `?workspace=`. The toggle lives in the
topbar next to the audience toggle. `simple` and `all` are available to both
audiences; the `noc`/`soc` buttons and CSS rules are **professional-audience
only** (`.pro-only` + a CSS gate on `data-audience="professional"`), so
beginner mode keeps a simplified flow.

## Simple workspace (default landing view)

The primary question hierarchy proposed by the operator and confirmed by the
5-second-rule research: *Is the overall situation good or bad? Below that: is
SOC good or bad, is NOC good or bad? Click to drill deeper only when needed.*

Three verdict tiles, and nothing else on screen (except the synthetic-data
warning banner, which is a safety requirement and always shows):

1. **Overall** — one large verdict + one-line reason + **one "Do now" action**
   (decision-support doctrine: never a bare status without the next step).
   Click → `all` workspace.
2. **SOC — Any threat activity?** — verdict + reason + NOW/WATCH/BACKLOG and
   visibility chips. Click → `soc` workspace (professional) / `all`
   (temporary).
3. **NOC — Is the network healthy?** — verdict + reason (the degraded
   components, e.g. `Path: DEGRADED | Clients: 3 ANOM`) + uplink / internet /
   services / clients chips. Click → `noc` workspace (professional) / `all`
   (temporary).

Design rules that keep the simplification honest:

- **Four states, not two**: GOOD (green) / WATCH (amber) / BAD (red) /
  **UNKNOWN (STALE)** (gray). When `command_strip.stale_warning` is set the
  verdict is withheld — a stale snapshot must never render a false green.
- **No new judgment logic**: verdicts reuse the exact `summarize*` helpers and
  `strongestTone` aggregation that drive the Command Strip hero and the
  SOC/NOC glance cards, so the Simple tile can never disagree with the full
  board, and the deterministic audit story ("why this color") is unchanged.
- **Reason + action always attached**: a verdict with no reason forces a
  click every time and defeats the simplification.

Scoping classes mirror the audience mechanism:

- `.soc-scope` — hidden in the NOC workspace
- `.noc-scope` — hidden in the SOC workspace
- unscoped — shared by both

## SOC workspace (threat evidence → bounded decision)

Order (top to bottom): Command Strip → Situation/Split/Action board (posture
card, SOC/NOC split with details auto-opened, action board, M.I.O. rail) →
Evidence & Timeline (auto-opened; keyword filter) → Topo-Lite → Mission →
Client Identity → Runtime health.

- Keeps the **NOC glance card** inside the split board: the doctrine requires
  checking NOC health before choosing stronger control, so the SOC view never
  hides the NOC summary — only the NOC *detail* sub-board.
- Hides: the NOC detail split card, the network-health facts card (uplink and
  internet state stay visible as Command Strip pills).

## NOC workspace (path / service / clients / capacity)

Order: Command Strip → Client Identity (details auto-opened) → Situation/Split
board (network health, service chips, NOC split details auto-opened, action
board, M.I.O. rail) → Runtime health (queue/latency meters) → Node Fleet →
Topo-Lite → Mission.

- Keeps the **SOC glance card** (is a threat driving this outage?) but hides
  the SOC detail split card, the threat-posture card, and the Evidence &
  Timeline audit board.
- Promotes the aggregator/fleet panel: multi-node freshness is a NOC concern.

## Fold defaults

Switching workspace applies *default* open states only to folds the operator
has never explicitly toggled (explicit choices are persisted by the fold-state
mechanism and always win):

- SOC: open SOC/NOC split details and Evidence & Timeline.
- NOC: open SOC/NOC split details and Client Identity endpoint details.

## Non-goals / future work

- No second data path: both workspaces render from the same poll cycle and the
  same payload contracts (`tests/test_dashboard_data_contract.py` unchanged in
  shape).
- Queue-age ("oldest unacknowledged NOW alert") and MTTA-style chips are a
  candidate follow-up once the alert-queue payload carries acknowledgement
  state.
- The booth (`/booth-focus`) and ops-comm surfaces are unaffected.
