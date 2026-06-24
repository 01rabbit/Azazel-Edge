# BHUSA 2026 Vegas readiness tracking

Parent roadmap: #283

This tracking file records the detailed execution plan from `2026-06-23` to the
Black Hat USA 2026 Arsenal session on `2026-08-05`.

For the finer-grained operational plan, see
`70-detailed-execution-plan.md`.

Public session:

- Title: Azazel-Edge: Deterministic Edge Decision Support for Constrained SOC/NOC Operations
- Presenter: Makoto "Mr. Rabbit" SUGITA
- Date: Wednesday, August 5, 10:10am-11:10am
- Location: Arsenal Station 4, Business Hall
- Track: Network

## Planning rule

Before Vegas, prioritize repeatability, documentation accuracy, operator
visibility, and auditability over new capability.

The critical path is:

1. #290 docs sync
2. #284 demo story and talk track lock
3. #285 deterministic replay readiness
4. #287 audit and explanation walkthrough
5. #286 operator decision-support view
6. #288 live Tactical first-pass boundary and fallback
7. #289 booth rehearsal and failure runbook
8. #291 final release freeze and no-risk rule

## Child issues

- #284 — Lock Vegas demo story and talk track
- #285 — Stabilize deterministic replay for Arsenal booth demo
- #286 — Build operator decision-support booth view
- #287 — Prepare audit and explanation walkthrough
- #288 — Clarify live Tactical path vs replay fallback boundary
- #289 — Prepare booth rehearsal runbook
- #290 — Sync docs with public Black Hat session description
- #291 — Define final release freeze and no-risk rule

## Weekly execution plan

### Week of 2026-06-23 to 2026-06-29

Primary target:
- Complete #290.

Tasks:
- Update `docs/arsenal/blackhat-usa-2026.md` with the public title, presenter, date, time, station, location, and track.
- Update `docs/ARSENAL_DEMO_PROFILE.md` so replay is explicitly documented as a booth-stability technique and not the normal live Tactical first-pass path.
- Verify `README.md` and deterministic-edge concept docs use the same constrained, local, deterministic framing.
- Remove or soften wording that implies autonomous AI defense, cloud SOC replacement, or full CTI platformization before Vegas.

Deliverables:
- Public-facing repo docs match the accepted BHUSA 2026 session.
- One consistent wording baseline exists for all later booth material.

Exit criteria:
- Docs preserve the accepted title and description.
- AI assist is consistently described as optional operator support.
- Replay vs live boundary is documented in repo-facing material.

### Week of 2026-06-30 to 2026-07-06

Primary target:
- Complete #284.

Tasks:
- Write the 90-second visitor explanation.
- Write the 5-minute compressed walkthrough.
- Write the full 60-minute booth outline.
- Add one canonical architecture/demo diagram: Tactical Engine -> Evidence Plane -> NOC/SOC Evaluators -> Action Arbiter -> Decision Explanation -> Audit Review.
- Cross-check talk notes against `README.md`, `docs/arsenal/blackhat-usa-2026.md`, and `docs/ARSENAL_DEMO_PROFILE.md`.

Deliverables:
- A fixed talk track for short, medium, and full-length conversations.
- One canonical diagram used in slides, notes, and booth explanation.

Exit criteria:
- A visitor can understand the core contribution in under 90 seconds.
- The 5-minute path starts from deterministic evidence-to-decision flow, not optional integrations.

### Week of 2026-07-07 to 2026-07-13

Primary target:
- Complete #285.

Tasks:
- Select one primary replay scenario and freeze it for booth use.
- Verify `bin/azazel-edge-demo run <scenario>` on the target Raspberry Pi-class device.
- Confirm stable evidence IDs, evaluator outputs, selected action, rejected alternatives, explanation record, and audit entries.
- Confirm `deterministic_replay` visibility where applicable.
- Confirm Internet-free execution and no booth-network dependency.
- Add or update replay determinism tests for the selected scenario.
- Document fallback from live-assisted mode to replay-only mode.

Deliverables:
- One known-good replay scenario for booth use.
- A documented replay command sequence and reset procedure.

Exit criteria:
- The selected replay scenario succeeds 5 consecutive times with only documented cleanup.
- The same replay input yields the same bounded decision under the same profile.

### Week of 2026-07-14 to 2026-07-20

Primary targets:
- Complete #287.
- Bring #286 to reviewable state.

Tasks for #287:
- Verify `bin/azazel-edge-audit-review --compact`, standard, and `--json` output after the selected replay scenario.
- Confirm the explanation record contains `trace_id`, selected action, rejected actions, `why_not_others`, release condition, policy profile, config hash, evidence IDs, and operator wording.
- Confirm audit chain verification reports OK for the selected scenario.
- Write the booth script for compact audit walkthrough.
- Add a negative-path note for audit mismatch handling.

Tasks for #286:
- Select the current Web UI route/component that will serve as the Vegas decision-support view.
- Expose evidence summary, separate NOC/SOC outputs, selected action, `why_chosen`, `why_not_others`, AI assist status, policy profile, and audit trace ID.
- Define a compact layout for booth projection or laptop use.
- Document CLI/JSON fallback if the Web UI is unavailable.

Deliverables:
- A 2-minute audit walkthrough path.
- A reviewable booth decision-support display with CLI fallback.

Exit criteria:
- Audit review is legible on a booth laptop screen.
- The operator view tells the deterministic story without raw JSON being the primary interface.

### Week of 2026-07-21 to 2026-07-27

Primary targets:
- Complete #288.
- Complete #289.

Tasks for #288:
- Document normal live Tactical first-pass operation vs Arsenal replay demonstration.
- Add a clear table or diagram separating live-assisted and replay-only booth paths.
- Define exact conditions for abandoning live-assisted mode during the session.
- Verify fallback behavior for Suricata failure, OpenCanary failure, network instability, and AI/Ollama failure.

Tasks for #289:
- Prepare boot checklist for the booth device.
- Prepare service-health checks for required services.
- Prepare replay checklist, audit review checklist, and reset procedure.
- Prepare offline-operation and no-AI-operation checklists.
- Fix final booth laptop layout: browser, terminal, notes, backup docs.
- Run at least 3 full rehearsals using the final script.
- Record actual run times for the 90-second, 5-minute, and full walkthrough variants.

Deliverables:
- A final fallback matrix.
- A practical booth runbook that can be used without code edits.

Exit criteria:
- Optional components can fail without breaking the core deterministic story.
- Rehearsal proves separate NOC/SOC evaluation, bounded arbitration, explanation, and auditability.

### Week of 2026-07-28 to 2026-08-01

Primary target:
- Complete #291 and enter freeze.

Tasks:
- Select the known-good demo branch, tag, or commit.
- Define allowed post-freeze changes: docs fixes, runbook corrections, replay bug fixes, and booth-safe UI text fixes.
- Define disallowed post-freeze changes: large refactors, new integrations, autonomous AI behavior, CTI sensorization, and broad architecture changes.
- Re-run replay and audit review on the freeze candidate.
- Archive exact commands, expected output snippets, and fallback commands.
- Confirm offline copies of key docs are present on the booth machine.

Deliverables:
- One known-good freeze candidate for Vegas.
- A final command sheet with fallback commands.

Exit criteria:
- The selected replay and audit review succeed on the target device.
- Any post-freeze change is narrowly tied to correctness or demo stability.

### Week of 2026-08-02 to 2026-08-04

Primary target:
- Final validation only.

Tasks:
- Run daily short-form rehearsal on the freeze candidate.
- Confirm browser, terminal, notes, and backup files are in final booth layout.
- Avoid code changes unless a true demo blocker appears.
- Confirm offline operation remains intact.

Deliverables:
- Final booth-ready state without further feature work.

Exit criteria:
- The presenter can switch to replay-only mode immediately.
- The booth can run without Internet access.

### 2026-08-05 session day

Pre-session checklist:
- Confirm service health on the booth machine.
- Run the selected replay scenario once before public start.
- Run compact audit review once before public start.
- Confirm local-only operation path and backup files are available.

## Success metrics

- A visitor understands the value proposition in under 90 seconds.
- The 5-minute walkthrough shows deterministic evidence-to-decision flow without leading with optional integrations.
- The audit/explanation path can be demonstrated in under 2 minutes after replay.
- Optional AI or integration failures do not prevent the core demonstration.
- The final demo can be run from the freeze candidate without day-of code edits.

## Explicit non-goals before Vegas

- Agentic Edge SOC/NOC reframing
- Tactical CTI Sensor expansion
- Full knowledge graph or richer long-horizon correlation implementation
- External SIEM/SOAR platformization
- Autonomous AI control paths
- Large refactors that increase booth risk
