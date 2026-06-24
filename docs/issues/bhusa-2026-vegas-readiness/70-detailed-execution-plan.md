# BHUSA 2026 Vegas readiness detailed execution plan

Parent roadmap: #283

This file converts the weekly readiness plan into concrete execution blocks for
the period from `2026-06-23` to the Black Hat USA 2026 Arsenal session on
`2026-08-05`.

Issue #283 defines two scopes:

- Before Vegas: polish the accepted deterministic edge decision-support story,
  improve demo stability, and make the SOC/NOC decision path visible.
- Post-2026: hold larger research extensions outside the Vegas path.

This detailed plan follows that split exactly.

## Planning assumptions

- Current date baseline: `2026-06-23`
- Session date: `2026-08-05`
- Primary booth scenario: `mixed_correlation_demo`
- Primary audience outcome: explain deterministic edge decision support in under
  90 seconds, then prove auditability and replay stability in under 5 minutes
- Non-goal before Vegas: new architecture, broad AI expansion, or research-led
  feature work

## Current state snapshot

Already drafted in repo:

- Public-session-aligned docs baseline
- Booth message and talk track
- Replay runbook
- Audit walkthrough
- Booth decision-support UI additions
- Live boundary and fallback note
- Booth runbook
- Freeze candidate note and final command sheet

Still required before Vegas:

- Create and link the GitHub child issues back to #283
- Validate the replay path on the target Raspberry Pi-class booth device
- Run and record at least 3 full rehearsals using the final booth script
- Select the actual freeze commit on the booth device
- Restrict post-freeze edits to booth-safe fixes only

## Workstreams

### Workstream A: roadmap hygiene and issue tracking

Goal:
- Turn the repo plan into trackable GitHub execution items.

Tasks:
- Create child issues from `01` through `08`.
- Link each child issue back to #283.
- Post the prepared parent tracking comment on #283.
- Use one status line per child issue: `planned`, `in progress`, `review`,
  `validated on booth device`, or `closed`.

Exit criteria:
- #283 has visible child links for the Vegas-only scope.
- Each child issue has a clear acceptance target.

### Workstream B: message lock

Goal:
- Ensure every public explanation uses the same deterministic framing.

Tasks:
- Review `README.md`, `docs/arsenal/blackhat-usa-2026.md`,
  `docs/ARSENAL_DEMO_PROFILE.md`, and the talk-track docs together.
- Remove wording drift if any text implies autonomous SOC, cloud SOC
  replacement, or open-ended AI control.
- Rehearse the 90-second and 5-minute tracks from notes only.

Exit criteria:
- Presenter wording stays consistent across short, medium, and long variants.
- Replay is described as a booth-stability technique, not the normal operating
  model.

### Workstream C: deterministic demo validation

Goal:
- Prove that the booth scenario is stable on the target device.

Tasks:
- Run `bin/azazel-edge-demo run mixed_correlation_demo --format json` on the
  booth device 5 consecutive times.
- Confirm stable `trace_id` shape, evidence flow, NOC/SOC evaluation, selected
  action, and explanation persistence.
- Confirm the booth path works without Internet access.
- Record cleanup required between runs, if any.

Exit criteria:
- Five consecutive successful runs on the booth device.
- No hidden dependency on live network access.

### Workstream D: audit walkthrough validation

Goal:
- Make the audit story fast, legible, and repeatable.

Tasks:
- Run `bin/azazel-edge-audit-review --compact` after the replay scenario.
- Run standard output and `--json` output once each on the booth device.
- Confirm the explanation record contains the expected decision fields.
- Confirm the compact output is readable on the actual presenter screen.
- Rehearse the 2-minute audit explanation using the frozen command path.

Exit criteria:
- Compact review is booth-readable.
- Audit verification succeeds immediately after the replay path.

### Workstream E: booth operator view validation

Goal:
- Ensure the UI tells the deterministic story without dropping into raw JSON.

Tasks:
- Validate the view on the actual booth display size.
- Confirm the operator can point to:
  `trace_id`, `policy_profile`, `config_hash`, selected action, NOC reasoning,
  SOC reasoning, rejected alternatives, and audit path.
- Validate the copy-audit-command flow.
- Keep the CLI fallback visible in notes if the Web UI is unavailable.

Exit criteria:
- The presenter can explain the decision chain from the view alone.
- CLI fallback remains documented and tested once.

### Workstream F: failure boundary and fallback

Goal:
- Keep optional failures from breaking the core demo.

Tasks:
- Rehearse booth behavior for:
  Suricata unavailable, OpenCanary unavailable, Web UI unavailable, Ollama/AI
  unavailable, and unstable booth networking.
- Confirm which failures trigger immediate replay-only mode.
- Keep fallback wording aligned with the live-boundary note and booth runbook.

Exit criteria:
- The switch to replay-only mode is immediate and unambiguous.
- No fallback path requires code changes under booth pressure.

### Workstream G: rehearsal and freeze

Goal:
- Arrive in Las Vegas with one known-good booth state and no day-of refactor
  pressure.

Tasks:
- Run at least 3 full rehearsals using the final script.
- Record actual run times for:
  90-second visitor pitch, 5-minute walkthrough, and full session path.
- Archive the recorded runs with `bin/azazel-edge-bhusa-rehearse record` and
  confirm totals with `bin/azazel-edge-bhusa-rehearse summary`.
- Select the booth freeze commit after the rehearsal set passes.
- Keep an explicit post-freeze change log with narrow justifications.
- Confirm offline copies of the runbook, command sheet, and fallback docs are on
  the booth machine.

Exit criteria:
- One freeze candidate is selected on the booth device.
- Only booth-safe fixes remain allowed after freeze.

## Calendar plan

### Block 1: `2026-06-23` to `2026-06-29`

Primary outcome:
- Convert the repo plan into tracked GitHub execution.

Required actions:
- Create child issues and link them to #283.
- Use `bin/azazel-edge-bhusa-issues create` for preview and
  `bin/azazel-edge-bhusa-issues create --apply` for actual creation.
- Review the drafted docs set for wording drift.
- Mark any item that is still document-only and not yet device-validated.

Definition of done:
- GitHub tracking exists.
- Repo docs and issue scope say the same thing.

### Block 2: `2026-06-30` to `2026-07-06`

Primary outcome:
- Lock presenter wording and the primary booth scenario.

Required actions:
- Rehearse the 90-second and 5-minute scripts.
- Confirm `mixed_correlation_demo` remains the primary booth path.
- Freeze any planned talk-track edits unless they fix clarity.

Definition of done:
- Presenter script is stable.
- Scenario choice is stable.

### Block 3: `2026-07-07` to `2026-07-13`

Primary outcome:
- Complete first booth-device replay and audit validation.

Required actions:
- Run the 5 consecutive replay tests.
- Run audit review in compact, standard, and JSON modes.
- Log any cleanup or reset steps required between runs.

Definition of done:
- Replay and audit both succeed on the target device.
- Reset procedure is precise enough for another operator to follow.

### Block 4: `2026-07-14` to `2026-07-20`

Primary outcome:
- Validate the operator view and fallback behavior on real booth hardware.

Required actions:
- Test the Web UI layout on the real display.
- Verify CLI fallback once.
- Rehearse failure cases and replay-only transition.

Definition of done:
- The booth story survives optional component failure.
- Presenter can recover without source edits.

### Block 5: `2026-07-21` to `2026-07-27`

Primary outcome:
- Complete full rehearsals and collect timing.

Required actions:
- Run 3 full rehearsals.
- Record actual durations and any script friction.
- Fix only correctness or clarity blockers found during rehearsal.

Definition of done:
- Rehearsal evidence exists.
- Remaining defects are narrow, booth-relevant, and explicitly listed.

### Block 6: `2026-07-28` to `2026-08-01`

Primary outcome:
- Enter freeze.

Required actions:
- Select the exact freeze commit on the booth device.
- Re-run replay and audit verification on that commit.
- Stage offline copies of the command sheet and runbook bundle.

Definition of done:
- Freeze candidate is named.
- Post-freeze edits are formally constrained.

### Block 7: `2026-08-02` to `2026-08-04`

Primary outcome:
- Final validation only.

Required actions:
- Run daily short-form rehearsals.
- Confirm the final booth layout: browser, terminal, notes, and backup docs.
- Avoid code changes unless there is a true booth blocker.

Definition of done:
- Final state is operationally ready.
- No day-of setup depends on new development.

### Session day: `2026-08-05`

Pre-open sequence:

1. Confirm booth-device service health.
2. Run the frozen replay scenario once.
3. Run compact audit review once.
4. Open the Web UI, terminal, notes, and offline backup docs.
5. Start in the short-message path unless a deeper audience question appears.

## Daily check template

Use this as the minimum daily update until freeze:

- Date:
- Booth-device validated today: yes/no
- Replay status: pass/fail
- Audit review status: pass/fail
- UI status: pass/fail
- Fallback path checked: yes/no
- New blocker:
- Allowed next action:

## Blocker rule

Treat these as true Vegas blockers:

- Replay fails on the booth device
- Audit verification fails after replay
- Presenter cannot explain selected vs rejected actions from the UI or fallback
- Offline operation is broken
- A required recovery step depends on live code edits

Treat these as non-blockers before Vegas unless they affect the accepted demo:

- Broader CTI expansion
- Autonomous AI experiments
- Large architecture cleanups
- New integrations that do not improve booth stability

## Final readiness gate

Vegas readiness is complete only when all of these are true:

- Child issues exist and are linked from #283
- Presenter wording is locked
- `mixed_correlation_demo` passes repeated booth-device replay
- Audit review succeeds on the booth device
- The operator view is legible on booth hardware
- Fallback to replay-only mode is rehearsed
- At least 3 full rehearsals are recorded
- One freeze commit is selected and revalidated
