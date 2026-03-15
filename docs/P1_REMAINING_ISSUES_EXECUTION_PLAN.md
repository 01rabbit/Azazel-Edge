# P1 Remaining Issues Execution Plan

## Scope

Open issues:

- #98 Decision Trust Capsule
- #99 Handoff Brief Pack
- #100 Progress Checklist
- #101 Beginner Onboarding

This document is intentionally iterative. It records:

1. the first draft,
2. the critique,
3. the revised plan,
4. the final execution order we will actually implement.

## Shared Constraints

- Do not add large new standalone panels unless there is no other option.
- Reuse existing dashboard blocks first.
- Keep the first view visual; avoid adding reading burden to the top of the screen.
- Beginner support must not depend on experts being present.
- Existing production direction remains:
  - Visual Baseline
  - SOC / NOC Split
  - Client Identity
  - Action Board
  - M.I.O. Assist

## Draft 1

### #98 Decision Trust Capsule

- Add a new dashboard card dedicated to:
  - why_this
  - confidence_source
  - unknowns
  - evidence_count

### #99 Handoff Brief Pack

- Add another dedicated dashboard card with:
  - current posture
  - primary anomaly
  - affected clients
  - actions done / do now / do not do
  - copy and send buttons

### #100 Progress Checklist

- Add a checklist panel for beginner mode:
  - Done
  - Next
  - Blocked
  - persistent state

### #101 Beginner Onboarding

- Add a dismissible overlay that explains three blocks.

## Critique 1

Draft 1 is wrong in three ways.

### 1. It recreates the panel-sprawl problem

The user explicitly pushed back on adding more standalone panels.
If we add one panel each for trust, handoff, and checklist, we regress again.

### 2. #101 is outdated

The original issue references removed panels:

- Normal Assurance
- Primary Anomaly

So the onboarding target is stale and must be rewritten around the current UI.

### 3. It implements outputs before foundations

Handoff and onboarding both need a compact explanation of:

- what we think is happening
- why we think so
- what is still unknown

That is exactly what #98 should solve first.

## Revised Plan

### Execution principle

- #98 becomes the shared trust/explanation layer
- #99 consumes #98 output
- #100 consumes #98 output and current actions
- #101 is redefined to point at the already-existing first-view blocks

### #98 Decision Trust Capsule

Embed it inside the existing Action Board, not as a new panel.

Implementation direction:

- API:
  - `decision_trust_capsule`
    - `beginner_summary`
    - `why_this`
    - `confidence_source`
    - `unknowns`
    - `evidence_count`
    - `tone`
- UI:
  - compact trust block inside `Immediate Action`
  - beginner sees one-line summary first
  - professional sees detail in the existing foldout / decision section

### #99 Handoff Brief Pack

Do not create a large dashboard area.

Implementation direction:

- API:
  - `handoff_brief_pack`
- UI:
  - one export area inside existing Action Board / M.I.O. Assist
  - buttons:
    - copy
    - open ops-comm
    - send mattermost

### #100 Progress Checklist

Use existing beginner-action flow, not a detached project-tracker panel.

Implementation direction:

- API/state:
  - `operator_progress_state`
  - persisted by session
- UI:
  - compact checklist inside Action Board beginner section
  - rows:
    - Done
    - Next
    - Blocked

### #101 Beginner Onboarding

Redefine it around the current first-view.

Implementation direction:

- first-visit banner only
- point to:
  - Visual Baseline
  - SOC / NOC Split
  - Client Identity
- dismiss via localStorage

## Critique 2

Revised plan is close, but still has two risks.

### 1. #99 and #100 still risk duplication

If both issues invent their own summaries, they will drift from #98.

Rule:

- #98 owns explanation truth
- #99 and #100 must consume it, not recreate it

### 2. #101 should be last

Onboarding must explain the final UI, not a moving target.
If implemented too early, it will instantly go stale.

## Final Plan

### Phase A: Explanation foundation

Target issue:

- #98

Deliverables:

- trust capsule in API
- embedded trust block in Action Board
- stale/missing/low-confidence unknowns
- beginner/professional density split

Why first:

- this becomes the source for later handoff and checklist wording

### Phase B: Handoff

Target issue:

- #99

Deliverables:

- one-click handoff pack
- copy / ops-comm / mattermost actions
- timestamps and stale flags

Dependency:

- consumes #98 trust capsule fields

### Phase C: Progress

Target issue:

- #100

Deliverables:

- persisted beginner checklist state
- Done / Next / Blocked
- state restore on refresh

Dependency:

- reuses current action recommendations and #98 trust context

### Phase D: Onboarding

Target issue:

- #101

Deliverables:

- first-visit onboarding banner
- current three-block guidance
- dismiss persistence

Dependency:

- must be implemented after UI is stable enough

## Final Closure Criteria

### #98 close criteria

- trust explanation visible without a new standalone panel
- stale or missing inputs shown as unknowns
- beginner and professional density differ

### #99 close criteria

- handoff pack generated in one action
- stale and timestamps included
- copy and send flows work

### #100 close criteria

- checklist persists and restores
- blocked state gives next question / next ask

### #101 close criteria

- onboarding references current UI only
- no removed panel names remain

## Execution Decision

We will implement in this order:

1. #98
2. #99
3. #100
4. #101

This is the final execution plan unless a new architectural contradiction is discovered.
