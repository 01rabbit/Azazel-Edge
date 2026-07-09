# Azazel-Common: Migration Plan

Status: **Design proposal only. No repository has been created and no
existing repository has been modified as part of this task.**

## Guiding constraint

Every phase below is additive and reversible. No phase requires deleting
or rewriting a working code path in Edge, Gadget, or CTI. No phase moves
Edge's Deterministic Arbiter, Edge's NOC/SOC Evaluators, CTI's Correlation
Engine, or Gadget's Wi-Fi/USB control. No phase before Phase 2 touches an
existing repository at all. BHUSA 2026 demo stability takes priority over
migration speed at every phase.

## Phase 0 — Design only (this task)

Deliverables: the six documents in `docs/azazel-common/` in this
repository (`architecture.md`, `design-principles.md`, `contracts.md`,
`migration-plan.md`, `repository-layout.md`, `issue-breakdown.md`). No
code, no new repository, no dependency changes.

Exit condition: design reviewed and approved by the repository owner.

## Phase 1 — Create `Azazel-Common`, schema-only

Create the `01rabbit/Azazel-Common` repository per `repository-layout.md`.
First release is `v0.1.0` and contains **only**:

- `azazel_common.schema` (`StateSnapshot`, `ModeState`, `ActionIntent`,
  `EvidenceRef`, `DecisionExplanation`, `AuditEvent`, `TrustCapsule`)
- `azazel_common.cti_contracts` (`CtiEventBatch`, `CtiFlowBatch`,
  `CtiReactionBatch`, `CtiContextRequest`, `CtiContextResponse`)
- unit tests validating the schemas construct/(de)serialize correctly
  (no product integration yet)

No execution logic. No path/audit/api/notify helpers yet — those are
Phase 5. This keeps the first release small enough to review completely
and stable enough to tag immediately.

Exit condition: `v0.1.0` tagged. Nothing outside `Azazel-Common` depends on
it yet.

## Phase 2 — Introduce into Azazel-CTI

Azazel-CTI adopts `azazel_common.cti_contracts` for payload *validation*
on `/v1/events`, `/v1/flows`, `/v1/reactions`, `/v1/context`.

Approach: wrap the existing endpoint handlers with validation against the
Common schema, running **alongside** (not replacing) existing validation
until parity is confirmed by contract tests (Issue 4). Existing API
consumers (including current Edge integration) must continue to work
unchanged — this phase is a validation-layer swap, not an API redesign.
`CtiContextResponse.behavioral_cti` omission-when-absent behavior must be
preserved exactly (see `contracts.md` §2).

Exit condition: CTI's four endpoints validate against Common schemas in
CI; no observed behavior change for existing callers; existing CTI test
suite still passes unmodified.

## Phase 3 — Introduce into Azazel-Edge

Edge adopts Common schemas for:

- the payloads it sends to CTI (`CtiEventBatch`/`CtiFlowBatch`/
  `CtiReactionBatch`/`CtiContextRequest`) and how it parses
  `CtiContextResponse`,
- `DecisionExplanation` and `AuditEvent` as the *serialization* shape for
  its existing Decision Explanation and Audit Logger output.

Explicitly out of scope for this phase: Edge's Action Arbiter, NOC/SOC
Evaluator internals, and Evidence Plane logic. Only the boundary — what
gets sent to CTI, and what shape decisions/audit records are serialized
into — changes. The arbiter still decides; Common only standardizes how
that decision is written down and transmitted.

Exit condition: Edge's outbound CTI payloads and audit/decision log output
validate against Common schemas in CI; existing demo flows (including
BHUSA prep) verified unaffected via the project's `/verify` and `/run`
checks before merge.

## Phase 4 — Introduce into Azazel-Gadget

Gadget adopts Common schemas for `StateSnapshot`, `ModeState`,
`ActionIntent`, `AuditEvent`, and notification payloads.

Explicitly out of scope: `wlan0` control, USB gadget control, captive
portal viewer. Gadget's existing path-schema/legacy-migration logic is
reviewed as *input* to `azazel_common.paths` design (Phase 5), not
replaced in this phase.

Exit condition: Gadget's state/mode/audit/notification payloads validate
against Common schemas in CI; Gadget's existing hardware-control code
paths untouched.

## Phase 5 — path / auth / notify helper consolidation

Once Phase 2–4 prove the schema layer is stable in production-adjacent
use, extract the genuinely duplicated helpers:

- `azazel_common.paths` (informed by Gadget's existing path-schema and
  legacy-migration design, generalized — not copied wholesale, since
  Gadget-specific assumptions must not leak into the shared version)
- `azazel_common.api` (token/role/fail-closed helpers)
- `azazel_common.notify` (ntfy/Mattermost/SSE payload helpers)

Each repository adopts these incrementally and only where it removes
actual duplication — not as a mandate to touch code that isn't already
duplicated.

Exit condition: at least one real duplicated implementation removed from
at least two of {Edge, Gadget, CTI} in favor of the Common helper, with
contract tests passing.

## Phase 6 — Future tools

`Azazel-Boot` and any new Azazel-series tool depend on `Azazel-Common`
from their first commit, rather than inventing their own state/audit/CTI
formats. This phase has no exit condition of its own — it's a standing
policy for new repositories going forward.

## Versioning and consumption policy (applies to every phase)

- SemVer. Proposed progression:
  - `v0.1.0` — schema-only / contract-only (Phase 1)
  - `v0.2.0` — audit + path helpers added
  - `v0.3.0` — api auth helper + notify model added
  - `v0.4.0` — CTI contract stabilized against real Edge↔CTI traffic
  - `v1.0.0` — after Edge, Gadget, and CTI each pass their contract test
    suite against Common
- Consumers pin an exact tag via
  `azazel-common @ git+https://github.com/01rabbit/Azazel-Common.git@vX.Y.Z`.
  No submodules, no floating branch dependency.
- Any breaking schema change is a major version bump, ships with a
  migration note in `Azazel-Common`'s own `CHANGELOG.md`, and is adopted
  by consumers on their own schedule — never forced by a Common release
  alone.

## Rollback posture

Because every phase is additive (new validation/serialization layered
alongside existing logic until parity is shown), rolling back any single
phase is a matter of reverting that phase's adapter commit(s) in the
consuming repository — it does not require unwinding schema changes in
`Azazel-Common` itself, and does not touch any other phase.
