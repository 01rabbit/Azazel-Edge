# Roadmap: Auditable Edge SOC/NOC CFP Preparation

> Status: CFP preparation / candidate concept roadmap.
> This document does not represent an accepted Black Hat Arsenal appearance.

Status: planning artifact for a CFP submission draft. This roadmap describes work
toward *submission readiness and demo readiness* for a candidate Arsenal
application. It does not imply that any event has reviewed, accepted, or
scheduled anything. All status labels use the project convention:
Implemented / Prototype / Planned / Conceptual / Unknown.

## Goal

Make the Auditable Edge SOC/NOC concept profile of the single Azazel-Edge core
platform CFP-submission-ready and demo-ready for a future Arsenal
application, with every claim in the submission and demo backed by verifiable
repository state (code, tests, configuration, and recorded outputs). The
emphasis is privacy-sensitive, regulated, auditable, explainable,
local-first operation.

## Scope

- Documentation that records, rather than overstates, current capability.
- Schema documentation and validation for the decision-explanation records.
- A dedicated, privacy-sensitive auditable demo scenario for deterministic replay.
- Read-only operator review tooling for the decision -> explanation -> audit walk.
- Claims-discipline checks that fail on hype and on premature `docs/arsenal/` entries.
- A pre-submission and pre-event rehearsal checklist.

## Non-Goals

- Any new attack capability or attack automation. All work is defensive,
  documentation, auditability, demo, or operations support.
- MEA field-deployment, disaster, shelter, or emergency framing for this
  profile.
- Live network enforcement enabled by default (`AZAZEL_DEFENSE_ENFORCE` stays
  off by default; demo stays dry-run / replay).
- Any claim or implication of legal or regulatory compliance guarantees.
- A repository split, fork, or a long-lived regional branch.
- Moving CFP material into `docs/arsenal/` or otherwise implying acceptance.
- Changes under `installer/`, `security/`, or `systemd/` (human approval required
  per `AGENTS.md`).

## Milestones

| Milestone | Theme | Issues |
|---|---|---|
| M1 | Evidence verification — make the 2026-06-10 field audit repeatable and document the canonical schema | 01, 02 |
| M2 | Traceability gaps — extend rejected-alternatives / release-condition and config-hash / policy-profile coverage across decision-bearing streams | 03, 04 |
| M3 | Review experience — read-only operator review command and reviewer walk-through | 05 |
| M4 | Auditable demo — add the `auditable_edge_socnoc` deterministic replay scenario | 06 |
| M5 | Submission package — finish claims/safety review and docs navigation (both mostly done) | 07, 08 |
| M6 | Discipline and dry run — automated claims-discipline check and the pre-event rehearsal checklist | 09, 10 |

## Issue Breakdown

Per-issue detail lives in `docs/issues/auditable-edge-socnoc/`. This table summarizes
only the issue, the status of the *underlying capability* it builds on, and the
primary issue file.

| Issue | Title | Underlying capability status | File |
|---|---|---|---|
| 01 | Confirm current auditable decision fields | Implemented (fields verified 2026-06-10; issue makes verification repeatable) | `docs/issues/auditable-edge-socnoc/01-confirm-auditable-decision-fields.md` |
| 02 | Normalize decision-explanation JSONL schema | Implemented (v2 writer); trace_id threading is Prototype | `docs/issues/auditable-edge-socnoc/02-normalize-decision-explanation-jsonl.md` |
| 03 | Add rejected alternatives and release conditions where missing | Implemented (main arbiter path); gap in other streams | `docs/issues/auditable-edge-socnoc/03-add-rejected-alternatives-release-conditions.md` |
| 04 | Config hash / policy profile traceability | Implemented (explanation records); Planned (full packaging) | `docs/issues/auditable-edge-socnoc/04-config-hash-policy-profile-traceability.md` |
| 05 | Audit trace viewer / CLI review path | Implemented (web + CLI + TUI surfaces); adds read-only review command | `docs/issues/auditable-edge-socnoc/05-audit-trace-viewer-cli-review-path.md` |
| 06 | Auditable demo scenario `auditable_edge_socnoc` | Planned (scenario does not exist) | `docs/issues/auditable-edge-socnoc/06-europe-demo-auditable-edge-socnoc.md` |
| 07 | CFP draft and paper | Implemented (draft + paper landed in commit ff8ef98); residual review tasks | `docs/issues/auditable-edge-socnoc/07-cfp-draft-and-paper.md` |
| 08 | Docs navigation / README links | Implemented (README + INDEX links landed); residual navigation tasks | `docs/issues/auditable-edge-socnoc/08-docs-navigation-readme-links.md` |
| 09 | Claims-discipline validation | Planned (no automated check yet) | `docs/issues/auditable-edge-socnoc/09-claims-discipline-validation.md` |
| 10 | Arsenal demo dry-run checklist | Planned (rehearsal artifact) | `docs/issues/auditable-edge-socnoc/10-arsenal-demo-dry-run-checklist.md` |

## Implementation Order

Dependency-ordered. Each step states why it precedes the next.

1. **Issue 01** — Lock the field inventory and a repeatable test first. Everything
   downstream relies on knowing exactly which auditable fields exist today.
2. **Issue 02** — Document the canonical v2 schema and its relationship to the
   tactics-engine `DecisionLogger` stream, and make trace_id expectations explicit.
   This frames the traceability work and prevents the schema duality from
   surfacing as a surprise during review.
3. **Issue 03** — With the schemas documented, verify and (where sensible) extend
   rejected-alternatives / release-condition coverage on the non-arbiter streams.
4. **Issue 04** — In the same streams, verify and extend `config_hash` /
   `policy_profile` coverage; advances the Planned reproducibility-packaging item.
5. **Issue 05** — Build the read-only review command on top of the now-verified
   fields and chain, so the reviewer walk is exercising real, consistent data.
6. **Issue 06** — Add the auditable demo scenario, which the review command and the
   documented schema let us showcase end to end.
7. **Issue 09** — Stand up the claims-discipline check before finalizing
   submission text, so the text is validated automatically.
8. **Issues 07 and 08** — Close out the residual CFP / paper review tasks and the
   docs-navigation tasks (the bulk landed in commit ff8ef98); these depend on the
   demo (06) and discipline check (09) being settled.
9. **Issue 10** — The pre-event rehearsal checklist runs last, exercising the
   whole package on target hardware.

## Validation Plan

- **pytest suites to run** (real files in `tests/`):
  - `tests/test_action_arbiter_v1.py`, `tests/test_action_arbiter_v2.py`
  - `tests/test_decision_explanation_v1.py`, `tests/test_decision_explanation_v2.py`
  - `tests/test_audit_logger_v1.py` (includes tamper-detection / chain verification)
  - `tests/test_soc_policy_v1.py`, `tests/test_soc_policy_dry_run_v1.py`
  - `tests/test_config_drift_audit_v1.py`
  - `tests/test_demo_scenario_pack_v1.py` (plus the new scenario assertions from Issue 06)
  - new field-presence test from Issue 01 and schema-validation test from Issue 02
  - new claims-discipline test from Issue 09 (e.g. `tests/test_claims_discipline_v1.py`)
- **Claims-discipline grep set** (must return no matches in `README.md` and `docs/`,
  outside of the explicit "forbidden phrases" lists that name them):
  - `grep -rniE "world'?s first|military[- ]grade|unbreakable|guaranteed protection|autonomous AI defender" README.md docs/`
  - `grep -rni "black hat europe" docs/arsenal/` (must be empty pre-acceptance)
  - `ls docs/arsenal/blackhat-europe-*.md` (must not exist pre-acceptance)
- **Demo replay verification**:
  - `bin/azazel-edge-demo run auditable_edge_socnoc` runs offline and reports
    `execution.mode = deterministic_replay` and `ai_used = false`.
  - The run produces an explanation record carrying the required auditable fields.
  - The hash-chained audit log verifies (`verify_chain` reports no mismatch).

## Demo Readiness Checklist

- [ ] Replay scenario `auditable_edge_socnoc` runs fully offline on Raspberry
      Pi-class hardware.
- [ ] Explanation JSONL field walk-through rehearsed (`selected_action`,
      `rejected_actions` / `why_not_others`, `release_condition`, `policy_profile`,
      `config_hash`, `trace_id`, `evidence_ids`, `operator_wording`).
- [ ] Audit-chain `verify_chain` demonstration rehearsed, including showing a
      modified record breaking the chain.
- [ ] SOC policy dry-run comparison rehearsed (`bin/azazel-soc-policy-dry-run`),
      reporting policy hash and would-be decisions for two profiles.
- [ ] Read-only review command (Issue 05) rehearsed for the decision ->
      explanation -> audit walk.
- [ ] Fallback to replay-only mode confirmed (no live telemetry, no live
      enforcement).
- [ ] Hardware checklist confirmed (device, power, storage, no network dependency,
      pre-loaded models for the optional AI-assist aside).
- [ ] Honest answers prepared for Prototype (trace_id threading, runtime profile
      switching, live enforcement) and Planned items.

## Risks and Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| Schema duality (v2 `DecisionExplainer` vs tactics-engine `DecisionLogger`) confuses reviewers | Medium | Issue 02 documents the canonical schema and explicitly maps or scopes the second stream; the reviewer walk uses only the v2 record. |
| Prototype trace_id threading gap is discovered live | Medium | State it up front as Prototype (Issues 02, 10); the demo correlates within the Python pipeline only and does not claim Rust->Python automatic threading. |
| Submission text over-claims | Medium | Issue 09 adds an automated forbidden-phrase check; Issue 07 requires a claims/safety sign-off before submission. |
| Europe demo scenario work slips | Medium | Scenario (Issue 06) is dependency-isolated and reuses existing deterministic machinery; replay-only fallback to an existing scenario remains available. |
| Premature `docs/arsenal/` entry implies acceptance | Low | Issue 09 fails on any `docs/arsenal/blackhat-europe-*.md` or "Black Hat Europe" reference under `docs/arsenal/`. |
| Live enforcement triggered during demo | Low | `AZAZEL_DEFENSE_ENFORCE` stays off; demo is deterministic replay; checklist (Issue 10) confirms replay-only. |

## Definition of Done

- [ ] Issue 01: field inventory documented and a passing field-presence test exists.
- [ ] Issue 02: canonical v2 schema documented, second stream mapped or scoped,
      schema-validation helper/test added, trace_id expectation recorded (test or
      documented limitation).
- [ ] Issue 03: every decision-bearing stream either carries rejected-alternatives /
      release-condition fields or has a documented reason it does not.
- [ ] Issue 04: every decision-bearing stream either carries `config_hash` and
      `policy_profile` or has a documented reason it does not; reproducibility story
      documented.
- [ ] Issue 05: a read-only review command exists and is documented.
- [ ] Issue 06: `auditable_edge_socnoc` scenario exists, is registered (no existing
      id renamed or removed), runs offline, and is covered by a test.
- [ ] Issue 07: claims/safety sign-off recorded; abstracts fit the submission-form
      limits; final proofread done.
- [ ] Issue 08: roadmap and issues directory registered in `docs/INDEX.md` and the
      concept doc; README kept minimal.
- [ ] Issue 09: claims-discipline check passes and fails appropriately on seeded
      violations.
- [ ] Issue 10: full offline rehearsal completed on target hardware with a passed
      fallback drill.
- [ ] All validation greps return clean; named pytest suites pass.
