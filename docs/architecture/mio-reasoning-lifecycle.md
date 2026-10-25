# M.I.O. reasoning lifecycle, supersession, restart and no-model handoff

Status: implemented, advisory-only. Tracking: #385 (parents #363, #365).

This covers what happens to hypotheses and reasoning cycles over time. None of
it is an authority path: nothing here calls the Action Arbiter, enforcement
handlers or AZ-06, adds approval flags, or reads environment bypasses. The
coordinator only decides which advisory result is *current* for a trace.

| Item | Location |
|---|---|
| Hypothesis transition policy, audit entries | `py/azazel_edge/mio/lifecycle.py` (`ALLOWED_HYPOTHESIS_TRANSITIONS`, `apply_hypothesis_update`) |
| Cycle coordinator (trace isolation, supersession, restart) | `py/azazel_edge/mio/lifecycle.py` (`ReasoningCoordinator`) |
| Deterministic no-model handoff | `py/azazel_edge/mio/handoff.py` (`mio.no_model_handoff.v1`) |
| Loop integration | `py/azazel_edge/mio/reasoning.py` (`ReasoningOutcome.hypothesis_audit`, `.handoff`, `stale_check`) |
| Golden fixture | `tests/fixtures/mio/no_model_handoff_v1.json` |
| Acceptance tests | `tests/test_mio_reasoning_lifecycle.py` |

## Hypothesis lifecycle

| From | Allowed to |
|---|---|
| `proposed` | `proposed`, `active`, `strengthened`, `weakened`, `falsified`, `unresolved`, `superseded` (first evidence revision promotes it implicitly) |
| `active`, `strengthened`, `weakened`, `unresolved` | `active`, `strengthened`, `weakened`, `falsified`, `unresolved`, `superseded` |
| `falsified`, `superseded` | themselves only (terminal; cannot be resurrected) |

The model proposes a revision; code validates it, and any violation rejects the
whole update (`VALIDATION_REJECTED`, no partial merge):

- `falsified` needs contradicting evidence refs *and* a falsification condition
  (current or prior). Absence of evidence alone never falsifies.
- A hypothesis the model omits is carried forward unchanged and audited as
  `carried_forward_omitted_by_update`; omission is not falsification.
- A new hypothesis ID introduced by an update must start `proposed`/`active`.
- Evidence refs are still checked by `GroundingValidator` first.

`ReasoningOutcome.hypothesis_audit` keeps every step (initial proposal, each
status change with evidence refs and falsification conditions). When a cycle is
cancelled or superseded, every non-terminal hypothesis gets a `superseded`
entry with the reason. The loop never compacts this list.

## Cycles, trace isolation and material supersession

`ReasoningCoordinator` holds per-trace state behind one lock; cycle IDs are
`<trace_id>:e<epoch>:c<n>`, so working state and audit rows never cross traces.
It has no clock: ordering is by call order, which keeps replays deterministic.

- `begin(frame)` computes `material_frame_digest` (the canonical frame without
  `frame_id`, `created_at`, `freshness_seconds`, `truncated`, `provenance`).
  - Same digest as the in-flight cycle: no new cycle (`deduplicated=True`).
  - Different digest: the in-flight cycle becomes `superseded`, and an accepted
    advisory describing the old situation is retired from `current()`.
- `stale_check(ticket)` / `cancel_check(ticket)` are passed to
  `BoundedReasoningLoop.run`; at the next checkpoint the loop ends with
  `STALE_SUPERSEDED` (`superseded_by_newer_frame`) or `OPERATOR_CANCELLED`.
- `complete(ticket, outcome)` accepts only the current in-flight cycle of the
  current epoch. Anything else — a result that finished after supersession,
  after cancel, or from before a restart — is discarded and audited as
  `stale_result_discarded` with its state, advisory ID and hypotheses (marked
  `superseded`). It is never returned by `current()`.
- In-flight traces are bounded (`max_traces`); excess `begin` raises
  `reasoning_coordinator_backpressure`. The audit log is bounded
  (`max_audit_events`, oldest dropped, count in `audit_dropped`).

## Restart

`snapshot()` is canonical, byte-stable JSON (no outcomes, prompts or raw logs).
`ReasoningCoordinator.restore(snapshot)` starts epoch + 1 and deterministically:

- in-flight cycles become `abandoned_on_restart`;
- accepted cycles become `restored_stale`; `current()` returns nothing until a
  new cycle completes, so a pre-restart advisory is never replayed as current;
- late results for pre-restart tickets are discarded (`unknown_or_pre_restart_cycle`);
- the audit log is kept.

## Deterministic no-model handoff

When a cycle ends in `DEPENDENCY_UNAVAILABLE` (including `model=None`, error
`model_absent`), `ERROR_FALLBACK`, `VALIDATION_REJECTED`, `BUDGET_EXHAUSTED` or
`INSUFFICIENT_EVIDENCE`, `ReasoningOutcome.handoff` carries a
`mio.no_model_handoff.v1` summary built only from the frame, the playbook
(next checks, stop conditions, claim boundaries) and hypotheses that already
passed validation. Wording is fixed templates, not attacker text; there is no
action field. Canonical bytes (sorted keys, no spaces, ASCII) are capped at
8192 bytes with deterministic tail trimming. Identical inputs give identical
bytes; an absent model and an unavailable model give the same handoff.
Cancelled/superseded cycles get no handoff, since their frame is no longer current.

## Not in scope

Live wiring of the coordinator into a running service and any #373 work.
