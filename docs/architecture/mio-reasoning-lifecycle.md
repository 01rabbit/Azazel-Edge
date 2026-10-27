# M.I.O. reasoning lifecycle, supersession, restart and no-model handoff

Canonical architecture, authority matrix and degradation ladder: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

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

- Round one (the first model reply) and any new ID in an update may only
  enter as `proposed`/`active` (`initial_hypothesis_must_start_proposed`,
  `new_hypothesis_must_start_proposed`).
- `falsified` needs contradicting evidence refs *and* a falsification condition
  (current or prior). Absence of evidence alone never falsifies.
- `strengthened` needs supporting refs; `weakened` needs refuting refs or a
  named `missing_evidence` gap. Cited refs must be in the current context
  (frame refs, knowledge refs, refs returned by this cycle's broker calls).
- A terminal (`falsified`/`superseded`) hypothesis cannot be edited at all,
  not even with the same status (`terminal_hypothesis_modified`). Content
  changes without a status change on a live hypothesis are audited
  (`content_revised`).
- A hypothesis the model omits is carried forward unchanged and audited as
  `carried_forward_omitted_by_update`; omission is not falsification.
- A new hypothesis ID introduced by an update must start `proposed`/`active`.
- Evidence refs are still checked by `GroundingValidator` first.

`ReasoningOutcome.hypothesis_audit` keeps every step (initial proposal, each
status change with evidence refs and falsification conditions). When a cycle is
cancelled or superseded, every non-terminal hypothesis gets a `superseded`
entry (there is no "cancelled" hypothesis status) with a distinct reason:
`cycle_superseded_by_newer_frame` or `cycle_cancelled_by_operator`. The loop
never compacts this list.

## Cycles, trace isolation and material supersession

`ReasoningCoordinator` holds per-trace state behind one lock; cycle IDs are
`<trace_id>:e<epoch>:c<n>` with one global sequence `n` (never reused, even
after eviction), so working state and audit rows never cross traces.
It has no clock: ordering is by call order, which keeps replays deterministic.

- `begin(frame)` computes `material_frame_digest`: the canonical frame without
  `frame_id`, `created_at`, `freshness_seconds`, `provenance`, with the list
  fields sorted (their order is a capping priority, not meaning). In the v2
  `actors`, the per-actor counters `event_count`, `first_seen`, `last_seen`,
  `distinct_target_ports` and `evidence_refs` are also left out
  (`NON_MATERIAL_ACTOR_FIELDS`, see [mio-situation-frame.md](mio-situation-frame.md)).
  The effect is limited: the top-level `evidence_refs` stay material (as in v1)
  and usually change with each new top-severity event, so sustained traffic can
  still supersede the in-flight cycle on every new frame. That is follow-up work. `mission`,
  the NOC/SOC summaries (status and reason codes, no timestamps or counters)
  and `truncated` (it marks lost data) are material. Two builder runs over the
  same events at different times or input order share a digest; a new event
  changes it (tested on real `MioSituationFrameBuilder` output).
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
- Memory is bounded: in-flight cycles by `max_traces` (excess `begin` raises
  `reasoning_coordinator_backpressure`); finished cycles by
  `max_retained_cycles` (oldest evicted with that trace's current advisory,
  audited as `cycle_evicted`); the audit log by `max_audit_events` (oldest
  dropped, counted in `audit_dropped`), and each row's strings/lists are capped.
  A late result for an evicted cycle is discarded like a stale one.

## Restart

`snapshot()` is canonical, byte-stable JSON holding cycle metadata and the
size-bounded audit rows (which include bounded hypothesis summaries of
discarded results); no outcome objects, prompts or raw logs.
`ReasoningCoordinator.restore(snapshot)` validates a closed schema (key sets,
types, non-negative epoch, each cycle's epoch within the snapshot's,
known statuses, unique cycle IDs, `latest` consistency) and raises
`ValueError` on anything malformed. It then starts epoch + 1 and deterministically:

- in-flight cycles become `abandoned_on_restart`;
- accepted cycles become `restored_stale`; `current()` returns nothing until a
  new cycle completes, so a pre-restart advisory is never replayed as current;
- late results for pre-restart tickets are discarded (`unknown_evicted_or_pre_restart_cycle`);
- the audit log is kept.

## Deterministic no-model handoff

When a cycle ends in `DEPENDENCY_UNAVAILABLE` (including `model=None`, error
`model_absent`), `ERROR_FALLBACK`, `VALIDATION_REJECTED`, `BUDGET_EXHAUSTED` or
`INSUFFICIENT_EVIDENCE`, `ReasoningOutcome.handoff` carries a
`mio.no_model_handoff.v1` summary. Its summary, lists and guidance come only
from the frame and the playbook (next checks, stop conditions, claim
boundaries). If the model already proposed hypotheses this cycle that passed
grounding and lifecycle checks, they appear separately under
`model_proposed_hypotheses`, each marked `verification:
model_proposed_unverified` with its `model_status`, and `model_contribution`
becomes `unverified_hypotheses_only` (otherwise `none`); the
`frame_derived_only` limitation is used only when no model content is present.
Wording is fixed templates, not attacker text; there is no action field.
Canonical bytes (sorted keys, no spaces, ASCII) are hard-capped at 8192 bytes:
deterministic trimming marks `handoff_truncated`, and if the cap is still
unreachable the builder raises instead of exceeding it. Identical inputs give
identical bytes; an absent model and an unavailable model give the same handoff.

Behaviour change: `BoundedReasoningLoop(model=None)` previously failed on the
first model call and ended in `ERROR_FALLBACK`. It now ends in
`DEPENDENCY_UNAVAILABLE` with error `model_absent` and a handoff, the same
class as a blocked/unavailable model.
Cancelled/superseded cycles get no handoff, since their frame is no longer current.

## Not in scope

Live wiring of the coordinator into a running service and any #373 work.
Trace identity, working memory, the durable audit projection and retention are
in `mio-reasoning-trace.md` (#389).
