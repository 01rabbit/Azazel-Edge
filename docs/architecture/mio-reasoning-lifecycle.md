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
| Deterministic no-model handoff | `py/azazel_edge/mio/handoff.py` (`mio.no_model_handoff.v2`) |
| Loop integration | `py/azazel_edge/mio/reasoning.py` (`ReasoningOutcome.hypothesis_audit`, `.handoff`, `stale_check`) |
| Golden fixtures | `tests/fixtures/mio/no_model_handoff_v2.json`, `no_model_handoff_v2_rich.json` |
| Acceptance tests | `tests/test_mio_reasoning_lifecycle.py`, `tests/test_mio_reasoning_lifecycle_385_v2.py` |

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
  current epoch, and only when the whole ticket (cycle ID, trace ID, epoch,
  frame ID, material digest) matches the recorded cycle. The accepted outcome is
  stored under the recorded cycle's trace, never under a trace named by the
  caller. Anything else is discarded and audited as `stale_result_discarded`
  with its state, advisory ID and hypotheses (marked `superseded`), and is never
  returned by `current()`. The reason is a fixed code chosen from the ticket and
  the cycle record only (`STALE_RESULT_REASONS`), never from the outcome:

  | Reason code | When |
  |---|---|
  | `stale_cycle_superseded` | a newer material frame superseded the cycle |
  | `stale_cycle_cancelled` | the operator cancelled the cycle |
  | `stale_cycle_already_completed` | a second result for a cycle that already has one |
  | `stale_pre_restart_cycle` | the ticket's epoch is older than the coordinator's (any number of restarts) |
  | `stale_unknown_or_evicted_cycle` | no recorded cycle has this ID (unknown, evicted, or a future-epoch ticket) |
  | `stale_ticket_mismatch` | the ticket names a recorded cycle but not its trace/frame/epoch/digest, or a field has the wrong type (for example an unhashable ID); `stale_check` is also true for it, and no exception is raised |

  A discard row is written only under a recorded cycle that this exact ticket
  names, and only for the first discard of that cycle. `discards_for(cycle_id)`
  returns the cumulative count for a retained cycle; it is part of the snapshot
  (`discards`, absent in older snapshots and read as 0), so a restored
  coordinator does not write a second row for the same cycle. Discards that cannot be
  tied to a recorded cycle (unknown, evicted, forged or malformed tickets) are
  only counted by reason in `unattributed_discards()`, outside every trace's
  audit and in memory only. A forged ticket therefore cannot write rows into
  another trace's audit or push its rows out of the cap. The cost is that a
  late result for an evicted cycle leaves only that count.
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
- late results for pre-restart tickets are discarded (`stale_pre_restart_cycle`);
- the audit log is kept.

## Deterministic no-model handoff

When a cycle ends in `DEPENDENCY_UNAVAILABLE` (including `model=None`, error
`model_absent`), `ERROR_FALLBACK`, `VALIDATION_REJECTED`, `BUDGET_EXHAUSTED` or
`INSUFFICIENT_EVIDENCE`, `ReasoningOutcome.handoff` carries a
`mio.no_model_handoff.v2` summary.

v2 is built from allowlisted structured fields only; no free text from any
input is copied. Frame facts, unknowns, contradictions, mission, NOC/SOC text,
model statements, assumptions and conditions, and the `reason` argument never
reach the payload (v1 copied redacted frame and model text). The payload holds:

| Field | Source |
|---|---|
| `trace_id`, `frame_id`, `evidence_refs`, hypothesis IDs and their refs | only IDs that fully match a closed shape the repo produces (`HANDOFF_ID_KINDS` over the shared `id_grammar.ID_KINDS`: allowlisted words and bounded digits, for example `trace-1`, `mio-shadow`, `<trace>:frame`, `sha256:<hex>`, `suricata_sid:<n>`, `ev:<kind>:<n>`, `h<n>`; trace counters up to six digits; plus the shared address/secret second layer); anything else (addresses, hostnames, hex/decimal address forms, free words, token shapes) becomes a fixed placeholder (`invalid-trace-id`, `invalid-frame-id`, `[redacted:evidence_ref]`, `hypothesis-<n>`) |
| `reason` | a `ReasoningState` value, otherwise `unspecified` |
| `current_defensive_state`, `threat_level`, `dependency_status`, `current_action` | closed vocabularies (`DEFENSIVE_STATES`, `LOW`..`CRITICAL`/`UNKNOWN`, `OPTIONAL_DEPENDENCY_STATUSES`, the v2 action-record vocabularies) |
| `counts` | integer sizes of the frame lists, actors and actions |
| `unknown_markers`, `contradiction_markers` | only the fixed marker codes emitted by the contract and `MioSituationFrameBuilder` (for example `KNOWLEDGE_UNAVAILABLE`, `NOC_DEGRADED_MODE`, `HIGH_SOC_RISK_WITH_FRAGILE_NOC`); caller text is counted, not copied |
| `playbook` | the ID only when it is a `DEFAULT_PLAYBOOKS` key and the version only when it equals that entry's version (else `invalid-playbook-id` / `invalid-version`); the next checks, stop conditions and claim boundaries only when the playbook equals its built-in `DEFAULT_PLAYBOOKS` entry (code constants), otherwise `guidance_source: omitted_not_builtin` and empty lists |
| `summary`, `operator_guidance` | fixed templates filled with the values above |

If the model already proposed hypotheses this cycle that passed grounding and
lifecycle checks, they appear under `model_proposed_hypotheses` as ID,
`model_status`, evidence refs and a falsification-condition count, each marked
`verification: model_proposed_unverified`; `model_contribution` becomes
`unverified_hypotheses_only` (otherwise `none`), and the `frame_derived_only`
limitation is used only when no model content is present. Every handoff carries
the `structured_fields_only` limitation. There is no action field.
`flow:<flow_id>` refs are always redacted in the handoff: frame evidence refs
are caller-supplied, so untrusted text can reach them, and a 64-bit flow ID
cannot be told apart from a decimal-encoded MAC or IPv4-mapped IPv6 address.
The handoff has no key for a digest; `counts.evidence_refs` still counts them.
Canonical bytes (sorted keys, no spaces, ASCII) are hard-capped at 8192 bytes:
deterministic trimming marks `handoff_truncated`, and if the cap is still
unreachable the builder raises instead of exceeding it. Identical inputs give
identical bytes, two frames that differ only in free text give the same payload
apart from `frame_digest`, and an absent model and an unavailable model give
the same handoff. Both golden fixtures are compared byte for byte.

Behaviour change: `BoundedReasoningLoop(model=None)` previously failed on the
first model call and ended in `ERROR_FALLBACK`. It now ends in
`DEPENDENCY_UNAVAILABLE` with error `model_absent` and a handoff, the same
class as a blocked/unavailable model.
Cancelled/superseded cycles get no handoff, since their frame is no longer current.

## Not in scope

Live wiring of the coordinator into a running service (how M.I.O. runs
resident is an open owner decision; nothing here adds a unit, service or
installer step) and any #373 work.
Trace identity, working memory, the durable audit projection and retention are
in `mio-reasoning-trace.md` (#389).
