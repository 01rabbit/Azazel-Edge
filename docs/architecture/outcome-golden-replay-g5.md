# Outcome-as-Evidence G5 — end-to-end golden replay

Status: implemented (recorded/synthetic fixture; not Pi/HIL evidence)
Tracking: #400, roadmap #408

## Purpose

G5 proves that the already-merged evidence path can be replayed deterministically, end to end, without any live mutation:

```text
Decision -> Execution -> Mechanism -> Release -> Outcome -> Effect
```

and that one execution's Outcome is identified and counted once across a process restart.

## What is replayed

`py/azazel_edge/outcome/golden_replay.py::run_golden_replay(fixture)` reads a recorded timeline (`outcome-golden-replay-input/v1`) and returns a transcript (`outcome-golden-replay-result/v1`). A fixture is data only:

| Step | Recorded input | Code path exercised |
|---|---|---|
| `event` (Rust event engine) | `normalized` / `defense` / `enforcement` record | `from_rust_event()` (Decision, Execution, Mechanism) and `OutcomeTelemetryCollector.observe_event()` |
| `probe` | recorded read-only `tc -j` / `nft -j` readback | G1a/G1b `verify_mechanism_postcondition()` through `RecordedProbeRunner` |
| `event` (release engine) | `rust_release_engine_v1` record | `from_rust_release_event()` + `reconcile_release_evidence()`; window truncation in the collector |
| `sample` | recorded procfs telemetry values | `OutcomeTelemetryCollector.record_sample()` through `RecordedTelemetrySource` |
| `finalize` | replay time | `OutcomeTelemetryCollector.finalize_due()` -> `OutcomeIdentityLedger.admit()` -> `assess_tactical_effect()` |

`boots` split the timeline into process lifetimes. At a boot boundary the collector (and its in-memory seen-execution guard and pending windows) is discarded, exactly as a real restart would; only the Outcome identity ledger state survives, carried through a JSON round trip.

The Decision stage is the recorded Rust `decide_defense()` result. Replay never re-decides; it does not call the Python `ActionArbiter`.

## Golden fixture

```text
tests/fixtures/outcome/g5_golden_replay_input_v1.json      recorded input
tests/fixtures/outcome/g5_golden_replay_expected_v1.json   golden transcript
tests/test_outcome_golden_replay_g5.py                     stage-by-stage comparison and boundary tests
```

The input is a synthetic recording built from the shapes the G1a/G1b/G3 tests already pin. It covers:

1. **throttle** — applied; mechanism `unverified` -> recorded tc readback `observed` (owned handle) -> verified owned release -> Outcome window truncated by release (`owned_mechanism_released`) -> `DELAY` assessment `inconclusive` (`outcome_inconclusive`, `confidence=null`);
2. **isolate** — provider failure; execution `failed`, mechanism `not_observed`, no Outcome, no Effect;
3. **redirect** — applied and observed in boot 1; the process restarts before its post window ends, so the pending observation is lost and reported in `restart_gaps` (never reconstructed); its verified owned release arrives in boot 2 and is still reconciled to the boot-1 execution;
4. **re-delivery after restart** — the throttle record is delivered again in boot 2. A fresh collector observes it and produces a second OutcomeRecord with a different `outcome_id` (the G3 id depends on collector receipt time). The identity ledger suppresses it; the Outcome is counted once.

The test compares every stage of every decision (`decision`, `correlation`, `execution`, `mechanism`, `mechanism_postcondition`, `release`, `execution_final`, `mechanism_final`, `objective`, `outcome`, `outcome_identity_key`, `effect`) and the replay-level records (`outcome_admissions`, `outcome_ledger`, `restart_gaps`, `rejected_inputs`, `summary`) with the golden file, and also asserts the #400 semantics directly so a regenerated golden cannot silently accept a success or causal claim.

Changing replay output requires regenerating the expected file deliberately and reviewing the diff; there is no environment-variable update switch.

## Determinism

Replay time comes only from the recording:

- telemetry samples, release attempts, Outcome `observed_at` and windows are recorded epochs;
- the G1a probe timestamp is pinned with the replay-only `observed_at` argument of `verify_mechanism_postcondition()` (default behaviour, current UTC time, is unchanged);
- the effect assessment id is derived from `outcome_id`/`objective_id`/`tactical_effect` inside the replay transcript.

The same fixture replayed twice produces the identical transcript, and replay does not mutate its input.

## Cross-restart Outcome identity and deduplication

`py/azazel_edge/outcome/outcome_identity.py`:

```text
outcome_identity_key = H(execution_id, objective_id)
```

Both inputs are restart-independent: `execution_id` derives from the Rust trace, `objective_id` from the policy template instantiated for that decision. Collector receipt time does not enter the key.

`OutcomeIdentityLedger` is first-wins and bounded:

| Case | Admission | Counted |
|---|---|---|
| new identity | `admitted` | yes |
| identical record again (e.g. rotated file read twice) | `duplicate_identical` | no |
| same identity, different record (e.g. re-observed after restart) | `duplicate_suppressed` | no; first record retained |
| ledger full | `capacity_exhausted` | no; fail closed, no identity is forgotten |
| same identity claimed by a different decision | rejected (`ValueError`) | no |

Ledger state is a plain mapping (`to_dict` / `from_mapping`); `from_mapping` rejects a wrong schema, an entry whose key does not match its execution/objective, duplicates and oversized state.

The ledger is not wired into the live G3 CLI. The live CLI still avoids historical replay by starting at EOF. Persisting the ledger on the device (path, fsync, growth, wear) is a G6 decision.

## Replay boundary (enforced by tests)

`ReplayLiveBoundaryTests` replaces, for the duration of the replay, each of these with a stub that records the call and fails:

- `subprocess.*`, `os.system` / `popen` / `exec*` / `posix_spawn`, file rename/remove/mkdir, `socket` connect;
- `SubprocessReadOnlyRunner.run` (live tc/nft readback) and `LinuxProcTelemetrySource.sample` (live procfs);
- the live G3 CLI loop and the outcome JSONL writers;
- `LiveExecutionProvider.execute` and `ReplayExecutionProvider.execute`;
- Python `ActionArbiter.decide`, `OpenCanaryRedirectController.apply`, `execute_runbook`;
- control-daemon client paths in `control_plane` (`_socket_request`, `send_action*`, command-file fallback);
- wall clock (`utc_now`, the collector's `time` module) and file writes through `open`.

The replay must produce the golden transcript with zero recorded calls. A negative-control test proves the stubs intercept those entry points. A static test also rejects importing subprocess/socket/os/time/pathlib/io, the arbiter, control plane, redirect controller, runbooks or `azazel_edge_control` from the replay modules.

The Rust enforcement and release engines are not part of the Python process and are never started by the replay; their behaviour enters only as recorded records.

## Authority

G5 adds no decision or enforcement authority, no approval flag, no environment-variable bypass and no live hook. M.I.O. is not involved. `ActionArbiter` and Rust `decide_defense()` behaviour are unchanged. Every Outcome remains `assessment=inconclusive`, `causal_support=inconclusive`; no Effect is `supported`.

## Observed limitation (unchanged)

The G3 collector records the mechanism status known when the Rust record arrived (`unverified` for a disruptive action), so the golden Outcome carries the `mechanism_postcondition_not_observed` confounder even though the G1a probe later observed the owned mechanism. Replay reproduces this faithfully; joining G1a results into G3 confounders would change G3 evidence semantics and is not done here.

## Not solved by G5

- Raspberry Pi/HIL validation, restart cadence, disk growth/wear, CPU/RSS (G6);
- persisting the identity ledger in the live collector (G6);
- long-term release tombstone compaction / trace-id migration (needs an explicitly approved storage migration design);
- authoritative actor/session identity;
- any new tactical-effect rule.
