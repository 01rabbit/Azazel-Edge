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

`py/azazel_edge/outcome/golden_replay.py::run_golden_replay(fixture)` reads a recorded timeline (`outcome-golden-replay-input/v1`) and returns a transcript (`outcome-golden-replay-result/v2`). A fixture is data only:

| Step | Recorded input | Code path exercised |
|---|---|---|
| `event` (Rust event engine) | `normalized` / `defense` / `enforcement` record | `from_rust_event()` (Decision, Execution, Mechanism) and `OutcomeTelemetryCollector.observe_event()` |
| `probe` | recorded read-only `tc -j` / `nft -j` readback | G1a/G1b `verify_mechanism_postcondition()` through `RecordedProbeRunner` |
| `event` (release engine) | `rust_release_engine_v1` record | `from_rust_release_event()` + `reconcile_release_evidence()`; window truncation in the collector |
| `sample` | recorded procfs telemetry values | `OutcomeTelemetryCollector.record_sample()` through `RecordedTelemetrySource` |
| `finalize` | replay time | `OutcomeTelemetryCollector.finalize_due()` -> `OutcomeIdentityLedger.admit()` -> `assess_tactical_effect()` |

`boots` split the timeline into process lifetimes. At a boot boundary the collector (and its in-memory seen-execution guard and pending windows) is discarded, exactly as a real restart would; the Outcome identity ledger (including lost-window tombstones) survives, carried through a JSON round trip.

The Decision stage is the recorded Rust `decide_defense()` result. Replay never re-decides; it does not call the Python `ActionArbiter`.

## Golden fixture

```text
tests/fixtures/outcome/g5_golden_replay_input_v1.json      recorded input
tests/fixtures/outcome/g5_golden_replay_expected_v2.json   golden transcript
tests/test_outcome_golden_replay_g5.py                     stage-by-stage comparison and boundary tests
```

The input is a synthetic recording built from the shapes the G1a/G1b/G3 tests already pin. It covers:

1. **throttle** — applied; mechanism `unverified` -> recorded tc readback `observed` (owned handle) -> verified owned release -> Outcome window truncated by release (`owned_mechanism_released`) -> `DELAY` assessment `inconclusive` (`outcome_inconclusive`, `confidence=null`);
2. **isolate** — provider failure; execution `failed`, mechanism `not_observed`, no Outcome, no Effect;
3. **redirect** — applied and observed in boot 1; the process restarts before its post window ends, so the pending observation is lost and reported in `restart_gaps`; its verified owned release arrives in boot 2 and is still reconciled to the boot-1 execution;
4. **re-delivery after restart, Outcome already admitted** — the throttle record is delivered again in boot 2. A fresh collector observes it and produces a second OutcomeRecord with a different `outcome_id` (the G3 id depends on collector receipt time). The identity ledger suppresses it; the Outcome is counted once;
5. **re-delivery after restart, window lost** — before dropping collector state,
   pending windows are tombstoned in the ledger. The fresh collector refuses the
   redirect redelivery, opens no new window and emits no Outcome/Effect for it.
   The transcript records `window_lost` and the rejection count. The lost
   pre-restart observation cannot be replaced by later telemetry.

The test compares every stage of every decision (`decision`, `correlation`, `execution`, `mechanism`, `mechanism_postcondition`, `release`, `execution_final`, `mechanism_final`, `objective`, `outcome`, `outcome_identity_key`, `effect`) and the replay-level records (`outcome_admissions`, `outcome_ledger`, `restart_gaps`, `rejected_inputs`, `summary`) with the golden file, and also asserts the #400 semantics directly so a regenerated golden cannot silently accept a success or causal claim.

Changing replay output requires regenerating the expected file deliberately and reviewing the diff; there is no environment-variable update switch.

## Determinism

Replay time comes only from the recording:

- telemetry samples, release attempts, Outcome `observed_at` and windows are recorded epochs;
- the G1a probe timestamp is pinned with the `observed_at` argument of `verify_mechanism_postcondition()`, passed explicitly down to the probe record (default behaviour, current UTC time, is unchanged). A test fixes that no caller under `py/` other than the golden replay (and the ownership wrapper's pass-through) supplies it;
- the effect assessment id is derived from `outcome_id`/`objective_id`/`tactical_effect` inside the replay transcript.

The same fixture replayed twice produces the identical transcript, and replay does not mutate its input.

## Cross-restart Outcome identity and deduplication

`py/azazel_edge/outcome/outcome_identity.py`:

```text
outcome_identity_key = H(execution_id, objective_id)
```

Both inputs are restart-independent: `execution_id` derives from the Rust trace, `objective_id` from the policy template instantiated for that decision. Collector receipt time does not enter the key.

`OutcomeIdentityLedger` is first-wins and bounded. Its v2 state also retains
lost-window identities. A lost window cannot later be counted, even if a caller
bypasses the collector guard and submits a fabricated new Outcome for that
identity. If capacity prevents recording a lost-window identity, the ledger
seals **all new admissions**, preserving duplicates of already retained facts.
A seal survives restoration even under a larger configured capacity.
| Case | Admission | Counted |
|---|---|---|
| new identity | `admitted` | yes |
| identical record again (e.g. rotated file read twice) | `duplicate_identical` | no |
| same identity, different record (e.g. re-observed after restart) | `duplicate_suppressed` | no; first record retained |
| lost window | `window_lost` | no; no replacement window |
| ledger full | `capacity_exhausted` | no; fail closed, no identity is forgotten |
| same identity claimed by a different decision | rejected (`ValueError`) | no |

Ledger state is a plain mapping (`to_dict` / `from_mapping`). `from_mapping` restores under the caller's configured bound: the bound stored in the state is validated (missing, `None` or non-integer is rejected) but never replaces the configured one. It also rejects a wrong schema, an entry whose key does not match its execution/objective, duplicates and state larger than the configured bound.

The checkpoint envelope adds a SHA-256 digest of canonical state. The digest
detects accidental corruption, not malicious rewriting or source truth. Strict
restoration validates counters, tombstones, bounds and identity overlaps; v1
state is refused because it cannot establish lost-window continuity. No
in-place migration that silently clears the ledger is permitted.

`status()` exposes capacity/used/remaining, retained and lost identities,
admission counters and whether new admission is closed. These are offline
read-model values, not new Web API endpoints.

The ledger is not wired into the live G3 CLI. The live CLI still avoids historical replay by starting at EOF. Persisting the ledger on the device (path, fsync, growth, wear) is a G6 decision.

## Replay boundary (enforced by tests)

`ReplayLiveBoundaryTests` replaces, for the duration of the replay, each of these with a stub that records the call and fails:

- `subprocess.*`, `os.system` / `popen` / `exec*` / `posix_spawn`, file rename/remove/mkdir, `socket` connect;
- `SubprocessReadOnlyRunner.run` (live tc/nft readback) and `LinuxProcTelemetrySource.sample` (live procfs);
- the live G3 CLI loop and the outcome JSONL writers;
- `LiveExecutionProvider.execute` and `ReplayExecutionProvider.execute`;
- Python `ActionArbiter.decide`, `OpenCanaryRedirectController.apply`, `execute_runbook`;
- control-daemon client paths in `control_plane` (`_socket_request`, `send_action*`, command-file fallback);
- wall clock (`utc_now`, the collector's `time` module, and `datetime.now`/`utcnow`/`today` in every outcome module the replay uses) and file writes through `open`, `io.open` and `os.open`.

The replay must produce the golden transcript with zero recorded calls. A negative-control test proves the stubs intercept those entry points. A static test also rejects, in the replay modules, importing subprocess/socket/os/time/pathlib/io/importlib/builtins, the arbiter, control plane, redirect controller, runbooks, the observer or `azazel_edge_control` (absolute, relative, or as a name from a package such as `from azazel_edge import control_plane`), and calling `open`/`exec`/`eval`/`__import__`/`getattr`, `os.open`, `importlib.import_module`, `datetime.now`/`utcnow`/`today` or `time.time`/`monotonic`. A negative control runs the same checker over each bypass shape.

The Rust enforcement and release engines are not part of the Python process and are never started by the replay; their behaviour enters only as recorded records.

## Authority

G5 adds no decision or enforcement authority, no approval flag, no environment-variable bypass and no live hook. M.I.O. is not involved. `ActionArbiter` and Rust `decide_defense()` behaviour are unchanged. Every Outcome remains `assessment=inconclusive`, `causal_support=inconclusive`; no Effect is `supported`.

## Limitations and recovery

Retention is the entire declared recording/evaluation scope: no time-based
pruning or automatic replenishment. At capacity, keep the checkpoint and
original input. Reconstruct it from the complete original recording under a
reviewed larger bound, retaining all identities/tombstones. A seal caused by a
lost tombstone cannot be cleared by raising a bound; a complete replay must
reconstruct the missing identity. If evidence is incomplete, leave admissions
closed. A new empty ledger is valid only for a separately identified new
experiment with no prior identities reused.

The replay knows which windows were pending at each recorded boot boundary.
This is not crash-safe persistence for a deployed collector: wiring durable
before-window journaling/fsync, boot recovery and storage budgets into the live
CLI still requires separate implementation/review and G6 evidence. Abrupt
loss without a complete checkpoint must be treated as unknown continuity;
never manufacture post-restart success. The default live observer remains
unchanged and begins at EOF.

No Pi/HIL measurement, comparative defensive benefit, causal claim, automatic
activation or model admission follows from these software tests. Every retained
Outcome and Effect remains inconclusive under the existing contracts.

## Source-to-gate audit (base df4ed2229e457ab80c86630659d78061895aa8ce)

| Gate | Existing source/test | Evidence and remaining owner boundary |
| --- | --- | --- |
| G1a | `postcondition.py`, `ownership.py`; `test_outcome_postcondition_v1.py`, `test_outcome_tc_options_readback.py` | Read-only postcondition code; real device evidence remains G6 |
| G1b | Rust `src/release.rs`, `release_evidence.py`; `test_outcome_release_g1b.py` | Existing owned release authority, not reimplemented here |
| G3 | `telemetry.py`; `test_outcome_telemetry_g3*.py` | Receipt-time windows, procfs/activity observations; no causal support |
| G5 | `golden_replay.py`, `outcome_identity.py`; `test_outcome_golden_replay_g5.py`, `test_outcome_window_recovery.py` | Offline replay rejects lost windows; v2 counters/checkpoint tests, not deployed crash recovery |
| G6 | #400 / #372 | Pi resource/retention/restart measurements outstanding; no hardware evidence in this change |
| Comparative measurements | #393 / Azazel#67 | Independent protected-goal and service-cost collector and experiments remain separate |

This table records software inspection and declared test scope, not a statement
that all historical gates or the full #400 issue are complete.
