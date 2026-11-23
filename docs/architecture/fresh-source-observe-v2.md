# Fresh Source v2: bounded measurement publication and immutable failure disposition

Prospective freeze, before v2 implementation or acquisition. Tracks #400/#393
and fixes PR #624's measurement perturbation and post-export failure-envelope
limitations. Preserve v1 protocol, original trial45085427927, raw files, evaluations,
and adverse result. This is a distinct instrumentation profile and collection,
not a favorable retry or a causal attribution that repairs v1.

## Unchanged conditions and authority

The v1 input recipe, SID/order/timestamp rules, duplicate bytes/positions, seed,
3000 nonalert/s pacing, 3s warmup/6s measurement, 2% rate tolerance, 98% actual
examined floor, 100ms original intake freshness, 50ms minimum poll and 5ms sampled
clock oracle remain exact. Product Source/journal/witness append/fsync and guard
logic remain untouched. Never substitute a later epoch or shift timestamps.
No permissions, production keys, production activation, installer/security/systemd
or confinement grants change. Observer remains read-only toward targets. Existing
phase/context synchronous writes remain disclosed residual measurement cost.

## Measurement-only publication change

A single bounded background writer handles ONLY calls and input_calls measurement
streams under the existing observer output grant. Main thread constructs immutable
canonical rows, assigns seq/hash in original order, and attempts bounded enqueue;
it does not wait for writes, batching or fsync during original calls. Fixed queue
limits are1156 rows/8MiB, with each stream retaining v1 row/byte limits (calls900/
4MiB, input_calls256/4MiB). Overflow/error is sticky incomplete: never drop,
overwrite, repair, replay original calls or invent a clean footer. Queue locking,
GIL, copying and background I/O still cost resources; no hard-real-time claim.

Fixed batching:100ms real-monotonic interval or64KiB pending bytes, whichever comes
first. No outcome-dependent adaptation. Worker writes ordered prefixes and fsyncs
only its measurement descriptors. Stream enqueued, written and fsynced watermarks
are separate. An enqueue return is NOT durability. Publish a bounded canonical
hash-chain observer-publication.raw (edge-observer-publication/v1), with actual
workerTID/clock domain binding, file object, prefix size/hash/last seq and actual
write/fsync wall/process/thread clocks. A committed prefix is reported only AFTER
successful real fsync. Interrupted/partial/error receipts never create success.
A self-report is trusted pinned-helper evidence under observed process/file custody,
not independent kernel/power-loss or hardware proof; product witness stays separate.

Original collector calls, arguments, epochs, results, exceptions and sample count
remain unchanged and occur once. Reuse the original wrappers through an explicit
optional sink factory with legacy default unchanged; never globally replace the
legacy CallRecording binding. The fresh input recorder's optional sink similarly
keeps v1 default behavior. V2 helper/config/context/phase/completion schemas and
code pins explicitly identify v2 and its publication dependency; no v2-to-v1 cast.

Before starting the input writer require original recovered input_ready, original
first sample return, product protected witness, AND a worker-fsynced calls prefix
covering that sample, observed by Root read-only. Before SIGKILL require first
original event+handler returns, their two worker-fsynced measurement prefixes,
product durable cursor+witness and Root snapshots before the unchanged<6s deadline.
A merely visible/written/queued row cannot satisfy either barrier. No retiming,
extra sample/recovery or reading additional input to manufacture readiness.

Normal close quiesces the original API, enqueues its genuine footer once, drains
and performs final measurement fsync, closes worker-owned descriptors and joins
within5s. Record genuine close result only if all stages succeed. If stuck, do not
close an FD underneath its worker, extend the timeout or synthesize END. Preserve
prefixes and incomplete result; process exit/ACK/fsync/witness remain distinct.
Include close/drain and publication intervals in reports; overlapping spans are
not additive. Process CPU includes the worker; main-thread CPU does not. No
causal cost comparison with v1 from this single new trial.

## Immutable outer disposition

Each case has an exact49-slot original map (v1's48 plus observer-publication.raw).
Write available originals and evaluation exclusively once. Then seal a separate
canonical <case>-snapshot.json AFTER evaluation write and BEFORE qualification
assertion. Fields: schema_version=edge-fresh-snapshot/v1,case_id,run_ref,
protocol_sha256,source_revision,files (all49 sha256/null). The evaluation file is
pinned externally; the proof evaluator still ignores its stored verdict/self pin.
Null means actual absence, never zero. Do not append failure.json after sealing.

A separate final disposition.json has exactly schema_version=edge-fresh-run-
disposition/v1,protocol_sha256,source_revision,run_ref,started_ns,finished_ns,cases,
errors. Ordered cases have case_id,state,snapshot_manifest_sha256,
evaluation_sha256,error,cleanup_errors. State is not_run/accepted/rejected/
collection_failed/cleanup_failed. Error null or {type,message<=4096}; cleanup
errors {stage,type,message}. Capture failures before sealing remain typed original
controller/failure evidence. Qualification/Unref/observer cleanup failures after
sealing go ONLY into outer disposition. Never upgrade rejected/cleanup failure.
Missing seal or disposition means incomplete. Stop after a failed case; later
assignment remains explicitly not_run. All actual assigned results are retained.

Strict read-only replay verifies external inventory/disposition/snapshot pins,
every positive file pin and null absence, original evaluation hash, source revision,
and freshly recomputed leaf facts. Outer failure keeps overall trial failed while
valid sealed leaf facts remain reproducible. Never omit failure evidence to pass.

## Fixed positive/negative acceptance data

Preserve legacy v1 tests. New synthetic positives: queued original calls return
once while fake fsync is blocked; two ordered streams fsync before committed
receipt; exact normal close; both sealed real-recipe synthetic cases; post-export
assertion/Unref/observer-close failure keeps49 originals identical and outerFAIL.
Synthetic negatives: queue/row/byte overflow, mutated caller payload, partial/EINTR
write, write-zero/fsync failure, wrong stream/FD/object/prefix/seq/order, forged or
missing ack, written-not-fsynced, footer queued but uncommitted, worker exception,
join timeout, kill before/after watermark, corrupt/missing snapshot/disposition,
extra post-seal failure.json, missing case, mismatched error/state and source pins.
Known test keys and synthetic faults are not actual Linux/key-independence proof.

One prospective actual Linux v2 acquisition only after targeted/regression tests
and independent source review. Same two cases/order. Require both original-call
facts, unchanged full clock/load/intake gates, exact durable barriers and immutable
final replay, genuine cleanup and final-head whole CI. Required Linux failures or
skips fail the gate. If a legitimate adverse result remains, preserve it, do not
rerun unchanged or tune the recipe/thresholds. APPLIED/safety-zero/comparison,
physical endurance, production and whole-system safety remain unaccepted.
