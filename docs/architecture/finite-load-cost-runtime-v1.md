# Finite load cost runtime interface v1 — implementation freeze

This freezes the runtime interface before dependent implementation. It refines
[finite-load-cost-v1.md](finite-load-cost-v1.md), retaining its authority limits,
existing profiles/permissions and protocol SHA256
`9764ea4b3d907f63d53f3526cfeef9f91895af6d8a0de44cc10236f636f8beec`.

## Exact cost payload

`cost` has exactly `schema_version,complete,invalid_reason,phases`.
`schema_version` is `azazel-edge/phase-cost/v1`; `complete` is an exact bool;
`invalid_reason` is null, `clock_error`, or `counter_overflow`.
`complete=true` requires null reason. A measurement fault sets complete=false
and its first reason permanently; it never changes, retries or suppresses the
original operation. Previously observed aggregates may survive as partial facts,
but no partial recorder establishes final phase totals. Further measurements
stop after a fault. Successful operation exceptions are not fabricated as returns.

Native `phases` has exactly `poll_total,committed_hash,admitted_callback`.
Receiver `phases` has exactly
`receive_wait,frame_validation,source_append,source_sign,source_verify,source_fsync`.
Every slot is null until an actual measured call completes. Null means unmeasured
or unavailable, never count=0. Each nonnull aggregate has exactly
`count,wall_ns,process_cpu_ns,thread_cpu_ns,max_wall_ns`, all exact integers in
`0 <= n < 2**63`, with count>=1 and max_wall_ns<=wall_ns. Arithmetic never wraps.
No timestamps, per-event correspondence, percentiles or scheduler-wait values
are inferred from these aggregates.

Read monotonic wall before process/thread CPU at entry; read thread/process CPU
before monotonic wall at exit. Clock failures or decreasing values invalidate
recording. Process CPU may include concurrent threads. Native poll_total includes
committed hashing and admitted callbacks; receiver source_append includes sign,
verification and fsync. Inclusive/nested/overlapping aggregates are not summed.
Publication overhead, writer-close duration and absent phases remain unmeasured.

Native phases measure existing poll attempts, committed-byte hash updates and
actual admitted parseable callback invocations. Non-alert normalization rejection
still consumes a callback; it is not a Source decision. Receiver source_verify
measures its actual SourceVerifier calls, including initial history verification.
No callback, input read, fsync, path grant, sidecar or hotpath lock is added.

## Opt-in receipts and strict analysis profile

`AZAZEL_LIVE_ORIGIN_LOAD_COST=v1` requires accounting, close receipts and ingress
accounting v1 plus the existing native registration v4. Absent this flag, default
runtime and older v1/v2 receipt/evaluation field sets remain unchanged.

Native `outcome-native-close-receipt/v3` has exactly the v2 fields plus `cost`:
`schema_version,session_ref,native_pid,local_worker_ack_observed,ingress,cost`.
Receiver `outcome-live-receiver-close-receipt/v2` has exactly its v1 fields plus
`cost`. Root `outcome-live-close-custody/v3` has exactly its v2 field set, with the
new schema identifier. Receiver reporting still follows clean EOF, terminal
append/fsync and successful writer context close. A missing receipt is unknown;
local worker acknowledgement is not a receiver or storage acknowledgement.

Bounds remain native4096 bytes, receiver report3072 bytes (stream4096 including
actual readiness), Root16384 bytes. Each child publication uses its existing
single nonblocking pipe write; failures cannot affect defense/receiver results.
A conservative canonical JSON+LF sizing exemplar using 19-digit values in every
integer slot, full hashes/references and longest enum strings is <=2271 bytes
for native and <=1892 bytes for receiver. This deliberately allows mutually
incompatible maxima as a size bound, not an acceptance fixture. Cost payloads
alone are <=661 native /1207 receiver bytes. No truncation or reduced evidence
is permitted to fit a receipt.

The internal close verifier selects this interface only with explicit profile
`load_cost=True,protocol_schema=edge-finite-load-cost-protocol/v1`, together
with that protocol's SHA and fixed cases. It requires the registered flag and
all exact new receipt schemas. Only this profile returns separately validated
`native_cost,receiver_cost` and uses `edge-native-close-analysis/v3`.
Older public analysis outputs remain unchanged and reject the new receipt
versions. Root's cost evaluator separately judges completeness and cost meaning;
structural receipt validation cannot authorize performance or comparison.
