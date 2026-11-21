# Finite load cost lab interface, version 1

Prospective lab-only interface for finite-load-cost-v1. This interface is frozen
before its dependent implementation. All objects are exact-key objects unless
explicitly described as existing runtime objects. Unavailable observations are
null; no missing datum is replaced by a planned value or a previous incarnation.
Canonical JSON is sorted compact UTF-8, finite numbers only, plus LF.

## Public files

Each arm retains the original finite-ingress 32-file map unchanged, through the
explicit load-cost runtime profile, plus exactly these thirteen files:
`load-controller.json`, `corpus-manifest.json`, `observer-config.json`,
`observer-policy.json`, `observer-phase.raw`, `observer-calls.raw`,
`observer-context.raw`, `observer-completion.json`, `observer-stdout.raw`,
`observer-stderr.raw`, `observer-journal.raw`, `observer-outcomes.raw`,
`observer-fault-anchors.raw`.
Missing files are null in the evaluator map. The original `journal-after.raw`
remains the final Source-reader journal; `observer-journal.raw` is the observer's
original journal at exit, before that independent readback. No late observer
restart/backfill occurs. OFF has null observer files/config/policy and no actor.
Auxiliary `failure.json` and `evaluation.json` remain diagnostic outputs.
Top-level `corpus-manifest.json` is published exclusively before arm one, then
copied byte-for-byte into each arm. Top-level `comparison.json` is derived only.
Root copies original sidecars after exit; observer-owned files are never
rewritten or repaired. Each copy uses original stable metadata brackets.

## Load controller

`load-controller.json` has exactly:

- `schema_version`: `edge-finite-load-controller/v1`;
- `case_id`: `load-off`, `load-on`, or `load-faulted`;
- `protocol_sha256`, `corpus_sha256`, `session_ref`;
- `started_ns`, `finished_ns`: actual controller monotonic nanoseconds;
- `controller_identity`: existing phase identity object, observed by Root;
- `controller_anchors`: `{before,after}` actual clock anchors;
- `writer`: writer receipt below or null;
- `observer`: observer receipt below or null;
- `resources`: `{native_before,native_after,receiver_before,receiver_after,
  observer_before,observer_after}`; each null or resource snapshot below;
- `audits`: actual independent audit receipt list described below;
- `errors`: bounded list of `{stage,type,message}` (message at most 4096 chars).

A clock anchor is exactly `{monotonic_before_ns,epoch_ns,monotonic_after_ns}`,
all actual nonnegative integer clock readings. Existing phase identity is
`{pid,start_ticks,native_tid,boot_id,clock_domain,clock_ticks_per_second,
clock_resolutions}`. Root obtains start ticks and clock domain from the actual
bound PID while alive; this is explicitly Root provenance. Domain is
`{time_namespace_device,time_namespace_inode,timens_offsets,established}`;
offsets are null or actual lists of `{clock,seconds,nanoseconds}`. Missing proof
sets established false. Resolution fields are actual monotonic/process_time/
thread_time resolutions. The helper supplies its real native TID and resolutions;
Root-supplied PID/start/boot/domain are never described as child self-reads.

## Writer and actual load windows

Writer receipt exact fields:
`{pid,tid,fd,flags,before,after,started_ns,first_write_before_ns,
marker_one_before_ns,final_nonalert_after_ns,finished_ns,joined_ns,
written_bytes,nonalert_records,per_class,write_calls,fsync_completed,joined,
sha256,error}`. Error is null or `{type,message}`. before/after use the existing
full eight-field OBJECT metadata (device,inode,owner_uid,mode,nlink,size,mtime_ns,
ctime_ns); flags are actual F_GETFL. `per_class` exact keys flow/dns/stats/http
and values are counts of actually completed writes. Each complete nonalert row
increments its class only after all its bytes were written. `sha256` is computed
from bytes actually written, never from requested input. Partial/error writes
retain actual prefix counts and bytes and cannot qualify load. fsync and thread
join are actual completions. Each os.write is bounded to one frozen row or its
remaining partial bytes; no catch-up batching hides offered-rate bursts.

Warmup spans actual first_write_before_ns through marker_one_before_ns and
contains the first 9000 nonalert rows. Measurement spans marker_one_before_ns
through final_nonalert_after_ns and contains the remaining 18004 nonalert rows.
The first bracket precedes writing the first byte, marker-one bracket precedes
writing marker one, and final bracket follows writing the final nonalert byte.
Minimum durations are respectively 3 and 6 seconds; overall duration exceeds
9 seconds. Actual whole and measurement per-class rates must meet 2% tolerance;
measurement class counts are derived from the actual written fixed raw prefix,
not by subtracting planned runtime counters. Native examined counters retain
the whole lifetime denominator. Deadlines are fixed from writer start at
3000 nonalerts/sec; no favorable-readiness delay, retries or dropped schedules.

## Observer receipt and bootstrap

Observer receipt exact fields:
`{unit,challenge,bootstrap,unit_properties,actor,identity,command_verified,
started_ns,ready_ns,stop_requested_ns,signal,signal_target,finished_ns,
runner_returncode,exit,stdout_bytes,stderr_bytes,stdout_truncated,
stderr_truncated,sidecars,error}`.

unit/challenge are fresh fixed lab names and 32-lowercase-hex nonces. Bootstrap
is null or `{schema_version,pid,challenge,invocation_id,actor,native_tid,
clock_resolutions}` with schema `edge-finite-load-observer-bootstrap/v1`.
Actor is the existing full native-accounting actor shape. Root verifies actual
transient MainPID/InvocationID, fixed command line and actor UID61002,
edge400-observer enforcing, no capabilities, NNP, existing groups. The child's
status must agree, except an unavailable self start tick is null. Root then
sends one bounded canonical JSON GO message exactly
`{schema_version,challenge,identity}`, schema `edge-finite-load-observer-go/v1`.
The helper checks actual own PID/TID/boot/status against the bound identity;
it does not attempt forbidden /proc/self/stat or time-namespace reads.

`unit_properties` is null or actual string-valued systemd MainPID/InvocationID
properties observed at bootstrap. `exit` is null or actual string-valued
ExecMainPID/ExecMainCode/ExecMainStatus/Result properties observed after wait,
not the systemd-run wrapper code. `signal_target` is null or actual actor
re-observation immediately before the signal; start tick must still match.
Signal is null, SIGTERM(15) for ON, SIGKILL(9) for FAULTED. Output raw retains
actual bytes up to 65536 each, with original byte counts and truncation flags.
Truncation or read failure is explicit error, never silent success.
`sidecars` maps the six original observer outputs (phase,calls,context,
completion,journal,outcomes) to null or `{before,after,sha256,size}` full stable
OBJECT brackets. Process resource snapshot is exactly
`{pid,start_ticks,observed_ns,stat,io,error}`; stat/io are actual original bounded
/proc raw text or null, error null or `{type,message}`. No RUSAGE_CHILDREN service
inference. Missing final /proc after exit remains null, not a prior sample.

ON: stop only after all three authenticated Source markers and actual journal
cursor progress; real cooperative stop result, closed API resources, real clock
end and process exit zero are independently checked. FAULTED: SIGKILL after
first actual Source marker and durable observer cursor/witness progress, before
second marker's fixed deadline. Missing readiness is adverse; never move corpus
deadlines. All native markers/End/witness/readback remain collected after the
observer's exit. OFF has no observer process. No Source history resets occur.

## Explicit v4 helper config and recordings

Config exact fields: `{schema_version,case_id,protocol_sha256,corpus_sha256,
registration_sha256,trust_sha256,helper_sha256,paths,metadata}`; schema
`edge-finite-load-observer-config/v1`. paths is exactly
`{registration,trust,policy,phase,calls,context,completion,journal,outcomes}`,
absolute fixed trusted lab paths. Metadata uses existing seven phase fields
run_id,arm,role,input_sha256,code_sha256,core_sha256,interpreter_sha256; arm is
load-on or load-faulted, role observer. Root-owned0444 config and trusted helper
code are pinned before invocation; aliases cannot target other evidence.
Original v3 loaders/profile refusals remain untouched.

Existing phase, call, clock-context and normal-stop-completion formats and bounds
remain unchanged. A dedicated phase initializer accepts only the new arm names;
no old-arm alias is emitted. A dedicated identity context binds Root-observed
identity to actual current process/TID without child self-stat. Existing real
clock anchors, original record_collector callbacks, original captured control
stop validation and completion publication are reused. New test entry points
alone select this profile. Root-bound identity is compared with independently
retained controller evidence by the new evaluator. An interrupted process gains
no end/footer/completion. Absence of fresh observe_event/APPLIED is explicit,
and absent phase costs are null. Existing unchanged 5ms clock qualifier alone
judges complete real brackets after genuine ON resource closure.

## Independent post-window audit and initial journal context

OFF means no measured observer during the offered load interval, not absence of
independent audit actors for the lifetime of the lab. Initial journal creation,
minimal handoff recovery and post-window SourceEnd witnessing use a fixed audit
entry of the same existing observer role. From the first journal creation these
new-flavor actors use the unchanged existing fixture
`tests/fixtures/signed_network_observer_policy.json` (its actual physical path as
policy source_ref), interface `lo`, sample interval 0.05 seconds. The measured
observer uses exactly that same context. The initial journal is never replaced,
reset or rewritten to accept another context. Original legacy g.observer paths
remain unchanged outside this explicit flavor.

Each audit receipt has exactly `{stage,unit,actor,started_ns,finished_ns,exit,error}`;
stage is `warmup_before` or `post_window`. Actor and exit have the same Root-bound
shapes described above. The audit uses the same bootstrap/RootGO identity binding,
then only opens authenticated BoundedInput/ObservationJournal and calls original
recover_input, closing both before return. It does not emit measured phase/call/
clock/completion sidecars. Audit actors may advance the original durable cursor
and witness SourceEnd only after measured observer-journal.raw and all other
measured originals are copied, after the native load interval and native stop.
The final independent read-only Source collector remains a separate actor.
Audits cannot upgrade original measured ON/KILL callback or clock evidence.

The governing corpus protocol pin is
`9764ea4b3d907f63d53f3526cfeef9f91895af6d8a0de44cc10236f636f8beec`.

## Observer unit metadata retention

A separate same-connection existing libsystemd client references only fresh
`edge400-load-observer-<32lowerhex>.service` units. After actual bootstrap binding,
Root calls RefUnit once before GO; after actual wait, exit metadata and original
sidecar/output preservation it calls UnrefUnit once and closes that connection.
No observer ResetFailedUnit, LoadUnit, restart policy or permission change is
introduced. On failure, preserve available originals before release; API cleanup
errors remain strict, bounded diagnostics without replacing the primary failure.

## Bounded drains, interrupted prefixes and fault boundary

Observer receipt additionally has exactly `stdout_eof`, `stderr_eof`,
`drain_errors`, `fault_boundary`. Concurrent private-pipe drains start immediately
on process creation, count every received byte and retain only the original first
65536 bytes per stream. They keep draining after capacity, recording truncation.
EOF is an actual read result. Drain errors are bounded `{stream,type,message}`
records. A timeout preserves prefix/count/EOF/error observations before owned-unit
cleanup; cleanup never replaces the primary error or precedes available original
preservation. Missing EOF, truncation or a drain error cannot qualify completion.

FAULTED retains the original pre-signal witness bytes in
`observer-fault-anchors.raw`, bounded to the unchanged witness 8MiB cap. ON/OFF
have null for this file. `fault_boundary` is null except FAULTED, where it is
exactly `{observed_ns,source_checkpoint,cursor_position,journal_checkpoint,
witness_sha256,witness_boundary}`. source_checkpoint is the actual authenticated
first-marker Source prefix `{seq,head,size,sha256}`. cursor_position is the actual
durable `{offset,sha256}`. journal_checkpoint is `{size,sha256}` over the actual
complete pre-signal journal prefix. witness_boundary uses the existing native
accounting witness boundary shape. Verify journal prefix against the original
post-kill measured journal, witness signatures/chain against original public
trust and its actual Source prefix, marker SID/session/span and first-cursor
coverage. The marker must precede the second planned marker: boundary observed
and actual signal request precede writer.first_write_before_ns+6000000000.
An expected SIGKILL alone does not verify this fault leg.

The observer verifier returns `{status,normal_completion,fault_verified,clock,
phase,error}`. OFF status absent has null normal/fault/clock/phase. FAULTED remains
clock withheld even when fault_verified true. ON collection acceptance requires
normal_completion true and unchanged qualify_clock status qualified. Any actual
5ms failure is an adverse failed trial with all originals retained; never retry
or accept unknown as qualification. Expected fault acceptance separately requires
fault_verified true. This does not confer broad comparison or safety authority.

Phase decoding retains independently verified complete original prefix rows and
an explicit original partial tail, never repairs the tail or invents a footer.
A partial-mode recording is complete only with a valid terminal clean footer,
normal_return true, incomplete false, and no unfinished spans. Missing/partial/
invalid footer withholds completion while retaining earlier valid phase facts.
Collector per-file caps: EVE16MiB/total64MiB, Source and witness8MiB, clock calls
and phase4MiB, clock context16KiB, observer stdout/stderr/completion64KiB,
load-controller/config128KiB, Root custody32768B (existing Root raw envelope),
native/receiver raw4096B. Existing other public originals retain their original
8MiB bound. No blanket cap silently expands a frozen recording limit.
