# Frozen notification timing attribution v1 — Edge #400/#393

Base main9675a365. Commit this contract and both protocol/parser-case fixtures
before implementation or workload collection. Environment-only probes precede
this contract and did not run workload. No runtime/default/provider/authority,
installer/security/systemd, service activation or production-key change.

## Question and limits

CI43907632518 observed one123.536682ms legacy interval exceeding50ms. That timer
wrapped fixture JSON read/construction, submit, overflow logging, statistics-lock
wait and scheduler delays. No same-event stage trace was retained. Its cause
remains UNKNOWN permanently in this slice; new experiments never backfill it.
No50ms performance pass is produced. Original5ms/98%/1.2x gates stay unchanged.

The11 cases/order/counts/control/watchdogs and positive/negative parser cases
are frozen in tests/fixtures/notification-timing/v1/. Run all assigned cases
once, retaining failures, incomplete artifacts and no-return calls. Controls
use test-only known intervention (one20ms wait or held existing primitive), not
runtime mitigation or reproduction of the old incident. No favorable retry.
The normal original/instrumented pair is descriptive, not randomized causal
performance/benefit acceptance. Do not subtract the two timings as true cost.

Fixed P0 probes exercise original120 events/six producers/max_pending8 plus
explicitly smaller controls. Original recorded+dropped accounting stays distinct
from the original Source nonalert examination denominator. Reuse UNCHANGED
mandatory Source1.2x nonalert ingress/98%/original sampled5ms CI paths separately.
Do not add another six-arm matrix or claim these P0 probes run concurrently
with that load, establish3000P0/s, or satisfy those old qualification gates.
Any same-run/historical report reference is pinned and labelled nonconcurrent
or historical; absent references stay absent, never replaced by P0 accounting.

## Trust and measurement boundary

Opt-in TEST HARNESS wrappers call original core_event, core_decision_payload,
CoreDecisionRecorder.submit, bounded queue handoff, original error logging,
recorder/audit locks, writer _record, audit save and actual inode-matched fsync.
Every delegated call occurs exactly once with original args/result/exception.
Scoped proxies delegate the SAME existing primitive; do not replace runtime
locks or queue algorithms. Restore after workers join, including failure.
No default module hook or persistent environment/service setting.

Wrapper scopes: fixture_input, legacy_interval, submit, payload, logging_call,
lock_acquire/lock_hold (recorder/audit object identifiers), queue_put,
writer_record, audit_save/audit_fsync, and legacy statistics-lock acquire/hold.
Save is inclusive serialization/write/projection/close, with nested fsync;
its remainder is NOT measured write latency. Logging is inclusive original
logger/handler/capture behavior, not a universal logging profile. Internal
logging/Queue locks not directly instrumented remain explicitly unobserved.
The old interval bracket ends INSIDE its statistics lock as before; standalone
submit has separate endpoints. Never combine those different scopes.

Use monotonic_ns, same-thread thread_time_ns, and process_time_ns with raw
endpoints and declared clock domain/resolutions. Report inclusive durations,
never sum overlapping/nested/thread spans into elapsed wall time. Wall minus
threadCPU, when arithmetically valid, is UNCLASSIFIED residual, not scheduler,
lock or I/O delay. Probe reads/recording locks/buffer handling perturb runs;
keep instrumentation/flush brackets and unknown overhead explicit. Resolution
is not clock accuracy; short CPU time never substitutes for5ms qualification.

Scheduler sampling reads only /proc/self/task/TID/{stat,schedstat} plus existing
/proc/sys/kernel/sched_schedstats. Preserve raw3 counters and read begin/end
brackets. Interpret runtime/runqueue-wait/timeslices only with exact same live
PID/process-start/TID/task-start/boot identity, nonregressing counters and
schedstats marker1 at both ends. Disabled0, denied, malformed, changed identity
or unestablished enablement => qualified runqueue delta null, even if old raw
counters are nonzero. Never enable schedstats, perf/BPF or add capabilities.
Counter brackets enclose operation plus probes; do not allocate their delta to
exclusive nested phases or equate it with all non-CPU time. Enabled raw zero is
only a bounded counter observation, never proof of zero total scheduling delay.
The conditional runnable-contention control runs once ONLY if enablement is
established; otherwise retain explicit unmeasured case, not pytest skip/pass.
Explicit blocking wait is a counterexample to wall-minus-CPU attribution.
Kernel field semantics: https://docs.kernel.org/scheduler/sched-stats.html .

## Separate bounded format and API

Do not change/extend/relabel old PhaseRecording or timing_cost_attribution v1.
New JSONL schema edge-notification-timing/v1 uses canonical JSON+LF hash-chain
rows {schema_version,seq,prev,kind,data}; kinds header,thread,event,intent,span,end.
Strict duplicate/type/uint/finite/field/phase/budget validation, no legacy
implicit conversion. Protocol bounds8192 rows/16MiB/depth16/120 events/16 threads.
Test-only row-loss case uses32 rows. Prefix completed facts survive later bad
rows/footer/missing originals; unavailable fields remain null with reasons.
Hash chains are integrity of supplied bytes, not independent authentication.

Header pins run/case, protocol SHA, source inventory SHA, original fixture SHA,
interpreter identity, PID/start/boot and clock domain. Register actual nativeTID
and task-start before phase use, checking scheduler identity at both samples.
Each span has stable ID/parent/phase/object and exact event index when known.
Bind original event bytes/hash/index to original returned core_event_key/trace_id;
queue/worker uses that exact key to recover context. Ambiguous/missing bindings
remain uncorrelated. No joins based on time proximity. Raised calls retain real
outcome, incomplete intents stay incomplete. Finish only after actual worker
completion; no forced timing endpoints or fabricated no-return success.

Shared interface for implementer/test harness:
- tests/p0_handoff_attribution_recording.py: NotificationRecording(path, *,
  metadata, max_rows=8192, max_bytes=16777216); span(phase, *, event_index=None,
  object_id=None) context manager, call(phase,function,*args,event_index=None,
  object_id=None,**kwargs), event_context(index) context manager,
  bind_event(index,event,key), lookup_event(key), finish().
- py/azazel_edge/benchmark/notification_timing.py:
  analyze_notification_timing(trace_raw, *, expected, event_index_raw,
  original_result_raw) -> deterministic read-only report.
- tests/p0_handoff_attribution_lab.py plus runner/Linux wrapper collect actual
  original counters/audit chain/queue, exact event index and trace independently
  before invoking analyzer. Export fixed public names exclusively, no private
  keys/configs or descriptor-directed file reads. No original overwrite.
The recorder may add optional simple introspection needed by the frozen lab;
record schema details before code if extending this interface is necessary.

## Acceptance and unknowns

Software acceptance requires positive/negative parser cases, original return/
exception preservation under recording failure, all11 actual assigned recipes
retained, exact normal120 accounting/chain checks and control-specific known
interventions. Inline receiver-save negative is SYNTHETIC extra audit write;
record its injected row separately, never count it as an original action.
Logging delay requires actual overflow error call; absent error is unexercised,
not zero logging cost. Held recorder-lock control must be the same real lock;
unrelated-lock negative cannot be scored as recorder-lock delay. Held writer
fsync can coexist with completed receiver submissions, preserving independence.

An ordinary-UID Linux path must EXECUTE under networknone/caps0/NNP/sourceRO;
skipping is not success. Save already verified siblings when one control fails.
Persist all original hashes and evaluator inputs/outputs exclusively. Explicit
missing scheduler evidence can satisfy software missing-handling tests but
NEVER scheduler measurement acceptance. All reports have historical_cause=
UNKNOWN, no safety count, comparison/whole-measurement/admission/resume=false.

Independent review checks code, originals and exact replay; final-head complete
CI and base/head/testmerge/tree equality precede merge, postmerge tree checked.
Update existing #400/#393 with measured scopes/unknowns; keep both OPEN. No new
Issue, no production/physical/Pi/HIL or whole-system latency/safety acceptance.

## Preimplementation wire/control clarification

20ms is a REQUESTED synthetic wait, not an observed exact delay or pure lock/
I/O cost. Store genuine target-callsite attempted/entered, primitive-held,
release and return brackets. Establish same target object/call and a pre-release
attempt; otherwise mark the control unexercised. Such Python wrapper brackets
can include descheduling before the delegated acquire and cannot prove exclusive
kernel mutex waiting. Never infer20ms actual blocking from a requested sleep.

If enabled, runnable control uses exactly one same-UID competitor process with
a100ms requested CPU window and one50ms requested observed-thread CPU-work
window, competitor-ready handshake before observation, no affinity/priority/
policy changes. Retain actual endpoints and counters; no positive runqueue delta
means unexercised positive control, never rerun. Disabled/unavailable enablement
means no competitor workload and an explicit unmeasured case.

NotificationRecording metadata EXACT six pins: run_id,case_id,protocol_sha256,
source_inventory_sha256,fixture_sha256,interpreter_sha256. Header adds pid,
process_start_ticks,boot_id,clock_domain,resolutions and limits. Thread row:
native_tid,task_start_ticks,pid,process_start_ticks,boot_id,thread_name. Event row:
index,event_sha256,core_event_key,trace_id. Intent row: span_id,parent_id,phase,
object_id,event_index,native_tid,task_start_ticks. Span repeats intent and adds
outcome,start_ns,end_ns,thread_cpu_start_ns,thread_cpu_end_ns,
process_cpu_start_ns,process_cpu_end_ns,scheduler_before,scheduler_after.
End: normal_return=true,active_spans=0,incomplete=false, only after genuine joins.
All integers strict nonnegative uints, optional identities/unknowns null with
reasons, outcome returned|raised. Header domain uses existing device/inode/
timens_offsets/established shape. Resolution floats are finite positive seconds.
Scheduler snapshots: read_begin_ns,read_end_ns,pid,process_start_ticks,native_tid,
task_start_ticks,boot_id,schedstats_raw,schedstat_raw,runtime_ns,runqueue_wait_ns,
timeslices,error. Preserve partial raw even when an error invalidates delta.

bind_event(index,event,key) accepts exact key mapping {core_event_key,trace_id};
lookup_event(core_event_key string) returns unique index orNone. Optional simple
introspection: incomplete,rows_written,bytes_written,lost_rows. The bounded
canonical event_index_raw is {schema_version:edge-notification-event-index/v1,
events:[{index,event,event_sha256,core_event_key,trace_id}]}. Original-result
EXACT envelope: schema_version=edge-notification-original-result/v1,case_id,
assigned_events,completed_submissions,metrics,audit_raw,queue_raw,control,
collection_errors. Metrics retain original dictionary verbatim or null/error;
audit_raw/queue_raw retain original UTF8 bytes as strings or null, controls are
explicit test metadata, not qualifications. Public original files remain
separately pinned too. Original audit chain verification uses existing helpers
independently; supplied collector summary is not authentication or safety proof.

Analyzer expected EXACT {header:{six pins,pid,process_start_ticks,boot_id,
clock_domain},event_index_sha256,original_result_sha256}. Collect those bootstrap
pins independently before the tracer; do not infer expected pins from supplied
trace bytes. Source commit/tree live in independently pinned outer manifest;
source inventory identifies exact executable test/runtime source bytes.
Strict known envelopes plus bounded original metrics/control JSON preserve all
material without accepting caller eligibility. Any malformed original/index
causes local descriptive attribution to be withheld while completed trace prefix
facts remain. No supplied counter or accepted boolean grants measurement/safety.

## Harness bracket labels

Input here means fixture construction and direct recorder.submit invocation,
not observed UNIX-socket ingress, Rust reception or application delivery.
When preserving proper parentage around the legacy statistics lock, its traced
hold may be only the held prefix through the original endpoint append. Label
that object/coverage explicitly partial, close its child before legacy_interval
while the same primitive is still held, and retain the genuine eventual release
bracket separately. The remainder is unallocated; never backdate tracer clocks
or report that prefix as the full lock hold. Keep actual original-timer t0/t1/
elapsed in control metadata separately from wider instrumented tracer brackets.

The original durable audit dispatcher has an idle daemon with no stop API.
Retain its actual alive/idle/pending/delivered/handed state; do not fabricate a
join or add runtime termination. Trace finish means measured producer/recorder/
relay workers joined and measured callbacks drained, not complete process-daemon
lifecycle. Shared-process CPU includes any other original/idle-case threads and
is never exclusive per-phase CPU. Whole lifecycle/cost acceptance stays false.

## Same-call control completion

A selected attempted call and its return must share an explicit attempt token
and nativeTID; another producer returning first cannot close that bracket.
For unrelated-lock negative control, hold the unrelated primitive for the
requested minimum20ms AND until that selected same call returns (bounded30s
watchdog). This is a causal no-dependency control, not a20ms response deadline.
A timeout remains unexercised/failure, not a successful zero delay.

Fsync identity-probe failure must still delegate the original fsync once and
preserve its exact return/exception; retain the separate probe error. Partial
setup/cleanup errors retain already captured originals and actual join state,
never fabricate completed workers or delete active-worker evidence. Derived
scheduler positive-control status belongs in new analysis/summary: never rewrite
already closed original-result bytes after observing counter outcomes.
