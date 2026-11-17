# Deferred notification capture v1: frozen prospective contract

Frozen before implementation and collection, 2026-11-17. Owner: Edge #400/#393.
Base: a118f6cee3997cdd0d1cb0a0cfa0690349f69248, tree
2b0c69377f99300da018e891fef6c5d9cdb9371a. The original 24-hour deadline is
2026-11-17T13:55:50Z; substantial feature additions stop at 09:55:50Z.

## Question and decision

PR #615 exposed large observer-generated work around original mutex-owned
regions. Its historical 123.536682 ms failure has no same-event trace and stays
UNKNOWN. Its prospective adverse CI result (222.174405 ms maximum, 119/120
intervals over 50 ms) remains published and immutable.

Implement a separately versioned `edge-notification-lean/v1` producer and pure
read-only evaluator. Existing v1 traces and their evaluator are preserved. There
is no implicit conversion, scheduler interpolation or performance admission.
Reduce observer proc reads, canonicalization, hashing and file writes in the
original workload; retain real clock endpoints in bounded per-thread buffers,
and explicitly measure deferred finalization outside quiescent original work.

The minimal capture API is event_context, bind_event, span, call, prepare_thread,
finish and abort. A new opt-in recording factory in the existing lab has exactly
the old default. Only the new runner selects the new producer. The underlying
fixture recipes/IDs and original-result/event-index schemas stay unchanged;
the new study manifest explicitly binds arm, capture profile, original recipe,
protocol hashes, source inventory, process bootstrap and all closed originals.

## Trust and authority

This is same-UID opt-in software diagnostic evidence, not an independent safety
sensor or kernel-authenticated execution witness. Parent Popen PID and bootstrap
identity/source pins must bind each fresh child. UID is ordinary, every capability
set is zero, no-new-privileges is set, and the network is disabled. Source is
read-only in the local virtual Linux environment. No production service, keys,
installer/security/systemd, enforcement, new privileges or original algorithm
changes are authorized. Existing 5 ms, 98% and 1.2-times Source gates stay exactly
unchanged and separate from notification accounting.

Prepare logical threads outside original target-lock ownership. A thread object
token must not collapse recycled native TIDs. Kernel task-start identity may be
recorded only by genuine outside-lock reads; unavailable identity stays null.
An unprepared thread must not perform a proc fallback inside a span. Per-phase
scheduler wait is always null in this profile; outer snapshots are descriptive
only. Wall minus CPU is UNCLASSIFIED. Shared process CPU is not exclusive cost.

During instrumented target-owned spans, observer work is limited to genuine
monotonic/thread/process CPU clocks, context bookkeeping and bounded per-thread
raw scalar slots. No observer proc/file I/O, JSON serialization, hashing, or
recorder-global lock is allowed there. Original audit serialization/write/fsync
under its own lock is retained exactly. Clock calls, Python allocations, GIL and
buffer writes still perturb execution and are not zero-overhead.

The lab wrappers themselves also contain observer work. For the deferred arm,
omit eager FsyncProxy fstat/path inode probes and GlobalSlowFsync shared-control
lock/list diagnostics while audit ownership is active. Retain the same requested
50-ms sleep followed by the captured original fsync exactly once, with a raw
`audit_fsync` span labelled `global.os.fsync.callsite.unclassified_fd`. It proves
only this wrapped global callsite, not the destination inode, pure syscall or
device latency. Original and v1 arms retain their exact existing wrappers. This
declared capture difference is part of the new profile, not an assertion of
exclusive profiler cost or equivalent timing instrumentation. Actual control
installation/restoration and deferred call endpoints remain available.

## Bounds, completion and loss

Maximum 16 logical threads, 120 original events, 8192 exported rows, 16 MiB trace,
64 MiB references, depth 16. Preallocate bounded per-thread slot storage before
work; no unbounded growth, executor references or background flush process.
Capacity refusal and clock/probe failure never alter delegated returns or
exceptions: each original call executes exactly once. No fake clock endpoints,
missing-to-zero, repaired chains or read-ahead input are permitted.

Normal finalization requires actual joined/quiescent instrumented work and no
active spans. Deferred serialization/close has its own genuine clock brackets.
On abort, retain and export already completed buffer facts with no normal END;
unfinished slots remain explicitly incomplete. Unjoined workers keep resources
and stop later assignments; do not export a racing buffer as a complete trace.
Whole-process termination may lose in-memory evidence: mark missing, never
claim durability before flush. Close failure is unknown, never retry a possibly
reused numeric descriptor. Published originals are never overwritten.

Both finish and abort require explicit actual outer quiescence/handover, not
merely an instant with zero active spans. With live workers, neither may read,
copy or serialize any still-worker-owned mutable buffer, including a purported
partial prefix. Keep resources and references alive and halt later assignments.

The new wire uses its own schema in a canonical LF sequence/hash-chain envelope.
Header binds the six underlying fixture/source/run metadata pins and external
process bootstrap, plus new study SHA, capture profile, limits and resolutions.
Thread rows bind separate logical token, native TID and unknown kernel task
start; slot rows bind local span ID/parent/token, event index/object/phase,
genuine nullable start/end clocks and native TIDs, outcome, completion and error.
Deferred event rows bind original index/key/hash. A normal end requires explicit
quiescence, no active slots, and no collection loss. These are new-profile
facts, never old v1 scheduler snapshots or a fabricated kernel task identity.

Closed field sets for this version (unknown keys are rejected):

```text
envelope: schema_version, seq, prev, kind, data
header: run_id, case_id, protocol_sha256, source_inventory_sha256,
        fixture_sha256, interpreter_sha256, pid, process_start_ticks, boot_id,
        clock_domain, study_protocol_sha256, capture_profile, resolutions, limits
thread: logical_thread_token, native_tid, task_start_ticks, thread_name,
        identity_scope
event: index, event_sha256, core_event_key, trace_id
span: span_id, parent_id, logical_thread_token, phase, object_id, event_index,
      start_ns, thread_cpu_start_ns, process_cpu_start_ns, native_tid_start,
      end_ns, thread_cpu_end_ns, process_cpu_end_ns, native_tid_end,
      outcome, complete, error
end: normal_return, active_spans, incomplete, quiescent, flush_start_ns,
     flush_before_end_ns
```

Each of 16 preallocated thread buffers has 480 span slots (7680 total), leaving
room for header/thread/event/end records under the separate 8192-row cap. Span
IDs and parents are local to their logical thread token; output uses reservation
order and validates nesting/clock consistency, not cross-thread chronological
sorting. Thread task_start_ticks is null; identity_scope is
`strong_python_Thread_object_native_tid_not_kernel_incarnation`. Incomplete
endpoints/outcome are null with an explicit error. Original finish begin/end
clocks enclose final serialization and close; footer clocks do not replace them.

## Frozen assignments and interpretation

Three prospective fresh same-authority children, fixed order original, v1,
deferred; no favorable reruns. Each has 120 events, 6 producers, max_pending 8,
the original event recipe and global requested-50-ms-fsync control installed
after readiness and restored before final stop. Record actual logging profile;
historical pytest capture equivalence remains unknown. Underlying fixture IDs
are retained in separate arm directories, never overwritten or merged by time.
Every assignment, failure, stdout/stderr prefix and closed original is retained.

This is descriptive pilot evidence only: no subtraction across unrelated events,
no isolated profiler cost, scientific superiority or 50-ms acceptance claim.
Report original timer samples/over-50-ms observations with complete denominators
or null, exact admission/drop counts, per-phase inclusive nonadditive spans,
unclassified gaps, finalize brackets and explicit incomplete reasons. Partial
valid facts survive a malformed later sibling/row. Exact joins use event hash,
original core key/index, source/protocol/run/child/thread token; never time-nearness.

## Positive/negative acceptance before collection

Synthetic parser/recorder tests are separate from real Linux communication:
normal nested spans; exact return/exception preservation; pre-enrolled worker
and unprepared worker; reused native TID with distinct thread object; CPU/clock
regression/missing endpoint; finite capacity; active-span abort/early finish;
write/short-write/close failure; modified/duplicate/reordered/oversized/deep or
wrong-profile input; original hash/event/run/source mismatch; valid-prefix
retention after later corruption. Guard observer proc/JSON/hash/write/global-lock
paths under target ownership, with a deliberately eager negative rejected.

Real Linux must execute all three frozen assignments without skip-as-pass and
retain all outcomes. Software passes only with original accounting/chains,
exact bindings, required controls and raw replay validated. Slow/adverse timing
does not fail evidence preservation or become performance acceptance. Missing
hardware/APPLIED/comparison authority remains a blocker; do not create it here.
Independent review and full final-head CI plus exact base/head/test-merge/tree
are required before merge; update existing #400/#393, keep both open.

## Pre-correction publication finding

The first three-arm pilot at d0f324f retained all assigned originals but its
Linux assertion failed: per-arm artifact descriptors use a filename relative to
the arm directory, while inventory descriptors use `arm/filename` relative to
the study directory. Comparing the path fields without mapping these bases
incorrectly flagged unchanged files. Preserve that failed report and all bytes.
The correction must explicitly map the enrolled arm prefix, and still require
exact path, byte length and SHA-256 agreement. Validate the same originals
read-only; do not recollect a more favorable pilot or rewrite its analysis.
