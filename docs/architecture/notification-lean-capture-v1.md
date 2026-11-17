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
