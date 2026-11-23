# Fresh Source v3 — all measurement publication off the original call path

Prospective freeze BEFORE v3 implementation/acquisition. PR624 v1 trial45085427927
and v2 trial45164558889 remain adverse, unpooled and unchanged. V2's original
sample204 bracket72.395411ms contains actual phase-intent write71.828561ms while
telemetry sample body is0.404128ms: a concrete remaining measurement perturbation.
Separately, required product journal fsync166.471280ms + witness64.756717ms delayed
same-snapshot duplicate2 beyond100ms. V3 removes main measurement I/O, NOT product
durability, and cannot promise to solve that distinct freshness failure.

## Exact unchanged gates and new writer profile

Keep identical v1/v2 input recipe, timestamps, duplicate bytes, Source positions,
SID/order, seed, pacing3000/s, measurement6s/warmup3s/rate tolerance2%, examined98%,
original freshness100ms, poll50ms and whole-call sampled clock5ms. Original calls,
epochs, arguments, results, exceptions, stack clock locations and sample count stay
unchanged. Never retime, fit, backfill, waive a late callback, add privileges or
change Source/journal/witness fsync. No installer/security/systemd/profile grants
or production deployment changes.

Publisher explicit version3 owns FOUR measurement FDs: calls,input_calls,phase,
context, plus publication. Sole worker opens/writes/fsyncs/closes them; main only
serializes immutable bounded rows/enqueues without I/O wait. Same fixed100ms/64KiB
batch and ONE5s main owner_close deadline; CPU clock endpoints stay on their actual
main/worker threads. Stream bounds: calls900rows/4MiB, input_calls256/4MiB,
phase4096/4MiB, context2/16KiB. Queue5254rows/12599296bytes, publication4096rows/1MiB.
No dropping, replacing, replaying, overwriting, adaptive batching or extra calls.
Sticky measurement overflow/failure withholds completion but preserves original
method return/exception identity and verified prefixes. Serialization/GIL/locks
and worker I/O still perturb resources; no realtime or causal-superiority claim.

Explicit helper/config/bootstrap/GO/input/phase/clock/completion versions are/v3;
publication is edge-observer-publication/v2, new four-stream limits/closed enum.
Calls keep the original underlying hash-chain row format. Phase data uses ONLY
previous_enqueue_cost instead of previous_write_cost: actual main-thread six-clock
submit/hash/queue admission cost, excluding earlier JSON serialization. It is not
write/fsync cost. Worker publication reports actual write/fsync intervals separately.
Do not add overlapping parent/child/process/thread spans or subtract worker CPU.
V1/v2 defaults, schemas, parsers, data and adverse evaluations remain supported.

All producer-side stream closes mean quiescent/footer-enqueued, not durable file
closure. Exact order input footer -> calls footer -> context end -> phase footer
then owner close/drain/final stream fsync/worker close/publication fsync+close/join.
Only actual main owner_close end AFTER join within5s may prove whole close. A worker
footer alone, timeout, partial row, failed enqueue or absent END is incomplete.

## Four-stream barriers and read-only proof

Keep exact49 original slots and immutable snapshot/outer disposition from v2,
parameterized by EXPLICIT protocol/profile (no raw-format cast). Root readiness
and interrupt objects add exact phase_checkpoint/context_checkpoint {size,sha256}
in addition to publication_checkpoint and existing fields. Root reads actual
fsynced prefix bytes/object under existing custody, never just visible data.

Before writer start: recovered/protected input_ready, first original sample return,
fsynced calls prefix covering it, fsynced phase prefix with header and completed
observation_sample span inside that exact original sample interval, and fsynced
context-begin prefix. Before unchanged<6s SIGKILL: first original callback and input
handler returned, their fsynced calls/input prefixes, product protected cursor and
witness, fsynced phase prefix with the completed observation_event span inside the
exact selected event-call interval, and context-begin. All selected Root prefix
checkpoints must be covered by valid publication commits observed before writer/
signal. A killed context/phase normal END is never required or manufactured.

Normal completion additionally requires four exact final fsynced watermarks and
genuine stream footers, all immutable original hashes, original clock oracle,
finite input accounting and outer accepted disposition. Worker fsync receipts are
pinned helper reports within Root-observed process/file/clock custody, not independent
hardware/power-loss proof. Later failed leg keeps earlier authenticated facts but
withholds dependent/global qualification. No missing-to-zero conversion.

## Failure, tests and acquisition limits

Keep v2 sealed49 originals/evaluation exclusive and stable; post-seal assertion,
manager reference or observer cleanup error goes ONLY outer disposition. Top-level
errors {stage:run|final-replay,type,message}; pre-seal collection error copied from
actual controller. Valid failed envelope must replay; rejected/not_run remains
withheld. ARM FileExistsError is a distinct setup bug: one fixture owns exclusive
public-root creation shared by diagnostic + capture, while files/subcases remain
exclusive; never accept stale roots, wipe evidence, extend10s probe/60s compile or
change expected syscall numbers/compiler selection.

Before capture synthetic positive/negative tests: block phase/context worker I/O
and verify original main methods run once, no main measurement open/write/fsync;
actual original epochs/clocks unchanged; v3 enqueue vs v2 write cost fields distinct;
all four caps/order/hash, overflow/errors/partial writes, wrong fd/object/seq/hash,
queued/written-not-fsynced phase/context at both barriers, absent/mismatched sample/
event phase span, missing context-begin, incomplete final phase/context, late owner
close and original exception preservation. Strict sealed failed envelope and ARM
single-owned-root integration must pass. Known synthetic keys/data are not actual
kernel/operational-independence proof.

One prospective v3 Linux acquisition after source review, as a different concrete
instrumentation change, never a repeat-until-green v2 trial. Preserve all assignments
and adverse results. If product freshness or5ms still fails, record valid failure;
do not tune TTL/pacing/epochs or weaken product durability to pass. No APPLIED,
whole safety-zero, performance/comparison authority, hardware or production
acceptance is released by this software slice. Final all-CI/ref/tree/raw replay
and independent review remain required for any normal conditional merge.
