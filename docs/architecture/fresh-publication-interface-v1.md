# Fresh v2 measurement publication interface

Prospective exact interface before implementation; supplements fresh-source-observe-v2.
No original Source/journal/witness behavior or legacy recorder default changes.

Publication file canonical JSON+LF rows, maximum4096 rows/1MiB. Envelope exact:
`schema_version,seq,prev,kind,data`; schema `edge-observer-publication/v1`, seq starts1,
prev zero64 then SHA256(full previous canonical row including LF).

Header data exact `metadata,identity,limits`; metadata and main identity are exactly
those in fresh config/context. Limits exact `queue_rows=1156,queue_bytes=8388608,
stream_rows={calls:900,input_calls:256},stream_bytes={calls:4194304,input_calls:4194304},
publication_rows=4096,publication_bytes=1048576,batch_bytes=65536,batch_ns=100000000,
close_ns=5000000000`.

Commit data exact `stream,first_seq,last_seq,rows,bytes,sha256,object,worker_native_tid,
write,fsync`. Stream calls/input_calls. first_seq is first row in THIS batch;
last_seq is cumulative last row, calls zero-based/input_calls one-based. rows is
cumulative stream rows. bytes/sha256 cumulative stream prefix INCLUDING LF. object
exact `device,inode,owner_uid,mode,link_count` from actual worker-owned descriptor;
mode full st_mode. write/fsync each exact `start_ns,end_ns,process_cpu_start_ns,
process_cpu_end_ns,thread_cpu_start_ns,thread_cpu_end_ns`, measured around actual
operation; CPU timestamps are process/worker thread CPU, not main thread CPU.
All counters integer uint64 excluding booleans; nondecreasing per clock. Commit
exists only after every write and successful fsync for this stream batch. Prefix
SHA hashes only successfully fully written complete rows. No commit on failure.

End data exact `normal_return,complete,incomplete,error,streams,close`; emitted
only after worker closes both stream descriptors. streams exact calls/input_calls,
each `enqueued,written,fsynced`, each watermark exact `rows,last_seq,bytes,sha256`.
Absent zero-row last_seq is null, bytes0/emptySHA; this records genuine empty queue
state, not a missing stream. error null or `{type,message}` (message<=4096).
close clock uses same exact timing shape above; start measured when main requests
close and end when worker drains/closes streams. complete means normal_return,
no sticky error/overflow, all watermark equality, worker successfully closed stream
FDs. Publication end itself is written+fsynced before worker closes publicationFD;
main join must succeed within5s and publication complete must be true for normal
completion. Missing end/join/error means unknown/incomplete, never synthetic end.

Implementation API `Publisher(paths,publication_path,metadata,identity)` validates
fixed two stream paths and starts sole daemon writer. Main producer creates
immutable canonical bytes and `submit(stream,raw,seq)` attempts bounded enqueue
without waiting for file I/O. `call_sink(path,metadata=...)` supplies original call
wrapper adapter; `close(normal_return=bool)` requests quiescence then bounded join,
returns exact `joined,complete,incomplete,error` facts. Startup may wait boundedly
for worker initialization; no original method occurs before initialization.

A failed enqueue/serialization only poisons measurement, never repeats or changes
original collector calls or exceptions. Worker is sole opener/writer/closer for
calls/input_calls/publication descriptors. A stuck worker retains FD ownership;
join timeout cannot close it underneath the thread. No runtime reader/re-read.
Normal completion adds exact `publication` field containing close result and pins
publication sidecar. Explicit new helper main `version=2`; default1 untouched.
V2 dependency composite pin SHA256(helper + NUL + input-recorder + NUL + publication).

Root reads actual publication prefixes under existing observer output custody.
Readiness and pre-kill barriers require valid signed Source/journal/witness plus
commits whose exact measurement prefix bytes contain the original required calls
and input_return; visible/queued/written alone is insufficient. Publication is
pinned helper self-report, not independent kernel or power-loss attestation.
