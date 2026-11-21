# Native close receipts v1 — implementation freeze

Tracking: Edge #400/#393. Base: `02b036f5787d7733f1cb37d596ad6b69fe70f144`.
Commit this protocol, schema and acceptance matrix before implementation/capture.
This is a new software slice; no old deadline or old evaluation is reinterpreted.

## Separate facts and trust boundary

1. The native finisher receives its own worker's internal acknowledgement after
   complete End frame write and an attempted write-half shutdown. This is NOT a
   receiver acknowledgement. Existing code ignores shutdown's result: neither a
   successful shutdown nor receiver EOF/fsync is inferred from this notification.
2. The receiver verifies clean EOF, appends/fsyncs the signed terminal, and closes
   its writer. A report is emitted only after all three operations return. The
   separate original signed Source and read-only readback remain authoritative
   for the retained bytes; the receiver report alone is not independent proof.
3. Independent protected witness coverage is established only by original signed
   anchors covering the exact selected Source boundary, not by child reports.
4. Actual native and receiver wait results belong to their trusted Root parent.
   Systemd independently records the manager-observed launcher exit. A Source
   End, disappearing PID, or aggregate exit zero cannot substitute for these.

The launcher, operator-installed protected code/interpreter, kernel/systemd and
Root collector remain trusted. Native image hash/0500/unlinked/seals15 and v4
native/capture AppArmor remain required. Known CI keys do not qualify operational
key management. Preserve 5ms/98%/1.2x, offline operation and no backfill. No edits
under installer/, security/, systemd/ or the existing AppArmor profile; no new
capability/account/permission, production unit activation or production keys.

## Registered opt-in and runtime channels

Add optional registered `AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS=v1`, requiring
accounting=v1, v4 registration and EVENT_STDOUT=off. Absence preserves the exact
old profile; empty/unknown values or incompatible settings refuse. Registration
bytes/digest bind the choice; no automatic migration of used scopes. Native
also validates this combination independently. Original Source schemas, counts,
end withholding and all old evaluator meanings remain unchanged.

Only in this profile, replace native stdout=/dev/null with its parent's private
pipe. Native validates fd1 is a FIFO and sets CLOEXEC and NONBLOCK before capture
threads/providers. Emit one canonical JSON+LF, at most1024bytes, with one raw
write after actual finish() return. Never retry/block/lock stdout to publish it;
EAGAIN, short write or missing delivery stays unknown. Stderr is unchanged.
Provider children cannot inherit this stdout capability across exec. This pipe
is not shared with the receiver. No reverse durability ACK protocol is added.

Receiver's existing private stdout retains exact readiness bytes, and at most
one canonical final/refusal JSON+LF. Set CLOEXEC. Final publication is one raw
nonblocking write of at most3072bytes, after writer close; no retry, print/flush
lock or blocking final publication. Publication failure alone does not turn a
successfully completed receiver into exit failure or change defense behavior.
Root retains the actual full
readiness/receipt stream rather than reconstructing it. Bound native1024bytes,
receiver4096bytes, Root custody record16384bytes. Read actual EOF with bounded
waits after actual child exits; leaked writers, timeout, excess, duplicates,
partial records and wrong session/PID never qualify. Reporting failures must
not restart/kill running defense or alter existing aggregate exit decisions.

### Exact runtime schemas

Native `outcome-native-close-receipt/v1`:
`schema_version,session_ref,native_pid,local_worker_ack_observed` (exact bool).
True means only the local notification above; false is not proof End is absent.
No report, including SIGKILL, is null/unknown, never false/zero by default.

Receiver success `outcome-live-receiver-close-receipt/v1`:
`schema_version,session_ref,receiver_pid,launcher_pid,registration_sha256,trust_sha256,source_checkpoint,clean_eof_observed,terminal_append_fsync_completed,source_writer_close_completed`.
All three completed flags must be true, checkpoint is the actual verifier tip.
Emit only after successful writer context exit; failure before/at close emits no
success. Authentic terminal bytes survive a later missing report unchanged.

Receiver direct-launch refusal `outcome-live-receiver-refusal-receipt/v1`:
`schema_version,session_ref,receiver_pid,launcher_pid,registration_sha256,trust_sha256,reason,prior_session_ref,source_checkpoint`.
Only reason `unclean_prior_session`, at the verified unclosed-history branch
before preparation. This is distinct from managed-start refusal below.

Root launcher `outcome-live-close-custody/v1`:
`schema_version,registration_sha256,trust_sha256,session_ref,boot_ref,launcher_pid,core_pid,receiver_pid,core_returncode,receiver_returncode,receiver_wait_timed_out,forwarded_signal,native_stream,receiver_stream,root_stdout`.
Each stream is exactly `{raw_b64,eof,over_limit}`. Null PID/returncode where no
process was spawned/observed. Wait timeout/kill keeps actual raw child returncode
separate from existing aggregate return1; do not replace -SIGKILL with guessed1.
Root reports its own observations/premises, not a derived persisted/completed flag.

### Managed refusal before receiver/native spawn

The actual managed path checks verified unclosed Source in service_switch.ready
BEFORE launch(). Introduce a typed OutcomeJournalError subclass at the SAME
branch with the SAME error text, carrying only already verified public p/r/tip
context. Do not move/skip/reorder the gate, parse generic exception strings or
reread evidence in its handler to guess a cause. service_entry catches this
typed error, emits an opt-in Root receipt, and re-raises for unchanged exit1.

Root managed refusal `outcome-managed-restart-refusal/v1`:
`schema_version,stage,attempted_session_ref,prior_session_ref,source_checkpoint,registration_sha256,trust_sha256,launcher_pid,boot_ref,invocation_id,core_spawn_attempted,receiver_spawn_attempted,root_stdout`.
Stage is `managed_ready_unclosed_history`; attempted session is null (none was
created), both spawn flags false, invocation is actual INVOCATION_ID. This is
not a generic key/profile/image failure classification. A missing report cannot
be upgraded from aggregate failure or absence of surviving processes.

## Independent Root custody and read-only collection

Journal markers/shared inherited stderr cannot authenticate role authorship.
For this disposable test harness only, precreate a fresh random-per-attempt
Root0600/single-link/no-follow file under existing lab BASE/close-custody. Set
the existing lab unit StandardOutput=append:<that file>, StandardError=journal.
No product unit, profile or capability setting changes. Native/receiver private
stdout pipes replace fd1; stderr remains on a distinct diagnostic journal sink.

Root observes actual current unit InvocationID/MainPID, protected fixed ExecStart
(typed manager command data), configured stdout/stderr, launcher fd1 matching
the pinned file and full child fd inventories. Child fd1 are distinct pipes;
no native/receiver FD may reference the Root output inode; fd2 must be distinct.
Validate existing native AppArmor/capture DAC denial of the Root file without
granting access. Root collects stable bounded raw file bytes only after this
same invocation exits, before another attempt; record metadata and O_RDONLY
readback. Archive journal bytes only as diagnostics, never as role authority.

Short-lived managed refusals may lack live fd/actor samples. Explicit alternate
custody premise is actual systemd ExecMainPID+InvocationID+fixed protected
service_entry ExecStart/code pins+fresh per-attempt Root sink setup and stable
after-exit readback. Require the Root refusal PID/invocation match those facts;
retain absent live samples as null, not invented observed identities. For live
close cases all original live actor/fd/image observations remain mandatory.

For actual restart refusal, retain before/after original Source, anchors and
observation journal bytes/hashes/object identities; record the actual attempted
invocation and typed pre-spawn reason. Require exact nonmutation. Do not initialize,
reset, recreate, replace keys or repair histories to obtain another test case.

## Public controller interface

`edge-native-close-controller/v1` exact top fields:
`schema_version,case_id,protocol_sha256,source_revision,core_image_sha256,trust_sha256,registration_sha256,boot_id,source_boot_ref,session_ref,previous_session_ref,attempt_ref,action,started_ns,finished_ns,custody_mode,actors,invocation,root_custody,fd_custody,stores,reader,outcome,error`.

- actors: launcher/native/receiver; reuse #620 actor schema (native plus image).
- invocation: unit,invocation_id,exec_main_pid,exec_main_start_monotonic_us,
  exec_main_exit_monotonic_us,active_state,result,exec_main_code,exec_main_status,
  exec_start_sha256,exec_start,standard_output,standard_error.
- root_custody: relative_name,prepared,launcher_fd1,after,bytes,sha256.
- fd_custody: sampled_ns,launcher,native,receiver; each pid,start_ticks,complete,
  entries,errors; entry fd,device,inode,owner_uid,mode,nlink,flags.
- stores: source,anchors,journal; each before/after `{object,bytes,sha256}`;
  source/anchors additionally before_checkpoint,after_checkpoint.
- object: device,inode,owner_uid,mode,nlink,size,mtime_ns,ctime_ns.
- reader: existing #620 O_RDONLY receipt, nullable on refusal/unsupported legs.
- custody_mode: live_parent_and_children or managed_prelaunch_refusal.

Both Root runtime reports include `root_stdout`, an actual fstat(1) object using
the eight-field object schema, or null if unavailable. Compare its identity
(device/inode/owner/mode/nlink) to the independently precreated/read-back sink;
size/timestamps naturally change while Root writes. Stable before/after metadata
is required around each read, not across the whole writing lifetime. Actual
systemd `standard_output` is `{mode,path}`; mode is the typed manager property,
path stays null if that manager exposes no typed output path. In that case
actual Root fd1 fstat-to-pinned-file binding is mandatory; unit-text guessing is
forbidden. `standard_error` must be actual typed `journal`. Refusal's short-lived
Root fstat is an explicitly trusted-code observation paired with independently
retained invocation/ExecMainPID/fixed code and exact sink, not a fabricated live
controller sample.

Unavailable values stay null. attempt_ref is a collector nonce, not a native
session. Refusal session_ref/previous_session_ref select the prior interrupted
session; runtime attempted_session_ref remains null. No derived success/ACK
booleans are accepted from the controller. Exact raw runtime messages, Source,
anchors and journal are separately pinned original inputs.

New pure evaluator API:
`evaluate_native_close_receipts(artifacts, *, expected)`; artifacts maps fixed
public names to bytes/None, expected externally retained SHA256 pins per name.
It performs no filesystem/RPC/key load, command, process or mutation. New explicit
analysis version; preserve #620/older evaluations independently. Reject malformed,
duplicate/noncanonical JSON, stale/crossed scopes/boots/sessions/PIDs/invocations,
forged role markers and missing custody. Distinct fields for bound native local
ACK, receiver report, independently authenticated/read-back End, witness coverage,
actual process waits and nonmutating managed refusal. Do not collapse them into
whole-system capture completion or release any safety/comparison/performance/
production/resume authority. Preserve valid signed prefixes on later leg failures.

## Fixed actual and synthetic assignments

Normal native-AppArmor CI: existing normal-four (SIDs90121001..04), restart-one
(downtime90121005 excluded; live90121006), witness-stopped-close (SID90122001),
interrupted-prefix (SID90121007), interrupted-restart-refused.
Record original End/old anchors for witness-stopped-close BEFORE witness restart;
later catch-up must never rewrite/upgrade that trial's historical coverage.

Fresh separate native-AppArmor receiver-fault CI variant: receiver-killed-prefix
(SID90122002), receiver-restart-refused. Same baseline roles/grants/profiles,
separate disposable job/scope, no history reset. Prove native remains alive after
receiver failure; do not infer continuing defense processing without independent
evidence. Then explicitly stop the owned unit and collect incomplete facts.

The post-End local ACK timeout is not deterministically inducible in the current
actual protocol with authorized grants: receiver pause does not delay local ACK,
and whole-core signal timing is not a test oracle. Keep deterministic Rust module
ACK-timeout tests labelled synthetic, never report an actual timeout observation.

Positive/negative fixtures before collection: exact normal close; false/missing
ACK with valid End; receiver report before writer close rejected; lost report
after authentic End preserves bytes; witness stopped/short coverage unknown;
native/receiver SIGKILL with exact waits; actual pre-spawn refusal with unchanged
three stores; forged stderr Root/native markers; wrong PID/session/invocation;
duplicate/truncated/oversize pipe reports; provider FD inheritance; changed Root
sink or state between brackets; refusal without actual attempt; legacy opt-out.
Pure parser/mock cases are synthetic. Actual tests must not skip-to-pass.

## Gates

Freeze before edits; targeted regressions and full final-head CI; independent
source and raw-original replay; exact base/head/test-merge/tree before merge.
GitHub requires approval by someone other than last pusher: do not bypass it or
switch identity. After authorized merge verify tree, automatic main CI and fresh
originals independently. Preserve adverse trials and all assigned failures.
Update existing #400/#393 (keep OPEN) rather than creating duplicate issues.
