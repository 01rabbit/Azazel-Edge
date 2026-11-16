# Natural-close individual recv completion observation v1

Related #400/#393. Base8e05ea987b1673aa56c55642413dcf0ac9d9796a.

## Conditions fixed before implementation or kernel collection

Reuse the existing UID/GID65534 nobody/nogroup development own-UID profile from
#606, never production Root/Web/advisory. Required accounts/maps/namespace and
cap0+NNP checks are unchanged. Existing0750/0660 own endpoint/state0644 are created
by the owner. Controller primaryGID65534 and separate cap0 same-UID namespace/status
sampler are declared lab custody premises. No account/group/resolver/DAC grant,
new capability, target tracing callback, service activation, production key or
installer/security/systemd change. Lab network none; outer setup only existing
BPF,PERFMON,KILL,SETGID,SETPCAP,SETUID; sensor exactBPF+PERFMON+NNP.

This harness NEVER duplicates/holds accepted socket FDs, passes SCM_RIGHTS,
changes receiver buffer lifetime, or delays the real handler's close. Unchanged
handle_client closes its original socket normally. A separate fixed isolated
controller may delay ACCEPT before a deterministic actor-death challenge; this
is lifecycle scheduling only, never target branch instrumentation. The sensor
only reads kernel metadata/maps and emits its own control notification; only
controller may kill its OWN disposable actor. No PID-wide production action.

Read-only feasibility checked actual6.8 BTF (no program load):
__arm64_sys_recvfrom(const pt_regs*) returns signedlong64; entryctx0 and exitctx1.
pt_regs336/anonymous union272+struct272/regs[31]u64@0; fdregs0, requestedlenregs2,
flagsregs3, pstate nativeAArch64 mode only. Exact files/fdt/fd/inode/socket traversal
and read_actor layout/prototypes must validate against actual BTF before attach;
unknown layouts refuse. New four hooks: recv entry/exit plus read_actor entry/exit,
all tracing26 attach24/25; actual BPF+PERFMON attachment remains a test gate.

New explicit edge-natural-close-{plan,probe,diagnostic,enrollment,collection}/v1,
never reinterpret #605/#606. Config72: same explicit fields as #606, both65534,
finite <=5s, maxevents32. Publish separate IMMUTABLE recv_entry, copy, recv_exit
facts through NOEXIST event slots. Keep syscall pending and copy pending separate,
keyed kernelpid_tgid; token syscallentryMONOns with exact workerstart+role+PID/TID.
No overwrite/collision/retry reconstruction. Entrypending death survives as an
immutable entry fact even if no exit. Kernel exit reads saved scalars only.

Syscallentry reads native regs, boundedfd0..4095 AND<max_fds, requestlen1..65536,
flags0 only, own actual fd->file->socket inode/mode/AF_UNIX/SOCK_STREAM/netns;
all required reads explicit rc. Same fixed singlethread held-worker/code and
nonshared-FD-table custody are premises: fentry precedes fget, no hostile FD-race
attestation. Nested read_actor must match SAME pending invocation and own inode;
required boundedlinear USERdestination/nonPEEK flags0or64/UID/time/start guards
remain. Snapshot original contiguous bytes <=256 at copy entry; ret==chunk on exit.
No user-buffer substitute, fragments stitched, repeated syscalls merged, padding,
missing-zero/backfill or cached peer replacement. Optional CURRENT peerfile/endpoint
absence/readerror yields explicit null+availability code, NEVER copied prior IDs
or discard of required-ownsocket/byte facts. Keep optional statuses independent.

Individual byte-read completion is true ONLY with one valid entry, one validexit,
exactly ONE completed copy in that invocation, matching owninode, same kernel token,
UID/start/namespace, ordered wholecall bounds and final signed syscallret==chunk>0.
Protocolcopy alone, retval alone, EOF0, negative/restart errno, duplicate/missing
facts, partial/multiple chunks, crosscall/FD/start reuse stay unknown for fullframe
completion. Raw return facts remain measured return facts; EOF is not missingzero.
Fullmessage additionally requires single LF frame/zero skip+consumed/linear skb.
Partial16byte read may qualify individual boundedbyte completion while fullmessage
remains unknown. This is not Python parsing/internal branch/application consumption.

Server request and client response are individual facts. Optional peer/endpoint reads are non-atomic best-effort metadata. With natural
close, the other process may release/reuse objects during this lockless chain;
read success does NOT establish coherent peer incarnation. This profile ALWAYS
leaves reciprocal pairing and authorization refusal consistency null, even when
all optional fields were readable. Missing peer NEVER gets filled from earlier
request/socket history. No stable peer-lifetime proof is claimed. Individual client
payload may classify a root_only refusal RESPONSE, explicitly not a proven pair or
internal branch. BOOTTIME birth and MONOTONIC invocation clocks stay distinct.

Seven literal cases fixed before implementation:
- own_uid_patch: real permitted hostname patch; normal close/no hold.
- root_only_refused: migrate_path_schema targetv2 dry_runtrue actual response.
- spoofed_root_refused: same + untrusted peer_uid0; normal close.
- partial_read_close: root-only request, client recv16bytes once then closes.
- actor_death: controller delays accept; actor sends then entersrecv; sensor entry
  notification precedes controller SIGKILL of its own actor; then accept/realhandler.
  Entry remains, return/completion unknown; unclean termination not normal-exit pass.
- observer_stop_after_copy: lose only own recv-exit link AFTER completed client copy;
  timing may allow alreadyverifiedexit; preserve all actual facts, coverage unknown.
- missing_after_sot: actualpositive; omit submitted after-SoT AFTER sampling;
  known changed audit survives, unchangedfalse, fullstatequalificationunknown.

Independent bounded original SoT/audit samples beforeGO and after actor reaped,
handlerjoined/server exit, before owner cleanup. Byte+metadata equality means only
sampled originals. Clean-lifecycle qualification separate; death/observer loss/missing
never finite safety pass. Normal positive must really change both originals with
actual auditpeer65534. Negative dryrun contains accidental dispatch and limits canary.
Sample equality is not absence of transient mutation/allpersistentstate/migration.

Collection exports before assertion: eight slots(plan,probe,sot_before,sot_after,
audit_before,audit_after,control,diagnostic)+manifest percase, plusindex;64 upperpaths,
63 expected actualfiles with declared missing afterSoT. Root0444 singlelink protected
copies are read by separate65533 using heldFD/currentboot readonlyintake. Preserve
all failed runs separately, never repair/retroactively qualify. Synthetics test
wrongUID/namespace/token/start/FD/inode/time, duplicates, retmismatch/EOF/errors,
missing entry/exit/copy/peer, partial frames and oldschemas; no synthetic kernelclaim.
Required nativeLinux CI sevenactualcases no skips-as-pass. Finalhead allCI, fresh
artifact exactreplay, independentreview, exactbase/head/tree before conditionalmerge.
All authorityflagsfalse; internalbranch/authverified/safetycountsnull; no automatic
resume/admission.98%/1.2x unchanged; Pi/HIL/physical/production/causalbenefit unknown.

## Explicit native wire (fixed before load)

Event416: u64token,entered_ns,exited_ns,start_ns,receiver_inode,peer_inode,
endpoint_inode,requested_len; s64ret; u32kind,role,tgid,tid,uid,euid,netns_inode,fd,
flags,iter_type,data_source,skip,chunk,consumed,skb_len,data_len,endpoint_major,
endpoint_minor,peer_status,endpoint_status,reserved,reserved2; data256 atbyte160.
Kinds0recv_entry/1copy/2recv_exit. Entrytime=token,exittime0/ret0 forentry; exit
uses originaltoken+savedscalars and actualreturntime. flags is scoped bykind:
entry/exit syscallflags0; copyinternalflags0or64. Emptydata forentry/exit.
Optional identity JSON fields are null when status!=1:1available,2absentpointer,
3readerror. No numericzero advertised asidentity. Sixmaps: config72,recv_pending
HASH8/416/2,copy_pending HASH8/416/2,eventsHASH4/416/32NOEXIST,zero_template
ARRAY4/416/1readonlyBPF128,statsARRAY4/128/1. Counters oldtwelve+recv_selected,
recv_completed,recv_inflight,unmatched_recv_exit. Hookkeys recv_entry,recv_exit,
copy_entry,copy_exit preserved separately in probe link_identities.

Normal-case bounded_individual_observation means bounded INDIVIDUAL receiver observations
and clean sampled-state lifecycle, never a missing-peer pair or globalcoverage.
Pair/refusalconsistency remain separate null when missing. The corpus full-client
frame expectation on observer_stop_after_copy means original completeCOPY bytes;
its syscallreturn may legitimately be absent. No callback forces a specific race.

recv_exit optional statuses0 mean NOT OBSERVED AT EXIT, with null identityfields;
never echo saved entry peer/endpoint identities as current exit facts. Entry/copy
statuses1..3 describe their own observation. Saved syscall-entry owninode/FD/UID/
start/ns/token inexit are explicit invocation binding, not a new exit reread.

An actor killed during recv may emit an actual negative/restart syscall return
before death; retain it as a return fact, never a completed positive read. If an
exit is absent, pending_not_empty may be present; neither shape is manufactured
or required as proof of positive completion. Normal lifecycle remains unclean.

## Independent precollection natural-close race restriction

Review found that removing the accepted-FD hold also removes a stable-lifetime
premise for the OTHER process's optional peerfile chain. Checked nonnull reads
are not atomic identity attestation. Retain exact best-effort optional readbacks
and statuses only; reciprocal_pair_verified and root_only_refusal_response_consistent
are ALWAYS null in this new profile. Individual own-inode/invocation/read completion
proof remains separate. Neither available optional fields nor historical IDs can
restore peer qualification. A future coherent peer observer needs its own gate.

## Actual virtual collection (before final CI acceptance)

Fresh isolated Linux6.8.0-117/aarch64 trial: sevenpassed27.95s, noskips, noacceptedFD
hold. Required BTF+wrapper attachment under unchanged BPF+PERFMON succeeded. Normal
request and client fullframe each have separate entry/copy/exit and actual matching
positive recvreturn. Partial16-byte client read completes but fullframe staysnull.
Intentional actordeath retains entry/negative-return facts and no byte completion;
normal-exit qualification staysnull. Own recv-exitlink loss happened after actual
client copy; this run already retained its return too, kept honestly rather than
fabricating missingexit. Coverage remainsunknown. Missing submitted afterSoT keeps
knownaudit change/unchangedfalse. All naturalpeer pairing/refusalconsistencynull.

Sixty-three immutable original files reproduce allseven diagnostics exactly;
index pinned beforecopy42170720be6fac753b3debffb9c14cf6352303cf1f8b9e5ae06956ab2a95673a.
No oldartifact converted. Targeted regressions329passed before threeadditional
pair-withholding cases; affectedpair tests passed. Independent concreteprecollection
review CLEAN. FinalheadallCI/freshCIartifact/review/base-head-tree remain mergegates.
No production, internalbranch, allstate or comparative-benefit acceptance follows.
