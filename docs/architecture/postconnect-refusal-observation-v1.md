# Independent post-connect refusal-response observation v1

Related: Edge #400/#393. Base1e726dfe3070a52da794690c8c940aac60aaf795.

## Feasibility and trust boundary fixed before implementation

Use the EXISTING cap0/no-new-privileges Root transport role and unchanged
Root:control directory0750/socket0660. No new account/group membership/resolver
mapping,0666/socket relaxation or advisory connection grant. Root already passes
existing peer authorization. Unchanged real handle_client/peer_credentials/table/
execute_action/sot_devices_patch/persistence must run against owned temporary
SoT/audit data using existing environment configuration, never daemon.main or
background services. No installer/security/systemd edits, installed service/key/
production deployment, enforcement or external network operations.

Select actual post-parse VALIDATION refusals, not a false authorization refusal.
A known Web-role account with preexisting transport permission is not established
in this environment. Unknown advisory peers still stop at DAC. Do not manufacture
an advisory-to-native bridge or claim that bad caller metadata reached parsing.
No sys.setprofile/sys.settrace/guard wrapper/stub/new logger or target mutation is
an independent observation. Existing Root/kernel/code custody remain premises.

Investigate passive fentry/fexit of the existing kernel unix_stream_read_actor.
Before load require exact actual BTF prototype and relevant layout/semantics,
not a guessed return-slot index. Candidate: kernel skb pointer, skip, chunk and
unix_stream_read_state pointer; entry snapshots bounded LINEAR skb bytes at the
actual consumed+skip offset and receiver socket/peer identities, exit publishes
only an exact successful copy. No userspace-buffer substitution, data injection,
PEEK, payload reconstruction/backfill, nonlinear-payload fallback or inferred copy
success. Verify bounded kernel-copy support and attachment under EXACT existing
BPF+PERFMON+no-new-privileges; outer disposable setup retains only the existing six
capabilities. No SYS_ADMIN/SYS_PTRACE/MAC_ADMIN/privileged/seccomp bypass.

A feasibility probe may use a fixed disposable Unix echo/rejection fixture to
calibrate actual request/response copies, explicitly NOT real-daemon branch proof.
Pin original raw bytes/code/source/object/kernel/profile/role/socket/session/PID
namespace/start ticks and finite times; BOOTTIME birth is not compared with
MONOTONIC observation timestamps. Preserve failure/unsupported conditions and
stopped original runs. No actual product observation before final corpus/wire/
acceptance/public inventory freeze and independent precollection review.

## Facts and limits

A successful kernel protocol copy can prove the recorded bytes were copied toward
the receiver buffer at that layer, not parsing/authorization/a final recv syscall
or a specific internal Python branch. Separate server request-copy and client
refusal-response-copy records, coupled to fixed unchanged server code and exact
input, support finite refusal-RESPONSE consistency. A response/log or aggregate
counter alone is insufficient. Internal branch/authorization verification stays
unknown unless a genuinely independent specific observable is established.
Never promote that unknown or qualified safety to zero/success.

Independently sample original owned SoT/audit bytes+metadata before the challenge
and after actor/server/handler completion, before cleanup. Fresh valid hostname
patch is positive; malformed device-list and invalid typed SoT are negatives.
Expected negatives leave both originals identical at those samples. This is not
proof of no transient mutation or other files/IPC/network effects. Known changes
and copy records survive loss/missing siblings. Missing readback is explicitly
unknown; injected availability controls are not natural OS read failures.

The observer is read-only toward targets; the isolated harness alone constructs
sockets/processes and sends fixed challenges. No automatic resume, repair,
backfill, implicit conversion of #604 v1 artifacts, production/HIL/physical or
whole-system safety acceptance. Existing98%/1.2x criteria are unchanged. Freeze
positive/negative/lifecycle/loss/identity cases and exact unknown rules next, once
kernel feasibility is observed. All authority flags false/qualified safety null.

## Preserved feasibility failure and scoped follow-up

First isolated probe compiled and exact kernel BTF prototype validation passed,
but the verifier rejected the signed helper length before either attachment.
No copy observation exists. Both waiting fixture processes were forcibly reaped
on failure, not reported as clean completion. Original source/object/log/result
and stopped container are retained independently.

The next bounded feasibility attempt may only change the helper size to an
explicitly unsigned, verifier-bounded length and add the predeclared receive guards:
AF_UNIX/SOCK_STREAM, known non-PEEK/non-OOB/non-ERRQUEUE flags, user-destination
iterator (data_source=false and exact observed UBUF/IOVEC type), checked linear
consumed+skip/chunk. No permission, hook/observation-layer or fallback substitution.
The finite scratch probe's128-byte bound is not yet the product payload contract.
Product corpus/wire/coverage/export remain unfrozen until actual feasibility.

The second finite attempt also refused before attachment: compiler spill/reload
lost the verifier's dynamic-size bound. No copy observations exist; original v1/v2
sources/objects/logs/results and stopped containers remain separate. Forced cleanup
of waiting fixture actors is recorded as failure cleanup, not clean completion.
A third proposed material change snapshots the SAME contiguous checked kernel
range through a fixed unrolled128-byte loop, constant1-byte helpers only where
index<validatedchunk. Every required byte must succeed; no fill, fragment stitching
or observation-layer/privilege substitution. Independent review and a new scratch
freeze precede any third actual attempt. The observer still only reads kernel data;
entry snapshots are bounded readbacks, not atomic hostile-Root/kernel attestation.

The third scratch material was independently reviewed before its actual attempt:
constant-byte reads are one entry snapshot, not fragment reconstruction. The
probe does not establish generic metadata-read fault safety; product code must
check required kernel-read return values explicitly where zero is a valid value.
No native/product wire or runtime profile is accepted merely from this review.

Literal five-case corpus tests/fixtures/postconnect-refusal/v1/cases.json is fixed
before product implementation: actual valid hostname patch; devices_not_list;
invalid_allowed_networks; observer_loss_after_refusal (after both complete copy
facts); missing_after_sot (explicit submitted-input omission on positive patch).
All use the same EXISTING Root transport permissions, never a newly admitted
advisory role. Internal Python branch and authorization-refusal verification stay
None. The future product may recognize a message only from one bounded complete
frame-copy record; segmented or truncated copies stay unknown, never stitched.

## Actual feasibility and final product contract

The third finite probe succeeded under the unchanged exact BPF+PERFMON+NNP role:
server request58bytes and client response48bytes, reciprocal socket file inodes,
entry snapshots paired with ret==chunk, linear range/zero skip and consumed.
All three owned processes exited0 without force. Originals and stopped container
are retained separately from failed v1/v2. This is a disposable protocol fixture,
NOT real-daemon/internal-branch/fault-safety or256-byte product acceptance.

### Fixed native profile and ABI

Native AArch64 Linux/USER_HZ100; compiler -target bpf -mcpu=v3
-D__TARGET_ARCH_arm64. Exactly two tracing programs copy_entry fentry and copy_exit
fexit on unix_stream_read_actor (program26/attach24,25/link2). Before compilation/
load, actual kernel BTF must identify exactly one function with four ordered args
skb:sk_buff*,skip:signed32int,chunk:signed32int,state:unix_stream_read_state* and
signed32int return. ctx[4] is never guessed. Unknown prototypes/layouts refuse.

read_state is exact48bytes/seven ordered members: recv_actor@bit0,socket@64,
msg@128,pipe@192,size@256,flags@320,splice_flags@352. Callback pointer targets the
same four-argument/int-return shape (anonymous arg names empty/(anon)); socket,
msghdr,pipe_inode_info pointers, unsigned64size_t,signed32flags,unsigned32splice.
Required skb len/data_len are unsigned32; data is a kernel byte pointer; cb is
48bytes. unix_skb_parms is randomized/has optional secid: NEVER hardcode consumed
offset. Require unique unsigned32 consumed member wholly within the actual cb
range and struct<=48, then use actual CO-RE relocation. All required metadata
reads check return status, especially when zero is a valid UID/flag/type/offset.

Exact known iov_iter path only (no recursive member search/flattening): STRUCT40
members iter_type@0,nofault@8,data_source@16,iov_offset@64,anonymous UNION@128,
anonymous UNION@256. Count comes through first anonymous UNION16, ordered
__ubuf_iovec:iovec16@0 and anonymous STRUCT16@0; that struct has anonymous UNION8@0
and unsigned64count@64 (absolute byte24). iovec16 is iov_base:void*@0/iov_len:u64@64.
Inner UNION8 has ordered pointer views __iov,kvec,bvec,xarray,ubuf (6.8), or
__iov,kvec,bvec,folioq,xarray,ubuf (7.0), all atbit0. Last UNION8 has nr_segs:u64,
xarray_start:s64 (6.8), or nr_segs,folioq_slot:u8,xarray_start (7.0), all atbit0.
Anonymous names empty/(anon) only; no extra members/bitfields/unknown dimensions.
Type wrappers are bounded/acyclic known typedef/qualifiers, no unknown-type fallback.
iter_type is unsigned8, data_source bool; actual enum ITER_UBUF=0/ITER_IOVEC=1.
Required socket/peer/file/path/task/credential fields must resolve to actual typed
kernel metadata. Unknown or missing CO-RE/layout metadata refuses, not assumed0.

Configuration64: six u64 pidns_device,pidns_inode,server_start_ticks,
actor_start_ticks,started_ns,deadline_ns; four u32 server_tgid,actor_tgid,user_hz,
max_events. Root UID/EUID0 roles0server/1actor, distinct PIDs>1, TID==TGID,
USER_HZ100, max_events1..16, finite MONOTONIC window<=5seconds. Fixed held workers,
coarse proc ticks and Root namespace enrollment remain external trust premises,
not a full census or global identifier-reuse defense. Exact kernel start_ns is
BOOTTIME and is only checked against ticks/conflicts, not MONOTONIC ordering.

Event376: six u64 entered_ns,exited_ns,start_ns,receiver_inode,peer_inode,
endpoint_inode; sixteen u32 role,tgid,tid,uid,euid,netns_inode,endpoint_major,
endpoint_minor,flags,iter_type,data_source,skip,chunk,consumed,skb_len,data_len;
s32 ret,u32 reserved; u8 data[256]. Endpoint filesystem identity comes from receiver
unix_sock.path for role0 and peer unix_sock.path for role1. Reciprocal socket file
inodes and same original endpoint filesystem incarnation bind request/response.

Statistics96: twelve u64 selected_entries,pending_inserted,successful_copies,
emitted,copy_failure,unsupported,read_failure,identity_failure,correlation_loss,
overflow,inflight,unmatched_exit. These are diagnostic counters, not safety counts.
Exactly four maps flags0: config ARRAY(key4,value64,max1), pending HASH(key8,
value376,max2), events ARRAY(key4,value376,max16), stats ARRAY(key4,value96,max1).
Pending key is kernel pid_tgid, not CPU; NOEXIST/no overwrite. Collision/insertion
loss is sticky and prevents mispaired publication. Ignore unrelated tasks at exit;
eligible unmatched exits are unknown. Delete only owned pending; record remaining
inflight after detachment without publishing incomplete rows or kernel pointers.

Entry requires explicit successful reads: UID/EUID0, expected PIDnamespace/birth,
AF_UNIX/SOCK_STREAM/connected peer+file identities, valid msg, USER destination
iter0or1/data_sourcefalse/count>=chunk; flags ONLY0or64(MSG_DONTWAIT), no PEEK/OOB/
ERRQUEUE/other flags. chunk1..256, data_len0, nonnegative skip and overflow-safe
consumed+skip+chunk<=skb_len. Unrolled256 constant1-byte reads snapshot only that
single original contiguous range; ANY required read failure rejects the call.
No invented bytes, padding export, fragment joining or atomicity/Pi claim. Exit
uses saved data/scalars only, ret==savedpositivechunk, matching invocation and finite
window; no skb/user dereference. Earlier completed copies survive later failures.

### New explicit recorded-evidence formats

Probe canonicalJSON+LF<=64KiB exact: schema_version(edge-postconnect-copy-probe/v1),
architecture(aarch64),started_ns,finished_ns,configuration,events,counters,
partial_reasons,link_identities. Event JSON has the above fields replacing data
with data_hex exact lowercase2*chunk bytes, never the zero-filled unused tail.
Counters may beNone when unavailable. Link identities exact entry/exit (eachNone
or existing tracing fields fd,type,link_id,prog_id,attach_type,target_obj_id,
target_btf_id); both require the same checked function, correct attach type.
Partial reasons: observer_link_lost,copy_failure,unsupported_copy,read_failure,
identity_failure,correlation_loss,overflow,pending_not_empty,unmatched_exit,
acquisition_error,observer_cleanup_unverified. Scan indexed raw slots and preserve
already retained rows before health/cleanup; no byte-value dedup or caller config
mutation after validation. Keep original counters/rows, no manufactured missing0.

Pure API verify_postconnect_refusal_observation(plan_raw,*,expected_plan_sha256,
probe_raw,sot_before_raw,sot_after_raw,audit_before_raw,audit_after_raw). No I/O,
process/socket access, callbacks or writes. Plan canonicalJSON+LF<=32KiB exact:
schema_version(edge-postconnect-refusal-plan/v1),capture_id,case_id,kernel_boot_id,
request_utf8,request_sha256,requested_path,target_paths,control_endpoint,actor,
server,go,configuration,samples,probe_sha256,observer_source_sha256,
observer_object_sha256. Five closed case/request literals are the fixed corpus;
no caller classification or arbitrary request. Same existing Root role/worker,
endpoint750/660/original Linux stat metadata, GO pipe bracket, original per-object
samples and target paths as #604 where exactly compatible; new schema/API is
validated directly, never synthesized into a fake v1 plan. DescriptorNone iff
submitted rawNone; actual precreated empty audit is a real sampled empty file.

A verified_copy_events row is any eligible completed bounded kernel copy, including
partial-message chunks. Keep those raw facts even if no semantic classification.
Only single COMPLETE frame copies may qualify request/response: skip0,consumed0,
data_len0,skb_len==chunk1..256,full actual single LF frame, no CR/multiple frames/
truncation/concatenation. Full server payload must equal the pinned fixed request;
full actor payload strict parses the actual unchanged daemon response. Negative
exact fields ok:false,error:(one frozen code),ts:finite numeric. Positive exact
ok:true,path:pinnedSoT,diff:{added:0,removed:0,updated:1},audit_logged:true,ts:numeric.
Reject bool-as-int/duplicate/nonfinite JSON. Request exit<=response entry; reciprocal
receiver/peer inodes and role-selected original endpoint dev/inode must match.
Known copy rows/per-object changes are calculated BEFORE later completeness gates.
Lifecycle faults do not erase them. Response consistency requires both full copies,
paired scope and clean recorded roles; it never proves an internal branch.

Diagnostic exact: schema_version(edge-postconnect-refusal-diagnostic/v1),
verified_copy_events,server_request_copy_verified(True|None),
client_response_copy_verified(True|None),reciprocal_pair_verified(True|None),
response_disposition(patch_success_response|validation_refusal_response|unknown),
validation_error(str|None,exact frozen codes),object_changes:{sot,audit}(bool|None),
sampled_originals_unchanged(bool|None),permitted_hostname_patch_consistent(True|None),
coverage_disposition(finite_case_consistent|unknown),reasons,raw_sha256,
internal_branch_verified:None,authorization_refusal_verified:None,
qualified_safety_count:None and existing five authorityflagsfalse. Copy booleans
are layer facts, not final recv/branch/authorization/effect proof. Any known object
change makes overall unchangedfalse even if siblingmissing; all known equal makes
true, elseNone. Positive full patch additionally requires clean lifecycle/four
bound samples and actual existing audit shape including integerpatched_count1,
plus typed SoT normalization of ONLY the fixed hostname change. Negative equality
is sampled original byte+metadata equality, not no-transient/global-state proof.
Coverage needs complete expected fixed case, both link health/counters/no inflight;
loss/unsupported/identity/read failures/fragmentation keep it unknown.

### Intake, public export and collection gates

collect_postconnect_refusal_observation(enrollment_path,*,
expected_enrollment_sha256,expected_plan_sha256) is read-only Root0444/singlelink/
protected ancestors/held-FD intake, actual boot and distinct nonroot reader, all
owned FDs closed on all errors. Enrollment exact schema_version
(edge-postconnect-refusal-enrollment/v1),plan_sha256,reader_uid,kernel_boot_id,paths.
Paths exact plan,probe,sot_before,sot_after,audit_before,audit_after; None mirrors
plan. No keys/live acquisition/qualification flag or v1 migration.

Fresh Root0755 public root/five fixed case directories0755; files0444/singlelink.
Per-case manifest exact eight slots plan.json,probe.json,sot_before.raw,
sot_after.raw,audit_before.raw,audit_after.raw,control.json,diagnostic.json;
manifest.json hashes/byte lengths or explicitNone for unavailable probe/samples
whose corresponding file is ABSENT. Empty measured audit is present bytes0/hash,
neverNone. control.json is control_only role/build/fixture provenance, not branch
or effect proof. No ELF/BTF/private key/private target directory export.
case-index.json written ONCE lists all five complete|missing/manifests. Complete
is availability, not pass. Export before verdict assertions. Upper whitelist46
paths; expected complete five-case run45files (missing_after_sot/sot_after.raw absent).
Do not rewrite originals or fuse runs into successful coverage.

Independent precollection code/wire review, one actual five-case matrix under
existing profile, appropriate regressions, final-head complete CI (five actual
cases/no skips), externally pinned fresh public original replay and exact base/
head/tree are merge gates. Keep #400/#393 open for all unmeasured categories.

### Explicit fixture-only accepted-socket lifetime

The unchanged real handle_client closes its accepted descriptor on return. To
observe reciprocal socket-file identities while the client receives the queued
reply, the isolated SERVER HARNESS may hold os.dup of its OWN already accepted
file before invoking the unchanged handler. This grants no connection permission,
creates no new connection/proxy/observer FD and changes no guard/return value.
The duplicate is kept only until the client completes; ALL holds/listener/server
close before the independent after-samples. Record this control-only premise.

This affects fixture EOF/lifetime and does NOT prove the unmodified production
close path or availability of peer-file identity after last close. In an unheld
or missing-peer environment, record unknown/read failure, never cached/backfilled
peer identity. Synthetic missing-peer negatives must preserve prior known copies
and state samples. No new actual race scenario is inferred from this fixture.

Eligible raw chunks must still satisfy the frozen linear/USER-destination/native
profile. Retaining partial MESSAGE chunks (nonzero consumed/skip or no complete LF)
does not allow unsupported nonlinear rows to masquerade as published native facts.

Copy-window clarification before collection: actual copy entry/exit must lie in
their receiver's recorded lifetime and the finite observer window. The fixed
actor completes within that window for finite-case consistency. Server FD-hold/
listener cleanup may follow observer finish; require clean handler/server closure
before after-samples, not invented whole-role-lifetime observation. Later worker
or cleanup faults withhold completeness without erasing earlier verified chunks
or independent original changes. Actual daemon reply JSON is strict original
unsorted serialization, not reserialized/canonicalized evidence.
