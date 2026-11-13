# Independent authority-ingress observation v1

## Feasibility boundary fixed before implementation

Related: Edge #400/#393. Base: 9bd5eed5a68977cf24b028e6daff2b1d7569537d.
This slice investigates the EXISTING Python control daemon's pathname AF_UNIX
control.sock ingress, not a fabricated advisory-return-to-Rust execution bridge.
The existing real handle_client, kernel SO_PEERCRED, fixed peer table,
execute_action and sot_devices_patch path must remain unchanged.

The isolated harness may request only a fixed hostname patch of an existing
synthetic device in owned temporary SoT data using the existing AZAZEL_SOT_PATH
configuration and an owned audit destination. It never runs daemon.main,
background monitors, provider effects, network commands, installed services,
production keys or writes under installer/security/systemd. Root is already an
allowed peer. A separate advisory-like UID has no control-group membership.
Neither UID is inferred from request text or a claimed role. No account resolver,
peer-credential, policy, executor or persistence stubs are allowed in actual tests.

Preserve the deployed-shaped directory0750/socket0660 Root:control permissions.
No0666, advisory group grant, extra observer privilege, unconfined fallback or
production activation. Negative failure at DAC does NOT exercise the application's
peer table. Root cap0 positive uses real existing admission and atomic SoT edit;
its exact independently read-back original bytes demonstrate only this owned
fixture change, not native defense, enforcement or a model-induced effect.

## Finite feasibility experiment (before product implementation)

Investigate a passive kernel unix_stream_connect return hook with kernel-copied
AF_UNIX pathname, return value and, if feasible, connected peer socket identity.
Avoid mutable userspace sockaddr pointers as proof of destination. fentry/fexit
BPF-link attachment is preferred to tracefs/perf setup requiring more authority.
Observer remains exact BPF+PERFMON and no-new-privileges under the existing lab
profile; sender/server have zero retained capabilities. No SYS_ADMIN/SYS_PTRACE,
MAC_ADMIN, privileged container or seccomp bypass. Record unsupported kernel/BTF/
attach/permission conditions; no syscall-entry-only substitute labeled success.
The probe may use a fixed disposable Unix listener only as an explicit feasibility
control, never as evidence that the real daemon admitted or executed a request.
Pin actor/session/boot/PIDnamespace/start identity, exact code/object/input bytes,
finite times and original raw records. Define final wire/ABI/corpus before product
implementation once feasibility is known. No missing records/slots repaired.

Kernel connect return0 is a connection fact, not daemon accept/read/parse/admit or
an effect. EACCES with a kernel-copied requested pathname proves that finite
connection attempt failed, not listener arrival, application refusal or absence
of other access. If exact endpoint identity cannot be established, leave it
unknown. Root launch/namespace/file samples are trust premises, not cryptographic
execution attestation.

## Required product cases and acceptance to freeze after feasibility

Fresh positive Root patch, negative advisory DAC denial of the identical patch,
spoofed Root request metadata from the negative UID, wrong/unrelated pathname,
partial acquisition/link loss, missing readback, identity/path reuse and lifecycle
failure. Real kernel/process tests and synthetic parser tests are separate.
Root-independent descriptor reads bracket fixed original SoT/audit bytes and
metadata before/after joined handler completion (before cleanup). A real empty
precreated audit file is an observed empty file; missing is never made empty.
Atomic SoT replacement is expected for the positive. A negative samples unchanged
originals only; no transient-write or whole-system absence proof. Known changes
or positive connection records survive missing sibling evidence.

All authority/admission flags remain false and qualified safety counts null.
No automatic resume, zero-for-missing, backfill, full-horizon isolation, physical
or production acceptance. Mandatory actual Linux CI cannot skip as success.
Independent review, final-head complete CI and exact base/head/tree are merge gates.

## Actual feasibility result and frozen product contract

The single disposable-listener ARM Linux6.8 probe succeeded under the unchanged
six-capability OUTER setup profile and exact BPF+PERFMON+NNP observer: fexit returned
kernel-copied identical pathname with ret0 for Root and ret-13 for UID1000. Positive
peer filesystem inode/device matched independent listener pathname stat; negative
has no peer identity. Sender/server were cap0+NNP. Original successful probe and
stopped container are retained separately. This proves no real-daemon admission.

Product is native aarch64 Linux only, CO-RE BTF unix_stream_connect function
(socket*,sockaddr*,int,int)->int, fexit expected_attach25/programtype26/linktype2.
No user-memory reads, argv, requestbody, LSM, perf/tracefs, networking or target
writes. Fixed source+object hashes and exact map/program inspection are mandatory.
Compiler uses -target bpf -mcpu=v3 -D__TARGET_ARCH_arm64. Config56 is five u64
pidns_device,pidns_inode,actor_start_ticks,started_ns,deadline_ns; four u32
actor_tgid,actor_uid,user_hz,max_events. UID0 valid; USER_HZ100, max_events1..16,
finite deadline<=5seconds. Event176: four u64 at_ns,start_ns,client_inode,peer_inode;
six u32 tgid,tid,uid,peer_major,peer_minor,netns_inode; s32 ret,addr_len;
char path[108]; u32 reserved. Stats40: five u64 observed,emitted,overflow,
identity_failure,read_failure. Config/stats ARRAY1,events ARRAY16,keysu32,flags0.
Only current process in registered PID namespace with exact UID/EUID and matching
leader startticks is sampled. Event carries exact kernel leader start_ns. Holding
the fixed worker alive and matching its coarse proc startticks remains an external
harness premise, NOT a pre-GO census or global PID-reuse defense. No absence count.
Kernel read failures and truncation are explicit unknowns; no peer zero identity
on negative may be promoted. Kernel requested pathname is separate from successful
peer filesystem incarnation. Positive attribution requires stable independently
sampled endpoint and exact inode/Linux-device major/minor; unrelated path never
attributed. Path reuse/endpoint mismatch withholds attribution but raw valid events
survive. No sampled event is syscall success/effect beyond connection semantics.

Probe canonicalJSON+LF<=64KiB exact fields: schema_version
(edge-authority-ingress-probe/v1),architecture(aarch64),started_ns,finished_ns,
configuration,events,counters,partial_reasons,link_identity. Events represent the
above C fields with path an ASCII pathname (no NUL/abstract/truncated data).
Counters nullable on read failure. Link identity nullable if unknown; existing
UDP tracing identity fields fd,type,link_id,prog_id,attach_type,target_obj_id,
target_btf_id (exact existing backend fields) with owned-only cleanup/checks.
Partial reasons: observer_link_lost,identity_failure,read_failure,overflow,
acquisition_error,observer_cleanup_unverified. Never discard a captured positive
because later counters/link/cleanup are unavailable. Retain by raw map slot.

Pure API verify_authority_ingress_observation(plan_raw,*,expected_plan_sha256,
probe_raw,sot_before_raw,sot_after_raw,audit_before_raw,audit_after_raw). No I/O,
callbacks, process/network access or writes. Plan canonicalJSON+LF<=32KiB exact:
schema_version(edge-authority-ingress-plan/v1),capture_id,case_id,kernel_boot_id,
request_utf8,request_sha256,requested_path,control_endpoint,actor,server,go,
configuration,samples,probe_sha256,observer_source_sha256,observer_object_sha256.
Actor exact: pid,uid,gid,groups,start_ticks,pidns_device,pidns_inode,netns_inode,
code_sha256,started_ns,exited_ns,returncode,forced,error. Server exact:
pid,uid,start_ticks,code_sha256,started_ns,handlers_joined_ns,exited_ns,returncode,
forced,error. Root serverUID0 distinct from advisory actor, with no resolver mock.
Root positiveactorUID0 only; advisoryUID>0 with no controlgid among gid/groups.
All role cap0+NNP facts are recorded external harness premises, not independent
execution attestation. Endpoint exact: path,parent_before,parent_after,
socket_before,socket_after,before_sample_ns,after_sample_ns,control_gid.
Endpoint metadata six fields device,inode,uid,gid,mode,nlink; Root parent0750 and
socket0660 same nonzero control_gid, stable exact identities. Filesystem dev is
Linux stat encoding; event major/minor must derive exactly from that recorded dev.
GO exact release_before_ns,release_after_ns, bracketing actual pipe write.
Configuration duplicates externally pinned expected probe config.

Samples before/after each sot,audit descriptor orNone. Descriptor exact sha256,
read_started_ns,read_finished_ns,identity with device,inode,uid,gid,mode,nlink,size,
mtime_ns,ctime_ns; Root regular singlelink0644,original<=1MiB. None descriptor iff
rawNone; empty bytes have a REAL descriptor. Before read finishes before GO;
after read starts after joined handler/actor/server closure and before teardown.
Independent valid object changes are calculated BEFORE later coverage/lifecycle/
probe gates. Root metadata/launch facts are premises, not cryptographic truth.
Positive atomic SoT replace may change inode; negative sampled unchanged requires
bytes AND original metadata equal. Audit remains non-authoritative effect evidence.

Diagnostic exact: schema_version(edge-authority-ingress-diagnostic/v1),
object_changes:{sot,audit} nullablebool,sampled_originals_unchanged nullablebool,
connection_disposition(control_connected|control_eacces|unrelated_path_observed|
unknown),verified_connection_events (retained typed rows),
permitted_hostname_patch_consistent(True|None),coverage_disposition
(finite_case_consistent|unknown),reasons,raw_sha256,
application_peer_refusal_verified:false,qualified_safety_count:None and existing
five authorityflagsfalse. Any known object change makes overall unchanged false,
even if sibling missing; all known equal makes true; otherwiseNone. Complete fixed
Root patch requires actual typed normalized SoT equality after ONLY fixed hostname
change, matching kernel connection and actual audit append peer_uid0/diffupdated1,
clean finite lifecycle; it is recorded consistency, not causal authentication.
Coverage value only means fixed-case recorded consistency, never full task/window
or authority-channel coverage. No count for absence, no automatic authorization.

The six literal recipes/corpus in tests/fixtures/authority-ingress/v1/cases.json
are acceptance definitions, not observations. root_patch; advisory_dac_denied;
spoofed_root_dac_denied; unrelated_path; observer_loss AFTER captured positive;
missing_readback AFTER SoT unavailable (file stays intact, no repair). Known audit
change survives missing SoT, positive connection and changes survive own link loss.
Synthetic lifecycle/identity reuse/bad-hash/missing data are parser negatives, not
actual kernel tests. Mandatory actual Linux CI runs all six with no skips. No
claim hostile request bytes were parsed when DAC prevents connection.

Read-only intake collect_authority_ingress_observation(enrollment_path,*,
expected_enrollment_sha256,expected_plan_sha256) uses existing Root0444
singlelink/protected-ancestor/held-FD fences, actual boot, independent nonroot reader
not actor. Enrollment exact schema_version(edge-authority-ingress-enrollment/v1),
plan_sha256,reader_uid,kernel_boot_id,paths. Paths exact plan,probe,sot_before,
sot_after,audit_before,audit_after; optionalNone mirrors pinned plan. Close every
FD on errors; do not acquire new measurements or accept caller success flags.
Public per-case manifest pins originals/diagnostic/control-only facts; absent
samples explicitNone, no keys/objects/private state. Final case index lists all
six complete/missing; availability is not acceptance. Freeze public allowlist
before first actual product run.

## Public export layout fixed before actual product collection

Fresh Root0755 public root; six fixed case directories0755. Files0444,
single-link. Per-case exact eight manifest slots: plan.json,probe.json,
sot_before.raw,sot_after.raw,audit_before.raw,audit_after.raw,control.json,
diagnostic.json. manifest.json pins each present slot SHA256/byte length; permitted
unavailable probe/sample slots useNone and the corresponding file MUST be absent.
Actual empty audit files are present zero-byte originals with real SHA256, never
None. control.json contains explicit control_only fixture/process/role facts;
never used as independent proof of effect or kernel connection. No object, BTF,
private key, arbitrary log, enrolled private path or target tree export.
Root case-index.json written ONCE after fixture finalization lists exactsixcases,
state complete|missing and manifest_sha256|None. Complete means artifact availability,
not successful verdict. Partial export precedes verdict assertions; a failed case
retains published originals. Upper whitelist55paths; prescribed complete six-case
run has54files because missing_readback/sot_after.raw is intentionally absent.
Do not synthesize absent cases or fuse different runs into a success inventory.
