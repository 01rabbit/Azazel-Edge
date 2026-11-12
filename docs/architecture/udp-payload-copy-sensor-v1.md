# Socket-bound UDP protocol userspace payload-copy observation — #400 / #393

## Frozen meaning and next feasibility gate

Base d54bc716 (#593). Commit contract/cases BEFORE code or attachment probe.
New layer udp_protocol_userspace_payload_copy means: the enrolled IPv4 UDP socket
supplied the exact matching64-byte payload through the protocol's successful
copy/consume path into a userspace-backed destination iterator. It does NOT mean
successful syscall return, receipt by a named/enrolled application process,
application handling/durability, protected_escape, safety or defense efficacy.
Queue admission and every existing schema/domain/count remain separate/unchanged.
No new privilege, target memory read/write, observer send/socket-receive, service,
production keys/deploy, namespace/host-PID mode, auto-resume or missing-data fill.

Primary Linux6.8 udp.c shows successful copy/checksum handling reaches
skb_consume_udp(sk,skb,+copied), then udp_recvmsg returns copied. Copyfault and
checksum-error/drop/retry are not successful matched consume+return. Later
net/socket.c ____sys_recvmsg name/header copyout may still EFAULT. Test that a
copy-positive can coexist with a syscall-negative; never label syscall success.
Read-only BTF found udp_recvmsg/skb_consume_udp on existing Linux6.8.0-117.
BTF is NOT attachability/verifier/runtime proof. The first bounded probe must
actually compile/load/attach the fixed3 hooks under SAME BPF+PERFMON+NNP and
observe real controlled traffic. Failure stays blocked; no fabricated fallback.

## Socket-centred identity and limits

Eligibility is exact socket inode/cookie/socket-owner UID/network namespace and
cookie, fixed loopback UDP tuple, exact64-byte challenge and original monotonic
window. Require actual calling REAL UID and EFFECTIVE UID both equal enrolled
socket-owner UID, using kernel initial-user-namespace IDs explicitly. PID/start
fields in the existing target metadata are LOCATOR PROVENANCE ONLY. Do not compare
them to host bpf_get_current_pid_tgid or claim named-process continuity.

Record actual receiver PID-namespace TGID/TID using bpf_get_ns_current_pid_tgid
with externally enrolled observer PIDNS device/inode; only tasks in that exact
active PIDNS are supported, no ancestor translation or --pid=host workaround.
Record current task -> group_leader.start_boottime as RAW OBSERVED kernel context,
never convert to proc ticks or infer a pre-enrolled process match. Another
same-UID process inheriting the same socket still satisfies this SOCKET-level
copy claim and must be visibly identified as the actual receiver. No exact-PID,
pidfd enrollment or process-restart continuity claim is introduced.

Observer time namespace device/inode and explicitly zero monotonic/boottime
offsets must be verified before/after capture, so userspace plan windows and
kernel ktime share a domain. Receiver start_ns remains raw kernel context; no
cross-clock or tick conversion. Unsupported namespace/helper layout blocks.
Root/kernel/approved C source/ELF/BTF and independently enrolled key/plan custody
remain external trust assumptions; public lab keys prove no production custody.

## Fixed hooks, data and correlation

Three fixed programs: fentry udp_recvmsg, fentry skb_consume_udp, fexit udp_recvmsg.
At outer entry save exact socket identity, calling credentials, supported PIDNS
receiver IDs, raw group-leader start_ns, original flags/request length and kernel
msg_iter metadata. Require userspace ITER_UBUF/ITER_IOVEC DESTINATION and adequate
remaining count; never dereference a userspace pointer. Accept only supported
ordinary flags (0 or MSG_DONTWAIT), rejecting PEEK/TRUNC/ERRQUEUE/unknown modes,
short buffers, UDP-Lite, GRO/GSO and nonlinear/unsupported skb layouts.

At consume ENTRY read still-live skb/socket facts and full exact64-byte payload,
network tuple and consume length64. At outer EXIT read saved scalars+return64 ONLY:
no skb/socket/msg/user-buffer dereference. Exactly one eligible consume candidate
per outer call; duplicate/unpaired/collision makes sticky loss, no overwriting.
Use global pid_tgid+socket as internal correlation key, NEVER CPU (blocked task
can migrate); export only declared namespace IDs. All entry/consume/exit timestamps
must lie within original window. Pending call past deadline is loss; no extension.

Attach exit/consume before entry; detach entry first, consume then exit; only
final own-map reads after detachment. Fixed config1/pending64/events16/stats1 maps,
bounded resources. Preserve completed positives through later correlation/link
loss only when their own binding remains verifiable. Unknown ownership/unsafe
cleanup returns no new report, preserves previously published records. Reuse
existing cached own-link identity/exactly-once safe cleanup principles. No global
object-disappearance or absence/coverage/zero claim from counters or close return.

## Wire/API profile (clarify exact ABI after feasibility before facade)

New plan edge-udp-payload-copy-plan/v1 mirrors existing strict socket-sensor plan
with this explicit layer, approved kernel/ELF/BTF pins, target locator+socket IDs,
PIDNS and zero-offset observer timeNS enrollment, exact protected opportunity/
challenge and <=5s duration/<=16 events. Contract retains existing finite safety
schema, exactly one protected opportunity and other lists empty. Its target-layer
reference is recomputed for THIS layer. Old queue parser must reject new wire.
New signed report/domain only; domain
b"azazel-edge:udp-protocol-userspace-payload-copy:v1\x00". Exact wire/ABI fields
will be specified before Python facade implementation; no auto old-format conversion.

Separate protocol_payload_copy_observed_count is1 OR null only. Always leave
successful_syscall_count, application_delivery_count and qualified_safety_count
null; authority/experiment/measurement/resume/production flags false. Observed
receiver context is not a named-app match. Missing/unsupported/invalid/partial
input never becomes zero. Positive typed signature authenticates configured
observer assertions, not hardware, custody, independent sensor truth or processing.

## Test classes and stages

1. Freeze this contract/cases; bounded actual3-hook probe under existing profile.
2. Native fixed read-only implementation + exact wire/ABI clarification; synthetic
   parser/crypto/FFI tests explicitly distinct from real kernel/traffic evidence.
3. Real isolated Linux sender/socket harness: normal IOVEC/UBUF, nonblocking,
   PEEK, short-buffer/TRUNC, payload-copyfault, later name/header EFAULT aftercopy,
   no app read, filter drop, wrong challenge/socket/UID/PIDNS/iterator, inherited
   socket actual receiver context, blocking migration, deadline/loss/restart.
   Packet/checksum controls need honest supported provenance; no inference from
   missing events/sender claims. Unsupported control remains explicitly unmeasured.
4. New Root-sealed read-only artifact intake/evaluation; preserve original bytes,
   held-FD/UID/boot/namespace/close fences and valid published history. No services.
5. Independent review and exact final-head full CI/base/tree before conditional
   merge, update existing400/393. Mandatory Linux path cannot skip as pass.
   Hardware/production/processing/full safety and efficacy gates remain open.

## Actual bounded feasibility and exact ABI/wire freeze

Actual Linux6.8.0-117 offline3-hook attach/helper probe succeeded after bootstrap
irreversibly dropped to permitted/effective/bounding BPF+PERFMON only,
Inh/Amb0, NNP1, default seccomp, network none, zero time offsets. IOVEC/UBUF each
produced one kernel event; PEEK/short/TRUNC/copyfault produced none. Later peer-name
copyout EFAULT produced one kernel payload-copy event despite syscall failure.
These are finite real probe observations, not signed-report/production acceptance.
Probe result SHA83d3b19d93a0b1d7fa04793a5666cf984600f1cf2a60ecfae7f9b35574c9ea49;
C SHAe2259af4b43205444e49576ca86c5fb5b5a58b89382792ed669c261951a65a4a.
First attempt ran image's unprivileged default user and failed before target setup;
corrected test bootstrap to Root then DROPPED privileges, never broadened observer.

Native configuration152 bytes:8u64 socket_inode/socket_cookie/netns_cookie/
netns_inode/started_ns/deadline_ns/pidns_device/pidns_inode;3u32 socket_uid/src_ip/
dst_ip;2u16 ports;2u32 max_events/reserved;payload64. Event160:8u64 entered_ns/
consumed_ns/exited_ns/socket_inode/socket_cookie/netns_cookie/netns_inode/
receiver_start_boottime_ns;7u32 socket_uid/receiver_real_uid/receiver_effective_uid/
receiver_tgid/receiver_tid/src_ip/dst_ip;2u16 ports;payload64. Pending key16:
globalpid_tgid/skopaque; pending value event160. Stats48:6u64 entry_matches,
consume_matches,accepted,rejected,correlation_loss,overflow. ConfigARRAY1,
pendingHASH64,eventsARRAY16,statsARRAY1; expected programtypeTRACING26,
attach24 entry/consume and25 exit. Exit+entry target same function, consume
separate; source/sections/ABI/pins fixed. No BPF-global object query by ID.

Public capture_udp_payload_copy(contract_raw,plan_raw,*,expected_contract_sha256,
expected_plan_sha256,object_path,observer_private_key); pure
evaluate_udp_payload_copy(contract_raw,plan_raw,report_raw,*,
expected_contract_sha256,expected_plan_sha256). Errors UDPPayloadCopyError.
New plan exact keys schema_version=edge-udp-payload-copy-plan/v1,
contract_sha256,observation_layer,opportunity_id,kernel_release,btf_sha256,
object_sha256,socket_identity,locator,receiver_pid_namespace,
observer_time_namespace,challenge_payload_hex,max_duration_ns,max_events.
socket_identity exact inode/cookie/uid/netns_cookie; locator exact pid/start_ticks/fd.
All original locator fields remain data only; capture NEVER opens/reads target
proc/socket descriptors or uses locator liveness as a process-identity claim.
PIDNS exact device/inode; observer timeNS exact device/inode/monotonic_offset_ns/
boottime_offset_ns with both offsets0. Require literal IPv4UDP127.0.0.1 tuple,
exact64-byte challenge, approved ELF/BTF/kernel and bounded original window.
Target reference SHA hashes canonicalNO-LF {observation_layer,protected_tuple,
socket_identity,locator,receiver_pid_namespace,observer_time_namespace}.

Report exact keys schema_version=edge-udp-payload-copy-report/v1,
contract_sha256,plan_sha256,observation_layer,kernel_release,btf_sha256,
object_sha256,kernel_boot_id,namespace,receiver_pid_namespace,
observer_time_namespace,capture_id,started_ns,finished_ns,events,counters,
partial_reasons,signature. namespace exact device/inode (socket networknamespace).
Each event exact entered_ns,consumed_ns,exited_ns,socket_inode,socket_cookie,
netns_cookie,netns_inode,receiver_start_boottime_ns,socket_uid,receiver_real_uid,
receiver_effective_uid,receiver_tgid,receiver_tid,src_ip,dst_ip,src_port,dst_port,
payload_hex. IPv4 strings canonical; namespace IDs and raw start_ns positive;
identities/credentials/payload/tuple match fixed profile, receiver IDs OBSERVED.
Every entered<=consumed<=exited inside original absolute kernel deadline.
Counters exact six native names, uint64. Reasons closed timeout,event_bound,
correlation_loss,event_overflow,observer_link_lost. No complete/zero flag.
CanonicalJSON+LF, existing bounded parser/signature helpers; domain above signs
canonical unsigned bodyNO-LF. Contract128KiB, plan32KiB, report64KiB, <=16events.

Capture verifies self Root/NNP/capabilities/environment before/after, protected
Root-sealed object via existing held-FD read, no runtime compiler/fetch. Native
backend _capture_events(configuration,object_raw) uses fixed own maps/threehooks,
safe cached-link checks/teardown and final own-map reads only; root+NNP role fixed.
Opaque internal key globalpid_tgid/sk is never exported. Calling UID fields are
initial-user-namespace real/effective IDs, compared to socketowner UID. Receiver
PID namespace is exact active namespace; raw leader start_ns has no tick conversion.

New evaluate result edge-udp-payload-copy-evaluation/v1 contains observation_layer,
protocol_payload_copy_observed_count1-or-null, successful_syscall_count=null,
application_delivery_count=null,qualified_safety_count=null,
independently_measured=false, unchanged safety_evaluation with emptychannels and
all old safety countsnull. No production/transition/resume/measurement authority.
New collect_udp_payload_copy(enrollment_path,plan_path,report_path,*,
expected_enrollment_sha256,expected_checkpoint_sha256,expected_plan_sha256,
expected_report_sha256) uses existing six-path Root-sealed read-only pattern,
registered nonroot reader/boot/final held-metadata/independent closes. It NEVER
translates new layer into old queue schema or counts. Old evaluators reject it.

## Implemented validation and explicitly open cases

The new native/backend/facade/intake are additive. Backend slot-read failure AFTER
safe owned-link teardown marks correlation loss and retains independently checked
earlier events; unread slots are not invented. Unknown ownership or failed cleanup
still refuses a new report. Existing published files are never reopened for writes.

Actual offline Linux6.8.0-117 ARM64 integration:14 tests passed without skips:
ordinary IOVEC, UBUF, later name-copyout EFAULT, inherited-socket receiver, PEEK,
short buffer, TRUNC, payload EFAULT, no receiver read, socket-filter drop, wrong
challenge, replaced socket, capability refusal and signed Root-sealed separate-UID
collection (including wrong report-pin refusal). Name-copyout returns EFAULT14
while the BPF payload-copy event is positive; successful_syscall_count stays null.
The inherited socket's actual child TGID differs from locator provenance. No-read
keeps copy count null even though the target's AFTER-detach control finds data.
Control responses are labeled control_only; assertions use signed kernel events
as the independent observation, never target success as the proof itself.

The first integration run's14 test bodies passed but teardown failed because the
ROOT TEST HARNESS lacked KILL for its separate-UID children. Retained failure
and corrected rerun are separate evidence. Harness-only KILL belongs to the
existing isolated setup profile; the sensor drops it, all other setup authority
and ambient/inheritable capabilities before the capture API. No observer profile,
expected result or production privilege was relaxed. Actual probe and integration
are finite virtual observations, not production custody or whole-system safety.

Parser/signature/FFI/held-reader tests are SYNTHETIC. They exercise strict field/
type/domain/pin/credential/time/namespace rejection, loss and cleanup, opaque
locator semantics and independent null safety counts. Fake map/iterator/lifecycle
faults do not prove actual scheduler migration, kernel/discard iterator behavior,
wrong real credential/PIDNS kernel branches, checksum corruption, GRO/GSO or
reboot continuity. Those real controls remain OPEN and never receive fabricated
positive/zero measurements. Nonzero-offset namespace creation was not exercised;
strict refusal is parser-tested. No named application identity, successful syscall,
processing/durability, observer-object disappearance, broad defense restoration,
Pi/HIL, production activation or comparative efficacy is accepted by this slice.

Mandatory actual-Linux CI explicitly includes the new suite and rejects skips;
ordinary nonroot/platform suite skips are not actual-kernel acceptance. Final
published head still requires complete CI, independent review and exact refs/tree.

## Frozen cross-kernel argument-layout correction (CI failure gate)

PR594 head c9bac451 on CI43269737980 failed13 required actual-Linux controls:
copy_exit attempted ctx offset40, but the actual udp_recvmsg function had fewer
arguments than the Linux6.8 five-argument signature. 252 existing cases passed;
this is FAILED acquisition, never skipped/accepted or a privilege insufficiency.
Do not retry unchanged, add capabilities or weaken expected actual observations.

Before code correction, freeze the permitted build profiles: exact udp_recvmsg
BTF prototypes with either (sock*,msghdr*,size_t,int,int*) or
(sock*,msghdr*,size_t,int), both returning signed int. The latter removes only the
unused address-length argument. Fixed entry accesses only the common first4;
fixed exit reads return from the statically selected correct argument slot. Root
TEST BUILD selects4 or5 only after exact local BTF prototype validation; unknown
count/types/name bindings must fail before compilation/attachment. skb_consume_udp
retains exact (sock*,sk_buff*,int) returning void. No verifier-error fallback,
runtime recompilation, dynamic ctx indexing or permissive unknown ABI is allowed.
The approved ELF and BTF are still external exact plan pins; no old report/ABI,
privilege, proof meaning, target identity or event/count conversion is changed.

Synthetic prototype-selection tests must accept only the two allowed shapes and
reject unknown/malformed/type drift. Actual local five-argument controls must stay
passing, while mandatory hosted actual controls must pass the hosted profile
without skips. Both variants need independent review and final-head full CI.

The permitted4-argument semantics were checked against pinned upstream udp.c
[6f8319e3](https://raw.githubusercontent.com/torvalds/linux/6f8319e3e9a44dd537d17f41565a8453c560a581/net/ipv4/udp.c):
successful copy/checksum handling still consumes then returns the copied count;
address length is stored in msg_namelen. This is not an attribution of CI's exact
kernel revision. Actual BTF selects only its observed allowed prototype. The new
selector has53 synthetic accept/reject tests; actual local BTF selected5 and all14
controls passed without skips. Actual hosted4-profile success is still pending.
