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
