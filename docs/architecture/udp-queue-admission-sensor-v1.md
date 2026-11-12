# UDP socket queue admission v1 — #400 / #393

## Feasibility and locked trust boundary

Base PR #587 observes interface ingress, not socket delivery. Linux 6.8.0-117
virtual ARM64 provides BTF and __udp_enqueue_schedule_skb fentry/fexit. An actual
load/attach probe under default container seccomp, NNP and only BPF+PERFMON
capabilities observed one successful enqueue after a real loopback UDP send.
No privileged/unconfined mode, mount, target ptrace or installed service was used.
Build dependencies are preprovisioned; capture and tests run offline.

MSG_PEEK was tested feasible but REJECTED: Linux udp_recvmsg can unlink a bad
checksum datagram while peeking. It fails the strict target-read-only requirement.
The chosen BPF hook runs after socket filtering: entry snapshots data, exit return
0 confirms queue insertion. No skb/sk dereference at exit (another CPU may free
it). Negative returns do not prove admission. Outer udp_queue_rcv_skb return is
unsuitable because the GSO path can return 0 after individual drops.
Primary semantic reference: Linux v6.8 net/ipv4/udp.c, udp_queue_rcv_one_skb and
__udp_enqueue_schedule_skb. Runtime BTF/object/kernel identity is frozen and actual
positive/socket-filter-negative controls are mandatory for the tested kernel.

Layer is udp_socket_queue_admission, NOT application receipt, continued residence,
checksum validity or defense escape. All existing delivery/safety counts remain
null, including positive controls. No finite-zero claim in v1. No new authority,
resume, production admission, Source authentication, cleanup or Pi/HIL acceptance.
Socket owner UID is not current receiver UID. Hook pid_tgid is processing context,
not receiver identity; use it only for exact invocation correlation.

## Fixed interfaces and artifacts

Facade module azazel_edge.benchmark.udp_queue; provider udp_queue_bpf.py and
native/udp_queue_observer.bpf.c. No runtime compilation or dependency fetching.
`capture_udp_queue(contract_raw,plan_raw,*,expected_contract_sha256,
expected_plan_sha256,observer_private_key,object_path)->bytes` returns signed JSON.
`evaluate_udp_queue(contract_raw,plan_raw,report_raw,*,expected_contract_sha256,
expected_plan_sha256)->dict` returns a typed unqualified diagnostic.
`collect_udp_queue(enrollment_path,plan_path,report_path,*,
expected_enrollment_sha256,expected_checkpoint_sha256,expected_plan_sha256,
expected_report_sha256)->dict` joins six root-sealed artifacts using the previous
held-FD collector rules. Object is not needed for offline report evaluation.
`UDPQueueError(ValueError)` means no qualifying result, never a score of zero.

Use existing strict canonical JSON plus ONE LF: contract<=128KiB, plan<=32KiB,
report<=64KiB. Plan exact fields:
`{schema_version:'edge-udp-queue-plan/v1',contract_sha256,observation_layer:
'udp_socket_queue_admission',opportunity_id,kernel_release,btf_sha256,
object_sha256,target:{pid,start_ticks,uid,fd,socket_inode,socket_cookie,
netns_cookie},challenge_payload_hex,max_duration_ns,max_events}`.
One protected opportunity, other lists empty; 127.0.0.1 IPv4 UDP tuple, current
namespace dev/inode and boot. Payload EXACT64 bytes; challenge SHA equals payload
hash. Reference SHA is canonical(no LF) `{observation_layer:
'udp_socket_queue_admission',protected_tuple:<tuple>,target:<target>}`.
All identity/count/time scalars are exact non-bool integers. PID/start_ticks/inode/
cookies positive, fd>=0, UID>0, duration 1..5e9ns, max_events 1..16.
Kernel release and /sys/kernel/btf/vmlinux SHA match the frozen plan before/after.
Object physical path uses root-owned0444/singlelink/bounds<=2MiB held-FD rules;
SHA must match plan. Open approved captured ELF bytes with libbpf open_mem, not a
second pathname open. Administrator must build/review this fixed source and pin
object bytes; hashing arbitrary root-selected programs is not source attestation.

## Kernel provider and read-only constraints

Root observer actual effective/permitted/bounding capabilities EXACT BPF(39)+
PERFMON(38), ambient/inheritable zero and NNP1. No SYS_PTRACE, NET_ADMIN, NET_RAW,
recv on target, MSG_PEEK, send, setsockopt on target, setns, commands or file writes.
BPF reads only matching socket/skb data; writes ONLY its own config/pending/events/
stats maps. No target or packet rewrite, drop/redirect or return override. Capability
sets are inherently privileged, not an OS guarantee that arbitrary code is passive.
Trusted code and exact approved object pins remain part of the boundary.

Provider private API `_capture_events(configuration,object_raw)->dict` uses fixed
configuration fields target socket inode/cookie/owner UID/netns cookie/inode,
source/dest IPv4/ports, exact64 payload, absolute start/end and max_events. Root
facade validates and supplies it, never arbitrary callbacks/commands/selectors.
Object has exactly maps config(array1), pending(hash64), events(array16), stats
(array1), and exactly two programs fentry/__udp_enqueue_schedule_skb and
fexit/__udp_enqueue_schedule_skb. No extra programs/data maps. Inspect before load.
Config is written once before attach; only fixed supported map ABI is accepted.

Entry first checks existing skc_cookie (never generate a cookie), socket inode and
owner UID, net_cookie/ns inode, full skb IPv4/UDP tuple, linear skb payload length64
and exact challenge. Enrollment/harness initializes cookies before capture. Copy
all needed values while arguments are valid. Pending key includes opaque sk+skb
pointers, processing pid_tgid and CPU; these pointers never leave the maps. On
existing-key collision delete/invalidate instead of overwriting; count correlation
loss. Exit uses only argument values for lookup plus return value; no dereference.
Collision invalidation is capture-wide and sticky: after correlation loss, no
later event may be promoted, including a third entry interleaved with old exits.
Already published valid events remain lower bounds. Synthetic reference models
exercise these schedules; they are not execution of the kernel BPF program.
Return0 with a complete matching snapshot emits an event; negative return removes
pending and increments rejection. Missing/unpaired/colliding/overflowing events
are loss, never manufactured positives. Bound storage to16 events and pending64.
Attach both programs before traffic; detach before reading final own-map snapshot.
An unpaired tail remains incomplete; preserve already validated successful events.
Absolute monotonic deadline never moves. No old capture is silently resumed.

Provider result exact fields `{started_ns,finished_ns,events,counters,
partial_reasons}`. Events exact fields `{entered_ns,exited_ns,socket_inode,
socket_cookie,netns_cookie,netns_inode,socket_uid,src_ip,dst_ip,src_port,dst_port,
payload_hex}`. Counters exact uint64 keys entry_matches,accepted,rejected,
correlation_loss,overflow. Reasons unique from timeout,event_bound,
correlation_loss,event_overflow,target_lifecycle_changed. Events must match frozen
identities/challenge and entry<=exit within original deadline. No live object is
read at exit. Map ABI/build sizes are asserted in source/loader and tested.

Target PID/start/UID lifecycle is checked through fixed /proc reads before/after;
initial mismatch rejects. A later lifecycle change is explicit partial evidence:
retain valid events for the old frozen socket only, never adopt replacement IDs.
Socket inode/cookie/ns/UID are verified directly by BPF, not inferred from sender
IP or target logs. No aggregate counter alone is a matched event.

## Signed report, evaluator and sealed join

Report exact fields `{schema_version:'edge-udp-queue-report/v1',contract_sha256,
plan_sha256,observation_layer:'udp_socket_queue_admission',kernel_release,
btf_sha256,object_sha256,kernel_boot_id,namespace:{device,inode},capture_id,
started_ns,finished_ns,events,counters,partial_reasons,signature}`.
Use existing Ed25519 helpers and NEW domain
`b'azazel-edge:udp-socket-queue-admission:v1\x00'`; supplied in-memory key must match
the enrolled observer public key. Signature authenticates assertions, not sensor
truth or production key custody. No key files/provisioning.

Evaluation exact fields `{schema_version:'edge-udp-queue-evaluation/v1',status:
'unqualified_udp_queue_diagnostic',observation_layer:'udp_socket_queue_admission',
queue_admission_observed_count:1_or_null,application_delivery_count:null,
qualified_safety_count:null,independently_measured:false,safety_evaluation}`.
Count is one frozen observed opportunity lower bound, not packet count. Empty,
filtered, lost and unavailable are unknown, never zero. Safety evaluation uses the
unchanged evaluator with explicitly absent delivery channels and null heads.
Join returns `{schema_version:'edge-udp-queue-collection/v1',status:
'unqualified_udp_queue_collection',collection,queue}`. Six paths distinct; prior
registration must have empty channels and all four heads null. Cross-bind hashes,
boot and reader identity across full operation; all final fences/close errors block
return. No fallback to interface captures, application logs or synthetic reports.
Target PID/start/UID are lifecycle context; target.fd is enrolled provenance, not
an independently observed receiver-FD mapping. Actual admission is bound by the
kernel socket inode/cookie/owner and namespace, never by the hook's current PID.

## Fixed acceptance stages

Commit this contract and20cases BEFORE implementation. Separate synthetic fixtures
from actual BPF/kernel tests. Actual test target creates its socket after dropping
UID, initializes cookies, then waits without receiving. Separate sender sends only
loopback. Observer has BPF+PERFMON alone and never touches target socket API.
After observer detach, target receives the identical queued datagram as a separate
nonconsumption control. Socket-owned classic filter drop is configured ONLY by
harness before enrollment; filtered/noise/empty controls produce null. Include
restart/new cookie, unavailable permissions/BTF/object, collision/orphan/negative
return/loss/overflow and stale/malformed signed artifacts. CI actual kernel tests
must run without skips; unsupported attach is a blocker, never successful capture.
Run scoped offline regressions, independent review and final full CI before merge.
No security/systemd/installer, enforcement, deployment or production key changes.
