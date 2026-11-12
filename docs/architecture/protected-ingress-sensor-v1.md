# Protected interface ingress sensor v1 — #400 / #393

## Frozen scope and trust boundary

Collect actual packets in offline virtual Linux using one passive AF_PACKET
SOCK_RAW socket bound to lo, IPv4 UDP 127.0.0.1 only. AF_PACKET sees ingress before
protocol handling and potentially before firewall rejection. Therefore introduce
an explicit interface_ingress report/schema/domain; NEVER convert it to an old
protected_escape delivery fact. No UDP/application receipt, actual defense escape,
Source authentication, cleanup, physical bypass or safety qualification is proved.
The existing delivery/safety evaluator receives no delivery observations and stays
unknown/null. Its existing v2 gate remains closed.

The sensor is trusted code running as root with CAP_NET_RAW only, zero inheritable
and ambient capabilities, and NoNewPrivs=1. Validate actual /proc/self/status before
and after. CAP_NET_RAW itself ALSO permits transmission: this is code-level
passivity, NOT a kernel-enforced receive-only capability. No send/sendto/sendmsg,
connect, IP socket, promiscuity, setns, ioctl, BPF, command or target mutation occurs.
Only the separate lab harness creates/sends UDP traffic and the disposable target.
No installed services, keys, enforcement profiles or network settings are changed.
Sign with an already supplied in-memory Ed25519 key matching the enrolled observer
public pin. No key paths/provisioning. Root/signer truth remains trusted, not proved
by signatures. Unprivileged producers/readers cannot obtain root registration or
CAP_NET_RAW. Reports do not identify the packet sender's UID from an IP address.

## Fixed API and bounded formats

Module `azazel_edge.benchmark.protected_ingress`:
`capture_protected_ingress(contract_raw,plan_raw,*,expected_contract_sha256,
expected_plan_sha256,observer_private_key)->bytes` returns a signed canonical
report after closing the capture socket. `SafetyIngressError(ValueError)` means
no result. Use strict existing canonical JSON+one LF, duplicate/type/depth guards;
contract <=128KiB, plan <=16KiB, report <=32KiB. No arbitrary callbacks/selectors.

Plan exact fields: `{schema_version:'edge-protected-ingress-plan/v1',
contract_sha256,opportunity_id,interface:'lo',observation_layer:'interface_ingress',
challenge_payload_hex,max_packets,max_matches,max_duration_ns}`.
One protected_escape opportunity is frozen; all other opportunity lists are empty.
Its tuple is exact IPv4 127.0.0.1/UDP, nonzero ports and actual namespace dev/inode.
The challenge hash is SHA256 of the exact 16..64 byte payload. The reference hash
is SHA256 of canonical JSON (no LF) of `{observation_layer:'interface_ingress',
interface:'lo',protected_tuple:<frozen tuple>}`. This machine-binds the layer.
This is a boundary challenge context, not proof of Source-byte authenticity.
max_packets is exact int 1..128; max_matches 1..16 and <=max_packets;
max_duration_ns 1..5_000_000_000. Capture must start within the frozen opportunity
window, using the original absolute deadline min(start+duration,window end).
No waiting/retiming of an out-of-window capture and no deadline extension.

Validate fixed /proc boot ID and current /proc/self/ns/net dev/inode, root role,
capabilities, interface index before and after. A change rejects, even if partial
packets existed. No peer UID is inferred from a packet. Pin the interface index.
Accept only Linux Ethernet-style 14-byte framing, ARPHRD_ETHER(1) or LOOPBACK(772),
PACKET_HOST(0), EtherType IPv4, version4/IHL5, consistent complete IP/UDP lengths,
no options/fragments/VLAN/IPv6, exact tuple and exact payload. No checksum validity
or application delivery claim (offload may affect checksum bytes). recvmsg <=2048
bytes; MSG_TRUNC/unsupported packets are diagnostic only. Both actual monotonic
receive brackets must lie within the opportunity window. Hash original frame bytes.

Report exact fields:
`{schema_version:'edge-protected-ingress-report/v1',contract_sha256,plan_sha256,
kernel_boot_id,namespace:{device,inode},interface:'lo',ifindex,capture_id,
observation_layer:'interface_ingress',started_ns,finished_ns,frames_seen,
matches:[{frame_sha256,observed_before_ns,observed_after_ns}],partial_reasons,
stats_before,stats_after,signature}`.
Capture ID equals the frozen protected channel. Stats are null or exact
`{packets,drops}` uint32 snapshots. PACKET_STATISTICS reads RESET counters; retain
both snapshots, never subtract. Drops/unavailable stats/receive failure do not erase
already valid matches. Match count <=max_matches; frames_seen <=max_packets.
Partial reasons are unique strings from timeout, packet_bound, match_bound,
packet_truncated, unsupported_frame, stats_unavailable, kernel_drops, receive_error.
Report signature uses existing input_auth.sign/verify_signature over report WITHOUT
signature, NEW domain `b'azazel-edge:protected-interface-ingress:v1\x00'`.
No fabricated open/begin/end/close rows, delivered:false facts or complete coverage.

## Evaluation and sealed read-only join

`evaluate_ingress_capture(contract_raw,plan_raw,report_raw,*,
expected_contract_sha256,expected_plan_sha256)->dict` authenticates the explicit
layered report. It returns schema_version edge-protected-ingress-evaluation/v1,
status unqualified_ingress_diagnostic, observation_layer interface_ingress,
interface_ingress_observed_count (1 if any admissible match else null),
qualified_safety_count null, independently_measured false, and safety_evaluation.
The count is a lower bound of observed frozen opportunities, NOT delivery/safety.
The safety_evaluation is the unchanged evaluator applied to an explicitly empty
DELIVERY-channel envelope: no delivery sensor was used. All four safety counts are
null and all authority flags false. Never zero even when capture runs without loss.
No caller-supplied complete/independent boolean can upgrade this result.

`collect_protected_ingress(enrollment_path,plan_path,report_path,*,
expected_enrollment_sha256,expected_checkpoint_sha256,expected_plan_sha256,
expected_report_sha256)->dict` joins the existing registered collection and ingress
evaluation, returning `{schema_version:'edge-protected-ingress-collection/v1',
status:'unqualified_ingress_collection',collection,ingress}`.
Require root-sealed plan/report files using the prior held-FD helper and all its
0444/owner/ancestor/path/race/close guarantees. Hold enrollment/contract/plan/report
through join and final checks; all six paths distinct and externally bound. Existing
registration must contain an EMPTY channels map, representing no delivery sensor;
checkpoint four heads must all be null. The joined contract hashes must match.
No external digest is derived from a file to approve that same file.

## Acceptance stages fixed before code

Commit this document plus the 20 frozen cases first. Unit parser/crypto/race tests
are synthetic. Actual isolated Linux tests require separate unprivileged UDP
sender/target processes, root passive sensor with only NET_RAW+NNP, and nonroot
registered artifact reader. Confirm positive real ingress, unrelated/no traffic
unknown, no matching packets after deadline, permission denial without NET_RAW,
and end-to-end root sealing/pinned read-only join. Sender sends only loopback; no
external network or installed defense process. Record actual versus synthetic
provenance and run tests in CI without skips. Independently review final diff and
full CI before merge; defer actual protected UDP/app receipt and Pi/HIL to later gates.
