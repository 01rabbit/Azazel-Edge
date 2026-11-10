# Confined real-provider virtual commissioning

Tracking: #400. This opt-in, marked disposable-VM slice exercises the **existing**
normal defense executor and signed live-origin path. It installs no production
policy, service, key, route, enforcement default or new command endpoint.
The native sealed bootstrap and v4 registration remain as documented in
[outcome-service-confinement.md](outcome-service-confinement.md).

## Permission and responsibility matrix

| Component | Necessary permission | Boundary |
| --- | --- | --- |
| Operator's fixed namespace-preparation unit | SYS_ADMIN and NET_ADMIN, only in the marked VM | Creates two new named namespaces and their sole veth pair; no existing namespace/route/table mutation. Source is protected, no caller-supplied argv. Preparation refuses existing names. This is not a runtime capability grant. |
| Launcher / native | Existing root capability bound 0x10c4; no ambient caps; no-new-privs, existing device/kernel/namespace restrictions | The native independently verifies its actual fully sealed memfd, enters registered `edge400-provider (enforce)` before configuration, and retains its singleton. Neither SYS_ADMIN nor MAC_ADMIN is added. |
| nft and conntrack subprocesses | Exact trusted `/usr/sbin/{nft,conntrack}` execution with `ix` inheritance; NET_ADMIN; netlink raw/datagram; minimum binary/library reads | Same enforcing policy as the native, fixed trusted binary resolution, cleared environment, existing argv validation/time/output bounds and ownership/readback checks. No shell, `ip`, arbitrary exec, policy change or key/evidence access. |
| Native decoy precondition | IPv4 stream creation in the isolated edge namespace | Existing `getifaddrs` and TCP reachability probe require netlink and local IPv4. Neither precondition is bypassed to make enforcement succeed. No IPv6 permission is added. |
| Signer | Existing separate UID/GID, no groups/capabilities, capture AppArmor | Its own irreversible Unix-only socket-creation filter is applied before signing key/writer access. Parent provider socket allowances are not inherited as effective creation permission. |
| Witness / observer / AI | Existing roles and permissions | No provider binary, NET_ADMIN or network-family grant is added to these roles. |

AppArmor does **not** constrain nft's argv, a netlink request to one table, or
an IPv4 socket to one destination. The reviewed Rust planner/runner and kernel
remain trusted. The lab limits the reach of provider authority by requiring the
native's actual network namespace to equal the prepared edge namespace and to
differ from PID1. Both lab namespaces have no IPv4/IPv6 default route and their
only non-loopback links connect to each other. The driver itself has no default
route. Parent network routes and rules are not altered; namespace preparation
independently checks the parent's nft ruleset structure is unchanged (live counter values are excluded). This is offline
local testing, not admission for an arbitrary routed production namespace.

The policy is `tests/real_systemd/edge400-provider.apparmor`, separate from the
read-only native fixture. It grants no `tc` execution: legacy TBF recovery is a
separate target-policy gate, never silently granted merely because its binary
resolver exists. Production artifacts, target policy semantics, legacy leases,
local IPC/broker mediation and root/kernel compromise remain separate gates.
`ix` is intentional: provider children do not escape to an unconfined domain.
There are no disconnected-path flags or mutable copies of the native image.

## Signer socket boundary

`socket_boundary.unix_only` adds a thread-synchronized seccomp filter after the
existing identity/capability/no-new-privileges checks and before key access.
It admits socket/socketpair creation only for AF_UNIX, rejects other families
with EPERM, blocks io_uring setup/enter/register as an alternate socket-creation
path, validates the audit architecture, and blocks the x32 syscall convention.
All existing threads synchronize to the restriction; a failed installation or
unsynchronized TID refuses startup. There is no listener, supervisor helper or
runtime dependency installation. Unknown ABI/non-little-endian/unavailable
filtering refuses; the supported native targets are Linux x86_64 and aarch64.

This is a **socket-creation** boundary, not universal IPC/FD isolation. It does
not invalidate an already open descriptor. The existing trusted launcher still
closes unrelated descriptors and supplies only the registered private Unix
reporting channel; the receiver verifies its root parent/peer before key use.
The filter persists across subsequent execution and cannot be relaxed. Real
Linux controls prove NETLINK_ROUTE creation works before restriction for the
same unprivileged UID, then fails with EPERM in both the main and an already
running thread. Unix socketpair transfer still works. The test does not infer
network denial merely from a restrictive parent unit or AppArmor label.

## Reproduction and acceptance

Use `tests/real_systemd/provider.py PHASE --allow-disposable-vm` in a **new** VM,
following the protected runtime/source/key staging and VM guards of the existing
[systemd protocol](outcome-systemd-vm.md). Prestage nftables, conntrack, iproute2,
AppArmor and optional pinned input-auth dependencies before going offline.
Phases are prepare, exercise, boot-check, bad-boot-check and smoke-finish (CI).
The fixed root preparation unit is a lab artifact and is not a product installer.
Its namespace phase deliberately runs in the manager's mount namespace so the
namespace handles are visible to services; its only network operations address
the two fresh lab namespaces. Runtime and test-driver offline checks remain
mandatory. Inspect the effective units, actual labels/caps and namespace inodes.

The explicit new scope pins full-auto/30-second leases and the provider profile;
used registrations are never rewritten to switch enforcement modes. A separate
sealed, confined `capture-origin-once` calculation first proves zero executed
commands, unchanged kernel/source, and remains **read-only calculation**, not a
signed execution receipt. Normal execution then uses the existing service switch,
real core -> private Unix channel -> separate-UID signer.

Acceptance checks:

- Existing ordinary core, signed launcher and repeated manager starts cannot
  create another native process for the same state; actual image seals/label,
  capabilities, namespace identity and witness-before-launch ordering hold.
- Synthetic current alerts produce actual owned throttle and redirect rules.
  Signed normal-path results report one successful command only after native
  readback; independent operator readback checks owner, complete flow, ingress,
  redirect port and exact rate/burst semantics. The input chain stays empty.
- An isolated client receives DECOY for the scoped redirect and REAL for its
  control; the owned connection has the expected conntrack mark. These are
  bounded lab packet controls, not comparative operational benefit/Outcome.
- Removing nft execution permission while owned state exists produces an honest
  failed apply and retry-pending/verified-false release. Independent readback
  confirms the rules still exist. No false applied/released/absence fact follows
  a denied command or unreadable state. Only exact original policy restoration
  allows the existing bounded retry/owned cleanup, without evidence repair.
- Successful releases have verified absence; marked conntrack entries disappear,
  unrelated conntrack controls and foreign rules remain, and traffic returns to
  REAL. No source-wide automatic isolation or indiscriminate deletion is added.
- Clean restart/reboot preserves history; downtime input is not replayed. Missing
  profile, changed/withheld registration and invalid verification refuse before
  connected start/evidence append. A second reboot with unregistered origin
  refuses reconnect. The public-key observer does not fabricate Outcomes.

CI adds a mandatory real-systemd provider matrix job alongside baseline,
role-AppArmor and native-AppArmor. CI uses a private driver network and never
reboots the hosted runner. Actual OS reboot evidence comes from the dedicated
local VM; physical Pi/storage/power-cut/resource/hostile-load and independent
comparative-effect gates remain open. Failed fixtures and evidence are retained;
no missing observation is filled in or promoted to execution/effect proof.
