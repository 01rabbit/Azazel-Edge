# Legacy tc recovery: confined virtual commissioning

Tracking: #400. This is an optional software/VM recovery slice, using synthetic
keys and explicit legacy ledger fixtures. It does not enable new tc applies,
production policy installation, physical acceptance or retrospective telemetry.
The [sealed native bootstrap](outcome-service-confinement.md) and
[signer socket boundary](outcome-provider-confinement.md) remain mandatory.

## Necessary permissions and authority

`tests/real_systemd/edge400-tc.apparmor` is a separate named policy for an
explicitly enrolled v4 scope. It permits the fixed trusted `/usr/sbin/tc` with
`ix` inheritance, required libraries/plugins, read-only `/proc/PID/net/psched`,
NET_ADMIN and Unix/netlink raw/datagram sockets. No nft, conntrack, shell,
arbitrary binary, policy change or IPv4/IPv6 permission is added. AppArmor stays
enforcing; no disconnected-path flag or mutable copy replaces the native's
anonymous root/0500 ELF with all four irreversible seals.

The native still uses the existing root capability bound 0x10c4, no ambient
capabilities and no-new-privileges. Only an operator-only lab setup unit receives
SYS_ADMIN/NET_ADMIN to create one fresh no-uplink namespace and new dummy links.
The native's actual namespace must equal that namespace and differ from PID1.
The setup checks the parent's qdisc configuration is unchanged. Its privileges
are not passed to the native, signer, witness or observer. The source, units,
aliases and state parents remain protected. Named accounts, key separation,
actual-label probes, witness readiness and the singleton remain unchanged.
The signer independently denies non-Unix socket creation even though its parent
allows netlink; witness/observer policies and families are not expanded.

The existing trusted binary resolver and runner keep fixed directories, cleared
environment, explicit argv validation, time/output bounds and no shell. AppArmor
cannot constrain tc argv to one interface/handle. The reviewed Rust runner,
protected ledger, root/code/policy and kernel remain trusted; the dedicated
namespace bounds this lab's authority. This profile is not admission for a shared
production interface or a namespace with an external route.

## Ownership and readback rule

A legacy throttle has an empty mechanism field and a `tc:root:IFACE` resource,
owned major handle, expected TBF rate/burst/latency and a durable lease. It is
recovered/released by the existing normal Rust process even when current new
applies are disabled/dry-run. No alternative recovery executor is introduced.

Before a root delete, the complete `tc -j qdisc show dev IFACE` result must be
unambiguous. A matching handle must be the root TBF and match the existing
bounded parameter tolerances. A different handle is not deleted. A same-handle
wrong kind or parameters remains retry-pending. After deletion, owned absence
must read back before a released fact is recorded. A command's exit status or
lease expiry alone is insufficient. Verified owned absence does not mean the
interface has no foreign qdisc.

A root delete also deletes attached descendants. The release guard now refuses
an explicit child qdisc under the owned major, regardless of array order, rather
than destroying a subtree the legacy lease never owned. Duplicate roots,
malformed identities or unknown parent topology likewise refuse; they cannot
be interpreted as verified absence. A separate clsact/ingress hook is outside
the root subtree and must remain unchanged. No extra mutation command or
readback fallback is added.

A newer active root owner supersedes the older task without deleting its state.
Existing newer prepared/uncertain same-handle ambiguity still defers the older
release. The major handle is a finite marker, not cryptographic ownership.
Identical same-handle replacement by an outside privileged writer cannot be
identified from readback alone, and read/check/delete is not a kernel compare-
and-swap. Production provenance/exclusive-writer coordination remains an
operator gate; this slice makes no claim against malicious/concurrent root.
Unknown layouts or unverifiable ownership must remain pending, not be repaired
by rewriting someone else's qdisc, ledger or signing history.

## Reproduction, fixtures and acceptance

Prestage Ubuntu 24.04, AppArmor, iproute2, the exact core and protected Python
runtime with pinned optional input-auth dependencies before going offline.
Use a fresh VM with the existing destructive marker/root/PID1/VM guards and no
default routes. Run
`tests/real_systemd/legacy_tc.py PHASE --allow-disposable-vm`, with phases
prepare, exercise, boot-check, bad-boot-check, smoke-finish. CI uses a private
driver network and does not reboot its runner. Namespace preparation runs in
the manager's mount namespace so its protected namespace handle is visible to
services; its operations address only the new named lab namespace/links.

Preparation enrolls a new v4 tc profile; current automatic enforcement remains
disabled/dry-run. The initial signed handoff is commissioned with an empty
ledger. The core is stopped cleanly, the shared lifetime lease is acquired,
and the operator fixture creates a new v1 ledger and two owned TBF roots. The
original fixture is retained. No unconfined core sees these tasks; no used
source/journal/anchor/ledger is reset. Subsequent v1->v2 migration, unconfirmed
startup recovery, reads, deletes, retries and signed facts come from the normal
sealed core, not Python computations or replay.

The nine explicit tasks/control interfaces cover:

- matching prepared/active owned roots: actual delete and independent absence;
- absent owned handle and an identical TBF with a different handle: zero deletes,
  owned-absence evidence and foreign configuration preserved;
- same handle with a foreign kind or changed parameters: readback failure, retry,
  no delete or false released fact;
- exact root parameters with a foreign child: refusal and unchanged whole tree;
- newer active same-handle owner: older task superseded without mutation;
- independent clsact/ingress classifier: retained when the owned root is removed.

The driver first removes tc execution permission without relaxing the profile.
Real denied readback must leave all configuration unchanged and produce only
unverified/retry facts. Restoring the exact lab policy permits the existing
bounded retry only where ownership is verifiable. Foreign controls are never
removed to make a test pass. They remain unchanged through service restart and
are explicitly reconstructed by the operator setup after an OS reboot; released
owned roots are not reconstructed. This distinguishes kernel reset from a
runtime deletion or replay.

Also require actual image seals, enforcing labels, caps, namespace identity,
normal/signed/manager duplicate exclusion, signer socket controls, readiness
ordering, registered reboot/history continuity, independent observer recovery,
downtime exclusion, and no-append refusal for missing profile/changed/withheld
registration. A second OS reboot with withheld registration refuses reconnect.
Retain all evidence and failed fixtures; disable lab services and stop the VM.

The current nft/conntrack profile does not silently gain tc permission. CI has a
separate mandatory legacy-tc matrix job alongside the prior four profiles.
Physical Pi/kernel/package policy, resource/hostile-load behavior, sudden power
loss/storage durability/wear, general IPC mediation and comparative benefit stay
separate #400/G6 gates. No missing observation, Outcome or effect is fabricated.
