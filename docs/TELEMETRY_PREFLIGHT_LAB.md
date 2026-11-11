# Read-only confined telemetry commissioning

Run this separately reviewed component once on a NEW unused offline marked VM
before freezing four signed-network experiment assignments. It creates no
experiment, capture keys, bundle, journal, witness, normal core, service, traffic
or ledger. A genuine read denial is **commissioning_blocked**, never a failed or
replaced efficacy assignment. The actual pytest may complete while its retained
result says blocked: test completion alone is not a telemetry qualification.

Use existing merged armor-lab staging: reviewed `/opt/edge400-src`, protected
`SOURCE_REVISION`, runtime plus root-owned site-packages `.pth` pathline to
`/opt/edge400-src/py`, reviewed core ELF (hashed, never launched), and protected
`/etc/edge400-disposable-vm` marker. Stage dependencies offline, then remove root
IPv4/IPv6 default routes. Set `EDGE_TELEMETRY_PREFLIGHT=1`,
`EDGE_TELEMETRY_SOURCE_COMMIT`, `EDGE_TELEMETRY_CORE_SHA256`, and
`EDGE_TELEMETRY_ARCHIVE_SHA256` to reviewed pins. The archive SHA is explicitly
an operator trust-boundary declaration: Root must verify the staged archive
out of band; the harness verifies protected revision/module/ELF/source hashes.
Before any output/account/profile mutation, the harness refuses preexisting
exact-unit, prefix and type-wide drop-in material across actual manager unit
search paths (including dangling aliases), and requires the actual full PID1
unified cgroup view. The new output directory is created through a protected
physical root-owned parent descriptor; writable/symlink ancestors refuse.
Run only `tests/test_telemetry_preflight.py` with the staged pytest. Defaults skip
actual commissioning. Actual hardware-free commissioning evidence is recorded below.

Root calls unchanged `prepare_accounts` (fixed locked UIDs61001/2/3, no keys) and
`install_policy` (exact unchanged profiles and protected aliases). It retains
installed profile hash and complete `apparmor_parser -p` expanded-include output
and hash, creates one fresh owned namespace, and adds only dummy interface es.
No host interfaces/routes or external connections are created. The worker uses
the same edge-observe alias, UID61002, enforced edge400-observer label, cap0,
no-new-privileges and AF_UNIX-only unit; Restart=no and bounded runtime are fixed.

A bounded ready/fence handshake lets Root independently pin actual unit PID,
original PID starttime and namespace inode before the worker samples. Before
releasing that sample fence, Root also validates the effective fixed executable
and arguments, UID/group, AppArmor, zero capabilities, AF_UNIX, NNP, Restart=no,
DefaultDependencies=no, runtime/stop limits, slice, namespace path, transient
fragment, absent drop-ins, empty ExecCondition/StartPre/Post/Stop/Post and
restricted activation dependencies. Requested launch flags alone do not pass.
Some systemctl backends omit empty ExecCondition/StartPre/Post/Stop/Post fields.
For only those five fields, a separate fixed-unit typed D-Bus query must return
exact `a(sasbttttuii)` empty arrays; missing/unsupported/nonempty values refuse.
Original systemctl and busctl argv, stdout, stderr and return status are retained
before validation, including partial timeout output. Omission itself never proves
an empty hook. Every other effective property and exact command remains strict. No new
observer proc-stat or namespace permissions are needed. The real
LinuxProcTelemetrySource samples es once. Original sample coverage and separate
actual per-path read errno/size/hash are retained for /proc/net/dev, loadavg,
meminfo and uptime. Separate reads are diagnostics, never substituted samples.
All four actual parsed coverage flags and readable paths are required for ready.
No TrustPolicy, auth scope, recovery or fake telemetry is used.

Cleanup always attempts the fixed actor stop, requires existing merged full
PID1 unified-cgroup view, original/final/canonical group emptiness including
populated descendants, and verifies original process identity. Only then may
owned namespace cleanup run; unknown quiescence retains the namespace for review.
Root rules/routes must match their original snapshot. Keep all raw outputs,
failures and blocked result private; no retry in a used VM. A denial must remain
blocked under unchanged permissions, not prompt capability/profile widening.


## Recorded Ubuntu 24.04 commissioning result

The reviewed runtime source was `37e1e38f4f01729dfc14001dcb250a6740375117`
(archive SHA-256 `a47dd67ce554d360fccafed10cfeef995f3336f147796e0bc7dcade9f172a578`).
A fresh native aarch64 QEMU VM used kernel boot
`edfaa70b-b6b0-42e6-983c-a15269d662f0`. The existing core ELF was hashed but never
launched. All **48 tests passed in 0.57 seconds**, including the actual confined
probe. The probe's retained result is **commissioning_blocked**:

| Actual source | Parsed coverage | Separate diagnostic read |
| --- | --- | --- |
| `/proc/net/dev` | false | `EACCES` (13) |
| `/proc/loadavg` | false | `EACCES` (13) |
| `/proc/meminfo` | true | readable |
| `/proc/uptime` | false | `EACCES` (13) |

The real worker retained UID/group 61002, enforced `edge400-observer`, no new
privileges, zero effective/permitted/ambient/bounding capabilities, and the
verified AF_UNIX-only unit. Profile permissions were unchanged. Test completion
therefore proves the precheck reports the gap; it does not qualify telemetry or
a signed network comparison. No comparison assignments were frozen or consumed.
No keys, bundle, journal, witness, defense process, traffic or service existed.

An independent post-run check verified the unit was collected with zero PIDs,
its canonical full-PID1-view cgroup was empty, namespaces were absent, no capture
bundle/base existed, and the native-core inventory was empty. Root routes/rules
matched the original snapshot. Evidence was archived privately and the VM stopped.
The blocked result remains authoritative under the unchanged profile.

The first fresh precheck, runtime source `bb55e768`, stopped **before** releasing
the sampling fence because `systemctl show` omits empty Exec hook properties.
Its 37 pure tests passed and its actual case failed. Original failure evidence
was retained and that VM stopped without a retry. The correction uses the actual
fixed service's typed D-Bus empty-array proofs; missing fields are never assumed
empty. The successful harness run above used a different source and fresh VM.

## Pending Root-only procfs metadata receipt

A new source adds a Root **stat-only** diagnostic while the actual worker is
blocked at its ready fence, before sample IPC. The path is derived only from the
validated fixed unit's canonical MainPID. Unit state, stable PID/starttime and
owned network-namespace identity must agree before and after lookup; a gap
retains `root-netdev-metadata.json` and refuses sampling. The protected receipt
records requested `/proc/net/dev`, derived/resolved `/proc/<PID>/net/dev` lookup,
UID/GID/mode/device/inode and original identity observations. No file contents,
worker permission, profile, alias, capability or coverage classification changes.
This metadata has **not yet been measured in a VM**. Even a UID match would not
prove an AppArmor owner rule works or self-only mediation; UID 0 must remain an
explicit unresolved owner-rule constraint. Old blocked results remain unchanged.


## Recorded netdev inode metadata (separate fresh VM)

Runtime source `268f1bdd1a035cb841ec575791631a94deee353b`, source archive SHA-256
`b61e1404b3f0e53966fc08b1e31eb28adf798ff70049f8fb12bc823068de1cbd`,
ran once on a different fresh native aarch64 Ubuntu 24.04 QEMU VM with kernel boot
`347657fa-10fe-476a-8a3b-55e37dd1e2d2`. All **63 tests passed in 0.57 seconds**.
The existing observer remained **commissioning_blocked** with the same three
read denials and unchanged profile, alias, capabilities and coverage rules.

While the actual UID61002 worker was held at its sample fence, Root inspected
only `/proc/<verified-worker-pid>/net/dev` metadata. Original, before and after PID
starttime and owned network namespace matched. The regular inode had UID0,
GID0 and mode `0444`. This is a Root metadata observation, not a successful worker
read, owner-qualified AppArmor rule test, self-only mediation proof, or permission
to add a PID wildcard. The retained three proof flags remain false. In particular,
an owner-qualified rule must not be assumed to match the UID61002 worker.

Independent post-run checks confirmed a collected unit with zero PIDs, an empty
canonical full-PID1-view cgroup, absent namespaces, no capture base or native core,
and the retained blocked result. Evidence was archived privately and the VM stopped.
No comparison, keys, authentication scope or new AppArmor policy was created.
