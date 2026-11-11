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
Run only `tests/test_telemetry_preflight.py` with the staged pytest. Defaults skip
actual commissioning. No execution has been performed by authoring this code.

Root calls unchanged `prepare_accounts` (fixed locked UIDs61001/2/3, no keys) and
`install_policy` (exact unchanged profiles and protected aliases). It retains
installed profile hash and complete `apparmor_parser -p` expanded-include output
and hash, creates one fresh owned namespace, and adds only dummy interface es.
No host interfaces/routes or external connections are created. The worker uses
the same edge-observe alias, UID61002, enforced edge400-observer label, cap0,
no-new-privileges and AF_UNIX-only unit; Restart=no and bounded runtime are fixed.

A bounded ready/fence handshake lets Root independently pin actual unit PID,
original PID starttime and namespace inode before the worker samples. No new
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
