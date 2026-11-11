# Optional terminal CONTROL stop: disposable VM proof

This test proves only the optional Python API's handling of an actual signed
normal-core `session_end`. It does not prove measurement completion, resumed
observation, release, service effect, efficacy, or production admission.
The default driver must still refuse the live terminal boundary.

Use two **separately created fresh offline Ubuntu systemd/AppArmor VMs** from an
unused dependency template: one `positive`, one `default-refusal`. Never reuse a
used scope, boot, keys, bundle, failed assignment, or output directory. The
operator must review the combined frozen production API and this helper before
starting either VM case. No test actor has been executed by authoring this code.

Prerequisites are the existing `tests/real_systemd/armor.py --native-core` lab:
Python/crypto dependencies staged at `/opt/edge400-runtime`, source at
`/opt/edge400-src`, reviewed sealed native core at
`/usr/local/bin/azazel-edge-core`, systemd and enforced AppArmor, and the existing
root-protected `/etc/edge400-disposable-vm` marker. Remove external IPv4/IPv6
default routes after staging; no network access, listener, traffic, model,
provider, namespace, or defense action is needed. Stage a root-protected
`SOURCE_REVISION` containing the exact combined 40-character source revision.
Before freezing an unused dependency template, the operator must stage a
root-owned mode0644 `.pth` file in that runtime's **actual site-packages**
(for example `/opt/edge400-runtime/lib/python3.12/site-packages/edge400-source.pth`)
containing only the absolute path line `/opt/edge400-src/py` followed by newline.
Its ancestor directories must be root-owned and not group/other writable. This
is the existing isolated runtime packaging prerequisite, not an environment
fallback: witness and role entry points run with `-I`; `PYTHONPATH` cannot supply
that import. The harness now runs the actual runtime Python with `-I -B`, imports
both reviewed Edge API modules, requires the optional parameter, and verifies
module `__file__` paths are exactly in protected reviewed source, retaining their
hashes. Missing/wrong imports refuse before account/profile setup, preparation,
keys, bundles or actors. `-B` prevents bytecode writes during this precheck.
Never repair and retry either already-used failed scope; retain it and use a new
VM assignment after correcting the unused template.

Keep all artifacts private; raw signed records and source paths are retained.

On each unused VM, set `EDGE_TERMINAL_VM_TESTS=1`,
`EDGE_TERMINAL_SOURCE_COMMIT=<reviewed combined revision>`,
`EDGE_TERMINAL_CORE_SHA256=<reviewed native binary SHA256>`, and
`EDGE_TERMINAL_VM_CASE=positive` (or `default-refusal` on the other fresh VM).
Run only `tests/test_terminal_stop_lab.py` with the staged pytest and source
Python paths. Default CI skips the actual case. The test refuses used base/unit
state and existing worker units before preparation. Never run both cases in one
VM. Preserve failed outputs without retrying their assignment.

The root controller uses existing armor account/profile setup and
`guest.prepare_lab`: authentic fresh synthetic lab provisioning, actual v4
registration and sealed core environment, witness first, then confined UID61002
empty journal initialization. The initializer uses exactly the live API's
policy/interface/sample/budget context. No policy fabrication, journal repair,
backfill, recovery override, key reuse, or unconfined observer is permitted.
`Switch.plan/apply` starts the genuine normal core under the unchanged native
profile. The observer begins after real prepare/start bytes exist, recovers
those as missed, and the controller verifies the exact durable `input_ready`
source-prefix offset/hash before requesting clean core stop. Before that stop,
the controller reads the effective observer unit command, UID/group, AppArmor,
zero capabilities, AF_UNIX restriction, no-new-privileges, explicit Restart=no,
runtime limits and restricted dependencies, then verifies actual kernel UID,
capabilities, enforced label and cgroup membership. DefaultDependencies=no avoids
unreviewed default activation edges; no observer/core/witness activation hook
is accepted.

The positive worker passes only the protected bundle `origin.json` to
`terminal_stop_registration`. After return it independently reads the closed
raw journal and queries the existing witness as UID61002, verifying its signed
reply and exact journal head/size/sequence. Root does not call the role endpoint.
The root controller independently checks original wire and decoded hashes,
lengths, durable missed CONTROL cursor, source tip and private retained bytes.
The default case omits the parameter, retains the original nonzero boundary
failure, emits no receipt, and leaves its cursor before the terminal. No
measurement windows are opened; pending-window loss remains covered by focused
product unit tests.

A signed end alone is not actor quiescence. Cleanup independently attempts all
worker, core and witness unit stops, checks unit states/MainPIDs, retained cgroup
membership and original PID identities, and scans existing core process discovery.
The narrow read-only `terminal_cgroup.py` extraction preserves reviewed signed
network scope semantics: matching PID1 cgroup namespace and canonical full
unified-v2 mount/root/device view, no subtree overlays, physical protected path
walks, empty parent cgroup.procs AND cgroup.events populated=0 (including
descendants). Missing groups count absent only in that verified full view.
Original, final and canonical fixed-unit groups are all checked even after
transient-unit collection. Pre-stop status/PID read errors remain sticky and
never skip any fixed unit stop attempt; each stop is bounded to five seconds.
Cleanup errors are retained even when the original test failure is raised. A
success artifact is written only after cleanup passes. Material and raw failure
evidence remain for operator review and eventual VM disposal; no host policy or
unit removal is attempted by this proof.
