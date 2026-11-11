# Optional telemetry isolation candidate: commissioning blocked

This is a separate lab commissioning candidate. Root's first actual case loaded
the candidate, then blocked before READY and every probe operation because the
protected source reader lacked source-root directory read permission. No candidate
role qualification is claimed; that used VM is retained and never retried. The original confined telemetry result remains **commissioning_blocked**:
netdev/loadavg/uptime EACCES, meminfo readable. Root's later stat-only measurement
found `/proc/<worker-PID>/net/dev` UID/GID 0, regular 0444. It did not test an owner
rule or worker access; never assume that inode belongs to UID61002.

Only new files are introduced. Existing `edge400.apparmor`, its installed roles,
`edge-observe` alias, native/capture/witness permissions and all product/trial
profiles, plans, defaults and schemas are unchanged. This does not authorize a
four-assignment freeze, repair of a used scope, execution, admission or resume.

## Retained v2 failure and narrow mount parser correction

Root's fresh v2 case used source `31adaaa4f275f22e342834982ada3229357fc649`,
archive SHA256 `9ebae8bab927c9a13845943e540d0bc2f90f3b17022418b9454f1a4206e2fcf4`,
boot `6c182cdc-4e92-4ac7-9102-ffe24fa21c7e`. It reached genuine peer READY with
validated UID61002/new enforcing label/zero capabilities/NNP/dumpable identity,
then blocked in the Root mount parser before probe startup or any probe operation.
The parser rejected namespace mount roots such as `net:[4026532228]` because they
are not absolute paths. All actor cgroups/namespaces were subsequently absent and
parent/old assets unchanged; the failed case is archived, stopped and never retried.
Private evidence archive SHA256 is
`0dc5deaa03838c4e6721359f29c2c82ac73d0711d95d4524d28fe5aa0bef0248`.

[Linux 6.8 nsfs_show_path](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/nsfs.c)
renders namespace type plus inode instead of an absolute root path. The parser
now accepts only canonical positive unsigned-64-bit `net:[inode]` roots on exactly
`nsfs`, targeting exactly the two fixed role namespace paths. Other filesystems
retain physical absolute root checks; every target remains subject to physical
absolute path and proc-overlay checks. The four unchanged selected nsfs rows and
actual proc row are regression fixtures, not evidence of completed isolation.
No profile permission, namespace FD grant/proxy or proc visibility/device gate
changes. Fresh commissioning and all actual negative probes remain required.

## Candidate policy and pure contracts

`tests/real_systemd/edge400-observer-telemetry-lab.apparmor` names only the NEW
`edge400-observer-telemetry-lab` profile and NEW protected interpreter alias
`/opt/edge400-runtime/bin/edge-observe-telemetry-lab`. A later Root installer must
verify alias bytes equal the protected installed interpreter; no fallback or
arbitrary alias/profile selection is allowed. The profile copies existing observer
permissions, including its own evidence-directory writes and Root readby access.
It adds:

- `/proc/ r`: **directory metadata/enumeration**, an explicit extra surface;
- read-only loadavg/uptime and numeric-PID netdev paths;
- explicit outgoing ptrace read/trace denial, overriding inherited base permission
  for same-profile reads, and explicit outgoing signal denial;
- a candidate `abi <abi/4.0>,` plus explicit `audit deny userns,` requirement.

The netdev pathname rule is **all numeric PIDs, not self-only**. Its proposed
restriction depends on actual private `ProtectProc=ptraceable` proc mounts and
LSM mediation. Directory enumeration and global loads/runnable tasks/last PID,
uptime/idle are additional information surfaces. Existing global meminfo remains
inherited. None of these metrics establishes a flow-specific effect or causality.
Parser/ABI/kernel userns support is unknown at this stage. Future commissioning
must block on unsupported/downgraded/ignored policy, compile warnings or failed
actual denial; never remove the rule or switch to an unconfined/older ABI fallback.

`telemetry_isolation_contract.py` contains pure local checks, not evidence
collection, caller-JSON authentication, policy loading or an executable entrypoint:

- `role_spec('probe'|'peer')` returns only fixed, separately named unit/namespace/
  alias properties: UID61002, zero capabilities, NNP, AF_UNIX, Restart=no,
  DefaultDependencies=no, 15-second runtime, 3-second stop bound,
  ProtectProc=ptraceable, ProcSubset=all and MountAPIVFS=yes.
- `validate_role_identity(actual, peer)` requires the exact new enforcing label,
  numeric UID/GID61002/capability zeros, dumpable=1 and distinct Pid=Tgid processes.
- `validate_proc_view(...)` requires distinct actor/PID1 mount namespaces, matching
  actual proc device, exactly one full root `/proc` with hidepid=4/ptraceable and
  no group exemption, subset=pid, alternate proc mount or proc submount/overlay.
  Unknown/escaped layouts refuse conservatively. Root must later collect the
  complete target-process mountinfo to EOF within its bound; a supplied string
  cannot establish completeness or effective kernel behavior by itself.
- `validate_pipe_fds(...)` requires exactly descriptors 0/1/2, three distinct FIFO
  device/inode/link identities matching independently collected Root-Popen pipe
  counterparts. Unknown/proc/namespace/socket/file FDs refuse. Actual systemd
  `--pipe` passthrough has not yet been proven for this candidate; a mismatch must
  block, not cause an automatic permissive descriptor exception.

## Required separate runtime review and commissioning

A later reviewed controller must stage a new explicit Root opt-in/source/archive
freeze, old/new source and expanded-policy pins, protected alias and unused names.
Both actors initially do only ready/status/wait, before Root's sampling fence.
Use owned independent edge/foreign namespaces, the same new label and UID for both
actors, distinct stable Tgid/PID/starttime, and dumpable=1 peer. Root must inspect
actual typed effective properties, kernel identity, complete target mountinfo and
FDs before and after probes. No extra actor mountinfo-read permission is needed:
Root collects `/proc/<actor-PID>/mountinfo` independently. Effective properties
alone cannot detect a kernel silently ignoring hidepid.

Actual acceptance requires self four-path telemetry coverage and denial of every
foreign same-UID/same-profile process and Root PID1 netdev/task/root aliases and
enumeration tested by the probe, plus valid ptrace denials. The self exception is
**process/thread group**, not literal thread-only isolation. Targets must remain
alive and identity-fenced before/after each negative so a dead peer cannot supply
a false ENOENT. Ptrace ESRCH/EFAULT/ENOSYS is not permission-denial proof. Preserve
fixed negative canaries for keys, unintended exec, source/stat writes, network,
capability/profile/user-namespace/setns changes and nondestructive signal checks.
No real keys, capture/core, witness, journal or comparison trial is needed.

Missing mount enforcement, visible peer, unexpected FD, unknown feature or any
incomplete negative keeps commissioning blocked. Root must stop and prove both
fixed actor cgroups empty, including descendants, before identity-fenced namespace
cleanup; retain failures/used VM and verify old policy and parent state unchanged.
There is no automatic fallback, retry, role selection or existing-trial wiring.

## Root collector helper chunk (no controller or worker)

`telemetry_isolation_preflight.py` now adds callable Root collectors only. It has
no `run`, worker entrypoint, installation, profile compilation/loading, canary
creation, sampling IPC or automatic trial wiring. `worker_argv` now points only to the committed fixed peer/probe worker for
effective-unit comparison. There is no automatic launcher. Use no command until
the complete source and remaining Root orchestration are frozen/reviewed.

`collect_features(output, expected_abi_sha256=...)` retains current public ABI4
bytes and namespace/ptrace masks before checking an external ABI pin and required
`userns_create`, `read`, `trace` tokens. Root's separate feature-only VM established
these metadata paths exist; the opaque `namespaces/userns_create` value is not
interpreted. Availability is not policy compilation, effective denial or hidepid
qualification. Later actual commissioning must still retain parser/expanded
policy output, reject warnings/unsupported enforcement and execute real negatives.

`collect_effective(mode, output)` uses fixed systemctl/typed D-Bus queries for only
the two literal units. Original argv/stdout/stderr/result files precede parsing.
Absent empty hooks require actual typed empty-array proof, never assumed defaults;
ProtectProc/ProcSubset/MountAPIVFS and all existing authority/dependency checks must
match. Existing collectors have their two-second query bounds; no arbitrary
Root command is accepted by this API.

`collect_actor(...)` reads only fixed actual-unit PID-derived kernel metadata.
It retains status, label, cgroup, complete bounded target mountinfo, namespace
identities, proc owner, finite FD inventory and before/after PID/starttime state,
plus the expected Root pipe/namespace and actual ready dumpable report. A failed
check keeps the originals. Dumpable is the worker's future actual prctl report,
corroborated by Root's proc-directory ownership; it is not invented from a missing
kernel status field. Mount and FD contract checks then refuse drift or unknowns.
The fixed private output must already be physical protected Root-owned 0700.
These helper tests use mocked Root observations; no new role has run.

`canary_spec` describes only PUBLIC NONKEY bytes, four world-readable denial
canaries and one nontruncating source-write canary. It creates nothing. Actual
source-write denial will describe the combined DAC/AppArmor boundary honestly.
The candidate intentionally supplies no namespace FD: a later real namespace-FD
open denial and unshare test must remain distinct from an **unexercised setns
syscall**. Invalid-FD calls are not permission evidence, and no Root FD proxy or
extra namespace-read permission is introduced to manufacture such evidence.

## Fixed-worker operations helper freeze

`telemetry_isolation_operations.py` is a private helper chunk, not a complete
worker or entrypoint. There is still no Root controller, installation or policy
loading. Its tests supply explicitly synthetic syscall returns; they establish
argument/errno/control-flow behavior, not actual permission, hidepid or LSM proof.
The fixed worker performs its real identity/source guard and emits READY before
waiting for a fixed Root frame; no probes precede that fence.

The helper binds typed libc interfaces, validates only fixed peer PID/Tgid/boot
and one-byte public-buffer fields, and bounds a single frame to 16 or 1024 bytes
with a fixed ten-second wait inside the future fifteen-second unit lifetime.
`process_vm_readv` uses actual one-byte iovecs; a later self-read sanity check is
required before the foreign valid public-buffer test. This operation's denial is
not labelled as AA read-class attribution. Ptrace/Yama context must be recorded
by Root later; actual known-live foreign PROC READ_FSCREDS negatives remain
mandatory even if memory-read or trace attempts return EPERM.

Only each fixed operation's specified errno can be recorded as a permission
denial. ESRCH/EFAULT/ENOSYS/ENOENT/EINVAL do not prove a valid peer memory-read or
trace denial; aa_change_profile permits legitimate EACCES or EPERM. Unexpected
success always aborts: close owned file/socket resources, and boundedly reap an
unexpected safe-version child (attempt kill/reap after timeout). If reaping is
denied or fails, retain that fact; it does not pretend no execution occurred.
Root's later all-actor cgroup cleanup remains mandatory. No later probe or
privilege/namespace restoration runs after an unexpected success.


## Fixed peer/probe worker (unqualified)

`telemetry_isolation_worker.py --worker peer|probe` is now the literal worker
entrypoint reserved in Root's expected argv. It cannot install/load policy, act
as Root controller, select arbitrary operations/paths or qualify its own output.
Before READY it requires Linux, the fixed protected source path/bytes, actual
UID/GID61002, zero E/P/A/B capabilities, NNP, new enforcing label, Pid=Tgid=current
PID, dumpable=1 and canonical raw boot. It emits source hash/role/identity markers;
Root's separate frozen archive, marker, effective-unit/mount/FD checks remain
mandatory. The worker does not invent read permission for Root's revision/marker.

Peer keeps a fixed PUBLIC NONKEY buffer alive while waiting only for `stop`.
Probe waits for a bounded fixed-field peer frame, then performs self one-byte
memory-read sanity, actual es telemetry coverage and numeric proc enumeration.
It then runs the fixed known-peer/PID1 direct/task/root-alias open denials,
legitimate valid-public-buffer memory read, trace, public canary read-open,
nontruncating source/stat write-open, safe-version exec, identity/capability/
profile/user-namespace/network-namespace change, namespace-FD open, IPv4/6 socket
and nondestructive signal-zero negatives. Open-for-write is labelled honestly;
no truncate/write payload is used. It executes no defense core. Setns remains
explicitly unexercised without a namespace FD; no invalid-FD call or proxy is used.

Unsupported errors and any unexpected success emit a fatal partial record and
nonzero exit, without proceeding to later probes. Unexpected safe-version exec
is reported as actual execution even if its child exits nonzero. Owned resources
are closed/reaped as supported by the reviewed helper; Root cgroup cleanup still
must prove no surviving descendants. Directory-enumeration failures retain their
partial numeric observations. Final JSON describes observations only, never a
PASS, resume/admission authority, live trial result or AA-only denial attribution.
These tests mock source/kernel/syscall observations explicitly; no actual role,
hidepid/Yama/LSM or complete Root precheck result has been established.

## Controller result-validator component

`telemetry_isolation_result.py` adds pure fixed-frame validation only, before the
Root controller is implemented. `parse_ready` checks a single bounded retained
frame against Root's actual boot/frozen worker SHA, exact role marker and typed
identity/public-buffer shape. `validate_result` requires unchanged canonical
context and the exact ordered 38 operations, legitimate per-operation errnos,
actual complete interface/system sample structure and coverage, self-read sanity,
self-only numeric enumeration and explicitly unexercised setns. Unknown rows,
bool/int/float substitutions, missing observations and partial/fatal results
refuse. No acceptance flags or score are generated. Root must still authenticate
the actual pipe/unit/source/mount/FD and before/after target-liveness bindings;
caller-authored JSON does not become proof through these local checks. Tests use
synthetic frames and the real telemetry parser on synthetic proc text, not a
running role or actual kernel-access result.

## Root staging prerequisites

`telemetry_isolation_setup.stage(output)` is callable code for a later explicitly
reviewed Root run, not an automatic command. It requires the NEW
`EDGE_TELEMETRY_ISOLATION_PREFLIGHT=1` plus the corresponding prefixed
`SOURCE_COMMIT`, `ARCHIVE_SHA256`, `CORE_SHA256`, `ABI_SHA256` pins. Root must
independently verify the source archive on host/guest; revision text is not proof.
The old locked UID61002 account and exact old interpreter aliases/profile must be
staged **externally** with the reviewed old helpers before this function; it
validates them without reinstalling, repairing or reloading old policy. Existing
candidate files/labels/units/drop-ins/names/base/output refuse rather than reuse.

Before any new alias/profile change, staging saves `root-before.json`, baseline
old inode/hash/mode/loaded-label facts, current ABI/mask metadata and Yama context.
It compiles the current protected candidate with warnings fatal before installing
new assets. Exclusive new files and directories use owned no-follow FDs, exact
modes and named-identity checks, never process-umask changes or existing repairs.
All fake canaries contain PUBLIC NONKEY data with newly created traversable
parents. `install-intent.json` precedes alias/profile/canary creation. A successful
fixed Werror load must add exactly the new enforcing label while retaining old
labels; command success is not loaded mediation or role qualification.

Failure retains the used scope, raw compiler/load output, new assets and original
intent. Independent invariant attempts continue through parent-state, old-asset,
new-asset and loaded-profile checks even when one check or evidence write fails.
No actors, namespaces, signer, real keys, witness, journal, trial or qualification
are created by this staging component. Its tests stub Root tools/kernel metadata;
those unit checks do not perform installation, policy loading or candidate access.
The manual controller composes this with both live roles and all cleanup proofs
before returning any complete precheck result; v1 remains blocked as recorded below.


## Manual one-case controller (v1 blocked)

`telemetry_isolation_controller.run(output)` is the only manual Root composition;
it has no CLI or VM/retry engine. Invoke only after complete source freeze,
independent review, explicit new opt-in and externally staged/verified old account,
profile and alias baseline. It calls guarded staging before creating two fixed
namespaces with intent/confirmed identities and dummy es; no traffic or native
core is launched. The private namespace workspace is added to the intended asset
inventory before creation. All heavy setup precedes the fixed 15-second roles.

Peer starts first, then probe. Root records three original FIFO counterparts,
retains READY before strict parsing, and verifies typed effective settings plus
actual source/identity/namespace/proc-view/FD evidence for each role. Only the exact
`{pid,dumpable}` projection reaches the Root kernel collector. Root requires same
UID/label, distinct Tgid/network namespace, stable known-live peer/PID1 before
sending the fixed public-buffer frame, and stable targets afterward before peer
stop. Raw replies, stderr, return codes and actual input-byte counts are retained
before result parsing. Replies have a two-second deadline and finite stream caps;
slow, malformed, missing or oversized output fails without retry or retuning.

The exact transcript is **38 rows: 34 negative attempts**, self-read sanity, actual
sample, enumeration, and explicitly unexercised setns. A complete worker JSON
alone is insufficient. Only after transport/source/kernel/mount/FD/target bindings,
full result validation and every cleanup/invariant gate may the controller return
`new_role_precheck_complete` for this boot/process-thread-group case. It sets
`authorizes_transition=False`, `experiment=False`, `production_admission=False`.
The previous old-profile blocked result is retained and explicitly not retested.

Finally, every fixed actor stop and full-PID1 cgroup/descendant proof is attempted.
Root clients are drained/reaped and their pipes closed before namespace deletion.
`actor-cleanup.json` is separate from reserved
`namespace-evidence/cleanup.json`. Unknown cgroups, failed proof persistence,
unreaped clients or unknown namespace residents prevent deletion; only matching
owned FDs are closed, never reused foreign descriptor numbers. Known empty owned
namespaces can be cleaned after a failed probe while its failure stays sticky.
Parent/old/new-asset/loaded-profile invariant attempts run independently even after
other cleanup or persistence failures. Failure retains raw evidence, named unknown
scopes and the used VM; no partial result or repair/resume path is published.

Controller tests use synthetic Root/namespace/actor observations and real private
stdio echo children only, not hardened candidate actors. No actual profile load,
role execution, hidepid qualification, trial or production admission is claimed.
The three-FIFO rule applies to this stateless precheck only. A signed observer's
journal/sidecar/witness lifecycle needs a separate reviewed pre-API fence design;
do not silently reuse or expand this descriptor contract for that observer.


## Actual v1 refusal and narrow source-directory delta

Root ran frozen source `7271d51c853e608032b8ec71098f41e1a88a5236` on a NEW
unused VM with boot `4d50bb01-b6dd-498b-9de3-4fa21e3138be`. The guest component
checks passed **235 tests in 3.93 seconds**. Actual candidate loading succeeded,
but peer startup failed **before READY and all probe operations**. The protected
`read_regular(SOURCE)` directory walk attempted to open `/opt/edge400-src/`;
Root's retained kernel audit confirms an enforcing new-profile file-class open
denial with requested/denied mask `r`, fsuid61002, ouid0, PID1964. The generic
source/role/boot marker refusal followed the worker's blocked frame; it does not
mean a READY marker or any isolation proof was obtained.

The separate next-source change adds only literal `/opt/edge400-src/ r,` to the
NEW candidate profile. This permits source-root directory metadata/listing needed
by the physical protected-parent walk. It grants no root-level file contents,
write, execute, mmap, arbitrary subtree or source-revision-file permission. Existing
py/tests rules and the entire old profile/aliases/defaults remain unchanged. This
static regression is not actual access proof; a reviewed different source and
NEW v2 VM must repeat current compilation and the complete candidate precheck.

Root verified actor/cgroup/namespace quiescence and parent/old/new-asset invariants
for the failed v1 case, archived original evidence and stopped the VM. The v1
case remains **BLOCKED**, with zero probe operations, no retry/repair and no trial,
resume, admission or claim that either old or new telemetry gate passed.
