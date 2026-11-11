# Optional telemetry isolation candidate: static stage only

This is a separate lab commissioning candidate. No policy has been compiled or
loaded, no alias installed, no controller/worker implemented and no VM run by this
change. The original confined telemetry result remains **commissioning_blocked**:
netdev/loadavg/uptime EACCES, meminfo readable. Root's later stat-only measurement
found `/proc/<worker-PID>/net/dev` UID/GID 0, regular 0444. It did not test an owner
rule or worker access; never assume that inode belongs to UID61002.

Only new files are introduced. Existing `edge400.apparmor`, its installed roles,
`edge-observe` alias, native/capture/witness permissions and all product/trial
profiles, plans, defaults and schemas are unchanged. This does not authorize a
four-assignment freeze, repair of a used scope, execution, admission or resume.

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
