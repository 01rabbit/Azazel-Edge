# Optional lab telemetry isolation: completed v6 precheck, limited scope

Root completed one fresh offline v6 precheck of the separately named lab role.
Both actual confined roles passed source, identity, proc-view, original three-FIFO,
namespace and endpoint checks. The probe retained all **40 ordered rows: 36 actual
negative attempts and four other observations**, including explicitly unexercised
setns. All four telemetry coverage fields were true. Known-live peer/PID1 checks
completed before and after the probe. Peer stop, actor/cgroup/namespace cleanup,
Root-client reaping without force and parent/asset/profile invariants completed.
The VM is stopped and its original evidence retained privately.

The result is `new_role_precheck_complete` for this boot and this stateless
self-process/thread-group case. Its `authorizes_transition`, `experiment` and
`production_admission` flags are **false**. This is not a signed observer join,
production admission, efficacy result or authorization to reuse the VM.
The old profile's three EACCES results remain blocked and **were not retested**.
The four-assignment signed experiment remains unfrozen and blocked.

## Exact tested evidence boundary

| Material | Immutable identity |
| --- | --- |
| Tested source | `d006f858b4b20948ef3e5c2ebd8ce949f88ef197` |
| Source archive SHA256 | `2ee0c603a5b24c4f7333b8ba7527a0ada13eff92493d6baefad74d9c52160953` |
| Candidate profile SHA256 | `7c6f00d088053b1f347cecaf3750f644c578e85b9199a11675810f27c52e40be` |
| Kernel boot UUID | `095d28ff-ca7d-4b08-9e4b-e36a62db4810` |
| Completed private archive SHA256 | `d88c1f436a3f40186c7ffc73319363c89369b582a676e41bea68955025d2f1c8` |

The guest component checks passed **343 tests in 4.06 seconds**. These unit checks
are distinct from the actual two-role precheck above. This documentation commit
was written afterward; it does not retroactively become the tested source.
The private archive is 245760 bytes, mode 0600. Do not publish whole mount/process
context, public-buffer addresses or unrelated operator evidence as a substitute
for the bounded facts. No real signing keys were provisioned or read.

## Separate role and explicit permission boundary

The new profile is `edge400-observer-telemetry-lab`, attached only to the protected
byte-identical interpreter alias
`/opt/edge400-runtime/bin/edge-observe-telemetry-lab`. The old `edge400.apparmor`,
old aliases/defaults, native/capture/witness permissions and existing experiment
plans are unchanged. New setup is explicit Root opt-in, never automatic activation.
The role inherits existing observer permissions, including its own evidence-folder
writes and Root readby access; it does not grant capabilities or key access.

Additional read surfaces are source-root directory metadata, `/proc/` directory
metadata/enumeration, global loadavg/uptime and numeric-PID netdev paths. The
netdev pathname rule covers **all numeric PIDs**, not self alone. Isolation depends
on the actual private `ProtectProc=ptraceable` proc mount plus explicit outgoing
ptrace read/trace denial, including same-profile peers. Explicit outgoing-signal
and user-namespace denials remain in the new ABI4 profile. Unsupported compilation,
warnings or missing feature classes refuse; there is no ABI/profile fallback.

The scope is **self process/thread group**, not literal thread-only visibility or
an entirely self-only proc filesystem. Global loads/runnable-task/last-PID,
uptime/idle and inherited meminfo are disclosed additional information surfaces.
These broad metrics establish no flow-specific effect or causality. Denials
reflect the combined kernel/DAC/LSM/unit boundary; the transcript does not establish
AA-only causation. In particular, valid user-namespace and signal-zero EACCES
observations are permission denials without an AA-only attribution claim.

## Manual API and fresh-case procedure

`telemetry_isolation_controller.run(output)` is the manual Root composition.
There is no generic CLI, VM/retry engine, dynamic role/command/path selector or
existing-trial wiring. Its supporting contract, preflight, setup, worker, operations
and result modules all live under `tests/real_systemd/`. Caller-authored JSON and
pure validators do not authenticate an imported precheck.

1. Freeze and independently review the complete source. On a new unused offline
   marked VM, Root externally verifies archive SHA on host and guest, extracts
   protected source and writes the exact revision marker. Revision text alone is
   not cryptographic proof of the archive. Verify the fixed interpreter/core and
   isolated imports; stage the exact old account/profile/alias baseline externally.
   The controller validates that baseline without repairing or reloading it.
2. Supply `EDGE_TELEMETRY_ISOLATION_PREFLIGHT=1` and the corresponding prefixed
   `SOURCE_COMMIT`, `ARCHIVE_SHA256`, `CORE_SHA256`, `ABI_SHA256` pins. Call the
   manual function with a new protected private output path. Existing output,
   base, candidate alias/profile/label, units/drop-ins or namespace names refuse.
   The case contains PUBLIC NONKEY canaries only; no auth scope, signer, journal,
   witness, capture/core execution, benchmark workload or registered trial is created.
3. Guarded setup records Root parent state and old asset/loaded-profile facts
   **before** candidate mutations. It records current ABI/feature/Yama evidence,
   compiles the current protected profile with warnings fatal, then exclusively
   installs only new assets and loads exactly the new enforcing label. Preserve
   raw compiler/load output. Command success alone does not prove mediation.
4. Before each file/directory/namespace creation, retain intended inventory or
   creation intent; immediately retain confirmed owned-FD identity. Never change
   process umask inside creation helpers, repair preexisting modes, predelete names
   or reuse unknown handles.
   Every intended path is inventoried even after partial creation/load failure;
   missing, partial or unknown objects cannot be reported as unchanged/clean.
5. Create only the two fixed owned namespaces and dummy `es` interface. Finish
   heavy setup before starting the fixed fifteen-second roles. Peer starts first,
   then probe, each via Root-owned three-pipe `systemd-run` client. The peer exposes
   one stable PUBLIC NONKEY buffer. Both roles initially guard, emit READY and wait;
   the probe performs no operation until Root's bounded fixed-field IPC fence.
6. Bind original READY/source bytes, typed effective unit properties and actual
   kernel/process/mount/FD evidence for both roles. Require same UID61002/new label,
   cap E/P/A/B all zero, NNP, AF_UNIX, dumpable1, distinct Pid=Tgid and distinct
   owned network namespaces. Check known-live peer/PID1 before IPC. Retain exact
   consumed READY prefix before parsing, including oversize/failure prefixes.
7. Send only the fixed peer PID/Tgid/boot/public-byte fields. Retain original reply,
   stderr, return code and actual input count before validating all ordered rows.
   Reply/readiness deadlines stay two seconds, fence ten seconds, runtime fifteen
   seconds; slow/incomplete output fails without retry or threshold retuning.
   Recheck live peer/PID1 and endpoint identities after probing, then stop peer.
8. Independently attempt all actor stops and full-PID1 cgroup/descendant emptiness
   proofs. Drain/reap every owned Root client, close its pipes and prove no unknown
   namespace residents before identity-fenced namespace deletion. Forced reaping
   remains a sticky failure. Unknown layout, lost proof or replaced handles retains
   scopes. Only matching owned FDs may close; never close a reused foreign FD.
9. Independently attempt parent network, old/new asset and loaded-profile checks
   even after another cleanup or evidence-write failure. Keep `actor-cleanup.json`
   separate from reserved `namespace-evidence/cleanup.json`. Only complete proof
   plus cleanup yields the limited result; failure retains originals, new assets
   and the used VM without repair, unload, retry, backfill or partial qualification.

## Actual proc, FD and API checks

Root retains complete bounded actor mountinfo, not its own view. Require distinct
actor/PID1 mount namespaces and exactly one full-root `/proc` on the actual proc
device, hidepid4/ptraceable, no group exemption or subset=pid. Effective unit
properties alone cannot establish kernel enforcement. All proc aliases, overlays
and other submounts refuse, with only the following two typed exceptions:

- [Linux 6.8 nsfs_show_path](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/nsfs.c)
  emits namespace type/inode roots. Only canonical positive unsigned-64-bit
  `net:[inode]` on filesystem `nsfs` at the two exact fixed owned role namespace
  paths is accepted. All targets retain physical absolute-path checks; all other
  filesystems retain physical absolute-root checks. This grants no namespace FD.
- At most one exact filesystem/source `binfmt_misc`, root `/`, target
  `/proc/sys/fs/binfmt_misc`, parent-bound to the validated private proc mount ID.
  The NEW profile explicitly denies directory/subtree read/write/execute. Root
  stat-only checks require stable root-owned regular `status`/`register` endpoints
  in both actor views, repeated before/after collection and in peer live checks.
  Worker nontruncating/nocreate/nofollow/cloexec opens must deny. Neither Root nor
  worker reads control payloads, registers/toggles formats or masks/unmounts the
  inherited parent API.

Exactly FD0/1/2 must be distinct FIFOs matching the independently retained Root
Popen counterparts by device/inode/link. No proc/namespace/socket/file/unknown FD
is permitted. Original source/identity context remains unchanged through replies.

The forty rows comprise real self memory-read sanity, actual four-path sample,
numeric proc enumeration, unexercised setns and thirty-six negative attempts:
foreign same-UID/same-profile peer and Root PID1 direct/task/root-alias opens,
valid-public-byte memory read, ptrace, public canaries, nontruncating source/stat
and binfmt opens, safe unintended exec, credential/capability/profile/userns/netns
changes, namespace-FD open, IPv4/6 sockets and both nondestructive signal-zero
checks. Setns is **unexercised**, without a valid namespace FD or Root FD proxy.
Known-live target checks prevent a dead peer from supplying false hidden evidence.

Only each exact operation's errno allowlist is accepted. Userns and signal zero
accept EACCES/EPERM; netns remains EPERM-only. Missing/unsupported/partial/fatal rows,
nonfinite or bool/int/float substitutions refuse. Any unexpected success closes
owned resources/reaps an unexpected safe child and aborts immediately, without
later probes or privilege restoration. A started child is actual execution even
if it exits nonzero. Sample network counters/memory values are integers; load and
uptime are finite nonnegative floats. Pure tests use declared synthetic fixtures;
only v6 above provides the complete actual case at its exact tested source.

## Preserved failed predecessors

Every case used a different fresh VM/boot and was stopped without same-scope
retry. Failures remain failures; later changes do not relabel old evidence.
Root verified actor/cgroup/namespace quiescence and parent/old-asset invariants.

| Case | Tested source | Boot UUID | Retained failure |
| --- | --- | --- | --- |
| v1 | `7271d51c853e608032b8ec71098f41e1a88a5236` | `4d50bb01-b6dd-498b-9de3-4fa21e3138be` | Source-root directory read denied before READY/probes; exact directory metadata grant added only in later source. |
| v2 | `31adaaa4f275f22e342834982ada3229357fc649` | `6c182cdc-4e92-4ac7-9102-ffe24fa21c7e` | Valid peer READY, then typed nsfs root rejected; zero probe operations. |
| v3 | `906d06fcb0205f2176e3002cf0a299cad3054580` | `4fae818f-3ca8-41cb-a44c-9b6bec2d2795` | Valid peer READY, then inherited binfmt child rejected; zero probe operations. |
| v4 | `491acb02a92a567bc1234eedc5e5e320f3bac6e1` | `f15ad7fa-672b-4695-91b5-c8cca9da59e8` | Four-path coverage true; 33 rows: three positives, 29 accepted denials, old unsupported userns EACCES. Later seven rows/post-peer proof absent. |
| v5 | `bfef8a4df44d76c73ea9aefa59ca78bbe45b04b9` | `2c75000f-2639-45b4-bc52-bb30625ebc5b` | Four-path coverage true; 39 rows: four others, 34 accepted denials, old unsupported peer signal-zero EACCES. PID1 final row/post-peer proof absent. |

Private failed-evidence archive SHA256 values (v1 retained separately):

| Case | SHA256 |
| --- | --- |
| v2 | `0dc5deaa03838c4e6721359f29c2c82ac73d0711d95d4524d28fe5aa0bef0248` |
| v3 | `42ebb2715af16bb6e5d7ab1b35b76d9d23dd051fa6b669569affd3457eb8595f` |
| v4 | `eaad833408d0af67b50830daecb21d19240de1187ef963666c30fa22b5a7ad76` |
| v5 | `8be4fea7df63a771a94ef78176457216d8655a150c08c9d0c686e80fb9948a08` |

## Separate next boundary: signed observer before API access

No signed observer is wired to this candidate. The existing live observer opens
journal/sidecar/witness resources before `input_ready`; silently reusing this
stateless three-FIFO READY contract would be false. A future change needs a
separate reviewed **pre-API READY/fence** before those opens, explicit new opt-in
and fixed experiment mode, plus new-label/ProtectProc bindings for initializer
and live worker together. Preserve existing signed registration, source/session,
terminal CONTROL, journal/witness, permission and forty-second lab runtime gates.

That is future design and commissioning, not an automatic continuation authorized
by v6. There is no new four-run source freeze, activation, resume, production
admission or claim that the original old-profile gate passed.
