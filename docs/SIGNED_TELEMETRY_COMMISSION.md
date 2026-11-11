# Single authenticated telemetry commissioning: two scoped runtime cases

`signed_network_telemetry_commission.commission_telemetry(output, *, source_commit,
archive_sha256, core_sha256, abi_sha256, interpreter_sha256)` now composes one
fresh authenticated initialization/live/terminal connection on an explicitly
marked offline disposable VM. It is a manual Root API with five mandatory
external pins, no CLI or automatic launcher. One fresh-VM positive connection
has completed at the exact source below. The earlier v6 stateless precheck remains
separate compatibility evidence, not admission for another source or scope.

Current explicit abstract transport and Root witness/namespace adapter boundaries
are described in [the lab transport guide](SIGNED_TELEMETRY_ABSTRACT_LAB.md).

Read-only evidence validation now requires **at least one recorded telemetry
sample with all four coverage flags true**, preserving the original call epoch.
Initialization, PRE-API READY or a terminal receipt cannot substitute for that
gate. The positive result below covers that gate for one source/boot only;
static fixtures and earlier failed attempts are not substituted for it.

## Reviewed positive runtime evidence: v8, 2026-11-12

Root completed one marked offline VM case and independently reviewed the retained
cryptographic evidence. Source/archive trust came from external host/guest checks,
not the revision field or receipt JSON. Exact references:

- Source: `9ecf03f564ca5060602254d627c0c577e5b8d114`.
- Source archive SHA256: `b1fcb04f4c5f7a7312f542f353cca10cd4412770fb563861c3f7412987c34b9f`.
- Actual kernel boot: `08e38f0b-f9f9-43d2-87c8-0bb92c6812db`.
- Private completed evidence archive SHA256: `bc802c7337eea05f901e86716b45e0537825ce199fe5ce81d989f51c012cd0ed`
  (1,054,720 bytes; excludes keys).

Genuine empty initialization preceded the original sealed native start and stop.
The signed source contains exactly prepare/start/end; the 10 journal frames and
11 signed witness anchors bind complete ordered cursors and natural terminal
CONTROL. One closed-sidecar sample has all four coverage flags true. There are
no outcomes or journal begin/commit/lost frames. Signed source/journal/witness
proof and the observer-owned sidecar remain distinct evidence classes.

Root observed UID61002, all capability sets zero, NNP, the enforcing new label,
original three stdio FIFOs and private-proc bindings. Init/live configuration
bindings agree; the boot-bound cookie and separately retained owned namespace
identity are different metadata, not interchangeable proofs. Five original sealed
witness proof calls completed with fixed cwd and clean owned-child reap/group
emptiness, without forced cleanup. All seven cgroups were empty, names absent,
no core remained and parent state was unchanged; the VM was stopped. Guest
regression checks also passed: 106 tests in 2.06 seconds.

Failed connection attempts v1–v7 remain retained at their original sources/boots;
v8 does not relabel them or the separate stateless precheck. The separate reviewed
negative case is recorded below.
This is one authenticated connection, not a four-assignment manifest/trial,
performance or efficacy result, hardware proof, general isolation acceptance or
production admission. Transition/experiment/admission/measurement flags stay false.

## Reviewed negative runtime evidence: separate v1, 2026-11-12

A separate fresh VM used the same source/archive pins above. Root independently
reviewed its evidence; no positive scope or key material was reused:

- Actual kernel boot: `b51683cc-ff52-40c8-928d-c13062992364`.
- Private public-only evidence archive SHA256: `c507012c45592337ace7923bcab4a161d7807b3973878ebe3edc423199077d4b`
  (972,800 bytes; excludes keys).

Genuine empty initialization produced four closed journal frames, five signed
witness anchors and a zero cursor. Root then appended exactly one explicitly
synthetic invalid-signature wire through the owned source FD. The actual worker
refused with exactly `authentication signature invalid`. The poisoned source
retained its bytes/inode across refusal; journal and anchors were byte-identical
before append, after append and after refusal. **Source verification READ the
bytes; zero durable cursor consumption does not mean no source access.** This
result neither acknowledges the bad frame nor fills missing evidence/backlog.

No live start-context, sidecar, outcomes, terminal artifacts or live result existed;
no core, Switch or workload ran. Root observed the UID61002 cap0/NNP enforcing
role, original three FIFOs and cookie versus separately owned namespace binding.
All Root metadata children reaped without force; cgroups were empty, namespaces
absent, no core remained and parent state was unchanged. The operator reported
`synthetic_signature_refusal_complete` with all authorization/measurement flags
false. Guest checks passed: 128 tests in 1.56 seconds; the VM was stopped.
Both cases remain narrow manual commissioning evidence, not four-trial, performance, efficacy, hardware or admission acceptance. Earlier failures remain.

## External prerequisites and current-source checks

Root must authenticate the complete source archive on host and guest before
extracting protected source and recording its revision. The supplied archive hash
records that external boundary; revision text or selected helper hashes alone
cannot authenticate the archive. Old/provider/new profiles, byte-identical aliases
and fixed locked accounts must already be staged externally. This API never
installs, repairs, reloads or broadens those profiles or aliases.

`signed_network_telemetry_commission_setup.preflight` checks the protected VM
marker, source revision, core ELF/hash, interpreter/ABI pins, current protected
material, feature masks and required enforcing-label facts. Matching installed
policy text, loaded labels and current compilation are separate observations,
not cryptographic proof of loaded policy bytes or observer-label binding.

Before creating private evidence, preflight requires unused output/BASE/three
provider names, all seven fixed actor units absent, the full actual PID1 cgroup
view empty for those units, no unmanaged native core, and protected imports.
Account UID/GID/nologin/locked status is checked without reading private keys.
Root network and external asset/material baselines precede scope mutations.
Retained actual unit search paths must contain no exact unit, dependency directory,
applicable dash-prefix drop-in or `service.d`, including dangling entries.
Current skip-kernel-load/skip-cache/Werror compilation precedes key or actor
provisioning. Unsupported, used or unknown state refuses without repair/retry.

## Current one-scope flow

1. Construct `NamespaceSetup` before preparation. It owns the three fixed provider
   namespaces, loopbacks and one dummy `es` in EDGE, with creation intents,
   confirmed original FDs, named identities and CLOEXEC fences. There is no
   address, forwarding toggle, workload, nft rule or external route setup.
2. Start the separately owned `p.NET_UNIT` dependency marker in a fresh dedicated
   evidence child. Its fixed Root cap0/NNP/AF_UNIX oneshot runs `/usr/bin/true`
   with RemainAfterExit, Restart=no and no default dependencies. Typed hooks,
   command, fragment, active-exited PID0 and full cgroup emptiness are checked.
   This marker supplies dependency compatibility, never namespace/API readiness.
3. Use the unchanged fixture's exclusive `g.prepare_lab` path to create genuine
   fresh v4 material and start the witness first. Record newly created core and
   witness unit ownership. The initializer callback records the exclusive BASE
   identity and normalizes only that new directory to 0755 through its owned FD;
   used-directory repair is refused. Private key material retains its own modes.
4. Call the current telemetry initializer with the fenced parent-owned EDGE FD
   and independent source/material pins. Then validate current registration,
   layout, exact C0 native environment and core hash. Start the ordinary core,
   apply the existing sealed Switch plan and require the actual signed two-frame
   `session_prepare`/`session_start` prefix on this boot.
5. Enter the current live helper using the direct successful initialization
   return and equal current public configuration/material binding. Independently
   await durable `input_ready` at the exact source prefix, then stop native/capture
   naturally while observer and witness remain available for terminal CONTROL.
   A status-only session exposes no client pipes or wait/communicate operation.
6. Require the typed natural terminal result and clean live-helper teardown.
   Read original source, journal, signed witness anchors, terminal wire/decoded
   bytes and closed collector sidecar. Existing validators check signatures,
   lifecycle, source/journal inode and policy bindings, exact cursor coverage,
   final witness acknowledgement and the three-event no-workload session. At least
   one complete four-coverage sample must match its recorded call epoch; terminal
   CONTROL can precede the first finalize call, so finalization is not required.

Both initializer and live use the new fixed units/alias/profile with UID61002,
cap0/NNP/AF_UNIX, private ptraceable proc view, Restart=no and unchanged 40s/5s
unit bounds. Before opening authenticated APIs, each worker emits PRE-API READY
and waits for exact bounded GO. Root independently checks source/boot, effective
unit command/hooks, PID/start-time/cgroup/label, proc/binfmt metadata, all three
nsfs identities and exactly the original three FIFOs. Root persists the full
proof bundle and binding, including directory fsync, before GO. Public trust/origin
configuration is checked at the caller's fences; its snapshot is not atomic or
self-authenticating. Actual authentication remains in the unchanged API after GO.

## Ownership, failure and cleanup

Keep the namespace state through every failure. Its failed/closed states cannot
be prepared or used again. Initializer/live helpers own their fixed unit, Root
client and pipes; raw replies precede parsing. They independently stop/prove their
unit, retain residual streams, boundedly reap the owned client and close pipes.
Forced reap, unknown state or evidence failure withholds their success result.

The main commissioner attempts every owned fixed actor with witness last. Legacy
families are never signalled. It then closes the namespace context, which stops
only its owned marker and independently inspects all seven actor families,
canonical full-PID1 cgroups, unmanaged cores, boot and external invariants.
Marker STOP requires a start attempt, original finalized 0644 file identity/bytes
and matching current loaded-unit fragment/command/hooks/properties/type. Proven
absence uses before/after snapshots and full cgroup proof without STOP.

Namespace deletion requires confirmed creation, unchanged named/FD identities,
zero residents, workspace identity, durable actor checks and each durable delete
intent. It never uses `Assets.close` resident signalling. Unknown/replaced names,
failed setup or persistence retain remaining names; only confirmed original FDs
may close. Parent network, old/provider assets and current material are audited
independently before/after cleanup. Scope files/history and used unit files remain
evidence; no filesystem/default-mode restoration, reset or automatic retry occurs.
Only temporary Python fixture globals are restored after the call.

## Evidence limits

Completion describes one authenticated connection only. Collector calls remain
observer-owned closed sidecar evidence, distinct from signed source/journal/witness
proof. Pre-API confinement provenance is Root lab metadata, not a new cryptographic
observer-label field in registration or journal context. Current code pins include
the actual commissioning and consumed helper modules; further edits require a new
complete source freeze. Composition fixtures use real ephemeral source/witness
signatures and original-byte validators, with synthetic Root/process observations
and manually assembled journal bytes. They prove no actual systemd confinement,
journal persistence or current-source VM acceptance.

Existing product and signed-network defaults remain unchanged. This API creates
no four-assignment manifest or ledger and performs no H window, traffic workload,
G5/effect calculation or efficacy assessment. Results keep transition, experiment,
production admission and measurement completion false. They authorize no trial,
resume, deployment or production activation.
