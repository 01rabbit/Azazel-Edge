# Single authenticated telemetry commissioning: manual API, runtime unrun

`signed_network_telemetry_commission.commission_telemetry(output, *, source_commit,
archive_sha256, core_sha256, abi_sha256, interpreter_sha256)` now composes one
fresh authenticated initialization/live/terminal connection on an explicitly
marked offline disposable VM. It is a manual Root API with five mandatory
external pins, no CLI or automatic launcher. No authenticated commissioning case
has run for this changed source. The completed v6 stateless precheck remains
compatibility evidence at its own source, not admission for this connection.

Current explicit abstract transport and Root witness/namespace adapter boundaries
are described in [the lab transport guide](SIGNED_TELEMETRY_ABSTRACT_LAB.md).

Read-only evidence validation now requires **at least one recorded telemetry
sample with all four coverage flags true**, preserving the original call epoch.
Initialization, PRE-API READY or a terminal receipt cannot substitute for that
gate. Runtime remains **UNRUN** for this changed source; static and fixture checks
do not establish current-source VM acceptance.

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
