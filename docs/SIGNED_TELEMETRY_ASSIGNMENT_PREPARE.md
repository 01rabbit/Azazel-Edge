# Explicit v2 assignment preparation (runtime unrun)

This component prepares one empty authenticated scope and the fixed isolated
service topology. It does not start an ordinary/sealed native producer, launch
traffic or a live observer, freeze a four-assignment manifest, compute H/G5,
qualify measurements, authorize resume, or activate production. The separately
commissioned manual connection does not validate this new preparation path.

Use `signed_network_telemetry_phase.prepare_telemetry_assignment(output, *,
manifest_sha256, start_head, source_commit, archive_sha256, core_sha256,
abi_sha256, interpreter_sha256)` as a context manager or explicitly close its
returned owner. `output` must equal the fixed `signed_network_phase.WORK`.
The owner cannot be constructed from a persisted JSON receipt. Keep it through
all later failures; callers must not substitute a reconstructed namespace owner.

## Frozen inputs before mutation

Root must independently verify the complete source archive on host and guest,
stage the protected revision/core/interpreter/ABI, locked accounts, aliases and
unchanged old/provider/new profiles, and retain those external pins. The archive
hash is an external staging assertion, not authenticated by recording it in JSON.
Existing protected-material, complete PID1 cgroup-view and fresh-unit checks apply.
There is no profile installation, repair, capability change or fallback.

`planned_telemetry(source, core, *, source_archive_sha256, abi_sha256,
interpreter_sha256)` binds those pins, actual source files, and the literal
assignment-mode descriptor/hash. The mode selects the fixed service veth topology,
trust v4, abstract witness transport and a v2 ticket; legacy v1 entry points still
reject it. No source pin is a placeholder for a future runner/reader.

`validated_telemetry_inputs(manifest_sha256, start_head, *, source_commit,
archive_sha256, core_sha256, abi_sha256, interpreter_sha256)` performs the same
read-only input checks. It reads only the fixed protected manifest/ticket and
current public source/core files. The ticket has exactly `schema_version`
(`signed-network-telemetry-ticket/v2`), `manifest_sha256`, `assignment_id`,
`run_id` and `start_head`. The manifest digest is canonical; original file-byte
hashes are separately retained. A caller-provided old ticket or receipt cannot
select a preparation mode.

## Owned preparation and handoff

`NamespaceSetup.prepare_service()` creates each of the three fixed namespaces
once, using the existing creation-intent/FD/name fences. It then configures the
same literal client/service veths, addresses, namespace-local routes/forwarding,
NFT chains and foreign canary as the existing network lab. Both IP families must
lack default routes. It never calls `Assets.setup()` to recreate names. The
manual `prepare()` path still uses loopbacks and dummy `es`.

Only the validated C0 or THROTTLE arm selects the existing native environment.
That environment is frozen before witness-first provisioning and genuine empty
initialization. The existing cookie/boot sampler, listener barrier, pre-API
proof/GO and initialization API remain mandatory. Empty initialization is not a
service horizon or a live readiness anchor. Ordinary-to-Switch startup and the
subsequent exact signed prefix/live readiness are later runner responsibilities.

The returned context carries direct `inputs`, `baseline`, `namespaces`,
`transport_context`, `initialization`, `owned`, `tracked`, `args` and `output`.
The preparation's temporary Python adapters remain installed for its owned
lifecycle and restore on close or any preparation failure.

Artifacts include `inputs.json`, `prepared.json`, `initialize/`, actual
`namespace-evidence/` records and byte-identical top-level intent/confirmed copies
for read-only compatibility. `namespace-boot.json` records current names, boot,
parent baseline and foreign token. These receipts are facts, not ownership tokens.

Close attempts the fixed five direct child clients, closes their pipes, stops all
owned fixed actors with witness last, then invokes existing full actor/cgroup,
resident and namespace identity cleanup. Forced/unknown process or cleanup proof
retains namespaces. Parent/assets/material checks run independently. Final
`actor-cleanup.json`, `namespace-evidence/cleanup.json` and
`assignment-cleanup.json` retain original cleanup facts; incomplete namespace
returns cannot qualify cleanup. Repeated close rethrows a stored failure rather
than implying success. Scope, source, journal and used evidence are never repaired.

Tests use declared synthetic Root/namespace/unit/API observations and real private
files/hash checks; a private child regression checks forced reap/pipe close.
They establish no actual namespace, policy, signed runtime or measurement result.
