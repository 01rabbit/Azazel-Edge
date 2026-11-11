# Single authenticated telemetry commissioning: prerequisites component only

No authenticated commissioning case has run for this changed source. There is
no four-assignment manifest, namespace setup, marker unit or commissioning entrypoint
in this first chunk. Existing signed-network preparation/runner defaults and all
profiles remain unchanged. The completed v6 stateless role precheck is compatibility
evidence at its own tested source, not admission for an authenticated scope.

The isolated helper
`signed_network_telemetry_commission_setup.preflight(output, *, source_commit,
archive_sha256, core_sha256, abi_sha256, interpreter_sha256)` takes one new private
output path and five mandatory independent Root pins. It is fixed to this lab's
old/new initializer/live families, core, witness, provider network marker name,
three provider namespace names and externally staged account/profile/alias set.
It has no arbitrary unit, command, profile, namespace or material path inputs.

Root must first authenticate the complete source archive on host and guest, then
extract protected source and record its exact revision. The supplied archive hash
records that **external** trust boundary; matching revision text is not archive
proof. Old/provider/new profiles and byte-identical aliases are externally staged
with current source hashes; this helper neither installs nor reloads them. Old
account UIDs/groups/nologin/locked status are checked using public account metadata
and `passwd --status`, never shadow or private-key content.

Before creating output, the helper checks the protected VM marker, exact source
revision/core ELF/hash, current candidate/interpreter/ABI/feature/loaded-label facts,
unused output/BASE/three names, all closed unit families absent, actual full-PID1
cgroup emptiness and no unmanaged native process. Isolated protected imports are
also checked. No unknown/used state is repaired, predeleted or reused.

Root parent-network and external-asset/material baselines are captured before the
private output is created and saved immediately afterward, before compilation or
any future scope/namespace/unit/key mutation. The actual bounded systemd unit
lookup query is retained. Every path is checked with LEXISTS for every fixed unit,
`.d/.wants/.requires/.upholds`, applicable dash-prefix `.service.d` and global
`service.d`; dangling links, malformed/duplicate paths and query failure refuse.

The only executable preparation work is the existing current-profile compile-only
helper with skip-kernel-load/skip-cache/Werror. No policy is loaded, key generated,
BASE created, unit started or namespace created. On success or a post-output
failure, parent network, old/provider assets and current material checks are each
attempted independently, preserving failures instead of hiding a skipped check.
Successful output still sets transition/experiment/admission false and is only a
prerequisite receipt, not a complete fresh authenticated case or runtime proof.
Tests use synthetic Root/kernel/tool observations; they create private test files,
not actual systemd actors, namespaces or policy.

Later separately reviewed setup must retain every namespace/unit creation intent
and confirmed owned FD, establish lo and dummy `es` only as required, and add a
fixed cap0/AF_UNIX `p.NET_UNIT` oneshot marker only for provider `Wants/After`
compatibility. That marker cannot prove namespaces exist. Outer fresh BASE0755
establishment needs recorded creation ownership, never used-directory repair.
The current initializer and future live helper must retain equal frozen material,
public authenticated-scope context and actual pre-API proofs before GO, then reuse
unchanged witness-first provisioning, sealed native startup, durable input_ready
and natural verified terminal handling. No fake four-run manifest is needed.

The outer commissioner must independently stop/prove every owned actor and client,
keep legacy families absent, and prove all cgroups/three namespaces empty before
fenced namespace deletion. Failed/unknown proof retains named scope/evidence; no
resident-kill shortcut, retry, reset, backfill or profile widening is authorized.
No H window, workload, service effect, G5 calculation or four-run ledger belongs
in that single authenticated-connection case.

## Fixed dependency-marker helper (not namespace setup)

`signed_network_telemetry_marker.Marker(output, baseline)` holds ownership state
before `start()` can mutate anything. The outer namespace owner must retain this
object on all paths and independently fence all three namespaces before each use.
The helper itself provides **dependency compatibility only**, not namespace proof,
authenticated API permission or a complete commissioning entrypoint.

It checks current material/boot, all-family inherited unit material and known
absent marker/cgroup state. It exclusively creates only fixed `p.NET_UNIT` through
a protected nofollow parent/owned FD, records intent and inode immediately, then
establishes exact0644 with that new FD and fsync. It never overwrites, repairs,
unlinks or reloads profiles. The fixed unit runs only `/usr/bin/true`, oneshot with
RemainAfterExit, Root user/group, cap0/AF_UNIX/NNP, Restart=no and no default
dependencies. Its five-second startup/three-second stop settings are fixed; manager
queries use the existing two-second retained command helper.

Original reload/start/state query outputs precede parsing. Typed empty-hook proof,
exact executable/argv, effective authority/dependencies/fragment, active-exited
MainPID/ControlPID0 and full-PID1 cgroup emptiness are required. `marker-verified`
metadata explicitly sets transition/experiment/admission false and still proves
no namespace or scope readiness. `stop()` acts only on its unchanged confirmed
owned file/unit and retains stop/cgroup evidence. Unknown/replaced files do not
permit stopping a foreign unit; failed stop/persistence proof remains failure.
The unit file is retained as used-case evidence after stop, never reused/deleted.

The real current preflight and marker modules are now mandatory new-plan source
pins, with no placeholder for the not-yet-implemented namespace context or main.
Tests use real private file writes plus explicitly synthetic Root/unit metadata;
no actual systemd unit, namespace, key or hardened role is created by these tests.
