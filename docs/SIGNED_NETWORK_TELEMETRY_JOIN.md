# Optional signed telemetry join: interface and scoped commissioning

There is one [scoped positive init/live/terminal result](SIGNED_TELEMETRY_COMMISSION.md#reviewed-positive-runtime-evidence-v8-2026-11-12),
with separate negative runtime qualification still open and no frozen four-assignment manifest. The existing signed-network preparation/runner still selects the
legacy role and **rejects the new manifest**. Do not use this component as an
operator entrypoint or interpret structural validation as permission to proceed.
The old-profile telemetry gap remains blocked. The separately completed v6
stateless precheck is compatibility evidence at its own tested source, not admission
for another source or scope.

## Explicit plan and external pins

`signed_network_plan.planned(source, core)` and `validate_manifest(value, core)`
retain their legacy behavior. New
`planned_telemetry(source, core, *, abi_sha256, interpreter_sha256)` returns the
separate literal `signed-v4-network-telemetry-v2` plan. Both lowercase SHA256 pins
are mandatory inputs from Root's independently frozen public-material receipts;
there is no default, checkbox, imported old-receipt or manifest-derived trust.

The new plan consumes `signed_network_telemetry_contract.observer_spec` for exact
initializer/live metadata: separately named units, fixed protected alias/profile,
provider edge namespace, cap0/NNP/AF_UNIX, Restart=no, private ProtectProc ptraceable,
ProcSubset all, MountAPIVFS and unchanged 40-second runtime/5-second stop bound.
Both fixed specs, external pins and current source/profile hashes enter every
arm's configuration hash. Policy, native v4 authentication, H5/client1.25,
C0 observe-only role and four fresh assignments remain unchanged.

`validate_telemetry_manifest(value, core)` compares the complete v2 structure and
types canonically. It does **not** authenticate imported JSON or independently
establish that declared pin values came from Root. The legacy validator still
rejects v2, preventing unwired preparation from provisioning an old role for it.
Later reviewed wiring must explicitly select the new mode, require opt-in and
compare independently provisioned pins with current protected guest material.

Source hashes describe the constructor's current checkout. Root's mandatory
external source-archive hash verification on host/guest and protected revision
boundary authenticates the source; these selected hashes are not a replacement
recursive source proof. The reviewed Root proof module is now present and mandatory in the source-pin
map, using its actual bytes; missing or changed entries refuse. The final worker
and remaining consumed helpers must still be integrated/reviewed before any final
plan/source freeze. Changes invalidate previous hashes.

## Current protected material, without installation or activation

`signed_network_telemetry_material.verify_current(*, abi_sha256,
interpreter_sha256)` requires Root and explicit
`EDGE_SIGNED_NETWORK_TELEMETRY=1`. It reads only bounded protected regular public
material: installed interpreter and byte-identical new alias, source/installed
candidate profile, selected source helpers and ABI4. It compares the mandatory
external interpreter/ABI hashes, current namespace/ptrace feature-class masks and
exact new enforcing-label fact, rejecting complain/child/unknown label variants.
No keys, actor, imported receipt or arbitrary path/profile input is consumed.

The read-only check can precede output creation. It establishes neither VM
freshness, successful profile loading, actual actor mediation nor source-archive
authenticity; callers must separately prove those boundaries. Matching installed
policy text and a loaded label are separate observations, not a cryptographic
kernel-policy-text binding. Actual confined initializer/live proof is still needed.

After independent freshness and creation of a protected private Root output,
`compile_current(output, *, abi_sha256, interpreter_sha256)` retains current raw
policy/ABI, before/after material facts and compiler argv/stdout/stderr/result.
Its fixed command uses skip-kernel-load, skip-cache, stdout and Werror; warnings,
nonzero/timeout/empty/oversize output or material drift refuse. It never installs,
loads, repairs or unloads policy and never creates keys/actors or authorizes APIs.
The compile evidence must precede any later key/actor provisioning.

Tests use explicitly synthetic Root/tool observations. No actual compiler, policy
load or hardened role is exercised by this chunk. Old defaults/profiles/aliases,
product registration and journal schemas remain unchanged.

## Remaining separately reviewed boundary

The future worker must emit PRE-API READY before opening trust/source/policy,
journal/sidecar/witness or telemetry handles. Root must verify both actual fixed
roles, source/alias/profile, typed effective properties, private proc mounts,
three original FIFO identities and owned provider namespace before sending the
literal GO. This GO is not durable input_ready or measurement acceptance.
Initializer and live must share the same frozen configuration and scope, then use
unchanged authenticated initialization, SourceVerifier, recorder and terminal API.

Root manifest plus current runtime proofs provide **lab provenance**, not
cryptographic observer-label binding in v4 registration or journal context.
No product field may be invented to imply that stronger property. Preserve actual
live Outcomes separately from Root-probe G5 calculation, complete C0 chain, actual
release callbacks, sampled clock/window/coverage/freshness gates and all cleanup.
First commission one current-source authenticated init/live case without a
four-trial manifest. Only afterward may Root decide whether to review and freeze
all four fresh boots/scopes/keys. Nothing in this interface performs that decision.

## Fixed initializer caller component (not a complete commissioning runner)

`signed_network_telemetry_initialize.initialize(output, *, abi_sha256,
interpreter_sha256, source_sha256, expected_sources, namespace_fd,
namespace_identity)` is a manual Root helper independent of a four-run manifest.
The source pin is the externally frozen observer SHA; `expected_sources` must
match the complete current material map, now including this caller's actual
implementation. Root must still authenticate the full source archive externally.
No imported success receipt, JSON flag or raw-file existence authorizes GO.

The outer fresh-scope controller must perform current compilation before keys,
provision genuine unused v4 material, start the witness first and retain ownership
of the exact fixed EDGE descriptor. This helper verifies current protected
material, private Root output, unused fixed initializer unit/full-PID1 cgroup and
FD/named namespace identity. The caller's namespace FD stays parent-only/CLOEXEC;
Popen closes non-stdio descriptors and never transfers a namespace FD to the role.
No file, alias, profile, key, witness, core or namespace is created by this helper.

Its owned three-pipe client starts the fixed new initializer. It calls the reviewed
Root collector, then exclusively persists the **full returned verified bundle**
`{ready,effective,actor,metadata}` plus binding and canonical binding SHA before
sending literal GO. The binding retains actual boot/namespace, source/material,
both fixed role specs and exact policy hashes. Current material, boot, policy and
namespace identity are checked again before GO. Raw collector files on failure
are preserved, but never interpreted as a successfully returned proof.

Remaining stdout/stderr/return code are bounded and retained before parsing the
unchanged genuine-empty initialization result. READY is a separate consumed and
retained frame, not concatenated with the final JSON. The client bound is twenty
seconds from launch; the role remains forty seconds and its GO deadline two
seconds. These bounds are not retuned on failure. The result only describes this
initializer and keeps transition/experiment/admission false.

Every post-intent failure and normal completion independently attempts the fixed
initializer stop/full-PID1 cgroup proof, bounded residual-stream retention, owned
client reap and all pipe closes. Forced reap, unknown cleanup or evidence failure
stays sticky and prevents publication of a successful initializer receipt. Raw
initial and cleanup-residual streams remain separate unchanged artifacts. No
arbitrary unit is stopped, no caller namespace descriptor is closed and no failed
scope is retried. **Outer witness/core and namespace cleanup remain the outer
controller's responsibility on every path**; initializer-only cleanup is not proof
of whole-scope quiescence or admission.

Tests use synthetic Root/unit/proof observations and real private client IO,
including a stuck owned client killed/reaped by the helper itself. They do not
execute a hardened initializer, policy loader, authenticated scope or VM. Separate
manual init/live commissioning now has the scoped result linked above; trial
phase/run dispatch remains unwired.


### Initializer prelaunch inherited-material refusal

Before Popen, `prelaunch_unit_material('initialize'|'live', output)` obtains the
actual systemd lookup paths with the existing fixed two-second retained query.
It checks every path for the selected literal unit, `.d`, `.wants`, `.requires`,
`.upholds`, every applicable dash-prefix `.service.d` and global `service.d`.
LEXISTS includes dangling aliases. This prevents an inherited hook/dependency
from running before the later effective-property proof could reject it. Unknown
modes, query errors/diagnostics, duplicate/malformed/oversize paths refuse before
launch or GO. Original argv/stdout/stderr/result remain private evidence. There
is no caller-supplied unit or path selection; live composition is still unwired.

The outer provisioner must make the **newly created** Root-owned fixture BASE
traversable with its intended 0755 mode and retain creation provenance before
calling this helper. In particular, an operator umask077 may leave a new BASE
0700 unless the outer fresh-creation path explicitly establishes its intended
mode. This helper does not chmod, repair or reuse an existing/used directory.
The precondition is separate from the private Root output's required 0700 mode.

### Public authenticated-scope configuration continuity

The initializer binding now includes `public_auth`, sampled by the reviewed
fixed `public_auth_binding()` helper before launch. Only protected public
`trust.json` and `origin.json` are read. Their original raw hashes, canonical trust
digest, configured registration digest and selected scope/source/journal/UID
metadata remain distinct. Source/journal/private-key files, sidecars and witness
endpoints are not opened by this snapshot helper; metadata paths are not read
selectors. Its actual implementation is mandatory in the source-pin map.

The initializer retains another public snapshot before GO and after initialization,
compares each with the initial binding, and refuses missing/invalid/drifting
configuration. A changed returned snapshot is saved before comparison; raw init
output survives an after-init refusal. Only an unchanged context can publish an
initializer result. This is sampled Root public-configuration continuity, not an
atomic pair snapshot, cryptographic observer-label/journal binding, source
admission or a replacement for the observer's unchanged authentication after GO.

Private `_current_binding(*, current, namespace, source_sha256, kernel, output, phase)` returns
`(binding, policy_raw)` for fixed init/live reuse. Callers must independently
verify its inputs. Binding keys are `role`, `kernel_boot_id`, `namespace`,
`observer_source_sha256`, `material`, `public_auth`, `roles` (both fixed specs),
`policy_file_sha256`, `policy_sha256` and sampled `witness_actor`. It adds no
role/path selector. The manual live caller compares the full same-context binding
and retains its own proof; this is separate from trial-runner integration.
