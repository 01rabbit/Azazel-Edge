# Optional signed telemetry join: first interface chunk only

There is no working signed telemetry join, frozen four-assignment manifest or new
runtime result. The existing signed-network preparation/runner still selects the
legacy role and **rejects the new manifest**. Do not use this component as an
operator entrypoint or interpret structural validation as permission to proceed.
The old-profile telemetry gap remains blocked. The separately completed v6
stateless precheck is compatibility evidence at its own tested source, not admission
for this changed source or a signed observer.

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
