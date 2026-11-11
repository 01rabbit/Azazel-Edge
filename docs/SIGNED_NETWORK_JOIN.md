# Signed network instrumentation: manual test APIs

**Status: COMMISSIONING_BLOCKED.** PR #574's separate confined telemetry precheck
passed 48 tests, but the actual unchanged observer label returned EACCES for
`/proc/net/dev`, `/proc/loadavg` and `/proc/uptime`; `/proc/meminfo` was readable.
Passing those checks established the permissions gap, not complete telemetry.
No four-assignment source/manifest has been frozen and no signed network trial has
run. Do not prepare or run the four assignments while this gate remains blocked.
No profile, capability, address-family or product default is broadened here.

These test-only functions connect the existing signed/sealed native service,
real observer, independent service peers and read-only calculations. They are not
production admission, efficacy evidence, flow-specific attribution or causal
support. The two-pair pilot thresholds are software calibration examples, not
field acceptance criteria. Resource overhead and physical-device G6 remain
separate. Old experiments, original bundles and all used scopes remain unchanged.

## Manual API boundary

There is no supported automatic trial CLI, VM orchestrator, retry engine or new
benefit calculator. Root owns manual provisioning and the external freeze ledger.
The implemented functions are:

| Module | Function | Result boundary |
| --- | --- | --- |
| `signed_network_plan` | `planned(source, core)` / `order(manifest)` | Exact source-bound four-assignment plan and frozen order |
| `signed_network_phase` | `prepare_assignment(manifest_sha, start_head)` | Fresh registered lab only |
| `signed_network_run` | `run_assignment(manifest_sha, start_head)` | Actual retained run facts after cleanup; not measurement success |
| `signed_network_read` | `read_assignment_artifacts(manifest_sha, start_head)` | Same-VM read-only verification and optional existing measurement record |
| `signed_network_freshness` | `validate_fresh_records(manifest, results, *, core_sha256)` | Original records in frozen execution order; local structural check only |
| `azazel_edge.benchmark.measurement` | `measure_experiment(manifest, inputs)` | Existing measurement and benefit gates |

The modules live under `tests/real_systemd`. The phase script's fixed namespace
preparation child, run script's fixed Root-query child and observer script's fixed
initialize/live roles are internal unit entrypoints, not general operator CLIs.
The following sequence describes the reviewed protocol; it does not authorize
execution while commissioning is blocked. Complete end-to-end synthetic
reader-to-calculator composition is still under development; do not infer a
positive calculation result from component unit tests.

## Freeze and provision before any assignment

1. Review the complete source and exact policy/configuration, then freeze **all
   four assignments before the first assignment VM work**. Existing plan order is
   pair 0 C0/candidate, pair 1 candidate/C0. H is 5 seconds, with client protocol
   origin H0+1.25 seconds, pre-window 1 second and post-window 2 seconds. Never
   retune order, timing, policy, thresholds or bounds after seeing results.
2. Use existing `RunLedger` to freeze the manifest and durably start each unique
   run ID in that order. Retain its head outside the store. Hash chains protect
   against changes relative to that checkpoint, not a malicious owner controlling
   both ledger and checkpoint. A failed/used assignment is retained, never reset,
   repaired, retried or relabelled as a fresh run.
3. Root may stage dependencies in an unused stopped template. Each assignment
   must have an independent actual cold boot and genuinely new registration,
   source, keys, journal, witness and scope. A dependency-only template has no
   registered material, actor units, profiles or namespace handles. Never clone
   used registered state into a supposedly fresh assignment.
4. Root verifies the reviewed `git archive` SHA on host and guest, extracts
   protected root-owned source without group/other writes, and stages protected
   `SOURCE_REVISION` with the exact commit (optional final newline). Retain the
   staging receipt/archive SHA for all assignments. This external operator trust
   boundary covers **all consumed source**. Internally read direct-file hashes
   and revision text do not substitute for independent archive verification.
5. Stage protected single-link root-owned manifest and ticket files at
   `/var/lib/edge400-signed-network-manifest.json` and
   `/var/lib/edge400-signed-network-ticket.json`. The ticket contains exactly
   `manifest_sha256`, `assignment_id`, `run_id`, `start_head`. Root supplies the
   canonical manifest digest and exact start head out of band. Keep the separately
   verified/frozen native ELF SHA for the eventual four-record gate.
6. Stage the isolated Python runtime's existing protected `.pth` prerequisite;
   do not supply a `PYTHONPATH` fallback. Preparation checks the actual `-I -B`
   imports, exact source/API and module protection before any mutation. Source,
   native ELF, manifest, ticket and direct policy files must match their pins.

Keep keys and private raw evidence private. Public key identities, hashes and
bounded status receipts are not authority to expose private key bytes. Neither
read-only importer nor freshness gate reads producer/witness private keys.

## Genuine initialization and fixed topology

`prepare_assignment` first validates exact inputs, marked Root/offline lab guards,
unused files/units/profiles/namespace slots, no unmanaged core, supported full
PID1 cgroup view and isolated runtime API. It refuses existing or uncertain state
before provisioning. It retains prepared boot, public trust/registration, source
pins, native PID and actual preflight results in `prepared.json`.

The fixed existing topology uses edge `edge400-provider-edge`, client
`edge400-provider-client` and service `edge400-provider-service`. Edge `ec` is
`10.91.1.1/24`, edge `es` is `10.91.3.1/24`, attacker is `10.91.1.2`, legitimate
client is `10.91.2.2/32`, and server is `10.91.3.2`. Existing explicit lab routes
introduce no parent/default route. Peer constants, namespace paths and existing
provider permissions remain fixed. The legitimate protected-policy writer is
installed **before** provider configuration captures its raw writer and before
registration, so the registered configuration includes actual legit protection.

Namespace creation saves an intent before each creation and a confirmed
device/inode identity immediately afterward. No predelete or reused name is
allowed. `guest.prepare_lab` starts the witness first. Its callback creates the
genuine empty observer journal with the real policy, registered authentication,
interface `es` and 0.25-second sampling context under the existing observer label.
Traversal normalization applies only to owned lab directories just created by
this invocation; it is not a generic chmod/repair operation.

The existing empty-EVE ordinary core → reviewed `Switch.plan/apply` → actual
native identity sequence follows. An inactive Switch is never used to newly
enable enforcement. Native v4 registration, seals, exclusive-writer ownership,
AppArmor, capability and namespace guards remain unchanged.

## One bounded actual assignment

`run_assignment` revalidates source/ticket/prepared boot, public enrollment and
sole native identity before workload. An exclusive run intent claims the attempt;
a second call refuses without cleaning up someone else's attempt. Only a fresh,
complete signed prepare/start prefix qualifies. All peer/config preparation
precedes observer start to preserve its fixed runtime budget.

The real observer remains UID/group 61002, existing enforcing AppArmor label,
zero effective/permitted/ambient/bounding capabilities, NNP and AF_UNIX, in the
fixed edge namespace. Initialization and live roles use `Restart=no` and
`DefaultDependencies=no`. Effective properties, typed empty execution hooks,
actual UID/caps/label/cgroup/namespace and stable PID/starttime must agree; retained
readback proves actual effective settings. The original observer unit must not
start alongside the signed-network worker. No privileged observer proxy exists.

Within two seconds, the worker must remain alive, write matching start context,
actually persist the exact durable `input_ready` source cursor and pass effective
identity checks. A context file alone is not readiness. Retain actual Root
controller start/end clock brackets and observer start/end brackets. H0/deadline
are actual monotonic coordinates. The client may launch before its fixed H0+1.25s
protocol origin; retain actual argv/spawn brackets separately from that scheduled
coordinate. No planned time is represented as an actual process-start timestamp.

After a real baseline interval, append exactly one fresh fixed EVE record and
retain its bytes and append brackets. Poll only authenticated complete prefixes.
An incomplete writer tail is not-ready, preserved unchanged; a complete bad
signature/registration/session/boot/task/tuple fails immediately. Both arms retain
independent Root baseline/active/absence query receipts, original query times,
child PID/argv, namespace identity, boot, source/tool pins and full raw chain.
Only the fixed read-only throttle-chain query is allowed. Candidate owned-flow
semantics and foreign-canary preservation reuse the production parser; C0 native
execution remains disabled/dry-run rather than an invented applied observe action.

At actual H, immediately persist each unchanged peer audit as it is received,
before another receive/wait/validation can fail. Original service/client objects,
artifact byte hashes and actual duration/error/transaction fields survive partial
failure. Only a copied capture-input coordinate translates client elapsed times
by the explicit 1.25-second origin offset; original audits remain unchanged.

Candidate release must be an authentic matching native release and an **actual
recorded collector callback with the exact original receipt epoch**. Keep failed
release attempts. Missing callbacks withhold the join; do not substitute native
attempt time or supplement an observer receipt. Require actual Root absence and
unchanged foreign context. The observer's 40-second runtime, 900-row recorder and
32-second release wait from actual append are fixed. Slow runs can fail/withhold;
there is no timeout retry, new scope, forced finalization or backfill.

## Terminal drain and cleanup

Stop capture/core first after actual release/absence (C0 after H), keeping witness
and observer live. The unchanged live API may naturally return only for the
explicitly opted-in authenticated registered normal-core terminal frame. Preserve
original signed wire bytes/hash, decoded bytes/hash, both source cursors and fresh
witness acknowledgement. This is terminal **CONTROL**, not observed activity,
release/quiescence proof, successful measurement or resume permission. Existing
pending windows close lost/unavailable through the normal journal path. No live
loop/signal/recovery override manufactures completion; recorder inflight or sticky
poison prevents a clean end even if a caller catches an exception.

Then stop observer, witness last, and attempt bounded stops for every fixed actor.
Failures/read errors are sticky but never skip other stop attempts. A collected
unit's nonzero stop is accepted only with independent exact not-found/inactive/
PID0 states before and after plus canonical full-view cgroup emptiness. Cgroup
absence counts only after protected canonical full-root cgroup2 mount/device and
same PID1 cgroup namespace/root-view proof; v1/hybrid/subtree/unknown views refuse.
Parent `cgroup.procs` must be empty and `cgroup.events populated=0`, including
all descendants. No anonymous children or unknown actor may be silently ignored.

Only verified all-actor quiescence permits existing identity-fenced peer reap and
namespace deletion, followed by parent-state/foreign preservation checks. Reopen
requires original boot and all saved intents/confirmed identities; replacement or
unknown names refuse, without predelete or signalling unknown handles. Cleanup,
log closes and owned-child reap continue after earlier failures; retain originals.

There is one narrow **preprovisioning** exception: if `Assets.setup` fails inside
its fixed namespace-preparation unit before registered actors or workload children
exist, existing `Assets.close` may remove only its own confirmed created identities
before that unit exits. Preserve partial intents and unknown/unconfirmed names.
Every postprovisioning failure still requires the all-actor stop proof first.

## Same-VM read-only verification and comparison

`read_assignment_artifacts` reads the protected original guest layout with actual
owner/device/inode identities. It has no arbitrary artifact-map import, chown
fallback, write, subprocess, socket, key read, store or journal reopen. Preserve
all original source/anchor/journal/raw-call bytes. Retained facts on failure are
explicitly unverified/withheld, never authenticated merely by a return-field name.

It verifies public v4 enrollment, exact frozen configuration, complete signed
source, every original signed witness anchor (existing public verifier/domain,
closed schema/counter/previous/trust digest), exact source/journal prefix
sequence/head/size/hash and journal device/inode, genesis, final acknowledged state,
full ordered cursors, genuine init/live sessions and terminal close. Bounds are
4 MiB/512 source records, 8 MiB/4096 journal frames and 8 MiB/4097 anchors, also
within registered limits. No unsigned state JSON or success flag substitutes.
C0 must pass this full chain too; its existing baseline `edge_recording=None`
exemption does not waive authentication. Pending/lost/missed activity withholds.

Raw kernel UUID, original systemd `%b` 32-hex wire boot and `kernel-boot-<UUID>`
journal reference remain separate with explicit injective mappings. Raw native
32-lowercase-hex session stays in wire and `authenticated_origin.session_ref`;
measurement linkage is exactly `native-session-<raw>`. No original ID is rewritten.
Complete ordered callbacks compare canonical bytes, including intermediate
releases; Python bool/int/float equality cannot replace an original signed fact.

The fixed 5 ms clock qualifier checks actual controller/observer start/end and
per-call wall/monotonic brackets, supplied epochs, call durations and offset
envelope. It proves **sampled anchor consistency only**, not continuous unsampled
stability. Preserve the original origin mapping; no alignment fit, timestamp move,
reordering, missing-clock reconstruction or post-result tolerance change is allowed.
Event and full pre/post sampled windows must fall inside actual H, with existing
coverage and release gates retained. A Root probe before the actual event callback
withholds rather than moving the probe or inventing an earlier observer receipt.

Actual live journal/output/collector Outcomes stay unchanged and separate from
both plain G5 replay and explicitly labelled **Root-augmented G5 calculation**.
Plain replay may differ only in `telemetry_coverage.policy_ref` and its one exact expected
policy-reference entry in `evidence_refs`, derived by the unchanged constructor
from the real recorded source and golden source; canonical policy SHA must match.
All other differences withhold. Root input never retrofits the live Outcome or
means the live unprivileged observer confirmed nft state. Broad interface/system
metrics and source-IP correlation remain confounded; causal support stays inconclusive.

Only `calculation_available` returns an existing measurement record; it is not a
measurement PASS. Pass unchanged reader outputs plus Root's frozen ELF SHA to
`validate_fresh_records`, which requires all four exact assignments, matching
origin/capture/linkage, distinct raw boots/scopes/sessions/registrations/run IDs and
all eight producer/witness public keys globally distinct. It returns original
record references in frozen order. This is local structural validation, **not
authentication of caller-authored JSON or flags**. Only then may Root pass
`{"manifest_sha256": manifest_digest(manifest), "records": records}` to existing
`measure_experiment` and finish existing RunLedger receipts. That calculator's
window/coverage/release/attribution/5 ms gates and withhold behavior remain unchanged.
