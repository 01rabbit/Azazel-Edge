# Signed network join instrumentation (test only, unfinished VM driver)

Status: hardware-free recording and service-coordinate components. The manual
four-VM driver remains a draft; no experiment has been frozen or run using it.
This is neither production admission nor an efficacy/causal-support result.
The old direct-core v3 experiment and all used scopes remain unchanged.

## Three different kinds of evidence

Keep the signed native stream, original live observer journal/outcomes, and
independent service/client audits unchanged. A root operator may separately
retain the complete raw nft chain response with its actual query times, source
pins, child/namespace identity and boot ID. That root-only lab query supplies no
observer privilege and is never a proxy available to the observer.

`tests/real_systemd/signed_network_recording.py` provides a test-only constructor
binding around the real `OutcomeTelemetryCollector` used by `run_live_resumable`.
`record_collector(path, policy=..., policy_source_ref=...)` calls unchanged super
methods and records their actual inputs, explicit epochs, monotonic call bounds,
returned samples, acceptance results and final Outcomes. It creates one exclusive
0600 sidecar under the existing observer-directory grant. It never calls an
extra sample or finalization. A call is marked inflight before entering super;
only its durable sidecar append clears that state. Caught exceptions, signals,
partial writes and exceeded bounds poison the recording and prevent a clean end.
Original journal results already persisted before a recording failure are retained
but cannot justify reconstructing missing calls. Bounds are 4 MiB/900 rows.

`read_calls` requires complete canonical finite JSON, duplicate-free keys,
sequence/hash continuity, ordered epoch/monotonic call bounds, a safe regular
single-link file, and stable identity/size/timestamps across reading. The hash
chain detects accidental changes; it does not authenticate a malicious operator
or the same UID. Signed source/witness/journal and source/assignment/clock checks
remain separate required inputs to the future coordinator.

`replay_calls` constructs a **read-only G5 projection** using those recorded
sample/event/finalize calls. It returns the original live Outcomes plus a plain
replay and, optionally, a separate root-probe-augmented replay. It never replaces
live outcomes or claims the live observer verified nft. The G5 constructor names
its policy source `golden-replay`, while the live constructor uses the real policy
file path. Comparison therefore names an explicit policy-source-label equivalence,
not byte equality: the canonical policy SHA must match, both exact references
must be derived by the unchanged policy constructor, and only
`telemetry_coverage.policy_ref` and its one exact `evidence_refs` entry may differ.
Both originals, hashes and exact differences remain in the result. Any other
Outcome delta, lost sample, incomplete coverage or changed sample timestamp refuses
the join. A changed augmented projection does not update the live Outcome.

## Service and clock coordinates

`tests/real_systemd/signed_network_service.py` reuses the existing
`network_measure_driver.measured_capture`, G5 and
`azazel_edge.benchmark.measurement.measure_experiment` contracts. There is no
replacement benefit calculator or independent private PASS.

The proposed new fixed plan has a five-second service horizon starting at actual
H0 and a client origin exactly H0 + 1.25 seconds. The unchanged peer uses its own
client origin for request elapsed times. `service_capture` adds that exact recorded
monotonic offset only to capture-input elapsed coordinates. It keeps original
audit hashes, nonce, transaction IDs, error flags, measured duration, service goal
commit time and actual deadline; client ACK never becomes objective truth. This
places six unchanged client requests at their original offsets within the common
service horizon, without moving a recorded collector sample/action/window.

`record_clock_anchor` reads wall time inside a real monotonic bracket.
`clock_binding` maps two independently retained observer/controller brackets to
actual service H0, carries the measured uncertainty and never tunes alignment.
The existing measurement gate still withholds uncertainty or disagreement above
5 ms. Its session/clock declarations require independent review; these helpers do
not authenticate arbitrary imported JSON. All original clock brackets must be
archived together with the source and namespace/time-domain identities.

`recorded_root_probe` accepts only the fixed nft throttle query, successful raw
text, declared root/boot/namespace/source bindings, the explicit independent-root
capture label and actual bounded UTC query interval. It performs no query. Keep
its original launch receipt and raw result as independent lab facts. The receipt
is not signed authority proof, and matching an owner marker alone is insufficient;
G5 invokes the strict production full-chain/plan/owner/tuple parser.

`measurement_record` uses `edge_recording=None` only for baseline role
`observe_only`. The actual signed/native disabled/dryrun facts must be retained
separately; they are never rewritten into an APPLIED observe action. Candidate
records carry the unchanged actual event, boot, decision, execution, mechanism,
objective and canonical policy bindings into G5. The existing measurement checks
coverage, horizons, independent mechanism readback, verified release absence,
clock mapping, safety and paired assignment completeness. Unit coverage explicitly
keeps a missing release **withheld** even when a separate synthetic root receipt
makes the mechanism observed in a projection.

## Remaining gates before any VM work

The draft `signed_network_measure.py` is not a supported CLI or a reviewed runnable
coordinator. It must still bind the recording sidecar to the authentic complete
signed source and durable observer journal; freeze all four source-bound
assignments before any per-assignment preparation; and retain complete evidence
on any failure. It must retain separate service-only facts when the join is
withheld, reject duplicate/conflicting artifact identity, and validate four unique
actual kernel boots/scopes. Review and pin the complete code before execution.

Only four manually provisioned independent cold-boot VMs, or cold clones of a
strictly unused dependency-only template, qualify for that proposed test. No used
registration, keys, ledger, source history, journal or namespaces may be reset or
reused. Existing v4 registration, sealed ELF, full policy/event binding, separate
UIDs, fixed paths, AppArmor profiles, zero-cap observer and provider capabilities
remain required. If the actual observer label cannot sample procfs, record the
commissioning gap and stop; do not broaden profiles or substitute an unconfined
collector. No runtime or experiment-freeze command is supplied here.

Interface counters, system metrics and source-IP activity remain broad/confounded.
A truthful flow mechanism scope and measured service change do not establish
flow-specific Outcome metrics, actor attribution, production readiness, or causal
support. Resource overhead and physical-device G6 gates remain separate.

Hardware-free checks:

```sh
PYTHONPATH=.:py python -m pytest -q tests/test_signed_network_recording.py tests/test_signed_network_service.py
```

The fixtures in these checks are synthetic, including root query envelopes; they
are not substitutes for an actual signed/sealed VM experiment.

## Frozen plan and scope components

`signed_network_plan.py` now supplies the source-bound four-assignment plan,
canonical telemetry-policy digest, exact per-arm native environment/config hash,
and the narrowly tested provider preparation callback. Its protected-policy writer
is installed **before** the existing provider captures its raw writer; the actual
legitimate `10.91.2.2/32` protection therefore exists before registration. It has
no CLI and does not provision or launch a VM. The existing network setup can be
reused unchanged with fixed namespace names: edge `edge400-provider-edge`, client
`edge400-provider-client`, service `edge400-provider-service`. The edge interfaces
are `ec` (`10.91.1.1/24`) and `es` (`10.91.3.1/24`), with client attacker
`10.91.1.2/24`, extra legitimate address `10.91.2.2/32`, and service
`10.91.3.2/24`. Its explicit lab routes and edge-only forwarding introduce no
parent or default route. The peer constants, profile paths, existing provider
permissions and fixed edge namespace path are unchanged.

`signed_network_scope.py` reopens only all three complete saved creation-intent
and confirmed device/inode records in the same actual kernel boot. It validates
protected files, exact names, foreign-canary identity, parent-state snapshot and
all current named handles. Refusal closes only descriptors it opened; it never
predeletes or signals an unknown handle. The returned `FencedAssets` rechecks the
selected namespace identity before every namespace command or process spawn,
while the existing `Assets.close` retains its own cleanup identity checks.

`stop_systemd_actors` attempts every fixed observer, core/capture, witness and
namespace-preparation unit, with explicit 2/3-second command bounds. It retains
failed steps even after best-effort force stop. A stop receipt requires inactive
or failed units with zero main/control PIDs, empty original/final cgroups and
`cgroup.events populated=0` (including descendants). `close_namespaces_after_actors`
first writes that receipt and refuses namespace cleanup on any actor gap. Only
then does existing Assets cleanup reap its own peers and delete identity-matching
handles, checking the original parent snapshot and final handle absence. Evidence
files, failed units and original history are not cleared.

The remaining necessary operational functions are small but still unimplemented:
(1) marked-VM fresh preparation binding this exact plan/policy to the actual new
v4 registration, (2) one bounded assignment measurement connecting real observer
sidecar/readiness/clock anchors to unchanged service peers and a separate operator
root query, and (3) a read-only strict evidence export/import that verifies signed
source, durable journal and all four unique scopes, then calls the existing
RunLedger/measurement APIs. A new VM orchestration or accounting engine is not
required. The untracked draft is not an operational entrypoint; do not freeze an
experiment or invoke preparation until the complete reviewed source is pinned.

Cgroup absence is accepted only after proving the complete unified cgroup2 view:
physical protected canonical `/sys/fs/cgroup`, one root (`/`) cgroup2 mount, no
v1/hybrid or nested overlay, mount device matched to the opened directory, the
same cgroup namespace as PID 1, and the same full canonical root through PID 1.
Mount information is read completely to EOF within fixed bounds. Live main/control
PID membership must agree with the manager's exact `ControlGroup`. Empty group
names and absent directories are subject to the same hierarchy proof. Unknown,
missing, subtree or inconsistent views retain the scopes and a failed stop
receipt. These failures never skip the bounded stop attempts for other actors.
The future preparation/start phase must check this supported view upfront; a
shutdown failure still attempts every fixed actor before retaining evidence.

The fixed stop set also covers `edge400-signed-network-initialize.service`.
Collected transient workers still receive a bounded stop attempt. A nonzero stop
is acceptable only when both independently read states are exactly not-found,
inactive, zero main/control PIDs and empty `ControlGroup`, and the canonical
fixed unit cgroup also passes the full PID1-view emptiness check. Any read error,
timeout, unknown state, loaded replacement or descendant remains a sticky failure;
all other fixed actors still receive their stop attempt. This is not a generic
nonzero-command-success exception or permission to address other units.

## Real confined observer worker

`signed_network_observer.py` is now the fixed role entrypoint for initialization
and one live observer. It has no workload, kernel query, service-control or VM
orchestration loop. The initializer uses the actual root-owned fixture policy,
current registered authentication, existing journal APIs and identical `es`/0.25s
persistence context. It refuses unavailable real procfs coverage under the existing
label instead of broadening permissions. Initialization must be a genuinely empty
new source/journal; it is never a used-history reset.

The live worker requires the actual signed prepare/start prefix before recording.
It archives `observer-start-context.json` with original source-prefix offset/hash,
policy/registration/scope/identity and an actual clock bracket. That file is **not
readiness**: the root controller must still verify the actual journal's exact
durable `input_ready` position, then collect the real baseline before service H0.
The raw kernel UUID, injective `kernel-boot-<UUID>` journal reference and original
systemd `%b` wire boot ID (UUID's 32 hex digits) remain separate. Every authenticated
wire boot ID must match that explicit current-kernel mapping; no wire is rewritten.

The unchanged `run_live_resumable` runs inside `record_collector`, explicitly
passing only its protected registration path to the optional terminal-stop API.
There is no replacement live loop, signal catch, forced finalization, recovery
retry or backfill. After actual capture/core stop, a natural verified terminal
return closes the recorder. The worker retains the original terminal wire/decoded
bytes, final source binding, closed journal and a separate fresh role-authorized
read-only witness acknowledgement. The emitted receipt remains terminal CONTROL,
not measurement success or resume authority; pending loss remains visible.

Both worker names are fixed and retain the existing observer UID/group, AppArmor
label, zero capability set, AF_UNIX restriction and fixed provider-edge namespace
path. `Restart=no`, `DefaultDependencies=no`, a 40-second runtime and five-second
stop timeout are explicit. Before workload, the root-only `effective_observer`
check verifies actual effective command, UID/group/profile/capability/address-family
settings, namespace path, restart/runtime bounds, empty extra hooks/activation
dependencies, and actual kernel UID/caps/bounding set/label/cgroup/namespace. It
fences PID/starttime across that readback. This check grants no observer authority.

The operational assignment functions and evidence join remain unfinished and the
old untracked `signed_network_measure.py` is not an entrypoint. No four-assignment
manifest or source has been frozen and no signed network assignment has run.
The eventual first slice must require the actual signed release in an original
recorded collector callback with its unchanged real receipt epoch. Missing or
missed callbacks withhold the join while preserving service/provider facts; the
first slice will not invent or supplement an observer receipt.

## Manual preparation segment (no assignment run yet)

`signed_network_phase.prepare_assignment(expected_manifest_sha256,
expected_start_head)` now implements only fresh preparation. Both expected pins
are supplied out of band by the root controller. Its only script entrypoint is
`--namespace <manifest-sha256> <start-head>` for the fixed existing-capability root
namespace-preparation unit; it is not a general preparation/run CLI. The old
untracked `signed_network_measure.py` remains unused and must not be imported.

Mandatory operator sequence **before any assignment preparation**:

1. Review and freeze the complete source revision and all four assignments. The
   root controller constructs the manifest using existing `signed_network_plan`,
   freezes it through existing `RunLedger`, and starts exactly one assignment in
   the frozen order. Record the returned start head and unique run ID; use no new
   private accounting implementation.
2. Root verifies the frozen `git archive` SHA on the host **and guest**, extracts
   root-owned source without group/other writes, and stages protected
   `SOURCE_REVISION` with exactly that commit (optional final newline). Archive
   checks and the staging receipt are an external operator trust boundary for
   **all consumed source**, not an internal cryptographic source-tree assertion.
   The phase helper records protected direct-file hashes but does not substitute
   those self-observed hashes or the revision text for external archive checks.
   Use only the unused dependency template and independent cold boots/scopes.
3. Stage protected single-link root-owned files at
   `/var/lib/edge400-signed-network-manifest.json` and
   `/var/lib/edge400-signed-network-ticket.json`. The manifest is unchanged from
   the existing plan/ledger contract. The ticket has exactly
   `manifest_sha256`, `assignment_id`, `run_id`, `start_head`. The expected manifest
   digest is existing `manifest_digest(manifest)` (canonical JSON content), while
   raw file hashes are retained separately. Root passes the exact out-of-band
   manifest digest and start head to `prepare_assignment`.
4. The function verifies those pins, assignment, core bytes/config, exact source
   revision and protected direct files before mutation. It then checks the marked
   root/offline VM, unused material/unit/profile/namespace slots, full PID1
   cgroup2 view and empty fixed cgroups, no unmanaged core, and the actual isolated
   runtime API preflight. No `PYTHONPATH` fallback is supplied. The runtime's
   root-protected single-path `.pth` prerequisite must already be staged.
5. Existing account/profile preparation and `configure_assignment` install the
   exact protected-policy writer before provider configuration. The fixed root
   preparation unit retains only the existing SYS_ADMIN/NET_ADMIN bound and runs
   unchanged `Assets.setup` with the three fixed names. Original creation intents,
   confirmed device/inode identities, actual boot, foreign canary and parent-state
   snapshot are saved before provisioning any registered scope. No existing name
   is removed. The limited-capability namespace child does not need a new PID1
   inspection grant: the root controller already checked the full cgroup view.
6. Existing `guest.prepare_lab` provisions a genuinely new scope and starts the
   witness first. Its callback normalizes traversal only on the owned lab base
   just created by this invocation, then invokes the real confined initializer.
   The callback never supports recovery/reset and retains raw initialization
   output even on a timeout. The exact materialized v4 environment and protected
   policy hash are checked before ordinary-core start. The existing empty-EVE
   ordinary-core → reviewed `Switch.plan/apply` → actual provider identity sequence
   follows; an inactive Switch is never used to newly enable enforcement.

`prepared.json` retains input/ticket/file hashes, actual boot, public trust and
registration, isolated preflight and native PID. It labels preparation only;
there is no service measurement, quiescence, efficacy or production-admission
claim. Any failure after mutation attempts all fixed actor stops before reopening
or deleting namespaces. Only verified stopped actors permit the existing
identity-fenced cleanup; unknown identities/state retain evidence and annotate the
original failure. Never repair or retry a used/failed assignment.

The timed assignment runner and authenticated read-only join are still pending.
Nothing in this segment authorizes starting workload or freezing an actual
experiment before independent review of the complete frozen source.

Preparation has one narrow cleanup-order exception: if `Assets.setup` fails
inside the fixed namespace-preparation unit, that unit may immediately call the
existing `Assets.close` for **its own confirmed created identities** before it
exits. At that point no namespace workload children or registered actors exist;
unknown/unconfirmed names and original partial intents remain for review. This is
not a new partial-cleanup engine. Once provisioning begins, every failure still
requires verified stop of all fixed actors before namespace deletion.

The observer terminal result also retains an actual `end_clock_anchor` sampled
immediately after the natural live API return and durable recorder close, before
result materialization. It is not reconstructed from the last sample or scheduled
horizon. Together with the original start anchor, per-call anchors and separately
recorded controller start/end brackets, it supports only the fixed-budget sampled
clock-consistency qualifier; it cannot prove continuous unsampled stability.

## Manual bounded assignment run (calculation still withheld until segment 3)

After independently reviewing the complete frozen source and successful fresh
preparation, Root may call
`signed_network_run.run_assignment(expected_manifest_sha256, expected_start_head)`.
This is a single manual assignment function, not a VM/accounting/retry engine.
It revalidates protected inputs against `prepared.json`, actual kernel boot,
public registration/trust and the actual sole native identity. Only a fresh
complete signed prepare/start prefix qualifies. An exclusive `run-intent.json`
claims the attempt before reopening assets; an existing intent refuses without
stopping another already-started run. No used assignment is retried.

The fixed helpers have only these purposes: bounded authenticated source polling,
existing Rust-adapter arm/task checks, a fixed explicit ROOT read-only query child
and bounded raw-envelope transport, and exact closed-recorder callback lookup.
No replacement source parser, collector loop, G5 pipeline, RunLedger or benefit
calculator is introduced. The query child is the module's only script entrypoint;
it checks the marked root VM, frozen input pins, actual boot and owned namespace,
then runs only the existing `SubprocessReadOnlyRunner` fixed throttle-chain query.
It is not callable with observer privileges and is no privileged observer proxy.

Sequence and retained facts:

1. Reopen all saved namespace identities through `FencedAssets`. Capture the
   independent baseline ROOT chain and require the original unique foreign canary.
   Stage the unchanged service peer and configuration before starting the observer.
2. Start the existing fixed observer role with private exclusive stdout/stderr.
   Within two seconds it must remain alive, expose matching startup context,
   actually persist the exact `input_ready` source-prefix offset/hash, and pass
   effective-unit/kernel/namespace/PID identity checks. A context file alone is
   never readiness.
3. Record an actual controller start clock bracket and actual monotonic H0. The
   service receives H0 and H0+5s. The unchanged client receives the frozen protocol
   origin H0+1.25s and actual deadline, and may launch before that target; retain
   its original argv and real spawn brackets. That scheduled protocol coordinate
   is not represented as the actual process-start timestamp. Wait for the real
   baseline interval, append exactly one current fixed EVE record, and retain its
   bytes and real append brackets. No new event/sample/metric timeline is fabricated.
4. Poll the existing `SourceVerifier`-authenticated complete prefix. An incomplete
   writer tail is only not-ready and remains byte-for-byte preserved; complete
   signature/registration/session/boot/tuple/task mismatches fail immediately.
   Native decision/provider facts stay unchanged, including disabled C0 status.
   Both arms retain the same separate ROOT active query; candidate full rule
   semantics reuse the production parser. Original foreign chain context must
   remain unchanged. Root queries never enter the live observer.
5. At actual H, record the controller end bracket and preserve unchanged service
   and client audits. Existing service capture performs the explicit client-origin
   coordinate translation. Candidate waits at most 32 seconds from the actual
   alert append for its signed matching release, then requires independent actual
   absence with the complete original foreign context. Baseline executes no command
   and also receives the independent absence query.
6. Stop actual capture/core first (two-second command bound), keep witness and
   observer alive, and wait at most two seconds for natural optional terminal drain.
   Verify closed signed source, actual terminal origin/cursor, journal close and
   fresh witness state before inspecting the closed recorder. Lookup requires the
   exact original event's canonical bytes, not only a matching task or Python
   numeric equality. Preserve the unchanged actual callback receipt epochs; missing
   decision/release callbacks or terminal pending loss yield `withheld`. No native
   attempt time is substituted for an observer callback time.
7. All fixed actor stops/quiescence proof precede existing identity-fenced peer and
   namespace cleanup. Cleanup, child reap and all log closes continue even after
   an artifact write/close failure. Failure snapshots retain the last observed raw
   source (including partial bytes), original facts and sticky failure; they never
   publish success or authorize repair/retry. A success file appears only after
   cleanup passes, with status `run_facts_complete` or `withheld` and explicit
   `measurement_completed=False`, `production_admission=False`.

The 40-second observer bound and 900-row recorder bound are unchanged. Slow but
otherwise correct runs can fail/withhold; no post-result retuning or retry is
allowed. The full readonly join/clock/window qualification remains segment 3:
`run_facts_complete` is not a measurement PASS. Actual live Outcomes/raw calls stay
separate from any later explicitly labelled ROOT-augmented G5 calculation.
Before any assignment freeze/VM work, Root must also resolve the existing-label
procfs commissioning gate with its separate read-only confined precheck. A denied
sample is a gap, never permission to broaden the profile or substitute an
unconfined collector.

Each successfully received peer audit is now persisted immediately and exclusively
before the next receive, wait or validation. `service-audit.json` and
`client-audit.json` preserve the unchanged decoded audit objects; their exact
artifact byte hashes, object digests and paths enter partial facts immediately.
These are canonical JSON artifacts, not claims about original stdout whitespace.
A later client receive or either peer wait failure therefore keeps the already
received independent service/client facts and still runs all cleanup. It does not
turn an incomplete join into a successful measurement.

## Read-only per-assignment import (code only; commissioning blocked)

`signed_network_read.read_assignment_artifacts(expected_manifest_sha256,
expected_start_head)` reads the **original protected guest layout** after the
reviewed runner has finished cleanup. It has no CLI, write operation, subprocess,
socket, journal reopen, witness store, key-material read, recovery or retry. It
uses the same external Root source-archive verification boundary as preparation;
self-observed source hashes are not an independent source attestation. It does not
support arbitrary imported artifact maps, ownership repair or remapped archives.

Original service/client audits are read independently before other prerequisites.
Bounded journal Outcomes and raw call-file hashes are also retained on a failed
run, explicitly labelled unverified until the original signed witness chain is
checked. A missing/failed/withheld run never produces a measurement record. All
successfully read original files keep their byte hashes; repeated and final reads
must retain byte content and device/inode identity. Files are never rewritten.

The importer verifies public v4 live-core enrollment and its exact frozen arm
configuration, the complete original signed source, actual terminal wire and
decoded bytes, explicit raw-UUID/systemd-hex/journal-boot mappings, full ordered
source cursor coverage, genuine initialization plus live session, and durable
terminal close. Pending/lost windows, recovery transitions, observed control
frames, missed activity or incomplete source are unavailable. C0 must pass the
same signed session, terminal, journal and witness checks; its existing baseline
`edge_recording=None` exemption does not waive authentication or convert its
native disabled/dry-run execution fact into an applied action.

Every **original signed witness anchor** is checked with the existing public-key
verifier and `ANCHOR_DOMAIN`, exact schema/counter/previous/trust digest, source
prefix sequence/head/size/hash, journal prefix sequence/head/size/hash and actual
journal device/inode. Genesis and the complete final prefixes must be present;
the final signed state must exactly match the worker's acknowledged state. An
unsigned state JSON, successful command, marker or matching task is insufficient.
Import limits are deliberately smaller than runtime retention: 4 MiB/512 source
records, 8 MiB/4096 journal frames and 8 MiB/4097 signed anchors, also bounded by
the registered anchor limits. Prefix digest construction is incremental; public
signature verification still processes the complete finite prefix history.

Only exact original collector callbacks and their unchanged epochs qualify.
Actual start/end controller and observer brackets plus per-call brackets pass
the fixed 5 ms `qualify_clock` gate; this is **sampled anchor consistency**, never
continuous unsampled clock proof. H remains the original 5 seconds, with the real
client protocol origin 1.25 seconds later. No timestamp is shifted to repair a
missing callback, pre-event Root probe, drift or sample/window gap.

The separate Root baseline/active/absence receipts must retain their original
launch PID, fixed namespace intent/confirmed identity, boot, source pins and full
chain context. Candidate full owned-rule semantics and foreign-context preservation
reuse the production parser; the observer receives no query capability or proxy.
The original live journal Outcomes, output export and raw recorder remain unchanged.
Existing `replay_calls` first checks the plain G5 projection with only its explicitly
named policy-source-label equivalence, then creates a **separate Root-augmented
G5 calculation**. Any projection mismatch or unavailable coverage withholds the
record; it never replaces the actual live Outcome or its confounders.

A successful import returns `status=calculation_available` and the existing
`measurement_record`, **not a measurement PASS**, production admission, successful
live observer NFT confirmation or resume authority. Existing `measure_experiment`
will still apply its window, coverage, release and attribution gates. This reader
never calls that four-assignment calculator prematurely. Cross-four freshness
validation (boots/scopes/sessions/registration and public keys) remains a separate
small pending component; Root must finish that validation before calling the
existing calculator or RunLedger completion. No four-assignment source/manifest
has been frozen and no assignment has run.

The independent confined precheck has now established a concrete commissioning
block: the unchanged enforcing observer label/capability/address-family settings
can read `/proc/meminfo`, but `/proc/net/dev`, `/proc/loadavg` and `/proc/uptime`
return EACCES. This code does not address or bypass those permissions. The current
four-run experiment remains **COMMISSIONING_BLOCKED**. The importer checks are
synthetic hardware-free tests with genuine ephemeral source/witness signatures;
they do not establish an actual complete imported calculation or service effect.

Native session identifiers also retain two explicit domains. Original signed
wire and `authenticated_origin.session_ref` retain the exact 32 lowercase hex
digits, including a leading digit. The existing measurement reference grammar
requires a leading letter. Only the test bridge therefore names the linkage
`native-session-<original-32-hex>` using `native_session_reference`; removing that
fixed prefix recovers the original uniquely. The reader and four-record structural
gate require this exact mapping. No original ID, signed byte, cursor, Outcome,
clock or production measurement parser is changed, and no session is repaired or
authenticated by adding the label.
