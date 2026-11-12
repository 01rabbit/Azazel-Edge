# Source byte authentication and independent recovery evidence — #400 / #393

## Frozen scope and invariants

Base main 4848bbce. Freeze this document and cases before implementation.
This stage authenticates recorded Source bytes and checks independently enrolled
post-run observer-resource evidence. It does not qualify safety, application
receipt, network restoration, comparative efficacy or production admission.
Existing safety/ingress/queue schemas and semantics stay unchanged. Independent
positive observations survive absent/invalid Source suffix or recovery evidence.
Missing data is unknown, never zero or reconstructed. No services, keys, runtime
resume, policy, installer, security or systemd changes.

## Source input and trust

Pure API verify_source_bytes(trust_raw, source_raw, *, expected_trust_sha256,
expected_context, expected_prefix_checkpoint, expected_final_checkpoint).
Trust bytes are canonical existing TrustPolicy JSON plus LF (32 KiB maximum).
The file SHA includes LF; TrustPolicy.digest does not. Only registered live v3/v4
policies are accepted. Reuse SourceVerifier, existing domain, signatures, chain,
and lifecycle FSM, without filesystem access, witness clients or private keys.
Source events may contain existing finite floats; do not impose safety JSON's
integer-only event grammar.

Context exact keys: scope_ref, producer_ref, stream_ref, registration_sha256,
session_ref, boot_ref, producer_public_key, witness_public_key, producer_uid,
observer_uid. boot_ref is exact canonical kernel UUID without hyphens; session
is 32 lowercase hex. Policy keys/IDs/UIDs/registration must agree. Every Source
wire must match boot_ref; all registered lifecycle events must belong to the one
session. Signer identity is authenticity, not proof an execution really happened.
Root/operator custody, source registration and independently retained checkpoints
remain external trust assumptions; public fixture keys establish none of them.

Checkpoints exact seq/head/size/sha256, using existing SourceVerifier tip semantics:
head hashes canonical signed last row without LF, sha256 hashes all prefix bytes
including LF. Verify the externally sized prefix once, then the full suffix once.
Nonempty valid signatures and exact checkpoint required for authenticated_prefix.
Empty data proves no producer signature. Bad or missing full input preserves the
previously verified prefix; it never authenticates a partial/bad suffix. Full byte
authentication and normal closed terminal are separate booleans. No terminal or
older matching prefix is evidence of recovery or run completion. External final
checkpoint prevents accepting an older authentic prefix as the enrolled full input;
it is not a durable one-use registry or a witness-custody proof.
Malformed global trust/pins/context raise an input error. Byte, signature, chain,
checkpoint, boot/session and terminal failures yield unqualified diagnostics.
No Source-authentication prefilter may erase independent forged-acceptance facts.

## Independent recovery scope and feasibility

A loader return, close success, missing process FD, Source terminal/cleanup claim,
or an unprivileged empty inventory is NOT independent kernel teardown evidence.
A new externally pinned resource plan identifies two tracing links, two programs
and four maps, their complete selected kernel identities, boot, capture interval,
contract/queue-plan/report hashes and checker public key. A separate checker
samples only those IDs, reads metadata, closes its temporary query descriptors,
and signs a new-domain report. It never detaches, deletes, loads, pins, sends,
changes networking, retries, or grants authority. Record positive residue when
identity matches; ENOENT can establish absence only if the kernel query was
actually permitted. Reused/mismatched IDs, errors, failed descriptor closes,
wrong/changed boot, missing resource coverage or report bindings remain unknown.
All eight sampled absent is only finite sampled observer_objects_absent, not
continuous absence, restoration of nft/tc/conntrack/network state, lack of other
objects, or whole-system cleanup. network_mechanism_restored remains unknown.

Feasibility was checked on offline Linux6.8 ARM64: direct link/program/map ID
lookup returns EPERM under existing BPF+PERFMON+NNP. Upstream Linux6.8 requires
CAP_SYS_ADMIN even for direct ID lookups. Retaining a link FD prevents its
release, so it is no alternative. Do not add SYS_ADMIN to this environment or
the sensor to make tests pass. The runtime checker must report unavailable/
unknown here; a denied query is not an absent resource. Authorized dedicated
inventory privileges and actual positive/residue/reuse cases in a separately
provisioned isolated environment remain required before claiming actual teardown.
Reference: Linux v6.8 kernel/bpf/syscall.c bpf_*_get_fd_by_id implementations.
No new kernel capability is granted by this change.

## Composition and sealed intake

New additive schemas/domains only, no conversion into old delivery/safety records.
The combined diagnostic evaluates the old independent safety evidence first and
keeps it intact. Source context/prefix hash must bind to the contract's scope,
policy and registered keys. Recovery plan must bind to the contract and its
boot/time; report signature uses the enrolled observer key and an externally
retained report digest. Both proof legs remain independent diagnostics with all
existing authority flags false and qualified_safety_count null. New registered
intake uses the existing held-FD/root0444/single-link/ancestor fences, nonroot
reader and external hashes. Old intake formats are unchanged.

## Stages and acceptance

1. Commit contract/cases first. Implementation and synthetic adversarial tests
   are separate ownership; integration owns real Linux tests and CI.
2. Source positive/negative signatures, registered session/boot, prefix and final
   checkpoint tests; invalid-suffix plus independent positive preserved.
3. Synthetic resource proof positive/residue/reuse/error/coverage/signature tests
   explicitly do NOT prove actual teardown. Actual Linux capability-denial tests
   exercise real syscalls under BPF+PERFMON and no-cap roles, with unknown results.
4. Actual separate-UID sealed intake with unchanged artifact hashes; unsafe paths,
   changed bytes or external pins refuse without writes. No Linux-required CI
   case may silently skip. Negative feasibility tests passing means honest refusal,
   never observed restoration. Positive privileged-kernel tests remain blocked.
5. Independent review, final-head full CI and base/head/tree checks before merge.
   Update existing #400/#393 with scopes, actual measurements and remaining gates.

## Fixed cases

See tests/fixtures/source-recovery/v1/cases.json. SYNTHETIC recipes and actual
Linux cases are explicitly separated. No acceptance threshold is fitted afterward.

## Wire/API clarification (same frozen acceptance scope)

Source plan exact keys: schema_version=edge-source-proof-plan/v1,
contract_sha256, trust_sha256, context, prefix_checkpoint, final_checkpoint.
The scope policy_sha256 is the raw canonical trust-file SHA including LF;
scope source_sha256 is the trusted Source prefix SHA, not a full-suffix validity
requirement. Missing Source/checkpoint arguments are None and yield unknown.

Recovery plan exact keys: schema_version=edge-observer-recovery-plan/v1,
contract_sha256, queue_plan_sha256, queue_report_sha256, kernel_boot_id,
kernel_release, observer_public_key, not_before_ns, deadline_ns, resources.
The sample window is positive and at most60s. Each of eight resources is exactly
{kind:link|program|map,id,identity_sha256}; IDs positive uint32, unique within kind.
Identity SHA is canonical selected metadata without LF: link kind/id/type plus
program_id/attach_type/target_object_id/target_btf_id; program kind/id/type/tag
(exact8-bytehex)/load_time_ns; map kind/id/type/key_size/value_size/max_entries/
map_flags/name_hex(exact16-bytehex). External Root enrollment must establish
these were the scoped owned objects; hashing arbitrary IDs is not enrollment.

Recovery report exact keys: schema_version=edge-observer-recovery-report/v1,
plan_sha256, kernel_boot_id, kernel_release,
observation_layer=observer_object_id_lookup, started_ns, finished_ns,
context_stable, resources, signature. Each resource sample is exactly
{kind,id,started_ns,finished_ns,state,identity_sha256,reason}. Closed state/reason
pairs: absent/not_found; present/matching_residue; identity_reused/identity_differs;
unknown/{metadata_failed,query_denied_or_failed,query_fd_close_failed}.
Only present/reused carries an identity SHA. Contradictory signed assertions are
invalid samples, never absence. Invalid siblings preserve admissible residue.
Domain is b"azazel-edge:independent-observer-recovery:v1\x00"; sign canonical
unsigned body without LF. External plan/report hashes include LF.
All query brackets must be inside the report and enrolled post-run window.

The current checker enforces Root+NNP with identical permitted/effective/bounding
sets either empty or exactly BPF+PERFMON, no inherited/ambient capabilities.
It never admits SYS_ADMIN or expands the sensor's boundary. Thus actual positive
Linux6.8 inventory proof is unavailable to this version. A future privileged
collector needs separate review/provisioning; synthetic acceptance of an enrolled
report is not privileged collector validation. Failure to load the fixed library,
wrong role/boot or inability to sign returns no report, never simulated evidence.

Composition API evaluate_safety_proofs evaluates old safety evidence first;
supplemental malformed bytes become unknown without suppressing those positives.
The existing UDP queue contract admits one protected opportunity and no other
category opportunities. Recovery composition deliberately retains that restriction;
a general multi-channel recovery join is not implemented. Source/forgery proofs
remain evaluable separately. Recovery binds an actually authenticated historical
queue report; not_before_ns must be at least that report's finished_ns. This proves
only after that observer capture, not after a larger defense experiment's end.

Sealed supplement exact keys: schema_version=edge-safety-proof-enrollment/v1,
enrollment_sha256, checkpoint_sha256, paths, sha256. The last two are exact maps of
source_plan/trust/source/recovery_plan/recovery_report/queue_plan/queue_report to
normalized absolute distinct paths and byte hashes, or matched None pairs.
Reuse held-FD metadata/ancestor fences through final validation and close. Source
file cap64MiB, trust/plan/recovery/supplement32KiB, queue report64KiB. Missing declared
files or unsafe metadata refuse the whole intake; explicit None is unknown.
Original four-file enrollment/checkpoint schemas and old diagnostics stay intact.
