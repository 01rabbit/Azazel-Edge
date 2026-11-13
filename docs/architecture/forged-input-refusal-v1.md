# Recorded forged-input refusal and independent state samples — #400/#393

Freeze before implementation, base4a372ef33b5ec49041a247e9ecb1b54d41fafa44.
Reuse existing SourceVerifier, InputAuthentication, BoundedInput,
ObservationJournal, witness and sealed-read paths. No authentication/runtime
policy, provider, privileges, services, installer/security/systemd or production
key/deployment change. Offline only; no repair, backfill, auto-resume or history
rewriting. Existing98%/1.2x and comparative timing gates are untouched.

## Finite challenge and fact boundary

First slice ONLY exercises a well-shaped registered v3 Source with an authentic
nonempty prefix and one otherwise eligible next frame whose Ed25519 signature
is deliberately invalid. Independently verify the exact original challenge with
unchanged SourceVerifier and distinguish its signature failure from malformed
wire, wrong context, permission failure, generic error, silence, timeout or kill.
The submitted bytes must remain unchanged through the attempt. Other forgery
types are future separately frozen controls, not implied coverage.

The actual separate-UID Linux consumer uses existing BoundedInput and journal
authentication. Retain exact refusal class/reason and original worker stdout/
stderr, process UID/PID, code hash, boot and bounded execution facts. These are
Root-controller provenance assertions; exit status alone is never refusal proof.
No synthetic success worker, mocked verifier or re-signed observer fact may stand
in for the actual attempt. Lifecycle event payloads and test keys remain lab data,
not native defense execution or production key-custody evidence.

Before challenge, genuinely initialize the existing witness and observer state,
accept a valid signed prefix and retain its exact independent checkpoints. Stop
or pause existing writers at a documented boundary. The baseline may be a closed
session before a refused reopen, or paused before consumption; specify which.
Acquire independent before/after original Source, journal and anchor bytes plus
dev/inode/uid/gid/mode/nlink/size/mtime/ctime and read times with bounded stable
held descriptors. The comparison interval must bracket the actual verifier
attempt and end BEFORE normal close/recovery/cleanup effects. No closing/reopening
the journal merely to read it. The read-only observation path never writes a
target artifact or requests a witness append. Harness setup/generation/teardown
are separate trusted roles. No private key belongs in a public export.

Validate journal chain and cursor data against the exact baseline bytes and
signed witness tip where feasible using existing primitives; explicitly mark any
semantic journal/cursor verification not established. Raw equality proves only
unchanged sampled persistent bytes/identity, not absence of transient writes,
all-horizon safety, execution truth or physical durability. No same-UID/Root
adversary resistance is claimed. A sealed exported copy's inode is distinct from
the recorded runtime inode; never substitute one for the other.

## Additive offline verification and intake

Add a versioned externally hash-pinned plan binding exact trust/context, Source
prefix and anchor checkpoints, challenge SHA, capture ID, before/after artifact
hashes/metadata and worker evidence. Pure verification consumes bounded original
bytes only; no I/O/process/network/key/signing/live query or witness request.
Root-sealed nonroot intake reuses existing held-FD/protected-ancestor/0444/
single-link/actual UID+boot/all-close fences and external enrollment/plan pins.
No old schema, evaluator, count or admission guard is upgraded implicitly.

Result distinguishes recorded refusal consistency, unchanged sampled state,
observed persistent change, and unknown with reasons. Any valid observed journal,
cursor or anchor change is preserved even when another artifact or worker proof
is missing/invalid. Missing/incomplete/unsafe/unpinned input never yields zero,
unchanged or refusal. The known positive is a bound state-change diagnostic, not
automatically forged acceptance, a safety count or an authentication oracle.
All runtime/experiment/causal/admission authority remains false and qualified
safety counts null. Original measurements stay immutable.

## Controls and acceptance fixed before code

1. Actual valid eligible next input in a separate matched scope advances the
   authenticated cursor/journal/witness, proving a functional positive path.
2. Actual invalid signature refuses with exact exception; submitted Source and
   independently sampled journal/cursor/anchors stay exactly unchanged.
3. Missing/failed/partial/oversized/wrong-context/hash/identity/clock/worker evidence
   remains unknown, without suppressing a valid independently observed change.
4. Synthetic parser/crypto negatives separately cover malformed plans, bool-as-
   integer, duplicate/noncanonical/deep JSON, wrong signature/domain, altered
   baseline/after/cursor/anchor, generic error, exit-only, forced stop, changed
   Source, missing controls and untrusted baseline/checkpoints.
5. Actual Linux intake tests use separate producer/consumer/reader UIDs, check
   unsafe sealed files, original immutability and producer/Root reader refusal.
   Required Linux CI must execute without skips; unsupported environment is
   blocked/unknown, never permissions expansion or simulated success.
6. Independent code review, appropriate regression tests, complete final-head CI
   and exact live base/head/tree are merge gates. Update existing#400/#393; no
   duplicate issue. No deadline/automation is inherited from prior work.

## Frozen wire clarification before implementation

Pure API: `verify_forged_input_refusal(plan_raw, *, expected_plan_sha256,
trust_raw, before, after, stdout_raw, stderr_raw)`. `before` and `after` each
have exactly `source`, `journal`, `anchors`, values original bytes or None.
Before Source is the full poisoned Source (authentic nonempty prefix plus ONE
otherwise eligible next frame with an invalid 64-byte Ed25519 signature), NOT
the earlier prefix alone. Its externally retained Source checkpoint selects only
that authentic prefix. After Source must match the entire poisoned before bytes.

Plan uses canonical journal `_json` plus ONE LF; its external SHA includes LF.
Exact keys: `schema_version` (`edge-forged-input-refusal-plan/v1`), `capture_id`,
`kernel_boot_id`, `expected_trust_sha256`, `expected_context`,
`expected_source_checkpoint`, `expected_anchor_checkpoint`, `samples`, `worker`.
Context/checkpoints reuse the public witnessed-Source-prefix API unchanged;
Source checkpoint is nonempty and anchor checkpoint selects the complete baseline
anchor log. Boot is a canonical UUID and matches context.boot_ref without hyphens.
`samples` has exactly `before`, `after`, each exactly the three artifact names.
A sample descriptor is None only for unavailable original bytes; otherwise exact
`{sha256,read_started_ns,read_finished_ns,identity}`. Identity exact keys are
`device,inode,uid,gid,mode,nlink,size,mtime_ns,ctime_ns` (mode permission bits).
All integer fields are exact ints, never bool. Positive device/inode, nlink1,
nonnegative size/times; Source0644 producer UID, journal0600 consumer UID,
anchors0600 witness UID. Original gid is retained, not inferred from uid.
Before sample read end <= worker start; after sample read start >= worker exit;
all intervals nondecreasing. Equality requires identical full original metadata
and bytes; identities here are original runtime metadata, not exported-copy IDs.

Worker exact keys: `pid,uid,code_sha256,started_ns,exited_ns,returncode,forced,
error,stdout_sha256,stderr_sha256`. UID is the policy consumer/observer UID;
code hash is an externally enrolled Root assertion, not authentication of code
execution by the pure verifier. Required refusal stdout is EMPTY; original
stderr ends with the exact complete traceback line
`azazel_edge.outcome.journal.OutcomeJournalError: authentication signature invalid\n`.
Require normal nonzero returncode, forced=false, error=null. Silence, exit alone,
other exception, timeout, kill, partial traceback or stdout success is unknown.
There is no caller-provided refusal/success flag. Actual worker uses unchanged
runtime authentication before recovery/session mutation; test control is a separate scope.
The existing reopen path opens, locks, loads and fsyncs the journal before the
Source snapshot is verified. No pre-open refusal or absence of fsync is claimed;
constructor failure closes descriptors without appending a new session.

Bounds: plan/trust/enrollment32KiB each, each original artifact1MiB with at most
4097 LF-delimited rows and no bare CR, each stdout/stderr64KiB. Journal proof
checks canonical hash chain, header input authentication/context, closed baseline,
and the last typed cursor matching the authentic Source prefix; separately bind
EVERY witness journal assertion to an exact journal byte boundary and runtime
journal identity. Report this as `journal_cursor_structurally_verified`, NEVER
full journal semantic verification (`full_journal_semantics_verified=false`).
No reuse of a read-write journal instance is permitted for offline verification.

Intake: `collect_forged_input_refusal(enrollment_path, *,
expected_enrollment_sha256, expected_plan_sha256)`. Enrollment canonical plus LF,
exact `{schema_version:'edge-forged-input-refusal-enrollment/v1',plan_sha256,
reader_uid,kernel_boot_id,paths}`. Reader is actual nonroot uid, distinct from
producer AND consumer AND Root; initial actual Linux reader65533. Paths exact
`plan,trust,before_source,before_journal,before_anchors,after_source,after_journal,
after_anchors,stdout,stderr`. Missing artifact descriptor requires corresponding
path None; all present paths, including enrollment, are distinct physical absolute
paths with existing protected Root ancestors. Files Root0444/single link, held
through pure verification and all final metadata fences; close errors block return.
Actual kernel boot and reader UID checked before and after; no key or live endpoint
read. Enrollment externally pins plan, plan independently pins every artifact.

Return schema `edge-forged-input-refusal-diagnostic/v1`, status
`recorded_refusal_consistent` or `unknown`, nullable `sampled_state_unchanged`,
`observed_persistent_change`, per-artifact `changes`, `invalid_signature_verified`,
`baseline_witness_verified`, `journal_cursor_structurally_verified`, reasons,
`full_journal_semantics_verified=false`, qualified_safety_count=null and all five
existing authority flags false. A validated bound artifact's positive change
survives missing/invalid siblings or worker evidence; unknown is never zero.
Intake wrapper `edge-forged-input-refusal-collection/v1` retains diagnostic under
`evaluation`, enrollment/plan hashes and reader/boot provenance, all flags false.
Sealed equality is not cross-file atomicity against Root, absence of transient
writes, actual execution authentication, cleanup proof, sensor truth or admission.

## Validation record before final CI

49 synthetic parser/real-test-crypto/unit cases passed;112 existing Source proof/
witness regressions passed. These are software tests, not actual refusal facts.
Two actual offline Linux scopes used the existing UID1000 producer,65534 consumer,
Root witness/controller and a distinct65533 sealed-artifact reader. The fixture
used only the existing setup capabilities CHOWN/SETUID/SETGID/DAC_OVERRIDE/FOWNER,
NNP and network-none; no SYS_ADMIN, BPF, NET_ADMIN, new privilege or host service.
Source code was mounted read-only. The genuine lifecycle payloads are lab data,
not native defense-execution facts.

The invalid-signature scope produced an actual uncaught authentication signature
exception and normal nonzero exit. Independent samples retained identical Source,
journal and anchor bytes AND the enrolled original identities/metadata. Genuine
prefix/witness, closed journal chain and selected cursor were reverified. Reader
65533 succeeded; Root/producer/consumer readers and unsafe sealed material were
refused; original sealed samples remained unchanged. A separate valid-next-frame
control advanced the authenticated cursor through existing recover_input's explicit
missed-backlog path. This proves the acceptance path, not Outcome or app processing.

Initial actual run: invalid case passed; valid control failed because its test
worker redundantly read after recover_input had already consumed the restart tail.
Only that test control was corrected and rerun successfully. No product guard,
runtime authentication or failed evidence was changed; the negative worker/code
hash and original public bytes remain unchanged. Independent review is clean.

The public export contains exactly11 original public files and one manifest;
no keys or whole private fixture. Externally retained manifest SHA256
`46532b40a747d0b10519adc8d50cdaf1e686332fed46c086c5ce6b20e825e9c2`
binds every file's original size/hash. Pure offline replay with the final session-
binding guard reproduces the original published result exactly, with no fresh
process or observation. Existing valid observations are not rerun as substitutes.
Final-head CI additionally retains a fresh public export, must execute the actual
Linux cases without skips, and remains required before conditional merge.

## Frozen CI environment correction

First PR CI43355694926 selected ubuntu-26.04 for the existing service-objectives
job's ubuntu-latest alias. Its unchanged Ubuntu24.04-only mirror guard refused
before dependencies or any measurement. Preserve that failed run. Before fixing
the workflow, freeze this boundary: pin ONLY that existing job to ubuntu-24.04,
matching the guard and existing systemd labs. Do not expand the OS/Root/hosted-runner
guard, change apt security checks, add privileges, skip tests or weaken verdicts.
All other jobs and runtime policies remain unchanged; new final-head CI required.

The same first run's Python job also selected Ubuntu26.04:260 actual Linux cases
passed (including both new refusal/control cases), while24 existing UDP-copy
cases failed at compilation under its changed toolchain. No sensor success is
claimed for those cases. Pin this job to the prior validated Ubuntu24.04 as well;
do not modify sensor source/compiler stack limits or skip unsupported cases.

Public upload separately failed because its new Root-owned export directory was
0700. Only the fixed-whitelist PUBLIC COPY directory will be0755 with files0444,
so the ordinary CI uploader can read it. Original private/runtime and Root-sealed
intake directories/permissions remain unchanged. Test the public-copy readability
from an unprivileged existing UID; no key/private fixture is exported.

Correction checks:37 existing CI guard regressions passed, including the exact
two affected host pins. A separate permission-only Linux check copied the retained
public artifact into a new0755 public directory with0444 files; UID1000 verified
the exact12-file allowlist and all original manifest hashes/sizes. No verifier,
Source attempt or protected-state measurement was rerun. Private/runtime/sealed
permissions and original manifest bytes stayed unchanged. Independent review of
the two image pins and public-copy boundary is clean; new full CI still required.
