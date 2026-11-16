# Enrolled finite artifact binding for safety observations v1

Tracking #400/#393. Base `190750e3`. Freeze this contract and the protocol before
implementation and any fresh capture. Preserve all original reports and failures.

## Scope and authority

Add a read-only annex to the existing safety evidence composition. Call the
existing composition FIRST with its original contract, observations, external
pins, composition plan and flat supplemental artifacts. Preserve that entire
result unchanged, including main positives, zeros/nulls, original seven verifier
results, historical-reference labels and blockers. Invalid main still raises its
original error. No supplemental binding can alter a category count or opportunity,
qualify safety/comparison, authorize admission/resume or establish causal benefit.
All five safety authority flags remain false and qualified_safety_count remains
null. No production, service, privilege, key or installer/security/systemd change.

Version 1 enrolls only `forged_refusal_v2`. Other six existing families continue
through their original APIs and are explicitly unsupported/unknown for the new
binding annex. Missing fields are never inferred from time proximity, identical
request text or a nearby historical case. Root/controller/kernel/test keys and
actual collector custody remain declared lab premises. Equal hashes and matching
IDs establish the enrolled original-byte association under those premises; they
do not independently attest true capture, process execution or physical events.

## Existing identifiers and exact meanings

The original main contract already carries boot, Source scope/session/registration,
producer/observer roles, Source/witness key pins, trust hash, channel/capture IDs,
and explicit opportunity IDs. Forged v2 carries corresponding expected_context,
trust and baseline checkpoints, capture_id, worker facts and the original reference
frame hash. Use these exact fields; do not invent or translate an old schema.

- main scope.source_sha256 equals the authenticated BASELINE Source checkpoint
  plan.expected_source_checkpoint.sha256. It does not name the poisoned suffix.
- The full original submitted before_source bytes, including baseline and invalid
  suffix, supply opportunity.challenge_sha256, predicate.invalid_input_sha256 and
  fact.data.input_sha256. All three equal SHA256 of those original bytes.
- opportunity.reference_sha256 equals SHA256 of the original reference_frame,
  also equal to plan.challenge.reference_frame_sha256.
- The selected signed main fact raw_ref_sha256 equals SHA256 of the original
  supplemental plan. Its journal and anchor before/after hashes name those exact
  original artifacts, including empty bytes where the original API permits them.
- The enrolled channel capture_id equals the supplemental plan capture_id. Boot,
  scope, session, registration, UID roles, trust and Source/witness keys must match
  exactly. Main channel source_actor_uid is the original Source producer UID.

The other families have capture/case/boot and actor or request identities, but
lack this complete Source scope/session/registration bridge. Their current fields
therefore do not authorize a common-event binding in version 1.

## Pure interface and bounded enrollment

New API:

`evaluate_common_event_binding(contract_raw, observations_raw, *, safety_pins,
composition_plan_raw=None, expected_composition_plan_sha256=None, supplements=None,
event_enrollment_raw=None, expected_event_enrollment_sha256=None)`.

No I/O, clocks, process calls or acquisition. Reuse unchanged original APIs and
bounds through evaluate_safety_evidence_composition. Return its exact result under
composition_evaluation and a separate binding annex. Do not accept precomputed
caller evaluations as replacements for original replay.

Enrollment is canonical JSON plus LF, at most 128KiB, externally SHA256-pinned.
Exact fields: schema_version=`edge-common-event-enrollment/v1`, capture_group_id,
main_contract_sha256, entries. Group/id fields use the existing bounded identifier
grammar. entries is a list of 0..64 exact objects:

`id, kind, category, channel_id, capture_id, opportunity_id, fact_seq, required_layers`.

id identifies one existing composition supplement. Duplicate IDs, duplicated
channel/opportunity/fact selectors, unknown kinds/categories/layers, extra fields,
non-integral/bool fact_seq, duplicate JSON keys or malformed hashes refuse the new
enrollment. All original main/supplement results remain available. fact_seq is an
explicit positive integer selector, not an inferred nearest event. For the v1
adapter category is forged_evidence_accepted and kind is forged_refusal_v2.
For that adapter required_layers must equal all eight frozen layers in protocol
order; an empty/subset/reordered list cannot weaken the declared checks. A known
unsupported family remains unknown even if its requested list is empty; it never
receives a vacuous complete-coverage result.

The enrollment and main contract are retained before the challenge worker starts;
all required layers and identities are fixed prospectively. They can name already
created baseline/invalid-input/reference bytes. The supplemental plan and signed
main fact are published after the actual worker and original sampling finish,
with their actual hashes. The fresh Root capture receipt retains the enrollment
pin before launch. This is an explicit Root chronology/custody premise, not a
claim that a JSON timestamp or current Root0444 metadata proves prior enrollment.

## Binding and finite artifact consistency

Require a fully authenticated original main signed channel and the exact enrolled
fact/opportunity selector. Check all identities and original-byte relations above.
Main begin/fact/end ordering and channel coverage remain governed by the unchanged
main evaluator. Any supplemental missing/invalid global enrollment is isolated;
no entries, format conversions or associations are guessed. Zero enrolled entries
produce not_exercised/unknown, never a vacuous fully-bound or coverage-complete
result. Individually valid original positives survive an incomplete main channel
even when this new binding leg requires complete authentication and stays unknown.

The annex reports each item separately:

- identity_binding: matched, conflict or unknown;
- main_assertion_consistency: consistent, conflict or unknown;
- finite_layer_coverage for the required fixed layers, with original diagnostic
  values/reasons and verified=true/false/null (verified, contradicted, unavailable);
- original raw hashes/pins and explicit binding/coverage blockers.

Required layer vocabulary: input_bytes, reference_authentication, baseline_witness,
journal_cursor_structure, worker_refusal, sampled_source, sampled_journal,
sampled_anchors. These labels mean only finite artifact consistency:

- input_bytes/reference/baseline/cursor qualification uses the original v2
  challenge_verified/reference_frame_authenticated/baseline_witness_verified/
  journal_cursor_structurally_verified results and exact original artifact pins;
- sampled_* means an independently validated original before/after comparison
  exists. A known changed=true remains a measured change, never a coverage zero;
- worker_refusal is established only when the unchanged original v2 result reports
  recorded_refusal_consistent. An unknown original result remains unknown; absence
  of an error string or a process return code alone does not establish refusal.

Check main fact disposition against known original refusal consistency. Its cursor
and artifact hashes must match the original structurally verified baseline and
sampled originals. A main positive contradicting an original refusal is retained
unchanged and flagged as a conflict. Unknown supplemental facts do not manufacture
a main zero or a refusal. Missing reference/worker/sibling artifacts must preserve
any independently known original state change and other valid binding items.

## Timing window meaning

Enroll a finite opportunity window before capture. Its start/end must lie inside
the main scope interval. Validate that the actual Root before-sample read brackets,
the original worker started_ns/exited_ns lifecycle brackets and the actual Root
after-sample read brackets all lie inside that opportunity. Preserve each original
sample's before/after relation to the worker, as verified by the original API.
The selected main fact timestamp must be an actual retained Root observation at
or after the latest submitted after-sample read_finished_ns and inside the same
opportunity. Main challenge begin/end rows retain the unchanged main evaluator's
rules for enclosing the enrolled opportunity. Missing sample/timing bounds yield
unknown finite consistency; they are never repaired from neighboring artifacts.

These are Root controller/process-call and read brackets on the declared common
boot/clock, not kernel proof of worker execution instants, signal delivery,
scheduling latency or observation of every intervening moment. Do not fit, shift,
interpolate or match events using timestamps. Gaps, delayed observations and
unobserved intervals remain gaps/unknown; no scheduling or missing-data zero can
be derived. This does not replace any existing 5ms, 98% or 1.2x condition.

No required-layer list or complete finite artifact set establishes whole-window
coverage, continuous absence of mutations, full journal semantics, internal branch,
application consumption, independent production custody or physical safety. The
old global comparison blockers remain unchanged inside the original result.

## Fresh matched control and capture handoff

The first actual capture uses the existing forged-v2 wrong_key recipe and its
genuine valid counterpart. Use fresh DISTINCT Source/control scopes under one
enrollment group, matching the recipe/profile. Their scope/session/capture IDs
remain distinct. They are not the same event and are never joined as one Source.
Do not reset, replace or repair a used/poisoned Source to manufacture a valid
counterpart. The valid counterpart is control-only evidence, not an invalid-input
opportunity or a forged-evidence-accepted violation.

Root owns actual Linux capture, readonly enrollment/intake and publication. Reuse
the existing original forged-v2 verifier and Root0444/separate-reader collector;
no new actor privileges, probes or duplicated kernel trials. Retain all originals
and separate failed attempts. Additional challenge kinds may use their existing
original recipes only after the same pre-enrollment requirements are satisfied.
Other families remain explicitly unsupported until actual missing bridge IDs are
available and a separately frozen adapter defines their meaning.

## Fixed checks and acceptance

Synthetic data is labeled synthetic and uses real original test signatures where
needed. Controls include exact prospective IDs/raw hashes and original replay;
wrong capture/scope/session/boot/UID/key/trust/baseline/input/reference/plan/fact/
opportunity; duplicate selectors; malformed/missing enrollment; unsupported family;
missing required reference/worker/samples with independent state changes retained;
main positive preservation and contradiction; old main rejection and seven-API
parity. A matched historical archive or timestamp overlap cannot substitute for a
fresh enrolled capture receipt.

Freeze before implementation. Then focused tests, independent code review, one
bounded fresh offline original-path capture after approval, readonly artifact
replay, full final-head CI and exact base/head/tree checks precede merge. No new
issue, favorable retry substitution, deployment or whole-system acceptance.

## Reviewed pre-collection close-boundary feasibility addendum

Original finite safety v1 requires the signed CLOSE row's monotonic_ns to equal
the prospectively frozen scope end EXACTLY. A genuine Root clock read after a
fixed deadline cannot guarantee that nanosecond. Do not backdate, substitute the
deadline, busy-wait/retry for a lucky equality, or reinterpret this v1 timestamp
as a different declared-boundary field. Keep the old parser and all gates.

The first actual wrong-key/control capture therefore has an expected partial/
UNKNOWN main channel and binding. Freeze a10-second opportunity at the actual
Root clock sampled after producer return and BEFORE original before-snapshots.
Retain the enrollment/contract pins before returning to the original worker
harness. Fact time and CLOSE time are genuine later Root reads. Wait until the
frozen end if necessary, then sample actual CLOSE; do not alter it to fit.
Preserve actual out-of-scope/late-close reasons, original v2 refusal and known
sampled state facts. Existing exact-matched positives remain SYNTHETIC only.
The distinct genuine valid control is control-only evidence, not a joined event.

This is a software evidence-path trial with an explicit boundary incompatibility,
not successful complete-event qualification. A future boundary-versus-recording-
time protocol needs a separately frozen version; it is outside this slice.
Original forged v2 also checks its declared source boot_ref==kernel UUID hex;
that inherited syntactic relation is not independent physical boot attestation.

## First actual offline path trial (2026-11-16 JST)

Committed source `dc0645e8b1826caa9edfb08d981a7dd0f47c098a` executed the two
existing distinct-scope valid-control/wrong-key paths: **2 passed, no skips,
12.65s**, in the existing network-disabled Root Linux container with no added
capabilities and a read-only checkout. Lifecycle payloads and observer keys are
explicit test premises, not real native defense execution or independent custody.

The genuine wrong-key verifier refused and all eight original finite artifact
checks were retained; before/after Source, journal and anchors were unchanged.
The separately scoped genuine valid-input control consumed its input through
the original recovery path and is control-only, never a forged-input opportunity.
The new main is partial_signed_rows/incomplete and its binding remains UNKNOWN.
All four main category counts are null. No main count or eligibility was changed.

Actual Root CLOSE was `40151762784908` against frozen end `40151759828517`.
The actual clock value was preserved; the deadline was not substituted. The
2,956,391ns difference is a boundary incompatibility observation, not a 5ms
clock/performance qualification. Main timing/coverage errors remain original.
The exported binding-evaluation SHA256 is
`63c72260f60d38c7b193bd0e265dbbb3a9e827d0a2987a07c4db4c386c18f5de`.
52 public allowlisted files retain both scopes, prelaunch registration, actual
process/read brackets, original strict evaluations and signed partial main data.
Independent replay and final-head complete CI are separate merge gates.
