# Explicit paired safety and UDP queue contracts — #400 / #393

## Frozen scope

Base main806c0676 (#592). Freeze this document/cases before implementation.
Existing queue contracts intentionally allow one protected opportunity and zero
other-category opportunities. Keep that parser/API restriction. A full four-category
main contract is evaluated separately, then explicitly paired with queue evidence
using its OWN original queue contract. Do not convert queue admission to delivery,
protected_escape, qualified safety, coverage completion or runtime authority.
No privilege, acquisition hook, service, key, deployment or missing-data fill.

## Pure API and additive result

evaluate_paired_safety_queue(main_contract_raw, main_observations_raw, *,
main_arguments, pair_plan_raw=None, expected_pair_plan_sha256=None,
queue_contract_raw=None, queue_plan_raw=None, queue_report_raw=None).
main_arguments are exactly the existing evaluate_safety_observations keyword pins
and external stream heads; evaluate main FIRST with unchanged behavior. Invalid
main retains its original exception; bad/missing optional pair is unknown and
preserves the complete byte-equivalent valid main result/known positives.
Return new edge-paired-safety-queue-evaluation/v1 containing main_evaluation and
queue_pairing separately; qualified_safety_count null and all authority flagsfalse.

Pair plan canonical JSON+LF32KiB, edge-safety-queue-pair-plan/v1, exact fields:
schema_version, main_contract_sha256, queue_contract_sha256, queue_plan_sha256,
queue_report_sha256, main_opportunity_id, queue_opportunity_id. All hashes include
original LF and are independently retained enrollment pins, not derived approving
hashes from submitted artifacts. Public refs use existing journal._ref grammar.
This is a post-capture artifact pairing checkpoint, not a preregistered experiment
result or a freshness/restart/admission proof. Original capture contract/conditions
remain frozen before traffic; report/pairing hashes are retained after publication.

Validate exact main hash against main_arguments AND pair plan. Validate separate
queue contract/plan/report byte hashes. Call existing evaluate_udp_queue against
queue_contract_raw only, retaining its old canonical wire/domain/signature/target/
reference/layer/time rules. Require canonical typed equality of COMPLETE scopes
and all three keypins across contracts (never Python equality with bool/int alias).
Select exactly the named protected opportunities, never search by tuple/fallback.
The queue opportunity remains its sole protected one; compare both selected
predicates/full protected tuples/start/end/challenge hashes exactly. Active queue
protected channel_id and capture_id must differ from EVERY main channel/capture.
No re-signing, ID repair, time extension or cross-scope/session/key/boot pairing.

Different reference_sha256 values are permitted deliberately. Main reference is
an EXTERNALLY FROZEN OPAQUE premise; the main parser checks its format, not meaning
or Source-prefix authenticity. Queue parser recomputes its layer/tuple/socket-target
reference. Pairing never assumes reference equivalence or observation-layer
identity. Matching scope/signatures is context binding, not sensor truth or actual
independence. Public test keys prove no production custody.

On valid pair queue_pairing status=context_bound_pair, retain the old queue
result as queue_evaluation and separately named queue_admission_observed_count
(1 OR null only). application_delivery_count and qualified_safety_count stay null.
Invalid/missing pair status=unknown, queue count null with reasons; NEVER zero.
Main result and every existing count/coverage/authority field stay unchanged.
Historical matching reports remain historical; no fresh measurement, durable
one-use or auto-resume assertion. No optional recovery join in this slice.

## Root-sealed intake

collect_paired_safety_queue(main_enrollment_path, pairing_enrollment_path, *,
expected_main_enrollment_sha256, expected_main_checkpoint_sha256,
expected_pairing_enrollment_sha256). Reuse existing collect_registered_safety and
held-FD Root0444/single-link/physical protected-ancestor fences. Reader is the
registered nonroot main observer, with initial/final UID/boot and main provenance
matches; re-hold all main artifacts and every pair artifact through final checks.
All paths distinct, independent close failures block a new composite result.
Original published main artifacts are never altered even on failed intake.

Pairing enrollment canonical32KiB edge-paired-safety-queue-enrollment/v1 exactkeys:
schema_version,main_enrollment_sha256,main_checkpoint_sha256,paths,sha256.
Last maps exact pair_plan/queue_contract/queue_plan/queue_report. Matched None pairs
represent deliberate missing optional evidence; unsafe declared/missing/changed
files refuse intake without repair. Valid optional bytes failing evaluation produce
unknown pairing while preserving main. Caps32KiB pair plan/queue plan/enrollment,
128KiB queue contract,64KiB queue report; original main caps unchanged.

## Acceptance/stages

1. Freeze data and source/observation boundaries, implement additive pure adapter,
   reuse existing evaluators, no old parser relaxation or generic execution engine.
2. SYNTHETIC real-signature cases cover full four-channel main + strict queue-only
   contract, retained positives through every optional failure, exact scopes/keys/
   tuple/predicate/window/challenge/selected IDs, channel/capture collisions,
   signatures/domains/reference errors, missing/empty/deep/noncanonical/typed data.
3. REAL Linux tests reuse existing BPF capture/profile + disposable sender/target,
   no added sensor/harness privileges beyond existing authorized tests. Pair actual
   queue evidence with explicitly SYNTHETIC main-channel facts; test normal queue
   and socket-filter-negative controls. A negative/no-event queue stays null.
   Main facts/keys do NOT become actual safety/independence/custody evidence.
4. Root-sealed real-UID intake, immutable artifacts, wrong reader/unsafe metadata
   refusal; existing required Linux CI includes cases and cannot pass by skipping.
5. Independent review, appropriate regression and final-head complete CI, exact
   base/head/tree before conditional merge; update existing400/393. Physical,
   production, application receipt and safety/efficacy gates remain open.
