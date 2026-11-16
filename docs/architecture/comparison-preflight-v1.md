# Frozen comparison preflight and mechanical regression — #400/#393

Base190750e3. Commit this contract and protocol before implementation or collection.
The 24h task completes software, not independent efficacy/safety acceptance.

## Authority and compatibility

Add a pure bounded offline preflight in `azazel_edge.benchmark.comparison_preflight`.
It never launches a workload, provider, sensor, model, service or executor. Keep
all existing benefit/measurement APIs, original pilot_v2 bytes and old outputs
unchanged. No new permissions, keys, roles, network or installer/security/systemd
changes. No qualified safety, comparison, completion, admission or resume flag.

API: evaluate_comparison_preflight(plan_raw, manifest_raw, inputs_raw, *,
expected_plan_sha256, expected_manifest_sha256, reference_artifacts=None,
expected_reference_sha256=None). All raw objects are canonical JSON+LF, strict
UTF8/duplicate/type/finite/bounds checking before reuse. Contract <=128KiB,
manifest/inputs <=8MiB each; <=128 assignments; nesting<=16. Optional references
are exactly event_binding/window_cost, each <=64MiB and externally pinned or
explicitly absent. They are retained diagnostic REFERENCES, never imported proof
of qualification or permission. Do not accept caller eligibility/approved flags.

The plan exact fields are schema_version=edge-comparison-preflight-plan/v1,
manifest_sha256, data_kind=FROZEN_SOFTWARE_PROTOCOL_NOT_MEASUREMENT,
hypothesis, fixed_gates, allocation_seed, arm_descriptions, exclusions,
required_prerequisites, historical_pilot.
Fixed gates exactly load_factor1.2/examined_floor0.98/clock_budget_ns5000000.
Required prerequisites fixed event_binding,finite_coverage,clock,assignments,
independent_safety,service_cost,execution_mechanism_release,independent_review.
No array/boolean of supplied qualifications can satisfy these prerequisites.

File pins use SHA256 of canonical JSON including the final LF. The inner
inputs.manifest_sha256 uses unchanged benefit.manifest_digest (without LF);
never substitute one for the other.

Manifest reuses benefit.validate_manifest and existing schema. Freeze ALL36
assignments (9 declared authored scenarios,2pairs,2arms), horizon60s, analysis
seed17/bootstrap500/minimum_pairs2 and old SOFTWARE thresholds5s/2ms/0.01.
Allocation has a distinct seed20261116 and explicit full assignment/order table.
Source config hashes equal benefit.manifest_digest of the exact frozen
arm_descriptions; allocation_seed is fixed separately from analysis_seed.
Source config hashes pin non-executable prospective arm descriptions; they are
NOT registered effective live profiles. This is an authored pilot protocol,
not an independently preregistered confirmatory/held-out experiment or permission.
Future effective arm enrollment and independent service/safety proof remain absent.

Inputs exact schema_version=edge-comparison-preflight-input/v1,
manifest_sha256, records. Records retain the original measurement record shape.
Unknown safety values may be null in this NEW boundary but NEVER converted to0
or sent to the old engine as qualified data. Per-assignment diagnostics enumerate
missing/duplicate/unknown assignments, known reported positive safety counts,
null categories, missing/malformed capture/recording/linkage, and original
execution/mechanism/release/clock/coverage reasons when strict replay is possible.
Do not choose a latest/favorable attempt. Preserve rejected attempts' known
positive facts as unqualified reported lower bounds, not deduplicated real safety
counts. Global plan/manifest/input-envelope unknown fields/schema/hash/budget reject;
per-record errors do not erase valid siblings. Malformed optional slots
and bad individual attempts preserve known siblings and original material.

For evidence_kind=synthetic ONLY, reuse measure_experiment on original correctly
typed receipts (after strict validation) as mechanical_evaluation. Include
all supplied attempts and gap/restart/harm cases, not only successful/full-horizon
records; original engine invalid-input refusal remains explicit. Its
original result is preserved verbatim and NEVER becomes actual comparison. For
container/recorded_lab/hardware input, comparison_result is null and reasons
remain explicit. Report status=preflight_complete_measurement_withheld,
actual_comparison_started=false, comparison_qualified=false,
qualified_safety_count=null, whole_measurement_qualified=false, all authority
flagsfalse. Current software has NO real-comparison admission path. A fresh later
qualification contract is required to remove independent prerequisites; simply
matching references or passing the original sampled clock cannot do this.

## Regression and Linux acceptance

Reuse tests/run_measurement_pilot.run unchanged for all9/36 historical synthetic
regressions in a separate report group. Original protocol/cases digests and
expected gain/neutral/service_harm/protection_harm/actor_pause/shared_source/
clock_uncertain/capture_gap/restart_lost gates MUST match. Report mechanical_only.
The new container manifest with no measured receipts must enumerate ALL36 missing
assignments, preserve unknowns, return no actual benefit score, and start nothing.

New tests: canonical/pin/type/bool/NaN/unknown/bounds; modified thresholds/order;
missing/duplicate/wrong assignment/source/config/seed/manifest; explicit null
safety and mixed knownpositive+unknown; poisoned optional references; historical
synthetic gate preservation; no action/causal/eligibility upgrades; determinism and
input bytes unchanged. Administrative goal censoring requires the original full
common horizon; gaps/restart/actor pause remain missing/inconclusive.

Run dedicated Linux offline process tests without Root privilege additions or
network; require positive pytest execution, not skip-as-pass, and export NEW
report/original-input groups exclusively. No real provider/network comparison
is run. Source-level/observed process no-launch controls and unchanged old replay
verify the pure path. Preserve every actual failure; no favorable data retry.
Root verifies final code, independent raw replay, complete final-head CI and
exact base/head/test-merge/tree before merge; update #400/#393, keepOPEN.
