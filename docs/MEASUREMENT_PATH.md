# Recorded measurement path and frozen software pilot

Tracking: #400/#393, MIO #58, Azazel #67. Status: implemented **recorded replay
and producer API**, not live integration, independent protection benefit or G6.
No Rust, arbiter, live observer, web, installer, security or service wiring is
changed. Existing product pins and enforcement/admission defaults are unchanged.

## Frozen input and acceptance

The first dataset commit precedes the measurement adapter. Historical v1 used
underscores in generated nft ownership references; existing G1a correctly
refused those records. V1 is retained unchanged with an explicit invalid-corpus
notice. V2 changes the recording namespace grammar, not the goals, service
costs, faults or expected gates. It also correctly distinguishes MIO's manifest
hash from its case hash. No threshold was tuned from a candidate outcome.

`tests/fixtures/measurement_pilot_v2/{protocol.json,cases.json,protocol.sha256}`
freeze nine cases, 36 assignments, source commits, source timeline/policy hashes,
MIO's frozen 24-case replay references, recording recipes, exact per-assignment
capture/recording/linkage hashes, resource caps and expected gates. The scenario
controller schedules are project-authored synthetic inputs; no client, model,
service, provider or enforcement was run to create their ground truth.

The comparison pilot uses H=60 seconds, two pairs/case, fixed counterbalanced
order/seeds, lower 95% paired bootstrap time gain greater than 5 seconds,
legitimate p95 increase at most 2 ms and error-rate increase at most .01.
These are **fixed mechanical regression thresholds**, not calibrated field
budgets, sample-size adequacy, deployment defaults or independently registered
confirmatory criteria. Safety violations, mismatched accepted links, causal
promotions and expected-gate mismatches must all be zero.

| Case | Frozen disposition |
|---|---|
| Recorded gain | thresholds met, independent review still required |
| Neutral | practical gain not demonstrated |
| Legitimate service harm | service gate fails |
| Protected-goal regression | protection gate fails |
| Declared artificial actor pause | inconclusive |
| Shared source without session identity | inconclusive |
| Clock uncertainty beyond 5 ms | inconclusive |
| Controller capture gap | inconclusive |
| Restart lost window | inconclusive; no replacement Outcome |

Every pilot result remains `mechanical_only`. The separate MIO corpus retains
unknown AI/maliciousness labels, disjoint development/reserved **replay** groups,
zero-authority gates and no identification accuracy/calibration thresholds.
Knowledge #111 retains independent dataset curation and training promotion.

## Producer, join and evidence flow

```text
IndependentServiceCapture (controller-measured times / transaction results)
    -> recorded capture, boot/clock/run/assignment identity
Recorded Edge timeline -> existing G5 adapter/readback/release/G3/ledger replay
    -> exact decision/execution/mechanism/objective/Outcome/release facts
Declared session + clock mapping + pinned capture/recording digests
    -> minimized measurement bundle + complete assignment ledger
    -> existing benefit_receipt/build_receipt + benefit/analyze
```

`measurement_capture.IndependentServiceCapture` records only a closed milestone
vocabulary and bounded transaction results. Products supply actual monotonic
elapsed times and independent safety observations; the recorder calls no clock,
network, process, model or actuator. It never interprets an alert or canary touch
as a protected-goal event. Duplicate identical entries are counted/suppressed;
conflicts, malformed observations, backwards clocks, boot/clock changes or
capacity loss taint coverage. Finish records the supplied actual end time;
early stop cannot synthesize a full horizon. At most 10,000 milestones and
10,000 transactions are kept. A lost capture/export remains failed/missing.
No actual protected-service instrumentation is registered by this change.

`measurement.measure_experiment` consumes immutable recorded inputs. It reuses
G5 rather than rebuilding decision/readback/release logic. Manifest, policy,
capture and recording digests and exact boot/decision/execution/mechanism/
objective IDs must agree. A declared controlled session is mandatory; IP/port
similarity is never used to join. Cross-run reuse of an execution is refused.
An explicit `observe_only` baseline may have no Edge execution, which is shown
as not applicable rather than manufactured execution evidence.

A qualified disruptive run requires applied execution, independent mechanism
readback, the original Outcome with adequate pre/post samples/source coverage,
and reconciled verified release absence. TTL or command exit alone cannot
establish cleanup. Lost restart windows withhold the run. Clock origins and
uncertainty are declared and capped; mapping declarations and hashes are not
source authentication. Uncertain alignment never creates a supported result.
The original telemetry still exposes its timestamp/confounding limitations.

The service receipt remains intact even when the Edge join is withheld. A
separate **comparison projection** marks the run unusable; it never edits the
service capture or canonical Outcome/Effect. Output contains safe correlation
IDs, statuses, coverage, boot/clock provenance and source digests, without raw
owner tokens, addresses, command plans, payloads or logs. Keep the full original
inputs privately with that minimized bundle for reproduction and review.

The existing calculator supplies restricted time through H, protected-goal
completion, p95/error denominators and paired uncertainty. The join also reports
nearest-rank p50, transaction completion rate and, only when separately recorded,
`actionable_detection` to goal/H margin. Negative margins are retained; a
censored margin uses H and says so. Missing detection yields null, never an
alert timestamp or lease TTL. Observation counts are not evidence-gain scores.
Resource overhead and discriminating-evidence rubrics remain unmeasured.

Input caps: 8 MiB/file/batch, 128 assignments, 8 recorded boots, 1,024 steps and
64 disruptive decisions/run. Missing assignments retain denominators. Invalid
known-assignment captures/joins produce rejected ledger rows and failed or
missing receipts; unknown safety never becomes zero. A recorded safety failure
still overrides benefit even when its linkage is invalid. No fail-open recovery
or automatic re-run/repair is performed.

## Reproduce and inspect

```sh
# Frozen regression pilot; exits nonzero on mismatched expected result.
PYTHONPATH=.:py python tests/run_measurement_pilot.py
# Optional new directory only; never overwrites an earlier evidence set.
PYTHONPATH=.:py python tests/run_measurement_pilot.py --export work/pilot-v2-run
# Replay the exported experiment from pinned input JSON.
PYTHONPATH=.:py python -m azazel_edge.benchmark.measurement \
  work/pilot-v2-run/gain-manifest.json work/pilot-v2-run/gain-inputs.json
PYTHONPATH=.:py python -m pytest -q tests/test_measurement_path.py
```

The exported set contains manifest, inputs and minimized bundle per scenario,
then a final pilot report. A failed write exits nonzero and leaves an incomplete
set; report existence alone is not acceptance. Validate complete JSON and all
digests. Source pins in the experiment identify the recorded system/template;
retain the evaluator's exact checkout/PR head and environment alongside an
actual run. These are software evidence, not a durable journal/fsync guarantee.

## Still open

- Independent real service/controller captures, reviewed ground truth, lawful
  isolated lab topology, sample-size/power and efficacy budgets before tuning.
- Live before-window crash journal, authenticated producer/clock/session mapping,
  capture adapters and bounded asynchronous integration; unchanged Rust receipt
  parity before any opt-in enablement. Live G3 still starts at EOF.
- Actual C0-C6 trials, model/Knowledge/canary ablations, observer off/on overhead,
  verified reset/isolation, full-disk/restart/wear tests on the G6 target.
- Independent rerun and claim review. A recorded gain cannot upgrade runtime
  causal support or establish human usefulness/external-tool superiority.
