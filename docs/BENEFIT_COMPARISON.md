# Offline comparative benefit analysis

Tracking: Edge #393, Azazel#67. Status: software-only mechanics; no field,
hardware, human-factor or external-reference superiority result.

`azazel_edge.benchmark.benefit` validates a frozen experiment manifest and
analyzes bounded recorded receipts. `benefit_receipt.build_receipt` normalizes
independent isolated-scenario milestones and legitimate-service transactions.
Neither imports an executor, contacts a model, generates traffic, changes an
Outcome record or grants causal/defense authority.

## Reproduce the mechanical fixture

From the checkout, with Python 3.11+ and the repository's test dependencies:

```sh
PYTHONPATH=.:py python -m azazel_edge.benchmark.benefit \
  tests/fixtures/benefit/synthetic_manifest.json \
  tests/fixtures/benefit/synthetic_observations.json
PYTHONPATH=.:py python -m pytest -q tests/test_benefit_comparison.py
```

The expected report is `tests/fixtures/benefit/synthetic_expected.json`.
The two-pair fixture deliberately encodes a time difference. It checks arithmetic,
not defensive efficacy. Its `claim_status` stays `mechanical_only` even when
recorded thresholds are met. A script failure exits nonzero; CLI success means
analysis completed, not that the candidate passed an experiment.

## Manifest and receipt contract

Schema `azazel-benefit-experiment/v1` binds a named experiment, phase, evidence
class, common horizon, source commit/configuration/policy/corpus hashes, arm
identities/environment, assignments and analysis plan. Each assignment has one
ID, pair ID, arm, scenario, seed and declared order. Within a pair scenario/seed
must agree, and arm/order must not repeat. Arm definitions and a hash alone do
not establish fair configuration, randomization or preregistration; the reviewer
must verify those against the frozen registration and run evidence.

The observation file contains `manifest_sha256` and one receipt per actual run.
Do not fill in missing runs: they remain in assigned denominators and make the
comparison inconclusive. Failed or incompletely observed pairs are reported and
not scored as successful defense. Duplicate IDs, mismatched manifests, nonfinite
numbers, invalid transaction denominators and absent safety measurements fail
validation. The report names both comparator arms and all scenario strata.

Independent milestone capture has one declared boot and monotonic elapsed-time
clock, unique bounded event IDs, a start at zero and an end at the common horizon.
Allowed milestones include discovery, protected reach, authentication attempt,
protected objective completion and verified containment. IDS alert counts cannot
stand in for protected-objective completion. A sensor gap invalidates horizon
coverage. The controller tag/digest does not authenticate its producer: retain
and independently verify source captures.

Each legitimate transaction records elapsed completion time, duration (including
timeouts) and error status. The capture adapter computes nearest-rank p95 and an
explicit error/transaction denominator. External adapters must use these same
units and scopes rather than treating a requested action as an executed one.

## Metric and gate semantics

For fully observed common horizon H, the run's restricted progression time is
`min(T, H)`; no objective by H is administrative censoring at H. Earlier capture
loss is missing evidence, not censoring at H. The primary paired estimate is
candidate minus comparator restricted time. This estimates a restricted mean
through H only for complete common-horizon observations; it does not impute an
unobserved counterfactual attacker response. Interactive lab trials are necessary
for adaptation claims; replay proves mechanics only.

The report computes paired mean deltas and deterministic percentile-bootstrap
95% intervals using the frozen seed/repeat count. A complete pair contributes
together in each resample. These intervals are descriptive for a small pilot;
independent sample-size/power, sampling unit, scenario weighting, multiple-testing
and stopping-rule review is mandatory before a confirmatory conclusion. A
constant two-pair interval is not a statement of real-world certainty.

Gates, in order: any unauthorized action/protected escape/accepted forged
evidence/advisory-authority conversion fails safety; missing or insufficient
pairs are inconclusive; excessive legitimate p95/error-rate increases fail
service non-inferiority; more completed protected goals fails protection; time
gain must exceed the declared practical threshold at the lower interval bound.
No dwell-time benefit compensates for harm. The output never declares universal
superiority or writes a supported causal/tactical effect. An external tool
comparison requires that tool's actual independently pinned and reviewed arm.

## Bounds and remaining work

Inputs are at most 8 MiB each; at most 10,000 assigned runs, 16 arms, 10,000
milestones/transactions per capture, and two million pair-resamples. Invalid
state fails visibly. Analysis performs no network/process calls. Corpus creation,
independent capture, commissioning, real lab traffic and admission are separate
owner tasks; no baseline is silently activated by running the analyzer.

The software slice still needs independent preregistration/rerun and actual
C0–C6 captures, practical threshold selection, model/Knowledge/canary ablations,
resource/fault/hardware measurements and controlled operator studies. No absent
provider or unexecuted comparator is scored as a real run. Keep #400/G6 and the
existing activation/isolation/admission gates open.

## Joined recorded path

[Recorded measurement path](MEASUREMENT_PATH.md) connects the existing G5
readback/release/telemetry path to the independent-service receipt calculator.
It includes a fixed software-only nine-scenario pilot, coverage/identity/clock
refusal and a minimized reproduction set. It introduces no live capture or
enforcement and does not complete the independent C0-C6 or G6 gates above.
