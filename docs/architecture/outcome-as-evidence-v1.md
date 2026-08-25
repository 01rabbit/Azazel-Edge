# Outcome-as-Evidence v1

Status: implementation baseline
Tracking: #400

## Objective

Outcome-as-Evidence extends the current defensive pipeline without replacing its live authority:

```text
Evidence
  -> Reasoning
  -> Decision
  -> Execution
  -> Observation
  -> Outcome
  -> Tactical Effect Assessment
  -> Re-evaluation / Replay / Knowledge
```

The central rule is that **intent, execution, mechanism, outcome, and tactical effect are different facts**.

## Locked invariants

- `Action != AppliedMechanism != Outcome != TacticalEffect`.
- requested command plan != provider-applied fact.
- `throttle` is not evidence that `DELAY` occurred.
- `redirect` is not evidence that diversion succeeded.
- post-action improvement is not causal proof.
- provider command exit status is not proof of the resulting host/network postcondition.
- a tactical-effect join with mismatched decision/objective/mechanism IDs is rejected, never guessed.
- policy guardrails must be explicitly sourced and evaluable; missing guardrail evidence is inconclusive, never pass.
- uncalibrated tactical confidence is represented as `null`; v1 must not invent numeric precision.
- `inconclusive` is a valid and expected result.
- observer/assessment failure cannot alter the existing deterministic defense path.
- AI cannot authorize actions, create canonical provider execution facts, or mark tactical success.
- replay cannot call a live executor.
- Knowledge remains advisory.
- Outcome-as-Evidence introduces no new enforcement mode.

## Current runtime grounding

The current Rust event engine in `rust/azazel-edge-core/src/main.rs` contains the executable path used by this v1 adapter:

```text
NormalizedEvent
  -> decide_defense()
  -> maybe_enforce()
  -> EnforcementOutcome
```

`EnforcementOutcome` already records `trace_id`, selected action, target, policy reason, command and rollback plans, executed/failed counts, errors, result, and metadata. v1 treats that structure as provider evidence and normalizes it; it does not replace it.

`py/azazel_edge/arbiter/action.py::ActionArbiter` remains an important deterministic decision implementation, but the repository also contains the independent Rust decision/enforcement path. Until the wiring is unified and proven, documentation must not call the Python ActionArbiter the sole live execution truth.

### Current mechanism scope

| Action | Current Rust implementation | v1 mechanism | Scope truth |
|---|---|---|---|
| `observe` | no disruptive command | `OBSERVATION_ONLY` | logical action |
| `notify` | no external delivery receipt in Rust core | `NOTIFICATION` | unverified delivery |
| `throttle` | `tc qdisc replace dev <iface> root tbf ...` | `TRAFFIC_SHAPING` | interface root qdisc |
| `redirect` | nft prerouting source-IP + destination-port redirect | `REDIRECTION` | source IP + destination port |
| `isolate` | nft input source-IP drop | `ISOLATION` | source IP |

The current throttle command is interface-level. The decision subject IP must not be used to relabel the actual qdisc scope as attacker-scoped.

A successful Rust command exit proves that the provider command completed successfully. It does **not** independently prove that the resulting qdisc/nft postcondition exists on the host. Therefore disruptive `AppliedMechanism.status` remains `unverified` until a postcondition observer supplies evidence. Partial application is `disputed`; rejected/failed application is `not_observed`.

### Release limitation

The Rust outcome contains rollback instructions and a TTL/rollback hint. v1 has not proven an automatic runtime scheduler that executes those rollback commands. Until explicit provider evidence is available, `released`/`expired` must not be inferred.

## Canonical contracts

### ActionExecutionReceipt

Execution-provider fact only. Status:

```text
unverified | applied | partial | rejected | failed | expired | released
```

The receipt separates requested parameters from applied facts. The complete command and rollback plans remain in `requested_parameters`. Current Rust `EnforcementOutcome` reports only aggregate executed/failed counts rather than a per-command receipt, so `applied_parameters` contains only those provider-reported aggregate facts and explicitly records `individual_command_mapping_verified=false`. In particular, a partial execution must never copy the entire requested plan into the applied side.

`applied` means the execution provider reports successful command completion; it is deliberately distinct from an independently verified `AppliedMechanism` postcondition.

### AppliedMechanism

Initial mechanism vocabulary:

```text
TRAFFIC_SHAPING
ROUTE_CHANGE
REDIRECTION
ISOLATION
NOTIFICATION
OBSERVATION_ONLY
UNKNOWN
```

`DELAY` is intentionally not a mechanism. Tactical assessment requires the concrete `AppliedMechanism` record, not just a caller-supplied mechanism kind. A disruptive mechanism must have `status=observed` before it can support a tactical effect.

### EffectObjective

Policy-owned observation/success criteria:

- metric;
- direction;
- target/range;
- observation window;
- guardrails;
- policy version.

v1 guardrails are deliberately narrow and numeric. Every guardrail must identify an explicit source so the assessor never guesses where a value came from:

```json
{"source":"noc_impact","metric":"impact_score","max":20}
```

Allowed sources are `post_metrics`, `noc_impact`, `resource_impact`, and `asset_impact`. Exactly one of `min` or `max` is required. Missing, malformed, ambiguous, or non-numeric guardrail evidence makes tactical assessment `inconclusive`; an observed violation makes the policy objective `unsupported`.

### OutcomeRecord

Bounded post-action observation includes:

- baseline/post metrics;
- adversary response;
- asset/NOC/resource impact;
- operator override and termination reason;
- telemetry coverage;
- explicit confounders;
- evidence references;
- `causal_support` = `supported|unsupported|inconclusive`;
- assessment = `effective|partially_effective|ineffective|harmful|inconclusive`.

An OutcomeRecord is evidence-backed assessment data. A changed metric and an `effective` label are not enough to establish a tactical effect; causal support is separate and defaults to `inconclusive`.

### TacticalEffectAssessment

```text
supported | unsupported | inconclusive
```

v1 implements a conservative `DELAY` rule only when all of the following are explicit:

1. the correlated `AppliedMechanism` has `status=observed`;
2. mechanism is `TRAFFIC_SHAPING`;
3. decision/mechanism/objective correlation IDs match exactly;
4. EffectObjective is a time metric with `direction=increase`;
5. baseline/post evidence is present;
6. OutcomeRecord is effective or partially effective;
7. `causal_support=SUPPORTED`;
8. every policy guardrail is well-formed, has evidence, and passes;
9. the policy target/range is met when one is defined.

Without a verified mechanism postcondition, explicit causal support, or evaluable guardrails, time increase remains `inconclusive`. Other tactical effects remain `inconclusive` until effect-specific deterministic evidence rules are implemented.

`TacticalEffectAssessment.confidence` is nullable. v1 emits `null` because no calibration corpus exists; deterministic rule execution must not be confused with probabilistic confidence in the real-world claim.

## Correlation

Do not collapse all state into an incident ID. Preserve distinct identifiers:

```text
incident_id
decision_id
action_id
execution_id
mechanism_id
objective_id
outcome_id
effect_assessment_id
reasoning_trace_id
```

The Rust adapter derives stable shadow IDs from the existing trace/event context. Because authoritative cross-event incident/session identity is not yet grounded, v1 uses a per-decision synthetic incident ID instead of guessing that separate events belong to the same actor/session. These IDs provide replay/idempotency support; they are not a replacement for a future authoritative actor/session identity service.

Tactical-effect assessment rejects mismatched `decision_id`, `objective_id`, or `mechanism_id` rather than correlating heuristically.

## Shadow modes

```text
OFF
SHADOW_RECORD
SHADOW_ASSESS
```

`SHADOW_RECORD` normalizes execution/mechanism evidence only.

`SHADOW_ASSESS` does not by itself create a tactical claim. An EffectObjective, verified mechanism postcondition, bounded observation window, explicit causal support, and policy guardrail evidence are still required.

## Failure semantics

| Condition | Result |
|---|---|
| dry-run | execution `unverified` |
| policy gate prevents action | execution `rejected`; mechanism `not_observed` |
| all planned commands succeed | execution `applied`; disruptive mechanism remains `unverified` until postcondition evidence |
| some commands succeed and some fail | execution `partial`; mechanism `disputed`; exact applied-command identity remains unknown |
| all attempted commands fail | execution `failed`; mechanism `not_observed` |
| external notification delivery not proven | execution `unverified` |
| missing baseline/post evidence | outcome/effect `inconclusive` |
| mechanism postcondition unverified | tactical effect `inconclusive` |
| metric changed but causal support missing | tactical effect `inconclusive` |
| guardrail evidence missing/malformed | tactical effect `inconclusive` |
| guardrail violated | tactical effect objective `unsupported` |
| correlation mismatch | assessment join rejected |
| observer unavailable or output write fails | live control unchanged |
| Knowledge/Fabric/AI unavailable | live control unchanged |
| replay attempts execution | fail closed |

## Replay boundary

`ReplayExecutionProvider` is read-only. Its `execute()` method raises `ReplayExecutionForbidden` by design. Live execution remains outside the v1 package.

## Implemented modules

```text
py/azazel_edge/outcome/
  __init__.py
  contracts.py
  adapter.py
  assessment.py
  replay.py
  observer.py

tests/test_outcome_as_evidence_v1.py
tests/test_outcome_guardrails_v1.py
tests/test_outcome_adapter_truthfulness_v1.py
```

The focused test suite contains 24 semantic/authority/retention/guardrail/truthfulness cases covering execution-state normalization, requested-vs-applied separation, effect-proof prerequisites, correlation rejection, replay authority, bounded shadow output, guardrail failure, and uncalibrated-confidence behavior.

The passive observer can normalize the existing Rust JSONL output:

```bash
PYTHONPATH=py python3 -m azazel_edge.outcome.observer \
  --input /var/log/azazel-edge/normalized-events.jsonl \
  --output /var/log/azazel-edge/outcome-shadow.jsonl
```

For live-follow experiments use `--follow`. By default, follow mode seeks to the current end of the input so a restart does not replay the full historical log. Use `--from-start` only when deliberate historical processing is desired.

Shadow output is bounded by default to 50 MiB and rotates the previous file to `.1`; configure with `--max-output-bytes` or `AZAZEL_OUTCOME_MAX_BYTES`. A record larger than the configured bound, or a record that cannot be written without preserving the bound, is dropped. Evidence loss is preferable to turning the shadow observer into a disk-pressure/control-path risk.

Do not install the observer as a default daemon until the Pi/HIL gate is passed.

## Gates

### G1 — runtime grounding

Partial. Current execution/command/error/scope data is grounded. Automatic rollback scheduling, independently verified mechanism postconditions, authoritative actor/session identity, external notify receipts and reboot reconciliation remain unresolved.

### G2 — shadow execution/mechanism contracts

Implemented on the feature branch. Must pass repository CI before merge.

### G3 — outcome collection

Contract implemented, including causal support, telemetry coverage and confounder fields. Automatic OutcomeRecord production waits for exact policy-owned pre/post metric sources and evidence rules.

### G4 — tactical effect

`DELAY` assessment helper is fail-closed on mechanism postcondition, correlation, evidence, causal support, policy guardrails and target/range. Numeric confidence remains unset until calibrated. No automatic runtime tactical claim is enabled.

### G5 — replay

Read-only receipt replay boundary implemented. End-to-end golden replay fixture remains required.

### G6 — Pi/HIL

Pending. Measure CPU, RSS, disk growth, observer latency, restart behavior, retention behavior, and deterministic-path regression before daemonizing or enabling by default.

## Parked until G1-G6 pass

Do not expand this slice into Presented Terrain, Belief, Counterfactual planning, MAGI Council, Co-Adaptation, automatic policy generation or broad autonomous response.
