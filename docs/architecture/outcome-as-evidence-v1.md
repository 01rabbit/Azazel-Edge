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
- `throttle` is not evidence that `DELAY` occurred.
- `redirect` is not evidence that diversion succeeded.
- post-action improvement is not causal proof.
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

### Release limitation

The Rust outcome contains rollback instructions and a TTL/rollback hint. v1 has not proven an automatic runtime scheduler that executes those rollback commands. Until explicit provider evidence is available, `released`/`expired` must not be inferred.

## Canonical contracts

### ActionExecutionReceipt

Execution-provider fact only. Status:

```text
unverified | applied | partial | rejected | failed | expired | released
```

The receipt separates requested parameters from applied parameters and carries provider evidence references.

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

`DELAY` is intentionally not a mechanism.

### EffectObjective

Policy-owned observation/success criteria:

- metric;
- direction;
- target/range;
- observation window;
- guardrails;
- policy version.

### OutcomeRecord

Bounded post-action observation with baseline/post metrics, adversary response, asset/NOC/resource impact, operator override, termination reason, evidence references and one of:

```text
effective
partially_effective
ineffective
harmful
inconclusive
```

An OutcomeRecord is evidence-backed assessment data; it is not automatically causal proof.

### TacticalEffectAssessment

```text
supported | unsupported | inconclusive
```

v1 implements a conservative `DELAY` rule only when an explicit time-based EffectObjective and evidence-backed OutcomeRecord are supplied. Other effects remain `inconclusive` until effect-specific deterministic evidence rules are implemented.

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

The Rust adapter derives stable shadow IDs from the existing trace/event context. These IDs provide replay/idempotency support; they are not a replacement for a future authoritative actor/session identity service.

## Shadow modes

```text
OFF
SHADOW_RECORD
SHADOW_ASSESS
```

`SHADOW_RECORD` normalizes execution/mechanism evidence only.

`SHADOW_ASSESS` does not by itself create a tactical claim. An EffectObjective and valid observation window are still required.

## Failure semantics

| Condition | Result |
|---|---|
| dry-run | execution `unverified` |
| policy gate prevents action | execution `rejected`; mechanism `not_observed` |
| all planned commands succeed | execution `applied` |
| some commands fail | execution `partial`; mechanism `disputed` |
| external notification delivery not proven | execution `unverified` |
| missing baseline/post evidence | outcome/effect `inconclusive` |
| observer unavailable | live control unchanged |
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
```

The passive observer can normalize the existing Rust JSONL output:

```bash
PYTHONPATH=py python3 -m azazel_edge.outcome.observer \
  --input /var/log/azazel-edge/normalized-events.jsonl \
  --output /var/log/azazel-edge/outcome-shadow.jsonl
```

For an explicit live-follow experiment, use `--follow`. Do not install it as a default daemon until the Pi/HIL gate is passed.

## Gates

### G1 — runtime grounding

Partial. Current execution/command/error/scope data is grounded. Automatic rollback scheduling, authoritative actor/session identity, external notify receipts and reboot reconciliation remain unresolved.

### G2 — shadow execution/mechanism contracts

Implemented. Must pass repository CI before merge.

### G3 — outcome collection

Contract implemented. Automatic OutcomeRecord production waits for exact policy-owned pre/post metric sources and telemetry-coverage semantics.

### G4 — tactical effect

`DELAY` assessment helper implemented only for explicit evidence-backed inputs. No automatic runtime tactical claim is enabled.

### G5 — replay

Read-only receipt replay boundary implemented. End-to-end golden replay fixture remains required.

### G6 — Pi/HIL

Pending. Measure CPU, RSS, disk growth, observer latency, restart behavior, queue/retention behavior, and deterministic-path regression before daemonizing or enabling by default.

## Parked until G1-G6 pass

Do not expand this slice into Presented Terrain, Belief, Counterfactual planning, MAGI Council, Co-Adaptation, automatic policy generation or broad autonomous response.
