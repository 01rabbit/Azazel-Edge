# Outcome-as-Evidence G3 — Passive pre/post telemetry collection

Tracking: #400  
Parent: `docs/architecture/outcome-as-evidence-v1.md`  
Prerequisites: G1a mechanism postcondition, G1b release lifecycle

## Purpose

G3 binds the existing `OutcomeRecord` contract to real, read-only pre/post telemetry without adding a second control plane.

The collector answers only:

> What was observed before and after this already-authorized action?

It does **not** answer:

> Did the action work?

Collection therefore cannot upgrade either of these fields:

```text
assessment     = inconclusive
causal_support = inconclusive
```

Tactical-effect assessment remains a separate deterministic gate.

## Authority boundary

```text
Rust event engine
  └─ Decision / apply / release authority

G3 collector
  ├─ read procfs
  ├─ read canonical Rust JSONL
  ├─ maintain bounded rolling telemetry
  ├─ correlate explicit policy-owned objective
  └─ emit OutcomeRecord evidence

G3 collector has no executor, no release callback, no nft/tc mutation path,
no shell command runner, and no AI authority.
```

The implementation lives in:

```text
py/azazel_edge/outcome/telemetry.py
```

## Why a rolling pre-action buffer is mandatory

The Rust event record is emitted after `maybe_enforce()` has already executed the provider command. Starting a baseline probe only after the JSONL record arrives would therefore falsely label post-action state as `baseline`.

G3 continuously records bounded telemetry before an action occurs:

```text
continuous read-only samples
        ↓
rolling bounded buffer
        ↓
Rust action record arrives
        ↓
freeze preceding samples as baseline window
        ↓
collect bounded post window
        ↓
OutcomeRecord
```

If the collector was started too late, it does not invent the missing baseline. It emits an explicit `insufficient_pre_samples` confounder and reduced telemetry coverage.

## Telemetry sources

### Linux procfs

`LinuxProcTelemetrySource` reads only:

```text
/proc/net/dev
/proc/loadavg
/proc/meminfo
/proc/uptime
```

No subprocess is used.

Initial network facts:

```text
rx_bytes
rx_packets
rx_errors
rx_dropped
tx_bytes
tx_packets
tx_errors
tx_dropped
```

Initial system facts:

```text
load1 / load5 / load15
MemTotal / MemAvailable
SwapTotal / SwapFree
uptime
```

A missing procfs component reduces coverage. It does not fail or alter the live defensive path.

### Rust event JSONL activity

The collector also records normalized Rust event timestamps scoped by `src_ip`.

This provides bounded observable facts such as:

```text
source_ip_event_count
source_ip_event_rate_hz
source_ip_interarrival_ms_median
first_followup_event_ms
```

`src_ip` is explicitly **not** promoted to attacker identity. Every generated outcome carries the confounder:

```text
source_ip_is_not_actor_identity
```

The action-triggering event itself is excluded from the before/after activity metrics so the decision trigger is not double-counted as evidence of subsequent behavior.

## Window metrics

Both baseline and post windows use the same metric vocabulary where available:

```text
window_seconds
telemetry_sample_count
source_ip_event_count
source_ip_event_rate_hz
source_ip_interarrival_ms_median
system_load1_mean
memory_available_kib_min
interface_rx_bytes_delta
interface_rx_packets_delta
interface_rx_errors_delta
interface_rx_dropped_delta
interface_tx_bytes_delta
interface_tx_packets_delta
interface_tx_errors_delta
interface_tx_dropped_delta
```

Counter decreases are not interpreted as negative traffic. They create a `counter_reset:<metric>` confounder and that delta is omitted.

## EffectObjective is explicit policy input

G3 has **no built-in success objective** and no AI-generated objective.

A live collector requires an operator/policy-owned JSON document:

```json
{
  "schema_version": "outcome-telemetry-policy/v1",
  "policy_version": "research-policy-1",
  "actions": {
    "throttle": {
      "metric": "source_ip_event_rate_hz",
      "direction": "observe",
      "target_or_range": {},
      "observation_window": {
        "pre_seconds": 30,
        "post_seconds": 30
      },
      "guardrails": []
    }
  }
}
```

The example above is a schema example, not a claim that event-rate reduction proves `DELAY`.

If an action has no explicit policy entry, G3 does not create an observation for that action.

The policy document is hashed and its reference is included in Outcome evidence. `objective_id` is deterministic for the decision + policy template so replay/comparison does not depend on a random identifier.

## Observation start rule

G3 starts a pending observation only when all are true:

1. record normalizes as a Rust event-engine execution record;
2. action is currently one of `throttle`, `redirect`, `isolate`;
3. execution status is `APPLIED`;
4. an explicit G3 policy template exists for that action;
5. the execution has not already been observed by this collector process;
6. bounded pending/seen capacity remains available.

Evidence capacity exhaustion fails closed by dropping the new observation request. It never changes the defensive action.

## Execution-time limitation

The current Rust execution receipt does not ground an exact provider completion timestamp.

G3 therefore anchors the action boundary to the time the collector receives the already-emitted Rust execution record and adds:

```text
provider_execution_timestamp_unavailable
```

as a confounder.

This avoids pretending `normalized.ts` is an exact provider-completion time.

## Release integration

A verified G1b release can shorten a pending post window, but only after exact matching of:

```text
decision_id
action
release_task_id
owner_token
resource_key
```

A release with only the same action or same decision is insufficient.

When a matching owned release arrives before the planned post window ends:

```text
termination_reason = owned_mechanism_released
window_truncated_by_release = true
```

The shorter record remains `inconclusive`; release is not tactical-effect proof.

## Replay boundary

The live CLI is intentionally **live-only**.

It always starts reading the canonical input at the current end of file. It does not offer a `--from-start` mode because replaying an old action and measuring current procfs state would create false pre/post evidence.

The library can still be driven with explicit synthetic/historical telemetry in tests or a future Golden Replay harness, but live collection never claims to reconstruct missing historical procfs state.

Within one collector process, started execution IDs are retained as replay guards. A finalized execution cannot be started again by replaying the same Rust record. If the bounded seen-ID capacity is exhausted, new Outcome collection fails closed rather than forgetting old execution identities.

Cross-restart durable Outcome deduplication remains a G5/G6 concern; the live CLI avoids historical replay by starting at EOF.

## Confounders emitted by G3

Current explicit confounders include:

```text
source_ip_is_not_actor_identity
provider_execution_timestamp_unavailable
mechanism_postcondition_not_observed
insufficient_pre_samples
insufficient_post_samples
objective_metric_not_collected
counter_reset:<counter>
```

A confounder is evidence about uncertainty; it is not automatically a pass/fail decision.

## Telemetry coverage

Each OutcomeRecord records:

```text
pre/post sample count
expected sample count
pre/post sample ratio
pre/post source-IP activity count
proc_net_dev coverage ratio
proc_loadavg coverage ratio
proc_meminfo coverage ratio
Rust JSONL activity availability
whether release truncated the window
collector interface
sample interval
policy evidence reference
```

## Resource bounds

Defaults:

```text
sample interval      1 second
rolling window       600 seconds
max samples          4096
max activity events  8192
max pending outcomes 128
max seen executions  4096
output rotation       existing Outcome observer 50 MiB bound
```

The collector rejects a configured policy observation window longer than its telemetry buffer.

These are software safety bounds, not Pi performance claims. G6 still must measure actual CPU, RSS, disk, latency and restart behavior.

## Live research invocation

Example:

```bash
PYTHONPATH=py python3 -m azazel_edge.outcome.telemetry \
  --input /var/log/azazel-edge/normalized-events.jsonl \
  --output /var/log/azazel-edge/outcome-telemetry.jsonl \
  --policy /path/to/operator-owned-outcome-policy.json \
  --interface br0
```

This is a foreground research tool only. Do **not** install or enable it as a daemon before G6.

## What G3 does not prove

A generated OutcomeRecord does not prove:

- `DELAY`;
- successful deception/diversion;
- containment effectiveness;
- causal attribution;
- attacker identity;
- attacker intent;
- business benefit;
- safe autonomous policy changes.

Even when the policy metric improves, G3 keeps:

```text
assessment     = inconclusive
causal_support = inconclusive
```

until a separate deterministic/evidence-backed evaluator supplies stronger proof.

## Adversarial review requirements

G3 is not merge-ready unless tests cover at least:

- procfs partial failure;
- no implicit policy objective;
- insufficient pre-action buffer;
- identical execution replay while pending;
- identical execution replay after finalization;
- pending/seen capacity fail-closed behavior;
- wrong release owner/task/resource not truncating a window;
- matching verified release truncating a window;
- no collection result becoming `effective` or causal merely because metrics changed;
- buffer shorter than policy window rejection.

## Remaining gates

G3 produces real pre/post Outcome evidence, but the full research baseline still requires:

- G5 Golden Replay and durable cross-restart correlation/deduplication;
- G6 Raspberry Pi/HIL performance, disk, restart and lifecycle testing;
- later evidence rules for any tactical-effect claim beyond the already fail-closed baseline.

Presented Terrain, Belief, Counterfactual planning, MAGI Council and Co-Adaptation remain parked until the current Outcome-as-Evidence gates are closed.
