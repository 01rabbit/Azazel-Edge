# Decision Loop

## Scope
This document describes the stable deterministic path used by Azazel-Edge to convert edge telemetry into explicit operator-facing actions.

## Pipeline
1. Event input (for example Suricata EVE and local probes) is received.
2. Inputs are normalized into Evidence Plane records.
3. NOC and SOC evaluators score state deterministically.
4. Policy thresholds are applied.
5. Action Arbiter selects one bounded action.
6. Decision Explanation is generated with rationale and alternatives.
7. Notification and optional AI assist are executed post-decision.
8. Audit logging records the full trace.

## Stable Components
| Component | Status | Notes |
|---|---|---|
| Evidence normalization | Implemented | Evidence Plane schema and bus are part of runtime baseline. |
| Deterministic evaluators | Implemented | NOC and SOC remain separate evaluators. |
| Policy-based action selection | Implemented | Arbiter action set is bounded. |
| Reversible control posture | Implemented | Actions are explicit and operator-reviewable. |
| Reproducibility metadata (`config hash`) | Planned | Partial support exists; full packaging across all outputs is still maturing. |

## Defensive State — the outward vocabulary

The Arbiter's bounded action set **is** the canonical Defensive State
vocabulary (Azazel#62, Azazel-Edge#379):

```text
OBSERVE | NOTIFY | THROTTLE | REDIRECT | ISOLATE
```

`ActionArbiter.ACTION_PROFILES` is keyed on exactly these five, so what Edge
outwardly *is doing* maps 1:1 onto what the Arbiter selected. A test pins that
(`tests/test_defensive_state_vocabulary.py`); an added or renamed action fails
there rather than quietly widening the vocabulary.

Four concepts have historically been described as a "mode" and are **not**
Defensive State:

| Term | Answers | Where it lives |
| --- | --- | --- |
| **Threat Level** | how severe is the situation? | NOC/SOC evaluator output |
| **Policy Profile** | which deterministic tuning is loaded? | `conservative` / `balanced` / `demo` |
| **AI Runtime Tier** | what can M.I.O. infer with? | M.I.O. runtime, advisory in every tier |
| **Control class** | how much control does an action exert, and is a human in the loop? | the `mode` key *inside* an action profile: `passive` / `human_loop` / `bounded_control` / `high_risk_control` |

The control class is the one most easily confused with a state, because it
literally lives under a key called `mode`. It is a different axis: `throttle`
and `redirect` are different Defensive States sharing one control class. The
test asserts the two sets never overlap.

**M.I.O. never sets the Defensive State.** It supplies bounded hypotheses; the
Arbiter remains the sole authority, and `azazel_edge.mio` carries the five
values as a closed set it validates against, not one it may extend.

**Absence is not a state.** The cross-product projection
(`azazel_edge.fabric_view`) reports `unknown` when a snapshot names no mode. It
used to default to the legacy name `shield`, which asserted a posture nobody
chose out of the absence of one. `unknown` is deliberately not one of the
canonical five either: "the snapshot did not say" and "Edge is observing" are
different facts and must not be indistinguishable on the wire.

Legacy names (`portal`, `shield`, `scapegoat`) remain permitted as concept
branding. No mapping from them to the canonical five is defined anywhere, and
that is deliberate — see
[the system doctrine page](https://github.com/01rabbit/Azazel/blob/main/docs/architecture/defensive-state.md).

## Safety Constraints
- Deterministic path remains authoritative.
- AI assist is optional and invoked only after deterministic decision stages.
- Fail-closed defaults are retained for protected API behavior.

## Related Documents
- [P0 Runtime Architecture](../P0_RUNTIME_ARCHITECTURE.md)
- [Evidence Model](evidence-model.md)
- [Local AI Triage](local-ai-triage.md)
