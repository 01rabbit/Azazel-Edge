# M.I.O. Cognitive Shadow Core

Status: initial test-stage implementation for issues #361-#366, #372, #376, and #377.

## Scope

This module establishes the first executable M.I.O. cognitive substrate without changing production enforcement behavior.

It is deliberately **shadow/replay only**:

```text
Evidence / deterministic state
        |
        v
MioSituationFrame
        |
        v
Reasoning Playbook
        |
        v
multiple hypotheses
        |
        v
Evidence Gaps
        |
        v
Typed read-only Capability Broker
        |
        v
Grounding Validator
        |
        v
M.I.O. Recommendation (executable=false)
```

No code in `py/azazel_edge/mio/` calls the Action Arbiter, enforcement handlers, nftables/iptables/tc, Docker, AZ-06 activation, or arbitrary shell/HTTP facilities.

## Authority boundary

- Deterministic Edge evaluation remains authoritative.
- M.I.O. output is advisory data only.
- `MioRecommendation.executable` is always `False`.
- Recommended action vocabulary is bounded to `OBSERVE / NOTIFY / THROTTLE / REDIRECT / ISOLATE`, but a recommendation does not set Defensive State.
- Runtime integration with the existing governed AI path is intentionally deferred until the shadow/replay contracts and adversarial tests are stable.

## Components

### `contracts.py`

Defines bounded local contracts for:

- `MioSituationFrame`
- `MioHypothesis`
- `MioEvidenceGap`
- capability request/result
- advisory recommendation
- reasoning state

The SituationFrame limits list cardinality and text size so small local models receive a compact state instead of unbounded raw logs.

### `playbook.py`

Defines versioned Reasoning Playbooks and a deterministic prompt/context compiler.

The compiler separates:

- `TRUSTED_CONTROL`: versioned instructions and playbook method
- `UNTRUSTED_DATA`: SituationFrame, hypotheses, and capability results

Attacker-controlled strings remain data even if they contain instruction-like text.

### `broker.py`

Provides a static typed allowlist of read-only evidence capabilities with per-capability and per-cycle call budgets plus result-size bounds.

It intentionally has no shell, arbitrary filesystem path, arbitrary HTTP, Docker socket, packet-control, or enforcement primitive.

### `grounding.py`

Rejects:

- fabricated evidence references
- unsupported recommendation actions
- executable recommendations
- directive-like fields such as `execute`, `override`, `activate`, or `enforce`

This validation is deterministic; an LLM never judges another LLM's authority.

### `reasoning.py`

Implements a bounded shadow state machine:

```text
FRAME_READY
 -> HYPOTHESES_READY
 -> EVIDENCE_GAPS_IDENTIFIED
 -> REQUEST_PLANNED / EVIDENCE_COLLECTED
 -> RECOMMENDATION_READY
 -> COMPLETE
```

Failure paths include validation rejection, budget exhaustion, dependency/model error fallback, and broker refusal.

### `trace.py`

Records a minimized replay trace with separate trace/cycle identifiers. Raw prompts and raw logs are intentionally not retained.

### `replay.py`

Provides the first deterministic replay harness seam. Tests currently use a fake structured model so the orchestration and authority boundaries can be verified independently of Ollama/model quality.

## Test-stage boundary

This implementation is ready for unit/replay testing of the cognitive mechanics. It is **not** yet permission to:

- feed M.I.O. output into live Arbiter inputs;
- activate Knowledge or Deception as runtime dependencies;
- enable live local-model invocation outside the existing AI-governance path;
- enable enforcement from M.I.O. recommendations.

Those steps remain gated by the later integration issues and adversarial review #373.

## Initial test coverage

`tests/test_mio_cognitive_shadow_core.py` verifies:

- SituationFrame bounding/normalization;
- trusted vs untrusted context separation;
- Capability Broker allowlisting and budgets;
- fabricated-reference/directive rejection;
- complete hypothesis -> gap -> evidence -> recommendation replay;
- fail-closed rejection of model-supplied execution directives;
- versioned playbook replay selection.

## Next test-stage work

1. Add deterministic builders from real Evidence Plane/evaluator snapshots into `MioSituationFrame`.
2. Expand playbooks to exploit, NOC-vs-SOC, friction-reaction, and deception-observation families.
3. Add stale-frame/cancellation/concurrency semantics.
4. Add resource profiling and adversarial fixtures to the #372 harness.
5. Define a governed local-model adapter that extends, rather than bypasses, `ai_governance.py`.
6. Begin #373 hostile review before any operational input to Engagement/Deception.
