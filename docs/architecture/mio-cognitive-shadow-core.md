# M.I.O. Cognitive Shadow Core

Status: test-stage implementation for issues #361-#366, #370, #372, #376, and #377.

## Scope

This module establishes the executable M.I.O. cognitive substrate without changing production enforcement behavior.

It remains deliberately **shadow/replay only**:

```text
Evidence Plane + deterministic NOC/SOC outputs + current Defensive State
        |
        v
MioSituationFrameBuilder
        |
        v
MioSituationFrame
        |
        v
Reasoning Playbook + bounded task schema
        |
        v
existing AIGovernance authorization gate
        |
        v
local/on-prem structured model
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
additional evidence
        |
        v
Hypothesis Revision
(strengthen / weaken / falsify / unresolved)
        |
        v
Grounding Validator
        |
        v
M.I.O. Recommendation (executable=false)
```

No code in `py/azazel_edge/mio/` calls the Action Arbiter, enforcement handlers, nftables/iptables/tc, Docker, AZ-06 activation, or arbitrary shell execution.

## Authority boundary

- Deterministic Edge evaluation remains authoritative.
- M.I.O. output is advisory data only.
- `MioRecommendation.executable` is always `False`.
- Recommended action vocabulary is bounded to `OBSERVE / NOTIFY / THROTTLE / REDIRECT / ISOLATE`, but a recommendation does not set Defensive State.
- The current Defensive State is input context; it is not selected by the model.
- M.I.O. model failure, governance refusal, stale context, or cancellation terminates only the reasoning cycle. Baseline Edge operation continues.

## Components

### `contracts.py`

Defines bounded local contracts for:

- `MioSituationFrame`
- `MioHypothesis`
- `MioEvidenceGap`
- capability request/result
- advisory recommendation
- reasoning state

The SituationFrame limits list cardinality and text size so small local models receive compact state instead of unbounded raw logs. Structured model output is treated as malformed unless list-shaped fields are actual arrays; a string is never silently split into character-sized references. Numeric fields such as Evidence Gap priority use bounded deterministic fallbacks instead of raising through the reasoning loop.

### `frame_builder.py`

Builds a `MioSituationFrame` from normalized Evidence Plane records and deterministic NOC/SOC evaluation dictionaries.

Privacy/context-minimization rules:

- raw event `attrs`, log messages, and subjects are **not** copied into the model frame;
- detailed records remain referenced by `evidence_id` and are retrieved only through typed capabilities;
- deterministic reason strings are reduced to reason taxonomy codes rather than retaining subject/value suffixes;
- malformed frame timestamps are rejected;
- future-dated evidence outside a small clock-skew allowance is treated as stale/unknown rather than fresh.

This builder performs no model call and no network call.

### `playbook.py`

Defines versioned Reasoning Playbooks and a deterministic prompt/context compiler.

Initial families:

1. authentication ambiguity
2. scan/recon ambiguity
3. exploit-signal ambiguity
4. NOC-vs-SOC ambiguity
5. friction/reaction analysis
6. deception-observation interpretation

The compiler separates:

- `TRUSTED_CONTROL`: versioned method, claim boundaries, budgets, and per-task output schema;
- `UNTRUSTED_DATA`: SituationFrame, hypotheses, and capability results.

The output schema is task-specific:

1. `generate_hypotheses`
2. `identify_evidence_gaps`
3. `update_hypotheses`
4. `recommend`

The explicit revision task is important: new broker evidence must be allowed to strengthen, weaken, falsify, or leave hypotheses unresolved **before** the final recommendation. This preserves the white-hacker sequence rather than jumping directly from evidence collection to advice.

For both initial hypothesis generation and revision, trusted control requires a per-hypothesis evidence reference to have exactly one role: supporting or contradicting, never both. Evidence whose role is ambiguous is retained as an explicit `missing_evidence` or `assumptions` entry, rather than being placed in either evidence list. A no-escalation recommendation must use `OBSERVE` explicitly; M.I.O. never represents it with an empty action.

### `broker.py`

Provides a static typed allowlist of read-only evidence capabilities with per-capability and per-cycle call budgets plus result-size bounds.

It intentionally has no shell, arbitrary filesystem path, arbitrary HTTP, Docker socket, packet-control, or enforcement primitive.

### `model_adapter.py`

Provides the first governed local structured-model adapter.

Governance properties:

- every model task passes the existing `AIGovernance.should_invoke` policy through the reusable `authorize()` seam;
- current automation scope therefore remains restricted by the repository's existing policy (for example ambiguous/uncertain Suricata candidate use); this PR does not silently widen AI invocation;
- raw compiled prompts are not persisted in the AI audit; only task name + prompt digest + bounded model/result metadata are recorded;
- model output remains `adopted_pending_grounding` until M.I.O.'s deterministic validator accepts it.

Transport properties:

- default endpoint is loopback Ollama only;
- model chain defaults to `qwen3.5:2b` then `qwen3.5:0.8b`;
- response size, timeout, context, prediction, and thread counts are bounded;
- public IPs and arbitrary DNS endpoints are rejected;
- a private-LAN on-prem endpoint must be a private IP literal and requires explicit opt-in, HTTPS, and bearer authentication;
- there is no automatic public/cloud fallback.

### `grounding.py`

Rejects:

- fabricated evidence references
- a per-hypothesis evidence reference used as both supporting and contradicting
- duplicate hypothesis IDs
- Evidence Gaps referencing nonexistent hypotheses
- Evidence Gaps requesting capabilities outside the selected Playbook
- unsupported recommendation actions
- executable recommendations
- directive-like fields such as `execute`, `override`, `activate`, `enforce`, or `executable`, including nested occurrences

This validation is deterministic; an LLM never judges another LLM's authority.

### `reasoning.py`

Implements a bounded shadow state machine:

```text
FRAME_READY
 -> HYPOTHESES_READY
 -> EVIDENCE_GAPS_IDENTIFIED
 -> REQUEST_PLANNED / EVIDENCE_COLLECTED
 -> HYPOTHESES_UPDATED (when evidence was returned)
 -> RECOMMENDATION_READY
 -> COMPLETE
```

The default model-call ceiling is four calls for a cycle that actually retrieves additional evidence. If no capability result exists, hypothesis revision is skipped to avoid a useless inference call on constrained hardware.

Terminal/fallback paths currently include:

- `STALE_SUPERSEDED`
- `OPERATOR_CANCELLED`
- `BUDGET_EXHAUSTED`
- `VALIDATION_REJECTED`
- `DEPENDENCY_UNAVAILABLE`
- `ERROR_FALLBACK`

Stale frames and immediate operator cancellation stop **before the first model call**.

### `trace.py`

Records a minimized replay trace with separate trace/cycle identifiers. Raw prompts and raw logs are intentionally not retained. The trace now records `HYPOTHESES_UPDATED` so a replay can show which newly retrieved evidence changed the working interpretation before recommendation.

### `replay.py`

Provides the deterministic replay seam. Unit tests use fake structured models so orchestration, boundary, and degradation behavior can be tested independently of model quality.

### `bin/azazel-mio-shadow-replay`

Manual test runner for a real local 2B/0.8B Ollama chain.

Example using the checked-in normalized fixture:

```bash
python bin/azazel-mio-shadow-replay \
  --fixture tests/fixtures/mio/auth_ambiguity_shadow.json \
  --playbook auth-ambiguity-v1
```

This command only prints a reasoning result and writes AI governance audit metadata. It never calls the Action Arbiter or enforcement.

For a private-LAN accelerator, the current test-stage transport requires all of:

```text
--allow-private-network
https://<private-ip>:<port>
AZAZEL_MIO_BEARER_TOKEN=<token>
```

The bearer token is read from an environment variable rather than a command-line argument.

## Test-stage boundary

This implementation is ready for:

- unit tests of contracts/budgets/grounding;
- replay tests with normalized deterministic snapshots;
- prompt-injection and malformed-output fixtures;
- local 2B/0.8B model quality experiments;
- model-down/governance-blocked/stale/cancelled degradation testing.

It is **not** permission to:

- feed M.I.O. output into live Arbiter inputs;
- make Knowledge or Deception a synchronous runtime dependency;
- enable enforcement from M.I.O. recommendations;
- broaden AI invocation policy without separate review;
- treat private-LAN model access as production-ready merely because the transport can authenticate to a test endpoint.

Operational influence remains gated by #373 adversarial review and the later cross-product integration issues.

## Current test coverage

`tests/test_mio_cognitive_shadow_core.py` covers the core cognitive loop, including explicit evidence-driven hypothesis revision and rejection of invented evidence during revision.

`tests/test_mio_shadow_runtime_integration.py` covers deterministic NOC/SOC frame construction, raw-data minimization, timestamp handling, existing AI-governance allow/block behavior, prompt non-retention, endpoint restrictions, stale/model-down/cancel degradation, and private-LAN TLS/auth requirements.

`tests/test_mio_frame_builder_with_evaluators.py` feeds real `NocEvaluator` and `SocEvaluator` result shapes into the builder and verifies evidence linkage without copying IP/subject content into the model frame.

`tests/test_mio_adversarial_schema.py` covers malformed array fields, nonnumeric priority, duplicate hypothesis IDs, invalid Evidence Gap hypothesis references, explicit hypothesis-revision schema, and arbitrary-DNS endpoint rejection.

## Remaining before the #373 gate

1. Add broader adversarial replay corpus (cross-trace refs, Unicode/delimiter injection, malformed Ollama envelopes, capability spoofing, concurrent cycles).
2. Add measured Pi-class resource/latency profiling for 0.8B/2B.
3. Add deterministic capability implementations backed by real read-only Evidence/health/trace stores (current replay broker can use static fixture results).
4. Add reasoning-cycle concurrency/backpressure ownership and explicit supersession across live shadow cycles.
5. Run the dedicated #373 hostile review and remediate all critical/high findings.

No Engagement/Deception operational influence should be enabled before that gate passes.
