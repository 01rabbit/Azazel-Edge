# M.I.O. Capability Broker (read-only, typed, allowlisted)

Implementation: `py/azazel_edge/mio/broker.py`. Tests:
`tests/test_mio_capability_broker_acceptance.py`. Parent design: #364, acceptance: #384.

> M.I.O. selects from capabilities. It does not invent commands.

The broker is the only evidence-access surface the M.I.O. reasoning loop has. It is a
security boundary: it never executes, writes, or reaches the network generically, and it
has no path to the Action Arbiter, enforcement handlers, the control-plane socket, or
AZ-06 Deception control.

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Capability name (from model evidence gap) | untrusted | must match `[a-z][a-z0-9_]{2,63}` and be an exact key of the frozen registry; otherwise `rejected` |
| Request arguments (from model) | untrusted | closed typed schema per capability; unknown keys / type confusion / oversize / control chars → `invalid` before any handler runs |
| Adapter result data | untrusted (`trust="untrusted_data"`) | JSON-only, depth ≤ 4, size-capped; never promoted into instructions |
| Adapter provenance claims (`source_component`, `status`, `trust`, `approved`, ...) | ignored | stripped; broker assigns provenance from the registry spec |
| Registry (`CapabilitySpec`) | trusted code | validated and frozen at construction |

## Registry rules (structural, enforced at construction)

- Names containing write / execute / network / path / enforcement / AZ-06 tokens
  (e.g. `exec`, `shell`, `write`, `delete`, `http`, `url`, `fetch`, `file`, `isolate`,
  `redirect`, `throttle`, `arbiter`, `approve`, `transition`, `activate`, `decoy`, `az06`)
  are refused (`FORBIDDEN_NAME_TOKENS`).
- Parameter names that would let the model aim a handler at an arbitrary target
  (`path`, `file`, `url`, `host`, `port`, `command`, `cmd`, `endpoint`, ...) are refused
  (`FORBIDDEN_PARAM_NAMES`).
- The registry is a `MappingProxyType`; it cannot be extended after construction.
- An empty registry (feature disabled baseline) refuses every request.

## Request contract

`MioCapabilityRequest`: `request_id`, `trace_id`, `capability`, `arguments`,
`purpose_hypothesis_ids` (audit only), optional `max_age_seconds` (can only tighten the
capability's freshness requirement).

Parameter kinds (`ParamSpec.kind`): `text` (opaque bounded data, never interpreted as a
path/URL/command), `identifier` (`[A-Za-z0-9][A-Za-z0-9:._@#+=-]*`, no `..`, no `/`),
`integer` (exact `int`, `bool` refused, range-checked), `boolean` (exact `bool`).
Default schema (what the reasoning loop sends): `question: text(300)`, `frame_id: identifier(96)`.

## Result contract

`MioCapabilityResult.status` is one of:
`ok | unavailable | timeout | stale | rejected | invalid | truncated | error`.

Broker-assigned fields: `source_component`, `source_timestamp`, `retrieved_at`,
`age_seconds`, `max_age_seconds`, `latency_ms`, `result_chars`, `truncated`,
`limitations`, `trust`. Evidence refs are filtered to the identifier grammar and capped at 32.

- `stale`: source timestamp older than the required freshness, or missing when freshness
  is required. Stale results carry **no data and no evidence refs**.
- Future timestamps (> 60 s skew) are `invalid`.
- Handler exceptions become `error` with only the exception class name
  (`handler_error:<Class>`); raw exception text is never returned or audited.
  `CapabilityUnavailable` becomes `unavailable`.

## Budgets, timeout and backpressure

| Knob | Where | Default |
|---|---|---|
| `max_total_calls` | `CapabilityBroker(...)` | 4 per broker (= per reasoning cycle) |
| `max_calls_per_cycle` | `CapabilitySpec` | 2 |
| `max_result_chars` | `CapabilitySpec` | 4096 |
| `timeout_seconds` | `CapabilitySpec` | 2.0 (range 0–30) |
| `max_concurrency` | `CapabilitySpec` | 1 (range 1–8) |
| `max_in_flight` | `CapabilityBroker(...)` | 4 (global, ≤ 16) |
| `max_age_seconds` | `CapabilitySpec` / request | none |

Slots are acquired with `blocking=False`. When a slot is unavailable the broker returns
`rejected` with `broker_overloaded` or `capability_overloaded` immediately. A handler that
exceeds its timeout yields `timeout`; its slot remains held until it returns, so a stuck
adapter produces typed refusals rather than an unbounded queue. The deterministic Edge path
never calls the broker and is not affected by any of these states.

`submit()` never raises. `execute()` (used by the reasoning loop) raises
`CapabilityBrokerError(<reason>)` for `rejected`/`invalid` to keep the loop's existing
error handling; every other status is returned as data.

## Audit projection

Every request, allowed or refused, appends one record (bounded ring, default 256; optional
`audit_sink`, whose failures are swallowed):

`schema, request_id, trace_id, purpose_hypothesis_ids, capability (only if allowlisted),
capability_digest (sha256 prefix if not), decision (allowed|refused), status, reason,
params, evidence_refs, source_component, age_seconds, latency_ms, result_chars, truncated`.

`params` holds only kind, Python type, length and (for identifiers) a digest; raw text values
and unknown key names are never recorded (`unknown_param_count` only). Records larger than
2048 characters are reduced and flagged `audit_truncated`.

## Adding a capability safely

1. Write down the reasoning use-case and a data-minimization argument (#364).
2. Use a read-only name (`get_`, `query_`, `lookup_` ...) that passes the registry rules.
3. Declare the narrowest `params` schema; prefer `identifier`/`integer`/`boolean` over `text`.
4. The handler must read already-normalized local Edge data in-process; it must not open
   sockets, spawn processes, write files, or call Arbiter / control-plane / AZ-06 clients.
5. Return `source_timestamp` and `evidence_refs`; set `max_age_seconds` and a tight
   `timeout_seconds` / `max_result_chars`.
6. Add the name to the relevant playbook's `allowed_capabilities` and add adversarial tests.
