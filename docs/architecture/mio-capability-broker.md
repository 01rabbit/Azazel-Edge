# M.I.O. Capability Broker (read-only, typed, allowlisted)

Canonical architecture, authority matrix and degradation ladder: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

Implementation: `py/azazel_edge/mio/broker.py`. Tests:
`tests/test_mio_capability_broker_acceptance.py`, `tests/test_mio_capability_broker_384_v1.py`.
Parent design: #364, acceptance: #384.

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

- Capability names are refused when a `_`-separated token is in `FORBIDDEN_NAME_TOKENS`
  (short words such as `run`, `set`, `file`, `send`, `block`) **or** when the name contains
  any `FORBIDDEN_NAME_STEMS` substring (`exec`, `shell`, `write`, `delete`, `http`, `url`,
  `fetch`, `filesystem`, `path`, `isolat`, `redirect`, `throttl`, `arbiter`, `approv`,
  `transition`, `activat`, `decoy`, `az06`, ...). Run-together names such as `writefile`,
  `readexec`, `fetchurl`, `get_filesystem` are therefore refused.
- Parameter names are refused by token (`uri`, `port`, `dir`, `dest`, ...) or by stem
  (`path`, `file`, `url`, `host`, `cmd`, `command`, `script`, `endpoint`, `target`, ...),
  e.g. `dest_path`, `file_name`, `target_host`.
- Specs are deep-frozen: each `CapabilitySpec` and its `params` are copied into a
  `MappingProxyType` and the copy is validated. Mutating the caller's dict after
  construction has no effect. The registry itself is a `MappingProxyType`.
- An empty registry (feature disabled baseline) refuses every request.

## Request contract

`MioCapabilityRequest` (frozen dataclass): `request_id`, `trace_id`, `capability`, `arguments`,
`purpose_hypothesis_ids` (audit only), optional `max_age_seconds` (can only tighten the
capability's freshness requirement).

The contract is closed. Only an instance of exactly `MioCapabilityRequest` is accepted;
a duck-typed object, a subclass, a dict or `None` is `invalid` / `request_type_invalid`
before any other check, so extra attributes (`approved`, `execute`, ...) cannot ride along.
`purpose_hypothesis_ids` must be a tuple or list of at most 8 non-empty strings of at most
96 characters without control characters; otherwise `invalid_purpose_hypothesis_ids`.

Parameter kinds (`ParamSpec.kind`): `text` (opaque bounded data, never interpreted as a
path/URL/command; C0 controls other than tab/newline, DEL, C1 controls, bidi controls and
lone surrogates are refused), `identifier` (`[A-Za-z0-9][A-Za-z0-9:._@#+=-]*`, no `..`, no `/`),
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
- `source_timestamp` is **self-claimed by the adapter**: the broker bounds and checks it
  but cannot verify it independently. Non-finite, negative or unparseable timestamps are
  `invalid` (`source_timestamp_invalid`); future timestamps (> 60 s skew) are `invalid`.
- Reserved keys (`status`, `provenance`, `authority`, `trust`, `approved`, ...) are stripped
  case-insensitively at every depth of the result; the walk is bounded (depth 4, 2048 nodes)
  and the size cap is applied during the walk, before full serialization.
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
| `max_quarantined` | `CapabilityBroker(...)` | 4 (bound on running + timed-out workers, ≤ 16) |
| `max_age_seconds` | `CapabilitySpec` / request | none |

Slots are acquired with `blocking=False`. When a slot is unavailable the broker returns
`rejected` with `broker_overloaded` or `capability_overloaded` immediately. Budget check,
increment and slot acquisition happen in one critical section, so concurrent callers cannot
exceed `max_total_calls`.

A handler that exceeds its timeout yields `timeout`. Its concurrency slot is released at
once (exactly-once release shared with the worker), and the still-running worker is counted
in a bounded quarantine. The bound holds exactly: a request is admitted only while
running + quarantined workers < `max_quarantined` (globally) and < `max_concurrency` (per
capability). Every quarantined worker was a running one, so even if all running handlers time
out at once or `close()` strands them, `quarantined() <= max_quarantined` (exposed as
`quarantine_limit()`) and per capability ≤ `max_concurrency`. The effective global concurrency
is therefore `min(max_in_flight, max_quarantined)`. A refusal caused by quarantined workers is
`capability_quarantined` / `broker_quarantine_full`; with no quarantined worker it is
`capability_overloaded` / `broker_overloaded`. A worker marks itself done before it wakes the
waiting submit, so a handler that finished is never reported as a timeout. A worker that fails to start
releases its slots and returns `error` / `worker_start_failed`.

### Cycle close (stale cycles)

A broker serves one reasoning cycle. `close()` ends it (for example when the cycle is
superseded by a newer frame). It is idempotent and has no other effect:

- later requests are refused with `rejected` / `broker_closed`, without calling the handler;
- a request waiting on a handler is woken at once and returns `stale` / `cycle_closed` with
  no data and no evidence refs, even if the handler finishes in the same instant;
- Python threads cannot be killed, so a handler still running is moved to the bounded
  quarantine (as for a timeout) and its result is discarded when it returns.

Nothing calls `close()` yet; wiring it to the lifecycle supersede path belongs to #385.

Callers: only `BoundedReasoningLoop` (`py/azazel_edge/mio/reasoning.py`), used by the offline
`bin/azazel-mio-shadow-replay` and `bin/azazel-mio-evaluate`, calls the broker. No
deterministic Edge path (Action Arbiter, control daemon, enforcement, AZ-06 client) imports
`azazel_edge.mio`, so none of these states can block it.

`submit()` never raises. `execute()` (used by the reasoning loop) raises
`CapabilityBrokerError(<reason>)` for `rejected`/`invalid` to keep the loop's existing
error handling; every other status is returned as data.

## Audit projection

Every request, allowed or refused, appends one record (bounded ring, default 256; optional
`audit_sink`, whose failures are swallowed):

`schema, request_id, trace_id, purpose_hypothesis_ids, capability (only if allowlisted),
capability_digest (sha256 prefix if not), decision (allowed|refused), status, reason,
params, evidence_refs, source_component, age_seconds, latency_ms, result_chars, truncated`.

The record has exactly these keys (`AUDIT_RECORD_FIELDS`), plus `audit_truncated` when
reduced. `reason` must match the broker's reason grammar
(`code[:Identifier[:Identifier]]`); anything else, such as an odd handler exception class
name, is recorded as `reason_redacted`.

`params` holds only kind, Python type, length and (for identifiers) a digest; free-text values
and unknown key names are never recorded (`unknown_param_count` only). `request_id`,
`trace_id`, `purpose_hypothesis_ids` and `evidence_refs` are kept only when they match the
identifier grammar **and** carry no address or credential shape: the SituationFrame opaque-ID
rule (IPv4 quads, also dashed or with a port, MAC-like runs, IPv6) and the M.I.O. redaction
token rules (API keys, bearer tokens, long tokens, e-mail). Otherwise they are replaced by
`h:<digest>`.

Before those checks, a value must fit a closed schema of the identifier shapes this repository
produces (`AUDIT_ID_VOCABULARY` in `broker.py`): evidence-plane event ids `sha256:<64 hex>`,
Edge core trace ids `trace-0x<hex>` with lifecycle/loop suffixes (`:e1:c3:req:2`), and ids made
of vocabulary words and short ordinals (`ev:auth:0001`, `replay:g5-golden-replay-v1:req:1`,
`h1`) with at most two numeric segments in a row. Hostnames, person names, bare hex, packed or
integer-encoded IPv4, separator-free MACs and token-like values are all digested. Adding a new
id shape means adding its words to the vocabulary and a test.

The result returned to the reasoning loop is unchanged; only the audit projection is reduced.
In particular `MioCapabilityResult.request_id` echoes the request's id (bounded, control
characters replaced): the only caller builds it as `<cycle_id>:req:<n>` from lifecycle or
replay cycle ids, and the trace audit (`trace_audit.py`) applies its own redaction before
anything is persisted. Digests are HMAC-SHA256 with a per-process
random key (truncated to 16 hex), so low-entropy values such as IP addresses cannot be
recovered offline; they are comparable only within one process. Records larger than
2048 characters are reduced and flagged `audit_truncated`. `audit_records()` and the sink receive
deep copies.

## Adding a capability safely

1. Write down the reasoning use-case and a data-minimization argument (#364).
2. Use a read-only name (`get_`, `query_`, `lookup_` ...) that passes the registry rules.
3. Declare the narrowest `params` schema; prefer `identifier`/`integer`/`boolean` over `text`.
4. The handler must read already-normalized local Edge data in-process; it must not open
   sockets, spawn processes, write files, or call Arbiter / control-plane / AZ-06 clients.
5. Return `source_timestamp` and `evidence_refs`; set `max_age_seconds` and a tight
   `timeout_seconds` / `max_result_chars`.
6. Add the name to the relevant playbook's `allowed_capabilities` and add adversarial tests.
