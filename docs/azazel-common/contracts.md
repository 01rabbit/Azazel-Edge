# Azazel-Common: Contracts

Status: **Design proposal only. Field lists below are a starting proposal
for `v0.1.0` and are expected to be refined during Issue 2/3 review, not
frozen by this document.**

All schemas are proposed as Pydantic v2 models under `azazel_common.schema`
and `azazel_common.cti_contracts`. Field types below are illustrative, not
final signatures.

## 1. State / mode / action contracts (`azazel_common.schema`)

### `StateSnapshot`

The single shape that Web UI, TUI, E-Paper, and any status API read to
render "what is the system doing right now."

| field | type | notes |
|---|---|---|
| `schema_version` | str | e.g. `"1.0"` |
| `product` | Literal[`"edge"`, `"gadget"`, `"cti"`, ...] | which Azazel product emitted this |
| `mode` | `ModeState` | current operating mode |
| `generated_at` | str (ISO 8601) | snapshot timestamp |
| `trace_id` | str | correlates with `AuditEvent`/`TrustCapsule` |
| `summary` | dict[str, Any] | product-specific, loosely-typed payload for fields that don't warrant their own shared schema yet |

### `ModeState`

| field | type | notes |
|---|---|---|
| `name` | Literal[`"portal"`, `"shield"`, `"scapegoat"`, `"observe"`, `"lockdown"`, ...] | open enum — products may register additional values via a documented extension list, not by breaking the base type |
| `since` | str (ISO 8601) | when this mode was entered |
| `reason` | str \| None | human-readable, optional |

### `ActionIntent`

Describes an *intended* action shape — not an executor, not a command to
nft/tc/OpenCanary. See `architecture.md` §4 and `migration-plan.md` for why
execution stays out of Common.

| field | type | notes |
|---|---|---|
| `kind` | Literal[`"observe"`, `"notify"`, `"throttle"`, `"redirect"`, `"isolate"`, `"decoy"`, `"release"`] | |
| `target` | str | opaque identifier (IP, session id, device id — product-defined) |
| `issued_by` | str | which component/product issued this intent |
| `evidence` | list[`EvidenceRef`] | |
| `trace_id` | str | |

### `EvidenceRef`

| field | type | notes |
|---|---|---|
| `evidence_id` | str | |
| `source` | str | e.g. `"noc_evaluator"`, `"soc_evaluator"`, `"cti_advisory"` |
| `trace_id` | str | |
| `observed_at` | str (ISO 8601) | |

### `DecisionExplanation`

The shared shape for "why did the system do this," independent of which
product's arbiter produced it.

| field | type | notes |
|---|---|---|
| `selected_action` | `ActionIntent` | |
| `why_chosen` | str | |
| `why_not_others` | list[str] | |
| `release_condition` | str \| None | condition under which this decision should be revisited/released |
| `confidence` | float \| None | 0.0–1.0, optional |
| `trace_id` | str | |

### `AuditEvent`

Standard JSONL audit-log record shape.

| field | type | notes |
|---|---|---|
| `event_id` | str | |
| `trace_id` | str | |
| `timestamp` | str (ISO 8601) | |
| `product` | str | |
| `event_type` | str | |
| `payload` | dict[str, Any] | product-defined body |
| `config_hash` | str \| None | |
| `hmac` | str \| None | tamper-evidence signature, optional |

### `TrustCapsule`

| field | type | notes |
|---|---|---|
| `trace_id` | str | |
| `config_hash` | str | |
| `hmac` | str | |
| `issued_at` | str (ISO 8601) | |

## 2. CTI contract (`azazel_common.cti_contracts`)

This is the highest-priority contract in the initial release: it is the
only place where two *different* repositories (Edge/Gadget and CTI) must
agree on wire format across a network boundary today.

### Direction and endpoints

| Direction | Endpoint | Payload schema |
|---|---|---|
| Edge/Gadget → CTI | `POST /v1/events` | `CtiEventBatch` |
| Edge/Gadget → CTI | `POST /v1/flows` | `CtiFlowBatch` |
| Edge/Gadget → CTI | `POST /v1/reactions` | `CtiReactionBatch` |
| Edge/Gadget → CTI | `POST /v1/context` | `CtiContextRequest` |
| CTI → Edge/Gadget | response to `/v1/context` | `CtiContextResponse` |

### `CtiEventBatch` / `CtiFlowBatch` / `CtiReactionBatch`

Common envelope shape (exact per-event field lists to be finalized against
current Azazel-CTI API during Issue 3, without breaking its existing
consumers):

| field | type | notes |
|---|---|---|
| `batch_id` | str | |
| `source_product` | Literal[`"edge"`, `"gadget"`] | |
| `source_device_id` | str | |
| `generated_at` | str (ISO 8601) | |
| `items` | list[dict] | events/flows/reactions; product-typed sub-schema layered on later, not forced in v0.1.0 |

### `CtiContextRequest`

| field | type | notes |
|---|---|---|
| `request_id` | str | |
| `source_product` | Literal[`"edge"`, `"gadget"`] | |
| `indicators` | list[str] | IPs, hashes, domains, etc. being queried |
| `trace_id` | str | |

### `CtiContextResponse`

This schema is the concrete encoding of the advisory-only boundary
described in `design-principles.md` §4.2–§4.3.

| field | type | notes |
|---|---|---|
| `request_id` | str | echoes the request |
| `matches` | list[`IocMatch`] | may be empty |
| `behavioral_cti` | `BehavioralCtiBlock` \| **omitted** | **Not present in the payload when there is nothing to report — never sent as `null`.** Consumers must treat a missing key and an empty object identically: "no behavioral signal available." |
| `advisory_notice` | str \| None | free-text advisory framing, explicitly non-directive |
| `limitations` | list[str] | e.g. `"feed stale > 24h"`, `"partial coverage"` |
| `source_freshness` | str (ISO 8601) \| None | |
| `generated_at` | str (ISO 8601) | |

`IocMatch` (nested):

| field | type | notes |
|---|---|---|
| `indicator` | str | |
| `confidence` | float | 0.0–1.0 |
| `reason` | list[str] | |
| `source_freshness` | str (ISO 8601) \| None | |

**Explicitly excluded fields, by design:** no `directive`, no
`must_execute`, no `override`, no `required_action`. Any field that reads
as an instruction rather than information is out of scope for this schema
and must be rejected in review if proposed later.

### Failure-mode contract

This is a behavioral contract, not just a schema, and must be documented
alongside the schema wherever it is implemented:

- A CTI response that fails validation, times out, or is unreachable
  **must** be treated by the caller as "no advisory context available,"
  and must **not** raise an exception that halts the calling product's own
  decision path.
- `CtiContextResponse.behavioral_cti` being absent is a normal, expected
  state, not an error state.

## 3. API / auth contracts (`azazel_common.api`)

Not full endpoint specs — just the shared vocabulary:

| concept | shape |
|---|---|
| token header | `X-AZAZEL-TOKEN` (primary), `X-Auth-Token` (compat alias) |
| roles | `viewer`, `operator`, `responder`, `admin` (ordered, least→most privileged) |
| default posture | fail-closed: missing/invalid credentials → reject, never default-allow |
| error shape | `{"error": {"code": str, "message": str, "trace_id": str | None}}` |

## 4. Notification contract (`azazel_common.notify`)

| field | type | notes |
|---|---|---|
| `event_id` | str | |
| `product` | str | |
| `severity` | Literal[`"info"`, `"warning"`, `"critical"`] | |
| `title` | str | |
| `body` | str | |
| `trace_id` | str \| None | |
| `created_at` | str (ISO 8601) | |

Transport-specific adapters (ntfy, Mattermost, SSE) consume this shape;
they do not define their own competing payload shape.

## 5. Path contract (`azazel_common.paths`)

| concept | convention |
|---|---|
| runtime dir | `/run/azazel-<product>` (e.g. `/run/azazel-edge`) |
| config dir | `/etc/azazel-<product>` |
| log dir | `/var/log/azazel-<product>` |
| legacy compatibility | `azazel-pi` → maps to `azazel-edge` path schema; `azazel-zero` → maps to `azazel-gadget` path schema |
| migration | dry-run-first helper; never silently moves/deletes files |
