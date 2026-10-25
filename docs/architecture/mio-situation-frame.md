# M.I.O. SituationFrame contract (`mio.situation_frame.v1`)

Status: implemented, advisory-only. Tracking: #383 (parents #362, #361).

`MioSituationFrame` is the compact, deterministic world-state that M.I.O. reasons over.
It is built before any model call, contains no raw log/attr text, and is
**advisory input only**: nothing in this contract feeds the Action Arbiter,
enforcement handlers, approval flags, or any environment bypass. Disabling or not
consuming the frame leaves deterministic Edge behavior unchanged.

## Ownership

| Item | Owner / location |
|---|---|
| Schema (fields, caps, vocabularies) | `azazel_edge.mio.contracts` (`py/azazel_edge/mio/contracts.py`) |
| Schema version | `SITUATION_FRAME_SCHEMA_VERSION = "mio.situation_frame.v1"` (serialized as `schema_version`) |
| Builder (normalized inputs -> frame) | `azazel_edge.mio.frame_builder.MioSituationFrameBuilder` |
| Golden fixture | `tests/fixtures/mio/situation_frame_canonical_v1.json` |
| Acceptance tests | `tests/test_mio_situation_frame_contract.py` |

Per #361 the contract stays Edge-local; it is not moved to Fabric.
Any change to the serialized field set, caps, vocabularies, or semantics must bump
`schema_version` and regenerate the golden fixture in the same PR. The golden test
pins the key set, the canonical bytes, and their SHA-256, so an unversioned change fails CI.
`MioSituationFrame.from_dict()` rejects any other `schema_version`.

## Provenance

`provenance` maps each material fact group to the deterministic inputs that produced it.
Both vocabularies are closed; anything else raises `ValueError`.

- groups: `known_facts`, `unknowns`, `contradictions`, `evidence_refs`, `knowledge_refs`, `freshness_seconds`
- sources: `caller`, `evidence_plane`, `frame_builder`, `knowledge`, `noc_evaluation`, `soc_evaluation`

A model is never a provenance source. Individual claims stay addressable through
`evidence_refs` / `knowledge_refs`; detail is fetched by ID through the read-only broker.

## Canonical serialization

`to_canonical_json()` = `json.dumps(to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
encoded as ASCII. `canonical_digest()` is its SHA-256. Same normalized snapshot -> identical bytes.
`from_dict(to_dict())` round-trips to an equal frame (caps are re-applied, truncation is preserved).
List order follows input order; derived state (facts, unknowns, freshness, provenance)
does not depend on event order.

## Optional dependencies (Knowledge / AZ-06)

`knowledge_status` and `deception_status` are one of
`available`, `not_provided`, `unavailable`, `timeout`, `malformed` (unknown values become `malformed`).

- `not_provided`: dependency absent (e.g. no AZ-06). The frame builds; no unknown is added.
- `unavailable` / `timeout` / `malformed`: the frame still builds, `KNOWLEDGE_<STATUS>` or
  `DECEPTION_<STATUS>` is placed at the front of `unknowns`, and for Knowledge all
  `knowledge_refs` are dropped. Unavailable is never rendered as empty confidence or fabricated context.

The frame carries no deception context fields in v1; AZ-06 state is never Edge authority.

## Budgets

| Budget | v1 value | Enforcement |
|---|---|---|
| Serialized frame ceiling | **16384 bytes** of canonical JSON | `_enforce_byte_budget()` trims deterministically, sets `truncated=true` |
| `known_facts` / `unknowns` / `contradictions` | 16 / 12 / 8 items, 160 chars each | `SITUATION_FRAME_CAPS` |
| `evidence_refs` / `knowledge_refs` | 32 / 16 items, 128 chars each | `SITUATION_FRAME_CAPS` |
| Event refs taken from Evidence Plane | 32 (configurable 1-64) | `max_event_refs` |
| Events scanned per build | 1024 (configurable 1-4096) | `max_events_scanned`; overflow adds `EVENT_SCAN_TRUNCATED` |
| Text fields | mission 240, NOC/SOC summary 480, ids 96 chars | `MioSituationFrame.build` |
| Build latency target (Pi-class) | <= 250 ms for the worst-case fixture | target only, see below |

Trim order when over the byte ceiling: `evidence_refs`, `knowledge_refs`, `known_facts`,
`contradictions`, `unknowns` (from the tail), then halve the longest of the NOC/SOC summaries
and mission. Identity fields and status fields are never trimmed. ASCII content within the
item caps fits without trimming; astral/control characters (escaped up to 12 bytes each) trigger it.

Because the event scan and every list are capped, raising input traffic does not grow the
frame or the build cost without bound (`test_input_traffic_volume_does_not_grow_frame`).

### Worst-case fixtures and how latency is tested

`tests/test_mio_situation_frame_contract.py` generates synthetic worst-case inputs:
up to 50,000 events, 200 evidence/knowledge refs per source, 64 reasons, 600-char strings,
in ASCII, BMP, astral (emoji), and control-character variants. Tests assert the byte ceiling and caps.

Latency is **measure-and-record**: the best of 3 worst-case builds is written as the JUnit test-suite
property `situation_frame_worst_case_build_ms`, and the only assertion is a generous 2 s
regression guard so CI is not flaky. Container or laptop timings are **not Raspberry Pi evidence**.
The 250 ms Pi-class target remains to be confirmed on real hardware (HIL), e.g. with
`azazel_edge.mio.resource_profile.ResourceTimer`.

## Trace isolation

The builder keeps only immutable configuration; all per-build state is local and the
frame is a frozen dataclass of tuples. Tests build 256 frames for 64 traces concurrently
on one shared builder and check each frame is byte-identical to its sequential build and
contains no foreign evidence/knowledge refs, and that mutating inputs after build does not change the frame.
