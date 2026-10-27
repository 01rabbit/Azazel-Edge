# M.I.O. SituationFrame contract (`mio.situation_frame.v2`)

Canonical architecture, authority matrix and degradation ladder: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

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
| Schema version | `SITUATION_FRAME_SCHEMA_VERSION = "mio.situation_frame.v2"` (serialized as `schema_version`) |
| Legacy versions read by `from_dict()` | `SITUATION_FRAME_LEGACY_SCHEMA_VERSIONS = ("mio.situation_frame.v1",)` |
| Builder (normalized inputs -> frame) | `azazel_edge.mio.frame_builder.MioSituationFrameBuilder` |
| Golden fixtures | `tests/fixtures/mio/situation_frame_canonical_v2.json` (current), `situation_frame_canonical_v1.json` (legacy read) |
| Acceptance tests | `tests/test_mio_situation_frame_contract.py`, `tests/test_mio_situation_frame_v2_contract.py` |

Per #361 the contract stays Edge-local; it is not moved to Fabric.
Any change to the serialized field set, caps, vocabularies, or semantics must bump
`schema_version` and regenerate the golden fixture in the same PR. The golden test
pins the key set, the canonical bytes, and their SHA-256, so an unversioned change fails CI.
`MioSituationFrame.from_dict()` rejects any `schema_version` other than the current one and
the legacy versions listed above.

## Versions

| Version | Change |
|---|---|
| `mio.situation_frame.v1` | Initial contract (#383): facts, unknowns, contradictions, refs, statuses, provenance, budgets. |
| `mio.situation_frame.v2` | Adds `actors`, `actions` and `deception_context` (the #362 fields). Every v1 field keeps its meaning and value. |

**Reading v1.** `from_dict()` accepts a v1 payload (exactly the v1 key set) and upgrades it
on read: all v1 fields are kept unchanged, `actors` and `actions` come back empty, and
`deception_context` is `null`. v1 never captured these fields, so an upgraded frame says
nothing about actors or actions; it does not claim there were none. A v1 payload with
`deception_status="available"` is rejected. This is acceptable because the v1 builder could
never produce it (it always downgraded `available` to `not_provided`, having no deception
content to show), so no genuine v1 frame is lost.
`to_dict()` always writes the current version. The same normalized v1 builder inputs give
the same values for every v1 field under v2 (`test_v1_builder_inputs_give_unchanged_v1_fields`).

## Provenance

`provenance` maps each material fact group to the deterministic inputs that produced it.
Both vocabularies are closed; anything else raises `ValueError`.

- groups: `known_facts`, `unknowns`, `contradictions`, `evidence_refs`, `knowledge_refs`, `freshness_seconds`, `actors`, `actions`, `deception_context`
- sources: `caller`, `deception`, `decision_audit`, `evidence_plane`, `frame_builder`, `knowledge`, `noc_evaluation`, `soc_evaluation`

The builder sets `actors` = `evidence_plane`, `frame_builder`; `actions` = `decision_audit`;
`deception_context` = `deception`.

A model is never a provenance source. Individual claims stay addressable through
`evidence_refs` / `knowledge_refs`; detail is fetched by ID through the read-only broker.

## Canonical serialization

`to_canonical_json()` = `json.dumps(to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)`
encoded as ASCII. `canonical_digest()` is its SHA-256. Same normalized snapshot -> identical bytes.
`from_dict(to_dict())` round-trips to an equal frame (caps are re-applied, truncation is preserved).
`from_dict()` is closed: the key set must match exactly, every field must have its declared
type (no stringifying dicts, no silently emptying a non-list), statuses must come from the
vocabulary, and `knowledge_status="available"` must come with non-empty `knowledge_refs`
whose provenance includes `knowledge` (and refs are only allowed when available).
Likewise `deception_status="available"` must come with a `deception_context` whose provenance
includes `deception`, and a context is only allowed when available. Each v2 nested record must
already be in normalized form (same keys, exact JSON types, in-vocabulary values, within caps);
`from_dict()` rejects it rather than repairing it. At most one action may be `current`.

Event order never changes the frame: freshness uses the newest timestamp of all events, and the
event IDs referenced are chosen by severity (desc), then recency (desc), then `event_id`, with
duplicates collapsed. NOC/SOC `evidence_ids` keep the evaluator's order, which is deterministic.

## v2 fields

All three fields are facts for M.I.O. to reason over. None of them is an input to the Rust
core, the Action Arbiter, enforcement, approval or AZ-06 control, and none carries an
approval flag.

**Scope of the no-address / no-free-text rule.** Inside `actors`, `actions` and
`deception_context`, no string is free text and none can hold an address: every one is a
frame-local actor key, an opaque ID, a closed-vocabulary value or a canonical UTC timestamp
(`YYYY-MM-DDTHH:MM:SSZ`). The rule covers only these three fields. The v1 fields keep their v1
rules unchanged: `mission`, the summaries, facts, unknowns and contradictions are bounded
text, and `evidence_refs` / `knowledge_refs` are bounded IDs as the evaluators and the caller
supply them, without the address check below.

**Opaque IDs** (`decision_ref`, nested `evidence_refs`, deception IDs and refs) must match
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` and must not contain an address-shaped run anywhere: a
dotted, dashed or underscored quad (`10.0.0.5`, `10.0.0.5:22`, `ev-10-0-0-5`), a MAC-like run
(`aa:bb:cc:dd:ee:ff`, `aa-bb-…`, `aabb.ccdd.eeff`), or an IPv6-like run: a hex-and-colon run with
five or more groups, or one that parses as an IPv6 address (`fe80::1`, `2001:db8::1`, `::1`).
Shorter colon runs such as `ev:12:34:56` are ordinary ID segments and pass. A value with an
address-shaped run is not an ID and is treated as absent or malformed.

Known limit: an address written as a bare number or bare hex (`167772165`, `0a000005`) cannot be
told apart from a legitimate numeric or hex ID (`2026`, `deadbeef`) and is accepted. The check
stops the address notations producers actually emit; it is not a guarantee that no address can
be encoded. The producers of these IDs are Edge and AZ-06 code, not attackers.

### `actors` (actor/entity summary, max 8)

Built by the frame builder from the event window. An actor is the source endpoint of an event
whose `subject` has the form `<src>-><dst>...` (Suricata EVE and flow adapters). Other subjects
(syslog `host:tag`, NOC probes, inventory) do not name an actor.

| Field | Meaning |
|---|---|
| `actor_key` | Frame-local position: `actor:0001` is the first actor of this frame, `actor:0002` the second, and so on. |
| `first_seen` / `last_seen` | Oldest / newest event timestamp (future-dated events beyond the clock-skew tolerance do not count). `""` when unknown. |
| `event_count`, `max_severity` | Exact count (clamped to 1,000,000) and highest severity (0-100). |
| `protocols` (4) | Most frequent first, ties by value. Closed vocabulary `tcp`, `udp`, `icmp`, `icmpv6`, `sctp`, `gre`, `esp`, `ah`, `igmp`, `other` (`ipv6-icmp`/`icmp6` count as `icmpv6`; anything else as `other`). |
| `target_ports` (8) | Most frequent first, ties by port. |
| `distinct_target_ports` | Exact number of distinct target ports, so the capped `target_ports` list shows its own truncation. |
| `event_kinds` (4) | Most frequent first. Closed vocabulary `alert`, `anomaly`, `drop`, `flow`, `flow_summary`, `netflow`, `dns`, `http`, `tls`, `ssh`, `smtp`, `ftp`, `smb`, `dhcp`, `fileinfo`, `other`. |
| `evidence_refs` (4) | Event IDs by severity, recency, ID. Detail is fetched by ID through the read-only broker. |

Actors are ranked by severity, event count, recency, first_seen, then the smallest event ID, then
their port/protocol/kind counts; the source value never takes part. The key is the position in
that ranking. More than 8 actors sets `truncated`.

**Data minimisation.** The source value only groups events inside one build. It is not copied,
hashed or otherwise used to make the key, so the key cannot be inverted to an address: two
windows with the same event pattern and different addresses give byte-identical frames
(`test_actor_keys_do_not_depend_on_the_source_value`). The destination, user names, messages
and other `attrs` never enter the frame. The cost is that a key means nothing outside its
frame: `actor:0001` in two frames need not be the same source, even for the same trace, so the
key **cannot be used to track an actor across frames or cycles** (including by the live wiring
in #385). Following one actor across frames is done through its `evidence_refs`, resolved by
the read-only broker under its own access rules. `MioSituationFrame.build()` renumbers supplied actors by position, and `from_dict()`
rejects keys that are not their position. A caller-supplied summary that does not validate is
dropped and `ACTOR_SUMMARY_MALFORMED` is added to `unknowns`.

### `actions` (current and previous actions, max 4)

Passed by the caller as `action_history`: normalized records from Edge's own decision audit
(the actions the Rust core already selected and, if allowed, applied). M.I.O. records them; it
does not select, approve, change or release an action. **No producer exists yet:** the code that
turns Edge's decision records into `action_history` and passes it in a running service is #385.
Today only tests and fixtures supply it.

| Field | Meaning |
|---|---|
| `role` | `current` or `previous`. At most one `current`. |
| `action` | One of the Defensive States `OBSERVE`, `NOTIFY`, `THROTTLE`, `REDIRECT`, `ISOLATE`. |
| `decision_ref` | Opaque ID of Edge's decision record. |
| `applied_state` | `applied`, `not_applied`, `apply_failed`, `none` (see the mapping below). |
| `mode` | `disabled`, `dry_run`, `policy_gated`, `release_guard_failed`, `enforced`, `none`. |
| `release_condition` | `lease_expiry` or `none`. |
| `decided_at`, `expires_at` | Canonical UTC timestamps or `""`. `expires_at` only with `lease_expiry`. |
| `evidence_refs` (4) | Opaque IDs. |

The vocabularies are exactly what Edge records, so the producer maps nothing Edge does not have:

| Frame field | Source in Edge | Values |
|---|---|---|
| `applied_state` | `azazel_edge.explanations.live.applied_state(enforcement)` (`applied_state` in the v2 explanation) | `applied`: result `applied`/`partial_failure` with a command executed. `not_applied`: `planned_not_applied` (dry run, policy gated, release guard failed). `apply_failed`: the core tried and executed nothing, or the result is missing or unknown. `none`: `no_disruptive_action` (observe, notify). |
| `mode` | The Rust core's `enforcement.mode` (`maybe_enforce` in `main.rs`); `none` when the record has none (`control_mode` in live.py) | `disabled`, `dry_run`, `policy_gated`, `release_guard_failed`, `enforced`, `none` |
| `release_condition`, `expires_at` | live.py `_release_condition`: an applied action whose `release_ledger_state` is `active` or `uncertain` | `lease_expiry` with `release_due_epoch` as `expires_at`; otherwise `none` and `""` |

`apply_failed` is a value Edge reports (an attempt that executed nothing, or an unknown result);
it is not a stand-in for an unknown record. There is no `unknown` value: a record with an
out-of-vocabulary `applied_state`, `mode` or `release_condition`, `lease_expiry` on an action that
was not applied, `expires_at` without `lease_expiry`, a malformed timestamp, or an unknown action,
role or `decision_ref` is dropped with `ACTION_RECORD_MALFORMED` in `unknowns`. Extra keys are
ignored. Order: the current action first, then newest first (undated last), then `decision_ref`.
Several `current` records keep the newest and add `MULTIPLE_CURRENT_ACTIONS` to `contradictions`
(the others are dropped, not demoted). A current action that differs from
`current_defensive_state` adds `CURRENT_ACTION_STATE_MISMATCH`; the frame keeps Edge's state and
does not reconcile them. These contradiction markers come before builder and caller contradictions.

### `deception_context` (optional AZ-06 facts, or `null`)

| Field | Meaning |
|---|---|
| `environment_id` | Required opaque ID. Without it the projection is malformed. |
| `package_id`, `node_id` | Opaque IDs or `""`. |
| `lifecycle_state` | `inactive`, `provisioning`, `active`, `terminating`, `terminated`, `unknown` (adds `DECEPTION_LIFECYCLE_UNKNOWN`). |
| `observation_refs` (8) | Opaque IDs of AZ-06 observations. |

Facts only: no belief, intent, attribution or effectiveness score, and AZ-06 state is never
Edge authority. A valid context makes `deception_status="available"`, which lets
`select_playbook` consider `deception-observation-v1` (a shadow choice of reasoning method, not
an action). Like `action_history`, no running service supplies it yet (#385).

### Material identity (lifecycle)

`material_frame_digest` (`lifecycle.py`) decides whether a newer frame for the same trace is a
new situation; a material change supersedes the in-flight cycle. An actor's `event_count`,
`first_seen`, `last_seen`, `distinct_target_ports` and `evidence_refs` are **not material**
(`NON_MATERIAL_ACTOR_FIELDS`): they move with every new event of an ongoing incident, and if
they were material, sustained traffic could supersede every cycle before it finished. The
actor's position, `max_severity`, `protocols`, `target_ports` and `event_kinds` stay material,
so a new actor, a higher severity or a new kind of behaviour is a new situation. `actions` and
`deception_context` are material in full (they change only when Edge or AZ-06 changes state).
`frame_id`, `created_at`, `freshness_seconds` and `provenance` stay non-material as before.
**Limited effect.** The top-level `evidence_refs` are material since v1 and this change leaves
them so (making them non-material would change the v1 meaning of the digest). They are chosen by
severity, then recency, so under sustained traffic a new event of the top severity usually
enters them, and the frame becomes material again. Leaving the actor counters out therefore
removes one source of churn, not all of it: persistent traffic can still supersede the in-flight
cycle on every new frame. How to treat the top-level refs (for example, severity-only or a
coarser material view) is follow-up work, not part of #383.

## Input contract

`MioSituationFrameBuilder.build()` expects a **bounded, already-materialised event window**,
not an open-ended stream. Building is O(n) in the number of events (one pass; O(`max_event_refs`)
memory for the event refs, plus the actor table, which grows with the distinct sources, ports and
kinds in the window), so the caller owns the bound: when live wiring lands, the bound is the Evidence Plane
read limit/time window used to fetch the events. Current callers pass fixture lists only:
`azazel_edge.mio.evaluation` (offline evaluation corpus) and `bin/azazel-mio-shadow-replay`.
The builder makes no network or model calls and never reads events itself.

## Optional dependencies (Knowledge / AZ-06)

`knowledge_status` and `deception_status` are one of
`available`, `not_provided`, `unavailable`, `timeout`, `malformed` (unknown values become `malformed`).

- `not_provided`: dependency absent (e.g. no AZ-06). The frame builds; no unknown is added.
- `unavailable` / `timeout` / `malformed`: the frame still builds, `KNOWLEDGE_<STATUS>` or
  `DECEPTION_<STATUS>` is placed at the front of `unknowns`, and for Knowledge all
  `knowledge_refs` are dropped. Unavailable is never rendered as empty confidence or fabricated context.
- `available` with no refs is downgraded to `not_provided` by `build()` and rejected by `from_dict()`.
  For AZ-06 the same holds for `deception_context`: `available` needs a valid context (v2).
  A context that is supplied but does not validate makes the status `malformed`, and any
  degraded status drops the context.

Order of `unknowns`: dependency markers (then `DECEPTION_LIFECYCLE_UNKNOWN`,
`ACTOR_SUMMARY_MALFORMED`, `ACTION_RECORD_MALFORMED`), then builder markers (`NO_TIMESTAMPED_EVIDENCE`,
`EVIDENCE_STALE`, `EVIDENCE_TIMESTAMP_FUTURE`, `SOC_VISIBILITY=*`, `NOC_DEGRADED_MODE`), then caller
`explicit_unknowns`; builder contradictions likewise come before caller contradictions. Caller
input therefore cannot crowd safety markers out of the caps.

AZ-06 state is never Edge authority.

## Budgets

| Budget | v1 value | Enforcement |
|---|---|---|
| Serialized frame ceiling | **16384 bytes** of canonical JSON | `_enforce_byte_budget()` trims deterministically, sets `truncated=true` |
| `known_facts` / `unknowns` / `contradictions` | 16 / 12 / 8 items, 160 chars each | `SITUATION_FRAME_CAPS` |
| `evidence_refs` / `knowledge_refs` | 32 / 16 items, 128 chars each | `SITUATION_FRAME_CAPS` |
| `actors` / `actions` | 8 / 4 records | `SITUATION_FRAME_CAPS` |
| Per actor: protocols / target ports / event kinds / refs | 4 / 8 / 4 / 4 | `SITUATION_FRAME_ACTOR_CAPS` |
| Per action refs; deception observation refs | 4; 8 | `SITUATION_FRAME_ACTION_EVIDENCE_REFS_CAP`, `SITUATION_FRAME_DECEPTION_OBSERVATION_REFS_CAP` |
| Event refs taken from Evidence Plane | 32 (configurable 1-64) | `max_event_refs`, chosen by severity/recency/id |
| Event pass | one O(n) pass, O(`max_event_refs`) memory | input volume affects build time linearly, never frame size |
| Text fields | mission 240, NOC/SOC summary 480, ids 96 chars | `MioSituationFrame.build` |
| Build latency target (Pi-class) | <= 250 ms for the worst-case fixture | target only, see below |

Trim order when over the byte ceiling: `evidence_refs`, `knowledge_refs` (down to one ref, so
`available` stays consistent), `actors`, `actions` (down to the first, the current one),
`deception_context.observation_refs` (the context itself stays), `known_facts`, `contradictions`,
`unknowns` (each from the tail),
then halve the longest of the NOC/SOC summaries and mission. `known_facts` are emitted most-important
first (NOC/SOC status, SOC suspicion/confidence/blast, then NOC/SOC reason codes interleaved), so
the tail trim drops reason codes first. Never trimmed: `schema_version`, `frame_id`, `trace_id`,
`created_at`, `current_defensive_state`, `threat_level`, both statuses, `provenance`,
`freshness_seconds`, `truncated`. With the v2 fields, content at every cap can exceed the
ceiling even in ASCII, and astral/control characters (escaped up to 12 bytes each) always can;
trimming is deterministic and sets `truncated`.

Every list is capped and the event pass keeps only `max_event_refs` candidates, so raising input
traffic never grows the frame (`test_input_traffic_volume_does_not_grow_frame`). Build time is
linear in the number of events handed over; the Evidence Plane query window bounds that input.
A pass cap was rejected because it made freshness depend on event order (a newest event past the cap was missed).

When the untrusted prompt budget forces the minimal view (`PromptCompiler`), it still includes
`unknowns`, `contradictions`, `truncated`, `knowledge_status`, `deception_status`, and `schema_version`.

### Worst-case fixtures and how latency is tested

`tests/test_mio_situation_frame_contract.py` generates synthetic worst-case inputs:
up to 50,000 events, 200 evidence/knowledge refs per source, 64 reasons, 600-char strings,
in ASCII, BMP, astral (emoji), and control-character variants. `tests/test_mio_situation_frame_v2_contract.py`
adds an actor-heavy worst case: up to 50,000 events from 50,000 distinct sources with 600-char
subjects, 65 action records with oversized refs, and a deception context with 50 observation refs.
Tests assert the byte ceiling and caps.

Latency is **measure-and-record**: the best of 3 worst-case builds is written as the JUnit test-suite
property `situation_frame_worst_case_build_ms` (and `situation_frame_v2_actor_worst_case_build_ms`
for the actor-heavy case), and the only assertion is a generous 2 s
regression guard so CI is not flaky. Container or laptop timings are **not Raspberry Pi evidence**.
The 250 ms Pi-class target remains to be confirmed on real hardware (HIL), e.g. with
`azazel_edge.mio.resource_profile.ResourceTimer`. For scale only: one macOS laptop run took about
70 ms for the 50,000-event worst case. Build time is linear in events, so a Pi may exceed the target
at that volume; if HIL confirms this, the fix belongs in the Evidence Plane query window, not in an order-dependent pass cap.

## Trace isolation

The builder keeps only immutable configuration; all per-build state is local and the
frame is a frozen dataclass of tuples. Tests build 256 frames for 64 traces concurrently
on one shared builder and check each frame is byte-identical to its sequential build and
contains no foreign evidence/knowledge refs, and that mutating inputs after build does not change the frame.
