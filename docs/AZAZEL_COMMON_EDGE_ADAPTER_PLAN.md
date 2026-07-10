# Azazel-Common Edge Adapter Plan

> **2026-07-10 naming update:** Azazel-Common was renamed **Azazel-Covenant**
> (AZ-05) on 2026-07-10. From `v0.3.0` the import namespace is
> `azazel_covenant`; the `v0.1.0`/`v0.2.0` tags referenced below keep the
> original `azazel_common` import name and `azazel-common` dist name. This
> plan's body below retains the names that were current when it was written
> (`Azazel-Common`/`azazel_common`); any future adapter code should target the
> new `azazel_covenant` namespace instead. The file itself is not renamed —
> it stays cross-referenced as `AZAZEL_COMMON_EDGE_ADAPTER_PLAN.md` from
> `docs/INDEX.md` and from the Covenant repo's docs.

Status: **Design note / proposal only.** No adapter code is written by this
document, and no existing Edge behavior is changed. This is the deliverable for
Issue 5 in `Azazel-Common/docs/issue-breakdown.md`, implementing the planning
step of `Azazel-Common/docs/migration-plan.md` Phase 3.

This note identifies the *exact* call sites in Edge that would serialize
through `azazel_common` schemas, states explicitly which code is **not**
touched, confirms zero behavior change to BHUSA-relevant demo paths, and
defines a per-adapter rollback point. Whether the adapters themselves are
implemented next is gated on review of this note.

**Scope boundary — CTI is deferred.** Edge has no CTI integration today, and
connecting Edge to Azazel-CTI is a **next-fiscal-year-onward (FY2027+) plan**,
not current work. Accordingly, only the schema-serialization adapters that
operate on data Edge *already* produces are near-term-applicable: the Decision
Explanation, Trust capsule, and Audit projections (§3). The CTI ingest client
and context-response consumer (§4) are documented here for completeness and to
capture the finding that they do not exist yet — but they are **out of scope
for the current cycle** and are not a near-term deliverable. This note can be
adopted for the §3 projections without waiting on any CTI work.

## 1. Prerequisite and dependency pinning

- Depends on `azazel-common` `v0.1.0` (schema-only) — already tagged and
  released on `01rabbit/Azazel-Common`.
- Edge has **no `pyproject.toml`/`setup.py`**; dependencies live in
  `requirements/runtime.txt`. The pin would be added there, tag-pinned per
  `Azazel-Common/docs/design-principles.md` §6:

  ```
  azazel-common @ git+https://github.com/01rabbit/Azazel-Common.git@v0.1.0
  ```

  Adding the pin is itself a standalone, revertible commit and introduces no
  runtime behavior (import only when an adapter is wired in).

## 2. Boundary map — what is a serialization site, what is decision logic

Per `docs/architecture/decision-loop.md`, the deterministic pipeline is:
event input → Evidence Plane normalization → NOC/SOC evaluators → policy
thresholds → Action Arbiter → **Decision Explanation** → notify/AI assist →
**Audit logging**.

Only the two **bold** stages are serialization boundaries for the current
cycle. (An outbound CTI exchange would be a third boundary, but it does not
exist yet and is deferred to FY2027+ — see §4.) Everything upstream of the
Decision Explanation is decision logic and is out of scope (§5). The arbiter
still decides; Common only standardizes how that decision is written down and
transmitted.

## 3. Adapter sites (existing code that would wrap Common schemas)

Each row is an independent, emit-alongside adapter: it adds a Common-shaped
serialization *next to* the existing write, and does not replace or alter the
existing output until contract tests prove parity (Issue 4). Each is its own
commit and its own rollback point.

### 3.1 Decision Explanation → `azazel_common.schema.DecisionExplanation`

- **Site:** `py/azazel_edge/explanations/decision.py`
  - explanation dict assembled at `decision.py:159-179` (`format_version: 'v2'`)
  - serialization at `decision.py:185-190` — `write_jsonl()`:
    `validate_v2_explanation(...)` then `json.dumps(...)` appended to
    `decision-explanations.jsonl`.
- **Field contract (consumer):** `py/azazel_edge/explanations/schema.py`
  `validate_v2_explanation()` (`schema.py:33`), required fields `_REQUIRED`
  (`schema.py:13-30`).
- **Producing call site (real pipeline):** `py/azazel_edge/scenario_replay.py:479-487`
  (explainer constructed `:465`, `persist=True`).
- **Mapping — LOSSY PROJECTION, not a replacement.** Edge's v2 record is
  richer than `DecisionExplanation` and several field *types* differ:

  | `azazel_common.DecisionExplanation` | Edge v2 (`decision.py`) | Note |
  |---|---|---|
  | `selected_action: ActionIntent` | `selected_action: str` (action name) | Edge stores the action name; the Common `ActionIntent` object (kind/target/issued_by/evidence/trace_id) must be *assembled* from `machine.arbiter` + `evidence_ids`. |
  | `why_chosen: str` | `why_chosen: dict` (`decision.py:78-122`) | Type mismatch — Edge's `why_chosen` is a structured block. Projection would map Edge's `operator_wording`/`reason` into the Common string field, keeping the rich dict Edge-side. |
  | `why_not_others: list[str]` | `why_not_others: list[{action, reason}]` (`decision.py:123-130`) | Flatten to strings for Common; keep structured form Edge-side. |
  | `release_condition: str \| None` | `release_condition` | Direct. |
  | `confidence: float \| None` | (in `trust_capsule.confidence`) | Sourced from the trust capsule, not the top-level dict. |
  | `trace_id: str` | `trace_id` (`decision.py:161`) | Direct. |

  **Decision for review:** the Common `DecisionExplanation` is used as the
  *interop/transport projection* at the boundary (what a sibling product or
  CTI would receive), **not** as a replacement for Edge's internal v2 record.
  Edge keeps writing its richer `decision-explanations.jsonl` unchanged; the
  adapter emits an additional Common-shaped projection.
- **`ActionIntent.kind` compatibility:** Edge's arbiter action set
  (`observe/notify/throttle/redirect/isolate`, see `arbiter/action.py:17-53`)
  is a **subset** of `azazel_common`'s `ActionKind`
  (`observe/notify/throttle/redirect/isolate/decoy/release`). Clean mapping,
  no new values needed on the Edge side.
- **Rollback point:** revert the single commit adding the projection emit in
  `write_jsonl` (or a sibling method); the original JSONL write is untouched.

### 3.2 Trust capsule → `azazel_common.schema.TrustCapsule`

- **Site:** `py/azazel_edge/explanations/trust_capsule.py`
  `build_trust_capsule()` (`:47-77`), injected at `decision.py:180`.
- **Mapping — LOSSY.** Edge's capsule
  (`trace_id, timestamp, action, confidence, evidence_ids, why_chosen,
  why_not_others, operator_wording, ai_contributed, ai_advice_hash, hmac_sig`)
  is richer than Common's (`trace_id, config_hash, hmac, issued_at`). Field
  name differences to reconcile in Issue 3: `hmac_sig`→`hmac`,
  `timestamp`→`issued_at`; **`config_hash` is absent from Edge's capsule** (it
  lives on the explanation at `decision.py:168`). Common's `TrustCapsule` is a
  minimal integrity capsule; Edge's carries decision context too.
- **Rollback point:** projection emit is additive; revert the one commit.

### 3.3 Audit Logger → `azazel_common.schema.AuditEvent`

- **Site:** `py/azazel_edge/audit/logger.py` `P0AuditLogger.log()`
  (`:72-88`); typed helpers `:90-121`; export `audit/__init__.py:1`.
- **Record shape:** `{ts, kind, trace_id, source, chain_prev, **payload,
  chain_hash}`.
- **Mapping — STRUCTURAL GAP to flag for Issue 3:**
  - Edge audit records have **no `event_id`** (identity is `kind` + position in
    the hash chain). `AuditEvent.event_id` is required — the adapter would need
    to synthesize one (e.g. `chain_hash`, or `trace_id:kind:seq`).
  - Edge audit has **no `config_hash` and no `hmac`** on the base record; it
    uses a **hash chain** (`chain_prev`/`chain_hash`, SHA-256 over canonical
    JSON, `logger.py:48-51`, verified by `verify_chain` `:53-70`).
    `AuditEvent`'s optional `config_hash`/`hmac` do **not** model a chain.
  - Edge's `kind` (constrained set `VALID_KINDS` `:11-23`) maps to
    `AuditEvent.event_type`; `source` and the `**payload` merge into
    `AuditEvent.payload`; `chain_prev`/`chain_hash` would ride in
    `AuditEvent.payload` until/unless Common grows a chain-of-custody field
    (noted as a future extension in `Azazel-Common/docs/repository-layout.md`
    `audit/chain.py`, Phase 5).
- **Producing call sites (many):** e.g. `azazel_edge_ai/agent.py:194-202`,
  `scenario_replay.py:466`, `notify/delivery.py:260`, `triage/engine.py:30-40`.
  The adapter wraps the single `log()` writer, so all callers are covered by
  one change point.
- **Rollback point:** the emit-alongside lives in `log()`; revert one commit
  and the hash-chained JSONL is exactly as before (chain integrity must not be
  perturbed — the Common projection is written to a *separate* stream, never
  interleaved into the chained file).

### 3.4 Second decision stream (Decision Logger) — defer, do not double-adapt

- **Site:** `py/azazel_edge/tactics_engine/decision_logger.py` `DecisionRecord`
  (`:50-89`), `to_json()` (`:69-89`), writer `log_decision()` (`:117-136`),
  path `<dir>/decision_explanations.jsonl` (`:107`); produced at
  `azazel_edge_ai/agent.py:1113,1133`.
- This is a **separate** decision-explanation stream with a different schema
  and path from §3.1, already flagged as a duality in
  `refactor-instructions.md:276` (item B1). Only the §3.1 v2 stream is
  validated and read by `audit_review.py`.
- **Recommendation:** adapt **only** the §3.1 v2 stream to
  `DecisionExplanation`. Do not build a second, competing Common projection
  here; resolving the duality is a pre-existing Edge concern (B1), not part of
  this adapter work. Revisit once B1 is resolved.

## 4. CTI client — DEFERRED to FY2027+ (no existing call site, and not built now)

**Load-bearing finding:** Edge currently has **no CTI HTTP client**. There is
no code that POSTs to `/v1/events`, `/v1/flows`, `/v1/reactions`, or
`/v1/context`, and no code that parses a CTI context response
(`matches`/`behavioral_cti`/`advisory_notice`/`limitations`). Verified by
repo-wide search (no matches for those endpoints or fields).

**This is not a gap to close in the current cycle.** Connecting Edge to
Azazel-CTI (now Azazel-Grimoire) is a next-fiscal-year-onward (FY2027+) plan. The material below
scopes that future work so it is not re-derived later; it is **not** a
near-term deliverable, and nothing in §3 depends on it. When the CTI
integration cycle eventually starts:

- The CTI request-builders (`CtiEventBatch`/`CtiFlowBatch`/`CtiReactionBatch`/
  `CtiContextRequest`) and the `CtiContextResponse` parser are **new code**,
  not adaptations of existing sites. They should be introduced *as* Common
  consumers from their first commit, rather than retrofitted.
- **Nearest existing precedent / template:**
  - `py/azazel_edge/integrations/upstream.py` — `UpstreamEnvelopeBuilder.build()`
    (`:11-45`) already builds a `v1` envelope
    (`ts/trace_id/noc/soc/decision/explanation`) and `WebhookSink.publish()`
    (`:59-77`) POSTs it via stdlib `urllib`. This is the natural shape to grow
    a `CtiReactionBatch`/`CtiEventBatch` builder from.
  - `py/azazel_edge/integrations/taxii_push.py` — `TAXIIPushClient.push_bundle()`
    (`:33-78`) is the existing "push threat data upstream" path (STIX 2.1 /
    TAXII); a CTI ingest client sits beside it, not replacing it.
  - `py/azazel_edge/ti/lookup.py` — `ThreatIntelFeed.match()` (`:35-64`) is the
    only current source of `matches`, and it is a **local, offline** feed
    lookup (no HTTP). A `CtiContextResponse.matches` consumer would be a new
    online path alongside this offline one, not a replacement.
- **Advisory-only fail-closed reminder (contract, not just schema):** per
  `Azazel-Common/docs/contracts.md` §2, if/when the CTI client is eventually
  written, a response that fails validation, times out, or is unreachable
  **must** be treated as "no advisory context available" and must **not** raise
  into Edge's decision path. `behavioral_cti` absent is normal, not an error.
  The deterministic path in `decision-loop.md` stays authoritative.
- **HTTP note:** existing outbound code uses stdlib `urllib` (upstream/taxii/
  aggregator) even though `requests` is declared in `runtime.txt`. The CTI
  client should match the surrounding `urllib` style unless a deliberate
  decision is made otherwise.

## 5. Explicitly NOT touched (decision logic — out of scope)

This adapter work changes **no** decision logic. The following are confirmed
untouched, with their role:

| Component | Path | Role — why out of scope |
|---|---|---|
| Action Arbiter | `py/azazel_edge/arbiter/action.py` (`ActionArbiter` `:14`, `ACTION_PROFILES` `:17-53`) | Selects the one bounded action from NOC+SOC. Final decision authority stays singular and local (`Azazel-Common/docs/design-principles.md` §4.1). |
| NOC Evaluator | `py/azazel_edge/evaluators/noc.py` | Deterministic network/ops health scoring. Edge-specific judgment. |
| SOC Evaluator | `py/azazel_edge/evaluators/soc.py` | Security evaluation (correlation, ATT&CK, Sigma/YARA, TI matching). Edge-specific detection logic. |
| Evidence Plane | `py/azazel_edge/evidence_plane/` | Ingests/normalizes raw sensor evidence into `EvidenceEvent`s upstream of the evaluators. Input plane, not an output-serialization boundary. |

The adapter reads the *outputs* of these components (the `machine.arbiter`,
`noc_summary`, `soc_summary`, `evidence_ids` already present in the explanation
dict) to build Common schemas; it never calls into or modifies them.

## 6. Zero-behavior-change guarantee for BHUSA demo paths

- Every adapter in §3 is **emit-alongside**: it adds a Common-shaped
  serialization to a *separate* stream and leaves the existing JSONL writes
  (`decision-explanations.jsonl`, the hash-chained audit log) byte-for-byte
  unchanged until contract tests (Issue 4) prove parity.
- The BHUSA-relevant producing paths — `scenario_replay.py:479-487` (decision
  explanation) and `azazel_edge_ai/agent.py:194-202`/`:1113`/`:1133` (audit +
  decision logger) — continue to run exactly as today; the adapter only reads
  the dict they already produce.
- The audit **hash chain must not be perturbed**: the Common projection is
  never interleaved into the chained file, so `verify_chain()` (`logger.py:53-70`)
  keeps passing.
- The deterministic decision path stays authoritative (`decision-loop.md`
  Safety Constraints); no CTI/AI/Common output can gate or delay it.
- Verification before any adapter merge: run the project's `/verify` and
  `/run` checks against the demo flows, plus `pytest` (the existing
  `tests/test_decision_explanation_*`, `test_audit_review_v1.py`,
  `test_ti_lookup_v1.py` suites must stay green unmodified).

## 7. Rollback posture

Each adapter is a single, self-contained commit that only *adds* an
emit-alongside projection. Rollback = revert that one commit; nothing in
Edge's decision, audit-chain, or demo behavior depends on the projection.
Rollback points, in dependency order:

1. Add `azazel-common` pin to `requirements/runtime.txt` (import-only).
2. Decision Explanation projection in `explanations/decision.py`.
3. Trust capsule projection in `explanations/trust_capsule.py`.
4. Audit projection in `audit/logger.py` (separate stream).

Item 5 below is **not part of the current cycle** — deferred to FY2027+:

5. (Deferred) CTI ingest client + context-response parser (new module under
   `integrations/`), introduced as a Common consumer from the first commit,
   only when the CTI integration cycle begins.

## 8. Open questions for review (feed Issue 3)

1. Confirm `DecisionExplanation` stays an interop *projection*, not a
   replacement for Edge's richer v2 record — so the `why_chosen` (dict→str) and
   `selected_action` (dict→`ActionIntent`) narrowing is acceptable at the
   boundary.
2. Decide how the audit hash-chain (`chain_prev`/`chain_hash`) is represented
   through `AuditEvent` — carry in `payload` for v0.1.0, or promote to a
   dedicated chain-of-custody field in a later Common release
   (`audit/chain.py`, Phase 5).
3. Reconcile `TrustCapsule` field names (`hmac_sig`↔`hmac`,
   `timestamp`↔`issued_at`) and the absent `config_hash` — Common change vs.
   Edge-side mapping.
4. Since no CTI client exists **and CTI integration is deferred to FY2027+**,
   validating the CTI request/response schemas against the real Azazel-CTI API
   is entirely Issue 3's job on the Common side (there is nothing to retrofit in
   Edge now). No Edge CTI work is scheduled for the current cycle; §3 adoption
   proceeds independently of it.
