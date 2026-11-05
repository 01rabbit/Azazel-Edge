# Live M.I.O. auxiliary path

Status: Draft PR #538 candidate. Its shared M.I.O. dependency is pinned to immutable MIO PR #47 head `ffac07cc9bf06d6904faa98001cfcfaea788bcf7`, package version `0.1.0.dev20261105+gitf5b0014`. This is a development candidate, not a release. The source tree is `f5b00149…`; metadata commit `ffac07c…` applies the unique PEP 440 development identity. The exact wheel hash/build inputs are recorded in the PR evidence. This document does not claim release or deployment.

Canonical M.I.O. authority and data-flow architecture: [M.I.O. Cognitive Plane](mio-cognitive-plane.md).

The agent's ordinary event consumer submits a bounded copy of each already
accepted Rust-core event to `azazel_edge_ai.mio_live_auxiliary.LiveMioAuxiliary`
after Edge's tactical scorer and decision record have completed. One daemon
worker calls the product-neutral `azazel_mio.assistant.AssistantCore` API when
that package is importable. The worker has a one-item latest-only queue and
rejects work older than ten seconds before starting it. It uses the shared core
without a model, so the call performs bounded deterministic framing and
no-model assistance only. Missing package, stale work, queue pressure, malformed
output, cancellation, and exceptions produce explicit degraded/unavailable
records and never delay or alter the Edge action, lease, or undo path.

The Edge tactical scorer remains the owner of the risk score, risk-level label,
and factors. The input frame carries Edge's already-computed risk-level label
unchanged and labels its score/factors as derived context; M.I.O. does not
re-score the event or supply a competing classification. This adapter makes no
Azazel-Fabric mapping claim. The frame labels normalized event observations
separately from the `edge_tactical_scorer_v1` derived risk score. Its input
`knowledge_status` remains `not_provided`; no Knowledge data or references are
synthesized. The shared core is called with `knowledge_attempted=False`, so its
typed result reports Knowledge outcome `not_queried`. Results carry source, generation,
trace, provenance, typed Knowledge status, and `read_only_advisory` authority.
They are not used for action selection, enforcement, or arbitration.

The same event advisory may carry the scorer's optional M.I.O. fast-assessment
shadow result as `edge_score_comparison`; its `matches` flag compares both the
numeric score and factor list. It is copied into the live panel only
when the scorer submission's generation and trace match the current auxiliary
result. The panel labels it comparison-only and suppresses it with stale or
uncorrelated M.I.O. results. Edge's score, factors, risk label, recommendation,
and action remain sourced only from `TacticalScorer`; the shadow score is not
consumed by a decision or enforcement path.

Completed async results are written into the agent snapshot and admitted by
the control daemon's typed snapshot overlay to the dashboard bundle. The
dashboard's M.I.O. live auxiliary panel displays status, Knowledge provenance,
hypotheses, next checks, and handoff separately from Edge's observed action and
result. It uses text-only DOM writes. Results from superseded generations are
marked stale. Edge metadata is copied only from bounded enums and a restricted
trace token; malformed supplied values are omitted with a fixed
`unknown_fields` marker. Safe Edge projection treats a valid `selected_action` as a recognized omitted field and never exports it; malformed values set `unknown_fields`. The full persisted M.I.O. envelope is capped at 16
KiB. No lease expiry, applied state, or release state is inferred.

The bounded source-context projection records event type, signature, category,
protocol, SID, severity, target port, rule-declared ATT&CK technique IDs, and
normalized event time when each value passes its field-specific type and size
checks. Each field has `observed` or `unavailable` status and names
`rust_core_normalized_event` provenance; addresses, payloads, and unlisted
fields are excluded. Missing fields are also identified in the frame's
`unknowns` list with `SOURCE_FIELD_UNAVAILABLE:<field>` entries.

Each completed result carries a `handoff_binding` that joins its generation and
safe event key to the Edge trace, action, mode, and result, plus the M.I.O.
trace and frame IDs. The server validates those values against the same
result envelope. The dashboard suppresses the handoff if a value is absent or
mismatched, while the dashboard response retains the binding for consumers
that export the available snapshot data.

Freshness limitation: the server reports `age_seconds`, `completed_at` and
`is_current` at the moment it serves a snapshot. The dashboard script
(`sentinel.js`) recomputes the age from `completed_at` on each render, so the
browser's view stays current as time passes. Exported snapshot and API
consumers do not get that recomputation: they must compare `completed_at`
with their own clock against `max_age_seconds` and must not treat a stored
`is_current: true` as still fresh.

The runtime dependency is declared in `requirements/runtime.txt` using an
immutable Git commit pin. The pinned source `ffac07cc9bf06d6904faa98001cfcfaea788bcf7`
is publicly available; this branch does not vendor the package. If the
package is absent at runtime, the guarded adapter reports `package_unavailable`
and Edge continues its existing behavior. The fast adapter itself supplies no
model transport or Knowledge adapter.

The product AI agent also has a separately paced M.I.O. model lane, disabled by
default and enabled only with `AZAZEL_MIO_MODEL_ENABLED=1`. It consumes the
matching current fast result asynchronously and reuses the Edge agent's existing
pinned loopback Ollama transport. This lane requires a numeric loopback endpoint
so hostname resolution cannot escape its deadline; the legacy analyst keeps its
existing hostname-compatible behavior. Its latest-only queue and end-to-end
deadline are capped at ten seconds; one request has an eight-second maximum and
no retry, with the existing 1 MiB response ceiling. Connect, upload, status/header
parsing, and body reads share an absolute deadline, including a hard-close timer
for slow-drip response headers. Events already routed to the legacy
analyst are skipped to prevent duplicate Ollama requests. Model failures degrade
to an explicit model-free result and stale generations are dropped. The display
separates static fast assessment and Knowledge status from measured model
analysis, and all generated text is rendered using text-only DOM writes.

The model lane keeps only bounded parsed summary/uncertainty fields for the live
snapshot. A 64-record in-memory diagnostics ring carries generation, trace,
model identity, duration, load duration, prompt/completion token counts, outcome,
and status; prompts, full completion bodies, request bodies, and raw exception
text are not logged.

At this candidate, Edge wraps the existing product-owned `StructuredTransport`
with MIO #45 `MeasuredTransport`, allowing only the four reasoning task labels
(`generate_hypotheses`, `identify_evidence_gaps`, `update_hypotheses`,
`recommend`). Each bounded lane result and diagnostic may carry at most four
task timings with elapsed nanoseconds and success/failure only. The durable
governance audit uses its existing closed metadata schema and does not persist
these timings. Edge continues to own endpoint authorization, deadlines, Ollama
transport, token counts, model
load duration, truncation and usage completeness. Timing records contain no
prompt, response, exception text or model-authored labels; they are diagnostic
only and do not change MIO result acceptance or Edge decisions.

The model snapshot optionally carries M.I.O.'s `validation_diagnostic` with
exactly `stage` and `rejection_class`. Edge accepts only the closed M.I.O.
vocabulary with strict string types and omits malformed diagnostics, including
objects with extra keys. It never forwards raw validation errors, trace details,
or model-authored identifiers through this field. Existing generic status,
reason, and advisory authority remain unchanged. The immutable dependency pin
is the public M.I.O. source commit `ffac07cc9bf06d6904faa98001cfcfaea788bcf7`.

Failure isolation and audit degradation:

- Enqueue failure isolation: if the optional model lane fails to enqueue, Edge
  logs a fixed warning (no exception detail) and continues to persist the event,
  advisory, and operator snapshot. The Edge decision fields are unchanged.
- Truncated audit degradation: a model result with `truncated_count` above zero
  is audited as `degraded`, never `adopted`. A `truncated_count` that is not
  an integer from 0 through 4 is treated as truncated and audited as degraded
  without raising before the audit record is written. `record_structured_result`
  applies the same rule to a present value (exact int 0..4, else persisted as 4);
  a missing value is omitted.
- Audit follows the lane's accepted analysis result: in the production lane the
  result is audited outside `LiveMioModelLane._lock`, after the pre-audit stale
  check and frame/trace binding check (so a binding rejection audits as
  `degraded`). `usage_status` is recomputed from normalized counts, never copied
  from the analyzer. If a newer generation arrives while a complete-result
  audit is being durably written, the lane does not publish the stale result and
  writes a compensating `degraded` `superseded` record. Here `adopted` means the
  lane accepted the result for publication when its audit began; it does not
  prove that a UI or operator observed it. The compensation write is best effort
  and emits a fixed warning plus a lane diagnostic if it fails. Snapshots also
  suppress a completed result if the fast generation changes immediately after
  the finalization check. If the initial audit raises, only a
  `degraded` result with an empty summary and bounded usage metrics is published.
  Only post-authorization analysis attempts use
  the output callback. Pre-analysis paths (fast result unavailable, pre-analysis
  deadline, frame unavailable, stale-before-analysis) do not; governance denial is
  recorded by the input authorization audit instead. Final freshness checks use
  the auxiliary lane's cheap generation accessor rather than deep-copying its
  full JSON snapshot on each model-cancellation poll. The deterministic Edge
  action path is unchanged.
- Allowlisted durable `knowledge_status`: the governed audit record persists
  `knowledge_status` only when it is a string in the fixed Knowledge status
  vocabulary. Any other value is dropped and never echoed into the audit payload.
  The vocabulary is kept in sync with the model lane by a parity test.

## Optional Knowledge operator receipt candidate

`edge_knowledge_advisory` is an optional `azazel.edge_knowledge_advisory.v1`
receipt, separate from score comparison. The adapter projects only MIO #18's
bounded `source_groups`, public ATT&CK identifiers, bounded source freshness,
and the `reported_unverified` claim label. Its status is `complete` and its
authority is `read_only_advisory`; missing or invalid receipts are omitted. Raw
IOC values, recommendation prose, canonical state, tokens and provenance are
excluded. Snapshot and display require current generation, trace, completion
freshness and handoff binding; the browser renders text only.

This local operator sidecar is based on Edge #528
`df61bd9847acc49d41d96d48e42046b858fb93da`, using MIO pin
`c6a0e0d6ef589693bc7bd54a4c2c1cdf32371524`, which includes MIO #18's typed
receipt. The fast adapter still calls `knowledge_attempted=False`; it projects
only a receipt already supplied by the shared core and adds no Knowledge query
or context construction. A separate optional loopback Knowledge query lane is
bounded and disabled by default. This does not establish full-node or deployed
Knowledge integration; it adds no network calls, installer changes or decision
consumers.

An Edge score/factor comparison is labeled `comparison_only` and separately
bound to generation and trace. Its M.I.O. score uses the same Edge-resolved
inputs, so a match indicates parity within that comparison, not independent
corroboration, detection, or ground truth. It does not alter the deterministic
decision path.
