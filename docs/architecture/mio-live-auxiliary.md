# Live M.I.O. auxiliary path

Status: branch preparation; the shared M.I.O. package source is not yet published.

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
shadow result as `edge_score_comparison`. It is copied into the live panel only
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
`unknown_fields` marker. The full persisted M.I.O. envelope is capped at 16
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

The runtime dependency is declared in `requirements/runtime.txt` using an
immutable Git commit pin. The source commit must be published before a normal
installation can resolve it; this branch does not vendor the package. If the
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
