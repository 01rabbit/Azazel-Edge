# Refactor Proposals

Last updated: 2026-06-11

This note captures proposal-only refactors identified during the safety-first
refactoring pass. None of these items should be implemented without a separate
review because they can affect operational contracts, test strategy, or
maintainer workflow.

## 6a. Decision Explanation Stream Consolidation

Motivation: The tactics-engine `DecisionLogger` stream and the v2
`DecisionExplainer` stream record related decisions with different schemas and
paths. This increases review cost and makes traceability harder to explain.

Design: Keep both writers initially, then define one canonical v2 record shape
for operator review. Add a compatibility reader for the tactics-engine stream
and mark it internal only if Q1 confirms no external consumer depends on it.

Migration steps: answer Q1, inventory readers, add dual-read review support,
publish a deprecation note, then switch new review tooling to the v2 stream.

Test impact: add fixtures for both streams and prove old records remain
readable. Keep existing v2 schema tests as the canonical writer contract.

Rollback plan: keep the existing tactics-engine writer path untouched until the
final cutover; if a consumer is found, stop at dual-read support.

## 6b. Web Blueprint Split And Test Configuration Object

Motivation: `azazel_edge_web/app.py` still owns routes, integration helpers,
configuration, auth constants, and template helpers. The first extraction moved
small I/O and auth helpers, but route groups remain tightly coupled to module
globals.

Design: Introduce blueprints by API area: dashboard, auth/admin, SOC/NOC state,
SOT, triage, demo, aggregator, STIX/TAXII, captive portal, and handoff. Keep a
single app factory only after all module-level symbols used by tests have stable
compatibility exports.

Migration steps: create route modules one group at a time, re-export moved names
from `app.py`, and add a small config object for test patching once all tests
can patch that object instead of scattered module globals.

Test impact: the 181-style monkey-patch pattern must keep working during each
move. Run the web contract group after every route group extraction and add a
compatibility test for `webapp.<name>` exports.

Rollback plan: each blueprint move should be a single reversible commit. If a
route shape changes, revert that route module extraction only.

## 6c. AI Agent Decomposition

Motivation: `py/azazel_edge_ai/agent.py` mixes socket handling, queueing,
manual queries, LLM calls, correlation, metrics, persistence, and advisory
building. This makes concurrency fixes harder to audit.

Design: Split by runtime responsibility: socket server, advisory builder,
LLM worker, manual-query handler, metrics store, and correlation state. Keep
`agent.py` as the systemd entry point and import the new modules from there.

Migration steps: add characterization tests for each extracted unit, move pure
functions first, then move stateful components behind small classes with the
same module-level singleton names.

Test impact: preserve current `agent.<name>` patch points until tests migrate.
Add direct tests for queue full, fallback, trace propagation, and manual query
routing.

Rollback plan: keep `agent.py` wrappers for every moved function; if an
extraction fails under operational tests, inline that module back without
changing the public entry point.

## 6d. i18n Data Externalization

Motivation: `i18n.py` is mostly dictionary literals and is parsed at import
time. Moving catalogs to data files would reduce code size and make language
review easier.

Design: Store catalogs as versioned JSON files under a dedicated data directory
and load them through the existing `translate()` / `ui_catalog()` APIs.

Migration steps: generate data files from the current literals, add a loader
with strict fallback behavior, then remove the literals after parity tests pass.

Test impact: keep catalog consistency tests and add a generated parity test
that compares old literals to loaded data during the migration branch.

Rollback plan: retain the literal-backed loader until the generated files have
passed parity on CI; switching back should be one import change.

## 6e. Full Path Registry Unification

Motivation: `path_schema.py` covers several runtime paths, but many modules
still hardcode audit, control, mode, and review paths. This makes v1/v2 path
compatibility harder to reason about.

Design: Extend `path_schema.py` with named helpers for every runtime path and
log stream, while preserving all current defaults and v1 compatibility.

Migration steps: add helpers first, migrate one module at a time, and keep
legacy candidate ordering where deployed devices may still rely on it.

Test impact: add contract tests for default paths, env overrides, v1 ordering,
v2 ordering, and legacy warning behavior.

Rollback plan: helper adoption should be per-module. Revert only the module
that changes path behavior.

## 6f. Rust Core Modulization And Command Argument Hardening

Motivation: The Rust core is a single file and parses prepared command strings
with whitespace splitting. That is a latent quoting risk in enforcement code.

Design: Split `main.rs` into config, event normalization, decision, enforcement
planning, enforcement execution, and tests. Represent commands as argv arrays
instead of strings before execution.

Migration steps: first move code without behavior changes, then introduce typed
command arguments behind tests, then update dry-run output only if explicitly
approved.

Test impact: existing Rust tests must continue to pass. Add tests for command
arguments containing spaces and for trace ID stability if that design is
approved.

Rollback plan: keep the old string rendering until typed execution is fully
tested. If output compatibility is at risk, stop at file modulization.

## 6g. CI Additions And Auth Token Caching

Motivation: CI currently relies on unit tests and contract tests. Additional
lint/type/coverage checks could catch drift earlier, and auth token parsing is
repeated on each request.

Design: Add optional ruff, mypy, and coverage jobs as reporting-only checks
first. For auth tokens, add a short-lived cache keyed by file path, mtime, and
size so freshness semantics remain clear.

Migration steps: introduce reporting-only CI, fix high-signal findings in
separate commits, then decide whether to make any check gating. For auth cache,
add tests for file update, missing file, and fail-closed behavior before use.

Test impact: CI workflow expectations change only after explicit approval.
Auth caching requires web auth contract tests plus concurrency tests around
token reload.

Rollback plan: keep new CI jobs non-gating until accepted. Make auth caching
disableable with an env var and revert to direct reads if any freshness issue
appears.

