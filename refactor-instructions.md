# refactor-instructions.md — Azazel-Edge Refactoring Directive

This document is the complete instruction set for an implementation model
(Codex / Opus / etc.) to execute a safety-first refactoring of this repository.
It was produced from a full evidence-based audit on 2026-06-11 (HEAD `9d5e1dd`).
Follow it exactly. When this document says STOP AND ASK, stop and ask the human.

---

## Objective

Reduce verified technical debt in the Azazel-Edge codebase **without changing
any observable behavior**, in small reversible steps, each independently
verified. Priorities, in order:

1. Fix silent-corruption and audit-integrity hazards (thread safety, trace_id).
2. Remove duplication and dead weight that is provably safe to remove.
3. Clarify module boundaries so the two giant files (`azazel_edge_web/app.py`,
   `py/azazel_edge_ai/agent.py`) become safely decomposable later.
4. Make the test suite cheaper to maintain (shared fixtures, no `/tmp` litter).

Large design changes are explicitly **proposal-only** in this effort (see
Implementation Phases, Phase 6, and Out-of-scope Items).

---

## Project Understanding

Azazel-Edge (AZ-01 / SENTINEL) is a Raspberry Pi-oriented **deterministic edge
SOC/NOC gateway**. It observes local telemetry (Suricata EVE, NetFlow, SNMP,
WiFi scans, NOC probes), evaluates NOC/SOC state with deterministic evaluators,
selects one of five bounded actions (observe / notify / throttle / redirect /
isolate) via an Action Arbiter, and records operator-visible explanations and a
hash-chained audit trail. Local AI (Ollama) is **advisory only** and is gated by
`py/azazel_edge/ai_governance.py`. Raw logs are handled local-first.

### Runtime topology (all on one device)

```
Suricata EVE ──► rust/azazel-edge-core (tail, normalize, decide, dry-run plan)
                    │ Unix socket /run/azazel-edge/ai-bridge.sock
                    ▼
py/azazel_edge_ai/agent.py (socket server, scoring, LLM worker thread)
                    │ uses py/azazel_edge/* (evaluators, arbiter, explanations, audit)
                    ▼
/run/azazel-edge/*.json snapshots + /var/log/azazel-edge/*.jsonl streams
                    ▲                                   ▲
py/azazel_edge_control/daemon.py (control socket,       │
  NOC probes, WiFi, mode mgmt)                          │
                    ▲                                   │
azazel_edge_web/app.py (Flask, ~70 routes, gunicorn 2 workers × 4 threads)
py/azazel_edge/cli_unified.py (TUI), azazel_edge_epd.py (e-paper)
```

### Key entry points

- `azazel_edge_web/app.py` — Flask app (`app` object; gunicorn target
  `azazel_edge_web.app:app` in `systemd/azazel-edge-web.service`)
- `py/azazel_edge_ai/agent.py` — AI agent daemon (path hardcoded in
  `systemd/azazel-edge-ai-agent.service`)
- `py/azazel_edge_control/daemon.py` — control daemon
- `rust/azazel-edge-core/src/main.rs` — single-file Rust capture/enforcement core
- `bin/*` — launchers; several are installed to `/usr/local/bin` by installer

### Layout facts the implementation must respect

- The repo is **not an installed package**: no `pyproject.toml`, no `setup.py`,
  no `conftest.py`, no `pytest.ini`. CI runs `PYTHONPATH=. pytest -q`; every
  test file inserts `ROOT/py` into `sys.path` itself (57 files carry this
  boilerplate).
- All tests are `unittest.TestCase` style. Test files are named
  `test_<subsystem>_v<N>.py`; `_v2` supplements `_v1`, it does not replace it.
- Web API tests pin behavior by **monkey-patching module-level names** on
  `azazel_edge_web.app` (181 occurrences across test files). Any symbol you
  move out of `app.py` must remain importable/patchable at its old name.

---

## Behaviors To Preserve

These are pinned by tests, consumed across the Rust/Python boundary, or relied
on by deployed systemd/installer artifacts. Changing any of them is a
behavioral change, not a refactor.

### Decision core
1. The five actions and their profiles in
   `py/azazel_edge/arbiter/action.py` (`ACTION_PROFILES`): names, and the
   `reversible` / `approval_required` / `audited` / `effect` / `mode` values.
   `approval_required=True` on throttle/redirect/isolate is a safety guarantee.
2. Arbiter decision logic and output keys: `action`, `reason`,
   `rejected_alternatives`, `release_condition`, `chosen_evidence_ids`,
   `action_profile`, `decision_trace`, `policy`.
3. The v2 explanation record fields enforced by
   `py/azazel_edge/explanations/schema.py`: `ts`, `trace_id`, `format_version`
   ("v2"), `selected_action`, `reason`, `rejected_actions`,
   `release_condition`, `policy_profile`, `config_hash`, `why_chosen`,
   `why_not_others`, `evidence_ids`, `next_checks`, `operator_wording`,
   `machine`, `trust_capsule`.
4. Audit chain format in `py/azazel_edge/audit/logger.py`: `chain_prev`,
   `chain_hash`, SHA-256 over canonical JSON with `sort_keys=True` and the
   existing separators. Do not alter the serialization in any way — it would
   invalidate every existing on-device log.
5. AI governance invariants in `py/azazel_edge/ai_governance.py`:
   `ALLOWED_INTENTS = {advice, summary, candidate}`, the `FORBIDDEN_KEYS` set,
   output length caps, and the fact that every invocation (including blocked
   ones) is audited. Never bypass `AIGovernance.invoke()`.

### Cross-language contract
6. The Rust→Python envelope: `{"normalized": ..., "defense": ...,
   "enforcement": ..., "enforcement_status": ..., "source": "suricata_eve",
   "pipeline": "rust_event_engine_v1"}` and all 14 `NormalizedEvent` field
   names consumed by `agent.py` (~lines 1015–1026): `ts, src_ip, dst_ip,
   attack_type, severity, target_port, protocol, sid, category, event_type,
   action, confidence, risk_score, ingest_epoch`. There is NO schema validation
   at this boundary; a rename fails silently.
7. `EnforcementOutcome.mode` strings (`dry_run`, `policy_gated`, `enforced`,
   `disabled`), the `trace-{hex}` trace_id prefix, and the nftables table name
   `inet azazel_edge`.

### Web API (pinned by tests — see test file for exact shapes)
8. All endpoint paths and response shapes listed in
   `tests/test_dashboard_data_contract.py`, `test_api_auth_contract.py`,
   `test_api_auth_rbac_v1.py`, `test_triage_api_v1.py`, `test_demo_api_v1.py`,
   `test_handoff_api_v1.py`, `test_sot_api_v1.py`, `test_aggregator_api_v1.py`,
   `test_stix_taxii_api_v1.py`, `test_captive_portal_api_v1.py`. Notable quirks
   that are intentional and pinned:
   - `/api/state` 403 body is `{"error": "Unauthorized"}` but `/api/runbooks`
     403 body is `{"ok": false, "error": "Unauthorized"}` — two shapes, both
     pinned. Do not unify.
   - `/api/wifi/connect` rejects with **401**, other routes with 403.
   - `GET /api/wifi/scan` and `POST /api/mattermost/command` intentionally do
     not use `require_token`.
9. Auth is fail-closed by default (`AUTH_FAIL_OPEN=False`); missing token file
   → 403. mTLS fingerprint check applies to operator-and-above only.

### Operational surface
10. Service names, socket paths (`/run/azazel-edge/ai-bridge.sock`,
    `/run/azazel-edge/control.sock`), JSONL/JSON paths under
    `/var/log/azazel-edge/` and `/run/azazel-edge/`, CLI names installed to
    `/usr/local/bin`, gunicorn target `azazel_edge_web.app:app`, and the
    hardcoded agent path in `azazel-edge-ai-agent.service`.
11. `verify_runtime_sync.sh` exit codes (0/1/2) and the file list it checks —
    renaming/moving any file it tracks breaks deployment verification.
12. OpenCanary decoy ports (SSH 12222, HTTP 18080) coupled between
    `security/opencanary/opencanary.conf` and `config/redirect_policy.yaml`.
13. The repository tree must stay clean under `tools/claims_discipline.py`
    (`tests/test_claims_discipline_v1.py` runs it against the real tree). Do
    not introduce the forbidden marketing phrases it checks — including in
    comments, docs, or this kind of instruction file. Refer to them only
    indirectly, as this document does.

---

## Non-Negotiables

From `AGENTS.md` and `CONTRIBUTING.md` (governance; violating these is a
hard failure regardless of test results):

1. **Never modify anything under `installer/`, `security/`, or `systemd/`.**
   These require explicit human approval. If a refactor seems to require it,
   STOP AND ASK.
2. **Never flip safety defaults**: `AZAZEL_AUTH_FAIL_OPEN` stays `"0"`,
   `AZAZEL_DEFENSE_ENFORCE` stays `false`, `AZAZEL_DEFENSE_DRY_RUN` stays
   `true`. Never set `requires_approval: false` on any runbook.
3. **Deterministic First**: AI never moves ahead of the Evidence Plane /
   deterministic path. No autonomous execution of throttle/redirect/isolate.
4. **Auditability stays intact**: adopt/fallback logging and required decision
   explanation fields must survive every change.
5. Docs are English-default. If you change API or configuration surface, update
   `docs/API_REFERENCE.md` / `docs/CONFIGURATION.md` in the same change set,
   and register any new doc in `docs/INDEX.md`. EN/JA doc pairs must be updated
   together for behavioral changes.
6. Never log or relocate secrets: web token, Mattermost tokens/credentials,
   ntfy token, TLS/CA private keys, aggregator HMAC key, mTLS fingerprint file.
7. Do not commit changes to `MEMORY`/policy files, and do not add new runtime
   dependencies (the `tests/test_runtime_dependency_contract.py` contract test
   enforces `requirements/runtime.txt` coverage; dependency installs happen in
   CI, not locally).

---

## Stop And Ask Conditions

STOP, do not implement, and ask the human when any of these occur:

- A change would alter any item in **Behaviors To Preserve**.
- A test contradicts the implementation and you cannot tell which is intended.
- You believe code is dead but cannot prove no runtime/operational consumer
  exists (scripts in `bin/` may be invoked manually by operators).
- A change touches public API shape, on-disk JSONL formats, stored data,
  auth, notification delivery, or external integrations (Mattermost, ntfy,
  Wazuh, TAXII, OpenCanary).
- A change would require touching `installer/`, `security/`, or `systemd/`.
- The fix has multiple defensible designs with product implications.
- Any item in the "Open Questions" file section below is a prerequisite for
  the change you are about to make and has not been answered yet.

### Open Questions (answers required before the marked phases)

- **Q1 (blocks Phase 6a):** Is the tactics-engine decision stream
  (`/opt/azazel-edge/logs/tactics_engine/decision_explanations.jsonl`, written
  by `py/azazel_edge/tactics_engine/decision_logger.py`) consumed by anything
  external to this repo? May it be marked internal/deprecated in favor of the
  v2 `DecisionExplainer` stream?
- **Q2 (blocks Phase 3 item 3.6):** `explanations/trust_capsule.py` falls back
  to a publicly known default HMAC key when `AZAZEL_TRUST_CAPSULE_HMAC_KEY` is
  unset. Should the fix hard-fail (raise), or warn-and-continue? Hard-fail
  could break explanation writing on deployed devices that never set the var.
- **Q3 (blocks any deletion):** Which of these are still operationally used:
  `bin/update-readme-stats`, `bin/azazel-edge-inject-test-events`, the
  `GET /demo` page, the root `images/` directory? Default assumption: all are
  in use; nothing is deleted in this effort.
- **Q4 (blocks Phase 5 item 5.2):** `tests/benchmark/test_pipeline_latency_bench_v1.py`
  asserts wall-clock p95 thresholds and runs inside the default `pytest -q`
  gate (flaky on slow runners). May benchmarks be excluded from the default
  test run and moved to a separate non-gating CI job? This changes the
  documented definition of "green" in CONTRIBUTING.md/AGENTS.md.
- **Q5 (blocks touching `path_schema.py` v1 branches):** Are any deployed
  devices still on `AZAZEL_PATH_SCHEMA=v1` (legacy azazel-gadget paths)?
  Default assumption: yes; leave all v1/legacy compatibility intact (legacy
  symlink deprecation date is 2026-12-31).

---

## Baseline Commands

Run all of these BEFORE any edit and record the output (counts, pass/fail,
durations) in your report. Re-run after every phase.

```bash
git status                                   # must be clean before you start
git log --oneline -3                         # record the base commit

# Python tests (CI-equivalent; use the repo venv or bin/azazel-edge-dev)
bin/azazel-edge-dev bootstrap                # once, if .venv is missing
PYTHONPATH=. .venv/bin/pytest -q             # the CI gate

# Rust tests
cd rust/azazel-edge-core && cargo test && cd ../..

# Syntax gate
python3 -m compileall -q py azazel_edge_web

# Claims discipline (also runs inside pytest)
python3 tools/claims_discipline.py || true   # record output
```

If the baseline is already red, STOP AND ASK before changing anything.

---

## Debt Map

Each item: evidence → why → risk → action class.
Action classes: **[FIX]** implement in this effort; **[FIX-Q]** implement only
after its Open Question is answered; **[PROPOSE]** write a proposal, do not
implement.

### A. Audit-integrity and concurrency (highest priority)

| # | Debt | Evidence | Why / blast radius | Class |
|---|---|---|---|---|
| A1 | `P0AuditLogger` is not thread-safe: `_last_chain_hash` read/update and file append are unguarded; `AI_AUDIT` is a singleton shared by per-client threads + LLM worker | `py/azazel_edge/audit/logger.py:82-84`, `py/azazel_edge_ai/agent.py:198` | Concurrent writes can silently break the hash chain — the core integrity guarantee | [FIX] add `threading.Lock` around `log()` |
| A2 | `_append_jsonl` calls in agent.py outside `IO_LOCK` (`EVENT_LOG_PATH` at ~1649; also ~803, 879, 1176, 1199) | `py/azazel_edge_ai/agent.py` | Interleaved/truncated JSONL lines under concurrent clients | [FIX] guard all appends with a lock (IO_LOCK or a dedicated append lock) |
| A3 | `EvidenceBus` fanout file append unguarded | `py/azazel_edge/evidence_plane/bus.py:21`; shared bus in `daemon.py:114` | Same corruption class | [FIX] add lock |
| A4 | trace_id never set in the live advisory: `_build_advisory()` omits it, so `advisory.get("trace_id")` is always empty in AI audit records | `py/azazel_edge_ai/agent.py:1012-1122, 920, 939, 1326` | Production AI audit entries have no trace linkage; contradicts the documented traceability story | [FIX] adopt the incoming Rust `enforcement.trace_id` when present, else generate one; propagate through `_handle_event` and `_process_llm_task`. Add an assertion test. |
| A5 | `validate_v2_explanation()` is never called by the writer; validation happens only at read time in `audit_review.py` | `py/azazel_edge/explanations/decision.py:170-175` | Invalid records written silently | [FIX] validate in `explain()` before `write_jsonl()`; on failure log a warning and still write (do NOT raise — preserves runtime behavior) |
| A6 | Web file writes without tmp+rename: `_save_captive_registry`, `_write_topolite_seed_mode`; `_record_dashboard_trend_point` appends outside its own lock | `azazel_edge_web/app.py:858, 2423, 3445` | Partial-write corruption under gunicorn 2×4 concurrency | [FIX] use the existing `_write_json_file` atomic pattern; move the trend append inside the lock |
| A7 | `SocEvaluator` mutable instance state (`_incident_store`, `_seen_*`) used via module-level singletons across threads | `py/azazel_edge/evaluators/soc.py:259-263`, `agent.py:139` | Race-prone correlation state | [FIX] add an internal lock around `evaluate()`; do NOT change to per-call instances (the statefulness is intentional) |
| A8 | Trust capsule default HMAC key is a public constant | `py/azazel_edge/explanations/trust_capsule.py:27` | Capsules forgeable when env unset | [FIX-Q: Q2] |

### B. Duplication and dead weight

| # | Debt | Evidence | Class |
|---|---|---|---|
| B1 | Two decision-explanation writers with different schemas/paths (`DecisionLogger` vs `DecisionExplainer`); only the latter is validated and read by `audit_review.py` | `py/azazel_edge/tactics_engine/decision_logger.py:91,101` vs `py/azazel_edge/explanations/decision.py:13` | [PROPOSE; consolidation gated on Q1] |
| B2 | Duplicated helpers: `_stable_json()` (`aggregator.py:37` = `explanations/trust_capsule.py:15`), `iso_utc_now()` (`evidence_plane/schema.py:21` = `notify/delivery.py:19`), `_ensure_parent()` (`demo_overlay.py:14` = `agent.py:221`) | — | [FIX] consolidate into `py/azazel_edge/_util.py`, re-export from old locations |
| B3 | In-file duplicate correlation logic: `agent.py:_evaluate_correlation` (~389-443) vs `correlation/advanced.py` `AdvancedCorrelator` | — | [PROPOSE] (agent.py has no direct tests; do not touch its logic in this effort beyond A2/A4) |
| B4 | 57 test files carry identical `sys.path` boilerplate; no `conftest.py`; builder helpers (`_noc`, `_soc`, `_dim`) duplicated across arbiter/evaluator tests | `tests/*` | [FIX] root `conftest.py` + `tests/helpers.py`; remove boilerplate mechanically |
| B5 | Six test files write to hardcoded `Path('/tmp/unused-*.jsonl')` | `tests/test_yara_assist_v1.py:71`, `test_advanced_correlation_v1.py:118`, `test_decision_explanation_fields_v1.py:80`, `test_decision_explanation_v2.py:19`, `test_sigma_assist_v1.py:79`, `test_attack_defend_visualization_v1.py:29` | [FIX] use `tempfile` |
| B6 | Repeated `_tail_jsonl(AI_LLM_LOG, limit=20)` reads across 5+ dashboard routes, token files re-parsed on every request | `azazel_edge_web/app.py` (multiple) | [PROPOSE] (caching changes observable freshness semantics) |
| B7 | Possibly orphaned scripts: `bin/update-readme-stats`, `bin/azazel-edge-inject-test-events` | report §4 | [no action; Q3 informational only] |

### C. Boundaries and configuration

| # | Debt | Evidence | Class |
|---|---|---|---|
| C1 | Layer violation: `explanations/decision.py:9` imports `azazel_edge.triage` (output layer pulling workflow layer + i18n transitively) | — | [FIX] invert: `explain()` accepts optional `runbook_support` param; caller computes it. Keep a deprecation shim so existing callers still work. |
| C2 | `path_schema.py` exists but is bypassed by many modules: hardcoded paths in `control_plane.py:11`, `daemon.py:60-67`, `mode_manager.py:20,36`, EPD files, `tactics_engine/decision_logger.py:101`, `tactics_engine/config_hash.py:61-62`, `audit_review.py:21-23`; audit log paths absent from path_schema entirely | — | [FIX, narrow] add env-var overrides where missing (e.g. `AZAZEL_CONTROL_SOCKET`) and route `config_hash.py` through `path_schema.first_minute_config_candidates()`. Defaults must remain byte-identical. Full path-registry unification: [PROPOSE]. |
| C3 | `azazel_edge_web/app.py` is a 6,593-line monolith (config, auth, ~70 routes, helpers, integrations) | report §1 | [FIX, staged + PROPOSE]: extract ONLY pure I/O helpers and the auth layer into modules with full re-export from `app.py` (so the 181 `webapp.*` monkey-patch sites keep working). Blueprint split: [PROPOSE]. |
| C4 | `agent.py` (1,781 lines) mixes socket server, LLM worker, correlation, metrics, manual queries; zero direct tests | — | [PROPOSE] decomposition; in this effort only A2/A4 + characterization tests |
| C5 | `cli_unified.py` (1,824 lines) holds the shared `Snapshot` contract used by Textual UI and EPD | `cli_unified.py:52,158` | [FIX] extract `Snapshot` + `build_snapshot()` to `py/azazel_edge/snapshot_model.py`, re-export from `cli_unified.py` |
| C6 | `i18n.py` is 1,923 lines of dict literals parsed at import | — | [PROPOSE] externalize to data files (startup-cost win on Pi, but migration risk) |
| C7 | PYTHONPATH documented four different ways (CI `.`, dev script `.:py`, CONTRIBUTING both, AGENTS another) | report §1/§6 | [FIX] root `conftest.py` makes them all work; align docs to one canonical command |
| C8 | Rust `main.rs` single file; `split_whitespace` re-parse of built command strings is a latent quoting hazard; `DefaultHasher` trace ids not stable across Rust versions | `rust/azazel-edge-core/src/main.rs:309,481,404` | [PROPOSE] (enforcement-sensitive; has tests but the hazard fix needs careful design) |

### D. Test and CI debt

| # | Debt | Evidence | Class |
|---|---|---|---|
| D1 | Benchmark latency thresholds run in the default CI gate | `tests/benchmark/test_pipeline_latency_bench_v1.py` | [FIX-Q: Q4] |
| D2 | No lint, no type check, no coverage in CI | `.github/workflows/ci.yml` | [PROPOSE] (adding gates changes contributor workflow) |
| D3 | Web tests monkey-patch 181 module-global names | report §3b | [PROPOSE] config-object migration; in this effort, preserve patchability instead |
| D4 | Manual patching without `unittest.mock.patch` in `test_phase5_operational_hardening.py` (leak risk on exception) | lines ~147-154, 435-448 | [FIX] convert to context-managed patching, behavior identical |
| D5 | No characterization tests for `agent.py` advisory building or the Rust→Python field contract | — | [FIX] add: (1) `_build_advisory()` unit test with a fixed event fixture; (2) a contract test asserting the 14 normalized field names against a sample envelope fixture |

---

## Implementation Phases

Work strictly in this order. One phase = one commit (or a small series of
commits) on a dedicated branch (e.g. `refactor/safety-first-pass`). Never start
phase N+1 with phase N unverified.

### Phase 0 — Baseline
1. `git status` — if not clean, STOP AND ASK (do not mix in others' changes).
2. Create the working branch.
3. Run all Baseline Commands; record results verbatim in the report.

### Phase 1 — Safety nets (tests only; no production code changes)
1. Add root `conftest.py` inserting `ROOT/py` into `sys.path` (B4, C7). Do not
   yet remove per-file boilerplate (additive only).
2. Add `tests/helpers.py` with the shared `_noc`/`_soc`/`_dim` builders
   (mirroring the existing ones; existing tests untouched for now).
3. Add characterization tests (D5): advisory-building fixture test and the
   Rust→Python `NormalizedEvent` field-name contract test.
4. Add a concurrency test for `P0AuditLogger` (threads × N appends, then
   `verify_chain`). It is EXPECTED TO FAIL or be flaky against current code —
   mark it skipped with a comment referencing Phase 3, or write it so it runs
   after the Phase 3 fix lands (your choice; state it in the report).
5. Verify: full baseline suite still green (plus the new tests).

### Phase 2 — Obviously safe cleanups
1. B5: replace the six `/tmp/unused-*` test paths with `tempfile`.
2. B2: create `py/azazel_edge/_util.py`; move `_stable_json`, `iso_utc_now`,
   `_ensure_parent`; keep thin re-export aliases at the original sites.
3. D4: convert manual patch/restore in `test_phase5_operational_hardening.py`
   to context-managed patching.
4. Mechanically remove the per-file `sys.path` boilerplate from test files
   (now covered by `conftest.py`). Touch nothing else in those files.
5. Verify after each sub-step: `PYTHONPATH=. .venv/bin/pytest -q`.

### Phase 3 — Small correctness fixes (behavior-preserving by construction)
1. A1: lock in `P0AuditLogger.log()` (and `verify_chain` if it touches shared
   state). Enable/un-skip the Phase 1 concurrency test.
2. A2: bring all `_append_jsonl` call sites in `agent.py` under a lock.
3. A3: lock in `EvidenceBus` fanout append.
4. A6: atomic writes for captive registry / topolite seed; trend append inside
   its lock.
5. A4: trace_id adoption in `_build_advisory()` (prefer incoming
   `enforcement.trace_id`, fallback to generated `trace-{hex}`-style id), plus
   test. Do not change the Rust side.
6. A8: trust-capsule HMAC key handling — ONLY after Q2 is answered.
7. A5: wire `validate_v2_explanation` into the writer (warn-only).
8. A7: internal lock around `SocEvaluator.evaluate()`.
9. Verify: full suite + `cargo test` + targeted re-run of audit/explanation
   tests.

### Phase 4 — Small responsibility separations (with re-exports)
1. C5: extract `Snapshot`/`build_snapshot()` → `py/azazel_edge/snapshot_model.py`;
   `cli_unified.py` re-imports them so all existing imports keep working.
2. C1: `DecisionExplainer.explain()` gains optional `runbook_support` param;
   internal `triage` import becomes lazy/fallback so the old call pattern
   still works; demo runner updated to pass it explicitly.
3. C3 (stage 1 only): extract pure I/O helpers from `app.py` into
   `azazel_edge_web/io_helpers.py`, and the auth functions into
   `azazel_edge_web/auth.py`. CRITICAL: `app.py` must re-export every moved
   name (`from .io_helpers import *` plus explicit names) so all
   `webapp.<name>` monkey-patch sites in tests still bind. Run the full web
   test group after each extraction.
4. C2 (narrow): `AZAZEL_CONTROL_SOCKET` env override in `control_plane.py`
   (and `daemon.py` reading the same var); `config_hash.py` through
   `path_schema` candidates. Defaults byte-identical; add/extend tests.
5. Verify: full suite; confirm zero changes in any pinned API response by
   running the web contract tests.

### Phase 5 — Test-structure improvements
1. Migrate arbiter/evaluator tests to use `tests/helpers.py` builders (delete
   the in-file duplicates).
2. D1: benchmark split — ONLY after Q4 is answered. If approved: add pytest
   config excluding `tests/benchmark` from default discovery, add a separate
   CI job (non-gating or with relaxed env-configurable thresholds), and update
   CONTRIBUTING.md/AGENTS.md commands in the same change.
3. Verify: full suite, and (if Q4 approved) the new benchmark job invocation.

### Phase 6 — Proposals only (NO implementation without explicit approval)
Write `docs/` proposal notes (or a single `refactor-proposals.md`) for:
- 6a. Unifying the two decision-explanation streams (B1; needs Q1).
- 6b. `app.py` blueprint decomposition + web-test config-object migration (C3
  stage 2, D3).
- 6c. `agent.py` decomposition (LLM worker / correlation / metrics / socket
  server) and replacing `_evaluate_correlation` with `AdvancedCorrelator` (B3,
  C4).
- 6d. `i18n.py` data externalization (C6).
- 6e. Full path-registry unification through `path_schema` (C2 full scope).
- 6f. Rust `main.rs` modulization + command-string quoting hardening (C8).
- 6g. CI additions: ruff/mypy/coverage (D2), auth-token caching (B6).
Each proposal must include: motivation, design, migration steps, test impact
(especially the monkey-patch sites), and rollback plan.

---

## Verification Requirements

- Record baseline results BEFORE the first edit; re-run the full gate after
  every phase: `PYTHONPATH=. .venv/bin/pytest -q`, `cargo test` (when Rust or
  the boundary contract is involved), `python3 -m compileall -q py
  azazel_edge_web`, and the claims-discipline check.
- After Phase 4 web extractions, additionally run the web test group
  explicitly: `PYTHONPATH=. .venv/bin/pytest -q tests/test_api_auth_contract.py
  tests/test_api_auth_rbac_v1.py tests/test_dashboard_data_contract.py
  tests/test_triage_api_v1.py tests/test_demo_api_v1.py tests/test_sot_api_v1.py
  tests/test_aggregator_api_v1.py tests/test_stix_taxii_api_v1.py
  tests/test_captive_portal_api_v1.py tests/test_handoff_api_v1.py`.
- Any test that fails after your change: do not "fix the test" unless the test
  itself was asserting the duplicated/internal detail you intentionally moved
  AND the pinned behavior is unchanged — state this explicitly in the report.
- No new runtime dependency may appear (contract test will catch it; do not
  add to `requirements/runtime.txt` without approval).
- Git hygiene: `git status` first; never mix pre-existing uncommitted changes
  with yours; one phase per commit with a message explaining what and why;
  changes small and revertible; NO drive-by reformatting, renaming, or
  "while I'm here" edits; behavior changes forbidden unless this document
  explicitly directs them.

---

## Reporting Format

At the end (and at any STOP AND ASK), report:

```
## Phase Status
Phase 0..6: done / partial / skipped (+reason)

## Baseline vs Final
- pytest: <N passed> → <N passed> (list any new tests)
- cargo test: <result> → <result>
- compileall: <result>
- claims discipline: <result>

## Changes Made
Per phase: files touched, one-line rationale each, commit hashes.

## Behavior Deltas
MUST be "none" outside items explicitly directed here; otherwise list and
justify against this document.

## Questions Raised / Answers Used
Which Open Questions (Q1–Q5) were answered and how they changed the work.

## Commands Run
The exact final verification commands and their results, verbatim.

## Remaining Debt
What was deliberately left (Phase 6 proposals, [PROPOSE] items).
```

---

## Out-of-scope Items

Do NOT do any of the following in this effort:

- Anything under `installer/`, `security/`, `systemd/`.
- Deleting any `bin/` script, template, static file, or the `images/` dir
  (Q3 is informational; deletion is a separate, human-approved effort).
- Unifying the two web error-response shapes, changing any endpoint path,
  status code, or response field.
- Changing on-disk formats: audit chain serialization, v2 explanation fields,
  tactics-engine record fields, NormalizedEvent envelope, snapshot JSON keys.
- Removing legacy azazel-gadget compatibility paths/symlinks (deprecation date
  2026-12-31) or `AZAZEL_PATH_SCHEMA=v1` branches.
- Dependency upgrades, packaging the repo (pyproject/setup), or Python version
  changes.
- New features, UI redesign, performance optimizations beyond the directed
  lock/atomic-write fixes.
- Editing BHEU CFP/paper/roadmap content (`docs/cfp/`, `docs/papers/`,
  `docs/roadmaps/`, `docs/issues/blackhat-europe/`) except where a directed
  change requires a doc cross-reference update.
- Rewriting `agent.py`, `app.py` routes, `i18n.py`, or Rust core structure
  (Phase 6 proposals only).
