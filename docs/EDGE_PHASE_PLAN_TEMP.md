# Azazel-Edge Phase Plan (Temporary)

Updated: 2026-03-05
Status: temporary memo for current migration and stabilization sequence.

## Preconditions
- `first_minute` full migration is out of scope.
- Implement what Azazel-Edge needs, not full Gadget parity.
- Current implemented baseline:
  - Suricata initial-response scoring (Tactical Engine path)
  - Decision audit logging (`decision_explanations.jsonl`)
  - `ui_snapshot` linkage for WebUI/TUI/EPD
  - Lightweight network health checks (captive/dns/route/wifi tags)

## Phase 1: Decision Foundation (Done)
1. Score Suricata events through Tactical Engine.
2. Persist decision explanation logs.
3. Reflect alert context into snapshot (`internal`, `attack`, recommendation).

Exit criteria:
- Injected Suricata event updates `risk_score`, `internal.suspicion`, `attack.suricata_*`.

## Phase 2: Edge Health Features (Done)
1. Add network-health assessment (captive portal, dns mismatch, route anomaly, wifi tags).
2. Reflect to snapshot (`network_health`, `connection.internet_check`, `connection.captive_portal`).
3. Ensure WebUI/TUI/EPD read same snapshot-derived state.

Exit criteria:
- `get_snapshot` returns health fields and connection verdicts.

## Phase 3: Co-host Stability (Done)
1. Apply Ollama hard limits (CPU, memory, pids).
2. Give Suricata fixed priority (nice/io settings).
3. Define overload behavior (LLM defer first, never Suricata degrade first).

Exit criteria:
- Under LLM load, Suricata capture/detection quality remains stable.

## Phase 4: Controlled LLM Integration (Done)
1. Send only ambiguous alerts to LLM.
2. Introduce queue-based flow: Suricata -> queue -> LLM worker.
3. Add backpressure: overflow => `deferred` classification instead of blocking pipeline.

Exit criteria:
- Alert spikes do not block pipeline; deferred cases are visible and traceable.

Implemented notes:
- Ambiguous alert routing only (`risk_score` in configurable range; default 40..79).
- Queue-based non-blocking LLM flow in AI agent.
- Backpressure on queue-full => advisory `llm.status=deferred` + deferred JSONL log.
- Runtime knobs (env): `AZAZEL_LLM_MODEL`, `AZAZEL_OLLAMA_ENDPOINT`, `AZAZEL_LLM_TIMEOUT_SEC`, `AZAZEL_LLM_QUEUE_MAX`, `AZAZEL_LLM_AMBIG_MIN/MAX`.

## Phase 5: Operational Hardening (Done)
1. Add metrics (`queue_depth`, `llm_latency_ms`, `deferred_count`).
2. Add failure handling (timeouts, retry policy, fallback policy).
3. Add regression tests for Suricata -> snapshot -> WebUI/TUI/EPD path.

Exit criteria:
- Stable day-2 operations with measurable reliability and debuggability.

Implemented notes:
- Metrics output: `/run/azazel-edge/ai_metrics.json` + snapshot field `llm_metrics`.
- Retry/fallback: configurable retries and backoff; failure result is `llm.status=fallback` with `policy=tactical_only_keep_recommendation`.
- Regression tests: `tests/test_phase5_operational_hardening.py` (3 tests, `unittest`).

## Notes
- This file is intentionally temporary and may be replaced by a formal architecture/operations document later.
- Known issue (postponed): `qwen3.5:2b` on current Pi co-host limits may timeout/runner-kill intermittently; Phase 5 fallback policy now absorbs this without blocking the pipeline.

## Phase 6: LLM Runtime Stabilization (Done)
1. Tune Ollama memory limit for `qwen3.5:2b` load margin.
2. Tune AI-agent LLM request profile (`keep_alive`, `num_ctx`, `num_predict`, timeout).
3. Keep single-worker / queue-first architecture and validate fallback remains effective.

Implemented notes:
- Ollama compose limit adjusted to `4g`.
- AI-agent defaults shifted to longer timeout and shorter responses for Pi runtime.
- Service env now exposes all runtime knobs for iterative tuning.
- Empty/invalid LLM outputs are normalized to `fallback` (not treated as successful advisory).

## Phase 7: Deferred Visibility (Done)
1. Surface `llm.status` and `llm_metrics` directly in WebUI.
2. Show deferred count and queue occupancy for operations triage.
3. Highlight deferred count when backlog exists.

Implemented notes:
- Risk card now displays `LLM Status`, `Deferred`, `Queue`, `LLM Latency`, and `LLM Reason`.
- Deferred counter is visually highlighted when `deferred_count > 0`.

## Phase 8: Load Test & Threshold Tuning (Done)
1. Execute staged burst input (`light=8`, `medium=24`, `heavy=64`) with ambiguous Suricata-like events.
2. Confirm overload behavior (`queue_full` => `deferred`) without blocking Suricata/agent services.
3. Tune runtime thresholds for day-2 operation.

Observed:
- Light: queued 8, deferred 0, queue depth ~7.
- Medium: queued 24, deferred 0, queue depth ~31 (near cap 32).
- Heavy: queued 1, deferred 63, queue depth hit cap 32; services remained active.
- Drain behavior was slow and mostly fallback (`empty_response`) under current model/runtime.

Applied tuning:
- `AZAZEL_LLM_QUEUE_MAX=8`
- `AZAZEL_LLM_AMBIG_MIN=60` (`MAX=79`)
- `AZAZEL_LLM_KEEP_ALIVE=5m`

## Phase 9: Model Quality Realization (Done)
1. Enforce role split in runtime:
   - `suricata-analyst`: primary/degraded models
   - `ops-coach`: explanation model
2. Add KPI-based policy switch (`normal` <-> `degraded`) using completion/fallback/empty rates.
3. Ensure invalid/empty outputs never count as success.

Implemented notes:
- Runtime model knobs:
  - `AZAZEL_LLM_MODEL_PRIMARY=qwen3.5:2b`
  - `AZAZEL_LLM_MODEL_DEGRADED=qwen3.5:0.8b`
  - `AZAZEL_OPS_MODEL=qwen3.5:4b`
- Auto degrade policy:
  - low quality => tighten ambiguous range and switch to degraded model.
  - recovered quality => back to normal policy.
- Policy and KPI outputs:
  - `/run/azazel-edge/ai_runtime_policy.json`
  - `/run/azazel-edge/ai_metrics.json` (`llm_completed_rate`, `llm_fallback_rate`, `llm_empty_rate`)
- Response quality hardening:
  - `think` disabled by default (`AZAZEL_LLM_THINK=0`)
  - JSON schema strict validation (invalid/empty => fallback)

## Phase 10: Memory Pressure Resolution (Done)
1. Prevent 4B model residency in default path.
2. Guard `ops-coach` execution by host memory/swap thresholds.
3. Keep SOC pipeline stable under memory pressure.

Implemented notes:
- `ops-coach` default is OFF (`AZAZEL_OPS_ENABLED=0`), enabled only when explicitly needed.
- `ops-coach` calls use `keep_alive=0s` to avoid model residency.
- Runtime guards skip `ops-coach` when memory is low or swap is already high.

## Phase 11: Production Profile Switch (Done)
1. Switch primary analyst model to `qwen3.5:0.8b`.
2. Enable conditional `ops-coach` escalation to `qwen3.5:4b`.
3. Keep memory-safe behavior (`ops` no residency + mem/swap guard + cooldown).

Implemented notes:
- Primary model: `AZAZEL_LLM_MODEL_PRIMARY=qwen3.5:0.8b`
- Escalation trigger (ops-coach):
  - when LLM fallback/not-completed
  - or high risk with low confidence
  - or critical risk direct path (`risk_score>=85`) even when non-ambiguous
- Escalation safety:
  - `AZAZEL_OPS_KEEP_ALIVE=0s`
  - minimum available memory / maximum swap-used threshold
  - escalation cooldown
- Ops model fallback chain:
  - `AZAZEL_OPS_MODEL_CHAIN=qwen3.5:4b,qwen3.5:2b,qwen3.5:0.8b`
  - if 4b fails, automatically fallback to smaller model and continue.
