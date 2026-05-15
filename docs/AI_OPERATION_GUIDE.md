# Azazel-Edge AI Operation Guide

Last updated: 2026-05-13
Related documents:
- `docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL.md`
- `docs/MIO_PERSONA_PROFILE.md`
- `docs/P0_RUNTIME_ARCHITECTURE.md`

## 1. Purpose
This guide defines how AI assist is operated without violating deterministic-first runtime behavior.
AI is advisory only and never replaces evaluator/arbiter decisions.

## 2. Runtime Model Policy
Recommended local model set:
- Analyst Primary: `qwen3.5:2b`
- Analyst Degraded: `qwen3.5:0.8b`
- Ops Coach Primary: `qwen3.5:2b`
- Ops Coach Fallback: `qwen3.5:2b,qwen3.5:0.8b`

Operational rule:
- Do not place `4b+` models on the default co-located runtime path.

## 3. Decision and AI Assist Flow
1. Tactical Engine performs first-minute triage.
2. Evidence Plane normalizes and enriches context.
3. NOC/SOC evaluators and Action Arbiter produce deterministic decisions.
4. AI assist runs only when governance conditions allow.
5. Audit logging records adopt/fallback outcomes.

### 3.1 AI Assist Governance Scope Contract
- Governance in-scope:
  - Calls that exchange normalized assist payloads with keys in `advice / summary / candidate` and optional `runbook_candidates / attack_candidates`.
  - Typical entrypoint: `py/azazel_edge/ai_governance.py`.
- Governance out-of-scope:
  - Runtime analyst inference in `py/azazel_edge_ai/agent.py` (`verdict/confidence/...` contract).
  - Ops coach and manual query contracts in `py/azazel_edge_ai/agent.py`.
- Required for out-of-scope paths:
  - Keep deterministic path primary (no direct action execution by AI).
  - Emit audit scope records with explicit `in_scope=false` and reason.
  - Keep output contracts bounded and fail closed to fallback behavior.

## 4. Key Thresholds and Guards
- Ambiguous band: `AZAZEL_LLM_AMBIG_MIN=60`, `AZAZEL_LLM_AMBIG_MAX=79`
- Correlation controls: `AZAZEL_CORR_*`
- Queue limit: `AZAZEL_LLM_QUEUE_MAX`
- Ops memory guard: `AZAZEL_OPS_MIN_MEM_AVAILABLE_MB`
- Swap guard: `AZAZEL_OPS_MAX_SWAP_USED_MB`

## 5. Operational Files to Monitor
- `/run/azazel-edge/ai-bridge.sock`
- `/run/azazel-edge/ai_advisory.json`
- `/run/azazel-edge/ai_metrics.json`
- `/var/log/azazel-edge/ai-events.jsonl`
- `/var/log/azazel-edge/ai-llm.jsonl`
- `/var/log/azazel-edge/ai-deferred.jsonl`

## 6. Daily Checks
```bash
systemctl is-active azazel-edge-ai-agent
jq '{processed_events,llm_requests,llm_completed,llm_failed,last_error}' /run/azazel-edge/ai_metrics.json
tail -n 5 /var/log/azazel-edge/ai-llm.jsonl
```

## 7. First Response for AI Degradation
When latency/failure increases:
```bash
jq '{llm_requests,llm_completed,llm_failed,llm_fallback_count,last_error}' /run/azazel-edge/ai_metrics.json
sudo journalctl -u azazel-edge-ai-agent -n 100 --no-pager
sudo docker logs --tail 100 azazel-edge-ollama
```

## 8. Mattermost and Manual Ask
- Manual ask API: `POST /api/ai/ask`
- Command endpoint: `POST /api/mattermost/command`
- Message bridge: `POST /api/mattermost/message`
- Language prefixes: `ja:` and `en:` are supported for operator requests.

## 9. Runbook Safety Integration
- Runbook registry: `runbooks/**/*.yaml`
- Controlled execution remains gated by:
  - `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=1`
  - Runbook-level `requires_approval=true`

## 10. Language Policy
- This file is the English base document.
- Use Japanese only for supplemental operational examples when required.
- Full Japanese reference is available at `docs/AI_OPERATION_GUIDE_JA.md`.
