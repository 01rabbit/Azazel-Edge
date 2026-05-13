# AI Agent Build and Operation Detail

Last updated: 2026-05-13
Target: Azazel-Edge on Raspberry Pi (arm64)
Related persona profile: `docs/MIO_PERSONA_PROFILE.md`

## 1. Scope
This document covers practical build/operation details for the AI-assist runtime path.
The deterministic runtime path remains authoritative for primary decisions.

## 2. Current Implementation Coverage
Implemented baseline includes:
- Ambiguous-band LLM execution
- Correlation-based escalation triggers
- Ops escalation with memory/swap guards
- Analyst/Ops schema validation
- Runbook registry loading and review scaffolding
- Controlled execution safety gates
- Manual ask API (`/api/ai/ask`)

Planned or iterative areas:
- Multi-turn guided intake workflows
- Beginner symptom wizard depth expansion
- Automated periodic model comparison operations

## 3. Build/Runtime Prerequisites
- 64-bit Linux (`arm64`) with sudo access
- Docker runtime for optional Ollama/Mattermost components
- Python virtual environment for Azazel-Edge application layer

## 4. Deployment Components
Primary AI-related runtime surfaces:
- `py/azazel_edge_ai/agent.py`
- `systemd/azazel-edge-ai-agent.service`
- `/run/azazel-edge/ai-bridge.sock`
- `/var/log/azazel-edge/ai-*.jsonl`

## 5. Configuration Areas
Common variables:
- `AZAZEL_LLM_AMBIG_MIN`, `AZAZEL_LLM_AMBIG_MAX`
- `AZAZEL_LLM_TIMEOUT_SEC`, `AZAZEL_LLM_QUEUE_MAX`
- `AZAZEL_OPS_MIN_MEM_AVAILABLE_MB`, `AZAZEL_OPS_MAX_SWAP_USED_MB`
- `AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC`

## 6. Verification Commands
```bash
systemctl is-active azazel-edge-ai-agent
jq '{processed_events,llm_requests,llm_completed,llm_failed,last_error}' /run/azazel-edge/ai_metrics.json
curl -sS http://127.0.0.1:8084/api/ai/capabilities | jq
```

## 7. Operational Rules
- Keep Suricata and deterministic path availability above AI assist convenience.
- Treat AI output as advisory only (`advice / summary / candidate`).
- Preserve audit traceability for adopt/fallback behavior.
- Avoid heavy model defaults on constrained Pi deployments.

## 8. Language Policy
- This file is the English base document.
- For full Japanese operational detail, see `docs/AI_AGENT_BUILD_AND_OPERATION_DETAIL_JA.md`.
