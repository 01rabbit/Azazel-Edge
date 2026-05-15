# Azazel-Edge P0 Runtime Architecture

Last updated: 2026-05-13
Scope: Minimum runtime architecture after P0 baseline completion.

## 1. P0 Completion Scope
Completed issues:
- `#10 Evidence Plane v1`
- `#9 Lightweight NOC monitoring v1`
- `#11 NOC Evaluator v1`
- `#12 SOC Evaluator v1`
- `#13 Action Arbiter v1`
- `#8 Lightweight SoT v1`
- `#14 Decision Explanation v1`
- `#15 AI Assist Governance v1`
- `#16 Notification v1`
- `#17 Minimal audit logging baseline v1`
- `#5 Epic: P0 baseline`

## 2. P0 Decision Pipeline
1. `Tactical Engine` first-minute triage
2. `suricata_eve / noc_probe / syslog_min`
3. `Evidence Plane`
4. `NOC Evaluator` / `SOC Evaluator`
5. `Action Arbiter`
6. `Decision Explanation`
7. `Notification` / `AI Assist Governance`
8. `P0 Audit Logger`

## 3. Implementation Modules
### 3.1 Evidence Plane
- [`schema.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/schema.py)
- [`bus.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/bus.py)
- [`suricata.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/suricata.py)
- [`noc_probe.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/noc_probe.py)
- [`syslog_min.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/syslog_min.py)
- [`service.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/service.py)

### 3.2 NOC Monitoring
- [`noc_monitor.py`](/home/azazel/Azazel-Edge/py/azazel_edge/sensors/noc_monitor.py)

Collectors:
- `icmp`
- `iface_stats`
- `cpu_mem_temp`
- `dhcp_leases`
- `arp_table`
- `service_health`

### 3.3 Evaluators
- [`noc.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evaluators/noc.py)
- [`soc.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evaluators/soc.py)

### 3.4 Arbiter
- [`action.py`](/home/azazel/Azazel-Edge/py/azazel_edge/arbiter/action.py)

### 3.5 SoT
- [`loader.py`](/home/azazel/Azazel-Edge/py/azazel_edge/sot/loader.py)

### 3.6 Explanation
- [`decision.py`](/home/azazel/Azazel-Edge/py/azazel_edge/explanations/decision.py)

Required fields:
- `why_chosen`
- `why_not_others`
- `evidence_ids`
- `operator_wording`

### 3.7 AI Governance
- [`ai_governance.py`](/home/azazel/Azazel-Edge/py/azazel_edge/ai_governance.py)

Guardrails:
- Invoke AI only when governance conditions match.
- Send only sanitized payload.
- Limit output class to `advice / summary / candidate`.
- Audit `adopt / fallback` decisions.

Governance scope:
- In scope:
  - Operator-facing runbook support and wording assist that consume or produce `advice / summary / candidate`
  - NOC/SOC support calls from deterministic outputs (post-evaluator/arbiter)
- Out of scope:
  - Analyst model scoring payloads in `py/azazel_edge_ai/agent.py` (`verdict/confidence/reason/suggested_action/escalation` schema)
  - Ops coach structured responses (`runbook_id/summary/operator_note`) in `py/azazel_edge_ai/agent.py`
  - Manual ask structured responses (`answer/confidence/runbook_id/operator_note/user_message`) in `py/azazel_edge_ai/agent.py`
- Out-of-scope calls must still emit audit scope records (`in_scope=false`) and must not bypass deterministic evaluator/arbiter decisions.

### 3.8 Notification
- [`delivery.py`](/home/azazel/Azazel-Edge/py/azazel_edge/notify/delivery.py)

### 3.9 Audit Logging
- [`logger.py`](/home/azazel/Azazel-Edge/py/azazel_edge/audit/logger.py)

Common fields:
- `ts`
- `kind`
- `trace_id`
- `source`

## 4. Current Constraints
- Evaluator/arbiter/explanation are implemented as libraries, but not every legacy path is fully refactored.
- P0 keeps deterministic evaluators primary and AI assist secondary.
- Advanced correlation prediction, TI/YARA/Sigma, and external CMDB sync are out of P0 scope.

## 5. Tests
Primary P0 baseline tests:
- [`test_evidence_plane_v1.py`](/home/azazel/Azazel-Edge/tests/test_evidence_plane_v1.py)
- [`test_noc_monitor_v1.py`](/home/azazel/Azazel-Edge/tests/test_noc_monitor_v1.py)
- [`test_noc_evaluator_v1.py`](/home/azazel/Azazel-Edge/tests/test_noc_evaluator_v1.py)
- [`test_soc_evaluator_v1.py`](/home/azazel/Azazel-Edge/tests/test_soc_evaluator_v1.py)
- [`test_action_arbiter_v1.py`](/home/azazel/Azazel-Edge/tests/test_action_arbiter_v1.py)
- [`test_sot_v1.py`](/home/azazel/Azazel-Edge/tests/test_sot_v1.py)
- [`test_decision_explanation_v1.py`](/home/azazel/Azazel-Edge/tests/test_decision_explanation_v1.py)
- [`test_ai_governance_v1.py`](/home/azazel/Azazel-Edge/tests/test_ai_governance_v1.py)
- [`test_notification_v1.py`](/home/azazel/Azazel-Edge/tests/test_notification_v1.py)
- [`test_audit_logger_v1.py`](/home/azazel/Azazel-Edge/tests/test_audit_logger_v1.py)
