# Azazel-Edge P0 Runtime Architecture

最終更新: 2026-03-10
対象: P0 成立ライン完了後の最小 runtime 構成

## 1. P0 完了範囲

完了 issue:

- `#10 Evidence Plane v1`
- `#9 軽量NOC監視機能 v1`
- `#11 NOC Evaluator v1`
- `#12 SOC Evaluator v1`
- `#13 Action Arbiter v1`
- `#8 軽量SoT機能 v1`
- `#14 Decision Explanation v1`
- `#15 AI補助の統治層 v1`
- `#16 通知機能 v1`
- `#17 最小監査ログ基盤 v1`
- `#5 Epic: P0 成立ライン`

## 2. P0 の判断パイプライン

1. `Tactical Engine` first-minute triage
2. `suricata_eve / noc_probe / syslog_min`
3. `Evidence Plane`
4. `NOC Evaluator` / `SOC Evaluator`
5. `Action Arbiter`
6. `Decision Explanation`
7. `Notification` / `AI Assist Governance`
8. `P0 Audit Logger`

## 3. 実装モジュール

### 3.1 Evidence Plane

- [`schema.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/schema.py)
- [`bus.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/bus.py)
- [`suricata.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/suricata.py)
- [`noc_probe.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/noc_probe.py)
- [`syslog_min.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/syslog_min.py)
- [`service.py`](/home/azazel/Azazel-Edge/py/azazel_edge/evidence_plane/service.py)

### 3.2 NOC Monitoring

- [`noc_monitor.py`](/home/azazel/Azazel-Edge/py/azazel_edge/sensors/noc_monitor.py)

collector:

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

action:

- `observe`
- `notify`
- `throttle`

### 3.5 SoT

- [`loader.py`](/home/azazel/Azazel-Edge/py/azazel_edge/sot/loader.py)

schema:

- `devices`
- `networks`
- `services`
- `expected_paths`

### 3.6 Explanation

- [`decision.py`](/home/azazel/Azazel-Edge/py/azazel_edge/explanations/decision.py)

required fields:

- `why_chosen`
- `why_not_others`
- `evidence_ids`
- `operator_wording`

### 3.7 AI Governance

- [`ai_governance.py`](/home/azazel/Azazel-Edge/py/azazel_edge/ai_governance.py)

guardrails:

- 条件一致時のみ AI 呼び出し
- sanitized payload のみ投入
- output は `advice / summary / candidate`
- adopt / fallback を監査

### 3.8 Notification

- [`delivery.py`](/home/azazel/Azazel-Edge/py/azazel_edge/notify/delivery.py)

adapters:

- `ntfy`
- `Mattermost`

### 3.9 Audit Logging

- [`logger.py`](/home/azazel/Azazel-Edge/py/azazel_edge/audit/logger.py)

P0 kind:

- `event_receive`
- `evaluation`
- `action_decision`
- `notification`
- `ai_assist`

共通項目:

- `ts`
- `kind`
- `trace_id`
- `source`

## 4. 現時点の制約

- evaluator / arbiter / explanation は library として実装済みだが、既存 web/daemon/ai-agent 全経路へ全面統合したわけではない
- P0 では deterministic evaluator を主とし、AI は補助に限定する
- 高度相関、容量予測、TI/YARA/Sigma、外部 CMDB 同期は P0 対象外

## 5. テスト

P0 追加テスト:

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
