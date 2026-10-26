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
- [`p0_alert.py`](/home/azazel/Azazel-Edge/py/azazel_edge/notify/p0_alert.py): the P0 visual/voice queue (`p0-alert-queue.jsonl`, SO-03). Notification only; nothing reads it back into the decision or enforcement path.
- [`core_decisions.py`](/home/azazel/Azazel-Edge/py/azazel_edge/notify/core_decisions.py): records the Rust core's P0 decisions in `core-decision-audit.jsonl` for that queue.

Startup reconcile of P0 decisions the agent missed (Edge#460, Edge#462 item 5):
- At start the agent reads the tail of the core's `normalized-events.jsonl` (at most 8 MiB) and records the P0 decisions its chain does not have, the newest 256 at most (`core_reconcile_skipped` counts the rest). Their alerts carry `reconciled: true` and the event's own `event_ts`.
- A decision older than 300 s (the core's default enforcement lease), or whose time cannot be read, is no longer a current alert, but it is still recorded and alerted so that an isolate applied while the agent was down reaches the operator. It is marked `reconcile_stale` in the chain and `stale: true`, `presentation: historical` in the queue; the visual text starts with 「過去の判定（<event time, UTC>）」, the voice text announces it as a past decision, and the voice entry has `voice_urgent: false`. Renderers use `render_p0_alert` or honour these fields.
- Counted in the `core_reconcile` status record as `core_reconcile_stale` (found) and `core_reconciled_stale` (recorded); stale and fresh decisions share the one 256 bound, so a long outage cannot flood the queue.
- A stale decision is in the chain under its core event key once recorded, so a later start neither records nor alerts it again.
- The P0 relay's own reconcile (decisions in the chain but not in the queue, e.g. an enqueue lost to a crash, or a new queue on an old chain) applies the same 300 s rule from the record's own time (`event_ts`, else `core_ingest_epoch`, else the record's `ts`; past when none can be read). Live alerts are never marked past. Core event times are not authenticated, so in both reconciles a time more than 60 s (`CLOCK_SKEW_TOLERANCE_S`) in the future, or a non-finite number (NaN, ±inf), counts as unreadable, i.e. past. The alert text shows `reason` and `target` on one line, at most 200 characters each.

Chain rotation, per-chain cursor and loss recovery (Edge#462 items 1, 3, 4; notification and audit only, the Rust core's `decide_defense` → `maybe_enforce` stays the only enforcement authority):
- **Rotation.** The agent opens `core-decision-audit.jsonl` with `max_bytes` 16 MiB and one rotated file kept (`core-decision-audit.jsonl.1`). Before a record is appended, a file of 16 MiB or more is renamed to `.1` (the previous `.1` is removed), so the retained chain is at most about 32 MiB, within the recorder's 32 MiB key window. Rotation happens on a chain boundary: the chain is not restarted. The new file's first record has `chain_prev` = the last record of `.1` and carries `chain_id` (the chain's identity: the genesis record's `chain_hash`). A failed rotation is counted (`rotate_failed_total`) and the record is appended to the active file; no record is lost. `P0AuditLogger.verify_rotated_chain` verifies the retained files as one chain (`anchored: true` when older files were rotated out; what was before them is not verified). Loggers built without `max_bytes` (the AI audit log, the SO evidence chains) are unchanged.
- **Readers.** The relay's reconcile and the recorder's key window read the retained files as one snapshot (`azazel_edge.audit.segments.read_chain`): every file is opened first and the snapshot is retaken if a rotation moved a file in between. A rotated file that does not continue the next newer one (for example a host logrotate copy with the same name) is not read and is counted as `chain_unlinked_segments`. Keep the core decision chain out of host logrotate.
- **Cursor and rotation.** A cursor in `.1` is found as before (`cursor_found`). A cursor in a file rotation already removed (possible only if more than one file's worth of chain was written while the queue's cursor did not advance) is reported as `cursor_rotated_out`: every retained record is after it, so the retained P0 decisions not in the queue are replayed (newest 256), never counted as `unreconcilable`. `cursor_not_in_chain` remains for a chain that was cut back or replaced without rotation, and for a cursor written before cursors were per chain that the chain does not have.
- **Cursor per chain.** Every alert and every relay_status record that carries `audit_cursor_chain_hash` also carries `audit_chain_id`. Each relay resumes from the last cursor of its own chain, so a relay with another chain sharing the queue no longer makes later reconciles `unreconcilable`. A chain with no cursor in a queue that has other chains' cursors is reconciled as `fresh_chain` (like `fresh_queue`). A cursor written before this change (no `audit_chain_id`) is used only while the queue holds no per-chain cursor at all; the status record's `cursor_scope` says which (`chain`, `legacy`, `none`).
- **Loss recovery without a restart.** A P0 decision the recorder's hand-off dropped (`core_record_loss`) is remembered by its core event key (at most 4096, the newest). Once the hand-off is at most half full, at most once a second, the recorder's writer reads the tail of `normalized-events.jsonl` (the core writes it before forwarding) and records those decisions with `recorded_by: loss_reconcile`, under the item 5 rules: older than 300 s (or of unreadable time) is `reconcile_stale` and alerted as a past decision; at most 256 per pass (the newest); deduplicated by the core event key. The relay does the same for records its own hand-off, or the audit logger's listener hand-off, dropped: it looks them up by chain hash in the chain and alerts them as reconciled, at most 256 per pass, without a cursor (the queue's cursor never moves back). Each pass writes a `core_loss_reconcile` or `loss_recovery` status record; keys the log tail (or the chain) no longer has, and anything over a bound, are counted as unrecovered (`core_loss_unrecovered_total`, `loss_unrecovered_total`). Events the core itself could not forward (`core_forward_loss`) have no key in the agent; the next start's reconcile still covers them.

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
