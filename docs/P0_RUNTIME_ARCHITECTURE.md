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
- **Rotation.** The agent opens `core-decision-audit.jsonl` with `max_bytes` 16 MiB and one rotated file (`core-decision-audit.jsonl.1`; `keep` other than 1 is rejected). Before a record is appended, a file of 16 MiB or more is renamed to `.1` (the previous `.1` is removed), so the retained chain is at most about 32 MiB, within the recorder's 32 MiB key window. Rotation happens on a chain boundary: the chain is not restarted. The new file's first record has `chain_prev` = the last record of `.1` and carries `chain_id` (the chain's identity: the genesis record's `chain_hash`). A crash at either step of a rotation leaves the active file or `.1` holding the chain's last record, and a new logger continues from it. A failed rotation is counted (`rotate_failed_total`) and the record is appended to the active file; no record is lost. `P0AuditLogger.verify_rotated_chain` verifies the retained files as one chain (`anchored: true` when older files were rotated out; what was before them is not verified). `azazel-edge-audit-review --audit-path …/core-decision-audit.jsonl` verifies the same snapshot (`audit_review.verify_audit_chain`) and prints what was verified: `scope` `from_genesis` or `from_rotation_boundary` (= `anchored`), the files read and the `chain_id`; a `.1` the active file does not continue (`chain_unlinked_segments`), a cut start, a foreign `chain_id`, or any rewritten, removed or reordered record fails (exit 3), and a missing or empty file is `EMPTY`, not `OK` (`chain.ok` stays true for it, `chain.verified` is false). Not detected: records removed from the end, a removed `.1` or active file, or both files replaced by another chain consistent in itself; compare the printed `chain_id` with the relay's `audit_chain_id`. A `snapshot_inconsistent` failure (rotations kept moving files) passes on a rerun. Loggers built without `max_bytes` (the AI audit log, the SO evidence chains) are unchanged.
- **Readers.** The relay's reconcile and the recorder's key window read the retained files as one snapshot (`azazel_edge.audit.segments.read_chain`): every file is opened first and the snapshot is retaken if a rotation moved a file in between. A rotated file that the next newer file does not continue (its first record's `chain_prev` is not the rotated file's last record; for example a host logrotate copy with the same name) is not read and is counted as `chain_unlinked_segments`. Keep the core decision chain out of host logrotate.
- **Cursor per audit file and chain.** Every alert and every relay_status record that carries `audit_cursor_chain_hash` also carries `audit_path` (the relay's audit file) and `audit_chain_id`. Each relay resumes from the last cursor of its own file and chain, so a relay of another audit file sharing the queue no longer makes later reconciles `unreconcilable`. The relay_status record's `cursor_scope` says which cursor was used (`chain`, `legacy`, `replaced`, `none`). Outcomes:
  - `cursor_found`: the cursor is in the retained chain, `.1` included; what came after it is replayed.
  - `cursor_rotated_out`: the cursor is older than every retained file. This needs the active file to continue a rotated `.1` (checked link) and the oldest retained record not to be the genesis. Every retained record is after the cursor, so the retained P0 decisions not in the queue are replayed (newest 256).
  - `fresh_chain`: the queue has cursors, but none of this audit file (another relay shares the queue). Every P0 decision in the chain not in the queue is replayed (newest 256).
  - `chain_replaced`: the queue has a cursor of this audit file but of another chain: the file was replaced by a new chain, or its start was cut off. Nothing is replayed; the chain's P0 decisions not in the queue are counted as `unreconcilable`, and the next start resumes from the new chain.
  - `cursor_not_in_chain`: this chain's cursor is not in the retained chain and no checked rotation explains it (the file was cut back, or a forged head copies the chain id without a `.1` it continues), or a legacy cursor the chain does not have. Nothing is replayed; counted as `unreconcilable`.
  - A cursor written before cursors were scoped (no `audit_chain_id`) is used when the queue has no cursor of this audit file: before this change only the agent relay wrote the queue.
- **Replays without this chain's cursor are past decisions.** Alerts replayed by `fresh_chain` or `cursor_rotated_out` are always `stale: true`, `presentation: historical`, `voice_urgent: false`, whatever the record's own time says: nothing places them relative to what the queue last alerted on.
- **Not authenticated.** Chain ids, chain hashes and record times are not keyed. A process that can write the audit file (or the core's normalized event log) can forge records, including a head that copies the chain's id or a `.1` that links. These rules keep a replaced, cut or foreign file from being replayed by accident; they are not a defence against a forger (the same holds for appended records today; see Edge#462 item 2). The effect of a forgery stays within notifications. Who can forge (Edge#462): `ai-bridge.sock` is in its own directory (`/run/azazel-edge-ai`, 0700, the agent's account; root under the shipped units), the socket is 0600, and neither takes `AZAZEL_RUNTIME_SOCKET_GROUP`; `normalized-events.jsonl` and `core-decision-audit.jsonl` are written by root with mode 0644. So members of the shared group can no longer connect to the socket or replace it, and only root, or a process running as the agent's account, can connect to, replace the socket, or write those files. Root can still forge, and the core and the Web UI do not verify the peer of the socket they connect to (Edge#471). Real protection needs privilege separation (the core and the Web UI in their own accounts with a peer-uid check) or authenticated socket traffic, which is tracked separately. Not validated on a VM or on hardware.
- **Loss recovery without a restart.** A P0 decision the recorder's hand-off dropped (`core_record_loss`) is remembered by its core event key (at most 4096, the newest). Once the hand-off is at most half full, at most once a second, the recorder's writer reads the tail of `normalized-events.jsonl` (at most 8 MiB; the core writes it before forwarding) and records those decisions with `recorded_by: loss_reconcile`, under the item 5 rules: older than 300 s (or of unreadable time) is `reconcile_stale` and alerted as a past decision; at most 256 per pass (the newest); deduplicated by the core event key. The relay does the same for records its own hand-off, or the audit logger's listener hand-off, dropped: it looks them up by chain hash in the newest 4 MiB of the chain (not the whole retained chain) and alerts them as reconciled, at most 256 per pass, without a cursor (the queue's cursor never moves back). Each pass writes a `core_loss_reconcile` or `loss_recovery` status record; keys the log tail (or the chain tail) no longer has, and anything over a bound, are counted as unrecovered (`core_loss_unrecovered_total`, `loss_unrecovered_total`).
- **Limits of loss recovery.** The dropped keys are kept in memory only. For the recorder, a decision not recovered before the agent stops is not in the chain, so the next start's reconcile still finds it in the log tail. For the relay, a record not recovered before a crash is in the chain but not in the queue. If the queue's cursor had already moved past it, the next start neither replays nor counts it. It can then be told only by comparing the chain with the queue. Events the core itself could not forward (`core_forward_loss`) have no key in the agent; the next start's reconcile covers them.

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
