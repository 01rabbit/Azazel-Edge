# Azazel Aggregator Architecture (Design)

Last Updated: 2026-05-12  
Status: Design baseline for issue #186 (implementation deferred)

## 1. Purpose

This document defines a lightweight `Azazel Aggregator` that unifies health/risk/action summaries from multiple Azazel-Edge nodes without replacing each node's local-first deterministic path.

The design preserves:
- Deterministic First at each edge node
- Offline-capable local operation when links are unstable or unavailable
- Raspberry Pi-class operational constraints on nodes
- Auditability of cross-node summaries

## 2. Design Principles

1. Edge remains authoritative.
Each node executes `Evidence Plane -> Evaluators -> Action Arbiter` locally. Aggregator never issues first-line decisions.

2. Aggregator is optional.
If aggregator is down, nodes continue monitoring and acting locally.

3. Low-bandwidth first.
Transport and payloads prioritize compact summary exchange, not raw event replication.

4. Security by default.
Node-to-aggregator communication is authenticated, tamper-evident, and fail-closed.

5. Not a SIEM.
Aggregator provides operational situational awareness, not full centralized analytics/log retention.

## 3. System Overview

### 3.1 Components

- Edge Node (existing Azazel-Edge runtime)
  - Produces deterministic outcomes and local audit logs.
  - Exposes summary API endpoint (pull mode) and optional summary export queue (push/offline mode).

- Aggregator Service (new component)
  - Collects node summaries.
  - Maintains in-memory + bounded local store of latest node snapshots.
  - Computes freshness/staleness and fleet-level risk rollups.

- Aggregated Dashboard (new or extended web view)
  - Per-node health/risk/status board.
  - Fleet overview timeline using summary points only.

### 3.2 Data Flow Modes

1. HTTPS polling (default)
- Aggregator polls each registered node `/api/state/summary` on fixed interval.
- Suitable for stable LAN / VPN links.

2. Push mode (optional)
- Node pushes summary bundle to aggregator `/api/ingest/summary`.
- Suitable for constrained NAT or intermittent uplink where pull is difficult.

3. Offline bundle transfer (optional)
- Node exports signed summary bundle file.
- Operator imports into aggregator for delayed synchronization.

4. Local MQTT broker (optional transport)
- Topic-scoped summary publish/subscribe for field environments already using MQTT.
- Must remain optional and minimized to summary payloads.

## 4. Node Identity and Registration

## 4.1 Identity model

Each node uses a stable identity:
- `node_id` (required): immutable unique ID (`az-node-<site>-<serial>` recommended)
- `site_id` (required): logical deployment/site grouping
- `node_label` (optional): operator-friendly display name
- `node_pubkey_fingerprint` (required): pinned trust identity

## 4.2 Registration states

- `pending`: discovered but not approved
- `active`: approved and ingesting summaries
- `quarantined`: temporarily blocked due to trust/signature mismatch
- `retired`: no longer expected in fleet view

Registration update events must be audit-logged.

## 5. Minimal Node Summary Schema

The schema is intentionally compact and deterministic.

```json
{
  "schema_version": "1.0",
  "trace_id": "agg-...",
  "node": {
    "node_id": "az-node-hq-01",
    "site_id": "hq",
    "node_label": "HQ Gateway 01"
  },
  "timestamps": {
    "generated_at": "2026-05-12T03:00:00Z",
    "node_uptime_sec": 98231
  },
  "health": {
    "status": "ok",
    "cpu_percent": 28.4,
    "memory_percent": 63.2,
    "temperature_c": 58.9,
    "ops_guard_min_mem_mb": 1400,
    "ops_guard_current_mem_mb": 1650
  },
  "risk": {
    "current_level": "watch",
    "score": 67,
    "policy_version": "2026.05",
    "policy_hash": "sha256:..."
  },
  "alerts": {
    "queue_now": 2,
    "queue_watch": 7,
    "queue_backlog": 3,
    "suppressed_count": 5,
    "escalation_candidates": 1
  },
  "actions": {
    "recent": [
      {
        "action": "throttle",
        "target": "10.0.10.42",
        "decision_time": "2026-05-12T02:58:10Z",
        "trace_id": "dec-..."
      }
    ]
  },
  "audit": {
    "chain_tip": "sha256:...",
    "records_since_boot": 4219
  },
  "sig": {
    "alg": "hmac-sha256",
    "key_id": "node-hq-01-k1",
    "value": "base64..."
  }
}
```

Schema rules:
- `trace_id` required for every summary message.
- `actions.recent` bounded to a small fixed size (for example, 10).
- No raw packet payloads or full EVE logs in aggregator summary schema.
- Unknown fields must be ignored by aggregator for forward compatibility.

## 6. Stale/Offline Behavior

Aggregator computes per-node freshness from `generated_at` and last successful ingest:

- `fresh`: last summary <= 2 x poll interval
- `stale`: > 2 x poll interval and <= 6 x poll interval
- `offline`: > 6 x poll interval or explicit transport failure threshold exceeded

Behavior:
- `stale`: keep last known risk/action snapshot; render warning badge and age counter.
- `offline`: keep last known snapshot with degraded confidence label; exclude from "current healthy nodes" counters.
- Never overwrite newer node snapshot with an older timestamp.
- Conflict resolution rule: `newer generated_at` wins; equal timestamp with different digest -> mark `conflict` and audit.

## 7. Security Assumptions and Controls

1. Trust bootstrap is explicit.
Node identity and trust material are pre-registered (or approved via operator flow) before `active`.

2. Mutual authentication.
Preferred: mTLS with pinned certificate fingerprints.  
Fallback: HTTPS + per-node HMAC key rotation policy.

3. Message integrity.
Each summary includes signature over canonical payload and `trace_id`.

4. Replay protection.
Aggregator stores recent nonce or `(node_id, generated_at, digest)` set and rejects duplicates/replays.

5. Least privilege API model.
Separate registration/ingest/read scopes; no ingest token can read fleet dashboard data.

6. Fail-closed behavior.
If signature verification or trust mapping fails, summary is not accepted and node moves to `quarantined` when threshold is met.

7. Audit continuity.
Registration, ingest accept/reject, stale/offline transitions, and conflict events are audit-logged with reason.

## 8. Aggregated Dashboard Model

Fleet dashboard minimum cards:
- Node Count: `active / stale / offline / quarantined`
- Fleet Risk Mix: `normal / watch / high / critical` counts
- Recent Actions Feed: last N actions across fleet (summary-only)
- Link Health: ingest success/failure rate by node

Per-node panel minimum:
- identity (`node_id`, `site_id`, label)
- freshness state + last seen age
- health metrics snapshot
- current risk level and score
- recent actions summary
- latest audit chain tip indicator

## 9. Out of Scope (Intentional)

The following are explicitly excluded from this design phase and MVP:
- Centralized raw log storage and long-term SIEM retention
- Cross-node automatic enforcement orchestration
- Aggregator-triggered direct action execution on nodes
- Full historical analytics warehouse
- Multi-tenant RBAC complexity beyond baseline operator/admin roles

## 10. Implementation Roadmap

## 10.1 MVP

Scope:
- Node registration table (`pending/active/quarantined/retired`)
- HTTPS polling transport
- `/api/state/summary` schema v1.0
- Fresh/stale/offline state engine
- Fleet dashboard summary view
- Audit log for ingest and state transitions

Exit criteria:
- Aggregator outage does not affect node local deterministic path
- At least 10 nodes can be tracked with bounded memory footprint
- Staleness/offline behavior proven via tests/simulation

## 10.2 Field-Ready

Scope:
- Push mode endpoint
- Key rotation and trust lifecycle tooling
- Conflict diagnostics and replay detection hardening
- Offline summary bundle export/import
- Operational runbooks for degraded links

Exit criteria:
- Intermittent-link deployments can maintain coherent fleet view
- Operator can rotate node trust without node redeploy

## 10.3 Extended

Scope:
- Optional MQTT transport adapter
- Fleet-level trend snapshots (still summary-only)
- Lightweight cross-site federation between aggregators

Exit criteria:
- Multi-site distributed operations can share high-level posture without SIEM scope creep

## 11. Implementation Notes

- Keep implementation isolated from `Action Arbiter` execution logic.
- Never bypass `AI Assist Governance` for any future aggregator-side AI summary assistance.
- Reuse existing dashboard trends/alert queue primitives where possible to reduce complexity.

## 12. Mapping to Issue #186 Acceptance Criteria

- Architecture document under `docs/`: satisfied by this document.
- Minimal node summary schema: Section 5.
- Stale/offline behavior: Section 6.
- Security assumptions: Section 7.
- Roadmap MVP/field-ready/extended: Section 10.
- Intentional out-of-scope: Section 9.
