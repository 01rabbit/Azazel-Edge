from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass(frozen=True)
class FreshnessPolicy:
    poll_interval_sec: int = 30
    stale_multiplier: int = 2
    offline_multiplier: int = 6

    @property
    def stale_after_sec(self) -> int:
        return max(1, self.poll_interval_sec * self.stale_multiplier)

    @property
    def offline_after_sec(self) -> int:
        return max(self.stale_after_sec + 1, self.poll_interval_sec * self.offline_multiplier)


class AggregatorRegistry:
    def __init__(self, policy: FreshnessPolicy | None = None) -> None:
        self.policy = policy or FreshnessPolicy()
        self._lock = threading.Lock()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._summaries: Dict[str, Dict[str, Any]] = {}

    def register_node(self, node_id: str, site_id: str, node_label: str = "", trust_fingerprint: str = "") -> Dict[str, Any]:
        nid = str(node_id or "").strip()
        sid = str(site_id or "").strip()
        if not nid:
            raise ValueError("node_id_required")
        if not sid:
            raise ValueError("site_id_required")
        now = time.time()
        with self._lock:
            row = self._nodes.get(nid, {})
            created_at = float(row.get("created_at") or now)
            status = str(row.get("status") or "active")
            updated = {
                "node_id": nid,
                "site_id": sid,
                "node_label": str(node_label or "").strip(),
                "trust_fingerprint": str(trust_fingerprint or "").strip(),
                "status": status,
                "created_at": created_at,
                "updated_at": now,
            }
            self._nodes[nid] = updated
            return dict(updated)

    def ingest_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(summary, dict):
            raise ValueError("summary_must_be_object")
        trace_id = str(summary.get("trace_id") or "").strip()
        if not trace_id:
            raise ValueError("trace_id_required")
        node = summary.get("node")
        if not isinstance(node, dict):
            raise ValueError("node_object_required")
        node_id = str(node.get("node_id") or "").strip()
        site_id = str(node.get("site_id") or "").strip()
        if not node_id:
            raise ValueError("node.node_id_required")
        if not site_id:
            raise ValueError("node.site_id_required")

        now = time.time()
        timestamps = summary.get("timestamps") if isinstance(summary.get("timestamps"), dict) else {}
        generated_at = _coerce_epoch(timestamps.get("generated_at"), default=now)
        if generated_at > now + 300:
            raise ValueError("generated_at_in_future")
        with self._lock:
            existing = self._summaries.get(node_id)
            if isinstance(existing, dict):
                prev_generated_at = _coerce_epoch(
                    ((existing.get("timestamps") if isinstance(existing.get("timestamps"), dict) else {}) or {}).get("generated_at"),
                    default=0.0,
                )
                if generated_at < prev_generated_at:
                    raise ValueError("older_summary_rejected")
            self._summaries[node_id] = dict(summary)
            if node_id not in self._nodes:
                self._nodes[node_id] = {
                    "node_id": node_id,
                    "site_id": site_id,
                    "node_label": str(node.get("node_label") or "").strip(),
                    "trust_fingerprint": "",
                    "status": "active",
                    "created_at": now,
                    "updated_at": now,
                }
            else:
                self._nodes[node_id]["updated_at"] = now
            return {
                "ok": True,
                "trace_id": trace_id,
                "node_id": node_id,
                "generated_at": generated_at,
                "received_at": now,
            }

    def list_nodes(self, now_epoch: float | None = None) -> List[Dict[str, Any]]:
        now = float(now_epoch if now_epoch is not None else time.time())
        with self._lock:
            nodes = [dict(v) for v in self._nodes.values()]
            summaries = {k: dict(v) for k, v in self._summaries.items()}
        result: List[Dict[str, Any]] = []
        for row in sorted(nodes, key=lambda x: str(x.get("node_id") or "")):
            nid = str(row.get("node_id") or "")
            summary = summaries.get(nid, {})
            timestamps = summary.get("timestamps") if isinstance(summary.get("timestamps"), dict) else {}
            generated_at = _coerce_epoch(timestamps.get("generated_at"), default=0.0)
            received_at = float(row.get("updated_at") or 0.0)
            last_seen_epoch = generated_at if generated_at > 0 else received_at
            freshness = _freshness_status(last_seen_epoch, now, self.policy)
            result.append(
                {
                    **row,
                    "last_seen_epoch": last_seen_epoch if last_seen_epoch > 0 else None,
                    "freshness": freshness,
                    "summary": summary if summary else None,
                }
            )
        return result


def _coerce_epoch(value: Any, default: float) -> float:
    if value in (None, ""):
        return float(default)
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return float(default)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        from datetime import datetime

        return float(datetime.fromisoformat(text).timestamp())
    except Exception:
        return float(default)


def _freshness_status(last_seen_epoch: float, now_epoch: float, policy: FreshnessPolicy) -> str:
    if last_seen_epoch <= 0:
        return "offline"
    age = max(0.0, now_epoch - last_seen_epoch)
    if age <= float(policy.stale_after_sec):
        return "fresh"
    if age <= float(policy.offline_after_sec):
        return "stale"
    return "offline"
