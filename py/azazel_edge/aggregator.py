from __future__ import annotations

import hashlib
import hmac as _hmac
import json as _json
import threading
import time
import urllib.error
import urllib.request
import uuid
import ssl
from dataclasses import dataclass
from typing import Any, Dict, List

# Fixed audit event kind constants
AEVT_NODE_REGISTER = "aggregator.node.register"
AEVT_INGEST_ACCEPT = "aggregator.ingest.accept"
AEVT_INGEST_REJECT = "aggregator.ingest.reject"
AEVT_NODE_QUARANTINE = "aggregator.node.quarantine"


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


def _stable_json(obj: Any) -> str:
    return _json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hmac_sha256_hex(secret: bytes, message: str) -> str:
    return _hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def compute_ingest_sig(summary_without_sig: Dict[str, Any], node_id: str, generated_at: float, secret: bytes) -> str:
    """Compute the HMAC-SHA256 ingest signature for a node to attach as `sig`."""
    digest = _sha256_hex(_stable_json(summary_without_sig))
    claims: Dict[str, Any] = {
        "digest": digest,
        "generated_at": float(generated_at),
        "node_id": str(node_id),
    }
    return _hmac_sha256_hex(secret, _stable_json(claims))


def verify_ingest_sig(summary_without_sig: Dict[str, Any], node_id: str, generated_at: float, sig_hex: str, secret: bytes) -> bool:
    """Verify the HMAC-SHA256 ingest signature in constant time."""
    expected = compute_ingest_sig(summary_without_sig, node_id, generated_at, secret)
    return _hmac.compare_digest(expected, str(sig_hex or "").lower())


class AggregatorRegistry:
    def __init__(
        self,
        policy: FreshnessPolicy | None = None,
        *,
        hmac_secret: bytes | None = None,
        sig_required: bool = False,
        replay_window_sec: int = 300,
    ) -> None:
        self.policy = policy or FreshnessPolicy()
        self.hmac_secret = hmac_secret
        self.sig_required = bool(sig_required)
        self.replay_window_sec = max(1, int(replay_window_sec))
        self._lock = threading.Lock()
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._summaries: Dict[str, Dict[str, Any]] = {}
        self._seen: Dict[str, float] = {}  # replay cache: key → expiry epoch

    def register_node(
        self,
        node_id: str,
        site_id: str,
        node_label: str = "",
        trust_fingerprint: str = "",
        poll_url: str = "",
    ) -> Dict[str, Any]:
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
            # Admin re-registration always resets to active, clearing any quarantine
            updated = {
                "node_id": nid,
                "site_id": sid,
                "node_label": str(node_label or "").strip(),
                "trust_fingerprint": str(trust_fingerprint or "").strip(),
                "poll_url": str(poll_url or "").strip(),
                "status": "active",
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

        # Compute digest over payload without the sig field
        payload_for_digest = {k: v for k, v in summary.items() if k != "sig"}
        digest = _sha256_hex(_stable_json(payload_for_digest))
        replay_key = f"{node_id}\x00{generated_at}\x00{digest}"

        # Signature verification (stateless — before acquiring the lock)
        sig = str(summary.get("sig") or "").strip()
        sig_fail = False
        if self.hmac_secret is not None or self.sig_required:
            if not sig:
                raise ValueError("sig_missing")
            if self.hmac_secret is not None:
                if not verify_ingest_sig(payload_for_digest, node_id, generated_at, sig, self.hmac_secret):
                    sig_fail = True

        with self._lock:
            if sig_fail:
                # Auto-quarantine: node stays registered but can no longer ingest
                if node_id in self._nodes:
                    self._nodes[node_id]["status"] = "quarantined"
                    self._nodes[node_id]["updated_at"] = now
                raise ValueError("sig_invalid")

            node_rec = self._nodes.get(node_id)
            if (self.hmac_secret is not None or self.sig_required) and node_rec is None:
                raise ValueError("node_not_registered")
            if node_rec is not None and str(node_rec.get("status") or "active") == "quarantined":
                raise ValueError("node_quarantined")

            # Replay detection
            self._prune_seen(now)
            if replay_key in self._seen:
                raise ValueError("replay_detected")

            existing = self._summaries.get(node_id)
            if isinstance(existing, dict):
                prev_generated_at = _coerce_epoch(
                    ((existing.get("timestamps") if isinstance(existing.get("timestamps"), dict) else {}) or {}).get("generated_at"),
                    default=0.0,
                )
                if generated_at < prev_generated_at:
                    raise ValueError("older_summary_rejected")

            self._seen[replay_key] = now + self.replay_window_sec
            # Strip sig before storing
            self._summaries[node_id] = {k: v for k, v in summary.items() if k != "sig"}
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

    def _prune_seen(self, now: float) -> None:
        expired = [k for k, exp in self._seen.items() if exp <= now]
        for k in expired:
            del self._seen[k]


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


class PollError(RuntimeError):
    pass


class AggregatorPoller:
    def __init__(
        self,
        registry: AggregatorRegistry,
        poll_interval_sec: int = 30,
        node_timeout_sec: int = 5,
        hmac_secret: bytes | None = None,
    ) -> None:
        self.registry = registry
        self.poll_interval_sec = max(5, int(poll_interval_sec))
        self.node_timeout_sec = max(2, int(node_timeout_sec))
        self.hmac_secret = hmac_secret
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._poll_loop, daemon=True, name="aggregator-poller")
        self._thread.start()

    def stop(self, timeout_sec: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout_sec)

    def poll_node_once(self, node_id: str, node_url: str) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(
                str(node_url),
                headers={"Accept": "application/json", "X-Azazel-Poller": "1"},
            )
            with urllib.request.urlopen(req, timeout=self.node_timeout_sec, context=ctx) as resp:
                raw = resp.read(1_048_576)
            payload = _json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise PollError(f"poll_invalid_payload:{node_id}")
            return payload
        except Exception as exc:
            raise PollError(f"poll_failed:{node_id}:{exc}") from exc

    def _poll_loop(self) -> None:
        while not self._stop_event.wait(timeout=self.poll_interval_sec):
            nodes = self.registry.list_nodes()
            for node in nodes:
                if self._stop_event.is_set():
                    break
                node_id = str(node.get("node_id") or "").strip()
                poll_url = str(node.get("poll_url") or "").strip()
                if not node_id or not poll_url:
                    continue
                if str(node.get("status") or "").strip() == "quarantined":
                    continue
                try:
                    summary = self.poll_node_once(node_id, poll_url)
                    if not isinstance(summary.get("node"), dict):
                        summary["node"] = {"node_id": node_id, "site_id": str(node.get("site_id") or "").strip()}
                    if not summary.get("trace_id"):
                        summary["trace_id"] = f"pull-{uuid.uuid4().hex[:12]}"
                    timestamps = summary.get("timestamps") if isinstance(summary.get("timestamps"), dict) else {}
                    if not timestamps.get("generated_at"):
                        summary["timestamps"] = {"generated_at": time.time()}
                    if self.hmac_secret:
                        payload_for_sig = {k: v for k, v in summary.items() if k != "sig"}
                        ts = _coerce_epoch(
                            ((summary.get("timestamps") if isinstance(summary.get("timestamps"), dict) else {}) or {}).get(
                                "generated_at"
                            ),
                            default=time.time(),
                        )
                        summary["sig"] = compute_ingest_sig(payload_for_sig, node_id, ts, self.hmac_secret)
                    self.registry.ingest_summary(summary)
                except Exception:
                    continue
