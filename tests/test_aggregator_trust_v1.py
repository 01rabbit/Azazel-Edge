from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.aggregator import (
    AEVT_INGEST_ACCEPT,
    AEVT_INGEST_REJECT,
    AEVT_NODE_QUARANTINE,
    AEVT_NODE_REGISTER,
    AggregatorRegistry,
    FreshnessPolicy,
    compute_ingest_sig,
)

import azazel_edge_web.app as webapp

_SECRET = b"test-hmac-secret"


def _make_summary(node_id: str = "az-node-1", generated_at: float = 1000.0, **extra) -> dict:
    return {
        "trace_id": f"t-{node_id}-{generated_at}",
        "node": {"node_id": node_id, "site_id": "hq"},
        "timestamps": {"generated_at": generated_at},
        **extra,
    }


def _signed_summary(node_id: str = "az-node-1", generated_at: float = 1000.0, secret: bytes = _SECRET, **extra) -> dict:
    payload = _make_summary(node_id=node_id, generated_at=generated_at, **extra)
    payload["sig"] = compute_ingest_sig(payload, node_id, generated_at, secret)
    return payload


class AggregatorSigVerificationTests(unittest.TestCase):
    def _registry(self, **kw) -> AggregatorRegistry:
        return AggregatorRegistry(hmac_secret=_SECRET, sig_required=True, **kw)

    # --- sig_missing ---

    def test_sig_missing_raises(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(_make_summary())
        self.assertEqual(str(ctx.exception), "sig_missing")

    def test_sig_missing_when_sig_required_but_no_hmac_secret(self) -> None:
        r = AggregatorRegistry(sig_required=True, hmac_secret=None)
        r.register_node("az-node-1", "hq")
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(_make_summary())
        self.assertEqual(str(ctx.exception), "sig_missing")

    # --- sig_invalid ---

    def test_sig_invalid_raises(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(_make_summary(sig="deadbeef00000000"))
        self.assertEqual(str(ctx.exception), "sig_invalid")

    def test_sig_invalid_quarantines_node(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        with self.assertRaises(ValueError):
            r.ingest_summary(_make_summary(sig="wrong"))
        nodes = r.list_nodes()
        self.assertEqual(nodes[0]["status"], "quarantined")

    def test_sig_wrong_secret_raises(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        summary = _make_summary()
        summary["sig"] = compute_ingest_sig(summary, "az-node-1", 1000.0, b"other-secret")
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(summary)
        self.assertEqual(str(ctx.exception), "sig_invalid")

    # --- node_not_registered ---

    def test_unregistered_node_rejected(self) -> None:
        r = self._registry()
        summary = _signed_summary()
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(summary)
        self.assertEqual(str(ctx.exception), "node_not_registered")

    # --- node_quarantined ---

    def test_quarantined_node_rejected_even_with_valid_sig(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        # Trigger quarantine via invalid sig
        with self.assertRaises(ValueError):
            r.ingest_summary(_make_summary(sig="bad"))
        # Valid sig on a later timestamp — should still be rejected
        summary = _signed_summary(generated_at=2000.0)
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(summary)
        self.assertEqual(str(ctx.exception), "node_quarantined")

    # --- quarantine recovery ---

    def test_register_resets_quarantine_to_active(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        with self.assertRaises(ValueError):
            r.ingest_summary(_make_summary(sig="bad"))
        self.assertEqual(r.list_nodes()[0]["status"], "quarantined")
        r.register_node("az-node-1", "hq")
        self.assertEqual(r.list_nodes()[0]["status"], "active")

    def test_after_re_register_valid_ingest_accepted(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        with self.assertRaises(ValueError):
            r.ingest_summary(_make_summary(sig="bad"))
        r.register_node("az-node-1", "hq")
        summary = _signed_summary(generated_at=9000.0)
        result = r.ingest_summary(summary)
        self.assertTrue(result["ok"])

    # --- valid sig accepted ---

    def test_valid_sig_accepted(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        result = r.ingest_summary(_signed_summary())
        self.assertTrue(result["ok"])
        self.assertEqual(result["node_id"], "az-node-1")

    # --- sig field stripped from stored summary ---

    def test_sig_stripped_from_stored_summary(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        r.ingest_summary(_signed_summary())
        stored_summary = r.list_nodes()[0]["summary"]
        self.assertNotIn("sig", stored_summary or {})

    # --- backward-compat: no-sig mode ---

    def test_no_sig_mode_accepts_unsigned_payload(self) -> None:
        r = AggregatorRegistry()
        result = r.ingest_summary(_make_summary())
        self.assertTrue(result["ok"])


class AggregatorAntiReplayTests(unittest.TestCase):
    def _registry(self) -> AggregatorRegistry:
        return AggregatorRegistry(hmac_secret=_SECRET, sig_required=True, replay_window_sec=300)

    def test_replay_detected_on_duplicate(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        summary = _signed_summary()
        r.ingest_summary(summary)
        with self.assertRaises(ValueError) as ctx:
            r.ingest_summary(summary)
        self.assertEqual(str(ctx.exception), "replay_detected")

    def test_different_generated_at_not_replay(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        r.ingest_summary(_signed_summary(generated_at=1000.0))
        result = r.ingest_summary(_signed_summary(generated_at=2000.0))
        self.assertTrue(result["ok"])

    def test_different_node_same_timestamp_not_replay(self) -> None:
        r = self._registry()
        r.register_node("az-node-1", "hq")
        r.register_node("az-node-2", "hq")
        r.ingest_summary(_signed_summary(node_id="az-node-1", generated_at=1000.0))
        result = r.ingest_summary(_signed_summary(node_id="az-node-2", generated_at=1000.0))
        self.assertTrue(result["ok"])

    def test_expired_replay_window_allows_retry(self) -> None:
        r = AggregatorRegistry(hmac_secret=_SECRET, sig_required=True, replay_window_sec=1)
        r.register_node("az-node-1", "hq")
        summary = _signed_summary(generated_at=1000.0)
        r.ingest_summary(summary)
        # Manually expire the replay cache
        r._seen.clear()
        # Must also use a newer generated_at because older_summary_rejected kicks in
        summary2 = _signed_summary(generated_at=2000.0)
        result = r.ingest_summary(summary2)
        self.assertTrue(result["ok"])


class AggregatorTrustApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.auth_tokens_path = root / "auth_tokens.json"
        self.auth_tokens_path.write_text(
            json.dumps(
                {
                    "tokens": [
                        {"token": "operator-token", "principal": "operator-1", "role": "operator"},
                        {"token": "admin-token", "principal": "admin-1", "role": "admin"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.authz_log = root / "authz-events.jsonl"
        self.agg_audit_log = root / "aggregator-events.jsonl"
        self._orig = {
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "AUTH_TOKENS_FILE": webapp.AUTH_TOKENS_FILE,
            "AUTHZ_AUDIT_LOG": webapp.AUTHZ_AUDIT_LOG,
            "AGGREGATOR_AUDIT_LOG": webapp.AGGREGATOR_AUDIT_LOG,
            "_AGGREGATOR_REGISTRY": webapp._AGGREGATOR_REGISTRY,
            "AEVT_NODE_REGISTER": webapp.AEVT_NODE_REGISTER,
            "AEVT_INGEST_ACCEPT": webapp.AEVT_INGEST_ACCEPT,
            "AEVT_INGEST_REJECT": webapp.AEVT_INGEST_REJECT,
            "AEVT_NODE_QUARANTINE": webapp.AEVT_NODE_QUARANTINE,
        }
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.auth_tokens_path
        webapp.AUTHZ_AUDIT_LOG = self.authz_log
        webapp.AGGREGATOR_AUDIT_LOG = self.agg_audit_log
        webapp.AEVT_NODE_REGISTER = AEVT_NODE_REGISTER
        webapp.AEVT_INGEST_ACCEPT = AEVT_INGEST_ACCEPT
        webapp.AEVT_INGEST_REJECT = AEVT_INGEST_REJECT
        webapp.AEVT_NODE_QUARANTINE = AEVT_NODE_QUARANTINE
        webapp._AGGREGATOR_REGISTRY = AggregatorRegistry(
            policy=FreshnessPolicy(poll_interval_sec=30),
            hmac_secret=_SECRET,
            sig_required=True,
        )
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for k, v in self._orig.items():
            setattr(webapp, k, v)
        self.tmp.cleanup()

    def _register(self, node_id: str = "az-node-1") -> None:
        self.client.post(
            "/api/aggregator/nodes/register",
            headers={"X-AZAZEL-TOKEN": "admin-token"},
            json={"node_id": node_id, "site_id": "hq"},
        )

    def _audit_events(self) -> list:
        if not self.agg_audit_log.exists():
            return []
        return [json.loads(line) for line in self.agg_audit_log.read_text().splitlines() if line.strip()]

    # --- register audit ---

    def test_register_emits_audit_event(self) -> None:
        resp = self.client.post(
            "/api/aggregator/nodes/register",
            headers={"X-AZAZEL-TOKEN": "admin-token"},
            json={"node_id": "az-node-1", "site_id": "hq"},
        )
        self.assertEqual(resp.status_code, 200)
        events = self._audit_events()
        self.assertTrue(any(e["event"] == AEVT_NODE_REGISTER and e["node_id"] == "az-node-1" for e in events))

    def test_register_failure_emits_audit_event(self) -> None:
        resp = self.client.post(
            "/api/aggregator/nodes/register",
            headers={"X-AZAZEL-TOKEN": "admin-token"},
            json={"node_id": "", "site_id": "hq"},
        )
        self.assertEqual(resp.status_code, 400)
        events = self._audit_events()
        self.assertTrue(any(e["event"] == AEVT_NODE_REGISTER and not e.get("accepted") for e in events))

    # --- ingest accept audit ---

    def test_ingest_accept_emits_audit_event(self) -> None:
        self._register()
        now = time.time()
        summary = _signed_summary(generated_at=now)
        resp = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json=summary,
        )
        self.assertEqual(resp.status_code, 200)
        events = self._audit_events()
        self.assertTrue(any(e["event"] == AEVT_INGEST_ACCEPT and e["node_id"] == "az-node-1" for e in events))

    # --- ingest reject: sig_missing ---

    def test_ingest_sig_missing_emits_reject_audit(self) -> None:
        self._register()
        resp = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json=_make_summary(generated_at=time.time()),
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "sig_missing")
        events = self._audit_events()
        self.assertTrue(any(e["event"] == AEVT_INGEST_REJECT and e["reason"] == "sig_missing" for e in events))

    # --- ingest reject: sig_invalid triggers quarantine audit ---

    def test_ingest_sig_invalid_emits_quarantine_audit(self) -> None:
        self._register()
        summary = _make_summary(generated_at=time.time(), sig="badhex")
        resp = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json=summary,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "sig_invalid")
        events = self._audit_events()
        self.assertTrue(any(e["event"] == AEVT_NODE_QUARANTINE and e["reason"] == "sig_invalid" for e in events))

    # --- ingest reject: replay_detected ---

    def test_ingest_replay_emits_reject_audit(self) -> None:
        self._register()
        now = time.time()
        summary = _signed_summary(generated_at=now)
        self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json=summary,
        )
        resp = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json=summary,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "replay_detected")
        events = self._audit_events()
        self.assertTrue(any(e["event"] == AEVT_INGEST_REJECT and e["reason"] == "replay_detected" for e in events))

    # --- unregistered node ---

    def test_unregistered_node_returns_400(self) -> None:
        now = time.time()
        summary = _signed_summary(generated_at=now)
        resp = self.client.post(
            "/api/aggregator/ingest/summary",
            headers={"X-AZAZEL-TOKEN": "operator-token"},
            json=summary,
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.get_json()["error"], "node_not_registered")


if __name__ == "__main__":
    unittest.main()
