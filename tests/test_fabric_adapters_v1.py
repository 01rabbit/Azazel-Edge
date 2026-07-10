"""Phase 3 — Azazel-Fabric emit-alongside adapters.

Covers the three §3 projections (DecisionExplanation, TrustCapsule, AuditEvent)
plus the owner-directed StatusView emit/read-back extension. Each adapter is
verified to (a) write a Fabric-shaped projection to a *separate* stream, (b)
leave Edge's native output byte-for-byte unchanged, (c) never raise into its
caller on failure, and (d) become a clean no-op when azazel_fabric is absent
(simulated by toggling the guarded-import flag).
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from azazel_edge.audit import P0AuditLogger
from azazel_edge.audit import fabric_adapter as audit_fabric
from azazel_edge.explanations import DecisionExplainer
from azazel_edge.explanations import fabric_adapter as expl_fabric
from azazel_edge import fabric_view


def _sample_explain(explainer: DecisionExplainer):
    return explainer.explain(
        noc={"summary": {"status": "good"}},
        soc={"summary": {"status": "critical", "ai_attack_candidates": ["T1190"]}},
        arbiter={
            "action": "redirect",
            "reason": "soc_high_confidence_redirect",
            "release_condition": "noc_recovers",
            "chosen_evidence_ids": ["ev1", "ev2"],
            "rejected_alternatives": [{"action": "notify", "reason": "too_weak"}],
            "policy": {"version": "p1", "hash": "cfg123"},
        },
        trace_id="trace-xyz",
        persist=True,
    )


class DecisionProjectionTests(unittest.TestCase):
    def test_projection_written_with_expected_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "decision-explanations.jsonl"
            _sample_explain(DecisionExplainer(output_path=out))
            proj = out.with_name(expl_fabric.DECISION_PROJECTION_NAME)
            self.assertTrue(proj.exists())
            row = json.loads(proj.read_text(encoding="utf-8").strip())
            self.assertEqual(row["trace_id"], "trace-xyz")
            self.assertEqual(row["selected_action"]["kind"], "redirect")
            self.assertEqual(row["selected_action"]["issued_by"], "edge_arbiter")
            self.assertEqual([e["evidence_id"] for e in row["selected_action"]["evidence"]], ["ev1", "ev2"])
            self.assertIsInstance(row["why_chosen"], str)
            self.assertEqual(row["why_not_others"], ["notify: too_weak"])
            self.assertEqual(row["release_condition"], "noc_recovers")
            self.assertIsInstance(row["confidence"], float)

    def test_trust_capsule_projection_field_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "decision-explanations.jsonl"
            _sample_explain(DecisionExplainer(output_path=out))
            proj = out.with_name(expl_fabric.TRUST_PROJECTION_NAME)
            self.assertTrue(proj.exists())
            row = json.loads(proj.read_text(encoding="utf-8").strip())
            # Field renames per plan §3.2: hmac_sig->hmac, timestamp->issued_at,
            # config_hash sourced from the explanation's top-level config_hash.
            self.assertEqual(set(row.keys()), {"trace_id", "config_hash", "hmac", "issued_at"})
            self.assertEqual(row["trace_id"], "trace-xyz")
            self.assertEqual(row["config_hash"], "cfg123")
            self.assertTrue(row["hmac"])
            self.assertTrue(row["issued_at"])

    def test_native_stream_byte_identical_with_and_without_adapter(self) -> None:
        # Adapter enabled.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "decision-explanations.jsonl"
            _sample_explain(DecisionExplainer(output_path=out))
            native_on = out.read_bytes()
        # Adapter disabled (simulate azazel_fabric absent).
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(expl_fabric, "HAVE_AZAZEL_FABRIC", False):
            out = Path(tmp) / "decision-explanations.jsonl"
            _sample_explain(DecisionExplainer(output_path=out))
            native_off = out.read_bytes()
            # No projection files at all when the package is absent.
            self.assertFalse(out.with_name(expl_fabric.DECISION_PROJECTION_NAME).exists())
            self.assertFalse(out.with_name(expl_fabric.TRUST_PROJECTION_NAME).exists())
        self.assertEqual(native_on, native_off)

    def test_adapter_failure_never_raises_into_caller(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            expl_fabric, "build_decision_projection", side_effect=RuntimeError("boom")
        ):
            out = Path(tmp) / "decision-explanations.jsonl"
            # Must not raise even though the projection blows up.
            _sample_explain(DecisionExplainer(output_path=out))
            self.assertEqual(len(out.read_text(encoding="utf-8").splitlines()), 1)


class AuditProjectionTests(unittest.TestCase):
    def test_projection_to_separate_file_and_chain_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            chain = Path(tmp) / "audit.jsonl"
            log = P0AuditLogger(chain)
            log.log_action_decision("trace-1", "arbiter", action="redirect")
            log.log_event_receive("trace-1", "suricata", event_id="e1")

            # Original hash chain still verifies.
            self.assertEqual(P0AuditLogger.verify_chain(chain)["ok"], True)

            fabric_path = audit_fabric.fabric_stream_path(chain)
            self.assertNotEqual(fabric_path, chain)
            self.assertTrue(fabric_path.exists())
            rows = [json.loads(l) for l in fabric_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual([r["event_type"] for r in rows], ["action_decision", "event_receive"])
            for r in rows:
                self.assertEqual(r["product"], "edge")
                self.assertTrue(r["event_id"])
                self.assertIn("chain_hash", r["payload"])
                self.assertIn("chain_prev", r["payload"])
                self.assertIn("source", r["payload"])

            # The chained file itself carries no AuditEvent fields.
            native_rows = [json.loads(l) for l in chain.read_text(encoding="utf-8").splitlines()]
            self.assertNotIn("event_id", native_rows[0])
            self.assertNotIn("product", native_rows[0])

    def test_no_package_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(audit_fabric, "HAVE_AZAZEL_FABRIC", False):
            chain = Path(tmp) / "audit.jsonl"
            log = P0AuditLogger(chain)
            log.log_action_decision("trace-1", "arbiter", action="redirect")
            self.assertEqual(P0AuditLogger.verify_chain(chain)["ok"], True)
            self.assertFalse(audit_fabric.fabric_stream_path(chain).exists())

    def test_projection_failure_never_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            audit_fabric, "build_audit_event", side_effect=RuntimeError("boom")
        ):
            chain = Path(tmp) / "audit.jsonl"
            log = P0AuditLogger(chain)
            rec = log.log_action_decision("trace-1", "arbiter", action="redirect")
            self.assertEqual(rec["kind"], "action_decision")
            self.assertEqual(P0AuditLogger.verify_chain(chain)["ok"], True)


class StatusViewTests(unittest.TestCase):
    SNAP = {
        "now_time": "12:00:00",
        "snapshot_epoch": 1720000000.0,
        "user_state": "CONTAIN",
        "recommendation": "Redirect suspicious flows",
        "reasons": ["suricata_sid=2001 risk=88"],
        "evidence": ["CRITICAL sid=2001 exploit"],
        "suricata_critical": 1,
        "suricata_warning": 0,
        "internal": {"state_name": "CONTAIN", "suspicion": 88},
        "connection": {"wifi_state": "CONNECTED", "uplink_if": "wlan0", "uplink_type": "wifi"},
        "attack": {"suricata_alert": True},
    }

    def test_build_status_view_carries_full_snapshot(self) -> None:
        view = fabric_view.status_view_from_snapshot(self.SNAP)
        self.assertIsNotNone(view)
        data = json.loads(view.model_dump_json())
        self.assertEqual(data["product"], "edge")
        self.assertEqual(data["posture"], "contain")
        self.assertEqual(data["operator_wording"], "Redirect suspicious flows")
        # Peer, not subset: the whole snapshot rides in product_view.
        self.assertEqual(data["product_view"]["edge_snapshot"], self.SNAP)

    def test_write_alongside_and_noop_without_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snap_path = Path(tmp) / "ui_snapshot.json"
            snap_path.write_text("{}", encoding="utf-8")
            fabric_view.write_status_view_alongside(self.SNAP, [snap_path])
            view_path = snap_path.with_name(fabric_view.STATUS_VIEW_NAME)
            self.assertTrue(view_path.exists())
            json.loads(view_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(fabric_view, "HAVE_AZAZEL_FABRIC", False):
            snap_path = Path(tmp) / "ui_snapshot.json"
            snap_path.write_text("{}", encoding="utf-8")
            fabric_view.write_status_view_alongside(self.SNAP, [snap_path])
            self.assertFalse(snap_path.with_name(fabric_view.STATUS_VIEW_NAME).exists())

    def test_write_alongside_never_raises_on_bad_path(self) -> None:
        # A non-path-like entry must not propagate an exception.
        fabric_view.write_status_view_alongside(self.SNAP, [object()])


class ApiStateStatusViewTests(unittest.TestCase):
    def setUp(self) -> None:
        import azazel_edge_web.app as webapp

        self.webapp = webapp
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self._orig = {
            "STATE_PATH": webapp.STATE_PATH,
            "FALLBACK_STATE_PATH": webapp.FALLBACK_STATE_PATH,
            "AUTH_FAIL_OPEN": webapp.AUTH_FAIL_OPEN,
            "load_token": webapp.load_token,
        }
        self.snap_path = root / "ui_snapshot.json"
        self.snap_path.write_text("{}", encoding="utf-8")
        webapp.STATE_PATH = self.snap_path
        webapp.FALLBACK_STATE_PATH = self.snap_path
        webapp.AUTH_FAIL_OPEN = True
        webapp.load_token = lambda: None
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        for k, v in self._orig.items():
            setattr(self.webapp, k, v)
        self.tmp.cleanup()

    def test_status_view_key_null_when_absent(self) -> None:
        res = self.client.get("/api/state")
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertIn("status_view", body)
        self.assertIsNone(body["status_view"])

    def test_status_view_key_populated_when_present(self) -> None:
        view = fabric_view.status_view_from_snapshot(StatusViewTests.SNAP)
        self.snap_path.with_name("ui_status_view.json").write_text(view.model_dump_json(), encoding="utf-8")
        res = self.client.get("/api/state")
        self.assertEqual(res.status_code, 200)
        body = res.get_json()
        self.assertIsNotNone(body["status_view"])
        self.assertEqual(body["status_view"]["product"], "edge")
        self.assertEqual(body["status_view"]["posture"], "contain")


if __name__ == "__main__":
    unittest.main()
