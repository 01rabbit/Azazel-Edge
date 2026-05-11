from __future__ import annotations

import sys
import unittest
import os
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge_control import daemon as control_daemon


class NocRuntimeIntegrationV1Tests(unittest.TestCase):
    def test_resolve_monitor_scope_defaults_to_internal(self) -> None:
        with patch.dict(os.environ, {"AZAZEL_NOC_MONITOR_SCOPE": "internal"}, clear=False):
            scope = control_daemon._resolve_monitor_scope(
                {"up_if": "eth1", "gateway_ip": "192.168.40.1"},
                {"down_if": "usb0"},
            )
        self.assertEqual(scope["mode"], "internal")
        self.assertEqual(scope["up_if"], "br0")
        self.assertEqual(scope["cidr"], "172.16.0.0/24")

    def test_resolve_monitor_scope_supports_external_override(self) -> None:
        with patch.dict(os.environ, {"AZAZEL_NOC_MONITOR_SCOPE": "external"}, clear=False):
            scope = control_daemon._resolve_monitor_scope(
                {"up_if": "eth1", "gateway_ip": "192.168.40.1"},
                {"down_if": "usb0"},
            )
        self.assertEqual(scope["mode"], "external")
        self.assertEqual(scope["up_if"], "eth1")
        self.assertEqual(scope["gateway_ip"], "192.168.40.1")

    def test_build_noc_runtime_projection_maps_evaluation_into_dashboard_shape(self) -> None:
        evaluation = {
            "summary": {"status": "degraded", "degraded_mode": False, "reasons": ["capacity_health:degraded"]},
            "capacity_health": {"label": "degraded", "reasons": ["capacity_elevated:utilization_known"]},
            "service_health": {"label": "poor", "reasons": ["service_probe_failed:resolver-tcp", "service_window_down:resolver-tcp"]},
            "resolution_health": {"label": "critical", "reasons": ["resolution_failed:example.com", "resolution_window_failed:example.com"]},
            "config_drift_health": {"label": "degraded", "reasons": ["config_drift_detected", "config_drift:uplink_preference.preferred_uplink"]},
            "affected_scope": {
                "affected_uplinks": ["eth1"],
                "affected_segments": ["lan-main", "wan"],
                "related_service_targets": ["resolver-tcp"],
                "affected_client_count": 4,
                "critical_client_count": 1,
            },
            "incident_summary": {
                "incident_id": "incident:abc123",
                "probable_cause": "resolution_failure",
                "confidence": 0.88,
                "supporting_symptoms": ["resolution_health:resolution_window_failed:example.com"],
            },
            "evidence_ids": ["ev-1", "ev-2"],
        }
        payloads = [
            {
                "kind": "capacity_pressure",
                "attrs": {
                    "interface": "eth1",
                    "mode": "utilization_known",
                    "state": "elevated",
                    "avg_utilization_pct": 77.8,
                },
            },
            {
                "kind": "traffic_concentration",
                "attrs": {
                    "top_sources": [{"src_ip": "192.168.40.12", "bytes": 4096, "packets": 40, "flows": 3}],
                },
            },
        ]
        inventory = {
            "current_client_count": 6,
            "new_client_count": 1,
            "unknown_client_count": 1,
            "unauthorized_client_count": 0,
            "inventory_mismatch_count": 1,
            "stale_session_count": 0,
        }

        result = control_daemon._build_noc_runtime_projection(
            evaluation=evaluation,
            event_payloads=payloads,
            inventory_summary=inventory,
            preferred_uplink="eth1",
        )

        self.assertEqual(result["noc_summary"]["status"], "degraded")
        self.assertEqual(result["noc_capacity"]["state"], "elevated")
        self.assertEqual(result["noc_capacity"]["mode"], "utilization_known")
        self.assertEqual(result["noc_capacity"]["top_sources"][0]["src_ip"], "192.168.40.12")
        self.assertEqual(result["noc_client_inventory"]["current_client_count"], 6)
        self.assertEqual(result["noc_service_assurance"]["degraded_targets"], ["resolver-tcp"])
        self.assertEqual(result["noc_resolution_assurance"]["failed_targets"], ["example.com"])
        self.assertEqual(result["noc_blast_radius"]["affected_uplinks"], ["eth1"])
        self.assertEqual(result["noc_config_drift"]["status"], "drift")
        self.assertEqual(
            result["noc_config_drift"]["changed_fields"],
            ["uplink_preference.preferred_uplink"],
        )
        self.assertEqual(result["noc_incident_summary"]["incident_id"], "incident:abc123")
        self.assertEqual(result["noc_runtime"]["evidence_count"], 2)

    def test_enrich_snapshot_injects_live_noc_projection(self) -> None:
        projection = {
            "noc_summary": {"status": "degraded", "degraded_mode": False, "reasons": ["capacity_health:degraded"]},
            "noc_capacity": {"state": "elevated", "mode": "utilization_known", "utilization_pct": 71.2, "top_sources": [], "signals": []},
            "noc_client_inventory": {
                "current_client_count": 5,
                "new_client_count": 1,
                "unknown_client_count": 0,
                "unauthorized_client_count": 0,
                "inventory_mismatch_count": 0,
                "stale_session_count": 0,
            },
            "noc_service_assurance": {"status": "degraded", "degraded_targets": ["resolver-tcp"]},
            "noc_resolution_assurance": {"status": "degraded", "failed_targets": ["example.com"]},
            "noc_blast_radius": {"affected_uplinks": ["eth1"], "affected_segments": ["lan-main"], "related_service_targets": ["resolver-tcp"], "affected_client_count": 2, "critical_client_count": 0},
            "noc_config_drift": {"status": "normal", "baseline_state": "present", "changed_fields": [], "rollback_hint": ""},
            "noc_incident_summary": {"incident_id": "incident:test", "probable_cause": "service_assurance_failure", "confidence": 0.76, "supporting_symptoms": ["service_health:service_window_down:resolver-tcp"]},
            "noc_runtime": {"status": "degraded", "evidence_count": 4, "updated_epoch": 1.0},
        }

        with patch.object(control_daemon, "_default_route_info", return_value={"up_if": "eth1", "up_ip": "192.168.40.10", "gateway_ip": "192.168.40.1", "uplink_type": "ethernet"}), \
             patch.object(control_daemon, "_read_cpu_usage_percent", return_value=12.3), \
             patch.object(control_daemon, "_read_mem_usage", return_value=(30, 100, 512)), \
             patch.object(control_daemon, "_read_temp_c", return_value=45.2), \
             patch.object(control_daemon, "_read_signal_dbm", return_value=None), \
             patch.object(control_daemon.NETWORK_HEALTH, "assess", return_value={"status": "SAFE", "signals": [], "internet_check": "PASS", "captive_portal": "NO", "captive_portal_reason": "NOT_CAPTIVE"}), \
             patch.object(control_daemon, "_compute_live_noc_projection", return_value=projection):
            enriched = control_daemon._enrich_snapshot({"user_state": "SAFE", "internal": {"state_name": "NORMAL", "suspicion": 0}})

        self.assertIn("noc_capacity", enriched)
        self.assertEqual(enriched["noc_capacity"]["state"], "elevated")
        self.assertEqual(enriched["noc_service_assurance"]["degraded_targets"], ["resolver-tcp"])
        self.assertEqual(enriched["noc_incident_summary"]["incident_id"], "incident:test")
        self.assertEqual(enriched["monitor_scope"]["mode"], "internal")
        self.assertIn("br0", enriched["monitor_scope"]["label"])


if __name__ == "__main__":
    unittest.main()
