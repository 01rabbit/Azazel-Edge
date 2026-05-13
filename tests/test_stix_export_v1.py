from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from azazel_edge.integrations.stix_export import STIXExporter, _stix_id


class STIXExportV1Tests(unittest.TestCase):
    def test_build_bundle_has_required_fields(self) -> None:
        exporter = STIXExporter()
        bundle = exporter.build_bundle([{"type": "indicator", "id": "indicator--x"}])
        self.assertEqual(bundle["type"], "bundle")
        self.assertIn("id", bundle)
        self.assertEqual(bundle["spec_version"], "2.1")
        self.assertIn("objects", bundle)

    def test_arbiter_to_sighting_produces_valid_object(self) -> None:
        exporter = STIXExporter()
        sighting = exporter.arbiter_to_sighting(
            {
                "action": "notify",
                "reason": "soc_high_but_noc_fragile",
                "evidence_ids": ["ev-1"],
                "trace_id": "trace-1",
                "level": "warning",
                "ts": "2026-05-13T00:00:00Z",
            }
        )
        self.assertEqual(sighting["type"], "sighting")
        self.assertIn("sighting_of_ref", sighting)

    def test_suricata_to_indicator_produces_valid_object(self) -> None:
        exporter = STIXExporter()
        indicator = exporter.suricata_alert_to_indicator(
            {
                "src_ip": "10.0.0.5",
                "dest_ip": "192.168.40.10",
                "alert": {"signature": "ET MALWARE Something", "signature_id": 9901101},
            },
            technique_id="T1566",
        )
        self.assertEqual(indicator["type"], "indicator")
        self.assertIn("pattern", indicator)
        self.assertEqual(indicator["pattern_type"], "stix")

    def test_action_to_coa_maps_all_five_actions(self) -> None:
        exporter = STIXExporter()
        for action in ("observe", "notify", "throttle", "redirect", "isolate"):
            coa = exporter.action_to_course_of_action(action, rationale="test")
            self.assertEqual(coa["type"], "course-of-action")
            self.assertIn("id", coa)
            self.assertIn(action, coa["name"])

    def test_export_audit_window_returns_bundle(self) -> None:
        exporter = STIXExporter()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "triage-audit.jsonl"
            rows = [
                {
                    "ts": "2026-05-13T00:00:00Z",
                    "kind": "action_decision",
                    "trace_id": "t-1",
                    "action": "notify",
                    "reason": "soc_high_but_noc_fragile",
                    "chosen_evidence_ids": ["ev-1", "ev-2"],
                    "level": "warning",
                },
                {"ts": "2026-05-13T00:00:01Z", "kind": "evaluation", "trace_id": "t-2"},
            ]
            path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            bundle = exporter.export_audit_window(path, max_entries=10)
        self.assertEqual(bundle["type"], "bundle")
        self.assertGreaterEqual(len(bundle["objects"]), 2)

    def test_stix_id_is_deterministic(self) -> None:
        a = _stix_id("indicator", "same-key")
        b = _stix_id("indicator", "same-key")
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
