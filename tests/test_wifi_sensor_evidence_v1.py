from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evidence_plane import EvidenceBus, EvidencePlaneService
from azazel_edge.evidence_plane.service import _wifi_congestion_severity


class WifiSensorEvidenceV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = EvidencePlaneService(EvidenceBus())
        self.service._own_bssid = 'aa:bb:cc:dd:ee:ff'

    def test_dispatch_wifi_scan_low_congestion_severity_1(self) -> None:
        result = self.service.dispatch_wifi_scan({'congestion_level': 'low', 'ap_count': 2, 'current_channel': 6, 'recommended_channel': 11, 'scan_success': True})
        self.assertTrue(result)
        self.assertEqual(result.get('severity'), 1)

    def test_dispatch_wifi_scan_critical_congestion_severity_4(self) -> None:
        result = self.service.dispatch_wifi_scan({'congestion_level': 'critical', 'ap_count': 25, 'current_channel': 6, 'recommended_channel': 149, 'scan_success': True})
        self.assertTrue(result)
        self.assertEqual(result.get('severity'), 4)

    def test_dispatch_wifi_scan_produces_evidence_event(self) -> None:
        result = self.service.dispatch_wifi_scan({'congestion_level': 'medium', 'ap_count': 7, 'current_channel': 1, 'recommended_channel': 11, 'scan_success': True})
        self.assertEqual(result.get('source'), 'wifi_channel_scanner')
        self.assertEqual(result.get('kind'), 'noc_wifi')
        self.assertIn('wifi_congestion:medium', str(result.get('subject') or ''))
        self.assertIn('trace_id', result.get('attrs', {}))

    def test_dispatch_rogue_ap_flags_evil_twin(self) -> None:
        nearby = [
            {'ssid': 'ShelterWiFi', 'bssid': '11:22:33:44:55:66', 'signal': -45},
            {'ssid': 'ShelterWiFi', 'bssid': 'aa:bb:cc:dd:ee:ff', 'signal': -35},
        ]
        events = self.service.dispatch_rogue_ap('ShelterWiFi', nearby)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].get('kind'), 'noc_wifi_rogue_ap')

    def test_dispatch_rogue_ap_no_flag_on_different_ssid(self) -> None:
        nearby = [{'ssid': 'OtherSSID', 'bssid': '11:22:33:44:55:66', 'signal': -55}]
        events = self.service.dispatch_rogue_ap('ShelterWiFi', nearby)
        self.assertEqual(events, [])

    def test_wifi_congestion_severity_map_all_levels(self) -> None:
        self.assertEqual(_wifi_congestion_severity('low'), 1)
        self.assertEqual(_wifi_congestion_severity('medium'), 2)
        self.assertEqual(_wifi_congestion_severity('high'), 3)
        self.assertEqual(_wifi_congestion_severity('critical'), 4)


if __name__ == '__main__':
    unittest.main()
