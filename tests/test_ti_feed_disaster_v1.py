from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import SocEvaluator
from azazel_edge.ti import load_ti_feed


class TiFeedDisasterV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.disaster_path = ROOT / 'config' / 'ti' / 'disaster_ioc.yaml'
        self.phishing_path = ROOT / 'config' / 'ti' / 'shelter_phishing.yaml'

    def test_disaster_ioc_yaml_loads_without_error(self) -> None:
        feed = load_ti_feed(self.disaster_path)
        self.assertGreater(len(feed.indicators), 0)

    def test_shelter_phishing_yaml_loads_without_error(self) -> None:
        feed = load_ti_feed(self.phishing_path)
        self.assertGreaterEqual(len(feed.indicators), 10)

    def test_phishing_domain_matches(self) -> None:
        feed = load_ti_feed(self.disaster_path)
        matches = feed.match(ips=[], domains=['saigai-kyufu.net'])
        self.assertTrue(matches)
        self.assertEqual(matches[0].indicator_type, 'domain')

    def test_malicious_ip_matches(self) -> None:
        feed = load_ti_feed(self.disaster_path)
        matches = feed.match(ips=['198.51.100.42'], domains=[])
        self.assertTrue(matches)
        self.assertEqual(matches[0].value, '198.51.100.42')

    def test_inactive_indicator_not_matched(self) -> None:
        feed = load_ti_feed(self.disaster_path)
        matches = feed.match(ips=[], domains=['inactive-disaster-fake.example'])
        self.assertEqual(matches, [])

    def test_technique_id_present_on_match(self) -> None:
        feed = load_ti_feed(self.disaster_path)
        matches = feed.match(ips=['198.51.100.42'], domains=[])
        self.assertTrue(matches)
        self.assertEqual(matches[0].to_dict().get('technique_id'), 'T1071')

    def test_ti_feed_integrates_with_soc_evaluator(self) -> None:
        evaluator = SocEvaluator()
        result = evaluator.evaluate([
            {
                'event_id': 'soc-ti-1',
                'ts': '2026-05-13T00:00:01Z',
                'source': 'suricata_eve',
                'kind': 'alert',
                'subject': '198.51.100.42->192.168.40.10:443/TCP',
                'severity': 70,
                'confidence': 0.8,
                'attrs': {
                    'sid': 210001,
                    'attack_type': 'Potentially Bad Traffic',
                    'category': 'Malware Command and Control Activity Detected',
                    'risk_score': 70,
                    'confidence_raw': 80,
                    'domain': 'saigai-kyufu.net',
                    'url': '/kyufu/apply',
                },
            }
        ])
        self.assertIn('ti_match_support', result['suspicion']['reasons'])
        ti_matches = result.get('summary', {}).get('ti_matches', [])
        self.assertTrue(ti_matches)
        self.assertTrue(any(str(item.get('technique_id') or '').startswith('T') for item in ti_matches))


if __name__ == '__main__':
    unittest.main()
