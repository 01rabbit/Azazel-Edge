from __future__ import annotations

import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import SocEvaluator
from azazel_edge.sigma import MiniSigmaExecutor


def _load_rules(path: Path):
    payload = yaml.safe_load(path.read_text(encoding='utf-8'))
    return list(payload.get('rules') or [])


class SigmaRulesDisasterV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.disaster_path = ROOT / 'config' / 'sigma' / 'disaster_shelter.yaml'
        self.network_path = ROOT / 'config' / 'sigma' / 'network_anomaly.yaml'

    def test_disaster_shelter_yaml_loads_and_parses(self) -> None:
        rules = _load_rules(self.disaster_path)
        self.assertGreaterEqual(len(rules), 5)

    def test_network_anomaly_yaml_loads_and_parses(self) -> None:
        rules = _load_rules(self.network_path)
        self.assertGreaterEqual(len(rules), 3)

    def test_azsh001_matches_on_subject_bypass(self) -> None:
        executor = MiniSigmaExecutor(_load_rules(self.disaster_path))
        hits = executor.match([{
            'event_id': 'ev-1',
            'source': 'captive_portal',
            'kind': 'auth_anomaly',
            'subject': 'operator bypass attempt',
            'severity': 3,
            'attrs': {'category': 'auth'},
        }])
        self.assertTrue(any(hit.get('rule_id') == 'AZSH-001' for hit in hits))

    def test_azsh005_matches_config_changed_event(self) -> None:
        executor = MiniSigmaExecutor(_load_rules(self.disaster_path))
        hits = executor.match([{
            'event_id': 'ev-2',
            'source': 'config_drift',
            'kind': 'config_change',
            'subject': 'critical config changed on gateway',
            'severity': 2,
            'attrs': {},
        }])
        self.assertTrue(any(hit.get('rule_id') == 'AZSH-005' for hit in hits))

    def test_no_false_match_on_unrelated_event(self) -> None:
        executor = MiniSigmaExecutor(_load_rules(self.disaster_path))
        hits = executor.match([{
            'event_id': 'ev-3',
            'source': 'sensor_ok',
            'kind': 'info',
            'subject': 'normal heartbeat',
            'severity': 1,
            'attrs': {},
        }])
        self.assertEqual(hits, [])

    def test_min_severity_filter_respected(self) -> None:
        executor = MiniSigmaExecutor(_load_rules(self.disaster_path))
        hits = executor.match([{
            'event_id': 'ev-4',
            'source': 'audit',
            'kind': 'defense_evasion',
            'subject': 'write_failed audit sink',
            'severity': 3,
            'attrs': {},
        }])
        self.assertFalse(any(hit.get('rule_id') == 'AZSH-004' for hit in hits))

    def test_sigma_integrates_with_soc_evaluator(self) -> None:
        evaluator = SocEvaluator()
        result = evaluator.evaluate([
            {
                'event_id': 'soc-sigma-1',
                'ts': '2026-05-13T00:00:01Z',
                'source': 'suricata_eve',
                'kind': 'alert',
                'subject': '198.51.100.1->192.168.40.10:443/TCP',
                'severity': 70,
                'confidence': 0.8,
                'attrs': {
                    'sid': 210001,
                    'attack_type': 'Potentially Bad Traffic',
                    'category': 'Malware Command and Control Activity Detected',
                    'risk_score': 70,
                    'confidence_raw': 80,
                },
            },
            {
                'event_id': 'ev-sigma-2',
                'source': 'noc_inventory',
                'kind': 'identity_anomaly',
                'subject': 'expected_link_mismatch on uplink',
                'severity': 2,
                'attrs': {},
            },
        ])
        sigma_hits = result.get('summary', {}).get('sigma_hits', [])
        self.assertTrue(any(hit.get('rule_id') == 'AZNET-002' for hit in sigma_hits))


if __name__ == '__main__':
    unittest.main()
