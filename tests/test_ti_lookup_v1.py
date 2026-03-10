from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.evaluators import SocEvaluator
from azazel_edge.explanations import DecisionExplainer
from azazel_edge.ti import load_ti_feed


class ThreatIntelLookupV1Tests(unittest.TestCase):
    def test_feed_loads_and_matches_ip_and_domain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ti.json'
            path.write_text(json.dumps({
                'indicators': [
                    {'type': 'ip', 'value': '10.0.0.5', 'confidence': 90, 'source': 'local', 'note': 'scanner'},
                    {'type': 'domain', 'value': 'evil.example', 'confidence': 80, 'source': 'local', 'note': 'c2'},
                ]
            }), encoding='utf-8')
            feed = load_ti_feed(path)
            matches = feed.match(['10.0.0.5'], ['evil.example'])
        self.assertEqual(len(matches), 2)

    def test_soc_evaluator_reflects_ti_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'ti.json'
            path.write_text(json.dumps({
                'indicators': [{'type': 'ip', 'value': '10.0.0.5', 'confidence': 90, 'source': 'local', 'note': 'scanner'}]
            }), encoding='utf-8')
            feed = load_ti_feed(path)
            evaluator = SocEvaluator(ti_feed=feed)
            result = evaluator.evaluate([{
                'event_id': 'soc-1',
                'ts': '2026-03-10T00:00:01Z',
                'source': 'suricata_eve',
                'kind': 'alert',
                'subject': '10.0.0.5->192.168.40.10:443/TCP',
                'severity': 65,
                'confidence': 0.8,
                'attrs': {
                    'sid': 210001,
                    'attack_type': 'Suspicious TLS Beacon',
                    'category': 'Potentially Bad Traffic',
                    'target_port': 443,
                    'risk_score': 65,
                    'confidence_raw': 80,
                },
            }])
        self.assertIn('ti_match_support', result['suspicion']['reasons'])
        self.assertTrue(result['summary']['ti_matches'])

    def test_decision_explanation_displays_ti_matches(self) -> None:
        explainer = DecisionExplainer()
        result = explainer.explain(
            noc={'summary': {'status': 'good'}},
            soc={'summary': {'status': 'high', 'ti_matches': [{'indicator_type': 'ip', 'value': '10.0.0.5'}]}},
            arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'chosen_evidence_ids': ['ev-1'], 'rejected_alternatives': []},
            target='edge-uplink',
        )
        self.assertIn('TI matches: ip:10.0.0.5', result['operator_wording'])


if __name__ == '__main__':
    unittest.main()
