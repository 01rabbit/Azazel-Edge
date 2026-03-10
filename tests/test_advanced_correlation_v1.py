from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.correlation import AdvancedCorrelator
from azazel_edge.evaluators import SocEvaluator
from azazel_edge.explanations import DecisionExplainer
from azazel_edge.evidence_plane import EvidenceEvent


def _suricata() -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:00:00Z',
        source='suricata_eve',
        kind='alert',
        subject='10.0.0.5->192.168.40.10:443/TCP',
        severity=82,
        confidence=0.88,
        attrs={
            'sid': 210010,
            'attack_type': 'Suspicious TLS Beacon',
            'category': 'Potentially Bad Traffic',
            'target_port': 443,
            'risk_score': 82,
            'confidence_raw': 88,
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
        },
        status='alert',
    )


def _flow() -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:01:00Z',
        source='flow_min',
        kind='flow_summary',
        subject='10.0.0.5->192.168.40.10:443/TCP',
        severity=45,
        confidence=0.70,
        attrs={
            'src_ip': '10.0.0.5',
            'dst_ip': '192.168.40.10',
            'dst_port': 443,
            'flow_state': 'failed',
            'app_proto': 'tls',
        },
        status='warn',
    )


def _syslog() -> EvidenceEvent:
    return EvidenceEvent.build(
        ts='2026-03-10T00:02:00Z',
        source='syslog_min',
        kind='syslog_line',
        subject='10.0.0.5->192.168.40.10:443/TCP',
        severity=60,
        confidence=0.75,
        attrs={'message': 'failed TLS proxy session', 'host': 'edge', 'tag': 'haproxy'},
        status='warn',
    )


class AdvancedCorrelationV1Tests(unittest.TestCase):
    def test_correlator_builds_multi_source_cluster(self) -> None:
        result = AdvancedCorrelator().correlate([_suricata(), _flow(), _syslog()])
        self.assertEqual(result['status'], 'high')
        self.assertGreaterEqual(result['cluster_count'], 1)
        self.assertIn('suricata_flow_alignment', result['clusters'][0]['reasons'])
        self.assertIn('syslog_support', result['clusters'][0]['reasons'])

    def test_soc_evaluator_exposes_correlation_summary(self) -> None:
        result = SocEvaluator().evaluate([_suricata(), _flow(), _syslog()])
        self.assertIn('correlation', result['summary'])
        self.assertGreaterEqual(result['summary']['correlation']['top_score'], 50)
        self.assertIn('correlation_support', result['suspicion']['reasons'])

    def test_explanation_mentions_correlation(self) -> None:
        soc = SocEvaluator().evaluate([_suricata(), _flow(), _syslog()])
        explanation = DecisionExplainer(output_path=Path('/tmp/unused-correlation-expl.jsonl')).explain(
            noc={'summary': {'status': 'good'}},
            soc=soc,
            arbiter={
                'action': 'notify',
                'reason': 'soc_high_but_noc_fragile',
                'control_mode': 'none',
                'client_impact': {'score': 0, 'affected_client_count': 0, 'critical_client_count': 0},
                'chosen_evidence_ids': soc['evidence_ids'],
                'rejected_alternatives': [],
            },
            target='edge-uplink',
        )
        self.assertIn('correlation', explanation['why_chosen'])
        self.assertIn('Correlation', explanation['operator_wording'])


if __name__ == '__main__':
    unittest.main()
