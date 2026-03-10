from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.integrations import JsonlMirrorSink, UpstreamEnvelopeBuilder, WebhookSink


class _Resp:
    def __init__(self, status: int = 202):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class UpstreamIntegrationV1Tests(unittest.TestCase):
    def test_builds_normalized_envelope(self) -> None:
        envelope = UpstreamEnvelopeBuilder().build(
            trace_id='trace-up-1',
            noc={'summary': {'status': 'good', 'reasons': ['stable']}, 'evidence_ids': ['n1']},
            soc={'summary': {'status': 'high', 'reasons': ['suspicion:high'], 'attack_candidates': ['T1071']}, 'evidence_ids': ['s1']},
            arbiter={'action': 'notify', 'reason': 'soc_high_but_noc_fragile', 'control_mode': 'none', 'chosen_evidence_ids': ['s1']},
            explanation={'operator_wording': 'Notify operator', 'next_checks': ['check_1']},
        )
        self.assertEqual(envelope['trace_id'], 'trace-up-1')
        self.assertEqual(envelope['decision']['action'], 'notify')
        self.assertEqual(envelope['soc']['attack_candidates'][0], 'T1071')

    def test_jsonl_mirror_sink_persists_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'upstream.jsonl'
            result = JsonlMirrorSink(path).publish({'trace_id': 'trace-up-2'})
            row = json.loads(path.read_text(encoding='utf-8').splitlines()[0])
        self.assertTrue(result['ok'])
        self.assertEqual(row['trace_id'], 'trace-up-2')

    def test_webhook_sink_posts_json(self) -> None:
        with patch('azazel_edge.integrations.upstream.request.urlopen', return_value=_Resp(status=204)) as mocked:
            result = WebhookSink('https://example.invalid/hook').publish({'trace_id': 'trace-up-3'})
        self.assertTrue(result['ok'])
        mocked.assert_called_once()


if __name__ == '__main__':
    unittest.main()
