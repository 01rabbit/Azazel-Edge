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

from azazel_edge.audit import P0AuditLogger
from azazel_edge.opencanary_redirect import OpenCanaryRedirectController


def _soc(high: bool) -> dict:
    if high:
        return {'suspicion': {'score': 90}, 'confidence': {'score': 85}}
    return {'suspicion': {'score': 20}, 'confidence': {'score': 20}}


class OpenCanaryRedirectV1Tests(unittest.TestCase):
    def test_redirect_only_for_high_confidence_soc_redirect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            config = Path(tmp) / 'opencanary.conf'
            config.write_text(json.dumps({'device.listen_addr': '127.0.0.1', 'http.port': 18080, 'ssh.port': 12222}), encoding='utf-8')
            controller = OpenCanaryRedirectController(
                audit_logger=audit,
                state_path=Path(tmp) / 'state.json',
                redirect_log_path=Path(tmp) / 'redirect.jsonl',
            )
            decision = controller.evaluate(
                arbiter={'action': 'redirect', 'chosen_evidence_ids': ['ev-1']},
                soc=_soc(high=True),
                target_ip='192.168.40.50',
                trace_id='trace-1',
                config_path=config,
            )
            applied = controller.apply(decision)
        self.assertTrue(decision['redirect'])
        self.assertTrue(applied['applied'])

    def test_noc_only_or_low_soc_does_not_redirect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            controller = OpenCanaryRedirectController(
                audit_logger=audit,
                state_path=Path(tmp) / 'state.json',
                redirect_log_path=Path(tmp) / 'redirect.jsonl',
            )
            decision = controller.evaluate(
                arbiter={'action': 'notify', 'chosen_evidence_ids': ['ev-1']},
                soc=_soc(high=False),
                target_ip='192.168.40.50',
                trace_id='trace-1',
            )
        self.assertFalse(decision['redirect'])

    def test_redirect_execution_is_audited(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / 'audit.jsonl'
            audit = P0AuditLogger(audit_path)
            config = Path(tmp) / 'opencanary.conf'
            config.write_text(json.dumps({'device.listen_addr': '127.0.0.1', 'http.port': 18080, 'ssh.port': 12222}), encoding='utf-8')
            controller = OpenCanaryRedirectController(
                audit_logger=audit,
                state_path=Path(tmp) / 'state.json',
                redirect_log_path=Path(tmp) / 'redirect.jsonl',
            )
            decision = controller.evaluate(
                arbiter={'action': 'redirect', 'chosen_evidence_ids': ['ev-1']},
                soc=_soc(high=True),
                target_ip='192.168.40.50',
                trace_id='trace-1',
                config_path=config,
            )
            controller.apply(decision)
            records = [json.loads(line) for line in audit_path.read_text(encoding='utf-8').splitlines()]
        self.assertEqual(records[-1]['kind'], 'action_decision')
        self.assertTrue(records[-1]['redirect'])


if __name__ == '__main__':
    unittest.main()
