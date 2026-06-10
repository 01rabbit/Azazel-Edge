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

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.audit import P0AuditLogger
from azazel_edge.demo.playback import scenario_summary
from azazel_edge.opencanary_redirect import OpenCanaryRedirectController


def _dim(score: int, label: str, evidence_ids: list) -> dict:
    return {'score': score, 'label': label, 'reasons': [], 'evidence_ids': evidence_ids}


def _noc_all_good() -> dict:
    return {
        'availability': _dim(98, 'good', ['noc-a']),
        'path_health': _dim(98, 'good', ['noc-p']),
        'device_health': _dim(98, 'good', ['noc-d']),
        'client_health': _dim(98, 'good', ['noc-c']),
        'summary': {'status': 'good', 'reasons': []},
        'evidence_ids': ['noc-a', 'noc-p', 'noc-d', 'noc-c'],
    }


def _soc_redirect_eligible() -> dict:
    """SOC state that triggers the redirect path:
    suspicion.score=92/critical, confidence.score=84/critical, blast=72/high.
    These satisfy redirect gate (suspicion>=90, confidence>=80, blast>=70)
    but not isolate gate (suspicion>=95, confidence>=90, blast>=80).
    Also satisfies OpenCanaryRedirectController threshold (suspicion>=80, confidence>=70).
    """
    return {
        'suspicion': _dim(92, 'critical', ['soc-s']),
        'confidence': _dim(84, 'critical', ['soc-c']),
        'technique_likelihood': _dim(70, 'high', ['soc-t']),
        'blast_radius': _dim(72, 'high', ['soc-b']),
        'summary': {'status': 'critical', 'reasons': []},
        'evidence_ids': ['soc-s', 'soc-c', 'soc-t', 'soc-b'],
    }


class DecisionStreamTraceabilityV1Tests(unittest.TestCase):

    def _build_redirect_arbiter(self) -> dict:
        """Build a real arbiter dict via ActionArbiter().decide() on the redirect path."""
        return ActionArbiter().decide(_noc_all_good(), _soc_redirect_eligible())

    # ------------------------------------------------------------------
    # Test 1: evaluate() decision dict carries the four traceability fields
    # ------------------------------------------------------------------
    def test_evaluate_carries_traceability_fields(self) -> None:
        arbiter = self._build_redirect_arbiter()
        self.assertEqual(arbiter['action'], 'redirect',
                         "Precondition: arbiter must choose redirect for this test to be meaningful")

        with tempfile.TemporaryDirectory() as tmp:
            audit = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            config = Path(tmp) / 'opencanary.conf'
            config.write_text(
                json.dumps({'device.listen_addr': '127.0.0.1', 'http.port': 18080, 'ssh.port': 12222}),
                encoding='utf-8',
            )
            controller = OpenCanaryRedirectController(
                audit_logger=audit,
                state_path=Path(tmp) / 'state.json',
                redirect_log_path=Path(tmp) / 'redirect.jsonl',
            )
            soc = _soc_redirect_eligible()
            decision = controller.evaluate(
                arbiter=arbiter,
                soc=soc,
                target_ip='192.168.40.50',
                trace_id='trace-traceability-1',
                config_path=config,
            )

        self.assertTrue(decision.get('redirect'), "evaluate() must return redirect=True")

        # release_condition
        self.assertTrue(
            decision.get('release_condition'),
            "release_condition must be non-empty in evaluate() result",
        )
        self.assertEqual(
            decision['release_condition'],
            arbiter['release_condition'],
            "release_condition in decision must equal arbiter['release_condition']",
        )

        # rejected_alternatives
        self.assertIsInstance(
            decision.get('rejected_alternatives'),
            list,
            "rejected_alternatives must be a list in evaluate() result",
        )
        self.assertEqual(
            decision['rejected_alternatives'],
            arbiter['rejected_alternatives'],
            "rejected_alternatives in decision must equal arbiter['rejected_alternatives']",
        )

        # config_hash
        self.assertTrue(
            decision.get('config_hash'),
            "config_hash must be non-empty in evaluate() result",
        )
        self.assertEqual(
            decision['config_hash'],
            arbiter['policy']['hash'],
            "config_hash in decision must equal arbiter['policy']['hash']",
        )

        # policy_profile
        self.assertTrue(
            decision.get('policy_profile'),
            "policy_profile must be non-empty in evaluate() result",
        )
        self.assertEqual(
            decision['policy_profile'],
            arbiter['policy']['version'],
            "policy_profile in decision must equal arbiter['policy']['version']",
        )

    # ------------------------------------------------------------------
    # Test 2: apply() writes audit record carrying all four fields; chain valid
    # ------------------------------------------------------------------
    def test_apply_audit_record_carries_traceability_fields(self) -> None:
        arbiter = self._build_redirect_arbiter()
        self.assertEqual(arbiter['action'], 'redirect')

        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / 'audit.jsonl'
            audit = P0AuditLogger(audit_path)
            config = Path(tmp) / 'opencanary.conf'
            config.write_text(
                json.dumps({'device.listen_addr': '127.0.0.1', 'http.port': 18080, 'ssh.port': 12222}),
                encoding='utf-8',
            )
            controller = OpenCanaryRedirectController(
                audit_logger=audit,
                state_path=Path(tmp) / 'state.json',
                redirect_log_path=Path(tmp) / 'redirect.jsonl',
            )
            decision = controller.evaluate(
                arbiter=arbiter,
                soc=_soc_redirect_eligible(),
                target_ip='192.168.40.50',
                trace_id='trace-traceability-2',
                config_path=config,
            )
            controller.apply(decision)

            records = [
                json.loads(line)
                for line in audit_path.read_text(encoding='utf-8').splitlines()
                if line.strip()
            ]

        action_decision_records = [r for r in records if r.get('kind') == 'action_decision']
        self.assertEqual(len(action_decision_records), 1)
        rec = action_decision_records[0]

        self.assertEqual(
            rec.get('release_condition'),
            arbiter['release_condition'],
            "audit record release_condition must match arbiter",
        )
        self.assertEqual(
            rec.get('rejected_alternatives'),
            arbiter['rejected_alternatives'],
            "audit record rejected_alternatives must match arbiter",
        )
        self.assertEqual(
            rec.get('config_hash'),
            arbiter['policy']['hash'],
            "audit record config_hash must match arbiter policy.hash",
        )
        self.assertEqual(
            rec.get('policy_profile'),
            arbiter['policy']['version'],
            "audit record policy_profile must match arbiter policy.version",
        )

        # Audit chain integrity must remain intact
        chain_result = P0AuditLogger.verify_chain(audit_path)
        self.assertTrue(chain_result['ok'], f"Audit chain broken: {chain_result.get('error')}")

    # ------------------------------------------------------------------
    # Test 3: scenario_summary() surfaces config_hash, policy_profile, release_condition
    # ------------------------------------------------------------------
    def test_scenario_summary_surfaces_traceability_fields(self) -> None:
        payload = {
            'ok': True,
            'result': {
                'scenario_id': 'test-traceability',
                'arbiter': {'action': 'redirect', 'control_mode': 'opencanary_redirect'},
                'explanation': {
                    'config_hash': 'abc123policyfix',
                    'policy_profile': 'soc-policy-v1',
                    'release_condition': 'no_repeated_failures_for_300_seconds',
                    'operator_wording': 'Redirect active.',
                    'next_checks': ['check-1'],
                },
                'demo': {'title': 'Test scenario'},
            },
        }

        summary = scenario_summary(payload)

        self.assertEqual(
            summary.get('config_hash'),
            'abc123policyfix',
            "scenario_summary must surface config_hash from explanation",
        )
        self.assertEqual(
            summary.get('policy_profile'),
            'soc-policy-v1',
            "scenario_summary must surface policy_profile from explanation",
        )
        self.assertEqual(
            summary.get('release_condition'),
            'no_repeated_failures_for_300_seconds',
            "scenario_summary must surface release_condition from explanation",
        )

    # ------------------------------------------------------------------
    # Test 4: evaluate() returns False when redirect is not warranted —
    #         verifies no change to threshold logic
    # ------------------------------------------------------------------
    def test_no_traceability_fields_on_non_redirect_evaluate(self) -> None:
        """When arbiter action is not redirect/throttle, evaluate() returns early
        without the traceability fields — redirect gating logic is unchanged."""
        with tempfile.TemporaryDirectory() as tmp:
            audit = P0AuditLogger(Path(tmp) / 'audit.jsonl')
            controller = OpenCanaryRedirectController(
                audit_logger=audit,
                state_path=Path(tmp) / 'state.json',
                redirect_log_path=Path(tmp) / 'redirect.jsonl',
            )
            decision = controller.evaluate(
                arbiter={'action': 'notify', 'chosen_evidence_ids': ['ev-1']},
                soc={'suspicion': {'score': 20}, 'confidence': {'score': 20}},
                target_ip='192.168.40.50',
                trace_id='trace-no-redirect',
            )
        self.assertFalse(decision.get('redirect'))
        self.assertEqual(decision.get('reason'), 'arbiter_not_redirect')


if __name__ == '__main__':
    unittest.main()
