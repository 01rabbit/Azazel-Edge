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
from azazel_edge.config_drift import (
    ConfigDriftAuditor,
    HEALTH_CONFIG_SCHEMA,
    extract_health_config_snapshot,
)
from azazel_edge.evidence_plane import build_config_drift_event


class ConfigDriftAuditV1Tests(unittest.TestCase):
    def test_detects_added_removed_and_modified_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_a = root / 'a.conf'
            file_b = root / 'b.conf'
            file_a.write_text('alpha\n', encoding='utf-8')
            file_b.write_text('bravo\n', encoding='utf-8')

            auditor = ConfigDriftAuditor(root / 'baseline.json')
            auditor.create_baseline([file_a, file_b])

            file_a.write_text('alpha-modified\n', encoding='utf-8')
            file_b.unlink()
            file_c = root / 'c.conf'
            file_c.write_text('charlie\n', encoding='utf-8')

            drift = auditor.detect_drift([file_a, file_b, file_c])

        self.assertEqual(drift['status'], 'drift')
        self.assertIn(str(file_a), drift['modified'])
        self.assertIn(str(file_b), drift['removed'])
        self.assertIn(str(file_c), drift['added'])

    def test_can_audit_drift_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file_a = root / 'a.conf'
            file_a.write_text('alpha\n', encoding='utf-8')
            audit_path = root / 'audit.jsonl'
            auditor = ConfigDriftAuditor(root / 'baseline.json', audit_logger=P0AuditLogger(audit_path))
            auditor.create_baseline([file_a])
            file_a.write_text('changed\n', encoding='utf-8')
            drift = auditor.detect_drift([file_a])
            record = auditor.audit_drift('trace-drift-1', drift)
            rows = [json.loads(line) for line in audit_path.read_text(encoding='utf-8').splitlines()]

        self.assertEqual(record['kind'], 'evaluation')
        self.assertEqual(rows[-1]['source'], 'config_drift_audit')
        self.assertEqual(rows[-1]['status'], 'drift')

    def test_health_config_snapshot_and_drift_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            auditor = ConfigDriftAuditor(root / 'health-baseline.json')
            sot = {
                'devices': [{'id': 'dev1', 'hostname': 'client-1', 'ip': '192.168.40.10', 'mac': 'aa:bb:cc:dd:ee:ff', 'criticality': 'critical', 'allowed_networks': ['lan-main']}],
                'networks': [{'id': 'lan-main', 'cidr': '192.168.40.0/24', 'zone': 'lan', 'gateway': '192.168.40.1'}],
                'services': [{'id': 'resolver-tcp', 'proto': 'tcp', 'port': 53, 'owner': 'noc', 'exposure': 'internal'}],
                'expected_paths': [],
            }
            baseline_snapshot = extract_health_config_snapshot(
                {'up_if': 'eth1', 'gateway_ip': '192.168.40.1', 'policy_version': 'v1'},
                sot=sot,
            )
            self.assertEqual(baseline_snapshot['schema'], HEALTH_CONFIG_SCHEMA)
            auditor.create_health_baseline(baseline_snapshot)

            current_snapshot = extract_health_config_snapshot(
                {'up_if': 'usb0', 'gateway_ip': '192.168.40.1', 'policy_version': 'v2'},
                sot=sot,
            )
            diff = auditor.detect_health_drift(current_snapshot)
            event = build_config_drift_event(diff).to_dict()

        self.assertEqual(diff['status'], 'drift')
        self.assertIn('uplink_preference.preferred_uplink', diff['changed_fields'])
        self.assertIn('policy_markers.policy_version', diff['changed_fields'])
        self.assertEqual(event['kind'], 'config_drift')
        self.assertEqual(event['attrs']['rollback_hint'], 'review_changed_fields_and_restore_last_known_good')

    def test_missing_and_invalid_health_baseline_are_degraded_not_green(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            auditor = ConfigDriftAuditor(root / 'health-baseline.json')
            current_snapshot = extract_health_config_snapshot({'up_if': 'eth1'}, sot={'devices': [], 'networks': [], 'services': [], 'expected_paths': []})
            missing = auditor.detect_health_drift(current_snapshot)
            auditor.baseline_path.write_text(json.dumps({'ts': '2026-03-13T00:00:00Z', 'snapshot': {'schema': 'broken'}}), encoding='utf-8')
            invalid = auditor.detect_health_drift(current_snapshot)

        self.assertEqual(missing['status'], 'baseline_missing')
        self.assertEqual(missing['rollback_hint'], 'create_last_known_good_baseline')
        self.assertEqual(invalid['status'], 'baseline_invalid')
        self.assertEqual(invalid['rollback_hint'], 'repair_or_replace_invalid_baseline')


if __name__ == '__main__':
    unittest.main()
