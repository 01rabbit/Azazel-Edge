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
from azazel_edge.config_drift import ConfigDriftAuditor


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


if __name__ == '__main__':
    unittest.main()
