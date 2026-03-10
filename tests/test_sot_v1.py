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

from azazel_edge.sot import SoTValidationError, load_sot_file


VALID_SOT = {
    'devices': [
        {
            'id': 'dev1',
            'hostname': 'client-1',
            'ip': '192.168.40.10',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'criticality': 'normal',
            'allowed_networks': ['lan-main'],
        }
    ],
    'networks': [
        {
            'id': 'lan-main',
            'cidr': '192.168.40.0/24',
            'zone': 'lan',
            'gateway': '192.168.40.1',
        }
    ],
    'services': [
        {
            'id': 'svc-dns',
            'proto': 'udp',
            'port': 53,
            'owner': 'netops',
            'exposure': 'internal',
        }
    ],
    'expected_paths': [
        {
            'src': 'lan-main',
            'dst': 'wan',
            'service_id': 'svc-dns',
            'via': '192.168.40.1',
            'policy': 'allow',
        }
    ],
}


class SoTV1Tests(unittest.TestCase):
    def test_loads_yaml_and_supports_lookups(self) -> None:
        import yaml

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sot.yaml'
            path.write_text(yaml.safe_dump(VALID_SOT), encoding='utf-8')
            sot = load_sot_file(path)

        self.assertEqual(sot.device_by_id('dev1')['hostname'], 'client-1')
        self.assertEqual(sot.device_by_ip('192.168.40.10')['id'], 'dev1')
        self.assertEqual(sot.network_by_id('lan-main')['gateway'], '192.168.40.1')
        self.assertEqual(sot.service_by_id('svc-dns')['port'], 53)
        self.assertEqual(sot.expected_path('lan-main', 'wan', 'svc-dns')['policy'], 'allow')

    def test_loads_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sot.json'
            path.write_text(json.dumps(VALID_SOT), encoding='utf-8')
            sot = load_sot_file(path)
        self.assertEqual(sot.to_dict()['devices'][0]['id'], 'dev1')

    def test_invalid_config_raises(self) -> None:
        invalid = dict(VALID_SOT)
        invalid['devices'] = [{'id': 'dev1'}]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sot.yaml'
            import yaml
            path.write_text(yaml.safe_dump(invalid), encoding='utf-8')
            with self.assertRaises(SoTValidationError):
                load_sot_file(path)


if __name__ == '__main__':
    unittest.main()
