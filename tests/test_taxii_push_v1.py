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

from azazel_edge.integrations.taxii_push import TAXIIPushClient

try:
    import azazel_edge_web.app as webapp
except Exception:
    webapp = None


class _FakeResp:
    def __init__(self, status: int = 202):
        self.status = status

    def read(self, _n: int = -1) -> bytes:
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TaxiiPushV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = {
            'type': 'bundle',
            'id': 'bundle--x',
            'spec_version': '2.1',
            'objects': [{'type': 'indicator', 'id': 'indicator--1', 'pattern': "[ipv4-addr:value='198.51.100.42']"}],
        }

    def test_push_bundle_success(self) -> None:
        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/', token='abc')
        with patch('azazel_edge.integrations.taxii_push.urllib.request.urlopen', return_value=_FakeResp(202)):
            result = client.push_bundle(self.bundle)
        self.assertTrue(result.ok)
        self.assertEqual(result.objects_pushed, 1)

    def test_push_bundle_empty_bundle_skipped(self) -> None:
        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/')
        result = client.push_bundle({'type': 'bundle', 'objects': []})
        self.assertTrue(result.ok)
        self.assertEqual(result.error, 'empty_bundle_skipped')

    def test_push_bundle_http_error_returns_result(self) -> None:
        from urllib.error import HTTPError

        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/')
        err = HTTPError(url='https://example', code=401, msg='unauthorized', hdrs=None, fp=None)
        with patch('azazel_edge.integrations.taxii_push.urllib.request.urlopen', side_effect=err):
            result = client.push_bundle(self.bundle)
        self.assertFalse(result.ok)
        self.assertEqual(result.status_code, 401)

    def test_push_bundle_network_error_never_raises(self) -> None:
        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/')
        with patch('azazel_edge.integrations.taxii_push.urllib.request.urlopen', side_effect=OSError('network down')):
            result = client.push_bundle(self.bundle)
        self.assertFalse(result.ok)
        self.assertIn('network down', str(result.error))

    def test_push_bundle_uses_bearer_token(self) -> None:
        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/', token='secret-token')

        def _check(req, timeout, context):
            self.assertEqual(req.headers.get('Authorization'), 'Bearer secret-token')
            return _FakeResp(202)

        with patch('azazel_edge.integrations.taxii_push.urllib.request.urlopen', side_effect=_check):
            result = client.push_bundle(self.bundle)
        self.assertTrue(result.ok)

    def test_push_bundle_wraps_in_taxii_envelope(self) -> None:
        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/')

        def _check(req, timeout, context):
            payload = json.loads(req.data.decode('utf-8'))
            self.assertIn('objects', payload)
            self.assertEqual(len(payload['objects']), 1)
            return _FakeResp(202)

        with patch('azazel_edge.integrations.taxii_push.urllib.request.urlopen', side_effect=_check):
            result = client.push_bundle(self.bundle)
        self.assertTrue(result.ok)

    def test_test_connection_success(self) -> None:
        client = TAXIIPushClient('https://example/taxii2/collections/c1/objects/')
        with patch('azazel_edge.integrations.taxii_push.urllib.request.urlopen', return_value=_FakeResp(200)):
            result = client.test_connection()
        self.assertTrue(result.ok)
        self.assertEqual(result.status_code, 200)


@unittest.skipIf(webapp is None, 'flask app unavailable in current environment')
class TaxiiPushApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.tokens = root / 'auth_tokens.json'
        self.tokens.write_text(
            json.dumps({'tokens': [{'token': 'admin-token', 'principal': 'admin-1', 'role': 'admin'}]}),
            encoding='utf-8',
        )
        self.audit_path = root / 'triage-audit.jsonl'
        self.audit_path.write_text('', encoding='utf-8')
        self._orig = {
            'AUTH_FAIL_OPEN': webapp.AUTH_FAIL_OPEN,
            'AUTH_TOKENS_FILE': webapp.AUTH_TOKENS_FILE,
            'TRIAGE_AUDIT_LOG': webapp.TRIAGE_AUDIT_LOG,
            'TRIAGE_AUDIT_FALLBACK_LOG': webapp.TRIAGE_AUDIT_FALLBACK_LOG,
        }
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.tokens
        webapp.TRIAGE_AUDIT_LOG = self.audit_path
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = self.audit_path
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.AUTH_FAIL_OPEN = self._orig['AUTH_FAIL_OPEN']
        webapp.AUTH_TOKENS_FILE = self._orig['AUTH_TOKENS_FILE']
        webapp.TRIAGE_AUDIT_LOG = self._orig['TRIAGE_AUDIT_LOG']
        webapp.TRIAGE_AUDIT_FALLBACK_LOG = self._orig['TRIAGE_AUDIT_FALLBACK_LOG']
        self.tmp.cleanup()

    def test_api_taxii_push_endpoint_requires_token(self) -> None:
        res = self.client.post('/api/taxii/push', json={'collection_url': 'https://example/taxii2/collections/c1/objects/'})
        self.assertEqual(res.status_code, 403)


if __name__ == '__main__':
    unittest.main()
