from __future__ import annotations

import io
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = PROJECT_ROOT / 'py'
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.aggregator import AggregatorPoller, AggregatorRegistry, FreshnessPolicy, PollError

try:
    import azazel_edge_web.app as webapp
except Exception:
    webapp = None


class _FakeResp:
    def __init__(self, payload: dict):
        self._raw = json.dumps(payload).encode('utf-8')
        self.status = 200

    def read(self, _cap: int) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class AggregatorPullV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry = AggregatorRegistry(FreshnessPolicy(poll_interval_sec=30, stale_multiplier=2, offline_multiplier=6))

    def test_poll_node_once_success(self) -> None:
        poller = AggregatorPoller(self.registry)
        payload = {'trace_id': 'p1', 'node': {'node_id': 'n1', 'site_id': 's1'}, 'timestamps': {'generated_at': time.time()}}
        with patch('azazel_edge.aggregator.urllib.request.urlopen', return_value=_FakeResp(payload)):
            got = poller.poll_node_once('n1', 'https://node-1/api/state/summary')
        self.assertEqual(got['trace_id'], 'p1')

    def test_poll_node_once_timeout_raises_poll_error(self) -> None:
        poller = AggregatorPoller(self.registry)
        with patch('azazel_edge.aggregator.urllib.request.urlopen', side_effect=TimeoutError('timeout')):
            with self.assertRaises(PollError):
                poller.poll_node_once('n1', 'https://node-1/api/state/summary')

    def test_poll_loop_calls_ingest_on_success(self) -> None:
        self.registry.register_node('n1', 's1', poll_url='https://node-1/api/state/summary')
        poller = AggregatorPoller(self.registry)
        poller.poll_node_once = MagicMock(return_value={
            'trace_id': 'pl-1',
            'node': {'node_id': 'n1', 'site_id': 's1'},
            'timestamps': {'generated_at': time.time()},
        })
        with patch.object(self.registry, 'ingest_summary', wraps=self.registry.ingest_summary) as ingest_spy:
            wait_mock = MagicMock(side_effect=[False, True])
            with patch.object(poller._stop_event, 'wait', wait_mock):
                poller._poll_loop()
            self.assertTrue(ingest_spy.called)

    def test_poll_loop_skips_quarantined_nodes(self) -> None:
        self.registry.register_node('nq', 's1', poll_url='https://node-q/api/state/summary')
        self.registry._nodes['nq']['status'] = 'quarantined'
        poller = AggregatorPoller(self.registry)
        poller.poll_node_once = MagicMock()
        wait_mock = MagicMock(side_effect=[False, True])
        with patch.object(poller._stop_event, 'wait', wait_mock):
            poller._poll_loop()
        poller.poll_node_once.assert_not_called()

    def test_poll_loop_skips_nodes_without_poll_url(self) -> None:
        self.registry.register_node('n2', 's2')
        poller = AggregatorPoller(self.registry)
        poller.poll_node_once = MagicMock()
        wait_mock = MagicMock(side_effect=[False, True])
        with patch.object(poller._stop_event, 'wait', wait_mock):
            poller._poll_loop()
        poller.poll_node_once.assert_not_called()

    def test_stop_terminates_thread(self) -> None:
        poller = AggregatorPoller(self.registry)

        def _runner():
            while not poller._stop_event.wait(0.05):
                pass

        poller._thread = threading.Thread(target=_runner, daemon=True)
        poller._thread.start()
        poller.stop(timeout_sec=1.0)
        self.assertFalse(poller._thread.is_alive())

    def test_register_node_accepts_poll_url(self) -> None:
        row = self.registry.register_node('n3', 's3', poll_url='https://node-3/api/state/summary')
        self.assertEqual(row.get('poll_url'), 'https://node-3/api/state/summary')


@unittest.skipIf(webapp is None, "flask app unavailable in current environment")
class AggregatorPollerApiV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.auth_tokens_path = root / 'auth_tokens.json'
        self.auth_tokens_path.write_text(
            json.dumps(
                {
                    'tokens': [
                        {'token': 'admin-token', 'principal': 'admin-1', 'role': 'admin'},
                    ]
                }
            ),
            encoding='utf-8',
        )
        self._orig = {
            'AUTH_FAIL_OPEN': webapp.AUTH_FAIL_OPEN,
            'AUTH_TOKENS_FILE': webapp.AUTH_TOKENS_FILE,
            '_AGGREGATOR_REGISTRY': webapp._AGGREGATOR_REGISTRY,
            '_AGGREGATOR_POLLER': getattr(webapp, '_AGGREGATOR_POLLER', None),
        }
        webapp.AUTH_FAIL_OPEN = False
        webapp.AUTH_TOKENS_FILE = self.auth_tokens_path
        webapp._AGGREGATOR_REGISTRY = AggregatorRegistry()
        webapp._AGGREGATOR_POLLER = AggregatorPoller(webapp._AGGREGATOR_REGISTRY)
        self.client = webapp.app.test_client()

    def tearDown(self) -> None:
        webapp.AUTH_FAIL_OPEN = self._orig['AUTH_FAIL_OPEN']
        webapp.AUTH_TOKENS_FILE = self._orig['AUTH_TOKENS_FILE']
        webapp._AGGREGATOR_REGISTRY = self._orig['_AGGREGATOR_REGISTRY']
        webapp._AGGREGATOR_POLLER = self._orig['_AGGREGATOR_POLLER']
        self.tmp.cleanup()

    def test_aggregator_poller_start_stop_api(self) -> None:
        start = self.client.post('/api/aggregator/poller/start', headers={'X-AZAZEL-TOKEN': 'admin-token'})
        self.assertEqual(start.status_code, 200)
        stop = self.client.post('/api/aggregator/poller/stop', headers={'X-AZAZEL-TOKEN': 'admin-token'})
        self.assertEqual(stop.status_code, 200)


if __name__ == '__main__':
    unittest.main()
