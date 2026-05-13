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

from azazel_edge.notify import OfflineQueueNotifier


class _OkDelegate:
    def __init__(self):
        self.calls = 0

    def send(self, payload):
        self.calls += 1
        return {'ok': True, 'adapter': 'dummy', 'status': 200}


class _FailDelegate:
    def send(self, payload):
        raise RuntimeError('delegate down')


class NotificationOfflineQueueV1Tests(unittest.TestCase):
    def test_send_enqueues_summary_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue_path = Path(tmp) / 'offline_queue.jsonl'
            notifier = OfflineQueueNotifier(queue_path, _OkDelegate())
            result = notifier.send({'action': 'notify', 'reason': 'test', 'target': 'edge-uplink'})
            self.assertTrue(result['ok'])
            self.assertTrue(queue_path.exists())
            lines = queue_path.read_text(encoding='utf-8').splitlines()
            self.assertEqual(len(lines), 1)

    def test_send_caps_at_max_queue_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue_path = Path(tmp) / 'offline_queue.jsonl'
            notifier = OfflineQueueNotifier(queue_path, _OkDelegate(), max_queue_entries=5)
            for i in range(10):
                notifier.send({'action': 'notify', 'reason': f'test-{i}', 'target': 'edge-uplink'})
            lines = queue_path.read_text(encoding='utf-8').splitlines()
            self.assertEqual(len(lines), 5)

    def test_flush_delivers_and_clears(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue_path = Path(tmp) / 'offline_queue.jsonl'
            delegate = _OkDelegate()
            notifier = OfflineQueueNotifier(queue_path, delegate)
            notifier.send({'action': 'notify', 'reason': 'a'})
            notifier.send({'action': 'notify', 'reason': 'b'})
            result = notifier.flush()
            self.assertEqual(result['flushed'], 2)
            self.assertEqual(result['failed'], 0)
            self.assertFalse(queue_path.exists())

    def test_flush_retains_failed_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue_path = Path(tmp) / 'offline_queue.jsonl'
            notifier = OfflineQueueNotifier(queue_path, _FailDelegate())
            notifier.send({'action': 'notify', 'reason': 'a'})
            notifier.send({'action': 'notify', 'reason': 'b'})
            result = notifier.flush()
            self.assertEqual(result['flushed'], 0)
            self.assertEqual(result['failed'], 2)
            self.assertTrue(queue_path.exists())
            self.assertEqual(len(queue_path.read_text(encoding='utf-8').splitlines()), 2)

    def test_send_strips_raw_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue_path = Path(tmp) / 'offline_queue.jsonl'
            notifier = OfflineQueueNotifier(queue_path, _OkDelegate())
            notifier.send(
                {
                    'action': 'notify',
                    'reason': 'test',
                    'target': 'edge-uplink',
                    'evidence_ids': ['ev-1', 'ev-2'],
                }
            )
            entry = json.loads(queue_path.read_text(encoding='utf-8').splitlines()[0])
            self.assertNotIn('evidence_ids', entry)

    def test_queue_depth_returns_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            queue_path = Path(tmp) / 'offline_queue.jsonl'
            notifier = OfflineQueueNotifier(queue_path, _OkDelegate())
            notifier.send({'action': 'notify'})
            notifier.send({'action': 'notify'})
            self.assertEqual(notifier.queue_depth(), 2)


if __name__ == '__main__':
    unittest.main()
