"""Per-collector timing of one NOC collection (Edge#414 SO-02, instrumentation).

Diagnostic only: the timing is exposed read-only in ``noc_runtime.collection``
and recorded by the SO-02 harness; it never feeds a decision.
"""

from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from azazel_edge.evidence_plane.noc_probe import NocProbeAdapter
from azazel_edge.sensors.noc_monitor import LightweightNocMonitor
from azazel_edge.service_objectives import so02_source_failure as so02
from azazel_edge_control import daemon as control_daemon

M = 'azazel_edge.sensors.noc_monitor.'


def _slow(seconds: float, value):
    def run(*_a, **_k):
        time.sleep(seconds)
        return value
    return run


def _patched(**over):
    base = {
        'collect_icmp': lambda *a, **k: {'target': '172.16.0.254', 'reachable': True},
        'collect_path_probes': lambda gw, interface='': [{'target': '1.1.1.1', 'interface': interface, 'scope': 'external', 'reachable': True}],
        'collect_dns_resolution': lambda name, *a, **k: {'name': name, 'resolved': True, 'answers': [], 'latency_ms': 1.0, 'probe': 'dns'},
        'collect_service_probes': lambda *a, **k: [],
        'collect_iface_stats': lambda *a, **k: [{'interface': 'br0', 'operstate': 'up', 'carrier': 1}],
        'collect_cpu_mem_temp': lambda: {},
        'collect_dhcp_leases': lambda: [],
        'collect_arp_table': lambda: [],
        'collect_service_health': lambda: {},
        '_default_icmp_target': lambda gw: '172.16.0.254',
    }
    base.update(over)
    return [patch(M + k, side_effect=v) for k, v in base.items()]


class CollectionTimingTests(unittest.TestCase):
    def _collect(self, **over):
        patches = _patched(**over)
        for p in patches:
            p.start()
        try:
            monitor = LightweightNocMonitor(up_interface='br0', down_interface='usb0')
            before = time.monotonic_ns()
            snap = monitor.collect_snapshot()
            after = time.monotonic_ns()
        finally:
            for p in patches:
                p.stop()
        return snap, before, after

    def test_every_collector_is_timed_in_order(self) -> None:
        snap, before, after = self._collect()
        timing = snap['collection_timing']
        names = [row['collector'] for row in timing['collectors']]
        self.assertEqual(
            names,
            ['icmp_target', 'iface_stats', 'path_probes', 'resolution_probes', 'service_probes',
             'icmp', 'cpu_mem_temp', 'dhcp_leases', 'arp_table', 'service_health'],
        )
        self.assertTrue(before <= timing['started_monotonic_ns'] <= after)
        offsets = [row['started_offset_ms'] for row in timing['collectors']]
        self.assertEqual(offsets, sorted(offsets))
        self.assertTrue(all(row['outcome'] == 'ok' for row in timing['collectors']))

    def test_slow_collector_is_the_one_that_shows_the_time(self) -> None:
        snap, _, _ = self._collect(collect_dns_resolution=_slow(0.15, {'name': 'x', 'resolved': False}))
        rows = {row['collector']: row for row in snap['collection_timing']['collectors']}
        # two resolution targets x 0.15 s
        self.assertGreaterEqual(rows['resolution_probes']['duration_ms'], 290.0)
        self.assertLess(rows['path_probes']['duration_ms'], 100.0)
        self.assertGreaterEqual(snap['collection_timing']['duration_ms'], rows['resolution_probes']['duration_ms'])
        self.assertGreaterEqual(rows['service_probes']['started_offset_ms'], 290.0)

    def test_failure_is_timed_as_error_and_still_reported(self) -> None:
        def boom(*_a, **_k):
            raise RuntimeError('probe disabled')
        snap, _, _ = self._collect(collect_service_probes=boom)
        rows = {row['collector']: row for row in snap['collection_timing']['collectors']}
        self.assertEqual(rows['service_probes']['outcome'], 'error')
        self.assertIn({'collector': 'service_probes', 'error': 'probe disabled'}, snap['collector_failures'])

    def test_icmp_target_failure_still_propagates(self) -> None:
        def boom(_gw):
            raise RuntimeError('route lookup failed')
        patches = _patched(_default_icmp_target=boom)
        for p in patches:
            p.start()
        try:
            with self.assertRaises(RuntimeError):
                LightweightNocMonitor(up_interface='br0').collect_snapshot()
        finally:
            for p in patches:
                p.stop()

    def test_timing_does_not_change_the_evidence(self) -> None:
        snap, _, _ = self._collect()
        adapter = NocProbeAdapter(up_interface='br0')
        with_timing = adapter.adapt_snapshot(snap)
        without = adapter.adapt_snapshot({k: v for k, v in snap.items() if k != 'collection_timing'})
        strip = lambda evs: [(e.kind, e.subject, e.severity, e.status, e.attrs) for e in evs]  # noqa: E731
        self.assertEqual(strip(with_timing), strip(without))


class CollectionViewTests(unittest.TestCase):
    def test_view_is_bounded_and_typed(self) -> None:
        timing = {
            'started_monotonic_ns': 123,
            'duration_ms': 4567.89,
            'collectors': [{'collector': 'x' * 200, 'started_offset_ms': i, 'duration_ms': True, 'outcome': 'ok' * 20} for i in range(40)]
            + ['junk'],
        }
        view = control_daemon._noc_collection_view(timing, 'periodic')
        self.assertEqual(view['trigger'], 'periodic')
        self.assertEqual(view['started_monotonic_ns'], 123)
        self.assertEqual(view['duration_ms'], 4567.9)
        self.assertEqual(len(view['collectors']), control_daemon.NOC_COLLECTION_VIEW_MAX_COLLECTORS)
        row = view['collectors'][0]
        self.assertEqual(len(row['collector']), control_daemon.NOC_COLLECTION_VIEW_NAME_MAX)
        self.assertIsNone(row['duration_ms'])  # a bool is not a number
        self.assertLessEqual(len(row['outcome']), 16)
        self.assertEqual(sorted(view), ['collectors', 'duration_ms', 'link_event_started_monotonic_ns', 'started_monotonic_ns', 'trigger'])

    def test_view_of_nothing_is_empty_not_an_error(self) -> None:
        view = control_daemon._noc_collection_view(None)
        self.assertEqual(view, {'trigger': 'periodic', 'started_monotonic_ns': None, 'link_event_started_monotonic_ns': None,
                                'duration_ms': None, 'collectors': []})
        self.assertIsNone(control_daemon._noc_collection_view({'started_monotonic_ns': True})['started_monotonic_ns'])

    def test_projection_carries_the_collection(self) -> None:
        view = control_daemon._noc_collection_view({'started_monotonic_ns': 5, 'duration_ms': 1.0, 'collectors': []})
        projection = control_daemon._build_noc_runtime_projection(
            evaluation={}, event_payloads=[], inventory_summary={}, collection=view,
        )
        self.assertEqual(projection['noc_runtime']['collection'], view)
        default = control_daemon._build_noc_runtime_projection(evaluation={}, event_payloads=[], inventory_summary={})
        self.assertEqual(default['noc_runtime']['collection']['collectors'], [])

    def test_harness_keeps_a_bounded_copy(self) -> None:
        value = {
            'trigger': 'periodic', 'started_monotonic_ns': 9, 'duration_ms': 3.0, 'extra': 'dropped',
            'collectors': [{'collector': 'c', 'started_offset_ms': 0.0, 'duration_ms': 1.0, 'outcome': 'ok', 'x': {'y': 1}}] * 30,
        }
        kept = so02._bounded_collection(value)
        self.assertEqual(sorted(kept), ['collectors', 'duration_ms', 'link_event_started_monotonic_ns', 'started_monotonic_ns', 'trigger'])
        self.assertEqual(len(kept['collectors']), 16)
        self.assertEqual(sorted(kept['collectors'][0]), ['collector', 'duration_ms', 'outcome', 'started_offset_ms'])
        self.assertIsNone(so02._bounded_collection(None))
        self.assertIsNone(so02._bounded_collection(['x']))
        self.assertEqual(so02._bounded_collection({'trigger': {'a': 1}})['trigger'], "{'a': 1}")


if __name__ == '__main__':
    unittest.main()
