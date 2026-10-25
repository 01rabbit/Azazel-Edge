"""Event-driven NOC re-evaluation on a link-state change (Edge#414 SO-02).

Observation only: a carrier/operstate change makes the NOC view of that
interface current sooner; nothing is decided or enforced from it.
"""

from __future__ import annotations

import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from azazel_edge.sensors import link_watch as lw
from azazel_edge.sensors import noc_monitor as nm
from azazel_edge_control import daemon as control_daemon


class FakeClock:
    def __init__(self) -> None:
        self.t = 100.0

    def __call__(self) -> float:
        return self.t


def _rtattr(atype: int, payload: bytes) -> bytes:
    raw = struct.pack('=HH', 4 + len(payload), atype) + payload
    return raw + b'\0' * ((-len(raw)) % 4)


def _link_msg(name: str, *, oper: int | None = 6, carrier: int | None = 1, flags: int = 0, mtype: int = lw.RTM_NEWLINK) -> bytes:
    attrs = _rtattr(lw.IFLA_IFNAME, name.encode() + b'\0')
    if oper is not None:
        attrs += _rtattr(lw.IFLA_OPERSTATE, bytes([oper]))
    if carrier is not None:
        attrs += _rtattr(lw.IFLA_CARRIER, bytes([carrier]))
    body = struct.pack('=BxHiII', 0, 1, 7, flags, 0) + attrs
    return struct.pack('=IHHII', 16 + len(body), mtype, 0, 0, 0) + body


class GateTests(unittest.TestCase):
    def test_debounce_waits_for_the_link_to_settle(self) -> None:
        clock = FakeClock()
        gate = lw.ReevaluationGate(debounce_s=0.25, max_delay_s=1.0, min_interval_s=2.0, clock=clock)
        self.assertEqual(gate.due(), [])
        self.assertIsNone(gate.wait_s())
        gate.note('br0')
        clock.t += 0.2
        self.assertEqual(gate.due(), [])
        gate.note('br0')  # still changing: the wait restarts
        clock.t += 0.2
        self.assertEqual(gate.due(), [])
        self.assertAlmostEqual(gate.wait_s(), 0.05, places=6)
        clock.t += 0.05
        self.assertEqual(gate.due(), ['br0'])
        self.assertEqual(gate.due(), [])
        self.assertEqual(gate.fired, 1)

    def test_flapping_link_is_still_reported_within_max_delay(self) -> None:
        clock = FakeClock()
        gate = lw.ReevaluationGate(debounce_s=0.25, max_delay_s=1.0, min_interval_s=2.0, clock=clock)
        fired_at = None
        for _ in range(30):
            gate.note('br0')
            clock.t += 0.1
            if gate.due():
                fired_at = clock.t
                break
        self.assertIsNotNone(fired_at)
        # within max_delay, give or take one 0.1 s step of the fake clock
        self.assertLessEqual(fired_at - 100.0, 1.1 + 1e-6)

    def test_rate_is_bounded(self) -> None:
        clock = FakeClock()
        gate = lw.ReevaluationGate(debounce_s=0.0, max_delay_s=0.0, min_interval_s=2.0, clock=clock)
        gate.note('br0')
        self.assertEqual(gate.due(), ['br0'])
        gate.note('usb0')
        clock.t += 1.9
        self.assertEqual(gate.due(), [])
        gate.note('br0')
        clock.t += 0.1
        self.assertEqual(gate.due(), ['br0', 'usb0'])  # one batched re-evaluation
        # a continuous storm for 20 s: at most one re-evaluation per 2 s
        fires = 0
        for _ in range(2000):
            gate.note('br0')
            clock.t += 0.01
            fires += len(gate.due()) > 0
        self.assertLessEqual(fires, 11)
        self.assertGreaterEqual(fires, 9)

    def test_invalid_gate_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            lw.ReevaluationGate(debounce_s=2.0, max_delay_s=1.0)
        with self.assertRaises(ValueError):
            lw.ReevaluationGate(min_interval_s=0)


class ParseTests(unittest.TestCase):
    def test_newlink_and_dellink(self) -> None:
        data = _link_msg('br0', oper=2, carrier=0) + _link_msg('usb0') + _link_msg('old0', mtype=lw.RTM_DELLINK)
        self.assertEqual(
            lw.parse_link_messages(data),
            [('br0', ('down', 0)), ('usb0', ('up', 1)), ('old0', None)],
        )

    def test_carrier_falls_back_to_lower_up_flag(self) -> None:
        self.assertEqual(lw.parse_link_messages(_link_msg('e0', carrier=None, flags=lw.IFF_LOWER_UP)), [('e0', ('up', 1))])
        self.assertEqual(lw.parse_link_messages(_link_msg('e0', oper=None, carrier=None)), [('e0', ('unknown', 0))])

    def test_malformed_input_never_raises(self) -> None:
        good = _link_msg('br0', oper=2, carrier=0)
        for data in (b'', b'\x00' * 7, good[:20], good[:-3], struct.pack('=IHHII', 4, 16, 0, 0, 0) + good):
            lw.parse_link_messages(data)
        other = struct.pack('=IHHII', 20, 3, 0, 0, 0) + b'\0' * 4  # NLMSG_DONE
        self.assertEqual(lw.parse_link_messages(other + good), [('br0', ('down', 0))])


class WatcherTests(unittest.TestCase):
    def _watcher(self, root: Path, calls: list, **kw) -> lw.LinkStateWatcher:
        return lw.LinkStateWatcher(
            lambda: ['br0'],
            calls.append,
            gate=lw.ReevaluationGate(debounce_s=0.05, max_delay_s=0.1, min_interval_s=0.2),
            sysfs_root=root,
            **kw,
        )

    @staticmethod
    def _sysfs(root: Path, iface: str, oper: str, carrier: str) -> None:
        (root / iface).mkdir(parents=True, exist_ok=True)
        (root / iface / 'operstate').write_text(oper + '\n')
        (root / iface / 'carrier').write_text(carrier + '\n')

    def test_observe_baseline_change_and_unmonitored(self) -> None:
        calls: list = []
        w = self._watcher(Path('/nonexistent'), calls)
        self.assertFalse(w.observe('br0', ('up', 1)))  # first sight is the baseline
        self.assertFalse(w.observe('br0', ('up', 1)))
        self.assertFalse(w.observe('eth9', ('down', 0)))  # not monitored
        self.assertEqual(w.gate.pending(), [])
        self.assertTrue(w.observe('br0', ('down', 0)))
        self.assertEqual(w.gate.pending(), ['br0'])

    def test_sysfs_poll_fallback_when_netlink_unavailable(self) -> None:
        def no_netlink():
            raise OSError('address family not supported')

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._sysfs(root, 'br0', 'up', '1')
            calls: list = []
            w = self._watcher(root, calls, open_netlink=no_netlink, poll_interval_s=5.0)
            self.assertEqual(w.poll_interval_s, lw.MAX_POLL_INTERVAL_S)  # never slower than 1 s
            w.poll_interval_s = 0.05
            w.start()
            try:
                deadline = time.monotonic() + 2
                while w.mode != 'sysfs_poll' and time.monotonic() < deadline:
                    time.sleep(0.01)
                time.sleep(0.15)
                self.assertEqual(calls, [])
                self._sysfs(root, 'br0', 'down', '0')
                t0 = time.monotonic()
                while not calls and time.monotonic() - t0 < 2:
                    time.sleep(0.01)
                self.assertEqual(calls, [['br0']])
                self.assertEqual(w.mode, 'sysfs_poll')
            finally:
                w.stop()

    def test_netlink_message_triggers_reevaluation(self) -> None:
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        a.setblocking(False)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._sysfs(root, 'br0', 'up', '1')
            calls: list = []
            w = self._watcher(root, calls, open_netlink=lambda: a)
            w.start()
            try:
                deadline = time.monotonic() + 2
                while 'br0' not in w._known and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(w.mode, 'netlink')
                b.send(_link_msg('br0', oper=6, carrier=1) + _link_msg('eth9', oper=2, carrier=0))
                time.sleep(0.2)
                self.assertEqual(calls, [])  # same state, other interface: nothing
                b.send(_link_msg('br0', oper=2, carrier=0))
                t0 = time.monotonic()
                while not calls and time.monotonic() - t0 < 2:
                    time.sleep(0.01)
                self.assertEqual(calls, [['br0']])
                self.assertLess(time.monotonic() - t0, 1.0)
            finally:
                w.stop()
                b.close()

    def test_failing_callback_does_not_kill_the_watcher(self) -> None:
        def boom(_ifaces):
            raise RuntimeError('probe failed')

        w = lw.LinkStateWatcher(lambda: ['br0'], boom, gate=lw.ReevaluationGate(debounce_s=0, max_delay_s=0, min_interval_s=0.01))
        w.observe('br0', ('up', 1))
        w.observe('br0', ('down', 0))
        self.assertEqual(w.fire_due(), ['br0'])


class CollectorTimeoutTests(unittest.TestCase):
    def test_runner_bounds_the_wait_and_keeps_one_stray(self) -> None:
        runner = nm._BoundedRunner()
        release = threading.Event()
        t0 = time.monotonic()
        with self.assertRaises(nm.CollectorTimeout):
            runner.run('dns', lambda: release.wait(5), 0.1)
        self.assertLess(time.monotonic() - t0, 1.0)
        started = []
        with self.assertRaises(nm.CollectorTimeout):
            runner.run('dns', lambda: started.append(1), 1.0)  # stray still running
        self.assertEqual(started, [])
        self.assertEqual(runner.run('other', lambda: 7, 1.0), 7)
        release.set()
        time.sleep(0.05)
        self.assertEqual(runner.run('dns', lambda: 'ok', 1.0), 'ok')
        with self.assertRaises(KeyError):
            runner.run('err', lambda: {}['x'], 1.0)

    def test_overrunning_collector_is_a_bounded_collector_failure(self) -> None:
        release = threading.Event()
        patches = [
            patch.object(nm, '_default_icmp_target', side_effect=lambda gw: '172.16.0.254'),
            patch.object(nm, 'collect_iface_stats', side_effect=lambda *a: []),
            patch.object(nm, 'collect_path_probes_multi', side_effect=lambda *a: [{'interface': 'br0', 'target': '1.1.1.1', 'reachable': True}]),
            patch.object(nm, 'collect_dns_resolution', side_effect=lambda name: release.wait(5) and {}),
            patch.object(nm, 'collect_service_probes', side_effect=lambda *a: []),
            patch.object(nm, 'collect_icmp', side_effect=lambda *a, **k: {}),
            patch.object(nm, 'collect_cpu_mem_temp', side_effect=lambda: {}),
            patch.object(nm, 'collect_dhcp_leases', side_effect=lambda: []),
            patch.object(nm, 'collect_arp_table', side_effect=lambda: []),
            patch.object(nm, 'collect_service_health', side_effect=lambda: {}),
        ]
        for p in patches:
            p.start()
        try:
            monitor = nm.LightweightNocMonitor(up_interface='br0')
            monitor.collector_timeouts_s['resolution_probes'] = 0.2
            t0 = time.monotonic()
            snap = monitor.collect_snapshot()
            elapsed = time.monotonic() - t0
        finally:
            release.set()
            for p in patches:
                p.stop()
        self.assertLess(elapsed, 2.0)
        self.assertEqual(snap['resolution_probes'], [])
        self.assertTrue(any(f['collector'] == 'resolution_probes' and 'timed out' in f['error'] for f in snap['collector_failures']))
        rows = {r['collector']: r for r in snap['collection_timing']['collectors']}
        self.assertEqual(rows['resolution_probes']['outcome'], 'timeout')
        self.assertEqual(rows['path_probes']['outcome'], 'ok')
        self.assertEqual(snap['path_probes'][0]['interface'], 'br0')

    def test_every_collector_has_an_explicit_bound(self) -> None:
        names = {'iface_stats', 'path_probes', 'resolution_probes', 'service_probes', 'icmp',
                 'cpu_mem_temp', 'dhcp_leases', 'arp_table', 'service_health'}
        self.assertEqual(set(nm.COLLECTOR_TIMEOUTS_S), names)
        self.assertTrue(all(0 < v <= 30 for v in nm.COLLECTOR_TIMEOUTS_S.values()))

    def test_dns_resolution_is_bounded(self) -> None:
        release = threading.Event()
        with patch.object(nm.socket, 'getaddrinfo', side_effect=lambda *a, **k: release.wait(5) and []):
            t0 = time.monotonic()
            row = nm.collect_dns_resolution('example.com', timeout_sec=0.2)
            elapsed = time.monotonic() - t0
        release.set()
        self.assertLess(elapsed, 1.0)
        self.assertFalse(row['resolved'])
        self.assertIn('timed out', row['error'])
        with patch.object(nm.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('93.184.216.34', 0))]):
            self.assertTrue(nm.collect_dns_resolution('example.com')['resolved'])


def _base_snapshot() -> dict:
    return {
        'icmp': {'target': '172.16.0.254', 'reachable': True},
        'path_probes': [
            {'interface': 'br0', 'target': '1.1.1.1', 'scope': 'external', 'reachable': True},
            {'interface': 'usb0', 'target': '1.1.1.1', 'scope': 'external', 'reachable': False},
        ],
        'path_probe_window': [{'interface': 'br0', 'target': '1.1.1.1', 'state': 'normal', 'reachable': True}],
        'iface_stats': [{'interface': 'br0', 'operstate': 'up', 'carrier': 1}],
        'resolution_probes': [{'name': 'example.com', 'resolved': True}],
        'collector_failures': [{'collector': 'iface_stats', 'error': 'old'}, {'collector': 'arp_table', 'error': 'x'}],
    }


class RefreshInterfaceTests(unittest.TestCase):
    def _monitor(self) -> nm.LightweightNocMonitor:
        monitor = nm.LightweightNocMonitor(up_interface='br0', down_interface='usb0')
        monitor._last_snapshot = _base_snapshot()
        return monitor

    def test_no_base_or_unmonitored_is_nothing(self) -> None:
        monitor = nm.LightweightNocMonitor(up_interface='br0', down_interface='usb0')
        self.assertIsNone(monitor.refresh_interfaces(['br0']))
        monitor._last_snapshot = _base_snapshot()
        self.assertIsNone(monitor.refresh_interfaces(['eth9']))

    def test_only_the_changed_interface_is_reprobed(self) -> None:
        monitor = self._monitor()
        probed = []

        def icmp(target, interface=''):
            probed.append((interface, target))
            time.sleep(0.3)
            return {'interface': interface, 'target': target, 'reachable': False}

        with patch.object(nm, 'collect_icmp', side_effect=icmp), \
             patch.object(nm, '_default_icmp_target', return_value='172.16.0.254'), \
             patch.object(nm, 'collect_iface_stats', return_value=[{'interface': 'br0', 'operstate': 'down', 'carrier': 0}]):
            t0 = time.monotonic()
            snap = monitor.refresh_interfaces(['br0', 'eth9'])
            elapsed = time.monotonic() - t0
        self.assertEqual(sorted(probed), [('br0', '1.1.1.1'), ('br0', '172.16.0.254'), ('br0', '8.8.8.8')])
        self.assertLess(elapsed, 0.8)  # the three probes ran concurrently
        br0 = [r for r in snap['path_probes'] if r['interface'] == 'br0']
        self.assertEqual([(r['target'], r['scope']) for r in br0],
                         [('172.16.0.254', 'gateway'), ('1.1.1.1', 'external'), ('8.8.8.8', 'external')])
        self.assertTrue(all(not r['reachable'] for r in br0))
        self.assertEqual([r for r in snap['path_probes'] if r['interface'] == 'usb0'], _base_snapshot()['path_probes'][1:])
        self.assertEqual(snap['iface_stats'][0]['carrier'], 0)
        # windows, other collectors and other failures are the periodic loop's
        self.assertEqual(snap['path_probe_window'], _base_snapshot()['path_probe_window'])
        self.assertEqual(snap['resolution_probes'], _base_snapshot()['resolution_probes'])
        self.assertEqual(snap['collector_failures'], [{'collector': 'arp_table', 'error': 'x'}])
        self.assertEqual(snap['collection_timing']['interfaces'], ['br0'])
        self.assertEqual([r['collector'] for r in snap['collection_timing']['collectors']], ['iface_stats', 'path_probes'])
        self.assertEqual(monitor._last_snapshot, _base_snapshot())  # base untouched

    def test_refresh_is_bounded(self) -> None:
        monitor = self._monitor()
        release = threading.Event()
        with patch.object(nm, 'INTERFACE_REFRESH_TIMEOUT_S', 0.2), \
             patch.object(nm, '_default_icmp_target', return_value='172.16.0.254'), \
             patch.object(nm, 'collect_icmp', side_effect=lambda target, interface='': release.wait(5) and {}), \
             patch.object(nm, 'collect_iface_stats', return_value=[]):
            t0 = time.monotonic()
            snap = monitor.refresh_interfaces(['br0'])
            elapsed = time.monotonic() - t0
        release.set()
        self.assertLess(elapsed, 1.0)
        self.assertEqual([r for r in snap['path_probes'] if r['interface'] == 'br0'], _base_snapshot()['path_probes'][:1])
        self.assertTrue(any('timed out' in f['error'] for f in snap['collector_failures'] if f['collector'] == 'path_probes'))
        self.assertEqual(snap['collection_timing']['collectors'][-1]['outcome'], 'timeout')

    def test_probe_error_keeps_the_old_rows_and_reports(self) -> None:
        monitor = self._monitor()

        def icmp(target, interface=''):
            raise RuntimeError('ping missing')

        with patch.object(nm, '_default_icmp_target', return_value='172.16.0.254'), \
             patch.object(nm, 'collect_icmp', side_effect=icmp), \
             patch.object(nm, 'collect_iface_stats', side_effect=FileNotFoundError('interface not found: br0')):
            snap = monitor.refresh_interfaces(['br0'])
        self.assertEqual(snap['path_probes'], _base_snapshot()['path_probes'])
        self.assertEqual(snap['iface_stats'], _base_snapshot()['iface_stats'])
        errs = [(f['collector'], f['error']) for f in snap['collector_failures']]
        self.assertIn(('path_probes', 'br0: ping missing'), errs)
        self.assertIn(('iface_stats', 'old'), errs)  # not re-run successfully: the old failure stays
        self.assertEqual(snap['collection_timing']['collectors'][-1]['outcome'], 'error')


class DaemonPublishTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = (dict(control_daemon._NOC_CACHE), dict(control_daemon._SNAPSHOT_CACHE),
                       control_daemon._NOC_ADAPTER, control_daemon._NOC_ADAPTER_KEY)

    def tearDown(self) -> None:
        noc, snap, adapter, key = self._saved
        control_daemon._NOC_CACHE.clear()
        control_daemon._NOC_CACHE.update(noc)
        control_daemon._SNAPSHOT_CACHE.clear()
        control_daemon._SNAPSHOT_CACHE.update(snap)
        control_daemon._NOC_ADAPTER, control_daemon._NOC_ADAPTER_KEY = adapter, key

    @staticmethod
    def _projection(started: int, uplinks: list, trigger: str = 'periodic') -> dict:
        return {
            'noc_blast_radius': {'affected_uplinks': uplinks},
            'noc_runtime': {'collection': {'trigger': trigger, 'started_monotonic_ns': started}},
        }

    def test_an_older_collection_never_overwrites_a_newer_one(self) -> None:
        control_daemon._NOC_CACHE.update({'key': 'k', 'ts': 0.0, 'payload': {}})
        newer = self._projection(200, ['br0'], 'link_event')
        self.assertEqual(control_daemon._publish_noc_projection('k', newer), newer)
        stale = self._projection(100, [])
        self.assertEqual(control_daemon._publish_noc_projection('k', stale), newer)
        self.assertEqual(control_daemon._NOC_CACHE['payload'], newer)
        later = self._projection(300, [])
        self.assertEqual(control_daemon._publish_noc_projection('k', later), later)
        # a link-event publish keeps the periodic schedule; a periodic one restarts it
        control_daemon._NOC_CACHE['ts'] = 5.0
        control_daemon._publish_noc_projection('k', self._projection(400, ['br0'], 'link_event'), periodic=False)
        self.assertEqual(control_daemon._NOC_CACHE['ts'], 5.0)
        control_daemon._publish_noc_projection('k', self._projection(500, []))
        self.assertGreater(control_daemon._NOC_CACHE['ts'], 5.0)
        # another scope always replaces
        self.assertEqual(control_daemon._publish_noc_projection('other', stale), stale)

    def test_snapshot_cache_shows_the_newest_noc_view(self) -> None:
        control_daemon._NOC_CACHE.update({'key': 'k', 'ts': time.time(), 'payload': self._projection(200, ['br0'], 'link_event')})
        built = {'ok': True, 'snapshot': {'user_state': 'SAFE', **self._projection(100, [])}}
        control_daemon._snapshot_cache_set(built)
        cached = control_daemon._SNAPSHOT_CACHE['payload']['snapshot']
        self.assertEqual(cached['noc_blast_radius']['affected_uplinks'], ['br0'])
        self.assertEqual(cached['user_state'], 'SAFE')
        # a snapshot without a NOC view (dev healthy baseline) is left alone
        control_daemon._snapshot_cache_set({'ok': True, 'snapshot': {'user_state': 'SAFE'}})
        self.assertNotIn('noc_blast_radius', control_daemon._SNAPSHOT_CACHE['payload']['snapshot'])

    def test_link_event_reevaluates_and_reaches_the_snapshot_cache(self) -> None:
        adapter = control_daemon.NocProbeAdapter(up_interface='br0', down_interface='usb0')
        adapter.monitor._last_snapshot = _base_snapshot()
        control_daemon._NOC_ADAPTER, control_daemon._NOC_ADAPTER_KEY = adapter, 'br0|usb0|'
        control_daemon._NOC_CACHE.update({'key': 'br0|usb0|', 'ts': time.time(), 'payload': self._projection(1, [])})
        control_daemon._SNAPSHOT_CACHE.update({'ts': time.time(), 'payload': {'ok': True, 'snapshot': {'user_state': 'SAFE', **self._projection(1, [])}}})
        with patch.object(nm, 'collect_icmp', side_effect=lambda t, interface='': {'interface': interface, 'target': t, 'reachable': False}), \
             patch.object(nm, '_default_icmp_target', return_value='172.16.0.254'), \
             patch.object(nm, 'collect_iface_stats', return_value=[{'interface': 'br0', 'operstate': 'down', 'carrier': 0}]):
            control_daemon._noc_link_event_reevaluate(['br0'])
        snap = control_daemon._snapshot_cache_get()['snapshot']
        self.assertIn('br0', snap['noc_blast_radius']['affected_uplinks'])
        self.assertEqual(snap['noc_runtime']['collection']['trigger'], 'link_event')
        self.assertEqual(snap['user_state'], 'SAFE')
        self.assertEqual(control_daemon._noc_monitored_interfaces(), ['br0', 'usb0'])

    def test_link_event_without_adapter_is_a_no_op(self) -> None:
        control_daemon._NOC_ADAPTER = None
        control_daemon._noc_link_event_reevaluate(['br0'])
        self.assertEqual(control_daemon._noc_monitored_interfaces(), [])

    def test_projection_reports_link_watch_mode(self) -> None:
        view = control_daemon._build_noc_runtime_projection(evaluation={}, event_payloads=[], inventory_summary={})
        self.assertIn(view['noc_runtime']['link_watch']['mode'], {'stopped', 'netlink', 'sysfs_poll'})


if __name__ == '__main__':
    unittest.main()
