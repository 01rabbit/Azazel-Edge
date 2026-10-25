from __future__ import annotations

import os
import re
import socket
import statistics
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .system_metrics import (
    get_cpu_temperature,
    get_cpu_usage,
    get_link_speed_mbps,
    get_memory_usage,
    get_network_stats,
)

DEFAULT_DHCP_LEASE_PATHS = [
    Path('/var/lib/misc/dnsmasq.leases'),
    Path('/var/lib/dhcp/dhcpd.leases'),
]

SERVICE_TARGETS = {
    'control-daemon': 'azazel-edge-control-daemon',
    'ai-agent': 'azazel-edge-ai-agent',
    'web': 'azazel-edge-web',
    'suricata': 'suricata',
    'opencanary': 'opencanary',
}
EXTERNAL_PATH_TARGETS = ('1.1.1.1', '8.8.8.8')
DEFAULT_RESOLUTION_TARGETS = ('example.com', 'openai.com')
DEFAULT_SERVICE_PROBE_TARGETS = (
    {'name': 'resolver-tcp', 'probe': 'tcp', 'host': '1.1.1.1', 'port': 53, 'timeout_sec': 2.0},
    {'name': 'https-head', 'probe': 'http', 'url': 'https://example.com', 'method': 'HEAD', 'timeout_sec': 3.0},
)


# Explicit upper bound for each collector of one NOC collection, so a
# collection always ends (Edge#414 SO-02). The bounds sit well above what each
# collector takes when healthy; the per-call timeouts inside the collectors
# (ping -W 2, subprocess timeouts, socket timeouts) still apply first. A
# collector that overruns is reported as a collector failure with its default
# value, exactly as one that raised -- except path_probes, which runs one
# thread per interface and, on overrun, keeps the rows collected and reports
# the rest unreachable (collect_path_probes_bounded), so a timeout can never
# look healthier than the probes failing. Name resolution has its own bound
# (collect_dns_resolution timeout_sec, 5 s per name).
COLLECTOR_TIMEOUTS_S: Dict[str, float] = {
    'iface_stats': 3.0,
    'path_probes': 30.0,
    'resolution_probes': 15.0,
    'service_probes': 10.0,
    'icmp': 6.0,
    'cpu_mem_temp': 3.0,
    'dhcp_leases': 3.0,
    'arp_table': 8.0,
    'service_health': 25.0,
}
DEFAULT_COLLECTOR_TIMEOUT_S = 10.0
# Bound for the targeted re-evaluation of one interface after a link change:
# its path probes run concurrently, each already bounded by ping -W 2 and a
# 4 s subprocess timeout.
INTERFACE_REFRESH_TIMEOUT_S = 5.0


MAX_TRACKED_REFRESHES = 32


def _apply_refreshes(snapshot: Dict[str, Any], refreshes: Dict[str, Dict[str, Any]], iface_stats: Optional[Dict[str, Any]], since_ns: int) -> Optional[int]:
    """Replace, in ``snapshot``, the path-probe rows of every interface whose
    link-event refresh started after ``since_ns`` (each by its own stamp), and
    the interface stats if their refresh did. Returns the newest stamp
    applied, or None if nothing was newer."""

    newer = {iface: r for iface, r in refreshes.items() if int(r.get('started_ns') or 0) > since_ns}
    applied = [int(r['started_ns']) for r in newer.values()]
    if newer:
        rows = [r for r in (snapshot.get('path_probes') or []) if not (isinstance(r, dict) and r.get('interface') in newer)]
        for iface in sorted(newer):
            rows.extend(newer[iface].get('path_probes') or [])
        snapshot['path_probes'] = rows
    if isinstance(iface_stats, dict) and int(iface_stats.get('started_ns') or 0) > since_ns and isinstance(iface_stats.get('rows'), list):
        snapshot['iface_stats'] = iface_stats['rows']
        applied.append(int(iface_stats['started_ns']))
    return max(applied) if applied else None


class CollectorTimeout(Exception):
    pass


class _BoundedRunner:
    """Run a collector with an upper bound on how long the caller waits.

    Python cannot cancel a thread, so an overrunning collector keeps running
    in the background; while it does, the next call for the same collector
    fails at once instead of starting another, so at most one stray thread
    exists per collector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inflight: Dict[str, threading.Thread] = {}

    def run(self, name: str, func: Callable[[], Any], timeout_s: float) -> Any:
        with self._lock:
            stray = self._inflight.get(name)
            if stray is not None and stray.is_alive():
                raise CollectorTimeout(f'{name}: previous run still in progress after its {timeout_s}s bound')
            self._inflight.pop(name, None)
        box: Dict[str, Any] = {}

        def target() -> None:
            try:
                box['value'] = func()
            except BaseException as exc:  # handed back to the caller
                box['error'] = exc

        thread = threading.Thread(target=target, name=f'noc-collector-{name}', daemon=True)
        thread.start()
        thread.join(max(0.0, float(timeout_s)))
        if thread.is_alive():
            with self._lock:
                self._inflight[name] = thread
            raise CollectorTimeout(f'{name}: timed out after {timeout_s}s')
        if 'error' in box:
            raise box['error']
        return box.get('value')


def _run(cmd: List[str], timeout: float = 3.0) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.stdout or ''


def _default_icmp_target(gateway_ip: str) -> str:
    gateway_ip = str(gateway_ip or '').strip()
    if gateway_ip:
        return gateway_ip
    try:
        out = _run(['ip', 'route', 'show', 'default'], timeout=2)
    except Exception:
        out = ''
    for line in out.splitlines():
        parts = line.split()
        if 'via' in parts:
            return parts[parts.index('via') + 1]
    return '1.1.1.1'


def collect_icmp(target: str, interface: str = '') -> Dict[str, Any]:
    cmd = ['ping', '-n', '-c', '1', '-W', '2']
    if interface:
        cmd.extend(['-I', interface])
    cmd.append(target)
    started = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
    elapsed_ms = round((time.time() - started) * 1000.0, 1)
    stdout = proc.stdout or ''
    latency_ms = None
    match = re.search(r'time=([0-9.]+)\s*ms', stdout)
    if match:
        try:
            latency_ms = float(match.group(1))
        except Exception:
            latency_ms = None
    return {
        'target': target,
        'interface': interface,
        'reachable': proc.returncode == 0,
        'latency_ms': latency_ms,
        'duration_ms': elapsed_ms,
        'raw': stdout.strip().splitlines()[-1] if stdout.strip() else '',
    }


def collect_path_probes(gateway_ip: str, interface: str = '') -> List[Dict[str, Any]]:
    probes: List[Dict[str, Any]] = []
    gateway = _default_icmp_target(gateway_ip)
    if gateway:
        row = collect_icmp(gateway, interface=interface)
        row['scope'] = 'gateway'
        probes.append(row)
    for target in EXTERNAL_PATH_TARGETS:
        row = collect_icmp(target, interface=interface)
        row['scope'] = 'external'
        probes.append(row)
    return probes


def collect_path_probes_multi(gateway_ip: str, interfaces: Iterable[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for interface in interfaces:
        iface = str(interface or '').strip()
        if not iface or iface in seen:
            continue
        seen.add(iface)
        rows.extend(collect_path_probes(gateway_ip, interface=iface))
    if not rows:
        rows.extend(collect_path_probes(gateway_ip, interface=''))
    return rows


def collect_path_probes_bounded(
    gateway_ip: str,
    interfaces: Iterable[str],
    timeout_s: float,
) -> tuple[List[Dict[str, Any]], List[str]]:
    """The path probes of every interface, one interface per thread, bounded.

    Each interface runs exactly what ``collect_path_probes`` runs for it. An
    interface whose probes have not finished within ``timeout_s`` contributes
    one row per expected target with ``reachable: False`` and
    ``error: 'collector_timeout'`` -- an overrun reads as unreachable, never
    as missing (a missing row would look healthier than a failed one).
    An interface whose probes raised gets the same rows with
    ``error: 'collector_error: ...'``. Returns (rows, problems), one problem
    string per interface that timed out or raised. Stray threads end on their
    own: every ping is bounded by its 4 s subprocess timeout."""

    ifaces: List[str] = []
    for interface in interfaces:
        iface = str(interface or '').strip()
        if iface and iface not in ifaces:
            ifaces.append(iface)
    if not ifaces:
        ifaces = ['']
    results: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, BaseException] = {}

    def run(iface: str) -> None:
        try:
            results[iface] = collect_path_probes(gateway_ip, interface=iface)
        except BaseException as exc:  # handed back to the caller
            errors[iface] = exc

    deadline = time.monotonic() + max(0.0, float(timeout_s))
    threads = [threading.Thread(target=run, args=(i,), name=f'noc-path-{i or "default"}', daemon=True) for i in ifaces]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0.0, deadline - time.monotonic()))
    done = dict(results)
    failed = dict(errors)
    if failed and not done and len(failed) == len(ifaces):
        raise next(iter(failed.values()))
    rows: List[Dict[str, Any]] = []
    problems: List[str] = []
    gateway = ''
    for iface in ifaces:
        if iface in done:
            rows.extend(done[iface])
            continue
        problems.append(f'{iface or "default"}: ' + (f'timed out after {timeout_s}s' if iface not in failed else str(failed[iface])))
        if not gateway:
            try:
                gateway = _default_icmp_target(gateway_ip)
            except Exception:
                gateway = str(gateway_ip or '')
        expected = ([(gateway, 'gateway')] if gateway else []) + [(t, 'external') for t in EXTERNAL_PATH_TARGETS]
        reason = 'collector_timeout' if iface not in failed else f'collector_error: {failed[iface]}'
        for target, scope in expected:
            rows.append({
                'target': target,
                'interface': iface,
                'reachable': False,
                'latency_ms': None,
                'duration_ms': None,
                'raw': '',
                'scope': scope,
                'error': reason,
            })
    return rows, problems


def collect_iface_stats(interfaces: Iterable[str]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for iface in sorted({str(x).strip() for x in interfaces if str(x).strip()}):
        base = Path('/sys/class/net') / iface
        if not base.exists():
            raise FileNotFoundError(f'interface not found: {iface}')
        row: Dict[str, Any] = {
            'interface': iface,
            'operstate': (base / 'operstate').read_text(encoding='utf-8').strip() if (base / 'operstate').exists() else '',
            'carrier': int((base / 'carrier').read_text(encoding='utf-8').strip()) if (base / 'carrier').exists() else 0,
            'mtu': int((base / 'mtu').read_text(encoding='utf-8').strip()) if (base / 'mtu').exists() else 0,
            'mac': (base / 'address').read_text(encoding='utf-8').strip().lower() if (base / 'address').exists() else '',
            'speed_mbps': int(get_link_speed_mbps(iface) or 0),
        }
        row.update(get_network_stats(iface))
        rows.append(row)
    return rows


def collect_cpu_mem_temp() -> Dict[str, Any]:
    return {
        'cpu_percent': get_cpu_usage(),
        'memory': get_memory_usage(),
        'temperature_c': get_cpu_temperature(),
    }


def collect_dhcp_leases(paths: Optional[List[Path]] = None) -> List[Dict[str, str]]:
    leases: List[Dict[str, str]] = []
    for path in paths or DEFAULT_DHCP_LEASE_PATHS:
        if not path.exists():
            continue
        for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 4 and parts[1].count(':') >= 5:
                leases.append({
                    'expiry': parts[0],
                    'mac': parts[1].lower(),
                    'ip': parts[2],
                    'hostname': parts[3],
                    'source': str(path),
                })
    return leases


def collect_bridge_fdb_ports() -> Dict[str, str]:
    rows: Dict[str, str] = {}
    out = _run(['bridge', 'fdb', 'show'], timeout=2)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3 or 'dev' not in parts:
            continue
        mac = str(parts[0] or '').strip().lower()
        if not mac or mac == '00:00:00:00:00:00':
            continue
        if 'self' in parts or 'permanent' in parts and 'master' not in parts:
            continue
        try:
            dev = parts[parts.index('dev') + 1]
        except Exception:
            continue
        if dev.startswith('br-') or dev.startswith('veth') or dev.startswith('docker'):
            continue
        if mac not in rows:
            rows[mac] = dev
    return rows


def collect_wifi_station_macs(interface: str = 'wlan0') -> set[str]:
    stations: set[str] = set()
    out = _run(['iw', 'dev', interface, 'station', 'dump'], timeout=2)
    for line in out.splitlines():
        line = line.strip()
        if not line.lower().startswith('station '):
            continue
        parts = line.split()
        if len(parts) >= 2:
            stations.add(parts[1].strip().lower())
    return stations


def collect_arp_table() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    bridge_ports = collect_bridge_fdb_ports()
    managed_bridge = str(os.environ.get('AZAZEL_INTERNAL_BRIDGE_IF', 'br0')).strip()
    managed_eth = str(os.environ.get('AZAZEL_INTERNAL_ETH_IF', 'eth0')).strip()
    managed_wlan = str(os.environ.get('AZAZEL_INTERNAL_WLAN_IF', 'wlan0')).strip()
    wifi_station_macs = collect_wifi_station_macs(managed_wlan) if managed_wlan else set()
    out = _run(['ip', 'neigh', 'show'], timeout=2)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        row = {'ip': parts[0], 'dev': '', 'mac': '', 'state': parts[-1]}
        if 'dev' in parts:
            row['dev'] = parts[parts.index('dev') + 1]
        if 'lladdr' in parts:
            row['mac'] = parts[parts.index('lladdr') + 1].lower()
        if row['mac']:
            bridge_port = bridge_ports.get(row['mac'], '')
            if not bridge_port and row['dev'] == managed_bridge:
                if row['mac'] in wifi_station_macs and managed_wlan:
                    bridge_port = managed_wlan
                elif managed_eth:
                    bridge_port = managed_eth
            if bridge_port:
                row['bridge_port'] = bridge_port
        rows.append(row)
    return rows


def collect_service_health(targets: Dict[str, str] = SERVICE_TARGETS) -> Dict[str, Dict[str, str]]:
    result: Dict[str, Dict[str, str]] = {}
    for alias, unit in targets.items():
        proc = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=2)
        state = (proc.stdout or '').strip() or 'unknown'
        show = subprocess.run(
            ['systemctl', 'show', unit, '--property=SubState,Result', '--value'],
            capture_output=True,
            text=True,
            timeout=2,
        )
        rows = [line.strip() for line in (show.stdout or '').splitlines()]
        result[alias] = {
            'target': alias,
            'unit': unit,
            'state': 'ON' if state == 'active' else 'OFF',
            'detail': state,
            'substate': rows[0] if len(rows) >= 1 and rows[0] else 'unknown',
            'result': rows[1] if len(rows) >= 2 and rows[1] else 'unknown',
        }
    return result


def _getaddrinfo_bounded(name: str, timeout_sec: float) -> List[Any]:
    """socket.getaddrinfo with a bound on the wait: the resolver's own
    retries (resolv.conf timeout x attempts) can take far longer than
    ``timeout_sec``. An overrun raises like any resolution failure."""

    box: Dict[str, Any] = {}

    def target() -> None:
        try:
            box['value'] = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
        except BaseException as exc:
            box['error'] = exc

    thread = threading.Thread(target=target, name='noc-dns', daemon=True)
    thread.start()
    thread.join(max(0.0, float(timeout_sec)))
    if thread.is_alive():
        raise TimeoutError(f'resolution timed out after {timeout_sec}s')
    if 'error' in box:
        raise box['error']
    return box.get('value') or []


def collect_dns_resolution(name: str, timeout_sec: float = 5.0) -> Dict[str, Any]:
    started = time.time()
    try:
        answers = _getaddrinfo_bounded(name, timeout_sec)
        latency_ms = round((time.time() - started) * 1000.0, 1)
        resolved = sorted({str(item[4][0]) for item in answers if item and len(item) >= 5 and item[4]})
        return {
            'name': name,
            'resolved': bool(resolved),
            'answers': resolved[:4],
            'latency_ms': latency_ms,
            'error': '',
            'probe': 'dns',
        }
    except Exception as exc:
        return {
            'name': name,
            'resolved': False,
            'answers': [],
            'latency_ms': round((time.time() - started) * 1000.0, 1),
            'error': str(exc),
            'probe': 'dns',
        }


def collect_tcp_connect(host: str, port: int, timeout_sec: float = 2.0) -> Dict[str, Any]:
    started = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_sec):
            pass
        return {
            'target': f'{host}:{int(port)}',
            'host': host,
            'port': int(port),
            'reachable': True,
            'latency_ms': round((time.time() - started) * 1000.0, 1),
            'error': '',
            'probe': 'tcp',
        }
    except Exception as exc:
        return {
            'target': f'{host}:{int(port)}',
            'host': host,
            'port': int(port),
            'reachable': False,
            'latency_ms': round((time.time() - started) * 1000.0, 1),
            'error': str(exc),
            'probe': 'tcp',
        }


def collect_http_probe(url: str, method: str = 'HEAD', timeout_sec: float = 3.0) -> Dict[str, Any]:
    started = time.time()
    parsed = urlparse(str(url or '').strip())
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return {
            'target': url,
            'url': url,
            'reachable': False,
            'status_code': 0,
            'latency_ms': 0.0,
            'error': 'invalid_url',
            'probe': 'http',
            'method': method,
        }
    request = Request(url=str(url), method=str(method or 'HEAD').upper())
    try:
        with urlopen(request, timeout=timeout_sec) as response:
            code = int(getattr(response, 'status', 0) or 0)
        return {
            'target': url,
            'url': url,
            'reachable': 200 <= code < 500,
            'status_code': code,
            'latency_ms': round((time.time() - started) * 1000.0, 1),
            'error': '',
            'probe': 'http',
            'method': method,
        }
    except Exception as exc:
        return {
            'target': url,
            'url': url,
            'reachable': False,
            'status_code': 0,
            'latency_ms': round((time.time() - started) * 1000.0, 1),
            'error': str(exc),
            'probe': 'http',
            'method': method,
        }


def collect_service_probes(targets: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for target in targets:
        if not isinstance(target, dict):
            continue
        name = str(target.get('name') or target.get('target') or '').strip()
        probe = str(target.get('probe') or 'tcp').strip().lower()
        if probe == 'http':
            row = collect_http_probe(
                str(target.get('url') or ''),
                method=str(target.get('method') or 'HEAD'),
                timeout_sec=float(target.get('timeout_sec') or 3.0),
            )
        else:
            row = collect_tcp_connect(str(target.get('host') or ''), int(target.get('port') or 0), timeout_sec=float(target.get('timeout_sec') or 2.0))
        row['name'] = name or row.get('target') or probe
        rows.append(row)
    return rows


class LightweightNocMonitor:
    def __init__(
        self,
        up_interface: str = 'eth1',
        down_interface: str = 'usb0',
        gateway_ip: str = '',
        extra_interfaces: Optional[List[str]] = None,
        capacity_window_size: int = 4,
        probe_window_size: int = 4,
        elevated_utilization_pct: int = 70,
        congested_utilization_pct: int = 85,
        resolution_targets: Optional[List[str]] = None,
        service_probe_targets: Optional[List[Dict[str, Any]]] = None,
    ):
        if int(capacity_window_size) < 2:
            raise ValueError('capacity_window_size_must_be_at_least_2')
        if int(probe_window_size) < 2:
            raise ValueError('probe_window_size_must_be_at_least_2')
        if not (0 < int(elevated_utilization_pct) < int(congested_utilization_pct) <= 100):
            raise ValueError('invalid_capacity_thresholds')
        self.up_interface = up_interface
        self.down_interface = down_interface
        self.gateway_ip = gateway_ip
        self.extra_interfaces = [str(x).strip() for x in (extra_interfaces or []) if str(x).strip()]
        self.capacity_window_size = int(capacity_window_size)
        self.probe_window_size = int(probe_window_size)
        self.elevated_utilization_pct = int(elevated_utilization_pct)
        self.congested_utilization_pct = int(congested_utilization_pct)
        self.resolution_targets = [str(x).strip() for x in (resolution_targets or list(DEFAULT_RESOLUTION_TARGETS)) if str(x).strip()]
        self.service_probe_targets = [dict(x) for x in (service_probe_targets or list(DEFAULT_SERVICE_PROBE_TARGETS)) if isinstance(x, dict)]
        self._capacity_history: Dict[str, deque[float]] = {}
        self._last_iface_counters: Dict[str, Dict[str, Any]] = {}
        self._path_probe_history: Dict[str, deque[Dict[str, Any]]] = {}
        self._resolution_probe_history: Dict[str, deque[Dict[str, Any]]] = {}
        self._service_probe_history: Dict[str, deque[Dict[str, Any]]] = {}
        self.collector_timeouts_s = dict(COLLECTOR_TIMEOUTS_S)
        self._runner = _BoundedRunner()
        self._last_snapshot: Optional[Dict[str, Any]] = None
        # The rows of the latest link-event refresh of each interface (each
        # with its own start stamp), so a full collection that started before
        # them does not bring older rows for those interfaces back.
        self._refreshes: Dict[str, Dict[str, Any]] = {}
        self._refresh_iface_stats: Optional[Dict[str, Any]] = None
        self._refresh_lock = threading.Lock()

    def monitored_interfaces(self) -> List[str]:
        seen: List[str] = []
        for iface in [self.up_interface, self.down_interface, *self.extra_interfaces]:
            iface = str(iface or '').strip()
            if iface and iface not in seen:
                seen.append(iface)
        return seen

    @staticmethod
    def _safe_counter_delta(current: int, previous: int) -> Optional[int]:
        curr = int(current or 0)
        prev = int(previous or 0)
        if curr < prev:
            return None
        return curr - prev

    def _compute_capacity_view(self, iface_stats: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        now = time.time()
        samples: List[Dict[str, Any]] = []
        pressure: List[Dict[str, Any]] = []
        for row in iface_stats:
            iface = str(row.get('interface') or '').strip()
            if not iface:
                continue
            speed_mbps = int(row.get('speed_mbps') or 0)
            prev = self._last_iface_counters.get(iface)
            sample = {
                'interface': iface,
                'speed_mbps': speed_mbps,
                'rx_bps': 0.0,
                'tx_bps': 0.0,
                'rx_pps': 0.0,
                'tx_pps': 0.0,
                'utilization_pct': None,
                'mode': 'utilization_known' if speed_mbps > 0 else 'utilization_unknown_rate_only',
                'sample_state': 'warmup',
            }
            if prev and float(now - float(prev.get('ts') or now)) > 0:
                interval = float(now - float(prev.get('ts') or now))
                rx_diff = self._safe_counter_delta(int(row.get('rx_bytes') or 0), int(prev.get('rx_bytes') or 0))
                tx_diff = self._safe_counter_delta(int(row.get('tx_bytes') or 0), int(prev.get('tx_bytes') or 0))
                rx_pkt_diff = self._safe_counter_delta(int(row.get('rx_packets') or 0), int(prev.get('rx_packets') or 0))
                tx_pkt_diff = self._safe_counter_delta(int(row.get('tx_packets') or 0), int(prev.get('tx_packets') or 0))
                if None in {rx_diff, tx_diff, rx_pkt_diff, tx_pkt_diff}:
                    sample['sample_state'] = 'counter_reset'
                else:
                    sample['rx_bps'] = round((int(rx_diff) * 8) / interval, 2)
                    sample['tx_bps'] = round((int(tx_diff) * 8) / interval, 2)
                    sample['rx_pps'] = round(int(rx_pkt_diff) / interval, 2)
                    sample['tx_pps'] = round(int(tx_pkt_diff) / interval, 2)
                    sample['sample_state'] = 'sampled'
                    if speed_mbps > 0:
                        utilization = (max(sample['rx_bps'], sample['tx_bps']) / float(speed_mbps * 1_000_000)) * 100.0
                        sample['utilization_pct'] = round(max(0.0, utilization), 2)
            history = self._capacity_history.setdefault(iface, deque(maxlen=self.capacity_window_size))
            if isinstance(sample.get('utilization_pct'), (int, float)):
                history.append(float(sample['utilization_pct']))
            state = 'unknown'
            avg_utilization = None
            peak_utilization = None
            if history:
                avg_utilization = round(sum(history) / len(history), 2)
                peak_utilization = round(max(history), 2)
                if peak_utilization >= self.congested_utilization_pct and avg_utilization >= self.elevated_utilization_pct:
                    state = 'congested'
                elif peak_utilization >= self.elevated_utilization_pct or avg_utilization >= self.elevated_utilization_pct:
                    state = 'elevated'
                else:
                    state = 'normal'
            pressure.append({
                'interface': iface,
                'mode': sample['mode'],
                'state': state,
                'window_size': self.capacity_window_size,
                'samples_seen': len(history),
                'avg_utilization_pct': avg_utilization,
                'peak_utilization_pct': peak_utilization,
                'speed_mbps': speed_mbps,
                'rx_bps': sample['rx_bps'],
                'tx_bps': sample['tx_bps'],
            })
            samples.append(sample)
            self._last_iface_counters[iface] = {
                'ts': now,
                'rx_bytes': int(row.get('rx_bytes') or 0),
                'tx_bytes': int(row.get('tx_bytes') or 0),
                'rx_packets': int(row.get('rx_packets') or 0),
                'tx_packets': int(row.get('tx_packets') or 0),
            }
        return samples, pressure

    @staticmethod
    def _latency_summary(history: deque[Dict[str, Any]]) -> tuple[Optional[float], Optional[float]]:
        latencies = sorted(
            float(item.get('latency_ms'))
            for item in history
            if isinstance(item.get('latency_ms'), (int, float)) and float(item.get('latency_ms')) >= 0.0
        )
        if not latencies:
            return None, None
        median_latency = round(float(statistics.median(latencies)), 2)
        p95_index = max(0, min(len(latencies) - 1, int((len(latencies) - 1) * 0.95)))
        return median_latency, round(float(latencies[p95_index]), 2)

    def _record_probe_window(
        self,
        rows: List[Dict[str, Any]],
        history_store: Dict[str, deque[Dict[str, Any]]],
        key_builder: Callable[[Dict[str, Any]], str],
        success_field: str,
        classify: Callable[[float, int], str],
    ) -> List[Dict[str, Any]]:
        summaries: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            key = key_builder(row)
            if not key:
                continue
            history = history_store.setdefault(key, deque(maxlen=self.probe_window_size))
            history.append({
                'ok': bool(row.get(success_field)),
                'latency_ms': row.get('latency_ms'),
            })
            sample_count = len(history)
            success_count = sum(1 for item in history if bool(item.get('ok')))
            success_ratio_pct = round((success_count / sample_count) * 100.0, 2) if sample_count else 0.0
            median_latency_ms, p95_latency_ms = self._latency_summary(history)
            summary = dict(row)
            summary.update({
                'window_size': self.probe_window_size,
                'samples_seen': sample_count,
                'success_ratio_pct': success_ratio_pct,
                'loss_pct': round(100.0 - success_ratio_pct, 2),
                'median_latency_ms': median_latency_ms,
                'p95_latency_ms': p95_latency_ms,
                'state': classify(success_ratio_pct, sample_count),
            })
            summaries.append(summary)
        return summaries

    def _compute_path_probe_window(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self._record_probe_window(
            rows,
            self._path_probe_history,
            lambda row: f"{str(row.get('interface') or '-')}/{str(row.get('scope') or '-')}/{str(row.get('target') or '-')}",
            'reachable',
            lambda ratio, count: 'unknown' if count < 1 else ('normal' if ratio >= 100.0 else ('degraded' if ratio >= 50.0 else 'down')),
        )

    def _compute_resolution_probe_window(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self._record_probe_window(
            rows,
            self._resolution_probe_history,
            lambda row: str(row.get('name') or ''),
            'resolved',
            lambda ratio, count: 'unknown' if count < 1 else ('healthy' if ratio >= 100.0 else ('degraded' if ratio >= 50.0 else 'failed')),
        )

    def _compute_service_probe_window(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self._record_probe_window(
            rows,
            self._service_probe_history,
            lambda row: str(row.get('name') or row.get('target') or ''),
            'reachable',
            lambda ratio, count: 'unknown' if count < 1 else ('healthy' if ratio >= 100.0 else ('degraded' if ratio >= 50.0 else 'down')),
        )

    def collect_snapshot(self) -> Dict[str, Any]:
        failures: List[Dict[str, str]] = []
        timings: List[Dict[str, Any]] = []
        collection_started_ns = time.monotonic_ns()

        def timed(name: str, func: Callable[[], Any]) -> Any:
            # Diagnostic only: when each collector started (offset from the
            # start of this collection) and how long it ran, on CLOCK_MONOTONIC.
            # Never read by any evaluator; exceptions propagate unchanged.
            started = time.monotonic_ns()
            outcome = 'error'
            try:
                value = func()
                outcome = 'ok'
                return value
            finally:
                ended = time.monotonic_ns()
                timings.append({
                    'collector': name,
                    'started_offset_ms': round((started - collection_started_ns) / 1e6, 1),
                    'duration_ms': round((ended - started) / 1e6, 1),
                    'outcome': outcome,
                })

        def capture(name: str, func: Callable[[], Any], default: Any) -> Any:
            bound = float(self.collector_timeouts_s.get(name, DEFAULT_COLLECTOR_TIMEOUT_S))
            try:
                return timed(name, lambda: self._runner.run(name, func, bound))
            except Exception as exc:
                failures.append({'collector': name, 'error': str(exc)})
                if isinstance(exc, CollectorTimeout) and timings and timings[-1]['collector'] == name:
                    timings[-1]['outcome'] = 'timeout'
                return default

        icmp_target = timed('icmp_target', lambda: _default_icmp_target(self.gateway_ip))
        iface_stats = capture(
            'iface_stats',
            lambda: collect_iface_stats([self.up_interface, self.down_interface]),
            [],
        )
        capacity_samples, capacity_pressure = self._compute_capacity_view(iface_stats if isinstance(iface_stats, list) else [])
        # Path probes bound themselves (one thread per interface) so an
        # overrun keeps the rows already collected and marks the rest
        # unreachable instead of dropping them all.
        path_bound = float(self.collector_timeouts_s.get('path_probes', DEFAULT_COLLECTOR_TIMEOUT_S))

        def path_probes_bounded() -> List[Dict[str, Any]]:
            rows, problems = collect_path_probes_bounded(
                self.gateway_ip,
                [self.up_interface, self.down_interface, *self.extra_interfaces],
                path_bound,
            )
            if problems:
                failures.append({'collector': 'path_probes', 'error': '; '.join(problems)})
                path_timed_out.extend(p for p in problems if 'timed out' in p)
            return rows

        path_timed_out: List[str] = []
        try:
            path_probes = timed('path_probes', path_probes_bounded)
        except Exception as exc:
            failures.append({'collector': 'path_probes', 'error': str(exc)})
            path_probes = []
        if path_timed_out and timings and timings[-1]['collector'] == 'path_probes':
            timings[-1]['outcome'] = 'timeout'
        resolution_probes = capture(
            'resolution_probes',
            lambda: [collect_dns_resolution(name) for name in self.resolution_targets],
            [],
        )
        service_probes = capture(
            'service_probes',
            lambda: collect_service_probes(self.service_probe_targets),
            [],
        )
        snapshot = {
            'icmp': capture('icmp', lambda: collect_icmp(icmp_target, self.up_interface), {}),
            'path_probes': path_probes,
            'path_probe_window': self._compute_path_probe_window(path_probes if isinstance(path_probes, list) else []),
            'iface_stats': iface_stats,
            'capacity_samples': capacity_samples,
            'capacity_pressure': capacity_pressure,
            'resolution_probes': resolution_probes,
            'resolution_probe_window': self._compute_resolution_probe_window(resolution_probes if isinstance(resolution_probes, list) else []),
            'service_probes': service_probes,
            'service_probe_window': self._compute_service_probe_window(service_probes if isinstance(service_probes, list) else []),
            'cpu_mem_temp': capture('cpu_mem_temp', collect_cpu_mem_temp, {}),
            'dhcp_leases': capture('dhcp_leases', collect_dhcp_leases, []),
            'arp_table': capture('arp_table', collect_arp_table, []),
            'service_health': capture('service_health', collect_service_health, {}),
            'collector_failures': failures,
        }
        snapshot['collection_timing'] = {
            'started_monotonic_ns': collection_started_ns,
            'duration_ms': round((time.monotonic_ns() - collection_started_ns) / 1e6, 1),
            'collectors': timings,
        }
        # Link-event refreshes that started while this collection ran: their
        # interface rows are newer than ours; everything else is ours.
        with self._refresh_lock:
            merged = _apply_refreshes(snapshot, dict(self._refreshes), self._refresh_iface_stats, collection_started_ns)
        if merged is not None:
            snapshot['collection_timing']['link_event_started_monotonic_ns'] = merged
        self._last_snapshot = snapshot
        return snapshot

    def refresh_interfaces(self, interfaces: Iterable[str]) -> Optional[Dict[str, Any]]:
        """Targeted re-evaluation after a link change on ``interfaces``.

        Re-reads the interface stats and re-runs the path probes of the
        changed monitored interfaces only (concurrently, bounded by
        ``INTERFACE_REFRESH_TIMEOUT_S``), and returns the last full snapshot
        with those rows replaced. Nothing else is re-collected and no rolling
        window or capacity history is touched: the windows stay the periodic
        loop's. None when there is no full snapshot yet or nothing monitored
        changed. The probes are the same ones the periodic loop runs.
        """

        base = self._last_snapshot
        monitored = self.monitored_interfaces()
        targets = [i for i in dict.fromkeys(str(x).strip() for x in interfaces) if i in monitored]
        if base is None or not targets:
            return None
        started_ns = time.monotonic_ns()
        deadline = time.monotonic() + INTERFACE_REFRESH_TIMEOUT_S
        failures: List[Dict[str, str]] = []
        timings: List[Dict[str, Any]] = []

        def stamp(name: str, t0: int, outcome: str) -> None:
            timings.append({
                'collector': name,
                'started_offset_ms': round((t0 - started_ns) / 1e6, 1),
                'duration_ms': round((time.monotonic_ns() - t0) / 1e6, 1),
                'outcome': outcome,
            })

        t0 = time.monotonic_ns()
        iface_stats: Any = base.get('iface_stats')
        try:
            iface_stats = collect_iface_stats([self.up_interface, self.down_interface])
            stamp('iface_stats', t0, 'ok')
        except Exception as exc:
            failures.append({'collector': 'iface_stats', 'error': str(exc)})
            stamp('iface_stats', t0, 'error')

        t0 = time.monotonic_ns()
        # The probes collect_path_probes runs for one interface (gateway, then
        # the external targets), here run concurrently so a down link costs
        # one ping timeout rather than one per target.
        probes: List[tuple] = []
        try:
            gateway = _default_icmp_target(self.gateway_ip)
        except Exception:
            gateway = ''
        for iface in targets:
            if gateway:
                probes.append((iface, gateway, 'gateway'))
            probes.extend((iface, target, 'external') for target in EXTERNAL_PATH_TARGETS)
        results: Dict[int, Dict[str, Any]] = {}
        errors: Dict[str, str] = {}

        def probe(index: int, iface: str, target: str, scope: str) -> None:
            try:
                row = collect_icmp(target, interface=iface)
                row['scope'] = scope
                results[index] = row
            except Exception as exc:
                errors[iface] = str(exc)

        threads = [
            threading.Thread(target=probe, args=(n, *p), name=f'noc-refresh-{p[0]}', daemon=True)
            for n, p in enumerate(probes)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        done = dict(results)
        refreshed = [
            i for i in targets
            if i not in errors and all(n in done for n, p in enumerate(probes) if p[0] == i)
        ]
        for iface in targets:
            if iface in errors:
                failures.append({'collector': 'path_probes', 'error': f'{iface}: {errors[iface]}'})
            elif iface not in refreshed:
                failures.append({'collector': 'path_probes', 'error': f'{iface}: timed out after {INTERFACE_REFRESH_TIMEOUT_S}s'})
        stamp('path_probes', t0, 'ok' if len(refreshed) == len(targets) else ('timeout' if not errors else 'error'))

        rows = [r for r in (base.get('path_probes') or []) if not (isinstance(r, dict) and r.get('interface') in refreshed)]
        for n, p in enumerate(probes):
            if p[0] in refreshed:
                rows.append(done[n])
        snapshot = dict(base)
        snapshot['path_probes'] = rows
        snapshot['iface_stats'] = iface_stats
        with self._refresh_lock:
            for iface in refreshed:
                self._refreshes[iface] = {
                    'started_ns': started_ns,
                    'path_probes': [done[n] for n, p in enumerate(probes) if p[0] == iface],
                }
            if not any(f['collector'] == 'iface_stats' for f in failures):
                self._refresh_iface_stats = {'started_ns': started_ns, 'rows': iface_stats}
            # Bounded: only monitored interfaces, at most MAX_TRACKED_REFRESHES.
            for iface in [i for i in self._refreshes if i not in monitored]:
                del self._refreshes[iface]
            while len(self._refreshes) > MAX_TRACKED_REFRESHES:
                del self._refreshes[min(self._refreshes, key=lambda i: self._refreshes[i]['started_ns'])]
            # Earlier refreshes of other interfaces since the base collection
            # stay in this result too.
            base_started = (base.get('collection_timing') or {}).get('started_monotonic_ns') if isinstance(base.get('collection_timing'), dict) else None
            others = {i: r for i, r in self._refreshes.items() if i not in refreshed}
            if isinstance(base_started, int) and others:
                _apply_refreshes(snapshot, others, None, base_started)
        rerun = {'iface_stats'} if not any(f['collector'] == 'iface_stats' for f in failures) else set()
        snapshot['collector_failures'] = [
            f for f in (base.get('collector_failures') or []) if not (isinstance(f, dict) and f.get('collector') in rerun)
        ] + failures
        snapshot['collection_timing'] = {
            'started_monotonic_ns': started_ns,
            'duration_ms': round((time.monotonic_ns() - started_ns) / 1e6, 1),
            'collectors': timings,
            'interfaces': targets,
        }
        return snapshot
