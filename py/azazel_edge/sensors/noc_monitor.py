from __future__ import annotations

import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from .system_metrics import (
    get_cpu_temperature,
    get_cpu_usage,
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


def collect_arp_table() -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
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


class LightweightNocMonitor:
    def __init__(
        self,
        up_interface: str = 'eth1',
        down_interface: str = 'usb0',
        gateway_ip: str = '',
    ):
        self.up_interface = up_interface
        self.down_interface = down_interface
        self.gateway_ip = gateway_ip

    def collect_snapshot(self) -> Dict[str, Any]:
        failures: List[Dict[str, str]] = []

        def capture(name: str, func: Callable[[], Any], default: Any) -> Any:
            try:
                return func()
            except Exception as exc:
                failures.append({'collector': name, 'error': str(exc)})
                return default

        icmp_target = _default_icmp_target(self.gateway_ip)
        snapshot = {
            'icmp': capture('icmp', lambda: collect_icmp(icmp_target, self.up_interface), {}),
            'path_probes': capture('path_probes', lambda: collect_path_probes(self.gateway_ip, self.up_interface), []),
            'iface_stats': capture(
                'iface_stats',
                lambda: collect_iface_stats([self.up_interface, self.down_interface]),
                [],
            ),
            'cpu_mem_temp': capture('cpu_mem_temp', collect_cpu_mem_temp, {}),
            'dhcp_leases': capture('dhcp_leases', collect_dhcp_leases, []),
            'arp_table': capture('arp_table', collect_arp_table, []),
            'service_health': capture('service_health', collect_service_health, {}),
            'collector_failures': failures,
        }
        return snapshot
