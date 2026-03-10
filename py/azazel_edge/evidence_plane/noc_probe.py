from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from azazel_edge.sensors.network_health import NetworkHealthMonitor
from azazel_edge.sensors.system_metrics import collect_all_metrics

from .schema import EvidenceEvent, iso_utc_now

DEFAULT_DHCP_LEASE_PATHS = [
    Path('/var/lib/misc/dnsmasq.leases'),
    Path('/var/lib/dhcp/dhcpd.leases'),
]
SERVICE_NAMES = ('azazel-edge-control-daemon', 'azazel-edge-ai-agent', 'azazel-edge-web', 'suricata', 'opencanary')


def _run(cmd: List[str], timeout: float = 3.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout or ''
    except Exception:
        return ''


def _service_health(names: Iterable[str] = SERVICE_NAMES) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name in names:
        try:
            proc = subprocess.run(['systemctl', 'is-active', name], capture_output=True, text=True, timeout=2)
            state = (proc.stdout or '').strip()
            result[name] = 'ON' if state == 'active' else 'OFF'
        except Exception:
            result[name] = 'OFF'
    return result


def _dhcp_leases(paths: Optional[List[Path]] = None) -> List[Dict[str, str]]:
    leases: List[Dict[str, str]] = []
    for path in paths or DEFAULT_DHCP_LEASE_PATHS:
        if not path.exists():
            continue
        try:
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
        except Exception:
            continue
    return leases


def _arp_table() -> List[Dict[str, str]]:
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


def _host_subject() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return 'azazel-edge'


def _network_severity(status: str, signals: List[str]) -> int:
    s = str(status or '').upper()
    if s == 'RISKY':
        return 80
    if s == 'SUSPECTED':
        return 55
    if s == 'NA':
        return 35
    return 10 if signals else 0


def _system_severity(metrics: Dict[str, Any]) -> int:
    cpu = float(metrics.get('cpu_percent') or 0.0)
    mem = int((metrics.get('memory') or {}).get('percent') or 0)
    temp = float(metrics.get('temperature_c') or 0.0)
    severity = 0
    if cpu >= 90:
        severity = max(severity, 60)
    elif cpu >= 75:
        severity = max(severity, 35)
    if mem >= 90:
        severity = max(severity, 80)
    elif mem >= 75:
        severity = max(severity, 45)
    if temp >= 80:
        severity = max(severity, 70)
    elif temp >= 65:
        severity = max(severity, 30)
    return severity


class NocProbeAdapter:
    def __init__(self, up_interface: str = 'eth1', down_interface: str = 'usb0', gateway_ip: str = ''):
        self.up_interface = up_interface
        self.down_interface = down_interface
        self.gateway_ip = gateway_ip
        self.network_monitor = NetworkHealthMonitor()

    def collect_snapshot(self) -> Dict[str, Any]:
        collector_failures: List[Dict[str, str]] = []

        try:
            network_health = self.network_monitor.assess(self.up_interface, self.gateway_ip)
        except Exception as exc:
            network_health = {}
            collector_failures.append({'collector': 'network_health', 'error': str(exc)})

        try:
            system_metrics = collect_all_metrics(up_interface=self.up_interface, down_interface=self.down_interface)
        except Exception as exc:
            system_metrics = {}
            collector_failures.append({'collector': 'system_metrics', 'error': str(exc)})

        try:
            service_health = _service_health()
        except Exception as exc:
            service_health = {}
            collector_failures.append({'collector': 'service_health', 'error': str(exc)})

        try:
            dhcp_leases = _dhcp_leases()
        except Exception as exc:
            dhcp_leases = []
            collector_failures.append({'collector': 'dhcp_leases', 'error': str(exc)})

        try:
            arp_table = _arp_table()
        except Exception as exc:
            arp_table = []
            collector_failures.append({'collector': 'arp_table', 'error': str(exc)})

        return {
            'network_health': network_health,
            'system_metrics': system_metrics,
            'service_health': service_health,
            'dhcp_leases': dhcp_leases,
            'arp_table': arp_table,
            'collector_failures': collector_failures,
        }

    def adapt_snapshot(self, snapshot: Dict[str, Any]) -> List[EvidenceEvent]:
        events: List[EvidenceEvent] = []
        ts = iso_utc_now()
        host = _host_subject()

        network_health = snapshot.get('network_health') if isinstance(snapshot.get('network_health'), dict) else {}
        if network_health:
            iface = str(network_health.get('iface') or self.up_interface or host)
            signals = network_health.get('signals') if isinstance(network_health.get('signals'), list) else []
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='network_health',
                subject=iface,
                severity=_network_severity(str(network_health.get('status') or ''), [str(x) for x in signals]),
                confidence=0.9,
                attrs=network_health,
                status=str(network_health.get('status') or '').lower(),
            ))

        system_metrics = snapshot.get('system_metrics') if isinstance(snapshot.get('system_metrics'), dict) else {}
        if system_metrics:
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='system_health',
                subject=host,
                severity=_system_severity(system_metrics),
                confidence=0.85,
                attrs=system_metrics,
                status='warn' if _system_severity(system_metrics) > 0 else 'ok',
            ))

        service_health = snapshot.get('service_health') if isinstance(snapshot.get('service_health'), dict) else {}
        for service, state in sorted(service_health.items()):
            sev = 0 if str(state).upper() == 'ON' else 70
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='service_health',
                subject=service,
                severity=sev,
                confidence=0.95,
                attrs={'service': service, 'state': state},
                status='ok' if sev == 0 else 'fail',
            ))

        dhcp_leases = snapshot.get('dhcp_leases') if isinstance(snapshot.get('dhcp_leases'), list) else []
        for lease in dhcp_leases:
            if not isinstance(lease, dict):
                continue
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='dhcp_lease',
                subject=str(lease.get('ip') or lease.get('mac') or host),
                severity=0,
                confidence=0.9,
                attrs=lease,
                status='info',
            ))

        arp_entries = snapshot.get('arp_table') if isinstance(snapshot.get('arp_table'), list) else []
        for entry in arp_entries:
            if not isinstance(entry, dict):
                continue
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='arp_entry',
                subject=str(entry.get('ip') or entry.get('mac') or host),
                severity=0,
                confidence=0.85,
                attrs=entry,
                status='info',
            ))

        failures = snapshot.get('collector_failures') if isinstance(snapshot.get('collector_failures'), list) else []
        for failure in failures:
            if not isinstance(failure, dict):
                continue
            collector = str(failure.get('collector') or 'unknown')
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='collector_failure',
                subject=collector,
                severity=45,
                confidence=1.0,
                attrs=failure,
                status='warn',
            ))
        return events

    def collect(self, snapshot: Optional[Dict[str, Any]] = None) -> List[EvidenceEvent]:
        return self.adapt_snapshot(snapshot if isinstance(snapshot, dict) else self.collect_snapshot())
