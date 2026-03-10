from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional

from azazel_edge.sensors.noc_monitor import LightweightNocMonitor

from .schema import EvidenceEvent, iso_utc_now


def _host_subject() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return 'azazel-edge'


def _icmp_severity(result: Dict[str, Any]) -> int:
    return 0 if bool(result.get('reachable')) else 70


def _iface_severity(row: Dict[str, Any]) -> int:
    oper = str(row.get('operstate') or '').lower()
    carrier = int(row.get('carrier') or 0)
    if oper == 'up' and carrier == 1:
        return 0
    if oper in {'unknown', 'dormant'}:
        return 20
    return 45


def _cpu_mem_temp_severity(metrics: Dict[str, Any]) -> int:
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
        self.monitor = LightweightNocMonitor(
            up_interface=up_interface,
            down_interface=down_interface,
            gateway_ip=gateway_ip,
        )

    def collect_snapshot(self) -> Dict[str, Any]:
        return self.monitor.collect_snapshot()

    def adapt_snapshot(self, snapshot: Dict[str, Any]) -> List[EvidenceEvent]:
        events: List[EvidenceEvent] = []
        ts = iso_utc_now()
        host = _host_subject()

        icmp = snapshot.get('icmp') if isinstance(snapshot.get('icmp'), dict) else {}
        if icmp:
            sev = _icmp_severity(icmp)
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='icmp_probe',
                subject=str(icmp.get('target') or host),
                severity=sev,
                confidence=0.95,
                attrs=icmp,
                status='ok' if sev == 0 else 'fail',
            ))

        path_probes = snapshot.get('path_probes') if isinstance(snapshot.get('path_probes'), list) else []
        for row in path_probes:
            if not isinstance(row, dict):
                continue
            sev = _icmp_severity(row)
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='path_probe',
                subject=str(row.get('target') or host),
                severity=sev,
                confidence=0.95,
                attrs=row,
                status='ok' if sev == 0 else 'fail',
            ))

        iface_stats = snapshot.get('iface_stats') if isinstance(snapshot.get('iface_stats'), list) else []
        for row in iface_stats:
            if not isinstance(row, dict):
                continue
            sev = _iface_severity(row)
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='iface_stats',
                subject=str(row.get('interface') or host),
                severity=sev,
                confidence=0.9,
                attrs=row,
                status='ok' if sev == 0 else 'warn',
            ))

        cpu_mem_temp = snapshot.get('cpu_mem_temp') if isinstance(snapshot.get('cpu_mem_temp'), dict) else {}
        if cpu_mem_temp:
            sev = _cpu_mem_temp_severity(cpu_mem_temp)
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='cpu_mem_temp',
                subject=host,
                severity=sev,
                confidence=0.9,
                attrs=cpu_mem_temp,
                status='ok' if sev == 0 else 'warn',
            ))

        service_health = snapshot.get('service_health') if isinstance(snapshot.get('service_health'), dict) else {}
        for alias, payload in sorted(service_health.items()):
            data = payload if isinstance(payload, dict) else {'target': alias, 'state': str(payload)}
            sev = 0 if str(data.get('state') or '').upper() == 'ON' else 70
            events.append(EvidenceEvent.build(
                ts=ts,
                source='noc_probe',
                kind='service_health',
                subject=str(data.get('target') or alias),
                severity=sev,
                confidence=0.95,
                attrs=data,
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
