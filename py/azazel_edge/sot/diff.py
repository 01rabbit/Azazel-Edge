from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .loader import SoTConfig


def _payloads(events: Iterable[Any]) -> List[Dict[str, Any]]:
    payloads: List[Dict[str, Any]] = []
    for event in events:
        if hasattr(event, 'to_dict'):
            payload = event.to_dict()
        elif isinstance(event, dict):
            payload = dict(event)
        else:
            continue
        if isinstance(payload.get('attrs'), dict):
            payloads.append(payload)
    return payloads


def _parse_subject(subject: str) -> Tuple[str, str]:
    match = re.match(r'(?P<src>[^-]+)->(?P<dst>[^:]+):', str(subject or ''))
    if not match:
        return '', ''
    return match.group('src'), match.group('dst')


def _network_id_for_ip(sot: SoTConfig, ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for net in sot.networks:
        try:
            cidr = ipaddress.ip_network(str(net.get('cidr') or ''), strict=False)
        except ValueError:
            continue
        if addr in cidr:
            return str(net.get('id') or '')
    if addr.is_global:
        return 'wan'
    return None


class SoTDiffInspector:
    def inspect(self, events: Iterable[Any], sot: SoTConfig) -> Dict[str, Any]:
        payloads = _payloads(events)
        unauthorized_devices: Set[str] = set()
        unauthorized_services: Set[str] = set()
        path_deviations: List[Dict[str, str]] = []
        evidence_ids: List[str] = []

        known_ports = {
            (str(item.get('proto') or '').lower(), int(item.get('port') or 0)): str(item.get('id') or '')
            for item in sot.services
            if isinstance(item, dict)
        }

        for payload in payloads:
            event_id = str(payload.get('event_id') or '')
            if event_id:
                evidence_ids.append(event_id)
            kind = str(payload.get('kind') or '')
            source = str(payload.get('source') or '')
            attrs = payload.get('attrs', {})

            if kind in {'dhcp_lease', 'arp_entry'}:
                ip = str(attrs.get('ip') or '')
                if ip and not sot.device_by_ip(ip):
                    unauthorized_devices.add(ip)

            if source in {'suricata_eve', 'flow_min'}:
                src_ip, dst_ip = _parse_subject(str(payload.get('subject') or ''))
                proto = str(attrs.get('app_proto') or attrs.get('proto') or '').lower()
                port = int(attrs.get('dst_port') or attrs.get('target_port') or 0)
                service_id = known_ports.get((proto, port))
                if not service_id and port:
                    # allow port-only match when proto is missing in incoming evidence
                    service_id = next((sid for (svc_proto, svc_port), sid in known_ports.items() if svc_port == port), None)
                if port and not service_id:
                    unauthorized_services.add(f'{proto or "unknown"}:{port}')

                src_net = _network_id_for_ip(sot, src_ip)
                dst_net = _network_id_for_ip(sot, dst_ip)
                if src_net and dst_net and (not service_id or not sot.expected_path(src_net, dst_net, service_id)):
                    path_deviations.append({
                        'src': src_net,
                        'dst': dst_net,
                        'service_id': service_id or f'unknown:{proto or "unknown"}:{port}',
                    })

        return {
            'unauthorized_devices': sorted(unauthorized_devices),
            'unauthorized_services': sorted(unauthorized_services),
            'path_deviations': path_deviations,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }
