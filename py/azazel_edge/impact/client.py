from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Set, Tuple


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


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _criticality_weight(value: str) -> int:
    lowered = str(value or '').strip().lower()
    if lowered in {'critical', 'high', 'core', 'mission'}:
        return 1
    return 0


class ClientImpactScorer:
    """
    Deterministic client impact estimator for action-time safety checks.

    Higher score means greater operator-visible impact.
    """

    def score(self, action: str, events: Iterable[Any], sot: Dict[str, Any] | None = None) -> Dict[str, Any]:
        normalized_action = str(action or 'observe').strip().lower()
        payloads = _payloads(events)
        affected_ips: Set[str] = set()
        affected_services: Set[str] = set()
        evidence_ids: List[str] = []

        for payload in payloads:
            event_id = str(payload.get('event_id') or '')
            if event_id:
                evidence_ids.append(event_id)
            source = str(payload.get('source') or '')
            kind = str(payload.get('kind') or '')
            attrs = payload.get('attrs', {})

            if source in {'suricata_eve', 'flow_min'}:
                src, dst = _parse_subject(str(payload.get('subject') or ''))
                if src and _is_private_ip(src):
                    affected_ips.add(src)
                if dst and _is_private_ip(dst):
                    affected_ips.add(dst)
                for key in ('target_port', 'dst_port', 'service_port'):
                    port = int(attrs.get(key) or 0)
                    if port:
                        affected_services.add(f'port:{port}')
                proto = str(attrs.get('app_proto') or '').strip().lower()
                if proto:
                    affected_services.add(proto)
            elif kind in {'dhcp_lease', 'arp_entry'}:
                ip = str(attrs.get('ip') or '').strip()
                if ip and _is_private_ip(ip):
                    affected_ips.add(ip)

        matched_devices: List[Dict[str, Any]] = []
        critical_clients = 0
        if sot and isinstance(sot.get('devices'), list):
            for ip in affected_ips:
                matched = next(
                    (
                        item for item in sot.get('devices', [])
                        if isinstance(item, dict) and str(item.get('ip') or '') == ip
                    ),
                    None,
                )
                if matched:
                    matched_devices.append(matched)
                    critical_clients += _criticality_weight(str(matched.get('criticality') or ''))

        if matched_devices:
            affected_client_count = len({str(item.get('ip') or '') for item in matched_devices if str(item.get('ip') or '')})
        else:
            affected_client_count = len(affected_ips)
        communication_scope = self._scope_for(affected_client_count, len(affected_services))

        if normalized_action == 'observe':
            impact_score = 0
        elif normalized_action == 'notify':
            impact_score = min(100, 5 + affected_client_count * 3 + critical_clients * 10)
        else:
            impact_score = min(
                100,
                20
                + affected_client_count * 10
                + critical_clients * 25
                + self._scope_penalty(communication_scope),
            )

        reasons = [
            f'affected_clients:{affected_client_count}',
            f'critical_clients:{critical_clients}',
            f'communication_scope:{communication_scope}',
        ]
        if normalized_action == 'throttle' and critical_clients:
            reasons.append('critical_client_control_risk')

        return {
            'action': normalized_action,
            'score': impact_score,
            'label': self._bucket(impact_score),
            'affected_client_count': affected_client_count,
            'critical_client_count': critical_clients,
            'communication_scope': communication_scope,
            'reasons': reasons,
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
        }

    @staticmethod
    def _scope_for(affected_clients: int, service_count: int) -> str:
        if affected_clients >= 5 or service_count >= 4:
            return 'broad'
        if affected_clients >= 3 or service_count >= 2:
            return 'segment'
        if affected_clients >= 2:
            return 'multi_client'
        if affected_clients == 1:
            return 'single_client'
        return 'minimal'

    @staticmethod
    def _scope_penalty(scope: str) -> int:
        return {
            'minimal': 0,
            'single_client': 10,
            'multi_client': 20,
            'segment': 30,
            'broad': 40,
        }.get(scope, 0)

    @staticmethod
    def _bucket(score: int) -> str:
        if score >= 80:
            return 'high'
        if score >= 40:
            return 'medium'
        return 'low'
