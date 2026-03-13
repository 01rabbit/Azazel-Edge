from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .schema import EvidenceEvent, iso_utc_now


def _event_payloads(events: Iterable[Any]) -> List[Dict[str, Any]]:
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


def _parse_ts(value: str) -> Optional[datetime]:
    raw = str(value or '').strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace('Z', '+00:00'))
    except ValueError:
        return None


def _epoch(value: str) -> Optional[float]:
    parsed = _parse_ts(value)
    if parsed is None:
        return None
    return parsed.timestamp()


def _network_id(networks: List[Dict[str, Any]], ip: str) -> str:
    try:
        addr = ipaddress.ip_address(str(ip or ''))
    except ValueError:
        return ''
    for item in networks:
        try:
            cidr = ipaddress.ip_network(str(item.get('cidr') or ''), strict=False)
        except ValueError:
            continue
        if addr in cidr:
            return str(item.get('id') or '')
    return ''


@dataclass
class _SessionRecord:
    key: str
    mac: str = ''
    ip: str = ''
    hostname: str = ''
    interface_or_segment: str = ''
    first_seen: str = ''
    last_seen: str = ''
    sources_present: set[str] = field(default_factory=set)
    service_hints: set[str] = field(default_factory=set)
    evidence_ids: set[str] = field(default_factory=set)
    source_states: Dict[str, str] = field(default_factory=dict)
    arp_state: str = ''

    def merge_ts(self, ts: str) -> None:
        if not ts:
            return
        if not self.first_seen:
            self.first_seen = ts
        else:
            current = _epoch(self.first_seen)
            candidate = _epoch(ts)
            if current is None or (candidate is not None and candidate < current):
                self.first_seen = ts
        if not self.last_seen:
            self.last_seen = ts
        else:
            current = _epoch(self.last_seen)
            candidate = _epoch(ts)
            if current is None or (candidate is not None and candidate > current):
                self.last_seen = ts


def _device_lookup(sot: Dict[str, Any] | None) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], List[Dict[str, Any]]]:
    if not isinstance(sot, dict):
        return {}, {}, []
    by_ip: Dict[str, Dict[str, Any]] = {}
    by_mac: Dict[str, Dict[str, Any]] = {}
    devices = sot.get('devices', []) if isinstance(sot.get('devices'), list) else []
    for item in devices:
        if not isinstance(item, dict):
            continue
        ip = str(item.get('ip') or '')
        mac = str(item.get('mac') or '').lower()
        if ip:
            by_ip[ip] = item
        if mac:
            by_mac[mac] = item
    networks = sot.get('networks', []) if isinstance(sot.get('networks'), list) else []
    return by_ip, by_mac, [item for item in networks if isinstance(item, dict)]


def build_client_inventory(
    events: Iterable[Any],
    sot: Dict[str, Any] | None = None,
    stale_after_sec: int = 900,
    new_after_sec: int = 300,
    now_ts: str | None = None,
) -> Dict[str, Any]:
    payloads = _event_payloads(events)
    by_ip, by_mac, networks = _device_lookup(sot)
    sessions: Dict[str, _SessionRecord] = {}
    now_norm = str(now_ts or iso_utc_now())
    now_epoch = _epoch(now_norm) or datetime.now(timezone.utc).timestamp()
    seen_sot_keys: set[str] = set()

    def ensure_session(key: str) -> _SessionRecord:
        if key not in sessions:
            sessions[key] = _SessionRecord(key=key)
        return sessions[key]

    def find_session(ip: str, mac: str = '') -> Optional[_SessionRecord]:
        for item in sessions.values():
            if mac and item.mac and item.mac == mac:
                return item
            if ip and item.ip and item.ip == ip:
                return item
        return None

    for payload in payloads:
        kind = str(payload.get('kind') or '')
        attrs = payload.get('attrs', {})
        ts = str(payload.get('ts') or '')
        evidence_id = str(payload.get('event_id') or '')
        ip = ''
        mac = ''
        source_name = ''
        iface = ''
        hostname = ''
        if kind == 'dhcp_lease':
            ip = str(attrs.get('ip') or '')
            mac = str(attrs.get('mac') or '').lower()
            iface = str(attrs.get('interface') or '')
            hostname = str(attrs.get('hostname') or '')
            source_name = 'dhcp'
        elif kind == 'arp_entry':
            ip = str(attrs.get('ip') or '')
            mac = str(attrs.get('mac') or '').lower()
            iface = str(attrs.get('dev') or attrs.get('interface') or '')
            source_name = 'arp'
        elif kind == 'flow_summary':
            ip = str(attrs.get('src_ip') or '')
            if not ip:
                continue
            service_hint = f"{attrs.get('app_proto') or attrs.get('proto') or 'unknown'}:{int(attrs.get('dst_port') or 0)}"
            source_name = 'flow'
            session = find_session(ip) or ensure_session(f'{ip}|flow')
            if not session.ip:
                session.ip = ip
            if service_hint:
                session.service_hints.add(service_hint)
            if not session.interface_or_segment:
                session.interface_or_segment = _network_id(networks, ip) or 'unknown'
            session.sources_present.add(source_name)
            if evidence_id:
                session.evidence_ids.add(evidence_id)
            session.merge_ts(ts)
            continue
        else:
            continue

        session = find_session(ip, mac=mac) or ensure_session(mac or f'{ip}|{iface or "unknown"}')
        session.ip = session.ip or ip
        session.mac = session.mac or mac
        session.hostname = session.hostname or hostname
        session.interface_or_segment = session.interface_or_segment or iface or _network_id(networks, ip) or 'unknown'
        if kind == 'arp_entry':
            session.arp_state = str(attrs.get('state') or '')
        session.sources_present.add(source_name)
        session.source_states[source_name] = str(attrs.get('state') or '')
        if evidence_id:
            session.evidence_ids.add(evidence_id)
        session.merge_ts(ts)

    rows: List[Dict[str, Any]] = []
    counts = {
        'current_client_count': 0,
        'new_client_count': 0,
        'unknown_client_count': 0,
        'unauthorized_client_count': 0,
        'inventory_mismatch_count': 0,
        'stale_session_count': 0,
        'authorized_missing_count': 0,
    }

    for session in sessions.values():
        device = by_mac.get(session.mac) or by_ip.get(session.ip) or {}
        device_key = str(device.get('id') or device.get('ip') or device.get('mac') or '')
        if device_key:
            seen_sot_keys.add(device_key)
        session_state = 'unknown_present'
        if device:
            if bool(device.get('authorized', True)):
                session_state = 'authorized_present'
            else:
                session_state = 'unauthorized_present'
        mismatch = 'dhcp' in session.sources_present and 'arp' not in session.sources_present
        if mismatch:
            session_state = 'inventory_mismatch'
        last_seen_epoch = _epoch(session.last_seen) or now_epoch
        if now_epoch - last_seen_epoch > max(60, stale_after_sec):
            session_state = 'stale_session'
        if session_state == 'authorized_present':
            counts['current_client_count'] += 1
        elif session_state == 'unknown_present':
            counts['current_client_count'] += 1
            counts['unknown_client_count'] += 1
        elif session_state == 'unauthorized_present':
            counts['current_client_count'] += 1
            counts['unauthorized_client_count'] += 1
        elif session_state == 'inventory_mismatch':
            counts['current_client_count'] += 1
            counts['inventory_mismatch_count'] += 1
        elif session_state == 'stale_session':
            counts['stale_session_count'] += 1
        first_seen_epoch = _epoch(session.first_seen) or now_epoch
        if now_epoch - first_seen_epoch <= max(60, new_after_sec):
            counts['new_client_count'] += 1
        rows.append({
            'session_key': session.key,
            'mac': session.mac,
            'ip': session.ip,
            'hostname': session.hostname,
            'interface_or_segment': session.interface_or_segment or 'unknown',
            'first_seen': session.first_seen or now_norm,
            'last_seen': session.last_seen or now_norm,
            'sources_present': sorted(session.sources_present),
            'service_hints': sorted(session.service_hints),
            'sot_status': 'known' if device else 'unknown',
            'session_state': session_state,
            'arp_state': session.arp_state,
            'evidence_ids': sorted(session.evidence_ids),
        })

    if isinstance(sot, dict) and isinstance(sot.get('devices'), list):
        for item in sot.get('devices', []):
            if not isinstance(item, dict):
                continue
            key = str(item.get('id') or item.get('ip') or item.get('mac') or '')
            if not key or key in seen_sot_keys:
                continue
            counts['authorized_missing_count'] += 1
            rows.append({
                'session_key': f'sot:{key}',
                'mac': str(item.get('mac') or '').lower(),
                'ip': str(item.get('ip') or ''),
                'hostname': str(item.get('hostname') or ''),
                'interface_or_segment': _network_id(networks, str(item.get('ip') or '')) or 'expected',
                'first_seen': '',
                'last_seen': '',
                'sources_present': [],
                'service_hints': [],
                'sot_status': 'known',
                'session_state': 'authorized_missing',
                'arp_state': '',
                'evidence_ids': [],
            })

    rows.sort(key=lambda item: (str(item.get('session_state') or ''), str(item.get('ip') or ''), str(item.get('mac') or '')))
    evidence_ids = sorted({
        evidence_id
        for row in rows
        for evidence_id in row.get('evidence_ids', [])
        if str(evidence_id)
    })
    return {
        'summary': counts,
        'sessions': rows,
        'evidence_ids': evidence_ids,
    }


def build_client_inventory_events(
    events: Iterable[Any],
    sot: Dict[str, Any] | None = None,
    stale_after_sec: int = 900,
    new_after_sec: int = 300,
    now_ts: str | None = None,
) -> List[EvidenceEvent]:
    inventory = build_client_inventory(
        events,
        sot=sot,
        stale_after_sec=stale_after_sec,
        new_after_sec=new_after_sec,
        now_ts=now_ts,
    )
    ts = str(now_ts or iso_utc_now())
    output: List[EvidenceEvent] = []
    for row in inventory['sessions']:
        state = str(row.get('session_state') or 'unknown_present')
        severity = 0
        if state in {'unauthorized_present', 'inventory_mismatch'}:
            severity = 60
        elif state in {'unknown_present', 'stale_session', 'authorized_missing'}:
            severity = 35
        output.append(EvidenceEvent.build(
            ts=ts,
            source='noc_probe',
            kind='client_session',
            subject=str(row.get('ip') or row.get('mac') or row.get('session_key') or 'client'),
            severity=severity,
            confidence=0.85,
            attrs=row,
            status='warn' if severity > 0 else 'info',
            evidence_refs=list(row.get('evidence_ids') or []),
        ))
    summary = dict(inventory['summary'])
    summary['sessions'] = inventory['sessions'][:10]
    output.append(EvidenceEvent.build(
        ts=ts,
        source='noc_probe',
        kind='client_inventory_summary',
        subject='client_inventory',
        severity=60 if summary.get('unauthorized_client_count', 0) or summary.get('inventory_mismatch_count', 0) else (35 if summary.get('unknown_client_count', 0) or summary.get('stale_session_count', 0) else 0),
        confidence=0.9,
        attrs=summary,
        status='warn' if summary.get('unauthorized_client_count', 0) or summary.get('inventory_mismatch_count', 0) or summary.get('unknown_client_count', 0) else 'info',
        evidence_refs=inventory['evidence_ids'],
    ))
    return output
