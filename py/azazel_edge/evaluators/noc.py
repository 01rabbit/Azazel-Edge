from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Dict, Iterable, List
import ipaddress
import re

from azazel_edge.evidence_plane.noc_inventory import build_client_inventory


DEFAULT_CONFIG: Dict[str, Dict[str, int]] = {
    'availability': {
        'icmp_unreachable_penalty': 60,
        'service_off_penalty': 15,
        'collector_failure_penalty': 10,
    },
    'path_health': {
        'probe_failed_penalty': 40,
        'iface_degraded_penalty': 25,
        'collector_failure_penalty': 10,
    },
    'device_health': {
        'cpu_hot_threshold': 90,
        'cpu_elevated_threshold': 75,
        'cpu_hot_penalty': 25,
        'cpu_elevated_penalty': 10,
        'mem_pressure_threshold': 90,
        'mem_elevated_threshold': 75,
        'mem_pressure_penalty': 30,
        'mem_elevated_penalty': 15,
        'temp_hot_threshold': 80,
        'temp_elevated_threshold': 65,
        'temp_hot_penalty': 25,
        'temp_elevated_penalty': 10,
        'collector_failure_penalty': 10,
    },
    'client_health': {
        'no_client_evidence_score': 70,
        'inventory_mismatch_penalty_per_client': 5,
        'inventory_mismatch_penalty_cap': 25,
        'stale_arp_penalty_per_entry': 5,
        'stale_arp_penalty_cap': 25,
        'unknown_client_penalty_per_client': 5,
        'unknown_client_penalty_cap': 20,
    },
    'capacity_health': {
        'elevated_penalty': 15,
        'congested_penalty': 35,
        'unknown_penalty': 10,
        'high_concentration_penalty': 10,
    },
    'client_inventory_health': {
        'unknown_client_penalty_per_client': 8,
        'unknown_client_penalty_cap': 24,
        'unauthorized_client_penalty_per_client': 12,
        'unauthorized_client_penalty_cap': 36,
        'inventory_mismatch_penalty_per_client': 10,
        'inventory_mismatch_penalty_cap': 30,
        'stale_session_penalty_per_client': 5,
        'stale_session_penalty_cap': 20,
        'authorized_missing_penalty_per_client': 4,
        'authorized_missing_penalty_cap': 16,
    },
    'service_health': {
        'probe_failed_penalty': 20,
        'window_degraded_penalty': 10,
        'window_down_penalty': 25,
        'collector_failure_penalty': 10,
    },
    'resolution_health': {
        'probe_failed_penalty': 25,
        'window_degraded_penalty': 10,
        'window_failed_penalty': 30,
        'collector_failure_penalty': 10,
    },
    'config_drift_health': {
        'drift_penalty_per_field': 8,
        'drift_penalty_cap': 32,
        'baseline_missing_penalty': 12,
        'baseline_invalid_penalty': 20,
    },
}


def _merge_config(config: Dict[str, Any] | None) -> Dict[str, Dict[str, int]]:
    merged = deepcopy(DEFAULT_CONFIG)
    if not isinstance(config, dict):
        return merged
    for section, values in config.items():
        if section not in merged or not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, (int, float)):
                merged[section][key] = int(value)
    if merged['capacity_health']['elevated_penalty'] < 0 or merged['capacity_health']['congested_penalty'] < merged['capacity_health']['elevated_penalty']:
        raise ValueError('invalid_capacity_health_config')
    if merged['client_inventory_health']['unauthorized_client_penalty_per_client'] < merged['client_inventory_health']['unknown_client_penalty_per_client']:
        raise ValueError('invalid_client_inventory_health_config')
    if merged['service_health']['window_down_penalty'] < merged['service_health']['window_degraded_penalty']:
        raise ValueError('invalid_service_health_config')
    if merged['resolution_health']['window_failed_penalty'] < merged['resolution_health']['window_degraded_penalty']:
        raise ValueError('invalid_resolution_health_config')
    if merged['config_drift_health']['drift_penalty_cap'] < merged['config_drift_health']['drift_penalty_per_field']:
        raise ValueError('invalid_config_drift_health_config')
    return merged


def _to_payloads(events: Iterable[Any]) -> List[Dict[str, Any]]:
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


def _bucket(score: int) -> str:
    if score >= 90:
        return 'good'
    if score >= 70:
        return 'degraded'
    if score >= 40:
        return 'poor'
    return 'critical'


def _make_dimension(score: int, reasons: List[str], evidence_ids: List[str]) -> Dict[str, Any]:
    return {
        'score': max(0, min(100, int(score))),
        'label': _bucket(score),
        'reasons': reasons,
        'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
    }


def _parse_subject(subject: str) -> tuple[str, str]:
    match = re.match(r'(?P<src>[^-]+)->(?P<dst>[^:]+):', str(subject or ''))
    if not match:
        return '', ''
    return match.group('src'), match.group('dst')


def _network_id_for_ip(networks: List[Dict[str, Any]], ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ''
    for net in networks:
        try:
            cidr = ipaddress.ip_network(str(net.get('cidr') or ''), strict=False)
        except ValueError:
            continue
        if addr in cidr:
            return str(net.get('id') or '')
    if addr.is_global:
        return 'wan'
    return ''


class NocEvaluator:
    """
    Deterministic NOC evaluator.

    Score semantics are health-oriented: 100 is healthy, 0 is critical.
    Input must be Evidence Plane events only.
    """

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = _merge_config(config)

    def evaluate(self, events: Iterable[Any], sot: Dict[str, Any] | None = None, sot_diff: Dict[str, Any] | None = None) -> Dict[str, Any]:
        payloads = _to_payloads(events)
        by_kind: Dict[str, List[Dict[str, Any]]] = {}
        all_evidence_ids: List[str] = []
        for payload in payloads:
            kind = str(payload.get('kind') or '')
            by_kind.setdefault(kind, []).append(payload)
            event_id = str(payload.get('event_id') or '')
            if event_id:
                all_evidence_ids.append(event_id)

        availability = self._evaluate_availability(by_kind)
        path_health = self._evaluate_path_health(by_kind)
        device_health = self._evaluate_device_health(by_kind)
        client_health = self._evaluate_client_health(by_kind, sot=sot, sot_diff=sot_diff)
        capacity_health = self._evaluate_capacity_health(by_kind)
        client_inventory_health = self._evaluate_client_inventory_health(payloads, by_kind, sot=sot, sot_diff=sot_diff)
        service_health = self._evaluate_service_health(by_kind)
        resolution_health = self._evaluate_resolution_health(by_kind)
        config_drift_health = self._evaluate_config_drift_health(by_kind)
        if sot_diff:
            path_health = self._apply_sot_diff_to_path_health(path_health, sot_diff)

        summary_reasons: List[str] = []
        degraded_mode = False
        if not sot:
            degraded_mode = True
            summary_reasons.append('sot_missing')
            if 'sot_missing' not in client_health['reasons']:
                client_health['reasons'].append('sot_missing')

        affected_scope = self._evaluate_affected_scope(payloads, by_kind, sot=sot)
        incident_summary = self._build_incident_summary(
            availability=availability,
            path_health=path_health,
            device_health=device_health,
            client_health=client_health,
            capacity_health=capacity_health,
            client_inventory_health=client_inventory_health,
            service_health=service_health,
            resolution_health=resolution_health,
            config_drift_health=config_drift_health,
            affected_scope=affected_scope,
        )

        dimensions = [
            availability,
            path_health,
            device_health,
            client_health,
            capacity_health,
            client_inventory_health,
            service_health,
            resolution_health,
            config_drift_health,
        ]
        worst_score = min(int(dim['score']) for dim in dimensions) if dimensions else 100
        if worst_score < 90:
            summary_reasons.extend(
                f"{name}:{dim['label']}"
                for name, dim in (
                    ('availability', availability),
                    ('path_health', path_health),
                    ('device_health', device_health),
                    ('client_health', client_health),
                    ('capacity_health', capacity_health),
                    ('client_inventory_health', client_inventory_health),
                    ('service_health', service_health),
                    ('resolution_health', resolution_health),
                    ('config_drift_health', config_drift_health),
                )
                if dim['label'] != 'good'
            )

        summary = {
            'status': _bucket(worst_score),
            'degraded_mode': degraded_mode,
            'reasons': sorted(dict.fromkeys(summary_reasons)),
        }
        if sot and isinstance(sot.get('networks'), list):
            segment_status = self._evaluate_segment_scope(payloads, sot.get('networks', []))
            summary['segment_scope'] = segment_status
        if affected_scope:
            summary['blast_radius'] = affected_scope
        if incident_summary:
            summary['incident_summary'] = incident_summary

        result = {
            'availability': availability,
            'path_health': path_health,
            'device_health': device_health,
            'client_health': client_health,
            'capacity_health': capacity_health,
            'client_inventory_health': client_inventory_health,
            'service_health': service_health,
            'resolution_health': resolution_health,
            'config_drift_health': config_drift_health,
            'affected_scope': affected_scope,
            'incident_summary': incident_summary,
            'summary': summary,
            'evidence_ids': sorted(dict.fromkeys(all_evidence_ids)),
        }
        return result

    def to_arbiter_input(self, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'source': 'noc_evaluator',
            'config': self.config,
            'summary': evaluation.get('summary', {}),
            'availability': evaluation.get('availability', {}),
            'path_health': evaluation.get('path_health', {}),
            'device_health': evaluation.get('device_health', {}),
            'client_health': evaluation.get('client_health', {}),
            'capacity_health': evaluation.get('capacity_health', {}),
            'client_inventory_health': evaluation.get('client_inventory_health', {}),
            'service_health': evaluation.get('service_health', {}),
            'resolution_health': evaluation.get('resolution_health', {}),
            'config_drift_health': evaluation.get('config_drift_health', {}),
            'affected_scope': evaluation.get('affected_scope', {}),
            'incident_summary': evaluation.get('incident_summary', {}),
            'evidence_ids': evaluation.get('evidence_ids', []),
        }

    def _evaluate_availability(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['availability']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        for event in by_kind.get('icmp_probe', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            if not bool(event.get('attrs', {}).get('reachable')):
                score -= cfg['icmp_unreachable_penalty']
                reasons.append('icmp_unreachable')

        for event in by_kind.get('service_health', []):
            attrs = event.get('attrs', {})
            evidence_ids.append(str(event.get('event_id') or ''))
            if str(attrs.get('state') or '').upper() != 'ON':
                score -= cfg['service_off_penalty']
                reasons.append(f"service_off:{attrs.get('target') or event.get('subject')}")
            elif str(attrs.get('substate') or '').lower() not in {'running', 'listening', 'unknown'}:
                score -= 5
                reasons.append(f"service_degraded:{attrs.get('target') or event.get('subject')}")
            elif str(attrs.get('result') or '').lower() not in {'success', 'unknown'}:
                score -= 5
                reasons.append(f"service_result:{attrs.get('target') or event.get('subject')}")

        for event in by_kind.get('collector_failure', []):
            collector = str(event.get('attrs', {}).get('collector') or '')
            if collector in {'icmp', 'service_health'}:
                evidence_ids.append(str(event.get('event_id') or ''))
                score -= cfg['collector_failure_penalty']
                reasons.append(f'collector_failure:{collector}')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_path_health(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['path_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        for event in by_kind.get('icmp_probe', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            if not bool(event.get('attrs', {}).get('reachable')):
                score -= cfg['probe_failed_penalty']
                reasons.append('path_probe_failed')

        probe_results: List[bool] = []
        by_interface: Dict[str, List[bool]] = {}
        for event in by_kind.get('path_probe', []):
            attrs = event.get('attrs', {})
            evidence_ids.append(str(event.get('event_id') or ''))
            reachable = bool(attrs.get('reachable'))
            scope = str(attrs.get('scope') or '')
            iface = str(attrs.get('interface') or '')
            probe_results.append(reachable)
            if iface:
                by_interface.setdefault(iface, []).append(reachable)
            if not reachable:
                score -= 20 if scope == 'external' else 10
                reasons.append(f'path_probe_failed:{scope or "unknown"}')
        if probe_results and len(set(probe_results)) > 1:
            score -= 15
            reasons.append('path_target_divergence')
        if by_interface and len(by_interface) > 1:
            interface_health = {iface: all(values) for iface, values in by_interface.items() if values}
            if len(set(interface_health.values())) > 1:
                score -= 10
                reasons.append('uplink_divergence')

        for event in by_kind.get('iface_stats', []):
            attrs = event.get('attrs', {})
            evidence_ids.append(str(event.get('event_id') or ''))
            oper = str(attrs.get('operstate') or '').lower()
            carrier = int(attrs.get('carrier') or 0)
            if oper != 'up' or carrier != 1:
                score -= cfg['iface_degraded_penalty']
                reasons.append(f"iface_degraded:{attrs.get('interface') or event.get('subject')}")

        for event in by_kind.get('flow_summary', []):
            attrs = event.get('attrs', {})
            flow_state = str(attrs.get('flow_state') or '').lower()
            evidence_ids.append(str(event.get('event_id') or ''))
            if flow_state in {'failed', 'reset', 'timeout'}:
                score -= 10
                reasons.append('flow_path_instability')

        for event in by_kind.get('collector_failure', []):
            collector = str(event.get('attrs', {}).get('collector') or '')
            if collector in {'icmp', 'iface_stats'}:
                evidence_ids.append(str(event.get('event_id') or ''))
                score -= cfg['collector_failure_penalty']
                reasons.append(f'collector_failure:{collector}')
            if collector == 'path_probes':
                evidence_ids.append(str(event.get('event_id') or ''))
                score -= cfg['collector_failure_penalty']
                reasons.append('collector_failure:path_probes')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_device_health(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['device_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        for event in by_kind.get('cpu_mem_temp', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            cpu = float(attrs.get('cpu_percent') or 0.0)
            mem = int((attrs.get('memory') or {}).get('percent') or 0)
            temp = float(attrs.get('temperature_c') or 0.0)
            if cpu >= cfg['cpu_hot_threshold']:
                score -= cfg['cpu_hot_penalty']
                reasons.append('cpu_hot')
            elif cpu >= cfg['cpu_elevated_threshold']:
                score -= cfg['cpu_elevated_penalty']
                reasons.append('cpu_elevated')
            if mem >= cfg['mem_pressure_threshold']:
                score -= cfg['mem_pressure_penalty']
                reasons.append('memory_pressure')
            elif mem >= cfg['mem_elevated_threshold']:
                score -= cfg['mem_elevated_penalty']
                reasons.append('memory_elevated')
            if temp >= cfg['temp_hot_threshold']:
                score -= cfg['temp_hot_penalty']
                reasons.append('device_hot')
            elif temp >= cfg['temp_elevated_threshold']:
                score -= cfg['temp_elevated_penalty']
                reasons.append('temperature_elevated')

        for event in by_kind.get('collector_failure', []):
            collector = str(event.get('attrs', {}).get('collector') or '')
            if collector == 'cpu_mem_temp':
                evidence_ids.append(str(event.get('event_id') or ''))
                score -= cfg['collector_failure_penalty']
                reasons.append('collector_failure:cpu_mem_temp')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_capacity_health(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['capacity_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        for event in by_kind.get('capacity_pressure', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            state = str(attrs.get('state') or 'unknown')
            mode = str(attrs.get('mode') or 'unknown')
            if state == 'congested':
                score -= cfg['congested_penalty']
                reasons.append(f'capacity_congested:{mode}')
            elif state == 'elevated':
                score -= cfg['elevated_penalty']
                reasons.append(f'capacity_elevated:{mode}')
            elif state == 'unknown':
                score -= cfg['unknown_penalty']
                reasons.append(f'capacity_unknown:{mode}')

        for event in by_kind.get('traffic_concentration', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            if bool(attrs.get('high_concentration')):
                score -= cfg['high_concentration_penalty']
                reasons.append('traffic_concentration_high')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_client_health(self, by_kind: Dict[str, List[Dict[str, Any]]], sot: Dict[str, Any] | None, sot_diff: Dict[str, Any] | None = None) -> Dict[str, Any]:
        cfg = self.config['client_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        dhcp_ips = set()
        arp_ips = set()
        stale_arp = 0

        for event in by_kind.get('dhcp_lease', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            ip = str(event.get('attrs', {}).get('ip') or '')
            if ip:
                dhcp_ips.add(ip)

        for event in by_kind.get('arp_entry', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            ip = str(attrs.get('ip') or '')
            state = str(attrs.get('state') or '').upper()
            if ip:
                arp_ips.add(ip)
            if state in {'STALE', 'FAILED', 'INCOMPLETE'}:
                stale_arp += 1

        for event in by_kind.get('flow_summary', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            if int(attrs.get('pkts_toserver') or 0) >= 20 and int(attrs.get('pkts_toclient') or 0) == 0:
                score -= 10
                reasons.append('one_way_client_flow')

        if not dhcp_ips and not arp_ips:
            score = cfg['no_client_evidence_score']
            reasons.append('no_client_evidence')
        else:
            mismatched = dhcp_ips.symmetric_difference(arp_ips)
            if mismatched:
                score -= min(cfg['inventory_mismatch_penalty_cap'], cfg['inventory_mismatch_penalty_per_client'] * len(mismatched))
                reasons.append('client_inventory_mismatch')
            if stale_arp:
                score -= min(cfg['stale_arp_penalty_cap'], cfg['stale_arp_penalty_per_entry'] * stale_arp)
                reasons.append('stale_arp_entries')

        if sot and isinstance(sot.get('devices'), list):
            known_ips = {
                str(item.get('ip') or '')
                for item in sot.get('devices', [])
                if isinstance(item, dict) and str(item.get('ip') or '')
            }
            unknown = {ip for ip in dhcp_ips.union(arp_ips) if known_ips and ip not in known_ips}
            if unknown:
                score -= min(cfg['unknown_client_penalty_cap'], cfg['unknown_client_penalty_per_client'] * len(unknown))
                reasons.append('unknown_clients_present')

        if sot_diff:
            unauthorized_devices = sot_diff.get('unauthorized_devices', []) if isinstance(sot_diff.get('unauthorized_devices'), list) else []
            if unauthorized_devices:
                score -= min(cfg['unknown_client_penalty_cap'], cfg['unknown_client_penalty_per_client'] * len(unauthorized_devices))
                reasons.append('unauthorized_devices_present')
                evidence_ids.extend(str(x) for x in sot_diff.get('evidence_ids', []) if str(x))

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_client_inventory_health(
        self,
        payloads: List[Dict[str, Any]],
        by_kind: Dict[str, List[Dict[str, Any]]],
        sot: Dict[str, Any] | None,
        sot_diff: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        cfg = self.config['client_inventory_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        summary_attrs: Dict[str, Any] = {}
        summaries = by_kind.get('client_inventory_summary', [])
        if summaries:
            summary_attrs = summaries[-1].get('attrs', {}) if isinstance(summaries[-1].get('attrs'), dict) else {}
            evidence_ids.extend(str(item.get('event_id') or '') for item in summaries)
        else:
            inventory = build_client_inventory(payloads, sot=sot)
            summary_attrs = inventory.get('summary', {})
            evidence_ids.extend(str(x) for x in inventory.get('evidence_ids', []) if str(x))

        unknown_count = int(summary_attrs.get('unknown_client_count') or 0)
        unauthorized_count = int(summary_attrs.get('unauthorized_client_count') or 0)
        mismatch_count = int(summary_attrs.get('inventory_mismatch_count') or 0)
        stale_count = int(summary_attrs.get('stale_session_count') or 0)
        missing_count = int(summary_attrs.get('authorized_missing_count') or 0)

        if unknown_count:
            score -= min(cfg['unknown_client_penalty_cap'], cfg['unknown_client_penalty_per_client'] * unknown_count)
            reasons.append('client_inventory_unknown_present')
        if unauthorized_count:
            score -= min(cfg['unauthorized_client_penalty_cap'], cfg['unauthorized_client_penalty_per_client'] * unauthorized_count)
            reasons.append('client_inventory_unauthorized_present')
        if mismatch_count:
            score -= min(cfg['inventory_mismatch_penalty_cap'], cfg['inventory_mismatch_penalty_per_client'] * mismatch_count)
            reasons.append('client_inventory_mismatch')
        if stale_count:
            score -= min(cfg['stale_session_penalty_cap'], cfg['stale_session_penalty_per_client'] * stale_count)
            reasons.append('client_inventory_stale_sessions')
        if missing_count:
            score -= min(cfg['authorized_missing_penalty_cap'], cfg['authorized_missing_penalty_per_client'] * missing_count)
            reasons.append('client_inventory_authorized_missing')
        if sot_diff:
            unauthorized_devices = sot_diff.get('unauthorized_devices', []) if isinstance(sot_diff.get('unauthorized_devices'), list) else []
            if unauthorized_devices and 'client_inventory_unauthorized_present' not in reasons:
                reasons.append('client_inventory_unauthorized_present')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_service_health(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['service_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        for event in by_kind.get('service_probe', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            name = str(attrs.get('name') or attrs.get('target') or event.get('subject') or 'unknown')
            if not bool(attrs.get('reachable')):
                score -= cfg['probe_failed_penalty']
                reasons.append(f'service_probe_failed:{name}')

        for event in by_kind.get('service_probe_window', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            name = str(attrs.get('name') or attrs.get('target') or event.get('subject') or 'unknown')
            state = str(attrs.get('state') or 'unknown')
            if state == 'degraded':
                score -= cfg['window_degraded_penalty']
                reasons.append(f'service_window_degraded:{name}')
            elif state == 'down':
                score -= cfg['window_down_penalty']
                reasons.append(f'service_window_down:{name}')

        for event in by_kind.get('collector_failure', []):
            collector = str(event.get('attrs', {}).get('collector') or '')
            if collector == 'service_probes':
                evidence_ids.append(str(event.get('event_id') or ''))
                score -= cfg['collector_failure_penalty']
                reasons.append('collector_failure:service_probes')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_resolution_health(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['resolution_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []

        for event in by_kind.get('resolution_probe', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            name = str(attrs.get('name') or event.get('subject') or 'unknown')
            if not bool(attrs.get('resolved')):
                score -= cfg['probe_failed_penalty']
                reasons.append(f'resolution_failed:{name}')

        for event in by_kind.get('resolution_probe_window', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            name = str(attrs.get('name') or event.get('subject') or 'unknown')
            state = str(attrs.get('state') or 'unknown')
            if state == 'degraded':
                score -= cfg['window_degraded_penalty']
                reasons.append(f'resolution_window_degraded:{name}')
            elif state == 'failed':
                score -= cfg['window_failed_penalty']
                reasons.append(f'resolution_window_failed:{name}')

        for event in by_kind.get('collector_failure', []):
            collector = str(event.get('attrs', {}).get('collector') or '')
            if collector == 'resolution_probes':
                evidence_ids.append(str(event.get('event_id') or ''))
                score -= cfg['collector_failure_penalty']
                reasons.append('collector_failure:resolution_probes')

        return _make_dimension(score, reasons, evidence_ids)

    def _evaluate_config_drift_health(self, by_kind: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        cfg = self.config['config_drift_health']
        score = 100
        reasons: List[str] = []
        evidence_ids: List[str] = []
        rollback_hint = ''

        for event in by_kind.get('config_drift', []):
            evidence_ids.append(str(event.get('event_id') or ''))
            attrs = event.get('attrs', {})
            status = str(attrs.get('status') or 'baseline_missing')
            changed_fields = [str(item) for item in attrs.get('changed_fields', []) if str(item)]
            if not rollback_hint:
                rollback_hint = str(attrs.get('rollback_hint') or '')
            if status == 'drift':
                penalty = min(cfg['drift_penalty_cap'], cfg['drift_penalty_per_field'] * max(1, len(changed_fields)))
                score -= penalty
                reasons.append('config_drift_detected')
                reasons.extend(f'config_drift:{field}' for field in changed_fields[:4])
            elif status == 'baseline_missing':
                score -= cfg['baseline_missing_penalty']
                reasons.append('config_baseline_missing')
            elif status == 'baseline_invalid':
                score -= cfg['baseline_invalid_penalty']
                reasons.append('config_baseline_invalid')

        result = _make_dimension(score, reasons, evidence_ids)
        result['rollback_hint'] = rollback_hint
        return result

    @staticmethod
    def _build_incident_summary(
        availability: Dict[str, Any],
        path_health: Dict[str, Any],
        device_health: Dict[str, Any],
        client_health: Dict[str, Any],
        capacity_health: Dict[str, Any],
        client_inventory_health: Dict[str, Any],
        service_health: Dict[str, Any],
        resolution_health: Dict[str, Any],
        config_drift_health: Dict[str, Any],
        affected_scope: Dict[str, Any],
    ) -> Dict[str, Any]:
        dimensions = {
            'availability': availability,
            'path_health': path_health,
            'device_health': device_health,
            'client_health': client_health,
            'capacity_health': capacity_health,
            'client_inventory_health': client_inventory_health,
            'service_health': service_health,
            'resolution_health': resolution_health,
            'config_drift_health': config_drift_health,
        }
        degraded = {
            name: dim
            for name, dim in dimensions.items()
            if str(dim.get('label') or 'good') != 'good'
        }
        if not degraded:
            return {
                'incident_id': 'incident:none',
                'probable_cause': 'stable',
                'confidence': 0.95,
                'supporting_symptoms': [],
                'affected_scope': affected_scope or {},
                'evidence_ids': [],
                'drill_down': {'dimension_reasons': {}, 'evidence_ids': []},
            }

        probable_cause = 'general_noc_degradation'
        if str(config_drift_health.get('label') or 'good') != 'good':
            probable_cause = 'misconfiguration_drift'
        elif str(resolution_health.get('label') or 'good') != 'good':
            probable_cause = 'resolution_failure'
        elif str(service_health.get('label') or 'good') != 'good':
            probable_cause = 'service_assurance_failure'
        elif str(capacity_health.get('label') or 'good') != 'good':
            probable_cause = 'capacity_pressure'
        elif str(path_health.get('label') or 'good') != 'good':
            probable_cause = 'uplink_or_path_instability'
        elif str(client_inventory_health.get('label') or 'good') != 'good':
            probable_cause = 'client_inventory_anomaly'
        elif str(device_health.get('label') or 'good') != 'good':
            probable_cause = 'device_resource_pressure'
        elif str(client_health.get('label') or 'good') != 'good':
            probable_cause = 'client_connectivity_anomaly'

        supporting_symptoms: List[str] = []
        evidence_ids: List[str] = []
        drill_down: Dict[str, List[str]] = {}
        severity_map = {'critical': 4, 'poor': 3, 'degraded': 2, 'good': 1, 'unknown': 0}
        top_label_weight = 0
        for name, dim in degraded.items():
            reasons = [str(item) for item in dim.get('reasons', []) if str(item)]
            if reasons:
                supporting_symptoms.extend(f'{name}:{reason}' for reason in reasons[:3])
                drill_down[name] = reasons
            evidence_ids.extend(str(item) for item in dim.get('evidence_ids', []) if str(item))
            top_label_weight = max(top_label_weight, severity_map.get(str(dim.get('label') or 'unknown'), 0))
        confidence = 0.6
        if probable_cause in {'misconfiguration_drift', 'resolution_failure', 'service_assurance_failure', 'capacity_pressure'}:
            confidence = 0.88
        elif top_label_weight >= 3:
            confidence = 0.8
        elif len(degraded) >= 2:
            confidence = 0.74
        basis = '|'.join([
            probable_cause,
            ','.join(sorted(affected_scope.get('affected_uplinks', []) if isinstance(affected_scope, dict) else [])),
            ','.join(sorted(affected_scope.get('affected_segments', []) if isinstance(affected_scope, dict) else [])),
            ','.join(sorted(dict.fromkeys(evidence_ids))[:8]),
        ])
        incident_id = 'incident:' + hashlib.sha256(basis.encode('utf-8')).hexdigest()[:12]
        return {
            'incident_id': incident_id,
            'probable_cause': probable_cause,
            'confidence': round(confidence, 2),
            'supporting_symptoms': supporting_symptoms[:8],
            'affected_scope': affected_scope or {},
            'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
            'drill_down': {
                'dimension_reasons': drill_down,
                'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
            },
        }

    @staticmethod
    def _apply_sot_diff_to_path_health(path_health: Dict[str, Any], sot_diff: Dict[str, Any]) -> Dict[str, Any]:
        updated = deepcopy(path_health)
        if sot_diff.get('path_deviations'):
            updated['score'] = max(0, int(updated.get('score') or 0) - 20)
            updated['reasons'] = list(updated.get('reasons', [])) + ['path_deviation_detected']
        if sot_diff.get('unauthorized_services'):
            updated['score'] = max(0, int(updated.get('score') or 0) - 10)
            updated['reasons'] = list(updated.get('reasons', [])) + ['unauthorized_services_present']
        updated['evidence_ids'] = sorted(dict.fromkeys(
            [str(x) for x in updated.get('evidence_ids', []) if str(x)] +
            [str(x) for x in sot_diff.get('evidence_ids', []) if str(x)]
        ))
        updated['label'] = _bucket(int(updated.get('score') or 0))
        return updated

    @staticmethod
    def _evaluate_segment_scope(payloads: List[Dict[str, Any]], networks: List[Dict[str, Any]]) -> Dict[str, Any]:
        segments = set()
        for payload in payloads:
            source = str(payload.get('source') or '')
            kind = str(payload.get('kind') or '')
            attrs = payload.get('attrs', {})
            if source in {'suricata_eve', 'flow_min'}:
                src, dst = _parse_subject(str(payload.get('subject') or ''))
                if src:
                    segment = _network_id_for_ip(networks, src)
                    if segment:
                        segments.add(segment)
                if dst:
                    segment = _network_id_for_ip(networks, dst)
                    if segment:
                        segments.add(segment)
            elif kind in {'dhcp_lease', 'arp_entry'}:
                ip = str(attrs.get('ip') or '')
                if ip:
                    segment = _network_id_for_ip(networks, ip)
                    if segment:
                        segments.add(segment)
        return {
            'affected_segments': sorted(segments),
            'multi_segment': len(segments) > 1,
        }

    @staticmethod
    def _evaluate_affected_scope(
        payloads: List[Dict[str, Any]],
        by_kind: Dict[str, List[Dict[str, Any]]],
        sot: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        networks = sot.get('networks', []) if isinstance(sot, dict) and isinstance(sot.get('networks'), list) else []
        devices = sot.get('devices', []) if isinstance(sot, dict) and isinstance(sot.get('devices'), list) else []
        services = sot.get('services', []) if isinstance(sot, dict) and isinstance(sot.get('services'), list) else []
        service_ids = {str(item.get('id') or item.get('name') or '').strip() for item in services if isinstance(item, dict)}
        service_ids.discard('')

        affected_uplinks: set[str] = set()
        affected_segments: set[str] = set()
        related_service_targets: set[str] = set()
        evidence_ids: set[str] = set()

        for kind in ('path_probe', 'path_probe_window'):
            for event in by_kind.get(kind, []):
                attrs = event.get('attrs', {})
                interface = str(attrs.get('interface') or '').strip()
                reachable = bool(attrs.get('reachable', True))
                state = str(attrs.get('state') or '').lower()
                if interface and (not reachable or state in {'degraded', 'down'}):
                    affected_uplinks.add(interface)
                    if str(event.get('event_id') or ''):
                        evidence_ids.add(str(event.get('event_id')))

        for event in by_kind.get('capacity_pressure', []):
            attrs = event.get('attrs', {})
            interface = str(attrs.get('interface') or '').strip()
            state = str(attrs.get('state') or '').lower()
            if interface and state in {'elevated', 'congested'}:
                affected_uplinks.add(interface)
                if str(event.get('event_id') or ''):
                    evidence_ids.add(str(event.get('event_id')))

        for kind in ('service_health', 'service_probe', 'service_probe_window'):
            for event in by_kind.get(kind, []):
                attrs = event.get('attrs', {})
                target = str(attrs.get('target') or attrs.get('name') or event.get('subject') or '').strip()
                if not target:
                    continue
                degraded = False
                if kind == 'service_health':
                    degraded = str(attrs.get('state') or '').upper() != 'ON' or str(attrs.get('substate') or '').lower() not in {'running', 'listening', 'unknown'}
                elif kind == 'service_probe':
                    degraded = not bool(attrs.get('reachable'))
                else:
                    degraded = str(attrs.get('state') or '').lower() in {'degraded', 'down'}
                if degraded:
                    related_service_targets.add(target)
                    if str(event.get('event_id') or ''):
                        evidence_ids.add(str(event.get('event_id')))

        for event in by_kind.get('resolution_probe_window', []):
            attrs = event.get('attrs', {})
            state = str(attrs.get('state') or '').lower()
            if state in {'degraded', 'failed'}:
                target = str(attrs.get('name') or event.get('subject') or '').strip()
                if target:
                    related_service_targets.add(target)
                    if str(event.get('event_id') or ''):
                        evidence_ids.add(str(event.get('event_id')))

        for payload in payloads:
            attrs = payload.get('attrs', {})
            event_id = str(payload.get('event_id') or '')
            if payload.get('source') in {'suricata_eve', 'flow_min'}:
                src, dst = _parse_subject(str(payload.get('subject') or ''))
                for ip in (src, dst):
                    if ip:
                        segment = _network_id_for_ip(networks, ip)
                        if segment:
                            affected_segments.add(segment)
                            if event_id:
                                evidence_ids.add(event_id)
                app_proto = str(attrs.get('app_proto') or '').strip()
                if app_proto:
                    related_service_targets.add(app_proto)
            elif payload.get('kind') in {'dhcp_lease', 'arp_entry', 'client_session'}:
                ip = str(attrs.get('ip') or '')
                segment = str(attrs.get('interface_or_segment') or '')
                if not segment and ip:
                    segment = _network_id_for_ip(networks, ip)
                if segment:
                    affected_segments.add(segment)
                    if event_id:
                        evidence_ids.add(event_id)

        device_by_ip = {
            str(item.get('ip') or ''): item
            for item in devices
            if isinstance(item, dict) and str(item.get('ip') or '')
        }
        affected_client_count = 0
        critical_client_count = 0
        client_groups: set[str] = set()
        for event in by_kind.get('client_session', []):
            attrs = event.get('attrs', {})
            ip = str(attrs.get('ip') or '')
            segment = str(attrs.get('interface_or_segment') or '')
            session_state = str(attrs.get('session_state') or '')
            if not segment and ip:
                segment = _network_id_for_ip(networks, ip)
            impacted = False
            if segment and segment in affected_segments:
                impacted = True
            if attrs.get('interface_or_segment') and str(attrs.get('interface_or_segment')) in affected_uplinks:
                impacted = True
            if session_state in {'authorized_missing', 'stale_session'}:
                impacted = False
            if impacted:
                affected_client_count += 1
                device = device_by_ip.get(ip, {})
                criticality = str(device.get('criticality') or '').lower()
                if criticality in {'critical', 'high', 'core', 'mission'}:
                    critical_client_count += 1
                    client_groups.add('critical')
                elif criticality:
                    client_groups.add(criticality)

        related_service_targets = {
            target
            for target in related_service_targets
            if not service_ids or target in service_ids or ':' in target or '.' in target
        }
        if not affected_segments and not affected_uplinks and not related_service_targets:
            return {}
        return {
            'affected_uplinks': sorted(affected_uplinks),
            'affected_segments': sorted(affected_segments),
            'related_service_targets': sorted(related_service_targets),
            'affected_client_count': affected_client_count,
            'critical_client_count': critical_client_count,
            'client_groups': sorted(client_groups),
            'multi_segment': len(affected_segments) > 1,
            'evidence_ids': sorted(evidence_ids),
        }
