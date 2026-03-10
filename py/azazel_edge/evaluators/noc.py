from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List


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
        if sot_diff:
            path_health = self._apply_sot_diff_to_path_health(path_health, sot_diff)

        summary_reasons: List[str] = []
        degraded_mode = False
        if not sot:
            degraded_mode = True
            summary_reasons.append('sot_missing')
            if 'sot_missing' not in client_health['reasons']:
                client_health['reasons'].append('sot_missing')

        dimensions = [availability, path_health, device_health, client_health]
        worst_score = min(int(dim['score']) for dim in dimensions) if dimensions else 100
        if worst_score < 90:
            summary_reasons.extend(
                f"{name}:{dim['label']}"
                for name, dim in (
                    ('availability', availability),
                    ('path_health', path_health),
                    ('device_health', device_health),
                    ('client_health', client_health),
                )
                if dim['label'] != 'good'
            )

        summary = {
            'status': _bucket(worst_score),
            'degraded_mode': degraded_mode,
            'reasons': sorted(dict.fromkeys(summary_reasons)),
        }

        result = {
            'availability': availability,
            'path_health': path_health,
            'device_health': device_health,
            'client_health': client_health,
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
        for event in by_kind.get('path_probe', []):
            attrs = event.get('attrs', {})
            evidence_ids.append(str(event.get('event_id') or ''))
            reachable = bool(attrs.get('reachable'))
            scope = str(attrs.get('scope') or '')
            probe_results.append(reachable)
            if not reachable:
                score -= 20 if scope == 'external' else 10
                reasons.append(f'path_probe_failed:{scope or "unknown"}')
        if probe_results and len(set(probe_results)) > 1:
            score -= 15
            reasons.append('path_target_divergence')

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
