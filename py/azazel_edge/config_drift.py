from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from azazel_edge.audit import P0AuditLogger
from azazel_edge.path_schema import (
    defaults_file_candidates,
    first_minute_config_candidates,
    mode_state_candidates,
    opencanary_config_candidates,
)
from azazel_edge.sensors.noc_monitor import DEFAULT_DHCP_LEASE_PATHS, DEFAULT_RESOLUTION_TARGETS, DEFAULT_SERVICE_PROBE_TARGETS, EXTERNAL_PATH_TARGETS


HEALTH_CONFIG_SCHEMA = 'noc_health_config_snapshot_v1'


def _normalize_list(values: Iterable[Any]) -> List[str]:
    return sorted(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))


def _normalize_service_targets(values: Iterable[Any]) -> List[str]:
    normalized: List[str] = []
    for item in values:
        if isinstance(item, dict):
            target = str(item.get('name') or item.get('target') or item.get('url') or f"{item.get('host') or ''}:{item.get('port') or ''}").strip(':')
        else:
            target = str(item).strip()
        if target:
            normalized.append(target)
    return _normalize_list(normalized)


def _flatten_dict(payload: Dict[str, Any], prefix: str = '') -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for key, value in sorted(payload.items()):
        current = f'{prefix}.{key}' if prefix else str(key)
        if isinstance(value, dict):
            flat.update(_flatten_dict(value, current))
        else:
            flat[current] = value
    return flat


def extract_health_config_snapshot(runtime: Dict[str, Any] | None = None, sot: Dict[str, Any] | None = None) -> Dict[str, Any]:
    state = runtime if isinstance(runtime, dict) else {}
    source_of_truth = sot if isinstance(sot, dict) else {}
    preferred_uplink = str(state.get('preferred_uplink') or state.get('up_if') or '')
    uplink_order = state.get('uplink_order') if isinstance(state.get('uplink_order'), list) else ([preferred_uplink] if preferred_uplink else [])
    path_targets = state.get('path_targets') if isinstance(state.get('path_targets'), list) else list(EXTERNAL_PATH_TARGETS)
    if str(state.get('gateway_ip') or '').strip():
        path_targets = [str(state.get('gateway_ip')).strip(), *[item for item in path_targets if str(item).strip() and str(item).strip() != str(state.get('gateway_ip')).strip()]]
    snapshot = {
        'schema': HEALTH_CONFIG_SCHEMA,
        'uplink_preference': {
            'preferred_uplink': preferred_uplink,
            'failover_order': _normalize_list(uplink_order),
        },
        'probe_targets': {
            'path_targets': _normalize_list(path_targets),
            'resolution_targets': _normalize_list(state.get('resolution_targets') if isinstance(state.get('resolution_targets'), list) else DEFAULT_RESOLUTION_TARGETS),
            'service_targets': _normalize_service_targets(state.get('service_probe_targets') if isinstance(state.get('service_probe_targets'), list) else DEFAULT_SERVICE_PROBE_TARGETS),
        },
        'dhcp_settings': {
            'gateway_ip': str(state.get('gateway_ip') or ''),
            'lease_sources': _normalize_list(state.get('dhcp_lease_paths') if isinstance(state.get('dhcp_lease_paths'), list) else [str(path) for path in DEFAULT_DHCP_LEASE_PATHS]),
            'managed_networks': _normalize_list(item.get('id') for item in source_of_truth.get('networks', []) if isinstance(item, dict)),
        },
        'segment_membership': {
            'network_ids': _normalize_list(item.get('id') for item in source_of_truth.get('networks', []) if isinstance(item, dict)),
            'service_ids': _normalize_list(item.get('id') for item in source_of_truth.get('services', []) if isinstance(item, dict)),
            'device_networks': {
                str(item.get('id') or ''): _normalize_list(item.get('allowed_networks', []))
                for item in source_of_truth.get('devices', [])
                if isinstance(item, dict) and str(item.get('id') or '')
            },
        },
        'policy_markers': {
            'current_mode': str(((state.get('mode') or {}) if isinstance(state.get('mode'), dict) else {}).get('current_mode') or state.get('current_mode') or ''),
            'policy_version': str(state.get('policy_version') or state.get('defaults_version') or ''),
            'expected_path_count': len([item for item in source_of_truth.get('expected_paths', []) if isinstance(item, dict)]),
            'service_count': len([item for item in source_of_truth.get('services', []) if isinstance(item, dict)]),
        },
    }
    validate_health_config_snapshot(snapshot)
    return snapshot


def validate_health_config_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise ValueError('health_config_snapshot_invalid')
    if str(snapshot.get('schema') or '') != HEALTH_CONFIG_SCHEMA:
        raise ValueError('health_config_snapshot_invalid')
    required_sections = ('uplink_preference', 'probe_targets', 'dhcp_settings', 'segment_membership', 'policy_markers')
    for section in required_sections:
        if not isinstance(snapshot.get(section), dict):
            raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['uplink_preference'].get('failover_order'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['probe_targets'].get('path_targets'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['probe_targets'].get('resolution_targets'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['probe_targets'].get('service_targets'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['dhcp_settings'].get('lease_sources'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['dhcp_settings'].get('managed_networks'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['segment_membership'].get('network_ids'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['segment_membership'].get('service_ids'), list):
        raise ValueError('health_config_snapshot_invalid')
    if not isinstance(snapshot['segment_membership'].get('device_networks'), dict):
        raise ValueError('health_config_snapshot_invalid')
    return snapshot


def diff_health_config_snapshots(baseline: Dict[str, Any] | None, current: Dict[str, Any] | None) -> Dict[str, Any]:
    if not isinstance(baseline, dict):
        return {
            'status': 'baseline_missing',
            'baseline_state': 'missing',
            'changed_fields': [],
            'baseline_values': {},
            'current_values': {},
            'rollback_hint': 'create_last_known_good_baseline',
        }
    try:
        validated_baseline = validate_health_config_snapshot(dict(baseline))
    except ValueError:
        return {
            'status': 'baseline_invalid',
            'baseline_state': 'invalid',
            'changed_fields': [],
            'baseline_values': {},
            'current_values': {},
            'rollback_hint': 'repair_or_replace_invalid_baseline',
        }
    validated_current = validate_health_config_snapshot(dict(current or {}))
    baseline_flat = _flatten_dict({k: v for k, v in validated_baseline.items() if k != 'schema'})
    current_flat = _flatten_dict({k: v for k, v in validated_current.items() if k != 'schema'})
    changed_fields = sorted(field for field in set(baseline_flat) | set(current_flat) if baseline_flat.get(field) != current_flat.get(field))
    return {
        'status': 'drift' if changed_fields else 'baseline_match',
        'baseline_state': 'present',
        'changed_fields': changed_fields,
        'baseline_values': {field: baseline_flat.get(field) for field in changed_fields},
        'current_values': {field: current_flat.get(field) for field in changed_fields},
        'rollback_hint': (
            'review_changed_fields_and_restore_last_known_good'
            if changed_fields else 'baseline_matches_current'
        ),
    }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_entry(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {
            'path': str(path),
            'exists': False,
            'sha256': '',
            'size': 0,
            'mtime': '',
        }
    data = path.read_bytes()
    stat = path.stat()
    return {
        'path': str(path),
        'exists': True,
        'sha256': _sha256_bytes(data),
        'size': stat.st_size,
        'mtime': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec='seconds'),
    }


def default_config_targets(repo_root: str | Path | None = None) -> List[Path]:
    root = Path(repo_root) if repo_root else None
    candidates: List[Path] = []
    for path in defaults_file_candidates():
        candidates.append(path)
    for path in first_minute_config_candidates():
        candidates.append(path)
    for path in mode_state_candidates():
        candidates.append(path)
    for path in opencanary_config_candidates(repo_root=root):
        candidates.append(path)
    candidates.extend(
        [
            Path('/etc/default/azazel-edge-web'),
            Path('/etc/default/azazel-edge-ai-agent'),
            Path('/etc/systemd/system/azazel-edge-web.service'),
            Path('/etc/systemd/system/azazel-edge-ai-agent.service'),
        ]
    )
    deduped: List[Path] = []
    seen: set[str] = set()
    for item in candidates:
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


class ConfigDriftAuditor:
    def __init__(self, baseline_path: str | Path, audit_logger: P0AuditLogger | None = None):
        self.baseline_path = Path(baseline_path)
        self.audit = audit_logger
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

    def create_baseline(self, targets: Iterable[str | Path]) -> Dict[str, Any]:
        snapshot = self._snapshot(targets)
        payload = {
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'entries': snapshot,
        }
        self.baseline_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding='utf-8')
        return payload

    def detect_drift(self, targets: Iterable[str | Path]) -> Dict[str, Any]:
        baseline = self._load_baseline()
        current_entries = self._snapshot(targets)
        baseline_map = {item['path']: item for item in baseline.get('entries', []) if isinstance(item, dict)}
        current_map = {item['path']: item for item in current_entries}

        added: List[str] = []
        removed: List[str] = []
        modified: List[str] = []

        for path, entry in current_map.items():
            before = baseline_map.get(path)
            if before is None:
                added.append(path)
                continue
            if bool(before.get('exists')) != bool(entry.get('exists')):
                if entry.get('exists'):
                    added.append(path)
                else:
                    removed.append(path)
                continue
            if entry.get('exists') and before.get('sha256') != entry.get('sha256'):
                modified.append(path)

        for path, entry in baseline_map.items():
            if path not in current_map and entry.get('exists'):
                removed.append(path)

        result = {
            'status': 'drift' if added or removed or modified else 'baseline_match',
            'added': sorted(dict.fromkeys(added)),
            'removed': sorted(dict.fromkeys(removed)),
            'modified': sorted(dict.fromkeys(modified)),
            'baseline_path': str(self.baseline_path),
            'baseline_ts': baseline.get('ts', ''),
            'current_entries': current_entries,
        }
        return result

    def create_health_baseline(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        validated = validate_health_config_snapshot(dict(snapshot))
        payload = {
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'schema': HEALTH_CONFIG_SCHEMA,
            'snapshot': validated,
        }
        self.baseline_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding='utf-8')
        return payload

    def detect_health_drift(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        try:
            baseline = self._load_health_baseline()
        except ValueError:
            baseline = {'ts': '', 'snapshot': {'schema': 'invalid'}}
        diff = diff_health_config_snapshots(baseline.get('snapshot'), snapshot)
        diff['baseline_path'] = str(self.baseline_path)
        diff['baseline_ts'] = baseline.get('ts', '')
        return diff

    def audit_drift(self, trace_id: str, drift: Dict[str, Any]) -> Dict[str, Any]:
        if self.audit is None:
            return drift
        return self.audit.log_evaluation(
            trace_id=trace_id,
            source='config_drift_audit',
            status=str(drift.get('status') or ''),
            added=drift.get('added', []),
            removed=drift.get('removed', []),
            modified=drift.get('modified', []),
            baseline_path=str(drift.get('baseline_path') or ''),
        )

    def _snapshot(self, targets: Iterable[str | Path]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for target in targets:
            rows.append(_file_entry(Path(target)))
        rows.sort(key=lambda item: str(item.get('path') or ''))
        return rows

    def _load_baseline(self) -> Dict[str, Any]:
        if not self.baseline_path.exists():
            return {'ts': '', 'entries': []}
        payload = json.loads(self.baseline_path.read_text(encoding='utf-8'))
        if not isinstance(payload, dict):
            raise ValueError('config_drift_baseline_invalid')
        if not isinstance(payload.get('entries', []), list):
            raise ValueError('config_drift_baseline_invalid')
        return payload

    def _load_health_baseline(self) -> Dict[str, Any]:
        if not self.baseline_path.exists():
            return {'ts': '', 'snapshot': None}
        payload = json.loads(self.baseline_path.read_text(encoding='utf-8'))
        if not isinstance(payload, dict):
            raise ValueError('config_drift_baseline_invalid')
        snapshot = payload.get('snapshot')
        if snapshot is None:
            return {'ts': '', 'snapshot': None}
        validate_health_config_snapshot(snapshot)
        return {'ts': str(payload.get('ts') or ''), 'snapshot': snapshot}
