from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from azazel_edge.audit import P0AuditLogger
from azazel_edge.path_schema import (
    defaults_file_candidates,
    first_minute_config_candidates,
    mode_state_candidates,
    opencanary_config_candidates,
)


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
