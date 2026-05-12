from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


VALID_KINDS = {
    'event_receive',
    'evaluation',
    'action_decision',
    'notification',
    'ai_assist',
    'triage_session_started',
    'triage_step_answered',
    'triage_state_changed',
    'triage_runbook_proposed',
    'triage_handoff',
    'triage_completed',
}


class P0AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last_chain_hash = self._read_last_chain_hash()

    def _read_last_chain_hash(self) -> str:
        if not self.path.exists():
            return ''
        try:
            lines = self.path.read_text(encoding='utf-8').splitlines()
        except Exception:
            return ''
        if not lines:
            return ''
        try:
            last = json.loads(lines[-1])
        except Exception:
            return ''
        return str(last.get('chain_hash') or '')

    @staticmethod
    def _compute_chain_hash(record: Dict[str, Any]) -> str:
        canon = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode('utf-8')
        return hashlib.sha256(canon).hexdigest()

    @classmethod
    def verify_chain(cls, path: str | Path) -> Dict[str, Any]:
        log_path = Path(path)
        if not log_path.exists():
            return {'ok': True, 'entries': 0, 'error': ''}
        lines = log_path.read_text(encoding='utf-8').splitlines()
        prev = ''
        for idx, line in enumerate(lines, start=1):
            row = json.loads(line)
            if str(row.get('chain_prev') or '') != prev:
                return {'ok': False, 'entries': idx - 1, 'error': f'chain_prev_mismatch_at:{idx}'}
            row_for_hash = dict(row)
            actual = str(row_for_hash.pop('chain_hash', '') or '')
            expected = cls._compute_chain_hash(row_for_hash)
            if actual != expected:
                return {'ok': False, 'entries': idx - 1, 'error': f'chain_hash_mismatch_at:{idx}'}
            prev = actual
        return {'ok': True, 'entries': len(lines), 'error': ''}

    def log(self, kind: str, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        if kind not in VALID_KINDS:
            raise ValueError(f'invalid_audit_kind:{kind}')
        record = {
            'ts': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'kind': kind,
            'trace_id': str(trace_id),
            'source': str(source),
            'chain_prev': self._last_chain_hash,
        }
        record.update(payload)
        record['chain_hash'] = self._compute_chain_hash(record)
        with self.path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=True, separators=(',', ':')) + '\n')
        self._last_chain_hash = str(record['chain_hash'])
        return record

    def log_event_receive(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('event_receive', trace_id=trace_id, source=source, **payload)

    def log_evaluation(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('evaluation', trace_id=trace_id, source=source, **payload)

    def log_action_decision(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('action_decision', trace_id=trace_id, source=source, **payload)

    def log_notification(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('notification', trace_id=trace_id, source=source, **payload)

    def log_ai_assist(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('ai_assist', trace_id=trace_id, source=source, **payload)

    def log_triage_session_started(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_session_started', trace_id=trace_id, source=source, **payload)

    def log_triage_step_answered(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_step_answered', trace_id=trace_id, source=source, **payload)

    def log_triage_state_changed(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_state_changed', trace_id=trace_id, source=source, **payload)

    def log_triage_runbook_proposed(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_runbook_proposed', trace_id=trace_id, source=source, **payload)

    def log_triage_handoff(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_handoff', trace_id=trace_id, source=source, **payload)

    def log_triage_completed(self, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        return self.log('triage_completed', trace_id=trace_id, source=source, **payload)
