from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


VALID_KINDS = {'event_receive', 'evaluation', 'action_decision', 'notification', 'ai_assist'}


class P0AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, kind: str, trace_id: str, source: str, **payload: Any) -> Dict[str, Any]:
        if kind not in VALID_KINDS:
            raise ValueError(f'invalid_audit_kind:{kind}')
        record = {
            'ts': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
            'kind': kind,
            'trace_id': str(trace_id),
            'source': str(source),
        }
        record.update(payload)
        with self.path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(record, ensure_ascii=True, separators=(',', ':')) + '\n')
        return record
