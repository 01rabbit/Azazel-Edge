from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from urllib import request


class UpstreamEnvelopeBuilder:
    def build(
        self,
        *,
        trace_id: str,
        noc: Dict[str, Any],
        soc: Dict[str, Any],
        arbiter: Dict[str, Any],
        explanation: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {
            'ts': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'format_version': 'v1',
            'trace_id': str(trace_id or ''),
            'noc': {
                'status': str(((noc or {}).get('summary') or {}).get('status') or 'unknown'),
                'reasons': list(((noc or {}).get('summary') or {}).get('reasons') or []),
                'evidence_ids': list((noc or {}).get('evidence_ids') or []),
            },
            'soc': {
                'status': str(((soc or {}).get('summary') or {}).get('status') or 'unknown'),
                'reasons': list(((soc or {}).get('summary') or {}).get('reasons') or []),
                'attack_candidates': list(((soc or {}).get('summary') or {}).get('attack_candidates') or []),
                'evidence_ids': list((soc or {}).get('evidence_ids') or []),
            },
            'decision': {
                'action': str((arbiter or {}).get('action') or 'observe'),
                'reason': str((arbiter or {}).get('reason') or 'unspecified'),
                'control_mode': str((arbiter or {}).get('control_mode') or 'none'),
                'chosen_evidence_ids': list((arbiter or {}).get('chosen_evidence_ids') or []),
            },
            'explanation': {
                'operator_wording': str((explanation or {}).get('operator_wording') or ''),
                'next_checks': list((explanation or {}).get('next_checks') or []),
            },
        }


class JsonlMirrorSink:
    def __init__(self, output_path: str | Path):
        self.output_path = Path(output_path)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

    def publish(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        with self.output_path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(envelope, ensure_ascii=True, separators=(',', ':')) + '\n')
        return {'ok': True, 'sink': 'jsonl', 'path': str(self.output_path)}


class WebhookSink:
    def __init__(self, url: str, timeout_sec: int = 5):
        self.url = str(url or '')
        self.timeout_sec = int(timeout_sec)

    def publish(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        payload = json.dumps(envelope, ensure_ascii=True, separators=(',', ':')).encode('utf-8')
        req = request.Request(
            self.url,
            data=payload,
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with request.urlopen(req, timeout=self.timeout_sec) as resp:
            return {
                'ok': 200 <= int(resp.status) < 300,
                'sink': 'webhook',
                'status': int(resp.status),
            }
