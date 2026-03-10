from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from azazel_edge.audit import P0AuditLogger
from azazel_edge.path_schema import choose_read_path, opencanary_config_candidates


class OpenCanaryRedirectController:
    def __init__(
        self,
        audit_logger: P0AuditLogger,
        state_path: str | Path = '/run/azazel-edge/opencanary_redirect_state.json',
        redirect_log_path: str | Path = '/var/log/azazel-edge/opencanary-redirect.jsonl',
        ttl_sec: int = 300,
    ):
        self.audit = audit_logger
        self.state_path = Path(state_path)
        self.redirect_log_path = Path(redirect_log_path)
        self.ttl_sec = int(ttl_sec)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.redirect_log_path.parent.mkdir(parents=True, exist_ok=True)

    def evaluate(
        self,
        arbiter: Dict[str, Any],
        soc: Dict[str, Any],
        target_ip: str,
        trace_id: str,
        config_path: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        if str(arbiter.get('action') or '') != 'throttle':
            return {'ok': False, 'redirect': False, 'reason': 'arbiter_not_throttle'}
        suspicion = int(soc.get('suspicion', {}).get('score') or 0)
        confidence = int(soc.get('confidence', {}).get('score') or 0)
        if suspicion < 80 or confidence < 70:
            return {'ok': False, 'redirect': False, 'reason': 'soc_not_high_confidence'}
        if not str(target_ip or '').strip():
            return {'ok': False, 'redirect': False, 'reason': 'target_missing'}

        target = self._load_target(config_path)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.ttl_sec)
        return {
            'ok': True,
            'redirect': True,
            'trace_id': trace_id,
            'target_ip': str(target_ip),
            'reason': 'high_confidence_soc_redirect',
            'opencanary': target,
            'expires_at': expires_at.isoformat(timespec='seconds'),
            'evidence_ids': [str(x) for x in arbiter.get('chosen_evidence_ids', []) if str(x)],
        }

    def apply(self, decision: Dict[str, Any]) -> Dict[str, Any]:
        if not bool(decision.get('redirect')):
            return {'ok': False, 'applied': False, 'reason': str(decision.get('reason') or 'redirect_not_requested')}

        self.state_path.write_text(json.dumps(decision, ensure_ascii=True, indent=2), encoding='utf-8')
        with self.redirect_log_path.open('a', encoding='utf-8') as fh:
            fh.write(json.dumps(decision, ensure_ascii=True, separators=(',', ':')) + '\n')
        self.audit.log_action_decision(
            trace_id=str(decision.get('trace_id') or ''),
            source='opencanary_redirect',
            redirect=True,
            target_ip=str(decision.get('target_ip') or ''),
            evidence_ids=decision.get('evidence_ids', []),
            reason=str(decision.get('reason') or ''),
        )
        return {'ok': True, 'applied': True, 'state_path': str(self.state_path)}

    @staticmethod
    def _load_target(config_path: Optional[str | Path]) -> Dict[str, Any]:
        path = Path(config_path) if config_path else choose_read_path(opencanary_config_candidates())
        payload = json.loads(path.read_text(encoding='utf-8'))
        return {
            'config_path': str(path),
            'listen_addr': str(payload.get('device.listen_addr') or '127.0.0.1'),
            'http_port': int(payload.get('http.port') or 0),
            'ssh_port': int(payload.get('ssh.port') or 0),
        }
