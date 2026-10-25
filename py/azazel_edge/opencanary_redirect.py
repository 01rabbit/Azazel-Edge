from __future__ import annotations

import json
import logging
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
        p0_alert_queue_path: str | Path | None = None,
    ):
        self.audit = audit_logger
        # P0 alert path (Edge#414, SO-03): every redirect decision this
        # controller records is enforcement-bearing, hence P0. The relay only
        # observes durable decision records; if it cannot be attached the
        # controller works exactly as before and the failure is logged.
        self.p0_alert_relay = None
        try:
            from azazel_edge.notify.p0_alert import attach_p0_alert_relay

            queue_path = Path(p0_alert_queue_path) if p0_alert_queue_path else Path(audit_logger.path).parent / 'p0-alert-queue.jsonl'
            self.p0_alert_relay = attach_p0_alert_relay(audit_logger, queue_path)
        except Exception as exc:
            logging.getLogger(__name__).error('p0 alert relay not attached: %s', exc)
        self.state_path = Path(state_path)
        self.redirect_log_path = Path(redirect_log_path)
        self.ttl_sec = int(ttl_sec)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.redirect_log_path.parent.mkdir(parents=True, exist_ok=True)

    def close(self, timeout: float = 5.0) -> None:
        """Stop the P0 alert relay after it has taken every decision handed
        to it so far. Optional; the relay thread is a daemon."""

        relay = self.p0_alert_relay
        if relay is None:
            return
        try:
            waiter = getattr(self.audit, 'wait_durable_listeners', None)
            if waiter is not None:
                waiter(timeout)
            relay.wait_idle(timeout)
            relay.stop(timeout)
        except Exception as exc:
            logging.getLogger(__name__).error('p0 alert relay stop: %s', exc)

    def evaluate(
        self,
        arbiter: Dict[str, Any],
        soc: Dict[str, Any],
        target_ip: str,
        trace_id: str,
        config_path: Optional[str | Path] = None,
    ) -> Dict[str, Any]:
        if str(arbiter.get('action') or '') not in {'redirect', 'throttle'}:
            return {'ok': False, 'redirect': False, 'reason': 'arbiter_not_redirect'}
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
            'control_mode': 'opencanary_redirect',
            'opencanary': target,
            'expires_at': expires_at.isoformat(timespec='seconds'),
            'evidence_ids': [str(x) for x in arbiter.get('chosen_evidence_ids', []) if str(x)],
            'release_condition': str(arbiter.get('release_condition') or ''),
            'rejected_alternatives': arbiter.get('rejected_alternatives', []) if isinstance(arbiter.get('rejected_alternatives'), list) else [],
            'config_hash': str((arbiter.get('policy') or {}).get('hash') or ''),
            'policy_profile': str((arbiter.get('policy') or {}).get('version') or ''),
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
            release_condition=str(decision.get('release_condition') or ''),
            rejected_alternatives=decision.get('rejected_alternatives', []),
            config_hash=str(decision.get('config_hash') or ''),
            policy_profile=str(decision.get('policy_profile') or ''),
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
