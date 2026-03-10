from __future__ import annotations

import re
from typing import Dict, Tuple

from .schema import EvidenceEvent, iso_utc_now

SYSLOG_RE = re.compile(r'^(?:<(?P<pri>\d+)>)?(?P<ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[^ ]+)?\s*(?P<host>[a-zA-Z0-9._:-]+)?\s*(?P<tag>[a-zA-Z0-9._/-]+)?(?:\[(?P<pid>\d+)\])?:?\s*(?P<msg>.*)$')


def _severity_from_pri(pri: str, message: str) -> Tuple[int, str]:
    if pri.isdigit():
        level = int(pri) % 8
        mapping = {
            0: (90, 'fail'),
            1: (85, 'fail'),
            2: (75, 'fail'),
            3: (60, 'warn'),
            4: (45, 'warn'),
            5: (30, 'info'),
            6: (15, 'info'),
            7: (5, 'info'),
        }
        return mapping.get(level, (20, 'info'))
    lowered = message.lower()
    if any(token in lowered for token in ('fatal', 'panic', 'critical', 'failed')):
        return 70, 'fail'
    if any(token in lowered for token in ('warn', 'degraded', 'retry')):
        return 40, 'warn'
    return 15, 'info'


def adapt_syslog_line(line: str) -> EvidenceEvent:
    text = str(line or '').strip()
    if not text:
        raise ValueError('empty_syslog_line')
    match = SYSLOG_RE.match(text)
    if not match:
        raise ValueError('invalid_syslog_line')
    groups = match.groupdict()
    message = str(groups.get('msg') or '').strip()
    host = str(groups.get('host') or 'unknown-host').strip()
    tag = str(groups.get('tag') or 'syslog').strip()
    pid = str(groups.get('pid') or '').strip()
    pri = str(groups.get('pri') or '').strip()
    severity, status = _severity_from_pri(pri, message)
    subject = f'{host}:{tag}'
    if pid:
        subject = f'{subject}[{pid}]'
    ts = str(groups.get('ts') or '') or iso_utc_now()
    return EvidenceEvent.build(
        ts=ts,
        source='syslog_min',
        kind='syslog_line',
        subject=subject,
        severity=severity,
        confidence=0.75,
        attrs={'host': host, 'tag': tag, 'pid': pid, 'pri': pri, 'message': message},
        status=status,
    )
