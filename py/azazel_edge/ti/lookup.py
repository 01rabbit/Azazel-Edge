from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

import yaml


@dataclass(frozen=True)
class ThreatIntelMatch:
    indicator_type: str
    value: str
    confidence: int
    source: str
    note: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'indicator_type': self.indicator_type,
            'value': self.value,
            'confidence': self.confidence,
            'source': self.source,
            'note': self.note,
        }


class ThreatIntelFeed:
    def __init__(self, indicators: List[Dict[str, Any]]):
        self.indicators = [dict(item) for item in indicators if isinstance(item, dict)]

    def match(self, ips: List[str], domains: List[str]) -> List[ThreatIntelMatch]:
        ip_set = {str(x).strip() for x in ips if str(x).strip()}
        domain_set = {str(x).strip().lower() for x in domains if str(x).strip()}
        matches: List[ThreatIntelMatch] = []
        for indicator in self.indicators:
            indicator_type = str(indicator.get('type') or '').lower()
            value = str(indicator.get('value') or '').strip()
            if not indicator_type or not value:
                continue
            matched = False
            if indicator_type == 'ip' and value in ip_set:
                matched = True
            elif indicator_type == 'domain' and value.lower() in domain_set:
                matched = True
            if matched:
                matches.append(ThreatIntelMatch(
                    indicator_type=indicator_type,
                    value=value,
                    confidence=max(0, min(int(indicator.get('confidence') or 50), 100)),
                    source=str(indicator.get('source') or 'local_feed'),
                    note=str(indicator.get('note') or ''),
                ))
        return matches


def load_ti_feed(path: str | Path) -> ThreatIntelFeed:
    source = Path(path)
    raw = source.read_text(encoding='utf-8')
    if source.suffix.lower() in {'.yaml', '.yml'}:
        payload = yaml.safe_load(raw)
    elif source.suffix.lower() == '.json':
        payload = json.loads(raw)
    else:
        raise ValueError('unsupported_ti_feed_format')
    if not isinstance(payload, dict) or not isinstance(payload.get('indicators'), list):
        raise ValueError('ti_feed_invalid')
    return ThreatIntelFeed(payload['indicators'])
