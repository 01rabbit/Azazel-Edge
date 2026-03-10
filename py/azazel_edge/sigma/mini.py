from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List


@dataclass(frozen=True)
class MiniSigmaRule:
    rule_id: str
    title: str
    source: str = ''
    kind: str = ''
    subject_contains: str = ''
    attrs: Dict[str, Any] = field(default_factory=dict)
    min_severity: int = 0

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> 'MiniSigmaRule':
        return cls(
            rule_id=str(payload.get('id') or ''),
            title=str(payload.get('title') or ''),
            source=str(payload.get('source') or ''),
            kind=str(payload.get('kind') or ''),
            subject_contains=str(payload.get('subject_contains') or ''),
            attrs=payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {},
            min_severity=int(payload.get('min_severity') or 0),
        )


class MiniSigmaExecutor:
    def __init__(self, rules: Iterable[MiniSigmaRule | Dict[str, Any]] | None = None):
        prepared: List[MiniSigmaRule] = []
        for item in rules or []:
            if isinstance(item, MiniSigmaRule):
                prepared.append(item)
            elif isinstance(item, dict):
                prepared.append(MiniSigmaRule.from_dict(item))
        self.rules = prepared

    def match(self, events: Iterable[Any]) -> List[Dict[str, Any]]:
        payloads: List[Dict[str, Any]] = []
        for event in events:
            if hasattr(event, 'to_dict'):
                payloads.append(event.to_dict())
            elif isinstance(event, dict):
                payloads.append(dict(event))

        hits: List[Dict[str, Any]] = []
        for rule in self.rules:
            evidence_ids: List[str] = []
            matched_sources: List[str] = []
            for payload in payloads:
                if self._matches_rule(payload, rule):
                    event_id = str(payload.get('event_id') or '')
                    if event_id:
                        evidence_ids.append(event_id)
                    source = str(payload.get('source') or '')
                    if source:
                        matched_sources.append(source)
            if evidence_ids:
                hits.append({
                    'rule_id': rule.rule_id,
                    'title': rule.title,
                    'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
                    'sources': sorted(dict.fromkeys(matched_sources)),
                })
        return hits

    @staticmethod
    def _matches_rule(payload: Dict[str, Any], rule: MiniSigmaRule) -> bool:
        if rule.source and str(payload.get('source') or '') != rule.source:
            return False
        if rule.kind and str(payload.get('kind') or '') != rule.kind:
            return False
        if rule.subject_contains and rule.subject_contains.lower() not in str(payload.get('subject') or '').lower():
            return False
        if int(payload.get('severity') or 0) < int(rule.min_severity or 0):
            return False
        attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
        for key, expected in rule.attrs.items():
            if str(attrs.get(key) or '') != str(expected):
                return False
        return True
