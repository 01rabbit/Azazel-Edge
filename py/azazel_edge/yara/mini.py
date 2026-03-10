from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List


@dataclass(frozen=True)
class MiniYaraRule:
    rule_id: str
    title: str
    tags: List[str] = field(default_factory=list)
    contains_any: List[str] = field(default_factory=list)
    source: str = ''
    kind: str = ''

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> 'MiniYaraRule':
        return cls(
            rule_id=str(payload.get('id') or ''),
            title=str(payload.get('title') or ''),
            tags=[str(x) for x in payload.get('tags', [])] if isinstance(payload.get('tags'), list) else [],
            contains_any=[str(x) for x in payload.get('contains_any', [])] if isinstance(payload.get('contains_any'), list) else [],
            source=str(payload.get('source') or ''),
            kind=str(payload.get('kind') or ''),
        )


class MiniYaraMatcher:
    def __init__(self, rules: Iterable[MiniYaraRule | Dict[str, Any]] | None = None):
        prepared: List[MiniYaraRule] = []
        for item in rules or []:
            if isinstance(item, MiniYaraRule):
                prepared.append(item)
            elif isinstance(item, dict):
                prepared.append(MiniYaraRule.from_dict(item))
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
            for payload in payloads:
                if self._matches_rule(payload, rule):
                    event_id = str(payload.get('event_id') or '')
                    if event_id:
                        evidence_ids.append(event_id)
            if evidence_ids:
                hits.append({
                    'rule_id': rule.rule_id,
                    'title': rule.title,
                    'tags': list(rule.tags),
                    'evidence_ids': sorted(dict.fromkeys(evidence_ids)),
                })
        return hits

    @staticmethod
    def _matches_rule(payload: Dict[str, Any], rule: MiniYaraRule) -> bool:
        if rule.source and str(payload.get('source') or '') != rule.source:
            return False
        if rule.kind and str(payload.get('kind') or '') != rule.kind:
            return False
        text = MiniYaraMatcher._artifact_text(payload)
        if rule.contains_any and not any(token.lower() in text for token in rule.contains_any):
            return False
        return True

    @staticmethod
    def _artifact_text(payload: Dict[str, Any]) -> str:
        parts: List[str] = [str(payload.get('subject') or '')]
        attrs = payload.get('attrs', {}) if isinstance(payload.get('attrs'), dict) else {}
        parts.extend(str(value) for value in attrs.values() if value is not None)
        refs = payload.get('evidence_refs', []) if isinstance(payload.get('evidence_refs'), list) else []
        parts.extend(str(value) for value in refs if value is not None)
        return ' '.join(parts).lower()
