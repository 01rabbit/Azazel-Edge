from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_ATTACK_MAPPING_PATH = Path(
    str(os.environ.get("AZAZEL_ATTACK_MAPPING_PATH", "config/attack_mapping.yaml")).strip()
    or "config/attack_mapping.yaml"
)


def _validate_rule(rule: Dict[str, Any]) -> None:
    required = {"technique_id", "technique_name", "tactic", "confidence"}
    missing = sorted(required.difference(rule.keys()))
    if missing:
        raise ValueError(f"attack_mapping_invalid:missing_keys:{','.join(missing)}")
    confidence = int(rule.get("confidence") or 0)
    if confidence < 0 or confidence > 100:
        raise ValueError("attack_mapping_invalid:confidence_range")


def load_attack_mapping(path: Path | None = None) -> Dict[str, Any]:
    target = path or DEFAULT_ATTACK_MAPPING_PATH
    if not target.exists():
        return {"version": "attack-mapping-default-v1", "rules": [], "path": str(target)}
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise ValueError(f"attack_mapping_invalid:yaml_unavailable:{e}")
    payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("attack_mapping_invalid:root_must_be_object")
    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise ValueError("attack_mapping_invalid:rules_must_be_list")
    normalized: List[Dict[str, Any]] = []
    for item in rules:
        if not isinstance(item, dict):
            raise ValueError("attack_mapping_invalid:rule_must_be_object")
        _validate_rule(item)
        normalized.append(
            {
                "technique_id": str(item.get("technique_id") or "").strip(),
                "technique_name": str(item.get("technique_name") or "").strip(),
                "tactic": str(item.get("tactic") or "").strip(),
                "confidence": int(item.get("confidence") or 0),
                "sid": [int(x) for x in (item.get("sid") or [])],
                "attack_type_contains": [str(x).strip().lower() for x in (item.get("attack_type_contains") or []) if str(x).strip()],
                "category_contains": [str(x).strip().lower() for x in (item.get("category_contains") or []) if str(x).strip()],
                "service_contains": [str(x).strip().lower() for x in (item.get("service_contains") or []) if str(x).strip()],
            }
        )
    return {
        "version": str(payload.get("version") or "attack-mapping-v1"),
        "rules": normalized,
        "path": str(target),
    }


def map_attack_techniques(payload: Dict[str, Any], mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    attrs = payload.get("attrs") if isinstance(payload.get("attrs"), dict) else {}
    sid = int(attrs.get("sid") or 0)
    attack_type = str(attrs.get("attack_type") or "").lower()
    category = str(attrs.get("category") or "").lower()
    service = str(attrs.get("service") or attrs.get("app_proto") or "").lower()
    rules = mapping.get("rules") if isinstance(mapping.get("rules"), list) else []
    hits: List[Dict[str, Any]] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        sid_match = not rule.get("sid") or sid in set(int(x) for x in (rule.get("sid") or []))
        atk_match = not rule.get("attack_type_contains") or any(x in attack_type for x in rule.get("attack_type_contains") or [])
        cat_match = not rule.get("category_contains") or any(x in category for x in rule.get("category_contains") or [])
        svc_match = not rule.get("service_contains") or any(x in service for x in rule.get("service_contains") or [])
        if sid_match and atk_match and cat_match and svc_match:
            hits.append(
                {
                    "technique_id": str(rule.get("technique_id") or ""),
                    "technique_name": str(rule.get("technique_name") or ""),
                    "tactic": str(rule.get("tactic") or ""),
                    "confidence": int(rule.get("confidence") or 0),
                    "mapped_by": "rule",
                }
            )
    if not hits:
        return [
            {
                "technique_id": "unmapped",
                "technique_name": "unmapped",
                "tactic": "unmapped",
                "confidence": 0,
                "mapped_by": "fallback",
            }
        ]
    uniq: Dict[str, Dict[str, Any]] = {}
    for item in hits:
        key = f"{item['technique_id']}|{item['tactic']}"
        prev = uniq.get(key)
        if prev is None or int(item.get("confidence") or 0) > int(prev.get("confidence") or 0):
            uniq[key] = item
    return list(uniq.values())

