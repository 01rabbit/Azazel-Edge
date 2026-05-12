from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict


DEFAULT_SOC_POLICY_PATH = Path(str(os.environ.get("AZAZEL_SOC_POLICY_PATH", "config/soc_policy.yaml")).strip() or "config/soc_policy.yaml")


def _validate_action_mapping(payload: Dict[str, Any]) -> None:
    mapping = payload.get("action_mapping")
    if not isinstance(mapping, dict):
        raise ValueError("soc_policy_invalid:action_mapping_required")
    for key in ("isolate", "redirect", "throttle", "strong_soc"):
        if not isinstance(mapping.get(key), dict):
            raise ValueError(f"soc_policy_invalid:action_mapping.{key}_required")


def load_soc_policy(path: Path | None = None) -> Dict[str, Any]:
    target = path or DEFAULT_SOC_POLICY_PATH
    if not target.exists():
        return {"version": "soc-policy-default-v1", "source": "default", "path": str(target), "hash": "default"}
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise ValueError(f"soc_policy_invalid:yaml_unavailable:{e}")
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("soc_policy_invalid:root_must_be_object")
    _validate_action_mapping(data)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    data["hash"] = digest
    data["path"] = str(target)
    return data

