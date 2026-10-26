from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)

# <root>/config/soc_policy.yaml, where <root> is the tree this module is in
# (the checkout, or /opt/azazel-edge when installed): py/azazel_edge/policy.py
# is two levels below it. Not the working directory, which is / under systemd.
# AZAZEL_SOC_POLICY_PATH still overrides it.
INSTALL_ROOT = Path(__file__).resolve().parents[2]
_BUILTIN_SOC_POLICY_PATH = INSTALL_ROOT / "config" / "soc_policy.yaml"
DEFAULT_SOC_POLICY_PATH = Path(
    str(os.environ.get("AZAZEL_SOC_POLICY_PATH", "")).strip() or str(_BUILTIN_SOC_POLICY_PATH)
)
_WARNED_MISSING: set[str] = set()


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
        if str(target) not in _WARNED_MISSING:
            _WARNED_MISSING.add(str(target))
            logger.warning("SOC policy %s not found; using the built-in defaults", target)
        return {"version": "soc-policy-default-v1", "source": "default", "path": str(target), "hash": "default"}
    try:
        import yaml  # type: ignore
    except Exception as e:
        raise ValueError(f"soc_policy_invalid:yaml_unavailable:{e}")
    # A file that is there but cannot be read or parsed is an error, never the
    # defaults: the operator's policy would be silently replaced.
    try:
        data = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise ValueError(f"soc_policy_invalid:unreadable:{target}:{type(e).__name__}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("soc_policy_invalid:root_must_be_object")
    _validate_action_mapping(data)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    data["hash"] = digest
    data["path"] = str(target)
    return data

