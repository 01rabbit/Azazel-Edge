from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml

from azazel_edge.i18n import (
    localize_runbook_steps,
    localize_runbook_title,
    localize_runbook_user_message,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNBOOK_DIRS = [
    Path(os.environ.get("AZAZEL_RUNBOOK_DIR", "/etc/azazel-edge/runbooks")),
    PROJECT_ROOT / "runbooks",
]
PLACEHOLDER_RE = re.compile(r"\$\{([a-zA-Z0-9_]+)\}")
ALLOWED_EXEC_PREFIXES = ("/bin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/opt/azazel-edge/")


def _iter_runbook_files() -> Iterable[Path]:
    seen: set[str] = set()
    for root in RUNBOOK_DIRS:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.yaml")):
            key = str(path.resolve())
            if key in seen:
                continue
            seen.add(key)
            yield path


def _load_yaml(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"runbook_invalid_yaml:{path}")
    data["_path"] = str(path)
    return data


def _validate_runbook_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    required = ("id", "title", "domain", "audience", "risk", "effect", "requires_approval")
    for key in required:
        if key not in doc:
            raise ValueError(f"runbook_missing_key:{key}")
    runbook_id = str(doc.get("id") or "").strip()
    if not runbook_id:
        raise ValueError("runbook_empty_id")
    effect = str(doc.get("effect") or "").strip()
    if effect not in {"read_only", "operator_guidance", "controlled_exec"}:
        raise ValueError("runbook_invalid_effect")
    args_schema = doc.get("args_schema") or {"type": "object", "properties": {}, "required": []}
    if not isinstance(args_schema, dict) or str(args_schema.get("type") or "") != "object":
        raise ValueError("runbook_invalid_args_schema")
    doc["args_schema"] = args_schema
    command = doc.get("command")
    if effect in {"read_only", "controlled_exec"}:
        if not isinstance(command, dict):
            raise ValueError("runbook_invalid_command")
        exec_path = str(command.get("exec") or "").strip()
        argv = command.get("argv")
        if not exec_path or not exec_path.startswith(ALLOWED_EXEC_PREFIXES):
            raise ValueError("runbook_invalid_exec_path")
        if not isinstance(argv, list) or not all(isinstance(x, str) for x in argv):
            raise ValueError("runbook_invalid_argv")
    return doc


def list_runbooks(lang: str | None = None) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for path in _iter_runbook_files():
        try:
            doc = _validate_runbook_doc(_load_yaml(path))
            items.append(
                {
                    "id": doc["id"],
                    "title": localize_runbook_title(doc, lang=lang),
                    "domain": doc["domain"],
                    "audience": doc["audience"],
                    "risk": doc["risk"],
                    "effect": doc["effect"],
                    "requires_approval": bool(doc["requires_approval"]),
                    "steps": localize_runbook_steps(doc, lang=lang),
                    "user_message_template": localize_runbook_user_message(doc, lang=lang),
                    "path": doc["_path"],
                }
            )
        except Exception:
            continue
    return sorted(items, key=lambda x: str(x.get("id") or ""))


def get_runbook(runbook_id: str, lang: str | None = None) -> Dict[str, Any]:
    target = str(runbook_id or "").strip()
    if not target:
        raise KeyError("runbook_id_required")
    for path in _iter_runbook_files():
        try:
            doc = _validate_runbook_doc(_load_yaml(path))
        except Exception:
            continue
        if str(doc.get("id")) == target:
            doc["title"] = localize_runbook_title(doc, lang=lang)
            doc["steps"] = localize_runbook_steps(doc, lang=lang)
            doc["user_message_template"] = localize_runbook_user_message(doc, lang=lang)
            return doc
    raise KeyError(f"runbook_not_found:{target}")


def _coerce_arg_value(spec: Dict[str, Any], value: Any) -> Any:
    kind = str(spec.get("type") or "string")
    if kind == "integer":
        coerced = int(value)
        if "minimum" in spec and coerced < int(spec["minimum"]):
            raise ValueError("arg_below_minimum")
        if "maximum" in spec and coerced > int(spec["maximum"]):
            raise ValueError("arg_above_maximum")
        return coerced
    if kind == "boolean":
        if isinstance(value, bool):
            return value
        text = str(value or "").strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        raise ValueError("arg_invalid_boolean")
    coerced = str(value or "")
    if "maxLength" in spec and len(coerced) > int(spec["maxLength"]):
        raise ValueError("arg_too_long")
    enum = spec.get("enum")
    if isinstance(enum, list) and coerced not in enum:
        raise ValueError("arg_not_in_enum")
    return coerced


def validate_args(runbook: Dict[str, Any], args: Dict[str, Any] | None) -> Dict[str, Any]:
    schema = runbook.get("args_schema") if isinstance(runbook, dict) else {}
    properties = schema.get("properties") if isinstance(schema, dict) else {}
    required = schema.get("required") if isinstance(schema, dict) else []
    src = args if isinstance(args, dict) else {}
    out: Dict[str, Any] = {}
    if isinstance(required, list):
        for key in required:
            if key not in src:
                raise ValueError(f"arg_required:{key}")
    if isinstance(properties, dict):
        for key, spec in properties.items():
            if key not in src:
                continue
            if not isinstance(spec, dict):
                raise ValueError(f"arg_invalid_spec:{key}")
            out[key] = _coerce_arg_value(spec, src[key])
    for key in src.keys():
        if key not in properties:
            raise ValueError(f"arg_unknown:{key}")
    return out


def _substitute(text: str, args: Dict[str, Any]) -> str:
    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in args:
            raise ValueError(f"placeholder_missing:{key}")
        return str(args[key])

    return PLACEHOLDER_RE.sub(repl, text)


def build_command(runbook: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    command = runbook.get("command")
    if not isinstance(command, dict):
        return {"exec": "", "argv": []}
    exec_path = _substitute(str(command.get("exec") or ""), args)
    argv = [_substitute(str(item), args) for item in command.get("argv", [])]
    return {"exec": exec_path, "argv": argv}


def _controlled_exec_enabled() -> bool:
    return os.environ.get("AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC", "0") == "1"


def execute_runbook(
    runbook_id: str,
    args: Dict[str, Any] | None = None,
    dry_run: bool = True,
    approved: bool = False,
    allow_controlled_exec: bool = False,
    lang: str | None = None,
) -> Dict[str, Any]:
    runbook = get_runbook(runbook_id, lang=lang)
    validated_args = validate_args(runbook, args)
    built = build_command(runbook, validated_args)
    result = {
        "ok": True,
        "runbook_id": runbook["id"],
        "title": localize_runbook_title(runbook, lang=lang),
        "effect": runbook["effect"],
        "requires_approval": bool(runbook.get("requires_approval")),
        "args": validated_args,
        "dry_run": bool(dry_run),
        "approved": bool(approved),
        "command": built,
        "steps": localize_runbook_steps(runbook, lang=lang),
        "user_message_template": localize_runbook_user_message(runbook, lang=lang),
    }
    effect = str(runbook.get("effect") or "")
    if dry_run or effect not in {"read_only", "controlled_exec"} or not built["exec"]:
        return result
    if effect == "controlled_exec":
        if not allow_controlled_exec or not _controlled_exec_enabled():
            raise PermissionError("controlled_exec_disabled")
        if not approved:
            raise PermissionError("controlled_exec_approval_required")

    proc = subprocess.run(
        [built["exec"], *built["argv"]],
        capture_output=True,
        text=True,
        timeout=float(os.environ.get("AZAZEL_RUNBOOK_TIMEOUT_SEC", "15")),
        check=False,
    )
    result["exit_code"] = proc.returncode
    result["stdout"] = proc.stdout[-8000:]
    result["stderr"] = proc.stderr[-4000:]
    result["ok"] = proc.returncode == 0
    return result
