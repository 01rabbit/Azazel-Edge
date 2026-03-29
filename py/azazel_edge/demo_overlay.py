from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict

DEMO_OVERLAY_PATH = Path(os.environ.get("AZAZEL_DEMO_OVERLAY", "/run/azazel-edge/demo_overlay.json"))
DEMO_OVERLAY_MAX_AGE_SEC = int(os.environ.get("AZAZEL_DEMO_OVERLAY_MAX_AGE_SEC", "120"))
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_demo_overlay(path: Path | None = None) -> Dict[str, Any]:
    target = path or DEMO_OVERLAY_PATH
    try:
        if not target.exists():
            return {}
        payload = json.loads(target.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return {}
        if _is_overlay_invalid(payload):
            clear_demo_overlay(target)
            return {}
        return payload
    except Exception:
        return {}


def write_demo_overlay(payload: Dict[str, Any], path: Path | None = None) -> Path:
    target = path or DEMO_OVERLAY_PATH
    _ensure_parent(target)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, target)
    return target


def clear_demo_overlay(path: Path | None = None) -> None:
    target = path or DEMO_OVERLAY_PATH
    try:
        if target.exists():
            target.unlink()
    except Exception:
        pass


def is_demo_overlay_active(payload: Dict[str, Any] | None = None) -> bool:
    data = payload if isinstance(payload, dict) else read_demo_overlay()
    return bool(data.get("active"))


def _is_overlay_stale(payload: Dict[str, Any]) -> bool:
    ts = payload.get("ts")
    try:
        age = time.time() - float(ts)
    except Exception:
        return False
    return age > DEMO_OVERLAY_MAX_AGE_SEC


def _current_boot_id() -> str:
    try:
        return BOOT_ID_PATH.read_text(encoding="utf-8").strip()
    except Exception:
        return ""


def _is_overlay_invalid(payload: Dict[str, Any]) -> bool:
    if _is_overlay_stale(payload):
        return True
    boot_id = str(payload.get("boot_id") or "").strip()
    current_boot_id = _current_boot_id()
    if not boot_id or not current_boot_id:
        return True
    return boot_id != current_boot_id


def build_demo_overlay(result: Dict[str, Any]) -> Dict[str, Any]:
    explanation = result.get("explanation") if isinstance(result.get("explanation"), dict) else {}
    arbiter = result.get("arbiter") if isinstance(result.get("arbiter"), dict) else {}
    noc = result.get("noc") if isinstance(result.get("noc"), dict) else {}
    soc = result.get("soc") if isinstance(result.get("soc"), dict) else {}
    execution = result.get("execution") if isinstance(result.get("execution"), dict) else {}
    capability_boundary = result.get("capability_boundary") if isinstance(result.get("capability_boundary"), dict) else {}
    demo = result.get("demo") if isinstance(result.get("demo"), dict) else {}
    presentation = result.get("presentation") if isinstance(result.get("presentation"), dict) else {}
    return {
        "active": True,
        "ts": time.time(),
        "boot_id": _current_boot_id(),
        "scenario_id": str(result.get("scenario_id") or "demo"),
        "description": str(result.get("description") or ""),
        "title": str(presentation.get("title") or demo.get("title") or result.get("scenario_id") or "demo"),
        "summary": str(presentation.get("summary") or demo.get("summary") or result.get("description") or ""),
        "attack_label": str(demo.get("attack_label") or presentation.get("attack_label") or ""),
        "event_count": int(result.get("event_count") or 0),
        "execution": execution,
        "capability_boundary": capability_boundary,
        "presentation": presentation,
        "demo": demo,
        "action": str(arbiter.get("action") or "observe"),
        "reason": str(arbiter.get("reason") or "demo_overlay"),
        "control_mode": str(arbiter.get("control_mode") or "none"),
        "action_profile": arbiter.get("action_profile") if isinstance(arbiter.get("action_profile"), dict) else {},
        "decision_trace": arbiter.get("decision_trace") if isinstance(arbiter.get("decision_trace"), dict) else {},
        "chosen_evidence_ids": list(explanation.get("evidence_ids") or arbiter.get("chosen_evidence_ids") or []),
        "rejected_alternatives": list(explanation.get("why_not_others") or arbiter.get("rejected_alternatives") or []),
        "next_checks": list(explanation.get("next_checks") or []),
        "operator_wording": str(explanation.get("operator_wording") or ""),
        "noc_status": str((noc.get("summary") or {}).get("status") or "unknown"),
        "noc_reasons": list((noc.get("summary") or {}).get("reasons") or []),
        "soc_status": str((soc.get("summary") or {}).get("status") or "unknown"),
        "soc_reasons": list((soc.get("summary") or {}).get("reasons") or []),
        "soc_suspicion": int((soc.get("suspicion") or {}).get("score") or 0),
        "soc_confidence": int((soc.get("confidence") or {}).get("score") or 0),
        "attack_candidates": list((soc.get("summary") or {}).get("attack_candidates") or []),
        "machine": explanation.get("machine") if isinstance(explanation.get("machine"), dict) else {},
        "raw_result": result,
    }


def purge_demo_artifacts(path: Path | None = None) -> None:
    clear_demo_overlay(path)
