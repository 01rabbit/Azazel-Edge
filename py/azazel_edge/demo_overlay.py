from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict

DEMO_OVERLAY_PATH = Path(os.environ.get("AZAZEL_DEMO_OVERLAY", "/run/azazel-edge/demo_overlay.json"))


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_demo_overlay(path: Path | None = None) -> Dict[str, Any]:
    target = path or DEMO_OVERLAY_PATH
    try:
        if not target.exists():
            return {}
        payload = json.loads(target.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
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


def build_demo_overlay(result: Dict[str, Any]) -> Dict[str, Any]:
    explanation = result.get("explanation") if isinstance(result.get("explanation"), dict) else {}
    arbiter = result.get("arbiter") if isinstance(result.get("arbiter"), dict) else {}
    noc = result.get("noc") if isinstance(result.get("noc"), dict) else {}
    soc = result.get("soc") if isinstance(result.get("soc"), dict) else {}
    return {
        "active": True,
        "ts": time.time(),
        "scenario_id": str(result.get("scenario_id") or "demo"),
        "description": str(result.get("description") or ""),
        "event_count": int(result.get("event_count") or 0),
        "action": str(arbiter.get("action") or "observe"),
        "reason": str(arbiter.get("reason") or "demo_overlay"),
        "control_mode": str(arbiter.get("control_mode") or "none"),
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
