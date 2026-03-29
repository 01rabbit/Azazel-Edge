from __future__ import annotations

import copy
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

from azazel_edge.demo_overlay import DEMO_OVERLAY_PATH, build_demo_overlay, clear_demo_overlay, write_demo_overlay

from .scenarios import DemoScenarioPack, DemoScenarioRunner


class DemoPlaybackRunner:
    def __init__(self, root_dir: Path | None = None, overlay_path: Path | None = None):
        self.pack = DemoScenarioPack()
        self.runner = DemoScenarioRunner()
        self.root_dir = root_dir or Path(__file__).resolve().parents[3]
        self.overlay_path = overlay_path or DEMO_OVERLAY_PATH

    def list_items(self) -> List[Dict[str, Any]]:
        return self.pack.list_items()

    def stage_order(self) -> List[str]:
        return self.pack.stage_order()

    def run_scenario(
        self,
        scenario_id: str,
        *,
        apply_overlay: bool = False,
        refresh_epd: bool = False,
    ) -> Dict[str, Any]:
        result = self.runner.run(str(scenario_id))
        payload: Dict[str, Any] = {"ok": True, "result": result}
        if apply_overlay:
            overlay = build_demo_overlay(result)
            write_demo_overlay(overlay, self.overlay_path)
            payload["overlay"] = overlay
            payload["overlay_written"] = True
            if refresh_epd:
                payload["epd_refresh"] = self.refresh_epd()
        return payload

    def run_flow(
        self,
        *,
        scenario_ids: Sequence[str] | None = None,
        hold_sec: int | None = None,
        apply_overlay: bool = True,
        refresh_epd: bool = False,
        keep_final: bool = False,
    ) -> Dict[str, Any]:
        selected = list(scenario_ids or self.stage_order())
        steps: List[Dict[str, Any]] = []
        for index, scenario_id in enumerate(selected):
            payload = self.run_scenario(
                scenario_id,
                apply_overlay=apply_overlay,
                refresh_epd=refresh_epd,
            )
            result = payload["result"]
            demo = result.get("demo") if isinstance(result.get("demo"), dict) else {}
            stage_hold = int(hold_sec if hold_sec is not None else demo.get("default_hold_sec") or 8)
            presentation = result.get("presentation") if isinstance(result.get("presentation"), dict) else {}
            steps.append(
                {
                    "index": index + 1,
                    "scenario_id": str(result.get("scenario_id") or scenario_id),
                    "title": str(presentation.get("title") or demo.get("title") or scenario_id),
                    "attack_label": str(demo.get("attack_label") or presentation.get("attack_label") or ""),
                    "action": str((result.get("arbiter") or {}).get("action") or ""),
                    "control_mode": str((result.get("arbiter") or {}).get("control_mode") or ""),
                    "hold_sec": stage_hold,
                    "overlay_written": bool(payload.get("overlay_written")),
                }
            )
            if stage_hold > 0 and index < len(selected) - 1:
                time.sleep(stage_hold)

        cleared = False
        epd_refresh = None
        if apply_overlay and not keep_final:
            clear_demo_overlay(self.overlay_path)
            cleared = True
            if refresh_epd:
                epd_refresh = self.refresh_epd()

        return {
            "ok": True,
            "mode": "demo_flow",
            "scenarios": steps,
            "keep_final": bool(keep_final),
            "overlay_cleared": cleared,
            "epd_refresh": epd_refresh,
        }

    def clear(self, *, refresh_epd: bool = False) -> Dict[str, Any]:
        clear_demo_overlay(self.overlay_path)
        payload: Dict[str, Any] = {"ok": True, "cleared": True}
        if refresh_epd:
            payload["epd_refresh"] = self.refresh_epd()
        return payload

    def refresh_epd(self) -> Dict[str, Any]:
        script = self.root_dir / "py" / "azazel_edge_epd_mode_refresh.py"
        if not script.exists():
            return {"ok": False, "error": "epd_refresh_script_missing"}
        timeout_sec = float(os.environ.get("AZAZEL_EPD_REFRESH_TIMEOUT_SEC", "15") or "15")
        try:
            completed = subprocess.run(
                [sys.executable, str(script)],
                cwd=str(self.root_dir),
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "ok": False,
                "error": "epd_refresh_timeout",
                "timeout_sec": timeout_sec,
                "stdout": (exc.output or "").strip() if isinstance(exc.output, str) else "",
                "stderr": (exc.stderr or "").strip() if isinstance(exc.stderr, str) else "",
            }
        except Exception as exc:
            return {"ok": False, "error": f"epd_refresh_failed:{exc}", "timeout_sec": timeout_sec}
        return {
            "ok": completed.returncode == 0,
            "exit_code": int(completed.returncode),
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "timeout_sec": timeout_sec,
        }


def scenario_summary(payload: Dict[str, Any]) -> Dict[str, Any]:
    result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
    demo = result.get("demo") if isinstance(result.get("demo"), dict) else {}
    presentation = result.get("presentation") if isinstance(result.get("presentation"), dict) else {}
    arbiter = result.get("arbiter") if isinstance(result.get("arbiter"), dict) else {}
    return {
        "ok": bool(payload.get("ok")),
        "scenario_id": str(result.get("scenario_id") or ""),
        "title": str(presentation.get("title") or demo.get("title") or result.get("scenario_id") or ""),
        "summary": str(presentation.get("summary") or demo.get("summary") or result.get("description") or ""),
        "attack_label": str(demo.get("attack_label") or presentation.get("attack_label") or ""),
        "action": str(arbiter.get("action") or ""),
        "control_mode": str(arbiter.get("control_mode") or ""),
        "operator_wording": str(result.get("explanation", {}).get("operator_wording") or ""),
        "talk_track": str(demo.get("talk_track") or ""),
        "decision_path": copy.deepcopy(demo.get("decision_path") or {}) if isinstance(demo.get("decision_path"), dict) else {},
        "proofs": copy.deepcopy(demo.get("proofs") or {}) if isinstance(demo.get("proofs"), dict) else {},
        "next_checks": list(result.get("explanation", {}).get("next_checks") or []),
        "overlay_written": bool(payload.get("overlay_written") or payload.get("overlay")),
        "epd_refresh": payload.get("epd_refresh"),
    }


__all__ = ["DemoPlaybackRunner", "scenario_summary"]
