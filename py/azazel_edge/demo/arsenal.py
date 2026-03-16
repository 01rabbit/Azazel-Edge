from __future__ import annotations

import copy
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.demo.scenarios import DemoScenarioPack, DemoScenarioRunner
from azazel_edge.demo_overlay import DEMO_OVERLAY_PATH, build_demo_overlay, clear_demo_overlay, write_demo_overlay
from azazel_edge.tactics_engine.scorer import TacticalScorer


ARSENAL_STAGE_ORDER = (
    "arsenal_low_watch",
    "arsenal_throttle",
    "arsenal_decoy_redirect",
)


@dataclass(frozen=True)
class ArsenalBand:
    label: str
    action: str
    control_mode: str
    state_message: str


def _band_for_score(score: int) -> ArsenalBand:
    if score >= 90:
        return ArsenalBand("DECOY REDIRECT", "redirect", "opencanary_redirect", "Selective decoy redirect is active.")
    if score >= 60:
        return ArsenalBand("THROTTLE", "throttle", "traffic_shaping", "Traffic shaping is active with bounded delay / bandwidth control.")
    if score >= 30:
        return ArsenalBand("WATCH", "observe", "none", "Detection is active, but Azazel-Edge remains in monitoring mode.")
    return ArsenalBand("NORMAL", "observe", "none", "No active control is required.")


class ArsenalDemoRunner:
    def __init__(self, root_dir: Path | None = None, overlay_path: Path | None = None):
        self.pack = DemoScenarioPack()
        self.runner = DemoScenarioRunner()
        self.scorer = TacticalScorer()
        self.root_dir = root_dir or Path(__file__).resolve().parents[3]
        self.overlay_path = overlay_path or DEMO_OVERLAY_PATH

    def list_items(self) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        scenarios = self.pack.scenarios()
        for stage_id in ARSENAL_STAGE_ORDER:
            scenario = scenarios.get(stage_id) or {}
            meta = scenario.get("arsenal") if isinstance(scenario.get("arsenal"), dict) else {}
            breakdown = self.scorer.score(meta.get("scorer_features", {}))
            band = _band_for_score(breakdown.score)
            items.append(
                {
                    "stage_id": stage_id,
                    "title": str(meta.get("title") or stage_id),
                    "description": str(scenario.get("description") or ""),
                    "score": int(breakdown.score),
                    "band": band.label,
                    "action": band.action,
                    "control_mode": band.control_mode,
                    "default_hold_sec": int(meta.get("default_hold_sec") or 8),
                }
            )
        return items

    def run_stage(self, stage_id: str, apply_overlay: bool = False, refresh_epd: bool = False) -> Dict[str, Any]:
        normalized = str(stage_id or "").strip()
        if not normalized:
            raise KeyError("unknown_arsenal_stage:")
        scenarios = self.pack.scenarios()
        scenario = scenarios.get(normalized)
        if not isinstance(scenario, dict):
            raise KeyError(f"unknown_arsenal_stage:{normalized}")
        meta = scenario.get("arsenal") if isinstance(scenario.get("arsenal"), dict) else None
        if not isinstance(meta, dict):
            raise KeyError(f"not_arsenal_stage:{normalized}")

        base_result = self.runner.run(normalized)
        result = self._adapt_result(base_result, meta)
        payload: Dict[str, Any] = {"ok": True, "result": result}
        if apply_overlay:
            overlay = build_demo_overlay(result)
            overlay["arsenal_demo"] = copy.deepcopy(result.get("arsenal_demo") or {})
            write_demo_overlay(overlay, self.overlay_path)
            payload["overlay"] = overlay
            payload["overlay_written"] = True
            if refresh_epd:
                payload["epd_refresh"] = self.refresh_epd()
        return payload

    def run_flow(
        self,
        stage_ids: Sequence[str] | None = None,
        hold_sec: int | None = None,
        apply_overlay: bool = True,
        refresh_epd: bool = False,
        keep_final: bool = False,
    ) -> Dict[str, Any]:
        selected = list(stage_ids or ARSENAL_STAGE_ORDER)
        steps: List[Dict[str, Any]] = []
        for index, stage_id in enumerate(selected):
            payload = self.run_stage(stage_id, apply_overlay=apply_overlay, refresh_epd=refresh_epd)
            result = payload["result"]
            arsenal = result.get("arsenal_demo") if isinstance(result.get("arsenal_demo"), dict) else {}
            stage_hold = int(hold_sec if hold_sec is not None else arsenal.get("default_hold_sec") or 8)
            steps.append(
                {
                    "index": index + 1,
                    "stage_id": stage_id,
                    "band": arsenal.get("band"),
                    "score": arsenal.get("score"),
                    "action": result.get("arbiter", {}).get("action"),
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
            "mode": "arsenal_flow",
            "stages": steps,
            "keep_final": bool(keep_final),
            "overlay_cleared": cleared,
            "epd_refresh": epd_refresh,
        }

    def clear(self, refresh_epd: bool = False) -> Dict[str, Any]:
        clear_demo_overlay(self.overlay_path)
        payload: Dict[str, Any] = {"ok": True, "cleared": True}
        if refresh_epd:
            payload["epd_refresh"] = self.refresh_epd()
        return payload

    def refresh_epd(self) -> Dict[str, Any]:
        script = self.root_dir / "py" / "azazel_edge_epd_mode_refresh.py"
        if not script.exists():
            return {"ok": False, "error": "epd_refresh_script_missing"}
        completed = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(self.root_dir),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "exit_code": int(completed.returncode),
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
        }

    def _adapt_result(self, base_result: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
        result = copy.deepcopy(base_result)
        breakdown = self.scorer.score(meta.get("scorer_features", {}))
        band = _band_for_score(breakdown.score)
        proofs = copy.deepcopy(meta.get("proofs") or {}) if isinstance(meta.get("proofs"), dict) else {}

        native_arbiter = result.get("arbiter") if isinstance(result.get("arbiter"), dict) else {}
        native_action = str(native_arbiter.get("action") or "observe")
        native_reason = str(native_arbiter.get("reason") or "baseline")

        result.setdefault("execution", {})
        if isinstance(result["execution"], dict):
            result["execution"]["arsenal_compatibility"] = True
            result["execution"]["offline_demo"] = True

        result["arsenal_demo"] = {
            "title": str(meta.get("title") or result.get("scenario_id") or "arsenal-demo"),
            "attack_label": str(meta.get("attack_label") or ""),
            "score": int(breakdown.score),
            "score_factors": list(breakdown.factors),
            "band": band.label,
            "state_message": band.state_message,
            "native_action": native_action,
            "native_reason": native_reason,
            "default_hold_sec": int(meta.get("default_hold_sec") or 8),
            "talk_track": str(meta.get("talk_track") or ""),
            "decision_path": copy.deepcopy(meta.get("decision_path") or {}) if isinstance(meta.get("decision_path"), dict) else {},
            "proofs": proofs,
        }

        action_profile = ActionArbiter.action_profile(band.action)
        result["arbiter"] = {
            "action": band.action,
            "reason": f"arsenal_score_band:{band.label.lower().replace(' ', '_')}",
            "control_mode": band.control_mode,
            "chosen_evidence_ids": list(native_arbiter.get("chosen_evidence_ids") or result.get("evidence_ids") or []),
            "rejected_alternatives": list(native_arbiter.get("rejected_alternatives") or []),
            "client_impact": dict(native_arbiter.get("client_impact") or {}),
            "action_profile": action_profile,
            "decision_trace": {
                "selected_action": band.action,
                "selected_reason": f"arsenal_score_band:{band.label.lower().replace(' ', '_')}",
                "arsenal_score": int(breakdown.score),
                "arsenal_band": band.label,
                "native_action": native_action,
                "native_reason": native_reason,
                "score_factors": list(breakdown.factors),
                "compatibility_mode": "arsenal_demo",
            },
        }

        explanation = result.get("explanation") if isinstance(result.get("explanation"), dict) else {}
        explanation = dict(explanation)
        explanation["operator_wording"] = str(meta.get("talk_track") or explanation.get("operator_wording") or "")
        next_checks = list(explanation.get("next_checks") or [])
        if not next_checks:
            next_checks = [
                "Confirm the Suricata alert fired.",
                f"Verify the score band is {band.label}.",
                f"Verify the active control is {band.action}.",
            ]
        explanation["next_checks"] = next_checks
        result["explanation"] = explanation
        return result


__all__ = ["ARSENAL_STAGE_ORDER", "ArsenalDemoRunner"]
