from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Sequence
from urllib.request import Request, urlopen

from azazel_edge.arbiter import ActionArbiter
from azazel_edge.demo.scenarios import DemoScenarioPack, DemoScenarioRunner
from azazel_edge.demo_overlay import DEMO_OVERLAY_PATH, build_demo_overlay, clear_demo_overlay, write_demo_overlay
from azazel_edge.tactics_engine.scorer import TacticalScorer


ARSENAL_STAGE_ORDER = (
    "arsenal_low_watch",
    "arsenal_throttle",
    "arsenal_ollama_review",
    "arsenal_decoy_redirect",
)

ARSENAL_EXHIBITION_FLOW = (
    "arsenal_low_watch",
    "arsenal_ollama_review",
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
    def __init__(
        self,
        root_dir: Path | None = None,
        overlay_path: Path | None = None,
        mattermost_sender: Callable[[Dict[str, Any]], Dict[str, Any]] | None = None,
    ):
        self.pack = DemoScenarioPack()
        self.runner = DemoScenarioRunner()
        self.scorer = TacticalScorer()
        self.root_dir = root_dir or Path(__file__).resolve().parents[3]
        self.overlay_path = overlay_path or DEMO_OVERLAY_PATH
        self.mattermost_sender = mattermost_sender or self._send_mattermost_notification

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

    def run_stage(
        self,
        stage_id: str,
        apply_overlay: bool = False,
        refresh_epd: bool = False,
        notify_mattermost: bool = False,
    ) -> Dict[str, Any]:
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
        if notify_mattermost:
            payload["mattermost"] = self.mattermost_sender(result)
        return payload

    def run_flow(
        self,
        stage_ids: Sequence[str] | None = None,
        hold_sec: int | None = None,
        apply_overlay: bool = True,
        refresh_epd: bool = False,
        keep_final: bool = False,
        notify_mattermost: bool = False,
    ) -> Dict[str, Any]:
        selected = list(stage_ids or ARSENAL_EXHIBITION_FLOW)
        steps: List[Dict[str, Any]] = []
        notifications: List[Dict[str, Any]] = []
        for index, stage_id in enumerate(selected):
            payload = self.run_stage(
                stage_id,
                apply_overlay=apply_overlay,
                refresh_epd=refresh_epd,
                notify_mattermost=notify_mattermost,
            )
            result = payload["result"]
            arsenal = result.get("arsenal_demo") if isinstance(result.get("arsenal_demo"), dict) else {}
            stage_hold = int(hold_sec if hold_sec is not None else arsenal.get("default_hold_sec") or 8)
            if notify_mattermost:
                notifications.append(
                    {
                        "stage_id": stage_id,
                        **(payload.get("mattermost") if isinstance(payload.get("mattermost"), dict) else {}),
                    }
                )
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
            "mattermost_notifications": notifications,
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
            return {
                "ok": False,
                "error": f"epd_refresh_failed:{exc}",
                "timeout_sec": timeout_sec,
            }
        return {
            "ok": completed.returncode == 0,
            "exit_code": int(completed.returncode),
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "timeout_sec": timeout_sec,
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

    def _send_mattermost_notification(self, result: Dict[str, Any]) -> Dict[str, Any]:
        arsenal = result.get("arsenal_demo") if isinstance(result.get("arsenal_demo"), dict) else {}
        arbiter = result.get("arbiter") if isinstance(result.get("arbiter"), dict) else {}
        band = str(arsenal.get("band") or "").strip().upper()
        attack_label = str(arsenal.get("attack_label") or result.get("scenario_id") or "Unknown attack").strip()
        score = int(arsenal.get("score") or 0)
        action = str(arbiter.get("action") or "observe").strip() or "observe"
        control_mode = str(arbiter.get("control_mode") or "none").strip() or "none"
        decision_path = arsenal.get("decision_path") if isinstance(arsenal.get("decision_path"), dict) else {}
        ollama = decision_path.get("ollama_review") if isinstance(decision_path.get("ollama_review"), dict) else {}
        ollama_status = str(ollama.get("status") or "unknown").strip() or "unknown"
        severity = "WARNING" if band == "WATCH" else "DANGER"
        open_url = self._arsenal_demo_url()
        message = (
            f"[{severity}] Azazel-Pi detected {attack_label}\n"
            f"score={score} band={band} action={action} control={control_mode}\n"
            f"ollama_review={ollama_status}\n"
            f"webui={open_url}"
        )

        if self._mattermost_bot_token() and self._mattermost_channel_id():
            payload = {"channel_id": self._mattermost_channel_id(), "message": message}
            return self._mattermost_api_post("/api/v4/posts", payload)
        webhook_url = self._mattermost_webhook_url()
        if webhook_url:
            request = Request(
                webhook_url,
                data=json.dumps({"text": message, "username": "Azazel-Pi"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urlopen(request, timeout=self._mattermost_timeout_sec()):
                    pass
                return {"ok": True, "mode": "webhook"}
            except Exception as exc:
                return {"ok": False, "mode": "webhook", "error": f"mattermost_webhook_error:{exc}"}
        return {"ok": False, "mode": "disabled", "error": "mattermost_not_configured"}

    def _mattermost_api_post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        request = Request(
            f"{self._mattermost_base_url()}{path}",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._mattermost_bot_token()}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._mattermost_timeout_sec()) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
            return {"ok": True, "mode": "bot_api", "post_id": str((parsed or {}).get("id") or "")}
        except Exception as exc:
            return {"ok": False, "mode": "bot_api", "error": f"mattermost_api_error:{exc}"}

    def _mattermost_base_url(self) -> str:
        host = str(
            os.environ.get("AZAZEL_MATTERMOST_ALERT_HOST")
            or os.environ.get("AZAZEL_MATTERMOST_HOST")
            or "172.16.0.254"
        ).strip() or "172.16.0.254"
        port = int(os.environ.get("AZAZEL_MATTERMOST_ALERT_PORT") or os.environ.get("AZAZEL_MATTERMOST_PORT") or "8065")
        default = f"http://{host}:{port}"
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_BASE_URL") or os.environ.get("AZAZEL_MATTERMOST_BASE_URL") or default).rstrip("/")

    def _mattermost_team(self) -> str:
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_TEAM") or os.environ.get("AZAZEL_MATTERMOST_TEAM") or "azazelops").strip() or "azazelops"

    def _mattermost_channel(self) -> str:
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_CHANNEL") or os.environ.get("AZAZEL_MATTERMOST_CHANNEL") or "soc-noc").strip() or "soc-noc"

    def _mattermost_open_url(self) -> str:
        default = f"{self._mattermost_base_url()}/{self._mattermost_team()}/channels/{self._mattermost_channel()}"
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_OPEN_URL") or os.environ.get("AZAZEL_MATTERMOST_OPEN_URL") or default).strip() or default

    def _arsenal_demo_url(self) -> str:
        explicit = str(os.environ.get("AZAZEL_ARSENAL_DEMO_URL", "")).strip()
        if explicit:
            return explicit
        web_host = str(os.environ.get("AZAZEL_WEB_PUBLIC_HOST", "172.16.0.254")).strip() or "172.16.0.254"
        web_scheme = str(os.environ.get("AZAZEL_WEB_PUBLIC_SCHEME", "https")).strip() or "https"
        return f"{web_scheme}://{web_host}/arsenal-demo"

    def _mattermost_webhook_url(self) -> str:
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_WEBHOOK_URL") or os.environ.get("AZAZEL_MATTERMOST_WEBHOOK_URL") or "").strip()

    def _mattermost_bot_token(self) -> str:
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_BOT_TOKEN") or os.environ.get("AZAZEL_MATTERMOST_BOT_TOKEN") or "").strip()

    def _mattermost_channel_id(self) -> str:
        return str(os.environ.get("AZAZEL_MATTERMOST_ALERT_CHANNEL_ID") or os.environ.get("AZAZEL_MATTERMOST_CHANNEL_ID") or "").strip()

    def _mattermost_timeout_sec(self) -> float:
        return float(os.environ.get("AZAZEL_MATTERMOST_ALERT_TIMEOUT_SEC") or os.environ.get("AZAZEL_MATTERMOST_TIMEOUT_SEC") or "8")


__all__ = ["ARSENAL_STAGE_ORDER", "ARSENAL_EXHIBITION_FLOW", "ArsenalDemoRunner"]
