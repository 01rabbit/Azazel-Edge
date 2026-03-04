#!/usr/bin/env python3
"""
Textual implementation for Azazel-Edge unified TUI.

This app is intentionally thin and reuses existing backend callbacks from
cli_unified.py for snapshot loading, command dispatch, and optional EPD updates.
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Footer, Header, Static


SnapshotLoader = Callable[[], Any]
ActionSender = Callable[[str], Dict[str, Any]]
EpdUpdater = Callable[[Any, bool], None]
EpdFingerprint = Callable[[Any], Tuple[str, str, str, Optional[int], str]]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PY_ROOT = PROJECT_ROOT / "py"


def _maybe_sudo(cmd: list[str]) -> list[str]:
    return cmd if os.geteuid() == 0 else ["sudo"] + cmd


class AzazelTextualApp(App):
    """Manual-refresh monitor app with key bindings compatible with curses UI."""

    TITLE = "Azazel-Edge Textual Monitor"
    SUB_TITLE = "Manual refresh mode"

    CSS = """
    Screen {
        layout: vertical;
        background: #080a0f;
        color: #eeeeee;
    }

    Header {
        background: #0f131a;
        color: #00d4ff;
        text-style: bold;
    }

    HeaderClock {
        color: #00d4ff;
        text-style: bold;
    }

    Footer {
        background: #0f131a;
        color: #aaaaaa;
        height: 1;
    }

    FooterKey {
        background: #0f131a;
    }

    FooterKey .footer-key--key {
        background: #00d4ff;
        color: #05080e;
        text-style: bold;
    }

    FooterKey .footer-key--description {
        background: #0f131a;
        color: #eeeeee;
    }

    FooterKey:hover {
        background: #22375f;
    }

    FooterKey:hover .footer-key--key {
        background: #2ecc71;
        color: #05080e;
    }

    FooterKey:hover .footer-key--description {
        color: #ffffff;
    }

    #status-line {
        height: 1;
        color: #05080e;
        background: #00d4ff;
        text-style: bold;
        content-align: left middle;
        padding: 0 1;
    }

    #status-line.state-checking {
        background: #00d4ff;
        color: #05080e;
    }

    #status-line.state-safe {
        background: #2ecc71;
        color: #05080e;
    }

    #status-line.state-limited {
        background: #f39c12;
        color: #05080e;
    }

    #status-line.state-contained {
        background: #e74c3c;
        color: #ffffff;
    }

    #status-line.state-deception {
        background: #e74c3c;
        color: #ffffff;
    }

    #summary {
        height: 8;
        border: round #00d4ff;
        background: #0f131a;
        padding: 0 1;
    }

    #summary.state-checking {
        border: round #00d4ff;
    }

    #summary.state-safe {
        border: round #2ecc71;
    }

    #summary.state-limited {
        border: round #f39c12;
    }

    #summary.state-contained {
        border: round #e74c3c;
    }

    #summary.state-deception {
        border: round #e74c3c;
    }

    #middle {
        height: 12;
    }

    #connection {
        width: 1fr;
        border: round #00d4ff;
        background: #0f131a;
        padding: 0 1;
    }

    #control {
        width: 1fr;
        border: round #00d4ff;
        background: #0f131a;
        padding: 0 1;
    }

    #evidence {
        height: 1fr;
        border: round #f39c12;
        background: #0f131a;
        padding: 0 1;
    }

    #flow {
        height: 1;
        background: #0f131a;
        color: #aaaaaa;
        content-align: left middle;
        padding: 0 1;
    }

    #details {
        height: 8;
        border: round #00d4ff;
        background: #0f131a;
        padding: 0 1;
        display: none;
    }

    #menu {
        height: 1fr;
        border: round #00d4ff;
        background: #0f131a;
        padding: 0 1;
        display: none;
    }
    """

    _STATE_CLASSES = (
        "state-checking",
        "state-safe",
        "state-limited",
        "state-contained",
        "state-deception",
    )

    BINDINGS = [
        Binding("u", "refresh", "Refresh"),
        Binding("a", "stage_open", "Stage-Open"),
        Binding("r", "reprobe", "Re-Probe"),
        Binding("c", "contain", "Contain"),
        Binding("l", "details", "Details"),
        Binding("m", "toggle_menu", "Menu"),
        Binding("up", "menu_up", "Menu Up", show=False),
        Binding("down", "menu_down", "Menu Down", show=False),
        Binding("j", "menu_down", "Menu Down", show=False),
        Binding("k", "menu_up", "Menu Up", show=False),
        Binding("enter", "menu_select", "Select", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(
        self,
        load_snapshot_fn: SnapshotLoader,
        send_command_fn: ActionSender,
        update_epd_fn: EpdUpdater,
        epd_fingerprint_fn: EpdFingerprint,
        unicode_mode: bool,
        enable_epd: bool,
        start_menu: bool = False,
    ) -> None:
        super().__init__()
        self._load_snapshot_fn = load_snapshot_fn
        self._send_command_fn = send_command_fn
        self._update_epd_fn = update_epd_fn
        self._epd_fingerprint_fn = epd_fingerprint_fn
        self._unicode_mode = unicode_mode
        self._enable_epd = enable_epd

        self._snapshot: Any = None
        self._is_loading = False
        self._details_open = False
        self._menu_open = start_menu
        self._menu_idx = 0
        self._menu_items = self._build_menu_items()
        self._last_epd_fp: Optional[Tuple[str, str, str, Optional[int], str]] = None
        self._status_message = "Ready"
        self._confirm_action: Optional[str] = None
        self._confirm_deadline: float = 0.0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Status: booting...", id="status-line", markup=False)
        yield Static("Loading snapshot...", id="summary", markup=False)
        with Horizontal(id="middle"):
            yield Static("Loading connection...", id="connection", markup=False)
            yield Static("Loading control...", id="control", markup=False)
        yield Static("Loading evidence...", id="evidence", markup=False)
        yield Static("Flow: PROBE -> DEGRADED -> NORMAL -> SAFE", id="flow", markup=False)
        yield Static("Control menu loading...", id="menu", markup=False)
        yield Static("Details hidden. Press [L] to toggle.", id="details", markup=False)
        yield Footer()

    async def on_mount(self) -> None:
        self.set_interval(1.0, self._tick_age_only)
        self._apply_menu_visibility()
        await self._refresh_snapshot(initial=True)

    def _build_menu_items(self) -> list[dict[str, object]]:
        ssid_cmd = _maybe_sudo(
            [sys.executable, str(PY_ROOT / "ssid_list.py"), "--textual", "wlan0"]
        )
        return [
            {"label": "Refresh Snapshot", "kind": "refresh"},
            {"label": "Mode: Portal", "kind": "send_action", "action": "mode_portal"},
            {"label": "Mode: Shield", "kind": "send_action", "action": "mode_shield"},
            {"label": "Mode: Scapegoat", "kind": "send_action", "action": "mode_scapegoat"},
            {"label": "Stage-Open", "kind": "send_action", "action": "stage_open"},
            {"label": "Re-Probe", "kind": "send_action", "action": "reprobe"},
            {"label": "Contain", "kind": "send_action", "action": "contain"},
            {"label": "Shutdown System", "kind": "send_action", "action": "shutdown"},
            {"label": "Reboot System", "kind": "send_action", "action": "reboot"},
            {"label": "Wi-Fi Selector (Textual)", "kind": "interactive_cmd", "cmd": ssid_cmd},
            {"label": "OpenCanary: start", "kind": "run_cmd", "cmd": _maybe_sudo(["systemctl", "start", "opencanary.service"])},
            {"label": "OpenCanary: stop", "kind": "run_cmd", "cmd": _maybe_sudo(["systemctl", "stop", "opencanary.service"])},
            {"label": "OpenCanary: hits (latest)", "kind": "interactive_cmd", "cmd": _maybe_sudo(["journalctl", "-u", "opencanary.service", "-n", "50", "--no-pager"])},
            {"label": "Toggle Details", "kind": "toggle_details"},
            {"label": "Close Menu", "kind": "close_menu"},
        ]

    def _menu_text(self) -> str:
        lines = ["Control Menu [Enter=Run, M=Close]", ""]
        for i, item in enumerate(self._menu_items):
            marker = ">" if i == self._menu_idx else " "
            lines.append(f"{marker} {item['label']}")
        return "\n".join(lines)

    def _apply_menu_visibility(self) -> None:
        summary = self.query_one("#summary", Static)
        middle = self.query_one("#middle", Horizontal)
        flow = self.query_one("#flow", Static)
        menu = self.query_one("#menu", Static)
        evidence = self.query_one("#evidence", Static)
        if self._menu_open:
            summary.styles.height = 6
            middle.styles.height = 8
            flow.styles.display = "none"
            evidence.styles.display = "none"
            menu.styles.display = "block"
        else:
            summary.styles.height = 8
            middle.styles.height = 12
            flow.styles.display = "block"
            evidence.styles.display = "block"
            menu.styles.display = "none"
        if self._menu_open:
            menu.update(Text(self._menu_text()))

    def _tick_age_only(self) -> None:
        if self._snapshot is not None:
            self._render_status_line()

    def _safe_get(self, obj: Any, name: str, default: Any) -> Any:
        try:
            return getattr(obj, name, default)
        except Exception:
            return default

    def _live_age(self) -> str:
        ts = self._safe_get(self._snapshot, "snapshot_epoch", 0.0) or 0.0
        if not ts:
            return "00:00:00"
        delta = max(0, int(time.time() - float(ts)))
        return time.strftime("%H:%M:%S", time.gmtime(delta))

    def _render_status_line(self) -> None:
        if self._snapshot is None:
            self.query_one("#status-line", Static).update(Text(f"Status: {self._status_message}"))
            return

        status_widget = self.query_one("#status-line", Static)
        ssid = self._safe_get(self._snapshot, "ssid", "-")
        state = self._safe_get(self._snapshot, "user_state", "CHECKING")
        self._apply_state_class(status_widget, state)
        source = self._safe_get(self._snapshot, "source", "SNAPSHOT")
        risk = self._safe_get(self._snapshot, "risk_score", 0)
        mode_info = self._safe_get(self._snapshot, "mode", {}) or {}
        mode_name = str(mode_info.get("current_mode", "shield")).upper()
        line = (
            f"State={state}  SSID={ssid}  Risk={risk}/100  "
            f"Mode={mode_name}  Age={self._live_age()}  View={source}  Status={self._status_message}"
        )
        status_widget.update(Text(line))

    def _state_label(self, state: str) -> str:
        labels = {
            "CHECKING": "CHECKING",
            "SAFE": "SAFE",
            "LIMITED": "LIMITED",
            "CONTAINED": "CONTAINED",
            "DECEPTION": "DECEPTION",
        }
        return labels.get(str(state).upper(), "CHECKING")

    def _state_icon(self, state: str) -> str:
        state = str(state).upper()
        if not self._unicode_mode:
            return {"SAFE": "OK", "LIMITED": "!", "CONTAINED": "X", "DECEPTION": "D"}.get(state, "~")
        return {
            "SAFE": "✅",
            "LIMITED": "⚠️",
            "CONTAINED": "⛔",
            "DECEPTION": "👁",
        }.get(state, "⟳")

    def _threat_bar(self, level: int) -> str:
        level = max(0, min(int(level), 5))
        if self._unicode_mode:
            return "".join("🔴" if i < level else "⚪" for i in range(5))
        return "".join("X" if i < level else "." for i in range(5))

    def _state_css_class(self, state: str) -> str:
        state_name = str(state).upper()
        if state_name == "SAFE":
            return "state-safe"
        if state_name == "LIMITED":
            return "state-limited"
        if state_name in ("CONTAINED", "LOCKDOWN"):
            return "state-contained"
        if state_name == "DECEPTION":
            return "state-deception"
        return "state-checking"

    def _apply_state_class(self, widget: Static, state: str) -> None:
        for css_class in self._STATE_CLASSES:
            widget.remove_class(css_class)
        widget.add_class(self._state_css_class(state))

    def _severity_prefix(self, line: str) -> str:
        lowered = line.lower()
        if any(x in lowered for x in ("blocked", "error", "fail", "contain", "anomaly", "hijack")):
            return "🔴" if self._unicode_mode else "X"
        if any(x in lowered for x in ("warning", "suspect", "portal", "dns", "degrade", "limited")):
            return "🟡" if self._unicode_mode else "!"
        if any(x in lowered for x in ("ok", "safe", "normal", "success")):
            return "🟢" if self._unicode_mode else "O"
        return "•"

    def _render_panels(self) -> None:
        if self._snapshot is None:
            return

        snap = self._snapshot
        connection = self._safe_get(snap, "connection", {}) or {}
        monitoring = self._safe_get(snap, "monitoring", {}) or {}
        mode_info = self._safe_get(snap, "mode", {}) or {}
        attack = self._safe_get(snap, "attack", {}) or {}
        degrade = self._safe_get(snap, "degrade", {}) or {}
        probe = self._safe_get(snap, "probe", {}) or {}
        dns_stats = self._safe_get(snap, "dns_stats", {}) or {}
        top_blocked = self._safe_get(snap, "top_blocked", []) or []
        evidence = self._safe_get(snap, "evidence", []) or []

        state = self._safe_get(snap, "user_state", "CHECKING")
        self._apply_state_class(self.query_one("#summary", Static), state)
        state_icon = self._state_icon(state)
        state_label = self._state_label(state)
        threat_level = self._safe_get(snap, "threat_level", 0)
        threat_bar = self._threat_bar(threat_level)
        reasons = " / ".join(self._safe_get(snap, "reasons", []) or ["-"])
        summary = (
            f"{state_icon} {state_label}   Recommendation: {self._safe_get(snap, 'recommendation', '-')}\n"
            f"Reason: {reasons}\n"
            f"Threat: [{threat_bar}] level={threat_level}   "
            f"Risk Score: {self._safe_get(snap, 'risk_score', 0)}/100\n"
            f"Next: {self._safe_get(snap, 'next_action_hint', '-')}\n"
            f"CPU: {self._safe_get(snap, 'cpu_percent', 0.0)}%  "
            f"Mem: {self._safe_get(snap, 'mem_used_mb', 0)}/{self._safe_get(snap, 'mem_total_mb', 0)}MB "
            f"({self._safe_get(snap, 'mem_percent', 0)}%)  Temp: {self._safe_get(snap, 'temp_c', 0.0)}C\n"
            f"Mode: {str(mode_info.get('current_mode', 'shield')).upper()}  "
            f"Changed: {self._safe_get(mode_info, 'last_change', '-')}\n"
            f"Monitoring: Suricata={monitoring.get('suricata', 'UNKNOWN')}  "
            f"OpenCanary={monitoring.get('opencanary', 'UNKNOWN')}  ntfy={monitoring.get('ntfy', 'UNKNOWN')}"
        )
        self.query_one("#summary", Static).update(Text(summary))

        connection_text = (
            "Connection\n"
            f"SSID: {self._safe_get(snap, 'ssid', '-')}\n"
            f"BSSID: {self._safe_get(snap, 'bssid', '-')}\n"
            f"Signal: {self._safe_get(snap, 'signal_dbm', '-')} dBm\n"
            f"Channel: {self._safe_get(snap, 'channel', '-')} "
            f"(congestion={self._safe_get(snap, 'channel_congestion', 'unknown')}, "
            f"APs={self._safe_get(snap, 'channel_ap_count', 0)})\n"
            f"Gateway: {self._safe_get(snap, 'gateway_ip', '-')}\n"
            f"Up/Down IF: {self._safe_get(snap, 'up_if', '-')}/{self._safe_get(snap, 'down_if', '-')}\n"
            f"WiFi: {connection.get('wifi_state', 'UNKNOWN')}  "
            f"NAT: {connection.get('usb_nat', 'UNKNOWN')}  "
            f"Internet: {connection.get('internet_check', 'UNKNOWN')}"
        )
        self.query_one("#connection", Static).update(Text(connection_text))

        delay_active = bool(attack.get("canary_delay_active", False))
        delay_target_count = int(attack.get("canary_delay_target_count", 0) or 0)
        if delay_active:
            delay_text = f"ACTIVE ({delay_target_count} target{'s' if delay_target_count != 1 else ''})"
        elif str(state).upper() == "DECEPTION":
            delay_text = "ARMED"
        else:
            delay_text = "OFF"

        control_text = (
            "Control / Safety\n"
            f"QUIC: {self._safe_get(snap, 'quic', 'unknown')}  "
            f"DoH: {self._safe_get(snap, 'doh', 'unknown')}  "
            f"DNS mode: {self._safe_get(snap, 'dns_mode', 'unknown')}\n"
            f"Degrade: on={degrade.get('on', False)} "
            f"rtt={degrade.get('rtt_ms', 0)}ms rate={degrade.get('rate_mbps', 0)}Mbps\n"
            f"Probe: ok={probe.get('tls_ok', 0)}/{probe.get('tls_total', 0)} "
            f"blocked={probe.get('blocked', 0)}\n"
            f"DNS stats: ok={dns_stats.get('ok', 0)} warn={dns_stats.get('anomaly', 0)} "
            f"blocked={dns_stats.get('blocked', 0)} avg={self._safe_get(snap, 'dns_avg_ms', 0.0)}ms\n"
            f"Delay-to-Win: {delay_text}\n"
            f"Traffic: down={self._safe_get(snap, 'download_mbps', 0.0):.1f} "
            f"up={self._safe_get(snap, 'upload_mbps', 0.0):.1f} Mbps\n"
            f"Monitoring: IDS={monitoring.get('suricata', 'UNKNOWN')} "
            f"Canary={monitoring.get('opencanary', 'UNKNOWN')} ntfy={monitoring.get('ntfy', 'UNKNOWN')}"
        )
        self.query_one("#control", Static).update(Text(control_text))

        ev_lines = evidence[-12:] if len(evidence) > 12 else evidence
        evidence_text = "Evidence (last entries)\n" + "\n".join(f"{self._severity_prefix(line)} {line}" for line in ev_lines)
        if not ev_lines:
            evidence_text += "\n- (no evidence)"
        self.query_one("#evidence", Static).update(Text(evidence_text))

        flow_text = (
            f"Flow: PROBE -> DEGRADED -> NORMAL -> SAFE"
            f" | state_timeline: {self._safe_get(snap, 'state_timeline', '-')}"
        )
        self.query_one("#flow", Static).update(Text(flow_text))

        if self._details_open:
            blocked_text = ", ".join(f"{d}({c})" for d, c in top_blocked[:5]) if top_blocked else "-"
            details_text = (
                f"Details / Internal\n"
                f"state_name={self._safe_get(snap, 'internal', {}).get('state_name', '-')}\n"
                f"suspicion={self._safe_get(snap, 'internal', {}).get('suspicion', '-')}\n"
                f"decay={self._safe_get(snap, 'internal', {}).get('decay', '-')}\n"
                f"state_timeline={self._safe_get(snap, 'state_timeline', '-')}\n"
                f"top_blocked={blocked_text}\n"
                f"session_uptime={self._safe_get(snap, 'session_uptime', 0)}s\n"
                f"traffic_total={self._safe_get(snap, 'traffic_total_mb', 0.0)}MB "
                f"(down={self._safe_get(snap, 'traffic_download_mb', 0.0)}MB "
                f"up={self._safe_get(snap, 'traffic_upload_mb', 0.0)}MB)"
            )
            self.query_one("#details", Static).update(Text(details_text))

        self._apply_menu_visibility()
        self._render_status_line()

    async def _refresh_snapshot(self, initial: bool = False) -> None:
        if self._is_loading:
            return
        self._is_loading = True
        self._status_message = "Refreshing..."
        self._render_status_line()
        try:
            snap = await asyncio.to_thread(self._load_snapshot_fn)
        except Exception as exc:
            self._status_message = f"Refresh failed: {exc}"
        else:
            self._snapshot = snap
            self._status_message = "Refresh complete"
            if self._enable_epd:
                try:
                    fp = self._epd_fingerprint_fn(snap)
                    if initial or fp != self._last_epd_fp:
                        await asyncio.to_thread(self._update_epd_fn, snap, self._enable_epd)
                        self._last_epd_fp = fp
                except Exception:
                    self._status_message = "Refresh complete (EPD update skipped)"
        finally:
            self._is_loading = False
            self._render_panels()

    def _append_local_evidence(self, message: str) -> None:
        if self._snapshot is None:
            return
        evidence = self._safe_get(self._snapshot, "evidence", None)
        if isinstance(evidence, list):
            evidence.append(message)
            del evidence[:-30]

    async def _send_action(self, action: str, log_line: str) -> None:
        try:
            result = await asyncio.to_thread(self._send_command_fn, action)
            if isinstance(result, dict) and result.get("ok"):
                self._status_message = f"Action accepted: {action}"
                self._append_local_evidence(log_line)
            else:
                err = str((result or {}).get("error", "unknown error")) if isinstance(result, dict) else "unexpected response"
                self._status_message = f"Action failed: {action} ({err})"
                self._append_local_evidence(f"• action failed: {action} ({err})")
        except Exception as exc:
            self._status_message = f"Action failed: {exc}"
            self._append_local_evidence(f"• action failed: {action} ({exc})")
        finally:
            self._render_panels()

    def _requires_double_confirm(self, action: str) -> bool:
        return action in ("shutdown", "reboot")

    def _confirmation_token(self, action: str) -> str:
        return action.upper()

    def _request_confirm(self, action: str) -> None:
        self._confirm_action = action
        self._confirm_deadline = time.time() + 8.0
        token = self._confirmation_token(action)
        self._status_message = (
            f"Confirm {action}: select again within 8s ({token})"
        )
        self._render_status_line()

    def _consume_confirm(self, action: str) -> bool:
        now = time.time()
        if self._confirm_action == action and now <= self._confirm_deadline:
            self._confirm_action = None
            self._confirm_deadline = 0.0
            return True
        self._confirm_action = None
        self._confirm_deadline = 0.0
        return False

    async def action_refresh(self) -> None:
        await self._refresh_snapshot()

    async def action_stage_open(self) -> None:
        await self._send_action("stage_open", "• action: stage-open command sent")

    async def action_reprobe(self) -> None:
        await self._send_action("reprobe", "• action: reprobe command sent")

    async def action_contain(self) -> None:
        await self._send_action("contain", "• action: contain command sent")

    def action_details(self) -> None:
        self._details_open = not self._details_open
        details = self.query_one("#details", Static)
        details.styles.display = "block" if self._details_open else "none"
        self._status_message = "Details shown" if self._details_open else "Details hidden"
        self._render_panels()

    def action_toggle_menu(self) -> None:
        self._menu_open = not self._menu_open
        self._status_message = "Menu opened" if self._menu_open else "Menu closed"
        self._apply_menu_visibility()
        self._render_status_line()

    def action_menu_up(self) -> None:
        if not self._menu_open:
            return
        self._menu_idx = (self._menu_idx - 1) % len(self._menu_items)
        self._apply_menu_visibility()

    def action_menu_down(self) -> None:
        if not self._menu_open:
            return
        self._menu_idx = (self._menu_idx + 1) % len(self._menu_items)
        self._apply_menu_visibility()

    async def action_menu_select(self) -> None:
        if not self._menu_open:
            return
        item = self._menu_items[self._menu_idx]
        kind = item.get("kind")
        label = str(item.get("label", "item"))

        if kind == "close_menu":
            self._menu_open = False
            self._status_message = "Menu closed"
            self._apply_menu_visibility()
            self._render_status_line()
            return
        if kind == "toggle_details":
            self.action_details()
            return
        if kind == "refresh":
            await self._refresh_snapshot()
            return
        if kind == "send_action":
            action = str(item.get("action", ""))
            if action:
                if self._requires_double_confirm(action):
                    if not self._consume_confirm(action):
                        self._request_confirm(action)
                        return
                await self._send_action(action, f"• action: {action} command sent (menu)")
            return
        if kind == "run_cmd":
            cmd = list(item.get("cmd", []))
            if not cmd:
                return
            self._status_message = f"Running: {label}"
            self._render_status_line()
            code = await asyncio.to_thread(subprocess.call, cmd)
            self._status_message = f"Done: {label} (code {code})"
            self._render_status_line()
            return
        if kind == "interactive_cmd":
            cmd = list(item.get("cmd", []))
            if not cmd:
                return
            self._status_message = f"Running: {label}"
            self._render_status_line()
            try:
                with self.suspend():
                    code = subprocess.call(cmd)
                self._status_message = f"Done: {label} (code {code})"
            except Exception as exc:
                self._status_message = f"Failed: {label} ({exc})"
            self._render_status_line()


def run_textual(
    load_snapshot_fn: SnapshotLoader,
    send_command_fn: ActionSender,
    update_epd_fn: EpdUpdater,
    epd_fingerprint_fn: EpdFingerprint,
    unicode_mode: bool,
    enable_epd: bool,
    start_menu: bool = False,
) -> None:
    app = AzazelTextualApp(
        load_snapshot_fn=load_snapshot_fn,
        send_command_fn=send_command_fn,
        update_epd_fn=update_epd_fn,
        epd_fingerprint_fn=epd_fingerprint_fn,
        unicode_mode=unicode_mode,
        enable_epd=enable_epd,
        start_menu=start_menu,
    )
    app.run()


if __name__ == "__main__":
    print(
        "This module is a backend for cli_unified.\n"
        "Run: python3 py/azazel_edge/cli_unified.py",
        file=sys.stderr,
    )
    sys.exit(2)
