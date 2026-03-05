#!/usr/bin/env python3
"""
Azazel-Edge full-screen TUI (manual refresh, dark theme, fixed layout).
 - Snapshot JSON is fetched on demand (no auto-refresh).
 - IPC prefers control-plane Unix socket (/run/azazel-edge/control.sock), then file fallback.
 - Actions send commands through control plane first, then command file fallback.
   shutdown/reboot are daemon-only and do not use command-file fallback.
 - Unicode が不安定なら ASCII 枠＋アイコンに自動フォールバック (--ascii/--unicodeで強制可)。
"""
from __future__ import annotations

import argparse
import curses
import json
import locale
import os
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import urlopen

PY_ROOT = Path(__file__).resolve().parents[1]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.control_plane import read_snapshot_payload, send_action, send_action_with_fallback
from azazel_edge.path_schema import log_dir_candidates, snapshot_path_candidates

DEFAULT_ROOT = Path(__file__).resolve().parent.parent.parent
_SNAPSHOT_PATHS = snapshot_path_candidates()
SNAPSHOT_PATH = _SNAPSHOT_PATHS[0]
FALLBACK_SNAPSHOT = _SNAPSHOT_PATHS[-1]
FALLBACK_RUN = FALLBACK_SNAPSHOT.parent
_LOG_DIRS = log_dir_candidates()
LOG_PATH = _LOG_DIRS[0] / "first_minute.log"
FALLBACK_LOG = _LOG_DIRS[-1] / "first_minute.log"

STATE_MAP = {
    "CHECKING": ("青", "⟳", "~"),
    "SAFE": ("緑", "✅", "OK"),
    "LIMITED": ("黄", "⚠️", "!"),
    "CONTAINED": ("赤", "⛔", "X"),
    "DECEPTION": ("紫", "👁", "O"),
}


@dataclass
class Snapshot:
    now_time: str
    ssid: str
    bssid: str
    channel: str
    signal_dbm: str
    gateway_ip: str
    down_if: str
    down_ip: str
    up_if: str
    up_ip: str
    user_state: str
    recommendation: str
    reasons: List[str]
    next_action_hint: str
    quic: str
    doh: str
    dns_mode: str
    degrade: Dict[str, object]
    probe: Dict[str, object]
    evidence: List[str]
    internal: Dict[str, object]
    connection: Dict[str, object]
    mode: Dict[str, object]
    monitoring: Dict[str, str]
    attack: Dict[str, object]
    age: str = "00:00:00"
    snapshot_epoch: float = 0.0
    source: str = "SNAPSHOT"
    dns_stats: Dict[str, int] = None  # {"ok": 45, "anomaly": 3, "blocked": 2}
    threat_level: int = 0  # 0-5 scale
    bssid_vendor: str = "-"  # AP vendor info
    battery_pct: int = -1  # -1 = unknown
    channel_congestion: str = "unknown"  # none, low, medium, high, critical
    channel_ap_count: int = 0  # 周囲のAP数
    recommended_channel: int = -1  # 推奨チャンネル
    cpu_percent: float = 0.0  # CPU使用率
    mem_percent: int = 0  # メモリ使用率
    mem_used_mb: int = 0  # 使用メモリ
    mem_total_mb: int = 0  # 総メモリ
    temp_c: float = 0.0  # CPU温度
    download_mbps: float = 0.0  # ダウンロード速度
    upload_mbps: float = 0.0  # アップロード速度
    session_uptime: int = 0  # WiFi接続時間（秒）
    suricata_critical: int = 0  # Suricata重大アラート
    suricata_warning: int = 0  # Suricata警告
    suricata_info: int = 0  # Suricata情報
    packet_loss_percent: float = 0.0  # パケットロス率
    latency_avg_ms: float = 0.0  # 平均レイテンシ
    latency_trend: List[float] = None  # レイテンシ推移
    dns_avg_ms: float = 0.0  # DNS平均応答時間
    dns_cache_hit_rate: int = 0  # DNSキャッシュヒット率
    dns_timeouts: int = 0  # DNSタイムアウト数
    traffic_total_mb: float = 0.0  # 累計トラフィック
    traffic_download_mb: float = 0.0  # 累計ダウンロード
    traffic_upload_mb: float = 0.0  # 累計アップロード
    traffic_packets: int = 0  # 累計パケット数
    state_timeline: str = "-"  # 状態遷移タイムライン
    top_blocked: List[Tuple[str, int]] = None  # ブロックトップ5
    risk_score: int = 0  # リスクスコア 0-100（優先度：低）

    def __post_init__(self):
        if self.dns_stats is None:
            self.dns_stats = {"ok": 0, "anomaly": 0, "blocked": 0}
        if self.latency_trend is None:
            self.latency_trend = []
        if self.top_blocked is None:
            self.top_blocked = []
        if self.connection is None:
            self.connection = {
                "wifi_state": "DISCONNECTED",
                "usb_nat": "OFF",
                "internet_check": "UNKNOWN",
                "captive_portal": "NA",
                "captive_portal_reason": "NOT_CHECKED",
            }
        if self.mode is None:
            self.mode = {
                "current_mode": "shield",
                "last_change": "",
                "requested_by": "",
                "config_hash": "",
            }
        if self.monitoring is None:
            self.monitoring = {"suricata": "UNKNOWN", "opencanary": "UNKNOWN", "ntfy": "UNKNOWN"}
        if self.attack is None:
            self.attack = {
                "suricata_alert": False,
                "suricata_severity": 0,
                "canary_target_alert": False,
                "canary_delay_active": False,
                "canary_delay_target_count": 0,
                "canary_delay_targets": [],
            }


def detect_unicode(force_ascii: bool, force_unicode: bool) -> bool:
    if force_ascii:
        return False
    if force_unicode:
        return True
    lang = (os.environ.get("LANG", "") + os.environ.get("LC_CTYPE", "")).upper()
    return "UTF-8" in lang or "UTF8" in lang


def build_snapshot(data: Dict[str, object], source: str = "SNAPSHOT") -> Snapshot:
    """Normalize dict -> Snapshot dataclass."""
    age = "00:00:00"
    ts = data.get("snapshot_epoch") or 0
    if ts:
        delta = max(0, int(time.time() - ts))
        age = time.strftime("%H:%M:%S", time.gmtime(delta))
    
    internal = data.get("internal", {}) if isinstance(data.get("internal"), dict) else {}
    try:
        suspicion = int(float(internal.get("suspicion", 0)))
    except Exception:
        suspicion = 0
    threat_level = min(5, max(0, int(suspicion / 20)))  # 0-100 -> 0-5
    connection = data.get("connection", {}) if isinstance(data.get("connection"), dict) else {}
    monitoring = data.get("monitoring", {}) if isinstance(data.get("monitoring"), dict) else {}

    user_state = str(data.get("user_state", "") or "").strip().upper()
    state_name = str(internal.get("state_name", "") or "").strip().upper()
    if not user_state and state_name:
        user_state = _user_state_from_stage_name(state_name)
    if not user_state:
        user_state = "CHECKING"

    normalized_connection = {
        "wifi_state": str(connection.get("wifi_state", "DISCONNECTED") or "DISCONNECTED").upper(),
        "usb_nat": str(connection.get("usb_nat", "OFF") or "OFF").upper(),
        "internet_check": str(connection.get("internet_check", "UNKNOWN") or "UNKNOWN").upper(),
        "captive_portal": str(connection.get("captive_portal", "NA") or "NA").upper(),
        "captive_portal_reason": str(connection.get("captive_portal_reason", "NOT_CHECKED") or "NOT_CHECKED"),
    }
    normalized_monitoring = {
        "suricata": str(monitoring.get("suricata", "UNKNOWN") or "UNKNOWN").upper(),
        "opencanary": str(monitoring.get("opencanary", "UNKNOWN") or "UNKNOWN").upper(),
        "ntfy": str(monitoring.get("ntfy", "UNKNOWN") or "UNKNOWN").upper(),
    }
    mode_payload = data.get("mode", {}) if isinstance(data.get("mode"), dict) else {}
    normalized_mode = {
        "current_mode": str(mode_payload.get("current_mode", "shield") or "shield").lower(),
        "last_change": str(mode_payload.get("last_change", "") or ""),
        "requested_by": str(mode_payload.get("requested_by", "") or ""),
        "config_hash": str(mode_payload.get("config_hash", "") or ""),
    }
    attack = data.get("attack", {}) if isinstance(data.get("attack"), dict) else {}
    normalized_attack = {
        "suricata_alert": bool(attack.get("suricata_alert", False)),
        "suricata_severity": int(attack.get("suricata_severity", 0) or 0),
        "canary_target_alert": bool(attack.get("canary_target_alert", False)),
        "canary_delay_active": bool(attack.get("canary_delay_active", False)),
        "canary_delay_target_count": int(attack.get("canary_delay_target_count", 0) or 0),
        "canary_delay_targets": attack.get("canary_delay_targets", []) if isinstance(attack.get("canary_delay_targets", []), list) else [],
    }
    
    return Snapshot(
        now_time=data.get("now_time", time.strftime("%H:%M:%S")),
        ssid=data.get("ssid", "-"),
        bssid=data.get("bssid", "-"),
        channel=str(data.get("channel", "-")),
        signal_dbm=str(data.get("signal_dbm", "-")),
        gateway_ip=data.get("gateway_ip", "-"),
        down_if=data.get("down_if", "-"),
        down_ip=data.get("down_ip", "-"),
        up_if=data.get("up_if", "-"),
        up_ip=data.get("up_ip", "-"),
        user_state=user_state,
        recommendation=data.get("recommendation", "Checking"),
        reasons=data.get("reasons", [])[:3],
        next_action_hint=data.get("next_action_hint", ""),
        quic=data.get("quic", "unknown"),
        doh=data.get("doh", "unknown"),
        dns_mode=data.get("dns_mode", "unknown"),
        degrade=data.get("degrade", {"on": False, "rtt_ms": 0, "rate_mbps": 0}),
        probe=data.get("probe", {"tls_ok": 0, "tls_total": 0, "blocked": 0}),
        evidence=data.get("evidence", [])[-6:],  # oldest→newest想定
        internal=internal,
        connection=normalized_connection,
        mode=normalized_mode,
        monitoring=normalized_monitoring,
        attack=normalized_attack,
        age=age,
        snapshot_epoch=float(ts) if ts else 0.0,
        source=source,
        dns_stats=data.get("dns_stats", {"ok": 0, "anomaly": 0, "blocked": 0}),
        threat_level=threat_level,
        bssid_vendor="-",
        battery_pct=data.get("battery_pct", -1),
        channel_congestion=data.get("channel_congestion", "unknown"),
        channel_ap_count=data.get("channel_ap_count", 0),
        recommended_channel=data.get("recommended_channel", -1),
        cpu_percent=data.get("cpu_percent", 0.0),
        mem_percent=data.get("mem_percent", 0),
        mem_used_mb=data.get("mem_used_mb", 0),
        mem_total_mb=data.get("mem_total_mb", 512),
        temp_c=data.get("temp_c", 0.0),
        download_mbps=data.get("download_mbps", 0.0),
        upload_mbps=data.get("upload_mbps", 0.0),
        session_uptime=data.get("session_uptime", 0),
        suricata_critical=data.get("suricata_critical", 0),
        suricata_warning=data.get("suricata_warning", 0),
        suricata_info=data.get("suricata_info", 0),
        packet_loss_percent=data.get("packet_loss_percent", 0.0),
        latency_avg_ms=data.get("latency_avg_ms", 0.0),
        latency_trend=data.get("latency_trend", []),
        dns_avg_ms=data.get("dns_avg_ms", 0.0),
        dns_cache_hit_rate=data.get("dns_cache_hit_rate", 0),
        dns_timeouts=data.get("dns_timeouts", 0),
        traffic_total_mb=data.get("traffic_total_mb", 0.0),
        traffic_download_mb=data.get("traffic_download_mb", 0.0),
        traffic_upload_mb=data.get("traffic_upload_mb", 0.0),
        traffic_packets=data.get("traffic_packets", 0),
        state_timeline=data.get("state_timeline", "-"),
        top_blocked=data.get("top_blocked", []),
        risk_score=data.get("risk_score", 0),
    )


def _fill_iface_defaults(data: Dict[str, object]) -> None:
    """Ensure interface fields are present even when rebuilt from logs."""
    defaults = {"down_if": "usb0", "down_ip": "10.55.0.10", "up_if": "wlan0", "up_ip": "-"}
    for key, val in defaults.items():
        cur = str(data.get(key, "-"))
        if (not cur) or cur == "-":
            data[key] = val


def _get_interface_ip(interface: str) -> str:
    """
    Get IP address of specified network interface.
    Returns IP address string or "-" if not found.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if "inet " in line:
                    # Format: "    inet 192.168.1.100/24 brd ..."
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_cidr = parts[1]
                        # Remove /24 suffix
                        ip_addr = ip_cidr.split("/")[0]
                        return ip_addr
    except Exception:
        pass
    return "-"


def _parse_signal_dbm(raw_val) -> Optional[int]:
    """Normalize signal strength to an int dBm if possible."""
    try:
        if raw_val is None:
            return None
        if isinstance(raw_val, (int, float)):
            return int(raw_val)
        text = str(raw_val).strip()
        if not text or text == "-":
            return None
        text = text.lower().replace("dbm", "").strip()
        return int(float(text))
    except Exception:
        return None


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def _service_active(name: str) -> bool:
    try:
        res = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            text=True,
            timeout=1.0,
        )
        return res.returncode == 0 and res.stdout.strip() == "active"
    except Exception:
        return False


def _pid_running(pid_file: Path, expected_cmd: str = "") -> bool:
    try:
        if not pid_file.exists():
            return False
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        os.kill(pid, 0)
    except PermissionError:
        pass
    except Exception:
        return False
    if expected_cmd:
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().decode("utf-8", errors="ignore")
            if expected_cmd not in cmdline:
                return False
        except Exception:
            return False
    return True


def _process_running(pattern: str) -> bool:
    try:
        res = subprocess.run(
            ["pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            timeout=1.0,
        )
        return res.returncode == 0
    except Exception:
        return False


def _container_running(name: str) -> bool:
    try:
        res = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if res.returncode != 0:
            return False
        names = {line.strip() for line in res.stdout.splitlines() if line.strip()}
        return name in names
    except Exception:
        return False


def _ntfy_health_ok() -> bool:
    mgmt_ip = os.environ.get("MGMT_IP", "10.55.0.10")
    ntfy_port = os.environ.get("NTFY_PORT", "8081")
    url = f"http://{mgmt_ip}:{ntfy_port}/v1/health"
    try:
        with urlopen(url, timeout=1.0) as resp:
            if resp.status != 200:
                return False
            body = resp.read(256).decode("utf-8", errors="ignore")
            return '"healthy":true' in body
    except Exception:
        return False


def _collect_monitoring_state() -> Dict[str, str]:
    opencanary_ok = (
        _service_active("opencanary@az_canary.service")
        or _service_active("opencanary.service")
        or _service_active("azazel-edge-opencanary.service")
        or _container_running("azazel-edge-opencanary")
    )
    suricata_ok = (
        _service_active("suricata.service")
        or _service_active("azazel-edge-suricata.service")
        or _container_running("azazel-edge-suricata")
    )
    ntfy_ok = _service_active("ntfy.service") and _ntfy_health_ok()
    opencanary_pid = Path("/home/azazel/canary-venv/bin/opencanaryd.pid")
    suricata_pid = Path("/run/suricata.pid")
    return {
        "opencanary": "ON" if (opencanary_ok or _pid_running(opencanary_pid, "opencanary") or _process_running("[o]pencanary.tac")) else "OFF",
        "suricata": "ON" if (suricata_ok or _pid_running(suricata_pid, "suricata")) else "OFF",
        "ntfy": "ON" if ntfy_ok else "OFF",
    }


def _threat_label_from_suspicion(suspicion: int) -> str:
    if suspicion >= 50:
        return "CRITICAL"
    if suspicion >= 30:
        return "HIGH"
    if suspicion >= 15:
        return "MEDIUM"
    return "LOW"


def _filled_segments_from_suspicion(suspicion: int) -> int:
    if suspicion <= 0:
        return 0
    if suspicion >= 50:
        return 5
    if suspicion >= 30:
        return 4
    if suspicion >= 15:
        return 3
    return 2


def _user_state_from_stage_name(stage_name: str) -> str:
    name = stage_name.upper()
    if name in ("PROBE", "INIT"):
        return "CHECKING"
    if name == "NORMAL":
        return "SAFE"
    if name == "DEGRADED":
        return "LIMITED"
    if name == "CONTAIN":
        return "CONTAINED"
    if name == "DECEPTION":
        return "DECEPTION"
    return "CHECKING"


def export_epd_snapshot(snap: Snapshot) -> None:
    """
    EPD表示用にスナップショットをエクスポート
    TUIで計算済みのrisk_scoreやrecommendationをEPDと共有して重複計算を避ける
    """
    try:
        from dataclasses import asdict
        
        # EPDに必要な最小限のフィールドのみをエクスポート
        epd_data = {
            "risk_score": snap.risk_score,
            "recommendation": snap.recommendation,
            "user_state": snap.user_state,
            "threat_level": snap.threat_level,
            "signal_dbm": str(snap.signal_dbm),
            "ssid": snap.ssid,
            "suricata_critical": snap.suricata_critical,
            "suricata_warning": snap.suricata_warning,
            "cpu_percent": snap.cpu_percent,
            "temp_c": snap.temp_c,
            "session_uptime": snap.session_uptime,
            "download_mbps": snap.download_mbps,
            "upload_mbps": snap.upload_mbps,
            "packet_loss_percent": snap.packet_loss_percent,
            "dns_avg_ms": snap.dns_avg_ms,
            "now_time": snap.now_time,
        }
        
        # /tmpに保存（権限問題を回避）
        epd_path = Path("/tmp/epd_snapshot.json")
        epd_path.write_text(json.dumps(epd_data, ensure_ascii=False), encoding="utf-8")
    except Exception:
        # エクスポート失敗してもTUI動作に影響しない
        pass


def _parse_log_ts(line: str) -> float:
    """Parse leading timestamp from a log line into epoch seconds."""
    try:
        parts = line.split(None, 2)
        if len(parts) >= 2:
            ts_part = f"{parts[0]} {parts[1]}"
            for fmt in ("%Y-%m-%d %H:%M:%S,%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return time.mktime(time.strptime(ts_part, fmt))
                except ValueError:
                    continue
    except Exception:
        return 0.0
    return 0.0


def load_snapshot_from_log() -> Optional[Snapshot]:
    """Fallback: rebuild snapshot from JSON log (first_minute.log)."""
    for path in (LOG_PATH, FALLBACK_LOG):
        if not path.exists():
            continue
        try:
            lines = deque(path.open(encoding="utf-8"), maxlen=200)
        except Exception:
            continue
        for line in reversed(lines):
            idx = line.find("{")
            if idx == -1:
                continue
            try:
                payload = json.loads(line[idx:])
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            
            # ログのタイムスタンプを確認
            snap_ts = _parse_log_ts(line) or time.time()
            age_seconds = time.time() - snap_ts
            
            # 1分以上古いログエントリは無視（常に最新を求める）
            if age_seconds > 60:
                continue
            
            stage = str(payload.get("state", "")).upper()
            link_meta = payload.get("wifi") or {}
            link = link_meta.get("link", {}) if isinstance(link_meta, dict) else {}
            probe_last = payload.get("last_probe") or {}
            tls_mismatch = bool(probe_last.get("tls_mismatch")) if isinstance(probe_last, dict) else False
            probe = {
                "tls_ok": 0 if not probe_last else int(not tls_mismatch),
                "tls_total": 1 if probe_last else 0,
                "blocked": 1 if (probe_last and tls_mismatch) else 0,
            }
            degrade_on = stage in ("PROBE", "DEGRADED")
            data = {
                "now_time": time.strftime("%H:%M:%S", time.localtime(snap_ts)),
                "snapshot_epoch": snap_ts,
                "ssid": link.get("ssid", "-"),
                "bssid": link.get("bssid", "-"),
                "channel": link.get("channel", "-"),
                "signal_dbm": link.get("signal", "-"),
                "gateway_ip": link.get("gateway", "-"),
                "down_if": "-",
                "down_ip": "-",
                "up_if": "-",
                "user_state": _user_state_from_stage_name(stage),
                "recommendation": payload.get("reason", "Checking"),
                "reasons": [payload.get("reason", "Checking")],
                "next_action_hint": "Rebuilt from log",
                "quic": "blocked" if stage in ("PROBE", "DEGRADED", "CONTAIN") else "allowed",
                "doh": "blocked",
                "dns_mode": "forced via Azazel DNS",
                "degrade": {
                    "on": degrade_on,
                    "rtt_ms": 180 if degrade_on else 0,
                    "rate_mbps": 2.0 if stage == "DEGRADED" else 1.0 if stage == "PROBE" else 0,
                },
                "probe": probe,
                "evidence": [f"state={stage} suspicion={payload.get('suspicion', 0)}"],
                "internal": {
                    "state_name": stage or "UNKNOWN",
                    "suspicion": payload.get("suspicion", 0),
                    "decay": "-",
                },
            }
            _fill_iface_defaults(data)
            return build_snapshot(data, source="LOG")
    return None


# セッション開始時刻（グローバル）
_session_start_time = time.time()

# スループット計算用の前回統計（優先度：低）
_last_net_stats = {}
_last_net_time = time.time()


def calculate_risk_score(snap: Snapshot) -> int:
    """
    リスクスコアを0-100で算出（優先度：低）
    高いほど危険
    """
    score = 0
    
    # 1. Threat Level (0-30点)
    # threat_levelは0-5の整数なので、直接計算
    if isinstance(snap.threat_level, int):
        score += min(snap.threat_level * 6, 30)  # 0-5を0-30にマッピング
    else:
        threat_map = {"low": 0, "medium": 10, "high": 20, "critical": 30}
        score += threat_map.get(str(snap.threat_level).lower(), 0)
    
    # 2. Suricata Alerts (0-25点)
    score += min(snap.suricata_critical * 10, 25)  # critical 1件=10点
    score += min(snap.suricata_warning * 3, 10)  # warning 1件=3点
    
    # 3. WiFi Signal Strength (0-15点)
    sig_dbm = _parse_signal_dbm(snap.signal_dbm)
    if sig_dbm is not None:
        if sig_dbm < -80:  # 弱い
            score += 15
        elif sig_dbm < -70:
            score += 10
        elif sig_dbm < -60:
            score += 5
    
    # 4. User State (0-20点)
    state_risk = {
        "SAFE": 0,
        "NORMAL": 5,
        "LIMITED": 10,
        "DEGRADED": 12,
        "DECEPTION": 15,
        "CONTAINED": 20,
    }
    score += state_risk.get(snap.user_state.upper(), 10)
    
    # 5. DNS Blocked (0-10点)
    dns_blocked = snap.dns_stats.get("blocked", 0)
    score += min(dns_blocked * 2, 10)
    
    return min(score, 100)  # 最大100


def generate_recommendation(snap: Snapshot) -> str:
    """
    現在の状態に応じた推奨アクションを生成（優先度：低）
    """
    recommendations = []
    
    # 1. チャンネル混雑度チェック
    if snap.channel_congestion in ["high", "critical"]:
        if snap.recommended_channel > 0:
            recommendations.append(f"📡 Ch{snap.recommended_channel}に変更推奨")
        else:
            recommendations.append("📡 混雑低チャンネルへ変更推奨")
    
    # 2. WiFi信号強度
    if isinstance(snap.signal_dbm, (int, float)) and snap.signal_dbm < -75:
        recommendations.append("📶 APに近づくか再接続")
    
    # 3. リスクスコア
    if snap.risk_score >= 70:
        recommendations.append("⚠️ 危険なネットワーク！切断推奨")
    elif snap.risk_score >= 50:
        recommendations.append("🛡️ Containモードへ移行検討")
    
    # 4. Suricataアラート
    if snap.suricata_critical > 0:
        recommendations.append(f"🚨 {snap.suricata_critical}件の重大脅威検知")
    
    # 5. DNSブロック
    dns_blocked = snap.dns_stats.get("blocked", 0)
    if dns_blocked >= 10:
        recommendations.append(f"🚫 {dns_blocked}件DNSブロック！確認推奨")
    
    # 6. バッテリー
    if 0 <= snap.battery_pct < 20:
        recommendations.append("🔋 バッテリー低下！充電推奨")
    
    # 7. 温度
    if snap.temp_c >= 70:
        recommendations.append("🌡️ 高温警告！冷却推奨")
    
    # 8. 問題なし
    if not recommendations and snap.user_state.upper() == "SAFE":
        recommendations.append("✅ ネットワークは安全です")
    
    return " | ".join(recommendations[:2]) if recommendations else "✅ 問題なし"


def load_snapshot() -> Snapshot:
    data: Dict[str, object]
    payload, source = read_snapshot_payload(prefer_control_plane=True)
    if payload is not None:
        try:
            snap = build_snapshot(payload, source=source)
        except Exception:
            snap_from_log = load_snapshot_from_log()
            if snap_from_log:
                snap = snap_from_log
            else:
                sample = default_snapshot()
                snap = build_snapshot(sample, source="SAMPLE")
    else:
        snap_from_log = load_snapshot_from_log()
        if snap_from_log:
            snap = snap_from_log
        elif SNAPSHOT_PATH.exists() or FALLBACK_SNAPSHOT.exists():
            path = SNAPSHOT_PATH if SNAPSHOT_PATH.exists() else FALLBACK_SNAPSHOT
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                snap = build_snapshot(data, source="SNAPSHOT")
            except Exception:
                FALLBACK_RUN.mkdir(parents=True, exist_ok=True)
                sample = default_snapshot()
                try:
                    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
                    SNAPSHOT_PATH.write_text(json.dumps(sample, ensure_ascii=False), encoding="utf-8")
                except Exception:
                    pass
                snap = build_snapshot(sample, source="SAMPLE")
        else:
            FALLBACK_RUN.mkdir(parents=True, exist_ok=True)
            sample = default_snapshot()
            try:
                SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
                SNAPSHOT_PATH.write_text(json.dumps(sample, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass
            snap = build_snapshot(sample, source="SAMPLE")
    
    # WiFiチャンネルスキャンを実行（上りインターフェースを使用）
    try:
        # 相対インポートまたは直接インポートを試行
        try:
            from .sensors.wifi_channel_scanner import scan_wifi_channels
        except ImportError:
            import sys
            from pathlib import Path
            sensors_path = Path(__file__).parent / "sensors"
            if str(sensors_path) not in sys.path:
                sys.path.insert(0, str(sensors_path.parent))
            from sensors.wifi_channel_scanner import scan_wifi_channels
        
        scan_result = scan_wifi_channels(snap.up_if)
        if scan_result.get("scan_success"):
            snap.channel_congestion = scan_result.get("congestion_level", "unknown")
            snap.channel_ap_count = scan_result.get("ap_count", 0)
            snap.recommended_channel = scan_result.get("recommended_channel", -1)
            # デバッグ情報をevidenceに追加
            snap.evidence.append(f"🔍 Scan: {snap.channel_ap_count} APs, {snap.channel_congestion}")
        else:
            # スキャン失敗時の情報を追加
            error_msg = scan_result.get("error", "scan failed")
            snap.evidence.append(f"⚠️ Scan failed: {error_msg}")
    except Exception as e:
        # スキャン失敗時はデフォルト値を保持し、エラーをevidenceに記録
        snap.evidence.append(f"⚠️ Scan error: {str(e)}")
    
    # システムメトリクスを収集
    try:
        try:
            from .sensors.system_metrics import collect_all_metrics
        except ImportError:
            import sys
            from pathlib import Path
            sensors_path = Path(__file__).parent / "sensors"
            if str(sensors_path) not in sys.path:
                sys.path.insert(0, str(sensors_path.parent))
            from sensors.system_metrics import collect_all_metrics
        
        metrics = collect_all_metrics(snap.up_if, snap.down_if)
        snap.cpu_percent = metrics.get("cpu_percent", 0.0)
        mem = metrics.get("memory", {})
        snap.mem_percent = mem.get("percent", 0)
        snap.mem_used_mb = mem.get("used_mb", 0)
        snap.mem_total_mb = mem.get("total_mb", 512)
        snap.temp_c = metrics.get("temperature_c", 0.0) or 0.0
        
        # スループット計算（前回値との差分）（優先度：低）
        global _last_net_stats, _last_net_time
        current_time = time.time()
        net_stats = metrics.get("network", {})
        
        if _last_net_stats.get(snap.up_if):
            time_diff = current_time - _last_net_time
            if time_diff > 0:
                last_rx = _last_net_stats[snap.up_if].get("rx_bytes", 0)
                last_tx = _last_net_stats[snap.up_if].get("tx_bytes", 0)
                curr_rx = net_stats.get("rx_bytes", 0)
                curr_tx = net_stats.get("tx_bytes", 0)
                
                rx_diff = max(0, curr_rx - last_rx)
                tx_diff = max(0, curr_tx - last_tx)
                
                # bytes/sec -> Mbps
                snap.download_mbps = (rx_diff / time_diff) * 8 / 1000000
                snap.upload_mbps = (tx_diff / time_diff) * 8 / 1000000
        
        # 次回のために保存
        _last_net_stats[snap.up_if] = net_stats
        _last_net_time = current_time
        
        # Suricataアラート
        alerts = metrics.get("suricata_alerts", {})
        snap.suricata_critical = alerts.get("critical", 0)
        snap.suricata_warning = alerts.get("warning", 0)
        snap.suricata_info = alerts.get("info", 0)
    except Exception:
        pass
    
    # ネットワーク解析（優先度：中）
    try:
        try:
            from .sensors.network_analytics import get_analytics
        except ImportError:
            import sys
            from pathlib import Path
            sensors_path = Path(__file__).parent / "sensors"
            if str(sensors_path) not in sys.path:
                sys.path.insert(0, str(sensors_path.parent))
            from sensors.network_analytics import get_analytics
        
        analytics = get_analytics()
        
        # 状態遷移の記録（前回の状態と比較）
        current_state = snap.user_state
        # グローバル変数で前回の状態を記憶（簡易版）
        if not hasattr(load_snapshot, 'last_state'):
            load_snapshot.last_state = None
        
        if load_snapshot.last_state and load_snapshot.last_state != current_state:
            # 状態が変化したら記録
            if not hasattr(load_snapshot, 'state_start_time'):
                load_snapshot.state_start_time = time.time()
            
            duration = int(time.time() - load_snapshot.state_start_time)
            analytics.add_state_transition(load_snapshot.last_state, current_state, duration)
            load_snapshot.state_start_time = time.time()
        
        load_snapshot.last_state = current_state
        
        # パケットロスとレイテンシ測定（軽量化のためcount=3）
        # ping_result = analytics.measure_packet_loss("8.8.8.8", 3)
        # snap.packet_loss_percent = ping_result.get("loss_percent", 0.0)
        # snap.latency_avg_ms = ping_result.get("avg_rtt_ms", 0.0)
        # snap.latency_trend = analytics.get_ping_trend()
        
        # DNS統計
        dns_stats = analytics.get_dns_stats()
        snap.dns_avg_ms = dns_stats.get("avg_ms", 0.0)
        snap.dns_cache_hit_rate = dns_stats.get("cache_hit_rate", 0)
        snap.dns_timeouts = dns_stats.get("timeouts", 0)
        
        # DNS blockedイベントからドメインを記録
        dns_blocked = snap.dns_stats.get("blocked", 0)
        if dns_blocked > 0:
            # evidenceからブロックされたドメインを抽出（簡易版）
            for ev in snap.evidence[-10:]:
                if "blocked" in ev.lower() and "dns" in ev.lower():
                    # "DNS blocked: example.com" のような形式を想定
                    parts = ev.split(":")
                    if len(parts) >= 2:
                        domain = parts[-1].strip().split()[0]  # 最初の単語を取得
                        analytics.add_blocked_domain(domain)
        
        # 状態遷移タイムライン
        snap.state_timeline = analytics.get_state_timeline()
        
        # ブロックトップ5
        snap.top_blocked = analytics.get_top_blocked(5)
        
        # 累計トラフィック（start_statsはnoneで起動からの累計）
        cumulative = analytics.get_traffic_cumulative(snap.up_if)
        snap.traffic_total_mb = cumulative.get("total_mb", 0.0)
        snap.traffic_download_mb = cumulative.get("download_mb", 0.0)
        snap.traffic_upload_mb = cumulative.get("upload_mb", 0.0)
        snap.traffic_packets = cumulative.get("packets", 0)
    except Exception:
        pass
    
    # セッション稼働時間（優先度：低）
    snap.session_uptime = int(time.time() - _session_start_time)

    # WebUIと同じ監視サービス状態を補完
    try:
        snap.monitoring = _collect_monitoring_state()
    except Exception:
        pass
    
    # リスクスコア計算（優先度：低）
    snap.risk_score = calculate_risk_score(snap)
    
    # 推奨アクション生成（優先度：低）
    auto_recommendation = generate_recommendation(snap)
    # 既存のrecommendationが空またはデフォルトの場合、自動推奨で上書き
    if not snap.recommendation or snap.recommendation == "Checking":
        snap.recommendation = auto_recommendation
    
    # wlan (upstream) の IP アドレスを取得
    if snap.up_if and snap.up_if != "-":
        snap.up_ip = _get_interface_ip(snap.up_if)
    
    # EPD用にスナップショットをエクスポート（計算済みデータを共有）
    export_epd_snapshot(snap)
    
    return snap


def default_snapshot() -> Dict[str, object]:
    return {
        "now_time": time.strftime("%H:%M:%S"),
        "ssid": "unknown",
        "bssid": "-",
        "channel": "-",
        "signal_dbm": "-",
        "gateway_ip": "-",
        "down_if": "usb0",
        "down_ip": "-",
        "up_if": "wlan0",
        "up_ip": "-",
        "user_state": "CHECKING",
        "recommendation": "Checking",
        "reasons": ["Collecting info"],
        "next_action_hint": "Waiting for re-evaluation",
        "quic": "blocked",
        "doh": "blocked",
        "dns_mode": "forced via Azazel DNS",
        "degrade": {"on": True, "rtt_ms": 180, "rate_mbps": 2.0},
        "probe": {"tls_ok": 2, "tls_total": 3, "blocked": 1},
        "evidence": ["waiting for snapshot"],
        "internal": {"state_name": "PROBE", "suspicion": 0, "decay": 0},
        "connection": {
            "wifi_state": "DISCONNECTED",
            "usb_nat": "OFF",
            "internet_check": "UNKNOWN",
            "captive_portal": "NA",
            "captive_portal_reason": "NOT_CHECKED",
        },
        "monitoring": {"suricata": "UNKNOWN", "opencanary": "UNKNOWN", "ntfy": "UNKNOWN"},
        "snapshot_epoch": time.time(),
    }


def send_command(action: str) -> Dict[str, Any]:
    # Power actions must go through control daemon scripts only.
    if action in ("shutdown", "reboot"):
        return send_action(action, timeout_sec=40.0)
    return send_action_with_fallback(action, logger=None)


def _epd_fingerprint(snap: Snapshot) -> Tuple[str, str, str, Optional[int], str]:
    """Small fingerprint of data rendered on the EPD to avoid redundant refresh."""
    wlan_ip = snap.up_ip if snap.up_ip and snap.up_ip != "-" else "No IP"
    rec = (snap.recommendation or "")[:20]
    sig_dbm = _parse_signal_dbm(snap.signal_dbm)
    return (snap.user_state.upper(), snap.ssid or "-", wlan_ip, sig_dbm, rec)


def update_epd(snap: Snapshot, enable_epd: bool = True) -> None:
    """
    Update E-Paper Display based on current snapshot state.
    Maps TUI states to EPD states:
      SAFE/CHECKING → normal
      LIMITED → warning
      CONTAINED → danger
      DECEPTION → stale
    """
    if not enable_epd:
        return
    
    try:
        epd_script = DEFAULT_ROOT / "py" / "azazel_epd.py"
        if not epd_script.exists():
            return
        
        user_state = snap.user_state.upper()
        
        # Map TUI state to EPD state
        if user_state in ("SAFE", "CHECKING"):
            # NORMAL state: show SSID, wlan IP, wlan signal
            signal_dbm = _parse_signal_dbm(snap.signal_dbm)
            
            # Use wlan (upstream) IP address instead of downstream
            wlan_ip = snap.up_ip if snap.up_ip and snap.up_ip != "-" else "No IP"
            mode_label = str((snap.mode or {}).get("current_mode", "shield") or "shield").upper()
            
            cmd = [
                "python3", str(epd_script),
                "--state", "normal",
                "--ssid", snap.ssid or "No SSID",
                "--mode-label", mode_label,
            ]
            if signal_dbm is not None:
                cmd += ["--signal", str(signal_dbm)]
        
        elif user_state == "LIMITED":
            # WARNING state
            msg = snap.recommendation[:20] if snap.recommendation else "LIMITED MODE"
            cmd = [
                "python3", str(epd_script),
                "--state", "warning",
                "--msg", msg
            ]
        
        elif user_state == "CONTAINED":
            # DANGER state
            msg = snap.recommendation[:20] if snap.recommendation else "ISOLATED"
            cmd = [
                "python3", str(epd_script),
                "--state", "danger",
                "--msg", msg
            ]
        
        elif user_state == "DECEPTION":
            # STALE state (repurposed for DECEPTION mode)
            msg = snap.recommendation[:20] if snap.recommendation else "DECEPTION MODE"
            cmd = [
                "python3", str(epd_script),
                "--state", "stale",
                "--msg", msg
            ]
        
        else:
            # Unknown state - show as warning
            cmd = [
                "python3", str(epd_script),
                "--state", "warning",
                "--msg", "UNKNOWN STATE"
            ]
        
        # Run EPD update in background (non-blocking)
        subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )
    
    except Exception:
        # Silently fail - EPD update is optional
        pass


def color_for_state(user_state: str, unicode_mode: bool) -> Tuple[int, str]:
    icon = "~"
    ascii_icon = "~"
    color_pair = 3  # cyan
    mapping = STATE_MAP.get(user_state.upper(), STATE_MAP["CHECKING"])
    icon = mapping[1] if unicode_mode else mapping[2]
    if user_state.upper() == "SAFE":
        color_pair = 1  # green
    elif user_state.upper() == "LIMITED":
        color_pair = 4  # yellow
    elif user_state.upper() == "CONTAINED":
        color_pair = 2  # red
    elif user_state.upper() == "DECEPTION":
        color_pair = 5  # magenta
    else:
        color_pair = 3
    return color_pair, icon


def draw_box(win, y, x, h, w, ascii_mode: bool):
    if ascii_mode:
        tl, tr, bl, br, hz, vt = "+", "+", "+", "+", "-", "|"
    else:
        tl, tr, bl, br, hz, vt = "┌", "┐", "└", "┘", "─", "│"
    win.addstr(y, x, tl + hz * (w - 2) + tr)
    for i in range(1, h - 1):
        win.addstr(y + i, x, vt + " " * (w - 2) + vt)
    win.addstr(y + h - 1, x, bl + hz * (w - 2) + br)


def wrap_text(text: str, width: int) -> List[str]:
    words = text.split()
    lines: List[str] = []
    cur = ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur.rstrip())
            cur = w + " "
        else:
            cur += w + " "
    if cur:
        lines.append(cur.rstrip())
    return lines or [""]


def render(stdscr, snap: Snapshot, unicode_mode: bool):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    min_w, min_h = 100, 30
    compact = w < min_w or h < min_h

    if h < 20 or w < 80:
        msg = "Terminal too small (min 80x20). Resize and press U to refresh."
        stdscr.addnstr(0, 0, msg[: w - 1], w - 1, curses.color_pair(2))
        stdscr.refresh()
        return

    # Colors (terminalによっては use_default_colors が失敗するため保護する)
    colors_on = curses.has_colors()
    if colors_on:
        try:
            curses.start_color()
            bg = -1
            try:
                curses.use_default_colors()
            except curses.error:
                bg = curses.COLOR_BLACK
            curses.init_pair(1, curses.COLOR_GREEN, bg)
            curses.init_pair(2, curses.COLOR_RED, bg)
            curses.init_pair(3, curses.COLOR_CYAN, bg)
            curses.init_pair(4, curses.COLOR_YELLOW, bg)
            curses.init_pair(5, curses.COLOR_MAGENTA, bg)
            curses.init_pair(6, curses.COLOR_WHITE, bg)
            curses.init_pair(7, curses.COLOR_BLACK, bg)
        except curses.error:
            colors_on = False

    def cp(idx: int):
        return curses.color_pair(idx) if colors_on else curses.A_BOLD

    # Status bar with icons, battery, and system metrics
    battery_icon = ""
    if snap.battery_pct >= 0:
        if snap.battery_pct >= 80:
            battery_icon = f"🔋 {snap.battery_pct}%" if unicode_mode else f"Bat:{snap.battery_pct}%"
        elif snap.battery_pct >= 20:
            battery_icon = f"🔋 {snap.battery_pct}%" if unicode_mode else f"Bat:{snap.battery_pct}%"
        else:
            battery_icon = f"🪫 {snap.battery_pct}%" if unicode_mode else f"LOW:{snap.battery_pct}%"
    
    # System metrics
    temp_icon = ""
    if snap.temp_c > 0:
        if snap.temp_c >= 70:
            temp_icon = f"🌡️ {snap.temp_c}°C" if unicode_mode else f"Temp:{snap.temp_c}C"
            temp_color = cp(2)  # red
        elif snap.temp_c >= 60:
            temp_icon = f"🌡️ {snap.temp_c}°C" if unicode_mode else f"Temp:{snap.temp_c}C"
            temp_color = cp(4)  # yellow
        else:
            temp_icon = f"🌡️ {snap.temp_c}°C" if unicode_mode else f"Temp:{snap.temp_c}C"
            temp_color = cp(1)  # green
    
    bar = (
        f"Azazel-Edge | "
        f"{'📶' if unicode_mode else 'WiFi'} SSID: {snap.ssid}  "
        f"{'⬇️' if unicode_mode else 'Down:'} {snap.down_if}  "
        f"{'⬆️' if unicode_mode else 'Up:'} {snap.up_if}  "
        f"{'Mode:'} {str(snap.mode.get('current_mode', 'shield')).upper()}  "
        f"{'🕐' if unicode_mode else 'Time:'} {snap.now_time}"
    )
    if battery_icon:
        bar += f"  {battery_icon}"
    stdscr.addnstr(0, 0, bar[: w - 1], w - 1, cp(6) | curses.A_BOLD)
    
    # 1行目の右側：システムメトリクス（温度のみ）
    if temp_icon:
        stdscr.addnstr(0, w - len(temp_icon) - 2, temp_icon, temp_color)

    # View line with age color coding
    live_age = "00:00:00"
    age_color = cp(1)  # green default
    age_icon = "🟢" if unicode_mode else "OK"
    if snap.snapshot_epoch:
        delta = max(0, int(time.time() - snap.snapshot_epoch))
        live_age = time.strftime("%H:%M:%S", time.gmtime(delta))
        if delta > 120:  # 2分以上
            age_color = cp(2)  # red
            age_icon = "🔴" if unicode_mode else "OLD"
        elif delta > 30:  # 30秒〜2分
            age_color = cp(4)  # yellow
            age_icon = "🟡" if unicode_mode else "OLD"
    
    # 2行目：CPU/メモリ + View情報
    color_note = "Color: ON" if colors_on else f"Color: OFF (TERM={os.environ.get('TERM','?')})"
    sys_metrics = f"CPU {snap.cpu_percent}% | Mem {snap.mem_used_mb}/{snap.mem_total_mb}MB ({snap.mem_percent}%)"
    view = f"{sys_metrics}  |  View: {snap.source} (manual)"
    stdscr.addnstr(1, 0, view[: w - 1], w - 1, cp(6))
    
    # 2行目の右側：Age情報
    age_text = f"Age: {age_icon} {live_age}"
    stdscr.addnstr(1, w - len(age_text) - 2, age_text, age_color | curses.A_BOLD)

    # Conclusion card
    card_w = w - 2
    card_h = 8
    card_y = 2  # 元々3だったが、ステータスが2行になったので2に
    draw_box(stdscr, card_y, 0, card_h, card_w, not unicode_mode)

    internal = snap.internal if isinstance(snap.internal, dict) else {}
    suspicion = _coerce_int(internal.get("suspicion", 0), 0)
    state_name = str(internal.get("state_name", "") or "").upper()
    web_state = _user_state_from_stage_name(state_name) if state_name else snap.user_state.upper()

    # リスク/疑わしさ表示（WebUI準拠）
    risk_color = cp(1)  # default green
    risk_icon = "🟢" if unicode_mode else "LOW"
    if snap.risk_score >= 70:
        risk_color = cp(2) | curses.A_BOLD  # red
        risk_icon = "🔴" if unicode_mode else "CRIT"
    elif snap.risk_score >= 50:
        risk_color = cp(2)  # red
        risk_icon = "🟠" if unicode_mode else "HIGH"
    elif snap.risk_score >= 30:
        risk_color = cp(4)  # yellow
        risk_icon = "🟡" if unicode_mode else "MED"

    risk_line = f"Suspicion: {suspicion}  |  Risk Score: {risk_icon} {snap.risk_score}/100"
    stdscr.addnstr(card_y + 1, 2, risk_line, risk_color | curses.A_BOLD)

    # State badge（2行目に移動）
    state_color, state_icon = color_for_state(web_state, unicode_mode)

    # 状態ラベル
    state_labels = {
        "CHECKING": "CHECKING",
        "SAFE": "SAFE",
        "LIMITED": "LIMITED",
        "CONTAINED": "CONTAINED",
        "DECEPTION": "DECEPTION",
    }
    state_label = state_labels.get(web_state.upper(), "CHECKING")
    badge = f" {state_icon} {state_label} "  # 括弧除去、前後にスペース

    # 脅威レベル（WebUIのしきい値: 15/30/50）
    threat_icons = ["🟢", "🟡", "🟠", "🔴", "🔴"] if unicode_mode else ["O", "!", "!", "X", "X"]
    filled = _filled_segments_from_suspicion(suspicion)
    threat_bar = "".join([threat_icons[i] if i < filled else ("⚪" if unicode_mode else ".") for i in range(5)])
    threat_label = _threat_label_from_suspicion(suspicion)
    threat_text = f"Threat: [{threat_bar}] {threat_label}"

    # 状態バッジを反転表示で強調（SAFE=緑背景、CONTAINED=赤背景など）
    # SAFEの場合は特に緑の太字を強調
    if web_state.upper() == "SAFE":
        badge_attr = cp(1) | curses.A_REVERSE | curses.A_BOLD if colors_on else curses.A_REVERSE | curses.A_BOLD
    else:
        badge_attr = cp(state_color) | curses.A_REVERSE | curses.A_BOLD if colors_on else curses.A_REVERSE

    stdscr.addnstr(card_y + 2, 2, badge, min(len(badge), card_w - 4), badge_attr)
    rec_text = f"  推奨：{snap.recommendation}"
    # 推奨文も状態に応じて強調
    rec_attr = cp(state_color) | curses.A_BOLD
    # 絵文字の実際の表示幅を考慮して、固定位置から表示（20文字目から開始）
    rec_start_pos = 20  # 固定位置
    stdscr.addnstr(card_y + 2, rec_start_pos, rec_text[: card_w - rec_start_pos - 2], rec_attr)
    reasons = "理由：" + " / ".join(snap.reasons or ["-"])
    # 理由を状態に応じた色で表示
    stdscr.addnstr(card_y + 3, 2, reasons[: card_w - 4], cp(state_color))

    # 脅威レベル表示
    threat_color = cp(2) if threat_label == "CRITICAL" else cp(4) if threat_label in ("HIGH", "MEDIUM") else cp(1)
    stdscr.addnstr(card_y + 4, 2, threat_text[: card_w - 4], threat_color | curses.A_BOLD)

    next_line = "次：" + (snap.next_action_hint or "再評価を待機")
    stdscr.addnstr(card_y + 5, 2, next_line[: card_w - 4], cp(6))

    monitoring = snap.monitoring if isinstance(snap.monitoring, dict) else {}
    monitor_line = (
        "Monitoring: "
        f"Suricata={monitoring.get('suricata', 'UNKNOWN')}  "
        f"OpenCanary={monitoring.get('opencanary', 'UNKNOWN')}  "
        f"ntfy={monitoring.get('ntfy', 'UNKNOWN')}"
    )
    stdscr.addnstr(card_y + 6, 2, monitor_line[: card_w - 4], cp(6))

    # Middle panes
    mid_y = card_y + card_h + 1
    pane_h = 10 if not compact else 7  # 高さを増やしてSuricata/Trafficを表示
    pane_w = (w - 3) // 2
    # Left: Connection
    draw_box(stdscr, mid_y, 0, pane_h, pane_w, not unicode_mode)
    stdscr.addnstr(mid_y, 2, "Connection", curses.color_pair(3) | curses.A_BOLD)
    
    connection = snap.connection if isinstance(snap.connection, dict) else {}
    wifi_state = str(connection.get("wifi_state", "DISCONNECTED") or "DISCONNECTED").upper()
    internet_check = str(connection.get("internet_check", "UNKNOWN") or "UNKNOWN").upper()
    captive_portal = str(connection.get("captive_portal", "NA") or "NA").upper()
    captive_reason = str(connection.get("captive_portal_reason", "") or "")

    portal_detected = captive_portal in ("YES", "SUSPECTED")
    portal_color = 2 if captive_portal == "YES" else 4 if captive_portal == "SUSPECTED" else 1
    captive_display = captive_portal if not portal_detected else f"{captive_portal} ({captive_reason})"

    # Gateway IP色分け (プライベートIP=緑、パブリック=黄)
    gw_ip = snap.gateway_ip
    gw_color = 3  # cyan default
    if gw_ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.")):
        gw_color = 1  # green (private)
        gw_display = f"🏠 {gw_ip}" if unicode_mode else gw_ip
    elif gw_ip != "-" and not gw_ip.startswith(("127.", "169.254.")):
        gw_color = 4  # yellow (public)
        gw_display = f"⚠️ {gw_ip}" if unicode_mode else f"PUB: {gw_ip}"
    else:
        gw_display = gw_ip

    if wifi_state in ("CONNECTED", "ONLINE"):
        wifi_state_color = 1
    elif wifi_state == "DISCONNECTED":
        wifi_state_color = 2
    else:
        wifi_state_color = 4

    if internet_check in ("OK", "YES", "ONLINE"):
        internet_color = 1
    elif internet_check in ("NO", "OFFLINE"):
        internet_color = 2
    elif internet_check in ("CAPTIVE", "SUSPECTED"):
        internet_color = 4
    else:
        internet_color = 6

    congestion = str(snap.channel_congestion or "unknown")
    ap_count = _coerce_int(snap.channel_ap_count, 0)
    scan_status = f"{ap_count} APs ({congestion})" if ap_count > 0 else "-"

    conn_lines = [
        ("SSID", snap.ssid, 6),
        ("BSSID", snap.bssid, 6),
        ("Signal", f"{snap.signal_dbm} dBm", 6),
        ("Gateway", gw_display, gw_color),
        ("State", wifi_state, wifi_state_color),
        ("Internet", internet_check, internet_color),
        ("Captive", captive_display, portal_color),
    ]

    # Signal強度を🟥🟧🟨🟩で視覚的に表現
    try:
        sig = float(snap.signal_dbm)
        if sig >= -50:
            # 非常に良好 (🟩🟩🟩🟩)
            sig_icon = "🟩🟩🟩🟩" if unicode_mode else "████"
            sig_color = 1  # green
        elif sig >= -60:
            # 良好 (🟩🟩🟩)
            sig_icon = "🟩🟩🟩" if unicode_mode else "███"
            sig_color = 1  # green
        elif sig >= -70:
            # 普通 (🟨🟨)
            sig_icon = "🟨🟨" if unicode_mode else "██"
            sig_color = 4  # yellow
        elif sig >= -80:
            # 弱い (🟧)
            sig_icon = "🟧" if unicode_mode else "█"
            sig_color = 4  # yellow/orange
        else:
            # 非常に弱い (🟥)
            sig_icon = "🟥" if unicode_mode else "█"
            sig_color = 2  # red
        conn_lines[2] = ("Signal", f"{sig_icon} {snap.signal_dbm} dBm", sig_color)
    except Exception:
        pass

    for i, (label, val, color_idx) in enumerate(conn_lines[: pane_h - 2]):
        line_text = f"{label}: {val}"[: pane_w - 4]
        attr = cp(color_idx) | curses.A_BOLD if label == "Captive" and portal_detected else cp(color_idx)
        stdscr.addnstr(mid_y + 1 + i, 2, line_text, attr)
    # Right: Control/Safety
    draw_box(stdscr, mid_y, pane_w + 1, pane_h, pane_w, not unicode_mode)
    stdscr.addnstr(mid_y, pane_w + 3, "Control / Safety", cp(3) | curses.A_BOLD)
    degrade = snap.degrade or {}
    probe = snap.probe or {}
    
    # QUIC状態の色分け (blocked=赤、allowed=緑)
    quic_status = snap.quic.lower()
    quic_color = 2 if "block" in quic_status else 1  # red or green
    quic_symbol = "⛔" if "block" in quic_status else "✓" if unicode_mode else "X" if "block" in quic_status else "OK"
    quic_display = f"{quic_symbol} {snap.quic.upper()}"
    
    # DoH状態の色分け
    doh_status = snap.doh.lower()
    doh_color = 2 if "block" in doh_status else 1
    doh_symbol = "⛔" if "block" in doh_status else "✓" if unicode_mode else "X" if "block" in doh_status else "OK"
    doh_display = f"{doh_symbol} {snap.doh.upper()}"
    
    # Degradeと速度（WebUI項目）
    deg_active = bool(degrade.get("on", False))
    deg_color = 4 if deg_active else 1
    deg_txt = "ON" if deg_active else "OFF"
    try:
        rate_mbps = float(degrade.get("rate_mbps", 0) or 0)
    except Exception:
        rate_mbps = 0.0
    speed_txt = f"{rate_mbps:.1f} / {rate_mbps:.1f} Mbps"

    # Probe（WebUI項目）
    blocked_count = _coerce_int(probe.get("blocked", 0), 0)
    tls_ok = _coerce_int(probe.get("tls_ok", 0), 0)
    tls_total = _coerce_int(probe.get("tls_total", 0), 0)
    if blocked_count > 0:
        probe_color = 2  # red
        probe_txt = f"{tls_ok}/{tls_total} OK ({blocked_count} blocked)"
    elif tls_total > 0 and tls_ok == tls_total:
        probe_color = 1  # green
        probe_txt = f"{tls_ok}/{tls_total} OK"
    else:
        probe_color = 4  # yellow
        probe_txt = f"{tls_ok}/{tls_total} OK"
    
    # DNS統計の色分け
    dns_ok = snap.dns_stats.get("ok", 0)
    dns_anomaly = snap.dns_stats.get("anomaly", 0)
    dns_blocked = snap.dns_stats.get("blocked", 0)
    dns_total = dns_ok + dns_anomaly + dns_blocked
    
    if dns_total > 0:
        dns_stat_text = f"DNS: ✅ {dns_ok} ⚠️ {dns_anomaly} 🔴 {dns_blocked}" if unicode_mode else f"DNS: OK:{dns_ok} WARN:{dns_anomaly} BLK:{dns_blocked}"
        if dns_blocked > 0:
            dns_stat_color = 2  # red
        elif dns_anomaly > 0:
            dns_stat_color = 4  # yellow
        else:
            dns_stat_color = 1  # green
    else:
        dns_stat_text = "DNS: (no data)"
        dns_stat_color = 6
    
    # Suricataアラート統計
    suri_total = snap.suricata_critical + snap.suricata_warning + snap.suricata_info
    if suri_total > 0:
        suri_text = f"IDS: 🔴 {snap.suricata_critical} ⚠️ {snap.suricata_warning} 🟢 {snap.suricata_info}" if unicode_mode else f"IDS: C:{snap.suricata_critical} W:{snap.suricata_warning} I:{snap.suricata_info}"
        if snap.suricata_critical > 0:
            suri_color = 2  # red
        elif snap.suricata_warning > 0:
            suri_color = 4  # yellow
        else:
            suri_color = 1  # green
    else:
        suri_text = "IDS: (no alerts)"
        suri_color = 6

    attack = snap.attack if isinstance(snap.attack, dict) else {}
    delay_active = bool(attack.get("canary_delay_active", False))
    delay_targets = _coerce_int(attack.get("canary_delay_target_count", 0), 0)
    if delay_active:
        delay_text = f"Delay=ACTIVE({delay_targets})"
    elif snap.user_state.upper() == "DECEPTION":
        delay_text = "Delay=ARMED"
    else:
        delay_text = "Delay=OFF"
    suri_text = f"{suri_text} {delay_text}"
    
    # ネットワークスループット
    traffic_text = f"Traffic: ↓ {snap.download_mbps:.1f} Mbps / ↑ {snap.upload_mbps:.1f} Mbps" if unicode_mode else f"Traffic: D:{snap.download_mbps:.1f} U:{snap.upload_mbps:.1f} Mbps"
    traffic_color = 6
    
    # パケットロス統計（優先度：中）
    loss_text = ""
    loss_color = 1  # default green
    if snap.packet_loss_percent > 0 or snap.latency_avg_ms > 0:
        loss_text = f"Loss: {snap.packet_loss_percent:.1f}% | RTT: {snap.latency_avg_ms:.1f}ms"
        if snap.packet_loss_percent >= 10:
            loss_color = 2  # red
        elif snap.packet_loss_percent >= 5:
            loss_color = 4  # yellow
        else:
            loss_color = 1  # green
    
    # DNS応答時間統計（優先度：中）
    dns_perf_text = ""
    dns_perf_color = 1
    if snap.dns_avg_ms > 0:
        cache_info = f" | Cache:{snap.dns_cache_hit_rate}%" if snap.dns_cache_hit_rate > 0 else ""
        timeout_info = f" | TO:{snap.dns_timeouts}" if snap.dns_timeouts > 0 else ""
        dns_perf_text = f"DNS Time: {snap.dns_avg_ms:.1f}ms{cache_info}{timeout_info}"
        if snap.dns_avg_ms >= 100:
            dns_perf_color = 4  # yellow
        elif snap.dns_timeouts > 0:
            dns_perf_color = 2  # red
        else:
            dns_perf_color = 1  # green
    
    # 累計トラフィック（優先度：中）
    traffic_cum_text = ""
    if snap.traffic_total_mb > 0:
        traffic_cum_text = f"Total: {snap.traffic_total_mb:.1f}MB (↓{snap.traffic_download_mb:.1f} ↑{snap.traffic_upload_mb:.1f})"
    
    ctl_items = [
        ("QUIC", quic_display, quic_color),
        ("DoH", doh_display, doh_color),
        ("Degrade", deg_txt, deg_color),
        ("Down/Up", speed_txt, 6),
        ("Probe", probe_txt, probe_color),
        ("IDS", suri_text.replace("IDS: ", ""), suri_color),
        ("DNS", dns_stat_text.replace("DNS: ", ""), dns_stat_color),
        ("Traffic", traffic_text.replace("Traffic: ", ""), traffic_color),
    ]
    
    for i, (label, val, color_idx) in enumerate(ctl_items[: pane_h - 2]):
        line_text = f"{label}: {val}"[: pane_w - 4]
        attr = cp(color_idx) | curses.A_BOLD if colors_on else curses.A_BOLD
        stdscr.addnstr(mid_y + 1 + i, pane_w + 3, line_text, attr)

    # Evidence
    ev_y = mid_y + pane_h + 1
    available = h - ev_y - 3
    if available < 3:
        available = 3
    ev_h = min(max(5, available), h - ev_y - 1)
    draw_box(stdscr, ev_y, 0, ev_h, w, not unicode_mode)
    stdscr.addnstr(ev_y, 2, "Evidence & State", cp(3) | curses.A_BOLD)

    state_metrics = (
        f"State: {state_label}  Suspicion: {suspicion}  "
        f"CPU Temp: {snap.temp_c:.1f}C  CPU: {snap.cpu_percent:.1f}%  Memory: {snap.mem_percent}%"
    )
    stdscr.addnstr(ev_y + 1, 2, state_metrics[: w - 4], cp(6))
    stdscr.addnstr(ev_y + 2, 2, f"Scan Results: {scan_status}"[: w - 4], cp(6))

    max_event_lines = max(0, ev_h - 5)
    if compact:
        max_event_lines = min(max_event_lines, 2)
    ev_lines = snap.evidence[-max_event_lines:] if max_event_lines > 0 else []

    # キーワードベースの色分け + 重要度マーク
    for i, ev in enumerate(ev_lines):
        ev_lower = ev.lower()
        severity_mark = "⚪" if unicode_mode else "·"  # default
        
        # 異常・エラー系 = 赤
        if any(kw in ev_lower for kw in ["blocked", "fail", "error", "mismatch", "hijack", "contain", "suspected", "anomaly"]):
            color = cp(2) | curses.A_BOLD  # red + bold
            severity_mark = "🔴" if unicode_mode else "X"
        # 警告・注意系 = 黄
        elif any(kw in ev_lower for kw in ["portal", "dns", "probe", "degrade", "warning", "suspect", "limited"]):
            color = cp(4)  # yellow
            severity_mark = "🟡" if unicode_mode else "!"
        # 成功・正常系 = 緑
        elif any(kw in ev_lower for kw in ["ok", "safe", "normal", "pass", "allow", "success"]):
            color = cp(1)  # green
            severity_mark = "🟢" if unicode_mode else "O"
        # アクション系 = シアン
        elif any(kw in ev_lower for kw in ["action", "command", "transition", "stage"]):
            color = cp(3)  # cyan
            severity_mark = "💠" if unicode_mode else ">"
        # その他 = デフォルト
        else:
            color = cp(6)
        
        # タイムスタンプ付き表示（簡易版：先頭に追加）
        ev_display = f"{severity_mark} {ev}"[: w - 4]
        stdscr.addnstr(ev_y + 3 + i, 2, ev_display, color)
    # decision line
    decision = f"Decision: State: {state_label}, Suspicion: {suspicion}"
    stdscr.addnstr(ev_y + ev_h - 2, 2, decision[: w - 4], cp(6))

    # 追加パネル：State遷移タイムラインとブロックドメイン（優先度：中）
    extra_y = ev_y + ev_h
    extra_h = h - extra_y - 4
    if extra_h >= 5:
        draw_box(stdscr, extra_y, 0, extra_h, w, not unicode_mode)
        stdscr.addnstr(extra_y, 2, "Analytics (State & Blocked)", cp(5) | curses.A_BOLD)
        
        # セッション稼働時間（優先度：低）
        uptime_str = time.strftime("%H:%M:%S", time.gmtime(snap.session_uptime))
        session_display = f"Session Uptime: ⏱️ {uptime_str}" if unicode_mode else f"Session Uptime: {uptime_str}"
        stdscr.addnstr(extra_y + 1, 2, session_display[: w - 4], cp(3) | curses.A_BOLD)
        
        # State遷移タイムライン
        timeline_display = f"Timeline: {snap.state_timeline}"
        stdscr.addnstr(extra_y + 2, 2, timeline_display[: w - 4], cp(6))
        
        # ブロックトップ5
        if snap.top_blocked:
            blocked_title = "Top Blocked:" if unicode_mode else "Top Blocked:"
            stdscr.addnstr(extra_y + 3, 2, blocked_title, cp(2) | curses.A_BOLD)
            for idx, (domain, count) in enumerate(snap.top_blocked[: extra_h - 5]):
                block_line = f"  {idx+1}. {domain} ({count}x)"
                stdscr.addnstr(extra_y + 4 + idx, 2, block_line[: w - 4], cp(2))
        else:
            no_blocks = "No blocked domains"
            stdscr.addnstr(extra_y + 3, 2, no_blocks[: w - 4], cp(1))

    # Actions + Hint (絵文字なし、シンプル表示)
    actions = "[U] Refresh  [A] Stage-Open  [R] Re-Probe  [C] Contain  [S] Shutdown  [B] Reboot  [L] Details  [M] Menu  [Q] Quit"
    
    # 状態遷移フロー表示
    state_flow = "Flow: PROBE → DEGRADED → NORMAL → ✅ SAFE" if unicode_mode else "Flow: PROBE->DEGRADED->NORMAL->SAFE"
    current_state = snap.internal.get("state_name", "-").upper() if isinstance(snap.internal, dict) else "-"
    if current_state in state_flow:
        # 現在位置を強調表示するため、別々に描画
        stdscr.addnstr(h - 3, 0, state_flow[: w - 1], cp(6))
    else:
        stdscr.addnstr(h - 3, 0, state_flow[: w - 1], cp(6))
    
    stdscr.addnstr(h - 2, 0, actions[: w - 1], cp(6) | curses.A_BOLD)
    hint = "Hint: この画面は自動更新しません。必要時に [U] で更新してください。"
    stdscr.addnstr(h - 1, 0, hint[: w - 1], cp(6))
    stdscr.refresh()


def details_view(stdscr, snap: Snapshot, unicode_mode: bool):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    stdscr.addnstr(0, 0, "Details (B=Back)", w - 1, curses.A_BOLD)
    # logs
    logs = snap.evidence[-30:]
    for i, ln in enumerate(logs[: h - 6]):
        stdscr.addnstr(1 + i, 0, ln[: w - 1], curses.color_pair(6))
    cur = snap.internal or {}
    info = [
        f"State: {cur.get('state_name','-')}",
        f"Suspicion: {cur.get('suspicion','-')}",
        f"Decay: {cur.get('decay','-')}",
        f"Rules: QUIC={snap.quic} DoH={snap.doh} DNS={snap.dns_mode}",
    ]
    base_y = h - 4
    for i, ln in enumerate(info):
        stdscr.addnstr(base_y + i, 0, ln[: w - 1], curses.color_pair(6))
    stdscr.refresh()
    while True:
        ch = stdscr.getch()
        if ch in (ord("b"), ord("B")):
            break


def confirm_keyword(stdscr, keyword: str) -> bool:
    h, w = stdscr.getmaxyx()
    prompt = f"Type {keyword} to confirm: "
    max_input = max(1, w - len(prompt) - 2)
    y = max(0, h - 1)

    stdscr.move(y, 0)
    stdscr.clrtoeol()
    stdscr.addnstr(y, 0, prompt, w - 1, curses.A_BOLD)
    stdscr.refresh()

    old_cursor = 0
    try:
        old_cursor = curses.curs_set(1)
    except Exception:
        old_cursor = 0
    curses.echo()
    typed = ""
    try:
        raw = stdscr.getstr(y, min(len(prompt), w - 2), max_input)
        typed = raw.decode("utf-8", errors="ignore").strip()
    except Exception:
        typed = ""
    finally:
        curses.noecho()
        try:
            curses.curs_set(old_cursor)
        except Exception:
            pass
        stdscr.move(y, 0)
        stdscr.clrtoeol()
        stdscr.refresh()

    return typed == keyword


def main():
    locale.setlocale(locale.LC_ALL, "")
    parser = argparse.ArgumentParser(description="Azazel-Edge manual-refresh TUI")
    parser.add_argument("--ascii", action="store_true", help="Force ASCII fallback")
    parser.add_argument("--unicode", action="store_true", help="Force Unicode box/icons")
    ui_group = parser.add_mutually_exclusive_group()
    ui_group.add_argument("--textual", action="store_true", help="Run Textual UI (default)")
    ui_group.add_argument("--curses", action="store_true", help="Run legacy curses UI")
    parser.add_argument("--menu", action="store_true", help="Open control menu on startup (Textual mode)")
    parser.add_argument("--enable-epd", action="store_true", help="Enable E-Paper display updates")
    parser.add_argument("--disable-epd", action="store_true", help="Disable E-Paper display updates")
    args = parser.parse_args()

    unicode_mode = detect_unicode(args.ascii, args.unicode)
    
    # EPD is enabled by default unless explicitly disabled.
    enable_epd = not args.disable_epd
    if args.enable_epd:
        enable_epd = True

    use_textual = not args.curses

    if use_textual:
        run_textual = None
        try:
            from .cli_unified_textual import run_textual
        except Exception:
            try:
                from cli_unified_textual import run_textual
            except Exception as exc:
                if args.textual:
                    print(f"[TUI] Textual mode unavailable: {exc}", file=sys.stderr)
                    sys.exit(1)
                print(
                    f"[TUI] Textual unavailable ({exc}); falling back to curses. "
                    "Use --curses to select it explicitly.",
                    file=sys.stderr,
                )
        if run_textual is not None:
            run_textual(
                load_snapshot_fn=load_snapshot,
                send_command_fn=send_command,
                update_epd_fn=update_epd,
                epd_fingerprint_fn=_epd_fingerprint,
                unicode_mode=unicode_mode,
                enable_epd=enable_epd,
                start_menu=args.menu,
            )
            return

    if args.menu:
        print("[TUI] --menu is Textual-only and is ignored in curses mode.", file=sys.stderr)

    snap = load_snapshot()
    
    # Initial EPD update
    last_epd_fp: Optional[Tuple[str, str, str, Optional[int], str]] = None
    if enable_epd:
        update_epd(snap, enable_epd)
        last_epd_fp = _epd_fingerprint(snap)

    def _loop(stdscr):
        nonlocal snap, last_epd_fp

        def _record_action(action: str, label: str) -> None:
            result = send_command(action)
            if isinstance(result, dict) and result.get("ok"):
                snap.evidence.append(f"• action: {label} command sent")
                return
            err = str((result or {}).get("error", "unknown error")) if isinstance(result, dict) else "unexpected response"
            snap.evidence.append(f"• action failed: {label} ({err})")

        while True:
            render(stdscr, snap, unicode_mode)
            ch = stdscr.getch()
            if ch in (ord("q"), ord("Q")):
                break
            elif ch in (ord("u"), ord("U")):
                snap = load_snapshot()
                fp = _epd_fingerprint(snap) if enable_epd else None
                if enable_epd and fp != last_epd_fp:
                    update_epd(snap, enable_epd)
                    last_epd_fp = fp
            elif ch in (ord("a"), ord("A")):
                _record_action("stage_open", "stage-open")
            elif ch in (ord("r"), ord("R")):
                _record_action("reprobe", "reprobe")
            elif ch in (ord("c"), ord("C")):
                _record_action("contain", "contain")
            elif ch in (ord("s"), ord("S")):
                if confirm_keyword(stdscr, "SHUTDOWN"):
                    _record_action("shutdown", "shutdown")
                else:
                    snap.evidence.append("• action canceled: shutdown")
            elif ch in (ord("b"), ord("B")):
                if confirm_keyword(stdscr, "REBOOT"):
                    _record_action("reboot", "reboot")
                else:
                    snap.evidence.append("• action canceled: reboot")
            elif ch in (ord("l"), ord("L")):
                details_view(stdscr, snap, unicode_mode)
            elif ch in (ord("m"), ord("M")):
                try:
                    menu_script = DEFAULT_ROOT / "py" / "azazel_menu.py"
                    cmd = ["python3", str(menu_script), "--textual"]
                    if enable_epd:
                        cmd.append("--enable-epd")
                    else:
                        cmd.append("--disable-epd")
                    subprocess.call(cmd)
                except Exception:
                    pass
            snap = snap  # no-op to keep reference

    curses.wrapper(_loop)


if __name__ == "__main__":
    main()
