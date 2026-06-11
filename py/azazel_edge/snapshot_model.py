from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Tuple


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
    dns_stats: Dict[str, int] = None
    threat_level: int = 0
    bssid_vendor: str = "-"
    battery_pct: int = -1
    channel_congestion: str = "unknown"
    channel_ap_count: int = 0
    recommended_channel: int = -1
    cpu_percent: float = 0.0
    mem_percent: int = 0
    mem_used_mb: int = 0
    mem_total_mb: int = 0
    temp_c: float = 0.0
    download_mbps: float = 0.0
    upload_mbps: float = 0.0
    session_uptime: int = 0
    suricata_critical: int = 0
    suricata_warning: int = 0
    suricata_info: int = 0
    packet_loss_percent: float = 0.0
    latency_avg_ms: float = 0.0
    latency_trend: List[float] = None
    dns_avg_ms: float = 0.0
    dns_cache_hit_rate: int = 0
    dns_timeouts: int = 0
    traffic_total_mb: float = 0.0
    traffic_download_mb: float = 0.0
    traffic_upload_mb: float = 0.0
    traffic_packets: int = 0
    state_timeline: str = "-"
    top_blocked: List[Tuple[str, int]] = None
    risk_score: int = 0

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
    threat_level = min(5, max(0, int(suspicion / 20)))
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
        evidence=data.get("evidence", [])[-6:],
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
