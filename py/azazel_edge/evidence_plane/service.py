from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from .bus import EvidenceBus
from .config_drift import build_config_drift_event
from .flow_min import read_flow_jsonl
from .noc_inventory import build_client_inventory_events
from .noc_probe import NocProbeAdapter
from .schema import EvidenceEvent
from .suricata import read_suricata_jsonl
from .syslog_min import adapt_syslog_line


class EvidencePlaneService:
    def __init__(self, bus: EvidenceBus):
        self.bus = bus
        self._own_bssid = str(os.environ.get("AZAZEL_WIFI_OWN_BSSID", "")).strip().lower()

    def dispatch_events(self, events: List[EvidenceEvent]) -> List[Dict[str, object]]:
        return self.bus.publish_many(events)

    def dispatch_suricata_jsonl(self, path: Path, limit: Optional[int] = None) -> List[Dict[str, object]]:
        return self.dispatch_events(read_suricata_jsonl(path, limit=limit))

    def dispatch_flow_jsonl(self, path: Path, limit: Optional[int] = None) -> List[Dict[str, object]]:
        return self.dispatch_events(read_flow_jsonl(path, limit=limit))

    def dispatch_noc_probe(self, adapter: Optional[NocProbeAdapter] = None, snapshot: Optional[Dict[str, object]] = None) -> List[Dict[str, object]]:
        probe = adapter or NocProbeAdapter()
        events = probe.collect(snapshot=snapshot if isinstance(snapshot, dict) else None)
        events.extend(build_client_inventory_events(events))
        return self.dispatch_events(events)

    def dispatch_config_drift(self, diff: Dict[str, object]) -> Dict[str, object]:
        return self.bus.publish(build_config_drift_event(diff))

    def dispatch_syslog_line(self, line: str) -> Dict[str, object]:
        return self.bus.publish(adapt_syslog_line(line))

    def dispatch_wifi_scan(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        congestion = str((scan_result or {}).get("congestion_level") or "unknown").strip().lower()
        event = EvidenceEvent.build(
            ts=None,
            source="wifi_channel_scanner",
            kind="noc_wifi",
            subject=f"wifi_congestion:{congestion}",
            severity=_wifi_congestion_severity(congestion),
            confidence=0.9,
            attrs={
                "trace_id": f"wifi-{uuid.uuid4().hex[:12]}",
                "congestion_level": congestion or "unknown",
                "ap_count": int((scan_result or {}).get("ap_count") or 0),
                "current_channel": int((scan_result or {}).get("current_channel") or 0),
                "recommended_channel": int((scan_result or {}).get("recommended_channel") or 0),
                "scan_success": bool((scan_result or {}).get("scan_success")),
                "observed_at": time.time(),
            },
        )
        published = self.dispatch_events([event])
        return dict(published[0]) if published else {}

    def dispatch_rogue_ap(self, current_ssid: str, nearby_aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        target_ssid = str(current_ssid or "").strip()
        if not target_ssid:
            return []
        own_bssid = str(self._own_bssid or "").strip().lower()
        rogues: List[Dict[str, Any]] = []
        for ap in nearby_aps or []:
            if not isinstance(ap, dict):
                continue
            ssid = str(ap.get("ssid") or "").strip()
            bssid = str(ap.get("bssid") or "").strip().lower()
            if not bssid:
                continue
            if ssid == target_ssid and own_bssid and bssid != own_bssid:
                rogues.append(ap)
        events: List[EvidenceEvent] = []
        for ap in rogues:
            bssid = str(ap.get("bssid") or "").strip().lower()
            signal = int(float(ap.get("signal") or 0))
            events.append(
                EvidenceEvent.build(
                    ts=None,
                    source="wifi_scanner",
                    kind="noc_wifi_rogue_ap",
                    subject=f"rogue_ap:{target_ssid}:{bssid}",
                    severity=4,
                    confidence=0.95,
                    attrs={
                        "trace_id": f"rogue-{uuid.uuid4().hex[:12]}",
                        "ssid": target_ssid,
                        "bssid": bssid,
                        "signal": signal,
                        "own_bssid": own_bssid,
                        "detection": "evil_twin",
                    },
                )
            )
        return self.dispatch_events(events) if events else []


def _wifi_congestion_severity(level: str | None) -> int:
    return {"none": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(level or "low").lower(), 1)
