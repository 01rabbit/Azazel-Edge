#!/usr/bin/env python3
"""
Lightweight network health probe for Azazel-Edge.

Borrowed/trimmed from Azazel-Gadget first_minute probes + wifi safety checks.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class NetworkHealthMonitor:
    def __init__(
        self,
        cache_ttl_sec: float = 25.0,
        captive_url: str = "http://connectivitycheck.gstatic.com/generate_204",
        known_wifi_db: Optional[Path] = None,
    ):
        self.cache_ttl_sec = max(5.0, float(cache_ttl_sec))
        self.captive_url = captive_url
        self.known_wifi_db = known_wifi_db or Path("/etc/azazel-edge/known_wifi.json")
        self._last_ts = 0.0
        self._last_result: Dict[str, Any] = {}

    def assess(self, iface: str, gateway_ip: str = "") -> Dict[str, Any]:
        now = time.time()
        if self._last_result and (now - self._last_ts) < self.cache_ttl_sec:
            return dict(self._last_result)

        iface = str(iface or "").strip()
        if not iface or iface in {"-", "none"}:
            result = self._na_result("NO_IFACE")
            self._store(result)
            return result

        ready = self._iface_ready(iface)
        if not ready["ready"]:
            result = self._na_result(str(ready["reason"]))
            result["iface"] = iface
            self._store(result)
            return result

        link = self._link_state(iface)
        wifi_tags = self._wifi_tags(link)
        captive = self._probe_captive_portal(iface)
        route_anomaly = self._probe_route(iface)
        dns_mismatch = self._probe_dns_compare()

        signals: List[str] = []
        if wifi_tags:
            signals.extend(wifi_tags)
        if captive["captive_portal"] in {"YES", "SUSPECTED"}:
            signals.append("captive_portal")
        if route_anomaly:
            signals.append("route_anomaly")
        if dns_mismatch >= 2:
            signals.append("dns_mismatch")

        status = "SAFE"
        if "captive_portal" in signals or "evil_ap" in signals or "arp_spoof" in signals:
            status = "RISKY"
        elif signals:
            status = "SUSPECTED"

        internet_check = self._internet_check(captive)
        result = {
            "status": status,
            "internet_check": internet_check,
            "iface": iface,
            "link": link,
            "signals": sorted(set(signals)),
            "wifi_tags": sorted(set(wifi_tags)),
            "captive_portal": captive["captive_portal"],
            "captive_portal_reason": captive["captive_portal_reason"],
            "dns_mismatch": dns_mismatch,
            "route_anomaly": route_anomaly,
            "checked_at_epoch": now,
        }
        self._store(result)
        return result

    @staticmethod
    def _internet_check(captive: Dict[str, str]) -> str:
        portal = str(captive.get("captive_portal") or "NA").upper()
        reason = str(captive.get("captive_portal_reason") or "").upper()
        if portal == "NO" or reason == "HTTP_204":
            return "OK"
        if portal in {"YES", "SUSPECTED"}:
            return "FAIL"
        if reason.startswith("CURL_ERR_") or reason == "TIMEOUT":
            return "FAIL"
        return "UNKNOWN"

    def _store(self, payload: Dict[str, Any]) -> None:
        self._last_ts = time.time()
        self._last_result = dict(payload)

    @staticmethod
    def _na_result(reason: str) -> Dict[str, Any]:
        return {
            "status": "NA",
            "internet_check": "N/A",
            "signals": [],
            "wifi_tags": [],
            "captive_portal": "NA",
            "captive_portal_reason": reason,
            "dns_mismatch": 0,
            "route_anomaly": False,
            "checked_at_epoch": time.time(),
        }

    @staticmethod
    def _run(cmd: List[str], timeout: float = 3.0) -> str:
        try:
            out = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return out.stdout or ""
        except Exception:
            return ""

    def _iface_ready(self, iface: str) -> Dict[str, Any]:
        try:
            link_raw = self._run(["ip", "-j", "link", "show", "dev", iface], timeout=2)
            link_data = json.loads(link_raw) if link_raw else []
            if not link_data:
                return {"ready": False, "reason": "NOT_FOUND"}
            oper = str(link_data[0].get("operstate", "")).upper()
            if oper != "UP":
                return {"ready": False, "reason": "LINK_DOWN"}
        except Exception:
            return {"ready": False, "reason": "NOT_FOUND"}

        try:
            addr_raw = self._run(["ip", "-j", "-4", "addr", "show", "dev", iface], timeout=2)
            addr_data = json.loads(addr_raw) if addr_raw else []
            for entry in addr_data:
                for info in entry.get("addr_info", []) or []:
                    if info.get("family") == "inet" and info.get("scope") != "host" and info.get("local"):
                        return {"ready": True, "reason": "READY"}
        except Exception:
            pass
        return {"ready": False, "reason": "NO_IP"}

    def _link_state(self, iface: str) -> Dict[str, str]:
        out = self._run(["iw", "dev", iface, "link"], timeout=2)
        if "Not connected" in out:
            return {"connected": "0"}
        link: Dict[str, str] = {"connected": "1"}
        for line in out.splitlines():
            s = line.strip()
            if s.startswith("Connected to"):
                parts = s.split()
                if len(parts) >= 3:
                    link["bssid"] = parts[2].lower()
            elif s.startswith("SSID:"):
                link["ssid"] = s.split("SSID:", 1)[1].strip()
            elif s.startswith("freq:"):
                link["freq_mhz"] = s.split("freq:", 1)[1].strip().split()[0]
            elif s.startswith("signal:"):
                link["signal"] = s.split("signal:", 1)[1].strip().split()[0]
        return link

    def _wifi_tags(self, link: Dict[str, str]) -> List[str]:
        tags: List[str] = []
        if link.get("connected") != "1":
            return tags
        ssid = str(link.get("ssid") or "")
        bssid = str(link.get("bssid") or "").lower()
        signal = str(link.get("signal") or "")
        try:
            if signal and float(signal) <= -80:
                tags.append("weak_signal")
        except Exception:
            pass

        if not self.known_wifi_db.exists():
            return tags
        try:
            known = json.loads(self.known_wifi_db.read_text(encoding="utf-8"))
            profile = known.get(ssid, {}) if isinstance(known, dict) else {}
            allowed = {str(x).lower() for x in profile.get("bssids", [])} if isinstance(profile, dict) else set()
            if allowed and bssid and bssid not in allowed:
                tags.append("evil_ap")
        except Exception:
            pass
        return tags

    def _probe_captive_portal(self, iface: str) -> Dict[str, str]:
        parsed = urlparse(self.captive_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return {"captive_portal": "SUSPECTED", "captive_portal_reason": "INVALID_URL"}

        try:
            proc = subprocess.run(
                [
                    "curl",
                    "--interface",
                    iface,
                    "-sS",
                    "--max-time",
                    "4",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    self.captive_url,
                ],
                capture_output=True,
                text=True,
                timeout=6,
            )
            http_code = (proc.stdout or "").strip()
            if proc.returncode != 0:
                return {"captive_portal": "NA", "captive_portal_reason": f"CURL_ERR_{proc.returncode}"}
            if http_code == "204":
                return {"captive_portal": "NO", "captive_portal_reason": "HTTP_204"}
            if http_code.startswith("30"):
                return {"captive_portal": "YES", "captive_portal_reason": "HTTP_30X"}
            if http_code == "200":
                return {"captive_portal": "SUSPECTED", "captive_portal_reason": "HTTP_200_BODY"}
            return {"captive_portal": "NA", "captive_portal_reason": f"HTTP_{http_code or '000'}"}
        except Exception:
            return {"captive_portal": "NA", "captive_portal_reason": "TIMEOUT"}

    @staticmethod
    def _probe_route(upstream: str) -> bool:
        out = NetworkHealthMonitor._run(["ip", "route", "show", "default"], timeout=2)
        lines = [ln for ln in out.splitlines() if ln.strip()]
        if not lines:
            return True
        return all(f"dev {upstream}" not in ln for ln in lines)

    @staticmethod
    def _probe_dns_compare() -> int:
        names = ("example.com", "cloudflare.com", "openai.com")
        mismatch = 0
        for name in names:
            default_ips: set[str] = set()
            ref_ips: set[str] = set()
            try:
                info = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
                default_ips = {item[4][0] for item in info if item and item[4]}
            except Exception:
                mismatch += 1
                continue

            for rrtype in ("A", "AAAA"):
                dig = NetworkHealthMonitor._run(
                    ["dig", "@9.9.9.9", name, rrtype, "+short", "+time=2", "+tries=1"],
                    timeout=3,
                )
                if dig:
                    ref_ips.update({ln.strip() for ln in dig.splitlines() if ln.strip()})
            else:
                if not ref_ips:
                    ref_ips = default_ips

            if default_ips != ref_ips:
                mismatch += 1
        return mismatch
