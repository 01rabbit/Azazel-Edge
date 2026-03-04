#!/usr/bin/env python3
"""
Wi-Fi Scan Module for Azazel-Edge Control Daemon

Performs Wi-Fi AP scan using NetworkManager/nmcli:
- Returns deduplicated AP list (strongest per SSID)
"""

import subprocess
import re
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import common scanner module
sys.path.insert(0, str(Path(__file__).parent.parent))
from azazel_edge.sensors.wifi_scanner import scan_and_parse, get_security_label

logger = logging.getLogger("wifi_scan")


def _split_nmcli_terse_line(line: str, expected_fields: int) -> List[str]:
    """
    Split nmcli -t output by unescaped ':'.
    nmcli escapes ':' inside fields as '\\:' (for BSSID, SSID with colon, etc.).
    """
    fields: List[str] = []
    cur: List[str] = []
    escaped = False

    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == ":" and len(fields) < expected_fields - 1:
            fields.append("".join(cur))
            cur = []
            continue
        cur.append(ch)

    if escaped:
        cur.append("\\")
    fields.append("".join(cur))

    if len(fields) < expected_fields:
        fields.extend([""] * (expected_fields - len(fields)))
    return fields[:expected_fields]


def _nmcli_security_label(security_raw: str) -> str:
    sec = (security_raw or "").upper()
    if not sec or sec == "--":
        return "OPEN"
    if "WPA3" in sec or "SAE" in sec:
        return "WPA3"
    if "WPA2" in sec or "RSN" in sec:
        return "WPA2"
    if "WPA" in sec:
        return "WPA"
    if "WEP" in sec:
        return "WEP"
    return "UNKNOWN"


def _signal_percent_to_dbm(signal_raw: str) -> int:
    """
    Convert nmcli SIGNAL(0-100) to approximate RSSI dBm.
    Approximation used: dBm ~= (percent / 2) - 100
    """
    if signal_raw.isdigit():
        pct = max(0, min(100, int(signal_raw)))
        return int(round((pct / 2.0) - 100.0))
    return -100


def get_wireless_interface() -> Optional[str]:
    """Detect wireless interface (prefer wlan0, else auto-detect)"""
    try:
        # Try wlan0 first
        result = subprocess.run(
            ["iw", "dev", "wlan0", "info"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            return "wlan0"
        
        # Auto-detect via iw dev
        result = subprocess.run(
            ["iw", "dev"],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        # Parse: Interface <name>
        match = re.search(r"Interface\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
        
        return None
    except Exception as e:
        logger.warning(f"Failed to detect wireless interface: {e}")
        return None


def check_networkmanager(iface: str) -> bool:
    """Check if NetworkManager manages this interface"""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE", "dev"],
            capture_output=True,
            text=True,
            timeout=2
        )
        return iface in result.stdout
    except:
        return False


def get_saved_networks_nm(include_open: bool = False) -> set:
    """Get saved network SSIDs from NetworkManager.

    By default, OPEN profiles are excluded because they are treated as ephemeral.
    """
    try:
        result = subprocess.run(
            [
                "nmcli",
                "-t",
                "-f",
                "NAME,TYPE",
                "con",
                "show",
            ],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        saved = set()
        for line in result.stdout.splitlines():
            parts = _split_nmcli_terse_line(line, 2)
            if len(parts) != 2:
                continue
            name, con_type = parts
            if con_type != "802-11-wireless":
                continue
            ssid_result = subprocess.run(
                ["nmcli", "-g", "802-11-wireless.ssid", "con", "show", name],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if ssid_result.returncode != 0:
                continue
            ssid_line = (ssid_result.stdout or "").strip()
            ssid_value = ssid_line.splitlines()[0] if ssid_line else ""
            if not ssid_value:
                continue

            if include_open:
                saved.add(ssid_value)
                continue

            key_mgmt_result = subprocess.run(
                ["nmcli", "-g", "802-11-wireless-security.key-mgmt", "con", "show", name],
                capture_output=True,
                text=True,
                timeout=2,
            )
            if key_mgmt_result.returncode != 0:
                continue
            key_mgmt_line = (key_mgmt_result.stdout or "").strip()
            key_mgmt = key_mgmt_line.splitlines()[0].strip().lower() if key_mgmt_line else ""
            if key_mgmt in {"", "--", "none", "(none)"}:
                continue
            saved.add(ssid_value)
        return saved
    except Exception as e:
        logger.warning(f"Failed to get saved networks from nmcli: {e}")
        return set()


def scan_with_iw(iface: str, saved_ssids: set) -> List[Dict[str, Any]]:
    """Scan Wi-Fi using iw (low-level) - now uses common scanner"""
    try:
        # Use common scanner module
        aps = scan_and_parse(iface, deduplicate=True, keep_hidden=False)
        
        # Mark saved networks and add security label
        for ap in aps:
            ap["saved"] = ap["ssid"] in saved_ssids
            ap["security"] = get_security_label(ap)
            ap["channel"] = int(ap["chan"]) if ap.get("chan") else 0
            # Convert float signal to int for consistency
            if ap["signal"] is not None:
                ap["signal_dbm"] = int(ap["signal"])
            else:
                ap["signal_dbm"] = -100
        
        return aps
    
    except Exception as e:
        logger.error(f"iw scan failed: {e}")
        return []


def scan_with_nmcli(iface: str, saved_ssids: set) -> List[Dict[str, Any]]:
    """Scan Wi-Fi using nmcli (NetworkManager)"""
    try:
        # Trigger rescan
        subprocess.run(
            ["nmcli", "dev", "wifi", "rescan", "ifname", iface],
            capture_output=True,
            timeout=10
        )
        
        # Get scan results
        result = subprocess.run(
            [
                "nmcli",
                "-t",
                "--escape",
                "yes",
                "-f",
                "SSID,BSSID,CHAN,SIGNAL,SECURITY",
                "dev",
                "wifi",
                "list",
                "ifname",
                iface,
            ],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0:
            return []
        
        aps = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue

            ssid, bssid, chan, signal, security_raw = _split_nmcli_terse_line(line, 5)
            if not ssid:
                continue

            channel = 0
            ch_match = re.search(r"\d+", chan or "")
            if ch_match:
                channel = int(ch_match.group(0))

            signal_pct = int(signal) if signal.isdigit() else None
            aps.append({
                "ssid": ssid,
                "bssid": bssid if bssid != "--" else "unknown",
                "channel": channel,
                "signal_percent": signal_pct,
                "signal_dbm": _signal_percent_to_dbm(signal),
                "security": _nmcli_security_label(security_raw),
                "saved": ssid in saved_ssids
            })
        
        return aps
    
    except Exception as e:
        logger.error(f"nmcli scan failed: {e}")
        return []


def deduplicate_aps(aps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate by SSID, keep strongest signal.
    Note: Common scanner already does this, but kept for nmcli path compatibility.
    """
    ssid_map = {}
    
    for ap in aps:
        ssid = ap["ssid"]
        if ssid not in ssid_map or ap["signal_dbm"] > ssid_map[ssid]["signal_dbm"]:
            ssid_map[ssid] = ap
    
    # Sort: strongest signal first, then alpha by SSID
    result = sorted(ssid_map.values(), key=lambda x: (-x["signal_dbm"], x["ssid"]))
    return result


def scan_wifi() -> Dict[str, Any]:
    """
    Main entry point: Auto-detect environment and scan Wi-Fi
    
    Returns:
        {
            "ok": bool,
            "aps": [{"ssid", "bssid", "signal_dbm", "channel", "security", "saved"}],
            "ts": str,
            "error": str (if failed)
        }
    """
    import time
    
    # Detect wireless interface
    iface = get_wireless_interface()
    if not iface:
        return {
            "ok": False,
            "error": "No wireless interface found",
            "ts": time.time()
        }
    
    logger.info(f"Using wireless interface: {iface}")

    # Saved SSIDs are managed by NetworkManager; scanning itself can still fallback to iw.
    saved_ssids = get_saved_networks_nm()
    aps = scan_with_iw(iface, saved_ssids)

    if aps:
        logger.info("Using iw scan results")
    else:
        if not check_networkmanager(iface):
            return {
                "ok": False,
                "error": "Scan failed (iw unavailable) and NetworkManager is not managing interface",
                "ts": time.time()
            }
        logger.info("Using NetworkManager for scan")
        aps = scan_with_nmcli(iface, saved_ssids)
    
    if not aps:
        return {
            "ok": False,
            "error": "Scan returned no results",
            "ts": time.time()
        }
    
    # Deduplicate
    aps = deduplicate_aps(aps)
    
    return {
        "ok": True,
        "aps": aps,
        "ts": time.time()
    }


if __name__ == "__main__":
    # Test mode
    logging.basicConfig(level=logging.INFO)
    result = scan_wifi()
    print(json.dumps(result, indent=2))
