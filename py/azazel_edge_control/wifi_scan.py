#!/usr/bin/env python3
"""
Wi-Fi Scan Module for Azazel-Edge Control Daemon

Performs Wi-Fi AP scan using NetworkManager/nmcli:
- Returns deduplicated AP list (strongest per SSID)
"""

import os
import subprocess
import re
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Import common scanner module
sys.path.insert(0, str(Path(__file__).parent.parent))
from azazel_edge.sensors.wifi_scanner import scan_and_parse, get_security_label

logger = logging.getLogger("wifi_scan")


def _nmcli_env() -> Dict[str, str]:
    """The environment every nmcli call of the control daemon runs with
    (wifi_scan, wifi_connect, daemon): the daemon's own,
    with the locale pinned to C.UTF-8 (Edge#477). nmcli translates its
    messages, and the UUID of a new or cloned profile is read from one
    ("Connection '<name>' (<uuid>) successfully added."); under C.UTF-8 they
    are the untranslated ones that pattern expects, whatever the device's
    locale. C.UTF-8 rather than C keeps non-ASCII SSIDs in nmcli's output as
    they are (UTF-8) instead of escaped for an ASCII charset."""
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("LANG", "LANGUAGE") and not key.startswith("LC_")
    }
    env["LC_ALL"] = "C.UTF-8"
    env["LANG"] = "C.UTF-8"
    return env


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


# /sys/class/net (replaced in tests).
SYS_CLASS_NET = Path("/sys/class/net")

# Shown when every wireless interface serves the internal LAN (Pi 5: the
# on-board wlan0 is the internal AP and there is no second radio).
NO_UPLINK_WIRELESS_ERROR = (
    "No wireless interface for the uplink: every wireless interface serves the internal LAN "
    "(AP mode or a port of the internal bridge). Add a USB Wi-Fi adapter (or use a USB Ethernet "
    "adapter) for the uplink."
)


def _iw_dev_interfaces() -> List[Dict[str, str]]:
    """Wireless interfaces from ``iw dev``: ``[{"name", "type"}]`` in order."""
    result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=2)
    if result.returncode != 0:
        # An unanswered query is not "no wireless interface" (fail closed).
        detail = (result.stderr or result.stdout or "").strip()[:200] or f"exit {result.returncode}"
        raise RuntimeError(detail)
    interfaces: List[Dict[str, str]] = []
    for raw in (result.stdout or "").splitlines():
        line = raw.strip()
        match = re.match(r"Interface\s+(\S+)$", line)
        if match:
            interfaces.append({"name": match.group(1), "type": ""})
            continue
        match = re.match(r"type\s+(.+)$", line)
        if match and interfaces and not interfaces[-1]["type"]:
            interfaces[-1]["type"] = match.group(1).strip()
    return interfaces


class InternalLanUnknown(RuntimeError):
    """Which interfaces serve the internal LAN could not be determined (a
    query failed). Callers fail closed: no interface is picked or touched."""


def nm_ap_profiles() -> Dict[str, str]:
    """NetworkManager Wi-Fi profiles in AP mode (the internal AP,
    ``lan-wlan0-ap``): ``{profile name: interface name ("" if unbound)}``.

    Raises ``InternalLanUnknown`` when nmcli fails: an unanswered query must
    not make the AP's interface look free."""
    profiles: Dict[str, str] = {}
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"],
            env=_nmcli_env(), capture_output=True, text=True, timeout=3,
        )
    except Exception as exc:
        raise InternalLanUnknown(f"nmcli con show failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or "").strip()[:200] or f"exit {result.returncode}"
        raise InternalLanUnknown(f"nmcli con show failed: {detail}")
    for line in (result.stdout or "").splitlines():
        name, con_type = _split_nmcli_terse_line(line, 2)
        if con_type != "802-11-wireless" or not name:
            continue
        try:
            detail_proc = subprocess.run(
                ["nmcli", "--escape", "no", "-g", "802-11-wireless.mode,connection.interface-name",
                 "con", "show", name],
                env=_nmcli_env(), capture_output=True, text=True, timeout=3,
            )
        except Exception as exc:
            raise InternalLanUnknown(f"nmcli con show {name!r} failed: {exc}") from exc
        if detail_proc.returncode != 0:
            detail = (detail_proc.stderr or "").strip()[:200] or f"exit {detail_proc.returncode}"
            raise InternalLanUnknown(f"nmcli con show {name!r} failed: {detail}")
        values = (detail_proc.stdout or "").splitlines() + ["", ""]
        if values[0].strip().lower() == "ap":
            profiles[name] = values[1].strip()
    return profiles


def internal_lan_interfaces(sys_class_net: Optional[Path] = None) -> set:
    """Interfaces that serve the internal LAN and must never be used (or
    scanned on, or taken down) as the uplink: a wireless interface in AP
    mode, the interface an AP-mode NetworkManager profile is bound to, a
    bridge, and a port of a bridge (``br0`` and its members).

    Raises ``InternalLanUnknown`` when any of the sources cannot be read."""
    net = sys_class_net or SYS_CLASS_NET
    internal: set = set()
    try:
        for entry in net.iterdir():
            if (entry / "bridge").exists() or (entry / "brport").exists():
                internal.add(entry.name)
    except OSError as exc:
        raise InternalLanUnknown(f"reading {net} failed: {exc}") from exc
    try:
        for iface in _iw_dev_interfaces():
            if iface["type"].lower() == "ap":
                internal.add(iface["name"])
    except Exception as exc:
        raise InternalLanUnknown(f"iw dev failed: {exc}") from exc
    # The AP's interface even while the AP is down.
    internal |= {iface for iface in nm_ap_profiles().values() if iface}
    return internal


def select_uplink_wireless_interface() -> Tuple[Optional[str], str]:
    """``(interface, "")`` for the uplink (scan and connect), or
    ``(None, error)`` with the cause.

    Interfaces that serve the internal LAN (``internal_lan_interfaces``) are
    never returned: on a Pi 5 the on-board wlan0 is the internal AP, and
    connecting it to another network would take the AP down. If that set
    cannot be determined, none is returned (fail closed). Among the rest,
    wlan0 is preferred, then the first one ``iw dev`` lists."""
    try:
        interfaces = [iface["name"] for iface in _iw_dev_interfaces()]
    except Exception as exc:
        error = f"No wireless interface found (iw dev failed: {exc})"
        logger.warning(error)
        return None, error
    if not interfaces:
        return None, "No wireless interface found"
    try:
        internal = internal_lan_interfaces()
    except InternalLanUnknown as exc:
        error = (f"Cannot tell which wireless interface serves the internal AP ({exc}); "
                 "no interface is used for the uplink")
        logger.warning(error)
        return None, error
    candidates = [name for name in interfaces if name not in internal]
    if not candidates:
        error = (f"{NO_UPLINK_WIRELESS_ERROR} Wireless interfaces serving the internal LAN: "
                 f"{', '.join(interfaces)}.")
        logger.warning(error)
        return None, error
    return ("wlan0" if "wlan0" in candidates else candidates[0]), ""


def get_wireless_interface() -> Optional[str]:
    """The uplink wireless interface, or None (see
    ``select_uplink_wireless_interface`` for the rules and the cause)."""
    return select_uplink_wireless_interface()[0]


def no_wireless_interface_error() -> str:
    """The error to show when ``get_wireless_interface`` found none."""
    return select_uplink_wireless_interface()[1] or "No wireless interface found"


def check_networkmanager(iface: str) -> bool:
    """Check if NetworkManager manages this interface"""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE", "dev"],
            env=_nmcli_env(),
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
            env=_nmcli_env(),
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
                env=_nmcli_env(),
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
                env=_nmcli_env(),
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
            env=_nmcli_env(),
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
            env=_nmcli_env(),
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
    iface, error = select_uplink_wireless_interface()
    if not iface:
        return {
            "ok": False,
            "error": error,
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
