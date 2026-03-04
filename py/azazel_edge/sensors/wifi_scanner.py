#!/usr/bin/env python3
"""
Common Wi-Fi Scanner Module
Shared by ssid_list.py (TUI) and wifi_scan.py (Web UI backend)

Provides:
- iw scan output parsing
- SSID deduplication
- Security type detection (OPEN/WPA/WPA2/WPA3)
"""

import subprocess
import re
from typing import List, Dict, Any, Optional


def run_iw_scan(iface: str) -> Optional[str]:
    """
    Run `iw dev <iface> scan` and return stdout text.
    Returns None on failure.
    """
    try:
        result = subprocess.run(
            ["/sbin/iw", "dev", iface, "scan"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception:
        return None


def parse_iw_scan(text: str) -> List[Dict[str, Any]]:
    """
    Parse `iw dev <iface> scan` output into structured AP list.
    
    Returns:
        List of dicts with keys:
        - bssid: str (MAC address)
        - ssid: str (network name, empty for hidden)
        - freq: int (MHz)
        - chan: int (channel number)
        - signal: float (dBm)
        - rsn: bool (WPA2/WPA3)
        - wpa: bool (WPA)
        - wpa3: bool (SAE detected)
    """
    nets = []
    cur = None
    rsn_block = False
    wpa_block = False
    
    for line in text.splitlines():
        line = line.rstrip()
        
        # New BSS entry
        m_bss = re.match(r"^BSS\s+([0-9a-f:]{17})", line)
        if m_bss:
            if cur:
                nets.append(cur)
            cur = {
                "bssid": m_bss.group(1),
                "ssid": "",
                "freq": None,
                "chan": None,
                "signal": None,
                "rsn": False,
                "wpa": False,
                "wpa3": False,
            }
            rsn_block = False
            wpa_block = False
            continue
        
        if cur is None:
            continue
        
        # SSID
        if line.strip().startswith("SSID:"):
            cur["ssid"] = line.split("SSID:", 1)[1].strip()
            continue
        
        # Frequency
        if line.strip().startswith("freq:"):
            try:
                freq_text = line.split("freq:", 1)[1].strip()
                cur["freq"] = int(float(freq_text))
            except Exception:
                pass
            continue
        
        # Signal strength
        if line.strip().startswith("signal:"):
            # e.g. "signal: -51.00 dBm"
            try:
                cur["signal"] = float(line.split("signal:", 1)[1].split("dBm")[0].strip())
            except Exception:
                pass
            continue
        
        # Security blocks
        if line.strip().startswith("RSN:"):
            cur["rsn"] = True
            rsn_block = True
            wpa_block = False
            continue
        
        if line.strip().startswith("WPA:"):
            cur["wpa"] = True
            wpa_block = True
            rsn_block = False
            continue
        
        # WPA3 (SAE) detection within RSN/WPA block
        if rsn_block or wpa_block:
            if "SAE" in line:
                cur["wpa3"] = True
        
        # Block termination heuristic
        if line and not line.startswith("\t") and not line.startswith(" "):
            rsn_block = False
            wpa_block = False
    
    # Add last AP
    if cur:
        nets.append(cur)
    
    # Calculate channel from frequency
    for n in nets:
        f = n.get("freq")
        ch = None
        if f:
            if 2412 <= f <= 2472:
                ch = (f - 2407) // 5
            elif f == 2484:
                ch = 14
            elif 5000 <= f <= 5900:
                ch = (f - 5000) // 5
        n["chan"] = ch
    
    return nets


def get_security_label(ap: Dict[str, Any]) -> str:
    """
    Return human-readable security label.
    
    Returns:
        "OPEN", "WPA", "WPA2", "WPA3", "WPA3/WPA2"
    """
    if ap.get("rsn") or ap.get("wpa"):
        if ap.get("wpa3"):
            return "WPA3" if not ap.get("rsn") else "WPA3/WPA2"
        return "WPA2" if ap.get("rsn") else "WPA"
    return "OPEN"


def deduplicate_by_ssid(aps: List[Dict[str, Any]], keep_hidden: bool = False) -> List[Dict[str, Any]]:
    """
    Deduplicate APs by SSID, keeping the strongest signal per SSID.
    
    Args:
        aps: List of AP dicts
        keep_hidden: If True, treat each hidden SSID as unique by BSSID
    
    Returns:
        Deduplicated list sorted by signal strength (strongest first)
    """
    best = {}
    
    for ap in aps:
        ssid = ap["ssid"]
        
        # Handle hidden SSIDs
        if not ssid:
            if keep_hidden:
                # Treat each hidden AP as unique
                key = f"<hidden:{ap['bssid']}>"
            else:
                # Skip hidden SSIDs
                continue
        else:
            key = ssid
        
        # Keep strongest signal per SSID
        if key not in best or (ap["signal"] is not None and 
                               (best[key]["signal"] is None or ap["signal"] > best[key]["signal"])):
            best[key] = ap
    
    # Sort by signal strength (descending)
    result = sorted(best.values(), key=lambda x: x["signal"] if x["signal"] is not None else -9999, reverse=True)
    return result


def scan_and_parse(iface: str, deduplicate: bool = True, keep_hidden: bool = False) -> List[Dict[str, Any]]:
    """
    High-level function: scan, parse, and optionally deduplicate.
    
    Args:
        iface: Wireless interface name (e.g., "wlan0")
        deduplicate: If True, deduplicate by SSID
        keep_hidden: If True (and deduplicate=True), keep hidden SSIDs
    
    Returns:
        List of AP dicts, or empty list on failure
    """
    raw_output = run_iw_scan(iface)
    if not raw_output:
        return []
    
    aps = parse_iw_scan(raw_output)
    
    if deduplicate:
        aps = deduplicate_by_ssid(aps, keep_hidden=keep_hidden)
    
    return aps


if __name__ == "__main__":
    # Test mode
    import sys
    import json
    
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0"
    aps = scan_and_parse(iface, deduplicate=True, keep_hidden=True)
    
    for ap in aps:
        print(f"{ap['ssid'] or '<hidden>':<32}  {get_security_label(ap):<12}  "
              f"{int(ap['signal']) if ap['signal'] else '?':>4} dBm  ch{ap['chan'] or '?':<3}  {ap['bssid']}")
    
    print(f"\nTotal: {len(aps)} APs")
