#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azazel-Edge: tmux top-pane status renderer
- Prints concise network and service status, refreshing periodically
- Designed to run in a plain terminal (no curses) so it can live in its own tmux pane
- Exit with Ctrl-C (SIGINT)

Environment:
  AZA_EMOJI=0|1  Force ASCII (0) or allow emoji (1, default if UTF-8)
  AZA_STATUS_INTERVAL=seconds (default: 2.0)
"""

import os
import sys
import time
import shutil
import subprocess
import shlex
import json
from datetime import datetime
from typing import Optional, Tuple
from pathlib import Path

PY_ROOT = Path(__file__).resolve().parent
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.path_schema import wifi_health_path_candidates

# ---------- helpers ----------

def _sh(cmd: str, timeout: float = 1.5) -> str:
    try:
        out = subprocess.check_output(shlex.split(cmd), stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode('utf-8', 'ignore').strip()
    except Exception:
        return ""


def _ip4_addr(iface: str) -> str:
    out = _sh(f"ip -4 addr show {iface}")
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            return line.split()[1].split('/')[0]
    return "—"


def _default_gw_iface() -> str:
    out = _sh("ip route get 8.8.8.8")
    parts = out.split()
    if 'dev' in parts:
        try:
            return parts[parts.index('dev') + 1]
        except Exception:
            pass
    return "—"


def _ssid_and_bssid() -> Tuple[str, str]:
    ssid = _sh("iwgetid -r")
    if not ssid:
        st = _sh("wpa_cli status")
        for ln in st.splitlines():
            if ln.startswith('ssid='):
                ssid = ln.split('=', 1)[1].strip()
                break
    bssid = ""
    st = _sh("wpa_cli status")
    for ln in st.splitlines():
        if ln.startswith('bssid='):
            bssid = ln.split('=', 1)[1].strip()
            break
    return (ssid or "—", bssid or "—")


def _wifi_rssi_dbm() -> Optional[int]:
    out = _sh("iw dev wlan0 link")
    for ln in out.splitlines():
        ln = ln.strip().lower()
        if ln.startswith('signal:') and 'dbm' in ln:
            try:
                return int(ln.split()[1])
            except Exception:
                return None
    return None


def _route_alive() -> bool:
    try:
        return subprocess.call(["ping", "-c1", "-W1", "8.8.8.8"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


def _captive_portal() -> Optional[bool]:
    try:
        if shutil.which('curl') is None:
            return None
        hdr = subprocess.check_output(
            ["curl", "-sI", "http://connectivitycheck.gstatic.com/generate_204"],
            stderr=subprocess.DEVNULL, timeout=1.5
        ).decode('utf-8', 'ignore').splitlines()
        for ln in hdr:
            if ln.lower().startswith('http/'):
                parts = ln.split()
                if len(parts) >= 2 and parts[1] == '204':
                    return False
                try:
                    code = int(parts[1])
                    if 300 <= code < 400:
                        return True
                    return None
                except Exception:
                    return None
        return None
    except Exception:
        return None


def _supports_emoji() -> bool:
    flag = os.environ.get('AZA_EMOJI', '').strip().lower()
    if flag in ('0', 'false', 'no', 'off'):
        return False
    s = (os.environ.get('LANG', '') + os.environ.get('LC_CTYPE', '')).upper()
    return 'UTF-8' in s


def _health_path() -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    candidates = wifi_health_path_candidates(home=Path.home(), repo_root=repo_root)
    for path in candidates:
        if path.exists() and os.access(path, os.R_OK):
            return path
    return candidates[0]


def _health_status() -> str:
    path = _health_path()
    if not path.exists():
        return ""
    try:
        data = json.loads(path.read_text())
    except Exception:
        return ""
    status = data.get("status", "")
    tags = data.get("tags", []) or []
    risk = data.get("risk", None)
    ts = data.get("ts", 0)
    age = int(time.time() - ts) if ts else None
    tag_str = ",".join(tags[:5])
    parts = []
    if status:
        parts.append(status)
    if risk is not None:
        parts.append(f"risk={risk}")
    if tag_str:
        parts.append(tag_str)
    if age is not None:
        parts.append(f"{age}s ago")
    return " | ".join(parts)


# ---------- rendering ----------

def _clear():
    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()


def _print_status():
    emoji = _supports_emoji()

    ap = '📶 AP' if emoji else '[AP]'
    aza = '🜲 Azazel-Edge' if emoji else '[Azazel-Edge]'
    dhcp = '🧩 DHCP' if emoji else '[DHCP]'
    lap = '💻 Laptop' if emoji else '[Laptop]'
    arw = ' ➜ ' if emoji else ' -> '

    ssid, bssid = _ssid_and_bssid()
    wlan_ip = _ip4_addr('wlan0')
    usb_ip = _ip4_addr('usb0')
    lap_ip = _latest_usb_client_ip()
    gw_if = _default_gw_iface()
    rssi = _wifi_rssi_dbm()
    net_ok = _route_alive()
    captive = _captive_portal()

    if emoji:
        ok_sym = '🟢' if net_ok else '🔴'
        cap_sym = '🔓' if captive is False else ('🔒' if captive is True else '❔')
    else:
        ok_sym = 'OK' if net_ok else 'ERR'
        cap_sym = 'OPEN' if captive is False else ('AUTH' if captive is True else 'UNK')

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Header line
    line1 = f"{ap}{arw}{ssid}{arw}{aza}{arw}{dhcp}{arw}{lap}"
    badges = f"  [NET {ok_sym}]  [CAP {cap_sym}]  [RSSI {rssi if rssi is not None else '—'} dBm]"
    health = _health_status()

    # Print
    print(f"==== Azazel-Edge Status  |  {now} ====")
    print(line1 + badges)
    print(f"AP(wlan0): {wlan_ip}   |   Pi(usb0): {usb_ip}   |   Laptop: {lap_ip}")
    print(f"GW-IF: {gw_if}    BSSID: {bssid}")
    if health:
        print(f"Wi-Fi health: {health}")
    print("-" * 80)


def _dnsmasq_leases_path() -> str:
    for p in ("/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/dnsmasq.leases"):
        if os.path.exists(p):
            return p
    return ""


def _latest_usb_client_ip() -> str:
    path = _dnsmasq_leases_path()
    if not path:
        return "—"
    try:
        last = "—"
        with open(path, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    last = parts[2]
        return last
    except Exception:
        return "—"


def main() -> int:
    try:
        interval = float(os.environ.get('AZA_STATUS_INTERVAL', '5.0'))
    except Exception:
        interval = 2.0

    try:
        while True:
            _clear()
            _print_status()
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"[status] error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
