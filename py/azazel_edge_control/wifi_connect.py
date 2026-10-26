#!/usr/bin/env python3
"""
Wi-Fi Connect Module for Azazel-Edge Control Daemon

Connects to target SSID and enables USB client NAT:
- Uses NetworkManager/nmcli for Wi-Fi management
- Validates input, detects captive portal, applies NAT
"""

import subprocess
import re
import json
import logging
import time
import socket
import tempfile
import os
from contextlib import contextmanager
from typing import Dict, Any, Iterator, Optional, List, Tuple
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("wifi_connect")
DEFAULT_CAPTIVE_RETRY_SCHEDULE_SEC = [0, 3, 10]

# Import wifi_scan helpers
import sys
sys.path.insert(0, str(Path(__file__).parent))
PY_ROOT = Path(__file__).resolve().parents[1]
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))
from wifi_scan import (
    _split_nmcli_terse_line,
    get_wireless_interface,
    check_networkmanager,
    get_saved_networks_nm,
)
from azazel_edge.path_schema import snapshot_path_candidates, warn_if_legacy_path


# The Wi-Fi secret never goes on nmcli's argv (readable by any local user from
# /proc/<pid>/cmdline while nmcli runs). nmcli takes it from a passwd-file
# instead: `nmcli connection up <ID> passwd-file <file>`, one
# "<setting>.<property>:<secret>" per line (nmcli(1), "connection up";
# NetworkManager 1.42 in Debian 12 and 1.52 in Debian 13). nmcli answers
# NetworkManager's secret request from that file, and NetworkManager stores
# the answer in the profile as it stored `password <psk>` or
# `wifi-sec.psk <psk>` before. The file lives in a fresh 0700 directory
# under /run (tmpfs, root-owned) and is removed when nmcli returns.
NM_PASSWD_FILE_BASE = "/run"
NM_PSK_PROPERTY = "802-11-wireless-security.psk"
NM_WEP_KEY0_PROPERTY = "802-11-wireless-security.wep-key0"


def _nm_passwd_escape(secret: str) -> str:
    """Escape a secret for a passwd-file line.

    nmcli strips unescaped leading and trailing whitespace and unescapes
    backslash sequences (``nm_utils_buf_utf8safe_unescape``), so every byte
    is written as a three-digit octal escape: the value nmcli reads back is
    exactly ``secret``. The error never carries the secret.
    """
    try:
        data = secret.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Wi-Fi secret is not valid text") from None
    if b"\x00" in data:
        raise ValueError("Wi-Fi secret contains a NUL character")
    return "".join("\\%03o" % byte for byte in data)


@contextmanager
def _nm_passwd_file(secrets: Dict[str, str]) -> Iterator[str]:
    """Yield the path of a 0600 passwd-file holding ``secrets``; it and its
    private directory are removed on return, on error and on exception."""
    content = "".join(f"{prop}:{_nm_passwd_escape(value)}\n" for prop, value in secrets.items())
    directory = tempfile.mkdtemp(prefix="azazel-nm-secret-", dir=NM_PASSWD_FILE_BASE)  # 0700, new name
    path = os.path.join(directory, "passwd")
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(content)
        yield path
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        try:
            os.rmdir(directory)
        except OSError as exc:
            logger.warning("could not remove the nmcli passwd-file directory: %s", exc.strerror)


def get_usb_interface() -> Optional[str]:
    """Detect USB gadget interface (prefer usb0)"""
    try:
        # Try usb0 first
        result = subprocess.run(
            ["ip", "link", "show", "usb0"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            return "usb0"
        
        # Auto-detect gadget NIC (heuristic: look for 10.55.0.0/24 subnet)
        result = subprocess.run(
            ["ip", "-o", "addr"],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        for line in result.stdout.splitlines():
            if "10.55.0." in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
        
        return None
    except Exception as e:
        logger.warning(f"Failed to detect USB interface: {e}")
        return None


def validate_input(ssid: str, security: str, passphrase: Optional[str], is_saved: bool = False) -> Optional[str]:
    """Validate Wi-Fi connection parameters"""
    # SSID length
    if not ssid or len(ssid) > 32:
        return "Invalid SSID (must be 1-32 chars)"
    
    # Passphrase requirement
    if security and security.upper() != "OPEN":
        if not passphrase and not is_saved:
            return "Passphrase required for protected network"
        if passphrase and (len(passphrase) < 8 or len(passphrase) > 63):
            return "Invalid passphrase length (8-63 chars typical)"
    
    return None


def parse_security(security: str) -> Dict[str, bool]:
    """Normalize security label into flags."""
    sec = (security or "").upper().strip()
    return {
        "open": sec == "OPEN",
        "wpa3": "WPA3" in sec,
        "wpa2": "WPA2" in sec,
        "wpa": ("WPA" in sec) and ("WPA2" not in sec) and ("WPA3" not in sec),
    }


def is_nm_managed(iface: str) -> bool:
    """Check if NetworkManager is actively managing the interface."""
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,STATE", "dev"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            if ":" not in line:
                continue
            dev, state = line.split(":", 1)
            if dev != iface:
                continue
            state = state.strip().lower()
            return state not in {"unmanaged", "unavailable"}
        return False
    except Exception:
        return False


# key-mgmt values of 802.1X (Enterprise / dynamic WEP) profiles. The
# daemon only carries a pre-shared key; it never creates such a profile or
# rewrites one to a PSK profile.
NM_EAP_KEY_MGMT = {"wpa-eap", "wpa-eap-suite-b-192", "ieee8021x"}
ENTERPRISE_ERROR = "802.1X (WPA-Enterprise) networks are not supported here; set the profile up with NetworkManager directly"


def _key_mgmt_from_nm_security(raws: List[str]) -> Optional[Tuple[str, str]]:
    """Map nmcli's SECURITY column of every AP of the SSID (``WEP``,
    ``WPA1``, ``WPA2``, ``WPA3``, ``802.1X`` …) to (key-mgmt, secret
    property), the way NetworkManager completes a profile in
    ``nmcli dev wifi connect`` (``nm_wifi_utils_complete_connection``):

    * any AP advertising 802.1X: ``None`` (refused; not a PSK network);
    * any AP offering a PSK (WPA1/WPA2, a WPA2/WPA3 transition AP
      included): ``wpa-psk``;
    * every AP SAE only (WPA3): ``sae``;
    * every AP WEP: ``none`` with ``wep-key0``;
    * otherwise (nothing usable): ``wpa-psk``.
    """
    token_sets = [set((raw or "").split()) for raw in raws]
    if any("802.1X" in tokens for tokens in token_sets):
        return None
    if any(tokens & {"WPA1", "WPA2"} for tokens in token_sets):
        return "wpa-psk", NM_PSK_PROPERTY
    if token_sets and all("WPA3" in tokens for tokens in token_sets):
        return "sae", NM_PSK_PROPERTY
    if token_sets and all("WEP" in tokens for tokens in token_sets):
        return "none", NM_WEP_KEY0_PROPERTY
    return "wpa-psk", NM_PSK_PROPERTY


def new_profile_security(iface: str, ssid: str) -> Optional[Tuple[str, str]]:
    """key-mgmt and secret property for a new profile of ``ssid``, from all
    APs of that SSID in NetworkManager's scan list (no rescan). ``None``
    when one of them advertises 802.1X. Falls back to ``wpa-psk`` when the
    list cannot be read."""
    raws: List[str] = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,SECURITY", "dev", "wifi", "list", "ifname", iface, "--rescan", "no"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            for line in (result.stdout or "").splitlines():
                ap_ssid, raw = _split_nmcli_terse_line(line, 2)
                if ap_ssid == ssid:
                    raws.append(raw)
    except Exception as exc:
        logger.debug(f"Wi-Fi security lookup failed: {type(exc).__name__}")
    return _key_mgmt_from_nm_security(raws)


# A saved profile given a new PSK is not changed until the new PSK works:
# `nmcli connection clone` copies it (all settings, secrets included) under
# NM_PENDING_CLONE_PREFIX + <original UUID>, with autoconnect off; only the
# clone's PSK is dropped (psk-flags 2, then 0: setting it to "" keeps the
# stored one) and the clone is brought up with the new PSK in a passwd-file.
# On success the original is deleted by UUID and the clone takes its name;
# on any failure the clone is deleted by UUID and the original keeps its old
# PSK. A clone left by a crash is swept on the next connect.
NM_PENDING_CLONE_PREFIX = "azazel-wifi-pending-"
_UUID_RE = r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}"


def _nm_run(cmd: List[str], timeout: float = 5) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _nm_name_uuid_list() -> List[Tuple[str, str]]:
    result = _nm_run(["nmcli", "-t", "-f", "NAME,UUID", "con", "show"])
    if result.returncode != 0:
        return []
    pairs = []
    for line in (result.stdout or "").splitlines():
        name, uuid = _split_nmcli_terse_line(line, 2)
        if re.fullmatch(_UUID_RE, uuid):
            pairs.append((name, uuid))
    return pairs


def sweep_stale_psk_clones() -> None:
    """Delete, by UUID, clones a crash left behind whose original still
    exists and which are not active. A clone whose original is gone (a crash between deleting the
    original and renaming the clone) is the only copy: it is kept and
    reported. No other profile is touched."""
    pairs = _nm_name_uuid_list()
    clones = [(name, uuid) for name, uuid in pairs if name.startswith(NM_PENDING_CLONE_PREFIX)]
    if not clones:
        return
    uuids = {uuid for _, uuid in pairs}
    active_result = _nm_run(["nmcli", "-t", "-f", "UUID", "con", "show", "--active"])
    if active_result.returncode != 0:
        logger.warning("could not list active connections; stale Wi-Fi profile clones are kept for now")
        return
    active = {line.strip() for line in (active_result.stdout or "").splitlines()}
    for name, uuid in clones:
        original = name[len(NM_PENDING_CLONE_PREFIX):]
        if uuid in active:
            logger.warning("a Wi-Fi profile clone is active; kept")
        elif original in uuids and original != uuid:
            _nm_run(["nmcli", "con", "delete", "uuid", uuid])
            logger.info("removed a stale Wi-Fi profile clone left by an interrupted connect")
        else:
            logger.warning("a Wi-Fi profile clone has no original left; kept (rename it by hand)")


def _up_saved_profile_with_new_psk(original_uuid: str, con_name: str, key_mgmt: Optional[str], passphrase: str):
    """Bring the saved profile ``original_uuid`` (named ``con_name``, found by
    its SSID) up with a new PSK through a clone (see
    NM_PENDING_CLONE_PREFIX). Returns (the `con up` result, the UUID of the
    profile now in place), or a failure dict when the clone could not be
    prepared."""
    clone_name = NM_PENDING_CLONE_PREFIX + original_uuid
    cloned = _nm_run(["nmcli", "con", "clone", "uuid", original_uuid, clone_name])
    if cloned.returncode != 0:
        return {"ok": False, "error": cloned.stderr.strip() or "Connection failed"}
    clone_uuids = [u for u in re.findall(r"\((" + _UUID_RE + r")\)", cloned.stdout or "") if u != original_uuid]
    if not clone_uuids:
        clone_uuids = [u for n, u in _nm_name_uuid_list() if n == clone_name]
        if len(clone_uuids) > 1:
            clone_uuids = []  # ambiguous: touch none of them
    if not clone_uuids:
        return {"ok": False, "error": "Connection failed (profile copy not found)"}
    clone_uuid = clone_uuids[-1]

    def delete_clone() -> None:
        try:
            _nm_run(["nmcli", "con", "delete", "uuid", clone_uuid])
        except Exception as exc:
            logger.warning(f"could not remove the Wi-Fi profile clone: {type(exc).__name__}")

    try:
        steps = [["connection.autoconnect", "no"]]
        if key_mgmt:
            steps.append(["wifi-sec.key-mgmt", key_mgmt])
        steps += [["wifi-sec.psk-flags", "2"], ["wifi-sec.psk-flags", "0"]]
        for step in steps:
            if _nm_run(["nmcli", "con", "mod", "uuid", clone_uuid, *step]).returncode != 0:
                delete_clone()
                return {"ok": False, "error": "Connection failed (could not prepare the profile)"}
        with _nm_passwd_file({NM_PSK_PROPERTY: passphrase}) as passwd_file:
            result = _nm_run(["nmcli", "con", "up", "uuid", clone_uuid, "passwd-file", passwd_file], timeout=20)
    except Exception:
        delete_clone()
        raise
    if result.returncode != 0:
        delete_clone()
        return result, original_uuid
    if _nm_run(["nmcli", "con", "delete", "uuid", original_uuid]).returncode != 0:
        logger.warning("connected with the new PSK, but the old Wi-Fi profile could not be removed")
    _nm_run(["nmcli", "con", "mod", "uuid", clone_uuid, "connection.id", con_name])
    return result, clone_uuid


# One connect at a time (the sweep of stale clones and the connect run under
# it), whoever calls: the daemon or a direct invocation. flock on a
# root-owned file under /run, opened without following a symlink.
NM_CONNECT_LOCK_PATH = "/run/azazel-edge-wifi-connect.lock"
NM_CONNECT_LOCK_WAIT_SEC = 30.0
BUSY_ERROR = "Wi-Fi connect busy: another connect is in progress; try again"


@contextmanager
def _wifi_connect_lock() -> Iterator[bool]:
    """Yield True while holding the exclusive lock, False when it could not
    be taken within NM_CONNECT_LOCK_WAIT_SEC."""
    import fcntl
    import stat as _stat
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(NM_CONNECT_LOCK_PATH, flags, 0o600)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise PermissionError("the Wi-Fi connect lock file is not a private regular file of this account")
        deadline = time.monotonic() + NM_CONNECT_LOCK_WAIT_SEC
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    yield False
                    return
                time.sleep(0.2)
        try:
            yield True
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def connect_nm(iface: str, ssid: str, security: str, passphrase: Optional[str], persist: bool) -> Dict[str, Any]:
    """Connect using NetworkManager/nmcli, one connect at a time."""
    try:
        with _wifi_connect_lock() as locked:
            if not locked:
                return {"ok": False, "error": BUSY_ERROR}
            return _connect_nm_locked(iface, ssid, security, passphrase, persist)
    except OSError as exc:
        logger.error(f"Wi-Fi connect lock unavailable: {exc.strerror or type(exc).__name__}")
        return {"ok": False, "error": "Wi-Fi connect lock unavailable"}


def _connect_nm_locked(iface: str, ssid: str, security: str, passphrase: Optional[str], persist: bool) -> Dict[str, Any]:
    """Connect using NetworkManager/nmcli (the caller holds the lock)."""
    try:
        if passphrase:
            # Refuse a secret nmcli cannot carry before any profile changes.
            _nm_passwd_escape(passphrase)
        try:
            sweep_stale_psk_clones()
        except Exception as exc:
            logger.warning(f"could not check for stale Wi-Fi profile clones: {type(exc).__name__}")
        key_mgmt: Optional[str] = None
        created_uuid: Optional[str] = None
        sec_flags = parse_security(security)
        # OPEN AP profiles are always treated as ephemeral to avoid stale reconnection failures.
        persist = bool(persist and not sec_flags["open"])

        def list_nm_connections_for_ssid(target_ssid: str) -> List[Tuple[str, str]]:
            """(name, UUID) of the NM Wi-Fi connections whose
            802-11-wireless.ssid is ``target_ssid``. Every later step uses
            the UUID: a name may be shared by profiles of other SSIDs."""
            found: List[Tuple[str, str]] = []
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "NAME,UUID,TYPE", "con", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    return found
                for line in result.stdout.splitlines():
                    name, uuid, con_type = _split_nmcli_terse_line(line, 3)
                    if con_type != "802-11-wireless" or not re.fullmatch(_UUID_RE, uuid):
                        continue
                    # Query SSID for each Wi-Fi connection (older nmcli doesn't expose it in list mode).
                    ssid_result = subprocess.run(
                        ["nmcli", "-t", "-f", "802-11-wireless.ssid", "con", "show", "uuid", uuid],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if ssid_result.returncode != 0:
                        continue
                    ssid_line = (ssid_result.stdout or "").strip()
                    if ":" in ssid_line:
                        _, ssid_value = ssid_line.split(":", 1)
                    else:
                        ssid_value = ssid_line
                    if ssid_value == target_ssid:
                        found.append((name, uuid))
                return found
            except Exception:
                return found

        def find_nm_connection_for_ssid(target_ssid: str) -> Optional[Tuple[str, str]]:
            found = list_nm_connections_for_ssid(target_ssid)
            return found[0] if found else None

        def delete_nm_connections_for_ssid(target_ssid: str) -> None:
            for _, con_uuid in list_nm_connections_for_ssid(target_ssid):
                subprocess.run(
                    ["nmcli", "con", "delete", "uuid", con_uuid],
                    capture_output=True,
                    timeout=5,
                )

        def get_nm_key_mgmt(connection_uuid: str) -> str:
            """Return current key-mgmt for an existing NM connection (empty if unset)."""
            try:
                result = subprocess.run(
                    ["nmcli", "-g", "802-11-wireless-security.key-mgmt", "con", "show", "uuid", connection_uuid],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return (result.stdout or "").strip()
            except Exception:
                pass

            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt", "con", "show", "uuid", connection_uuid],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode != 0:
                    return ""
                line = (result.stdout or "").strip()
                if ":" in line:
                    _, value = line.split(":", 1)
                    return value.strip()
                return line
            except Exception:
                return ""

        def desired_nm_key_mgmt() -> Optional[str]:
            """Decide key-mgmt to set based on security flags."""
            if sec_flags["open"]:
                return "none"
            if sec_flags["wpa3"]:
                return "sae"
            if sec_flags["wpa2"] or sec_flags["wpa"]:
                return "wpa-psk"
            return None

        if sec_flags["open"]:
            # OPEN reconnects are fragile when stale profiles remain; force a clean connect path.
            delete_nm_connections_for_ssid(ssid)
            cmd = ["nmcli", "dev", "wifi", "connect", ssid, "ifname", iface]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0:
                # One recovery retry after best-effort cleanup.
                delete_nm_connections_for_ssid(ssid)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
            if result.returncode != 0:
                return {"ok": False, "error": result.stderr.strip() or "Connection failed"}

            # Keep OPEN profiles ephemeral; do not leave remembered AP entries behind.
            delete_nm_connections_for_ssid(ssid)
            logger.info("Wi-Fi connected via nmcli (OPEN ephemeral)")
            return {"ok": True}

        # Check if connection exists for this SSID
        found_con = find_nm_connection_for_ssid(ssid)
        con_exists = found_con is not None
        con_name, con_uuid = found_con if found_con else (None, None)
        
        if con_exists:
            # Update credentials if provided (or clear for OPEN)
            if sec_flags["open"]:
                subprocess.run(
                    ["nmcli", "con", "mod", "uuid", con_uuid, "wifi-sec.key-mgmt", "none"],
                    capture_output=True,
                    timeout=5
                )
                subprocess.run(
                    ["nmcli", "con", "mod", "uuid", con_uuid, "-u", "wifi-sec.psk"],
                    capture_output=True,
                    timeout=5
                )
            else:
                existing_key_mgmt = get_nm_key_mgmt(con_uuid)
                if passphrase and existing_key_mgmt in NM_EAP_KEY_MGMT:
                    # Never rewrite an 802.1X profile into a PSK one.
                    return {"ok": False, "error": ENTERPRISE_ERROR}
                desired = desired_nm_key_mgmt()
                key_mgmt = None

                # Only set key-mgmt if missing (or clearly wrong) to avoid breaking saved profiles.
                if not existing_key_mgmt or existing_key_mgmt == "none":
                    key_mgmt = desired or "wpa-psk"  # safe default for WPA2-PSK
                elif passphrase and desired and existing_key_mgmt != desired:
                    # User provided credentials explicitly; align key-mgmt with the requested security.
                    key_mgmt = desired

                if key_mgmt and not passphrase:
                    subprocess.run(
                        ["nmcli", "con", "mod", "uuid", con_uuid, "wifi-sec.key-mgmt", key_mgmt],
                        capture_output=True,
                        timeout=5
                    )

            if passphrase and not sec_flags["open"]:
                # New PSK for a saved profile: a clone takes it and is
                # brought up; the original (with its old PSK) is replaced
                # only when that worked (formerly `con mod … wifi-sec.psk
                # <psk>` on the original, then `con up`).
                outcome = _up_saved_profile_with_new_psk(con_uuid, con_name, key_mgmt, passphrase)
                if isinstance(outcome, dict):
                    return outcome
                result, con_uuid = outcome
            else:
                result = subprocess.run(
                    ["nmcli", "con", "up", "uuid", con_uuid],
                    capture_output=True,
                    text=True,
                    timeout=20
                )
        else:
            if not sec_flags["open"] and not passphrase:
                return {"ok": False, "error": "Saved connection not found; passphrase required"}

            # Create new connection: add the profile without its secret, then
            # bring it up with the secret in a passwd-file (formerly
            # `nmcli dev wifi connect <ssid> … password <psk>`, which put the
            # passphrase on nmcli's argv). Autoconnect stays off, as it is
            # set below for a kept profile.
            security_choice = new_profile_security(iface, ssid)
            if security_choice is None:
                return {"ok": False, "error": ENTERPRISE_ERROR}
            key_mgmt, secret_property = security_choice
            add_cmd = [
                "nmcli", "con", "add", "type", "wifi", "ifname", iface, "con-name", ssid, "ssid", ssid,
                "connection.autoconnect", "no", "wifi-sec.key-mgmt", key_mgmt,
            ]
            if secret_property == NM_WEP_KEY0_PROPERTY:
                add_cmd.extend(["wifi-sec.wep-key-type", "key"])
            added = subprocess.run(
                add_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if added.returncode != 0:
                return {"ok": False, "error": added.stderr.strip() or "Connection failed"}
            uuid_match = re.search(r"\(([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\)", added.stdout or "")
            created_uuid = uuid_match.group(1) if uuid_match else None
            if not created_uuid:
                # No profile of this SSID existed before `con add`, so the
                # one found now is the one just added.
                created_uuid = (find_nm_connection_for_ssid(ssid) or (None, None))[1]
            if not created_uuid:
                return {"ok": False, "error": "Connection failed (new profile not found)"}
            up_target = ["uuid", created_uuid]

            def delete_created_profile() -> None:
                # `nmcli dev wifi connect` left nothing behind on failure;
                # neither does this path. Only the profile added above is
                # removed (by its UUID).
                try:
                    subprocess.run(["nmcli", "con", "delete", "uuid", created_uuid], capture_output=True, timeout=5)
                except Exception as exc:
                    logger.warning(f"could not remove the new Wi-Fi profile: {type(exc).__name__}")

            try:
                with _nm_passwd_file({secret_property: passphrase}) as passwd_file:
                    result = subprocess.run(
                        ["nmcli", "con", "up", *up_target, "passwd-file", passwd_file],
                        capture_output=True,
                        text=True,
                        timeout=20
                    )
            except Exception:
                delete_created_profile()
                raise
            if result.returncode != 0:
                delete_created_profile()

            # If not persisting, delete the connection after use (best-effort)
            if not persist and result.returncode == 0:
                delete_nm_connections_for_ssid(ssid)
        
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr.strip() or "Connection failed"}

        # Disable auto-connect to ensure Wi-Fi only connects on explicit user action
        if con_exists or persist:
            try:
                if not con_uuid:
                    con_uuid = created_uuid or (find_nm_connection_for_ssid(ssid) or (None, None))[1]
                if not con_uuid:
                    raise RuntimeError("profile UUID unknown")
                subprocess.run(
                    ["nmcli", "con", "mod", "uuid", con_uuid, "connection.autoconnect", "no"],
                    capture_output=True,
                    timeout=5
                )
            except Exception as e:
                logger.debug(f"Failed to disable autoconnect for {ssid}: {e}")
        
        logger.info("Wi-Fi connected via nmcli")
        return {"ok": True}
    
    except Exception as e:
        logger.error(f"nmcli connection failed: {e}")
        return {"ok": False, "error": str(e)}


def get_interface_ip(iface: str) -> Optional[str]:
    """Get IP address of interface"""
    try:
        result = subprocess.run(
            ["ip", "-o", "-4", "addr", "show", iface],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        match = re.search(r"inet\s+(\S+)", result.stdout)
        if match:
            return match.group(1).split("/")[0]
        return None
    except:
        return None


def get_gateway_ip(iface: str) -> Optional[str]:
    """Get default gateway for interface"""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        match = re.search(r"default via\s+(\S+)", result.stdout)
        if match:
            return match.group(1)
        return None
    except:
        return None


def _parse_location(headers: str) -> str:
    for line in headers.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return ""


def _normalize_http_url(candidate: Any) -> str:
    """Return normalized http(s) URL or empty string."""
    text = str(candidate or "").strip()
    if not text or any(ch in text for ch in ("\r", "\n")):
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""
    return text


def _choose_portal_url_from_checks(checks: Dict[str, Any], status: str) -> str:
    """Pick best portal URL candidate from captive probe checks."""
    if status not in ("YES", "SUSPECTED"):
        return ""
    for key in ("location", "effective_url", "probe_url"):
        normalized = _normalize_http_url(checks.get(key, ""))
        if normalized:
            return normalized
    return ""


def check_connectivity(iface: Optional[str]) -> Dict[str, Any]:
    """
    Connectivity checks with captive-portal aware HTTP probe.

    Returns:
        gateway_reachable: OK|FAIL
        dns_resolution: OK|FAIL
        http_code: str
        http_check: OK|FAIL
        location: str
        body_len: int
        effective_url: str
        curl_error: str
    """
    checks: Dict[str, Any] = {
        "gateway_reachable": "UNKNOWN",
        "dns_resolution": "UNKNOWN",
        "http_check": "FAIL",
        "http_code": "000",
        "location": "",
        "body_len": 0,
        "effective_url": "",
        "probe_url": "http://connectivitycheck.gstatic.com/generate_204",
        "curl_error": "",
    }

    # Gateway ping
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", "8.8.8.8"],
            capture_output=True,
            timeout=3
        )
        checks["gateway_reachable"] = "OK" if result.returncode == 0 else "FAIL"
    except Exception:
        checks["gateway_reachable"] = "FAIL"

    # DNS resolution
    try:
        socket.gethostbyname("connectivitycheck.gstatic.com")
        checks["dns_resolution"] = "OK"
    except Exception:
        checks["dns_resolution"] = "FAIL"

    body_path = ""
    hdr_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="azazel_wifi_body_", delete=False, dir="/tmp") as bf:
            body_path = bf.name
        with tempfile.NamedTemporaryFile(prefix="azazel_wifi_hdr_", delete=False, dir="/tmp") as hf:
            hdr_path = hf.name

        cmd = [
            "curl",
            "-sS",
            "--max-time",
            "4",
            "-o",
            body_path,
            "-D",
            hdr_path,
            "-w",
            "%{http_code} %{url_effective}",
            "http://connectivitycheck.gstatic.com/generate_204",
        ]
        if iface:
            cmd[1:1] = ["--interface", iface]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=6
        )
        checks["http_check"] = "OK" if result.returncode == 0 else "FAIL"
        if result.returncode != 0:
            if result.returncode == 28:
                checks["curl_error"] = "TIMEOUT"
            elif result.returncode == 6:
                checks["curl_error"] = "DNS_FAIL"
            elif result.returncode in (35, 51, 58, 60):
                checks["curl_error"] = "CERT_FAIL"
            else:
                checks["curl_error"] = f"CURL_ERR_{result.returncode}"
            checks["http_check"] = "FAIL"
        else:
            payload = (result.stdout or "").strip().split(maxsplit=1)
            checks["http_code"] = payload[0] if payload else "000"
            checks["effective_url"] = payload[1] if len(payload) > 1 else ""
            try:
                checks["body_len"] = Path(body_path).stat().st_size
            except Exception:
                checks["body_len"] = 0
            try:
                headers = Path(hdr_path).read_text(encoding="utf-8", errors="ignore")
                checks["location"] = _parse_location(headers)
            except Exception:
                checks["location"] = ""
    except subprocess.TimeoutExpired:
        checks["curl_error"] = "TIMEOUT"
        checks["http_check"] = "FAIL"
    except Exception as exc:
        checks["curl_error"] = f"CURL_ERR:{exc}"
        checks["http_check"] = "FAIL"
    finally:
        for p in (body_path, hdr_path):
            if p:
                try:
                    Path(p).unlink(missing_ok=True)
                except Exception:
                    pass

    return checks


def detect_captive_portal(checks: Dict[str, Any]) -> Dict[str, str]:
    """
    Captive portal decision table:
      - 204 => NO
      - 30x => YES
      - 200(body>0) => SUSPECTED
      - other non-204 => NA
      - timeout/curl errors => NA
    """
    code = str(checks.get("http_code", "000") or "000")
    body_len = int(checks.get("body_len", 0) or 0)
    curl_error = str(checks.get("curl_error", "") or "")

    if curl_error in ("NO_IP", "LINK_DOWN", "NOT_FOUND"):
        return {"status": "NA", "reason": curl_error}
    if curl_error:
        return {"status": "NA", "reason": curl_error}
    if code == "204":
        return {"status": "NO", "reason": "HTTP_204"}
    if code.startswith("30"):
        return {"status": "YES", "reason": "HTTP_30X"}
    if code == "200" and body_len > 0:
        return {"status": "SUSPECTED", "reason": "HTTP_200_BODY"}
    if code and code != "000":
        return {"status": "NA", "reason": f"HTTP_{code}"}
    return {"status": "NA", "reason": "HTTP_000"}


def get_captive_retry_schedule() -> List[int]:
    """
    Retry schedule in seconds.
    Override via env: AZAZEL_CAPTIVE_RETRY_SCHEDULE_SEC="0,3,10"
    """
    raw = os.environ.get("AZAZEL_CAPTIVE_RETRY_SCHEDULE_SEC", "")
    if not raw.strip():
        return DEFAULT_CAPTIVE_RETRY_SCHEDULE_SEC[:]

    parsed: List[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            value = int(token)
        except ValueError:
            continue
        if value < 0:
            continue
        parsed.append(value)

    if not parsed:
        return DEFAULT_CAPTIVE_RETRY_SCHEDULE_SEC[:]
    if parsed[0] != 0:
        parsed.insert(0, 0)
    return parsed


def evaluate_captive_portal_with_retries(iface: str, has_ip: bool) -> Dict[str, Any]:
    """
    Run captive-portal check at connect timing with short retries.
    NO at first probe may still become YES/SUSPECTED shortly after association.
    """
    if not has_ip:
        checks = {
            "gateway_reachable": "FAIL",
            "dns_resolution": "FAIL",
            "http_check": "FAIL",
            "http_code": "000",
            "location": "",
            "body_len": 0,
            "effective_url": "",
            "curl_error": "NO_IP",
        }
        return {
            "status": "NA",
            "reason": "NO_IP",
            "checks": checks,
            "attempts": [{
                "attempt": 1,
                "delay_sec": 0,
                "status": "NA",
                "reason": "NO_IP",
                "http_code": "000",
                "curl_error": "NO_IP",
            }],
        }

    schedule = get_captive_retry_schedule()
    attempts: List[Dict[str, Any]] = []
    final_status = "NA"
    final_reason = "NOT_CHECKED"
    final_checks: Dict[str, Any] = {
        "gateway_reachable": "UNKNOWN",
        "dns_resolution": "UNKNOWN",
        "http_check": "FAIL",
        "http_code": "000",
        "location": "",
        "body_len": 0,
        "effective_url": "",
        "curl_error": "",
    }

    for idx, delay in enumerate(schedule):
        if idx > 0 and delay > 0:
            time.sleep(delay)
        checks = check_connectivity(iface)
        decision = detect_captive_portal(checks)
        final_status = decision["status"]
        final_reason = decision["reason"]
        final_checks = checks
        attempts.append(
            {
                "attempt": idx + 1,
                "delay_sec": delay,
                "status": final_status,
                "reason": final_reason,
                "http_code": str(checks.get("http_code", "000")),
                "curl_error": str(checks.get("curl_error", "")),
            }
        )
        logger.info(
            "captive probe attempt %s/%s: status=%s reason=%s http_code=%s",
            idx + 1,
            len(schedule),
            final_status,
            final_reason,
            checks.get("http_code", "000"),
        )
        # Portal-positive signal should be reported immediately.
        if final_status in ("YES", "SUSPECTED"):
            break
        # Interface-level NA should not be retried.
        if final_status == "NA" and final_reason in ("NO_IP", "LINK_DOWN", "NOT_FOUND", "INVALID_IFACE"):
            break

    return {
        "status": final_status,
        "reason": final_reason,
        "checks": final_checks,
        "attempts": attempts,
    }


def detect_firewall_tool() -> Optional[str]:
    """Detect available firewall tool (prefer nftables)"""
    tools = ["nft", "iptables-nft", "iptables"]
    
    for tool in tools:
        try:
            result = subprocess.run(
                ["which", tool],
                capture_output=True,
                timeout=2
            )
            if result.returncode == 0:
                return tool
        except:
            continue
    
    return None


def apply_nat(wlan_iface: str, usb_iface: str) -> Dict[str, Any]:
    """Apply NAT/forwarding for USB client"""
    try:
        # Enable IPv4 forwarding
        subprocess.run(
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            capture_output=True,
            timeout=2
        )
        
        # Detect firewall tool
        fw_tool = detect_firewall_tool()
        
        if not fw_tool:
            return {"ok": False, "error": "No firewall tool found (nft/iptables)"}
        
        logger.info(f"Using firewall tool: {fw_tool}")
        
        if fw_tool == "nft":
            # nftables: create table + chain + masquerade rule
            subprocess.run(
                ["nft", "add", "table", "ip", "azazel_nat"],
                capture_output=True
            )
            subprocess.run(
                ["nft", "add", "chain", "ip", "azazel_nat", "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}"],
                capture_output=True
            )
            subprocess.run(
                ["nft", "add", "rule", "ip", "azazel_nat", "postrouting", "oifname", wlan_iface, "masquerade"],
                capture_output=True,
                timeout=2
            )
        else:
            # iptables/iptables-nft
            subprocess.run(
                [fw_tool, "-t", "nat", "-A", "POSTROUTING", "-o", wlan_iface, "-j", "MASQUERADE"],
                capture_output=True,
                timeout=2
            )
            subprocess.run(
                [fw_tool, "-A", "FORWARD", "-i", usb_iface, "-o", wlan_iface, "-j", "ACCEPT"],
                capture_output=True,
                timeout=2
            )
            subprocess.run(
                [fw_tool, "-A", "FORWARD", "-i", wlan_iface, "-o", usb_iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
                capture_output=True,
                timeout=2
            )
        
        logger.info("NAT applied successfully")
        return {"ok": True, "fw_tool": fw_tool}
    
    except Exception as e:
        logger.error(f"Failed to apply NAT: {e}")
        return {"ok": False, "error": str(e)}


def update_state_json(wifi_state: str, **kwargs):
    """Update snapshot.json with Wi-Fi state (schema-aware paths)."""
    candidates = snapshot_path_candidates(home=Path.home())
    runtime_candidates = [p for p in candidates if str(p).startswith("/run/")]
    if not runtime_candidates:
        runtime_candidates = candidates[:2]
    state_path = runtime_candidates[0]
    fallback_path = runtime_candidates[-1]
    
    try:
        # Read from both paths to get the most complete state
        data = {}
        
        # Try all candidate paths to get the richest current state
        for p in runtime_candidates:
            if not p.exists():
                continue
            try:
                warn_if_legacy_path(p, logger=logger)
                data = json.loads(p.read_text(encoding="utf-8"))
                if data:
                    break
            except Exception as e:
                logger.debug(f"Failed to read {p}: {e}")
        
        default_conn = {
            "wifi_state": "DISCONNECTED",
            "usb_nat": "OFF",
            "internet_check": "N/A",
            "ssid": "",
            "ip_wlan": "",
            "ip_usb": "",
            "gateway_ip": "",
            "bssid": "",
            "captive_probe_iface": "",
            "captive_probe_attempts": [],
            "captive_portal": "NA",
            "captive_portal_reason": "NOT_CHECKED",
            "captive_checked_at": "",
            "captive_portal_url": "",
            "captive_probe_url": "",
            "captive_effective_url": "",
            "captive_location": "",
        }
        conn = {}
        if isinstance(data.get("connection"), dict):
            conn = data["connection"].copy()
        merged = default_conn.copy()
        merged.update(conn)
        merged["wifi_state"] = wifi_state
        merged.update(kwargs)

        if wifi_state == "DISCONNECTED":
            for key in ("ssid", "ip_wlan", "gateway_ip", "bssid"):
                merged[key] = ""
            merged["internet_check"] = "N/A"
            merged["usb_nat"] = "OFF"
            merged["captive_probe_attempts"] = []
            merged["captive_portal_url"] = ""
            merged["captive_probe_url"] = ""
            merged["captive_effective_url"] = ""
            merged["captive_location"] = ""

        merged["captive_portal_detail"] = {
            "status": merged.get("captive_portal", "NA"),
            "reason": merged.get("captive_portal_reason", "NOT_CHECKED"),
            "checked_at": merged.get("captive_checked_at", ""),
            "portal_url": merged.get("captive_portal_url", ""),
            "probe_url": merged.get("captive_probe_url", ""),
            "effective_url": merged.get("captive_effective_url", ""),
            "location": merged.get("captive_location", ""),
        }
        data["connection"] = merged
        
        # Write to primary + fallback for backward compatibility.
        for p in (state_path, fallback_path):
            try:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(json.dumps(data, indent=2), encoding="utf-8")
                warn_if_legacy_path(p, logger=logger)
                logger.info(f"Updated {p}: wifi_state={wifi_state}")
            except Exception as e:
                logger.debug(f"Could not write to {p}: {e}")
    
    except Exception as e:
        logger.warning(f"Failed to update state.json: {e}")


def connect_wifi(ssid: str, security: str = "UNKNOWN", passphrase: Optional[str] = None, persist: bool = False) -> Dict[str, Any]:
    """
    Main entry point: Connect to Wi-Fi and enable NAT
    
    Args:
        ssid: Target SSID
        security: OPEN | WPA2 | WPA3 | UNKNOWN
        passphrase: Passphrase (required unless OPEN)
        persist: Save network for auto-connect
    
    Returns:
        {
            "ok": bool,
            "wifi_state": "CONNECTED|FAILED",
            "ip_wlan": str,
            "ip_usb": str,
            "gateway_ip": str,
            "usb_nat": "ON|OFF",
            "internet_check": "OK|FAIL",
            "captive_portal": "YES|NO|SUSPECTED|NA",
            "captive_portal_reason": str,
            "error": str (if failed)
        }
    """
    # Sanitize passphrase from logs (never log it)
    logger.info(f"Connecting to SSID: {ssid}, Security: {security}, Persist: {persist}")
    
    # Step 2: Set CONNECTING state
    update_state_json("CONNECTING", wifi_error=None, ssid=ssid)
    
    # Step 3: Detect interfaces
    wlan_iface = get_wireless_interface()
    usb_iface = get_usb_interface()
    
    if not wlan_iface:
        update_state_json("FAILED", wifi_error="No wireless interface")
        return {"ok": False, "error": "No wireless interface found", "ts": time.time()}
    
    if not usb_iface:
        logger.warning("No USB interface detected (NAT will not be applied)")
    
    # Step 4: Check NetworkManager
    if not check_networkmanager(wlan_iface):
        update_state_json("FAILED", wifi_error="NetworkManager not available")
        return {
            "ok": False,
            "error": "NetworkManager not found or not managing interface",
            "ts": time.time()
        }
    
    logger.info("Wi-Fi manager: NetworkManager")
    
    # Get saved networks
    saved_ssids = get_saved_networks_nm()
    is_saved = ssid in saved_ssids

    # Step 5: Validate input (allow saved networks without passphrase)
    error = validate_input(ssid, security, passphrase, is_saved=is_saved)
    if error:
        update_state_json("FAILED", wifi_error=error)
        return {"ok": False, "error": error, "ts": time.time()}

    # Step 6: Connect Wi-Fi using NetworkManager
    result = connect_nm(wlan_iface, ssid, security, passphrase, persist)
    
    if not result["ok"]:
        update_state_json("FAILED", wifi_error=result.get("error", "Connection failed"))
        return {"ok": False, "error": result.get("error"), "ts": time.time()}
    
    # Step 7: Get IP info
    ip_wlan = get_interface_ip(wlan_iface)
    ip_usb = get_interface_ip(usb_iface) if usb_iface else None
    gateway_ip = get_gateway_ip(wlan_iface)
    
    # Step 8: Connectivity checks (captive aware, with short retries)
    captive_eval = evaluate_captive_portal_with_retries(wlan_iface, has_ip=bool(ip_wlan))
    checks = captive_eval["checks"]
    captive_attempts = captive_eval.get("attempts", [])
    captive_portal = captive_eval["status"]
    captive_reason = captive_eval["reason"]
    captive_portal_url = _choose_portal_url_from_checks(checks, captive_portal)
    internet_check = "OK" if captive_portal == "NO" else "FAIL"
    
    # Step 9: Apply NAT
    usb_nat = "OFF"
    if usb_iface:
        nat_result = apply_nat(wlan_iface, usb_iface)
        if nat_result["ok"]:
            usb_nat = "ON"
        else:
            logger.warning(f"NAT not applied: {nat_result.get('error')}")
    
    # Step 10: Finalize state
    update_state_json(
        "CONNECTED",
        wifi_error=None,
        ssid=ssid,
        ip_wlan=ip_wlan,
        ip_usb=ip_usb,
        gateway_ip=gateway_ip,
        bssid="",
        usb_nat=usb_nat,
        internet_check=internet_check,
        captive_probe_iface=wlan_iface,
        captive_portal=captive_portal,
        captive_portal_reason=captive_reason,
        captive_checked_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        captive_probe_attempts=captive_attempts,
        captive_portal_url=captive_portal_url,
        captive_probe_url=str(checks.get("probe_url", "") or ""),
        captive_effective_url=str(checks.get("effective_url", "") or ""),
        captive_location=str(checks.get("location", "") or ""),
    )
    
    return {
        "ok": True,
        "wifi_state": "CONNECTED",
        "ip_wlan": ip_wlan,
        "ip_usb": ip_usb,
        "gateway_ip": gateway_ip,
        "usb_nat": usb_nat,
        "internet_check": internet_check,
        "captive_portal": captive_portal,
        "captive_portal_reason": captive_reason,
        "checks": checks,
        "captive_probe_attempts": captive_attempts,
        "ts": time.time()
    }


if __name__ == "__main__":
    # Test mode
    import argparse
    logging.basicConfig(level=logging.INFO)
    
    parser = argparse.ArgumentParser(description="Wi-Fi Connect Test")
    parser.add_argument("ssid", help="Target SSID")
    parser.add_argument("--security", default="UNKNOWN", help="Security type (OPEN|WPA2|WPA3)")
    parser.add_argument("--passphrase", help="Passphrase (if required)")
    parser.add_argument("--persist", action="store_true", help="Save network")
    
    args = parser.parse_args()
    
    result = connect_wifi(args.ssid, args.security, args.passphrase, args.persist)
    print(json.dumps(result, indent=2))
