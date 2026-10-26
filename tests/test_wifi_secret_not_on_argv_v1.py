"""Edge#477: the Wi-Fi passphrase never goes on nmcli's argv.

nmcli's argv is readable by any local user from /proc/<pid>/cmdline while it
runs. The control daemon hands the secret to `nmcli connection up` in a
passwd-file instead (one "<setting>.<property>:<secret>" line), created 0600
in a fresh 0700 directory and removed on success, on failure and on an
exception.

All values here are fakes; nmcli is not run (subprocess.run is replaced).
"""

from __future__ import annotations

import logging
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from azazel_edge_control import wifi_connect  # noqa: E402

FAKE_SSID = "example-ssid"
FAKE_UUID = "0e0e0e0e-1111-4222-8333-444444444444"
# Leading/trailing blanks, a backslash, colons, '#' and non-ASCII: each one
# is something nmcli's passwd-file parser would change if written raw.
TRICKY = " fake\\pass:#wordé "
PLAIN = "fake-passphrase-123"


def nm_unescape(value: str) -> str:
    """Port of NetworkManager's nm_utils_buf_utf8safe_unescape with
    NM_UTILS_STR_UTF8_SAFE_UNESCAPE_STRIP_SPACES, as nmcli applies it to the
    secret of a passwd-file line (identical in 1.42.4 and 1.52.x)."""
    s = value.lstrip(" \t\n\r\f\v")
    if "\\" not in s:
        return s.rstrip(" \t\n\r\f\v")
    out = bytearray()
    i = 0
    while i < len(s):
        ch = s[i]
        if ch != "\\":
            j = s.find("\\", i)
            chunk = s[i:] if j < 0 else s[i:j]
            if j < 0:
                chunk = chunk.rstrip(" \t\n\r\f\v")
            out += chunk.encode("utf-8")
            i = len(s) if j < 0 else j
            continue
        i += 1
        if i >= len(s):
            break
        ch = s[i]
        if ch.isdigit():
            v = int(ch)
            i += 1
            for _ in range(2):
                if i < len(s) and s[i] in "01234567":
                    v = v * 8 + int(s[i])
                    i += 1
                else:
                    break
            out.append(v & 0xFF)
        else:
            out += {"b": b"\b", "f": b"\f", "n": b"\n", "r": b"\r", "t": b"\t", "v": b"\v"}.get(ch, ch.encode())
            i += 1
    return out.decode("utf-8")


ORIG_UUID = "0a0a0a0a-1111-4222-8333-555555555555"
CLONE_UUID = "0c0c0c0c-1111-4222-8333-666666666666"
OTHER_UUID = "0d0d0d0d-1111-4222-8333-777777777777"


class FakeNmcli:
    """Records every argv and answers like nmcli for the calls connect_nm
    makes, over a small store of profiles {uuid: {name, ssid}}."""

    def __init__(self, *, saved: bool, ap_security="WPA2", up_rc: int = 0, up_raises: bool = False,
                 existing_key_mgmt: str = "wpa-psk", clone_rc: int = 0, mod_fail: str = "",
                 add_stdout: str = f"Connection '{FAKE_SSID}' ({FAKE_UUID}) successfully added.\n"):
        self.ap_security = [ap_security] if isinstance(ap_security, str) else list(ap_security)
        self.existing_key_mgmt = existing_key_mgmt
        self.up_rc = up_rc
        self.up_raises = up_raises
        self.clone_rc = clone_rc
        self.mod_fail = mod_fail
        self.add_stdout = add_stdout
        self.profiles: dict = {OTHER_UUID: {"name": "example-other", "ssid": "other-ssid", "psk": "kept"}}
        if saved:
            self.profiles[ORIG_UUID] = {"name": "example-saved", "ssid": FAKE_SSID, "psk": "old"}
        self.active: set = set()
        self.by_name: list = []
        self.calls: list[list[str]] = []
        self.passwd_files: list[dict] = []

    def names(self):
        return sorted(p["name"] for p in self.profiles.values())

    def _by_name(self, name):
        return [u for u, p in self.profiles.items() if p["name"] == name]

    def __call__(self, cmd, *args, **kwargs):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        out, rc = "", 0
        if cmd[:6] == ["nmcli", "-t", "-f", "NAME,UUID,TYPE", "con", "show"]:
            out = "".join(f"{p['name']}:{u}:802-11-wireless\n" for u, p in self.profiles.items())
        elif cmd == ["nmcli", "-t", "-f", "UUID", "con", "show", "--active"]:
            out = "".join(u + "\n" for u in self.active)
        elif cmd[:6] == ["nmcli", "-t", "-f", "NAME,UUID", "con", "show"]:
            out = "".join(f"{p['name']}:{u}\n" for u, p in self.profiles.items())
        elif cmd[:4] == ["nmcli", "-t", "-f", "802-11-wireless.ssid"]:
            if cmd[-2] != "uuid":
                self.by_name.append(cmd)
            prof = self.profiles.get(cmd[-1])
            out = f"802-11-wireless.ssid:{prof['ssid']}\n" if prof else ""
            rc = 0 if prof else 10
        elif cmd[:3] == ["nmcli", "-g", "802-11-wireless-security.key-mgmt"]:
            if cmd[-2] != "uuid":
                self.by_name.append(cmd)
            out = self.existing_key_mgmt + "\n"
        elif cmd[:3] == ["nmcli", "-g", "connection.uuid"]:
            self.by_name.append(cmd)
            out = "".join(u + "\n" for u in self._by_name(cmd[-1]))
        elif cmd[:4] == ["nmcli", "-t", "-f", "SSID,SECURITY"]:
            out = "other-ssid:WPA2 802.1X\n" + "".join(f"{FAKE_SSID}:{sec}\n" for sec in self.ap_security)
        elif cmd[:3] == ["nmcli", "con", "add"]:
            self.profiles[FAKE_UUID] = {"name": FAKE_SSID, "ssid": FAKE_SSID, "psk": None}
            out = self.add_stdout
        elif cmd[:4] == ["nmcli", "con", "clone", "uuid"]:
            rc = self.clone_rc
            if not rc:
                src = self.profiles[cmd[4]]
                self.profiles[CLONE_UUID] = dict(src, name=cmd[5])
                out = f"{src['name']} ({cmd[4]}) cloned as {cmd[5]} ({CLONE_UUID}).\n"
        elif cmd[:3] == ["nmcli", "con", "up"] and cmd[3] != "uuid":
            self.by_name.append(cmd)
            rc = 2
        elif cmd[:4] == ["nmcli", "con", "mod", "uuid"]:
            if self.mod_fail and self.mod_fail in cmd:
                rc = 1
            elif cmd[5:7] == ["connection.id", cmd[-1]]:
                self.profiles[cmd[4]]["name"] = cmd[6]
            elif cmd[5:7] == ["wifi-sec.psk-flags", "2"]:
                self.profiles[cmd[4]]["psk"] = None
        elif cmd[:4] == ["nmcli", "con", "delete", "uuid"]:
            rc = 0 if self.profiles.pop(cmd[4], None) else 10
        elif cmd[:3] == ["nmcli", "con", "delete"] or cmd[:3] == ["nmcli", "con", "mod"] and cmd[3] != "uuid":
            self.by_name.append(cmd)
            rc = 2
        elif cmd[:3] == ["nmcli", "con", "up"] and "passwd-file" in cmd:
            path = Path(cmd[cmd.index("passwd-file") + 1])
            st, dst = os.lstat(path), os.lstat(path.parent)
            self.passwd_files.append({
                "path": path,
                "mode": stat.S_IMODE(st.st_mode),
                "regular": stat.S_ISREG(st.st_mode),
                "dir_mode": stat.S_IMODE(dst.st_mode),
                "lines": path.read_text(encoding="ascii").splitlines(),
            })
            if self.up_raises:
                raise subprocess.TimeoutExpired(cmd, 20)
            rc = self.up_rc
            if not rc and cmd[3] == "uuid" and cmd[4] in self.profiles:
                self.profiles[cmd[4]]["psk"] = "new"
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="Error: fake failure\n" if rc else "")

    def argv_with(self, *head):
        return [c for c in self.calls if c[:len(head)] == list(head)]


@pytest.fixture
def secret_base(tmp_path, monkeypatch):
    base = tmp_path / "run"
    base.mkdir()
    monkeypatch.setattr(wifi_connect, "NM_PASSWD_FILE_BASE", str(base))
    return base


@pytest.fixture(autouse=True)
def private_lock(tmp_path, monkeypatch):
    lock = tmp_path / "wifi-connect.lock"
    monkeypatch.setattr(wifi_connect, "NM_CONNECT_LOCK_PATH", str(lock))
    return lock


def _connect(monkeypatch, fake, passphrase, security="WPA2", persist=False):
    monkeypatch.setattr(wifi_connect.subprocess, "run", fake)
    out = wifi_connect.connect_nm("wlan-fake0", FAKE_SSID, security, passphrase, persist)
    assert fake.by_name == [], "a profile was addressed by name"
    return out


def _assert_never_on_argv(fake, passphrase):
    for argv in fake.calls:
        for arg in argv:
            assert passphrase not in arg, argv
            assert passphrase.strip() not in arg, argv


def _assert_passwd_file_gone(fake, secret_base):
    assert fake.passwd_files, "nmcli con up was not given a passwd-file"
    for seen in fake.passwd_files:
        assert not os.path.lexists(seen["path"])
        assert not os.path.lexists(seen["path"].parent)
    assert list(secret_base.iterdir()) == []


def test_the_escape_round_trips_through_nmcli_unescaping():
    for value in (PLAIN, TRICKY, "  \t", "a\\101b", "あいうえお12345"):
        escaped = wifi_connect._nm_passwd_escape(value)
        assert escaped.isascii() and "\n" not in escaped
        assert nm_unescape(escaped) == value
    with pytest.raises(ValueError) as err:
        wifi_connect._nm_passwd_escape("fake\x00secret")
    assert "fake" not in str(err.value)


@pytest.mark.parametrize("passphrase", [PLAIN, TRICKY])
def test_new_profile_takes_the_passphrase_from_a_private_passwd_file(monkeypatch, secret_base, passphrase):
    fake = FakeNmcli(saved=False)
    assert _connect(monkeypatch, fake, passphrase) == {"ok": True}
    _assert_never_on_argv(fake, passphrase)
    assert not fake.argv_with("nmcli", "dev", "wifi", "connect")
    (add,) = fake.argv_with("nmcli", "con", "add")
    assert add[add.index("ssid") + 1] == FAKE_SSID
    assert add[add.index("connection.autoconnect") + 1] == "no"
    assert add[add.index("wifi-sec.key-mgmt") + 1] == "wpa-psk"
    assert not any(a.startswith("wifi-sec.psk") or a.endswith(".psk") for a in add)
    (up,) = fake.argv_with("nmcli", "con", "up")
    assert up[3:5] == ["uuid", FAKE_UUID]
    (seen,) = fake.passwd_files
    assert seen["regular"] and seen["mode"] == 0o600 and seen["dir_mode"] == 0o700
    assert Path(seen["path"]).parent.parent == secret_base
    (line,) = seen["lines"]
    prop, _, value = line.partition(":")
    assert prop == "802-11-wireless-security.psk" and nm_unescape(value) == passphrase
    _assert_passwd_file_gone(fake, secret_base)
    # Not kept: deleted after use, as before.
    assert fake.argv_with("nmcli", "con", "delete")


def test_new_profile_is_found_by_its_ssid_when_nmcli_prints_no_uuid(monkeypatch, secret_base):
    fake = FakeNmcli(saved=False, add_stdout="")
    assert _connect(monkeypatch, fake, PLAIN)["ok"] is True
    (up,) = fake.argv_with("nmcli", "con", "up")
    assert up[3:5] == ["uuid", FAKE_UUID]


@pytest.mark.parametrize("ap_security,key_mgmt,prop", [
    ("WPA2", "wpa-psk", "802-11-wireless-security.psk"),
    ("WPA1 WPA2", "wpa-psk", "802-11-wireless-security.psk"),
    ("WPA2 WPA3", "wpa-psk", "802-11-wireless-security.psk"),  # transition: as NetworkManager completes it
    ("WPA3", "sae", "802-11-wireless-security.psk"),
    ("WEP", "none", "802-11-wireless-security.wep-key0"),
    ("", "wpa-psk", "802-11-wireless-security.psk"),
])
def test_new_profile_security_follows_the_ap(monkeypatch, secret_base, ap_security, key_mgmt, prop):
    fake = FakeNmcli(saved=False, ap_security=ap_security)
    assert _connect(monkeypatch, fake, PLAIN, persist=True)["ok"] is True
    (add,) = fake.argv_with("nmcli", "con", "add")
    assert add[add.index("wifi-sec.key-mgmt") + 1] == key_mgmt
    assert ("wifi-sec.wep-key-type" in add) == (key_mgmt == "none")
    assert fake.passwd_files[0]["lines"][0].split(":", 1)[0] == prop
    assert not fake.argv_with("nmcli", "con", "delete")  # persist keeps it
    _assert_never_on_argv(fake, PLAIN)


def test_a_saved_profile_takes_the_new_psk_through_a_clone_and_keeps_its_name(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True)
    assert _connect(monkeypatch, fake, TRICKY)["ok"] is True
    _assert_never_on_argv(fake, TRICKY)
    clone_name = wifi_connect.NM_PENDING_CLONE_PREFIX + ORIG_UUID
    assert fake.argv_with("nmcli", "con", "clone") == [["nmcli", "con", "clone", "uuid", ORIG_UUID, clone_name]]
    mods = [c[5:] for c in fake.argv_with("nmcli", "con", "mod", "uuid") if c[4] == CLONE_UUID]
    assert mods[:3] == [["connection.autoconnect", "no"], ["wifi-sec.psk-flags", "2"], ["wifi-sec.psk-flags", "0"]]
    # The original is never modified; it is deleted only after the clone came up.
    assert not [c for c in fake.calls if c[:3] == ["nmcli", "con", "mod"] and ORIG_UUID in c]
    final = ["nmcli", "con", "mod", "uuid", CLONE_UUID, "connection.autoconnect", "no"]
    assert fake.calls.count(final) == 2 and fake.calls[-1] == final  # the renamed clone, at the end
    (up,) = fake.argv_with("nmcli", "con", "up")
    assert up[3:6] == ["uuid", CLONE_UUID, "passwd-file"]
    order = [fake.calls.index(c) for c in (up, ["nmcli", "con", "delete", "uuid", ORIG_UUID],
                                           ["nmcli", "con", "mod", "uuid", CLONE_UUID, "connection.id", "example-saved"])]
    assert order == sorted(order)
    assert fake.profiles[CLONE_UUID]["name"] == "example-saved" and ORIG_UUID not in fake.profiles
    assert fake.profiles[CLONE_UUID]["psk"] == "new"
    assert fake.names() == ["example-other", "example-saved"]
    assert nm_unescape(fake.passwd_files[0]["lines"][0].split(":", 1)[1]) == TRICKY
    _assert_passwd_file_gone(fake, secret_base)


@pytest.mark.parametrize("failure", ["up_rc", "timeout", "clone", "prepare"])
def test_a_failed_new_psk_leaves_the_saved_profile_untouched(monkeypatch, secret_base, failure):
    fake = FakeNmcli(saved=True, up_rc=4 if failure == "up_rc" else 0, up_raises=failure == "timeout",
                     clone_rc=1 if failure == "clone" else 0,
                     mod_fail="wifi-sec.psk-flags" if failure == "prepare" else "")
    out = _connect(monkeypatch, fake, PLAIN)
    assert out["ok"] is False and PLAIN not in out.get("error", "")
    assert fake.profiles[ORIG_UUID] == {"name": "example-saved", "ssid": FAKE_SSID, "psk": "old"}
    assert CLONE_UUID not in fake.profiles
    assert fake.names() == ["example-other", "example-saved"]
    assert not [c for c in fake.calls if ORIG_UUID in c and c[:3] in (["nmcli", "con", "mod"], ["nmcli", "con", "delete"])]
    if failure != "clone":
        assert ["nmcli", "con", "delete", "uuid", CLONE_UUID] in fake.calls
    _assert_never_on_argv(fake, PLAIN)
    assert list(secret_base.iterdir()) == []


def test_stale_clones_are_swept_by_uuid_and_nothing_else(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True)
    stale = "0e0e0e0e-2222-4222-8333-888888888888"
    orphan = "0f0f0f0f-2222-4222-8333-999999999999"
    prefix = wifi_connect.NM_PENDING_CLONE_PREFIX
    fake.profiles[stale] = {"name": prefix + ORIG_UUID, "ssid": FAKE_SSID, "psk": "new"}
    fake.profiles[orphan] = {"name": prefix + "01010101-2222-4222-8333-000000000000", "ssid": FAKE_SSID, "psk": "x"}
    fake.profiles["02020202-2222-4222-8333-000000000000"] = {"name": "my-" + prefix + ORIG_UUID, "ssid": "s", "psk": "y"}
    assert _connect(monkeypatch, fake, None)["ok"] is True
    deletes = fake.argv_with("nmcli", "con", "delete")
    assert deletes == [["nmcli", "con", "delete", "uuid", stale]]
    assert fake.calls.index(deletes[0]) < fake.calls.index(fake.argv_with("nmcli", "con", "up")[0])
    assert orphan in fake.profiles  # its original is gone: the only copy is kept
    assert "02020202-2222-4222-8333-000000000000" in fake.profiles and OTHER_UUID in fake.profiles


def test_existing_profile_without_a_passphrase_is_brought_up_as_before(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True)
    assert _connect(monkeypatch, fake, None)["ok"] is True
    assert fake.argv_with("nmcli", "con", "up") == [["nmcli", "con", "up", "uuid", ORIG_UUID]]
    assert not [c for c in fake.calls if "wifi-sec.psk-flags" in c]
    assert fake.passwd_files == [] and list(secret_base.iterdir()) == []


@pytest.mark.parametrize("saved", [False, True])
def test_the_passwd_file_is_removed_when_nmcli_fails(monkeypatch, secret_base, saved):
    fake = FakeNmcli(saved=saved, up_rc=4)
    out = _connect(monkeypatch, fake, PLAIN)
    assert out["ok"] is False and PLAIN not in out["error"]
    _assert_never_on_argv(fake, PLAIN)
    _assert_passwd_file_gone(fake, secret_base)


@pytest.mark.parametrize("saved", [False, True])
def test_the_passwd_file_is_removed_and_nothing_logged_when_nmcli_times_out(monkeypatch, secret_base, caplog, saved):
    fake = FakeNmcli(saved=saved, up_raises=True)
    with caplog.at_level(logging.DEBUG):
        out = _connect(monkeypatch, fake, TRICKY)
    assert out["ok"] is False
    assert TRICKY.strip() not in out["error"]
    assert all(TRICKY.strip() not in r.getMessage() for r in caplog.records)
    _assert_passwd_file_gone(fake, secret_base)


def test_a_passphrase_nmcli_cannot_carry_is_refused_without_echoing_it(monkeypatch, secret_base):
    fake = FakeNmcli(saved=False)
    out = _connect(monkeypatch, fake, "fake\x00passphrase")
    assert out["ok"] is False and "fake" not in out["error"]
    assert not fake.argv_with("nmcli", "con", "add") and not fake.argv_with("nmcli", "con", "up")
    assert list(secret_base.iterdir()) == []


def test_the_passwd_file_lives_under_run_and_no_nmcli_call_carries_a_secret_in_the_source():
    assert wifi_connect.NM_PASSWD_FILE_BASE == "/run"
    src = (ROOT / "py" / "azazel_edge_control" / "wifi_connect.py").read_text(encoding="utf-8")
    assert '"password", passphrase' not in src
    assert '"wifi-sec.psk", passphrase' not in src


@pytest.mark.parametrize("ap_security", ["WPA2 802.1X", "WPA3 802.1X", "WPA1 WPA2 802.1X", "802.1X",
                                         ["WPA2", "WPA2 802.1X"]])
def test_an_enterprise_ap_is_refused_before_any_profile_is_made(monkeypatch, secret_base, ap_security):
    fake = FakeNmcli(saved=False, ap_security=ap_security)
    out = _connect(monkeypatch, fake, PLAIN)
    assert out == {"ok": False, "error": wifi_connect.ENTERPRISE_ERROR}
    assert not fake.argv_with("nmcli", "con", "add") and not fake.argv_with("nmcli", "con", "up")
    assert list(secret_base.iterdir()) == []


@pytest.mark.parametrize("key_mgmt", ["wpa-eap", "wpa-eap-suite-b-192", "ieee8021x"])
def test_an_existing_enterprise_profile_is_not_rewritten_to_psk(monkeypatch, secret_base, key_mgmt):
    fake = FakeNmcli(saved=True, existing_key_mgmt=key_mgmt)
    out = _connect(monkeypatch, fake, PLAIN)
    assert out == {"ok": False, "error": wifi_connect.ENTERPRISE_ERROR}
    assert not [c for c in fake.calls if c[:3] == ["nmcli", "con", "mod"]]
    assert not fake.argv_with("nmcli", "con", "up")
    # Without a passphrase it is brought up as it is, as before.
    fake = FakeNmcli(saved=True, existing_key_mgmt=key_mgmt)
    assert _connect(monkeypatch, fake, None)["ok"] is True
    assert not [c for c in fake.calls if c[:3] == ["nmcli", "con", "mod"] and "connection.autoconnect" not in c]


@pytest.mark.parametrize("aps,key_mgmt", [
    (["WPA3", "WPA2"], "wpa-psk"),
    (["WPA3", "WPA2 WPA3"], "wpa-psk"),
    (["WPA3", "WPA3"], "sae"),
    (["WPA3", "WEP"], "wpa-psk"),
    (["WEP", "WEP"], "none"),
])
def test_duplicate_ssids_pick_key_mgmt_across_every_ap(monkeypatch, secret_base, aps, key_mgmt):
    fake = FakeNmcli(saved=False, ap_security=aps)
    assert _connect(monkeypatch, fake, PLAIN, persist=True)["ok"] is True
    (add,) = fake.argv_with("nmcli", "con", "add")
    assert add[add.index("wifi-sec.key-mgmt") + 1] == key_mgmt


@pytest.mark.parametrize("failure", ["rc", "timeout"])
def test_a_new_profile_is_deleted_by_uuid_when_activation_fails(monkeypatch, secret_base, failure):
    fake = FakeNmcli(saved=False, up_rc=4 if failure == "rc" else 0, up_raises=failure == "timeout")
    out = _connect(monkeypatch, fake, PLAIN, persist=True)
    assert out["ok"] is False
    assert fake.argv_with("nmcli", "con", "delete", "uuid") == [["nmcli", "con", "delete", "uuid", FAKE_UUID]]
    up_index = fake.calls.index(fake.argv_with("nmcli", "con", "up")[0])
    assert fake.calls.index(fake.argv_with("nmcli", "con", "delete", "uuid")[0]) > up_index
    _assert_passwd_file_gone(fake, secret_base)


def test_a_new_profile_is_deleted_when_the_passwd_file_cannot_be_made(monkeypatch, tmp_path):
    monkeypatch.setattr(wifi_connect, "NM_PASSWD_FILE_BASE", str(tmp_path / "missing"))
    fake = FakeNmcli(saved=False)
    out = _connect(monkeypatch, fake, PLAIN, persist=True)
    assert out["ok"] is False and PLAIN not in out["error"]
    assert fake.argv_with("nmcli", "con", "add")
    assert not fake.argv_with("nmcli", "con", "up")
    assert fake.argv_with("nmcli", "con", "delete", "uuid") == [["nmcli", "con", "delete", "uuid", FAKE_UUID]]


def test_a_successful_new_profile_is_not_deleted_by_uuid(monkeypatch, secret_base):
    fake = FakeNmcli(saved=False)
    assert _connect(monkeypatch, fake, PLAIN, persist=True)["ok"] is True
    assert not fake.argv_with("nmcli", "con", "delete")


def test_a_key_mgmt_fix_goes_to_the_clone_not_the_original(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True, existing_key_mgmt="none")
    assert _connect(monkeypatch, fake, PLAIN)["ok"] is True
    mods = [c[5:] for c in fake.argv_with("nmcli", "con", "mod", "uuid") if c[4] == CLONE_UUID]
    assert ["wifi-sec.key-mgmt", "wpa-psk"] in mods
    assert not [c for c in fake.argv_with("nmcli", "con", "mod") if "wifi-sec.key-mgmt" in c and CLONE_UUID not in c]


def test_a_same_named_profile_of_another_ssid_is_never_cloned_or_deleted(monkeypatch, secret_base):
    fake = FakeNmcli(saved=False)
    twin = "0b0b0b0b-1111-4222-8333-121212121212"
    # Listed first: a name lookup would pick it.
    fake.profiles = {twin: {"name": "example-saved", "ssid": "other-ssid", "psk": "twin"},
                     ORIG_UUID: {"name": "example-saved", "ssid": FAKE_SSID, "psk": "old"}}
    assert _connect(monkeypatch, fake, PLAIN)["ok"] is True
    assert fake.argv_with("nmcli", "con", "clone") == [
        ["nmcli", "con", "clone", "uuid", ORIG_UUID, wifi_connect.NM_PENDING_CLONE_PREFIX + ORIG_UUID]]
    assert fake.profiles[twin] == {"name": "example-saved", "ssid": "other-ssid", "psk": "twin"}
    assert not [c for c in fake.calls if twin in c and c[1] == "con"
                and c[2] in ("mod", "delete", "clone", "up")]
    assert ORIG_UUID not in fake.profiles and fake.profiles[CLONE_UUID]["name"] == "example-saved"


def test_an_active_stale_clone_is_kept(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True)
    stale = "0e0e0e0e-2222-4222-8333-888888888888"
    fake.profiles[stale] = {"name": wifi_connect.NM_PENDING_CLONE_PREFIX + ORIG_UUID, "ssid": FAKE_SSID, "psk": "x"}
    fake.active = {stale}
    assert _connect(monkeypatch, fake, None)["ok"] is True
    assert stale in fake.profiles and not fake.argv_with("nmcli", "con", "delete")


def test_a_second_connect_waits_and_reports_busy(monkeypatch, secret_base, private_lock):
    import fcntl
    monkeypatch.setattr(wifi_connect, "NM_CONNECT_LOCK_WAIT_SEC", 0.3)
    fake = FakeNmcli(saved=True)
    holder = os.open(private_lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX)
        out = _connect(monkeypatch, fake, PLAIN)
        assert out == {"ok": False, "error": wifi_connect.BUSY_ERROR}
        assert fake.calls == []  # neither the sweep nor the connect ran
    finally:
        os.close(holder)
    assert _connect(monkeypatch, fake, PLAIN)["ok"] is True  # free again
    assert stat.S_IMODE(os.stat(private_lock).st_mode) == 0o600


def test_the_lock_is_held_for_the_sweep_and_the_connect_and_released_on_error(monkeypatch, secret_base, private_lock):
    import fcntl
    seen = []

    def probe(cmd, *a, **kw):
        fd = os.open(private_lock, os.O_RDWR)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen.append("free")
            except BlockingIOError:
                seen.append("held")
        finally:
            os.close(fd)
        return fake(cmd, *a, **kw)

    fake = FakeNmcli(saved=True, up_raises=True)
    monkeypatch.setattr(wifi_connect.subprocess, "run", probe)
    assert wifi_connect.connect_nm("wlan-fake0", FAKE_SSID, "WPA2", PLAIN, False)["ok"] is False
    assert seen and set(seen) == {"held"}
    fd = os.open(private_lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released after the exception
    finally:
        os.close(fd)


@pytest.mark.parametrize("kind", ["symlink", "wide"])
def test_an_unsafe_lock_file_refuses_the_connect(monkeypatch, secret_base, private_lock, tmp_path, kind):
    if kind == "symlink":
        private_lock.symlink_to(tmp_path / "elsewhere")
    else:
        private_lock.write_text("", encoding="utf-8")
        private_lock.chmod(0o666)
    fake = FakeNmcli(saved=True)
    out = _connect(monkeypatch, fake, PLAIN)
    assert out == {"ok": False, "error": "Wi-Fi connect lock unavailable"}
    assert fake.calls == []
    assert not (tmp_path / "elsewhere").exists()


def test_the_lock_lives_under_run():
    src = (ROOT / "py" / "azazel_edge_control" / "wifi_connect.py").read_text(encoding="utf-8")
    assert 'NM_CONNECT_LOCK_PATH = "/run/azazel-edge-wifi-connect.lock"' in src


# ------------------------------------------- locale and the manual CLI (#477)

class _EnvRecorder:
    """Wraps FakeNmcli and keeps the env= each nmcli call was given."""

    def __init__(self, fake):
        self.fake = fake
        self.envs: list = []

    def __call__(self, cmd, *args, **kwargs):
        if list(cmd)[:1] == ["nmcli"]:
            self.envs.append((list(cmd), kwargs.get("env")))
        return self.fake(cmd, *args, **kwargs)


@pytest.mark.parametrize("saved", [False, True])
def test_every_nmcli_call_runs_with_the_c_locale(monkeypatch, secret_base, saved):
    monkeypatch.setenv("LANG", "ja_JP.UTF-8")
    monkeypatch.setenv("LC_MESSAGES", "ja_JP.UTF-8")
    monkeypatch.setenv("LANGUAGE", "ja")
    rec = _EnvRecorder(FakeNmcli(saved=saved))
    monkeypatch.setattr(wifi_connect.subprocess, "run", rec)
    assert wifi_connect.connect_nm("wlan-fake0", FAKE_SSID, "WPA2", PLAIN, True) == {"ok": True}
    assert rec.envs
    for cmd, env in rec.envs:
        assert env is not None, cmd
        assert env["LC_ALL"] == "C.UTF-8" and env["LANG"] == "C.UTF-8", cmd
        assert "LANGUAGE" not in env and "LC_MESSAGES" not in env, cmd
        assert env.get("PATH") == os.environ.get("PATH"), cmd


def _nmcli_calls(src: str):
    """(call node, env keyword or None) of every subprocess call in ``src``
    whose argv is an nmcli command: a literal list starting with "nmcli", or
    a variable last assigned such a list shortly before the call."""
    import ast

    tree = ast.parse(src)
    assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"):
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.List):
            runs_nmcli = bool(first.elts) and isinstance(first.elts[0], ast.Constant) and first.elts[0].value == "nmcli"
        elif isinstance(first, ast.Name):
            prior = [a for a in assigns if a.lineno < node.lineno and node.lineno - a.lineno < 40
                     and any(isinstance(t, ast.Name) and t.id == first.id for t in a.targets)]
            value = prior[-1].value if prior else None
            runs_nmcli = (isinstance(value, ast.List) and bool(value.elts) and isinstance(value.elts[0], ast.Constant)
                          and value.elts[0].value == "nmcli")
        else:
            runs_nmcli = False
        if runs_nmcli:
            yield node, next((k.value for k in node.keywords if k.arg == "env"), None)


def test_every_nmcli_call_in_the_repository_passes_the_locale_env():
    """Every Python file that starts nmcli (found by scanning the repository,
    not a fixed list) passes env=_nmcli_env() on each call."""
    import ast

    files = [p for top in ("py", "azazel_edge_web") for p in (ROOT / top).rglob("*.py")]
    checked: dict = {}
    for path in files:
        src = path.read_text(encoding="utf-8")
        if "nmcli" not in src:
            continue
        for node, env in _nmcli_calls(src):
            rel = str(path.relative_to(ROOT))
            checked[rel] = checked.get(rel, 0) + 1
            assert env is not None and ast.unparse(env) == "_nmcli_env()", f"{rel}:{node.lineno}"
    assert checked.get("py/azazel_edge_control/wifi_connect.py", 0) >= 17
    assert checked.get("py/azazel_edge_control/wifi_scan.py", 0) >= 6
    assert checked.get("py/azazel_edge_control/daemon.py", 0) >= 3
    # One definition, shared.
    scan_src = (ROOT / "py" / "azazel_edge_control" / "wifi_scan.py").read_text(encoding="utf-8")
    assert "def _nmcli_env(" in scan_src
    for name in ("wifi_connect.py", "daemon.py"):
        other = (ROOT / "py" / "azazel_edge_control" / name).read_text(encoding="utf-8")
        assert "def _nmcli_env(" not in other and "_nmcli_env" in other


def test_the_saved_network_scan_runs_nmcli_with_the_c_locale(monkeypatch):
    from azazel_edge_control import wifi_scan

    monkeypatch.setenv("LANG", "ja_JP.UTF-8")
    seen = []

    def fake(cmd, *args, **kwargs):
        seen.append((list(cmd), kwargs.get("env")))
        out = "example-saved:802-11-wireless\n" if "NAME,TYPE" in cmd else "example-ssid\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    monkeypatch.setattr(wifi_scan.subprocess, "run", fake)
    wifi_scan.get_saved_networks_nm()
    nm = [(c, e) for c, e in seen if c[:1] == ["nmcli"]]
    assert nm
    for cmd, env in nm:
        assert env is not None and env["LC_ALL"] == "C.UTF-8" and env["LANG"] == "C.UTF-8", cmd


def test_the_uuid_of_a_new_profile_is_read_from_the_c_locale_message(monkeypatch, secret_base):
    rec = _EnvRecorder(FakeNmcli(saved=False))
    monkeypatch.setattr(wifi_connect.subprocess, "run", rec)
    assert wifi_connect.connect_nm("wlan-fake0", FAKE_SSID, "WPA2", PLAIN, True) == {"ok": True}
    (up,) = rec.fake.argv_with("nmcli", "con", "up")
    assert up[3:5] == ["uuid", FAKE_UUID]


def test_the_cli_refuses_a_passphrase_on_argv_without_echoing_it(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(wifi_connect, "connect_wifi", lambda *a, **k: called.append(a) or {"ok": True})
    for argv in (["example-ssid", "--passphrase", PLAIN], [f"--passphrase={PLAIN}", "example-ssid"],
                 [f"--password={PLAIN}", "example-ssid"], ["example-ssid", f"--passphrase-stdi={PLAIN}"],
                 ["example-ssid", f"--pass={PLAIN}"]):
        assert wifi_connect.main(argv) == 2
        err = capsys.readouterr().err
        assert "--passphrase-stdin" in err and PLAIN not in err
    assert called == []


@pytest.mark.parametrize("line, expected", [(PLAIN + "\n", PLAIN), (PLAIN + "\r\n", PLAIN), (PLAIN, PLAIN),
                                            (" " + PLAIN + " \n", " " + PLAIN + " "), ("\n", None)])
def test_the_cli_reads_the_passphrase_from_stdin(monkeypatch, capsys, line, expected):
    import io

    called = []
    monkeypatch.setattr(wifi_connect, "connect_wifi", lambda *a: called.append(a) or {"ok": True})
    assert wifi_connect.main(["example-ssid", "--security", "WPA2", "--passphrase-stdin"], stdin=io.StringIO(line)) == 0
    assert called == [("example-ssid", "WPA2", expected, False)]
    assert PLAIN not in capsys.readouterr().out


def test_the_cli_without_the_stdin_flag_passes_no_passphrase(monkeypatch, capsys):
    import io

    called = []
    monkeypatch.setattr(wifi_connect, "connect_wifi", lambda *a: called.append(a) or {"ok": True})
    assert wifi_connect.main(["example-ssid", "--persist"], stdin=io.StringIO(PLAIN + "\n")) == 0
    assert called == [("example-ssid", "UNKNOWN", None, True)]


def test_the_cli_has_no_passphrase_argument():
    src = (ROOT / "py" / "azazel_edge_control" / "wifi_connect.py").read_text(encoding="utf-8")
    assert 'argparse.ArgumentParser(description="Wi-Fi Connect Test", allow_abbrev=False)' in src
    assert 'add_argument("--passphrase"' not in src and "args.passphrase," not in src
