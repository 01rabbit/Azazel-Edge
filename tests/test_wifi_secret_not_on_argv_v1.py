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


class FakeNmcli:
    """Records every argv and answers like nmcli for the calls connect_nm makes."""

    def __init__(self, *, saved: bool, ap_security="WPA2", up_rc: int = 0, up_raises: bool = False,
                 existing_key_mgmt: str = "wpa-psk",
                 add_stdout: str = f"Connection '{FAKE_SSID}' ({FAKE_UUID}) successfully added.\n"):
        self.saved = saved
        self.ap_security = [ap_security] if isinstance(ap_security, str) else list(ap_security)
        self.existing_key_mgmt = existing_key_mgmt
        self.up_rc = up_rc
        self.up_raises = up_raises
        self.add_stdout = add_stdout
        self.added = False
        self.calls: list[list[str]] = []
        self.passwd_files: list[dict] = []

    def __call__(self, cmd, *args, **kwargs):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        out, rc = "", 0
        if cmd[:6] == ["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"]:
            out = ("example-saved:802-11-wireless\n" if self.saved else "") + \
                (f"{FAKE_SSID}:802-11-wireless\n" if self.added else "")
        elif cmd[:4] == ["nmcli", "-t", "-f", "802-11-wireless.ssid"]:
            out = f"802-11-wireless.ssid:{FAKE_SSID}\n"
        elif cmd[:3] == ["nmcli", "-g", "802-11-wireless-security.key-mgmt"]:
            out = self.existing_key_mgmt + "\n"
        elif cmd[:4] == ["nmcli", "-t", "-f", "SSID,SECURITY"]:
            out = "other-ssid:WPA2 802.1X\n" + "".join(f"{FAKE_SSID}:{sec}\n" for sec in self.ap_security)
        elif cmd[:3] == ["nmcli", "con", "add"]:
            self.added = True
            out = self.add_stdout
        elif cmd[:4] == ["nmcli", "con", "delete", "uuid"]:
            self.added = False
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
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="Error: fake failure\n" if rc else "")

    def argv_with(self, *head):
        return [c for c in self.calls if c[:len(head)] == list(head)]


@pytest.fixture
def secret_base(tmp_path, monkeypatch):
    base = tmp_path / "run"
    base.mkdir()
    monkeypatch.setattr(wifi_connect, "NM_PASSWD_FILE_BASE", str(base))
    return base


def _connect(monkeypatch, fake, passphrase, security="WPA2", persist=False):
    monkeypatch.setattr(wifi_connect.subprocess, "run", fake)
    return wifi_connect.connect_nm("wlan-fake0", FAKE_SSID, security, passphrase, persist)


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


def test_new_profile_falls_back_to_the_name_when_nmcli_prints_no_uuid(monkeypatch, secret_base):
    fake = FakeNmcli(saved=False, add_stdout="")
    assert _connect(monkeypatch, fake, PLAIN)["ok"] is True
    (up,) = fake.argv_with("nmcli", "con", "up")
    assert up[3:5] == ["id", FAKE_SSID]


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


def test_existing_profile_drops_the_stored_psk_and_takes_the_new_one_from_the_file(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True)
    assert _connect(monkeypatch, fake, TRICKY)["ok"] is True
    _assert_never_on_argv(fake, TRICKY)
    flags = [c[c.index("wifi-sec.psk-flags") + 1] for c in fake.calls if "wifi-sec.psk-flags" in c]
    assert flags == ["2", "0"]
    assert not [c for c in fake.calls if "wifi-sec.psk" in c]
    (up,) = fake.argv_with("nmcli", "con", "up")
    assert up[3] == "example-saved" and up[4] == "passwd-file"
    assert fake.calls.index(up) > max(i for i, c in enumerate(fake.calls) if "wifi-sec.psk-flags" in c)
    assert nm_unescape(fake.passwd_files[0]["lines"][0].split(":", 1)[1]) == TRICKY
    _assert_passwd_file_gone(fake, secret_base)


def test_existing_profile_without_a_passphrase_is_brought_up_as_before(monkeypatch, secret_base):
    fake = FakeNmcli(saved=True)
    assert _connect(monkeypatch, fake, None)["ok"] is True
    assert fake.argv_with("nmcli", "con", "up") == [["nmcli", "con", "up", "example-saved"]]
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
