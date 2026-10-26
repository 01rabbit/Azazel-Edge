"""Edge#477: secrets and scratch files are private from their first byte.

- provision_mattermost_workspace.sh writes the Mattermost workspace
  credentials file 0600 from the start (mktemp beside it, renamed over it),
  not with the default umask followed by chmod.
- azazel-edge-selftest (root) writes its SD write-speed test file under a
  new mktemp name instead of the fixed /tmp/azazel_sdtest, and removes it.

All values here are fakes.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PROVISION = ROOT / "installer" / "internal" / "provision_mattermost_workspace.sh"
SELFTEST = ROOT / "bin" / "azazel-edge-selftest"


def _function(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def _gnu_mv() -> bool:
    return subprocess.run(["mv", "--version"], capture_output=True).returncode == 0


needs_gnu_mv = pytest.mark.skipif(not _gnu_mv(), reason="mv -T is GNU coreutils (Debian); run in Linux")

FAKE_CREDS = "MATTERMOST_USERNAME=example-user\nMATTERMOST_PASSWORD=fake-password-123\n"


def _write_private(dst: Path, *, stub_chmod: bool) -> subprocess.CompletedProcess:
    # umask 022 is the usual default; with chmod stubbed out, only a file
    # that is 0600 from its creation ends up 0600.
    script = "umask 022\n" + ("chmod() { :; }\n" if stub_chmod else "") + \
        _function(PROVISION, "write_private_file") + 'write_private_file "$1"\n'
    return subprocess.run(["bash", "-c", script, "bash", str(dst)], input=FAKE_CREDS,
                          capture_output=True, text=True)


@needs_gnu_mv
@pytest.mark.parametrize("stub_chmod", [True, False])
def test_the_credentials_file_is_0600_from_its_creation(tmp_path, stub_chmod):
    dst = tmp_path / "mattermost-credentials.env"
    res = _write_private(dst, stub_chmod=stub_chmod)
    assert res.returncode == 0, res.stderr
    assert dst.read_text(encoding="utf-8") == FAKE_CREDS
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == [dst.name]  # no temp left


@needs_gnu_mv
def test_an_existing_wider_file_is_replaced_by_a_0600_one(tmp_path):
    dst = tmp_path / "mattermost-credentials.env"
    dst.write_text("OLD=1\n", encoding="utf-8")
    dst.chmod(0o644)
    res = _write_private(dst, stub_chmod=True)
    assert res.returncode == 0, res.stderr
    assert dst.read_text(encoding="utf-8") == FAKE_CREDS
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600


@needs_gnu_mv
@pytest.mark.parametrize("target_kind", ["file", "dir", "dangling"])
def test_a_symlink_at_the_credentials_path_is_replaced_not_followed(tmp_path, target_kind):
    target = tmp_path / "elsewhere"
    if target_kind == "file":
        target.write_text("victim\n", encoding="utf-8")
    elif target_kind == "dir":
        target.mkdir()
    dst = tmp_path / "mattermost-credentials.env"
    dst.symlink_to(target)
    res = _write_private(dst, stub_chmod=False)
    assert res.returncode == 0, res.stderr
    assert not dst.is_symlink() and dst.read_text(encoding="utf-8") == FAKE_CREDS
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    if target_kind == "file":
        assert target.read_text(encoding="utf-8") == "victim\n"
    elif target_kind == "dir":
        assert list(target.iterdir()) == []
    else:
        assert not target.exists()


def test_a_failed_write_leaves_no_partial_file(tmp_path):
    dst = tmp_path / "missing-dir" / "mattermost-credentials.env"
    res = _write_private(dst, stub_chmod=False)
    assert res.returncode != 0 and not dst.exists()


def test_write_outputs_uses_the_private_writer():
    src = PROVISION.read_text(encoding="utf-8")
    body = _function(PROVISION, "write_outputs")
    assert 'write_private_file "${CRED_ENV}" <<EOF' in body
    assert 'cat > "${CRED_ENV}"' not in src and 'chmod 0600 "${CRED_ENV}"' not in src


FAKE_TOKEN = "fake-token#with&odd\\chars"


def _upsert(dst: Path, key: str, value: str, *, stub_chmod: bool = True) -> subprocess.CompletedProcess:
    script = "set -euo pipefail\numask 022\n" + ("chmod() { :; }\n" if stub_chmod else "") + \
        _function(PROVISION, "write_private_file") + _function(PROVISION, "upsert_env") + \
        'upsert_env "$1" "$2" "$3"\n'
    return subprocess.run(["bash", "-c", script, "bash", str(dst), key, value], capture_output=True, text=True)


@needs_gnu_mv
def test_upsert_env_creates_the_env_file_0600(tmp_path):
    dst = tmp_path / "azazel-edge-web"
    res = _upsert(dst, "AZAZEL_MATTERMOST_BOT_TOKEN", FAKE_TOKEN)
    assert res.returncode == 0, res.stderr
    assert dst.read_text(encoding="utf-8") == f"AZAZEL_MATTERMOST_BOT_TOKEN={FAKE_TOKEN}\n"
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == [dst.name]


@needs_gnu_mv
def test_upsert_env_replaces_in_place_and_narrows_an_existing_file(tmp_path):
    dst = tmp_path / "azazel-edge-web"
    dst.write_text("A=1\nAZAZEL_MATTERMOST_BOT_TOKEN=old\nAZAZEL_MATTERMOST_BOT_TOKEN_X=keep\n"
                   "B=2\nAZAZEL_MATTERMOST_BOT_TOKEN=dup\nC=3", encoding="utf-8")
    dst.chmod(0o644)
    res = _upsert(dst, "AZAZEL_MATTERMOST_BOT_TOKEN", FAKE_TOKEN)
    assert res.returncode == 0, res.stderr
    assert dst.read_text(encoding="utf-8") == (
        f"A=1\nAZAZEL_MATTERMOST_BOT_TOKEN={FAKE_TOKEN}\nAZAZEL_MATTERMOST_BOT_TOKEN_X=keep\nB=2\nC=3\n")
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    res = _upsert(dst, "NEW_KEY", "v")
    assert res.returncode == 0, res.stderr
    assert dst.read_text(encoding="utf-8").endswith("C=3\nNEW_KEY=v\n")


def test_upsert_env_leaves_an_unreadable_path_alone(tmp_path):
    dst = tmp_path / "azazel-edge-web"
    dst.mkdir()  # cat fails on a directory
    (dst / "inside").write_text("x", encoding="utf-8")
    res = _upsert(dst, "AZAZEL_MATTERMOST_BOT_TOKEN", FAKE_TOKEN)
    assert res.returncode != 0
    assert dst.is_dir() and (dst / "inside").read_text(encoding="utf-8") == "x"
    assert FAKE_TOKEN not in res.stderr + res.stdout


@pytest.mark.parametrize("value", ["fake-token\nINJECTED=1", "fake-token\r", "\nfake"])
def test_upsert_env_refuses_a_line_break_in_the_value(tmp_path, value):
    dst = tmp_path / "azazel-edge-web"
    dst.write_text("A=1\n", encoding="utf-8")
    dst.chmod(0o644)
    res = _upsert(dst, "AZAZEL_MATTERMOST_BOT_TOKEN", value)
    assert res.returncode != 0 and "line break" in res.stderr
    assert "fake" not in res.stderr + res.stdout
    assert dst.read_text(encoding="utf-8") == "A=1\n" and stat.S_IMODE(dst.stat().st_mode) == 0o644
    assert sorted(p.name for p in tmp_path.iterdir()) == [dst.name]


def test_upsert_env_never_writes_under_the_default_umask():
    body = _function(PROVISION, "upsert_env")
    assert 'write_private_file "${file}"' in body
    for gone in ("touch ", "sed -i", ">>", "awk -v"):
        assert gone not in body, gone


# ------------------------------------------------------------------ selftest

def _run_sd_check(tmp_path: Path, dd_rc: int) -> tuple[Path, Path, Path, str]:
    """Run check_sd_write_speed with SD_TEST_DIR in tmp_path (reported as an
    ext4 directory), the old fixed name planted there as a symlink and a stub
    dd that opens of= like dd does (following symlinks) and records the
    file's mode first."""
    sd_dir, stubs, victim = tmp_path / "tmp", tmp_path / "bin", tmp_path / "victim"
    sd_dir.mkdir()
    stubs.mkdir()
    (sd_dir / "azazel_sdtest").symlink_to(victim)
    record = tmp_path / "dd-record"
    (stubs / "dd").write_text(
        "#!/usr/bin/env python3\n"
        "import os, stat, sys\n"
        "of = [a[3:] for a in sys.argv[1:] if a.startswith('of=')][0]\n"
        "conv = ','.join(a[5:] for a in sys.argv[1:] if a.startswith('conv='))\n"
        "mode = oct(stat.S_IMODE(os.lstat(of).st_mode)) if os.path.lexists(of) else 'absent'\n"
        f"open({str(record)!r}, 'a').write(f'{{of}} {{mode}} {{conv}}\\n')\n"
        "fd = os.open(of, os.O_WRONLY | os.O_TRUNC | (0 if 'nocreat' in conv else os.O_CREAT), 0o644)\n"
        "os.write(fd, b'x' * 1024)\n"
        "os.close(fd)\n"
        f"sys.exit({dd_rc})\n",
        encoding="utf-8")
    for p in stubs.iterdir():
        p.chmod(0o755)
    script = (
        f'SD_TEST_DIR="{sd_dir}"\nSD_TEST_FILE=""\nFAILURES=()\nWARNINGS=()\n'
        + 'sd_test_dir_fstype() { echo ext2/ext3; }\n'
        + _function(SELFTEST, "warn") + _function(SELFTEST, "fail") + _function(SELFTEST, "now_usec")
        + _function(SELFTEST, "cleanup_sd_test_file") + _function(SELFTEST, "check_sd_write_speed")
        + 'check_sd_write_speed\necho "failures=${FAILURES[*]:-} left=${SD_TEST_FILE}"\n'
    )
    env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}")
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    return sd_dir, victim, record, res.stdout


@pytest.mark.parametrize("dd_rc", [0, 1])
def test_selftest_never_writes_through_a_planted_name_and_cleans_up(tmp_path, dd_rc):
    sd_dir, victim, record, out = _run_sd_check(tmp_path, dd_rc)
    assert not victim.exists()
    assert sorted(p.name for p in sd_dir.iterdir()) == ["azazel_sdtest"]  # only the planted link
    (line,) = record.read_text(encoding="utf-8").splitlines()
    of, mode, conv = line.split(" ", 2)
    assert Path(of).parent == sd_dir and Path(of).name.startswith("azazel_sdtest.")
    assert mode == "0o600" and "nocreat" in conv  # dd writes only the file mktemp made
    assert ("sd_write_test_failed" in out) == (dd_rc != 0)
    assert out.rstrip().endswith("left=")


def test_selftest_has_no_fixed_tmp_name_and_cleans_up_on_exit():
    src = SELFTEST.read_text(encoding="utf-8")
    assert "/tmp/azazel_sdtest" not in src
    # On the SD card in a root-only directory, not the (tmpfs) /tmp.
    assert 'SD_TEST_DIR="/var/lib/azazel-edge/selftest"' in src
    assert "trap cleanup_sd_test_file EXIT" in src
    # Plain assignments: nothing here is taken from the environment.
    assert "${SD_TEST_DIR:-" not in src
