"""No default SNMP target and no default community (Edge#477, #480).

install_sensors.sh used to write the placeholder target 192.168.1.1 with the
community "public" when SNMP_TARGETS was not set, and the poller replaced an
empty community with "public": once the poller ran it could query whatever
device has that address on the site's network. These tests run a copy of the
installer with stand-ins for everything it changes outside the test
directory (root check, the env file path, apt-get, systemctl, install, ip,
setup_sensor_account.sh).
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import stat
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SENSORS = ROOT / "installer" / "internal" / "install_sensors.sh"
SNMP_UNIT = ROOT / "systemd" / "azazel-edge-snmp-poller.service"
NETFLOW_UNIT = ROOT / "systemd" / "azazel-edge-netflow-receiver.service"
PROVISION = ROOT / "installer" / "internal" / "provision_mattermost_workspace.sh"

sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.sensors.snmp_poller import SNMPPollError, SNMPPoller  # noqa: E402

PLACEHOLDER = '[{"host":"192.168.1.1","community":"public","port":161}]'
SECRET = "s3cr3t-community-xyz"
VALID = '[{"host":"10.20.30.40","community":"%s","port":161}]' % SECRET
OLD_FILE = (
    "# Azazel-Edge sensor configuration\n"
    "SNMP_TARGETS='%s'\nSNMP_POLL_INTERVAL_SEC=60\n" % PLACEHOLDER
)


def _installer(tmp_path: Path) -> tuple[Path, Path, Path]:
    """A copy of install_sensors.sh writing into tmp_path; returns (script, env file, call log)."""
    src = SENSORS.read_text(encoding="utf-8")
    root_check = 'if [[ "${EUID}" -ne 0 ]]; then'
    env_line = 'SENSOR_ENV_FILE="/etc/default/azazel-edge-sensors"'
    assert src.count(root_check) == 1 and src.count(env_line) == 1
    env_file = tmp_path / "azazel-edge-sensors"
    src = src.replace(root_check, "if false; then").replace(env_line, f'SENSOR_ENV_FILE="{env_file}"')
    internal = tmp_path / "repo" / "installer" / "internal"
    internal.mkdir(parents=True)
    script = internal / "install_sensors.sh"
    script.write_text(src, encoding="utf-8")
    log = tmp_path / "calls.log"
    fake = tmp_path / "bin"
    fake.mkdir()
    for name in ("apt-get", "systemctl", "install", "ip"):
        (fake / name).write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\n', encoding="utf-8")
    setup = internal / "setup_sensor_account.sh"
    setup.write_text(f'#!/bin/sh\necho "setup_sensor_account" >> "{log}"\n', encoding="utf-8")
    for f in list(fake.iterdir()) + [setup]:
        f.chmod(0o755)
    return script, env_file, log


def _run(tmp_path: Path, script: Path, **env: str) -> subprocess.CompletedProcess:
    python_dir = os.path.dirname(shutil.which("python3") or sys.executable)
    full = {"PATH": f"{tmp_path / 'bin'}:{python_dir}:/usr/bin:/bin", "NETFLOW_LISTEN_HOST": "172.16.0.254"}
    full.update(env)
    return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=full)


def _gnu_mv() -> bool:
    return subprocess.run(["mv", "--version"], capture_output=True).returncode == 0


# write_private_file uses mv -T (GNU coreutils, as on the device).
needs_gnu_mv = pytest.mark.skipif(not _gnu_mv(), reason="mv -T is GNU coreutils (Debian); run in Linux")


def _func(path: Path, name: str) -> str:
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", path.read_text(encoding="utf-8"), re.S | re.M)
    assert m, name
    return m.group(0)


def _private(path: Path) -> None:
    st = path.stat()
    assert stat.S_IMODE(st.st_mode) == 0o600
    assert (st.st_uid, st.st_gid) == (os.getuid(), os.getgid())  # root:root when run as root
    assert not path.is_symlink()
    assert [p.name for p in path.parent.iterdir() if p.name.startswith("." + path.name)] == []


def _calls(log: Path) -> str:
    return log.read_text(encoding="utf-8") if log.exists() else ""


@pytest.mark.parametrize("targets", [
    None, "", "[]", "  ", PLACEHOLDER,
    '[{"host": "192.168.1.1", "community": "public"}]',
    '[{"host":"10.0.0.2","community":"x"},{"host":"192.168.1.1","community":"public"}]',
    '[{"host":"10.0.0.2"}]', '[{"host":"10.0.0.2","community":""}]', '[{"community":"x"}]',
    '{"host":"10.0.0.2","community":"x"}', "not json", '["10.0.0.2"]',
    '[{"host":"10.0.0.2","community":"x","port":0}]',
    '[{"host":"10.0.0.2","community":"it\'s"}]',
])
def test_enabling_snmp_without_real_targets_stops_and_changes_nothing(tmp_path, targets):
    script, env_file, log = _installer(tmp_path)
    env = {"ENABLE_SNMP": "1", "ENABLE_SERVICES": "1"}
    if targets is not None:
        env["SNMP_TARGETS"] = targets
    res = _run(tmp_path, script, **env)
    assert res.returncode != 0
    assert not env_file.exists()
    assert _calls(log) == ""
    assert "ENABLE_SNMP=1 needs SNMP_TARGETS" in res.stderr
    assert "Nothing in the sensors configuration was changed" in res.stderr
    # The community is never printed (the guidance shows only "<community>").
    out = res.stdout + res.stderr
    assert '"public"' not in out and "community\":\"public" not in out


def test_the_community_is_not_printed_when_a_target_is_refused(tmp_path):
    script, env_file, log = _installer(tmp_path)
    bad = '[{"host":"10.20.30.40","community":"%s","port":70000}]' % SECRET
    res = _run(tmp_path, script, ENABLE_SNMP="1", SNMP_TARGETS=bad)
    assert res.returncode != 0 and not env_file.exists() and _calls(log) == ""
    assert "invalid port" in res.stderr and "10.20.30.40" in res.stderr
    assert SECRET not in res.stdout + res.stderr


def test_an_existing_placeholder_file_is_left_as_it_is_and_pointed_at(tmp_path):
    script, env_file, log = _installer(tmp_path)
    env_file.write_text(OLD_FILE, encoding="utf-8")
    res = _run(tmp_path, script, ENABLE_SNMP="1")
    assert res.returncode != 0
    assert env_file.read_text(encoding="utf-8") == OLD_FILE
    assert _calls(log) == ""
    assert "still holds the placeholder target 192.168.1.1" in res.stderr
    # Without the placeholder in the file there is no such notice.
    env_file.write_text("NETFLOW_PORT=2055\n", encoding="utf-8")
    res = _run(tmp_path, script, ENABLE_SNMP="1")
    assert res.returncode != 0 and "placeholder" not in res.stderr


@needs_gnu_mv
def test_real_targets_are_written_and_snmp_is_installed(tmp_path):
    script, env_file, log = _installer(tmp_path)
    env_file.write_text(OLD_FILE, encoding="utf-8")
    env_file.chmod(0o644)  # as an earlier version left it
    res = _run(tmp_path, script, ENABLE_SNMP="1", SNMP_TARGETS=VALID)
    assert res.returncode == 0, res.stdout + res.stderr
    text = env_file.read_text(encoding="utf-8")
    assert re.findall(r"^SNMP_TARGETS=.*$", text, re.M) == [f"SNMP_TARGETS='{VALID}'"]
    assert "192.168.1.1" not in text and "public" not in text
    _private(env_file)
    calls = _calls(log)
    assert "setup_sensor_account" in calls and "apt-get install" in calls
    assert "azazel-edge-snmp-poller.service" in calls
    assert SECRET not in res.stdout + res.stderr


@needs_gnu_mv
@pytest.mark.parametrize("existing", [None, OLD_FILE])
def test_without_snmp_no_target_is_written(tmp_path, existing):
    script, env_file, log = _installer(tmp_path)
    if existing is not None:
        env_file.write_text(existing, encoding="utf-8")
        env_file.chmod(0o644)
    res = _run(tmp_path, script, ENABLE_NETFLOW="1")
    assert res.returncode == 0, res.stdout + res.stderr
    text = env_file.read_text(encoding="utf-8")
    assert not re.search(r"^SNMP_TARGETS=", text, re.M)
    assert "192.168.1.1" not in text and "public" not in text
    assert "NETFLOW_LISTEN_HOST=172.16.0.254\n" in text
    _private(env_file)
    calls = _calls(log)
    assert "apt-get" not in calls and "snmp-poller" not in calls
    # Nothing enabled at all: the file is written as before, without a target.
    script2, env_file2, log2 = _installer(tmp_path / "off")
    res = _run(tmp_path / "off", script2)
    assert res.returncode == 0
    assert not re.search(r"^SNMP_TARGETS=", env_file2.read_text(encoding="utf-8"), re.M)
    _private(env_file2)
    assert _calls(log2) == ""


@pytest.mark.parametrize("targets", [
    "not json", "  ", '{"host":"10.0.0.2","community":"x"}', '["10.0.0.2"]',
    '[{"host":"10.0.0.2","community":"it\'s"}]',
    '[{"host":"10.0.0.2","community":"x"}]\nSNMP_POLL_INTERVAL_SEC=1',
    "[]'\nEXTRA=1\n'",
    '[{"host":"10.0.0.2"}]', '[{"host":"10.0.0.2","community":"x","port":"161"}]',
])
def test_without_snmp_a_given_snmp_targets_must_still_be_well_formed(tmp_path, targets):
    script, env_file, log = _installer(tmp_path)
    env_file.write_text("NETFLOW_PORT=2055\n", encoding="utf-8")
    res = _run(tmp_path, script, ENABLE_NETFLOW="1", SNMP_TARGETS=targets)
    assert res.returncode != 0
    assert env_file.read_text(encoding="utf-8") == "NETFLOW_PORT=2055\n"
    assert _calls(log) == ""
    assert "SNMP_TARGETS is given but" in res.stderr
    assert "Nothing in the sensors configuration was changed" in res.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == ["azazel-edge-sensors", "bin", "repo"]


@needs_gnu_mv
@pytest.mark.parametrize("targets", ["[]", VALID, PLACEHOLDER])
def test_without_snmp_a_well_formed_snmp_targets_is_written_as_given(tmp_path, targets):
    # The placeholder is refused only when SNMP is enabled.
    script, env_file, log = _installer(tmp_path)
    res = _run(tmp_path, script, ENABLE_NETFLOW="1", SNMP_TARGETS=targets)
    assert res.returncode == 0, res.stdout + res.stderr
    text = env_file.read_text(encoding="utf-8")
    assert re.findall(r"^SNMP_TARGETS=.*$", text, re.M) == [f"SNMP_TARGETS='{targets}'"]
    _private(env_file)
    assert "apt-get" not in _calls(log)
    assert SECRET not in res.stdout + res.stderr


def test_the_unit_default_is_no_target_and_no_placeholder_is_written():
    assert 'Environment="SNMP_TARGETS=[]"' in SNMP_UNIT.read_text(encoding="utf-8")
    src = SENSORS.read_text(encoding="utf-8")
    write = src[src.index("# SNMP_TARGETS is written only when given"):src.index('} | write_private_file "${SENSOR_ENV_FILE}"')]
    assert "192.168.1.1" not in write and "public" not in write
    for mode in ("enable", "format"):
        check = f"check_snmp_targets {mode}; then"
        assert src.count(check) == 1
        assert src.index(check) < src.index('} | write_private_file "${SENSOR_ENV_FILE}"')
        assert src.index(check) < src.index("setup_sensor_account.sh\"")


@needs_gnu_mv
def test_the_env_file_is_0600_from_its_creation_under_umask_022(tmp_path):
    # With chmod stubbed out only a file that is 0600 from creation ends 0600.
    script, env_file, _log = _installer(tmp_path)
    src = script.read_text(encoding="utf-8")
    script.write_text(src.replace("set -euo pipefail\n", "set -euo pipefail\numask 022\nchmod() { :; }\n", 1),
                      encoding="utf-8")
    res = _run(tmp_path, script, ENABLE_SNMP="1", SNMP_TARGETS=VALID)
    assert res.returncode == 0, res.stdout + res.stderr
    _private(env_file)


@needs_gnu_mv
def test_a_symlink_at_the_env_path_is_replaced_not_followed(tmp_path):
    script, env_file, _log = _installer(tmp_path)
    victim = tmp_path / "victim"
    victim.write_text("victim\n", encoding="utf-8")
    env_file.symlink_to(victim)
    res = _run(tmp_path, script, ENABLE_SNMP="1", SNMP_TARGETS=VALID)
    assert res.returncode == 0, res.stdout + res.stderr
    assert victim.read_text(encoding="utf-8") == "victim\n"
    _private(env_file)
    assert SECRET in env_file.read_text(encoding="utf-8")


def test_the_env_file_is_written_by_the_shared_private_writer():
    src = SENSORS.read_text(encoding="utf-8")
    assert _func(SENSORS, "write_private_file") == _func(PROVISION, "write_private_file")
    assert '} | write_private_file "${SENSOR_ENV_FILE}"\n' in src
    # The only write to the file is the private writer; nothing widens it.
    assert not re.search(r'(>|chmod [0-7]+|chown \S+) "\$\{SENSOR_ENV_FILE\}"', src)


def test_only_systemd_reads_the_env_file():
    # The units read it through EnvironmentFile= (systemd, as root); no unit
    # step and no sensor code opens it as User=azazel-sensor.
    for unit in (SNMP_UNIT, NETFLOW_UNIT):
        text = unit.read_text(encoding="utf-8")
        assert "User=azazel-sensor" in text
        lines = [ln for ln in text.splitlines() if "azazel-edge-sensors" in ln and not ln.startswith("#")]
        assert lines == ["EnvironmentFile=-/etc/default/azazel-edge-sensors"]
        assert not re.search(r"^ExecStart(Pre|Post)?=.*/etc/default", text, re.M)
    for py in (ROOT / "py" / "azazel_edge" / "sensors").glob("*.py"):
        assert "/etc/default" not in py.read_text(encoding="utf-8"), py


# ----------------------------------------------------------------- the poller


def test_poll_once_refuses_an_empty_community_without_sending():
    poller = SNMPPoller(targets=[])
    with patch("azazel_edge.sensors.snmp_poller.socket.socket") as sock, \
            patch("azazel_edge.sensors.snmp_poller.shutil.which") as which:
        for community in ("", None):
            with pytest.raises(SNMPPollError, match="snmp_community_missing"):
                poller.poll_once("10.20.30.40", community, 161)
    sock.assert_not_called()
    which.assert_not_called()


def test_run_forever_skips_a_target_without_community_and_does_not_log_secrets(caplog):
    polled = []
    poller = SNMPPoller(
        targets=[
            {"host": "10.0.0.1", "port": 161},
            {"host": "10.0.0.2", "community": "", "port": 161},
            {"host": "10.0.0.3", "community": SECRET, "port": 161},
        ],
        dispatch_fn=lambda _line: poller.stop(),
    )

    def _poll(host, community, port):
        polled.append((host, community, port))
        return {}

    with patch.object(SNMPPoller, "poll_once", side_effect=_poll), \
            caplog.at_level(logging.WARNING, logger="azazel_edge.sensors.snmp_poller"):
        poller.run_forever()
    assert polled == [("10.0.0.3", SECRET, 161)]
    refused = [r.getMessage() for r in caplog.records]
    assert refused == [
        "snmp target refused host=10.0.0.1 reason=community_missing",
        "snmp target refused host=10.0.0.2 reason=community_missing",
    ]
    assert all("public" not in m and SECRET not in m for m in refused)


def test_the_poller_has_no_default_community():
    src = (ROOT / "py" / "azazel_edge" / "sensors" / "snmp_poller.py").read_text(encoding="utf-8")
    assert '"public"' not in src
