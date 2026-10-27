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
    assert "Nothing was changed" in res.stderr
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


def test_real_targets_are_written_and_snmp_is_installed(tmp_path):
    script, env_file, log = _installer(tmp_path)
    env_file.write_text(OLD_FILE, encoding="utf-8")
    res = _run(tmp_path, script, ENABLE_SNMP="1", SNMP_TARGETS=VALID)
    assert res.returncode == 0, res.stdout + res.stderr
    text = env_file.read_text(encoding="utf-8")
    assert re.findall(r"^SNMP_TARGETS=.*$", text, re.M) == [f"SNMP_TARGETS='{VALID}'"]
    assert "192.168.1.1" not in text and "public" not in text
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o644
    calls = _calls(log)
    assert "setup_sensor_account" in calls and "apt-get install" in calls
    assert "azazel-edge-snmp-poller.service" in calls
    assert SECRET not in res.stdout + res.stderr


@pytest.mark.parametrize("existing", [None, OLD_FILE])
def test_without_snmp_no_target_is_written(tmp_path, existing):
    script, env_file, log = _installer(tmp_path)
    if existing is not None:
        env_file.write_text(existing, encoding="utf-8")
    res = _run(tmp_path, script, ENABLE_NETFLOW="1")
    assert res.returncode == 0, res.stdout + res.stderr
    text = env_file.read_text(encoding="utf-8")
    assert not re.search(r"^SNMP_TARGETS=", text, re.M)
    assert "192.168.1.1" not in text and "public" not in text
    assert "NETFLOW_LISTEN_HOST=172.16.0.254\n" in text
    calls = _calls(log)
    assert "apt-get" not in calls and "snmp-poller" not in calls
    # Nothing enabled at all: the file is written as before, without a target.
    script2, env_file2, log2 = _installer(tmp_path / "off")
    res = _run(tmp_path / "off", script2)
    assert res.returncode == 0
    assert not re.search(r"^SNMP_TARGETS=", env_file2.read_text(encoding="utf-8"), re.M)
    assert _calls(log2) == ""


def test_the_unit_default_is_no_target_and_no_placeholder_is_written():
    assert 'Environment="SNMP_TARGETS=[]"' in SNMP_UNIT.read_text(encoding="utf-8")
    src = SENSORS.read_text(encoding="utf-8")
    write = src[src.index("# SNMP_TARGETS is written only when given"):src.index('} > "${SENSOR_ENV_FILE}"')]
    assert "192.168.1.1" not in write and "public" not in write
    assert src.index("check_snmp_targets; then") < src.index('} > "${SENSOR_ENV_FILE}"')
    assert src.index("check_snmp_targets; then") < src.index("setup_sensor_account.sh\"")


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
