"""Edge#477: the netflow and snmp units run as the dedicated account
User=azazel-sensor / Group=azazel-sensor (before: azazel, which no installer
created and which is the login account on many devices), and
install_sensors.sh creates it (setup_sensor_account.sh): a system user and
group, no login shell, no home. An existing azazel-sensor that is not such an
account stops the script before anything is changed. The account azazel is
never created, changed or looked at.

The script runs here with stub getent/groupadd/useradd/id over a fake
account database in tmp_path; nothing on the host is touched. All names and
ids are fakes.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "installer" / "internal" / "setup_sensor_account.sh"
SENSORS = ROOT / "installer" / "internal" / "install_sensors.sh"
UNITS = [ROOT / "systemd" / "azazel-edge-netflow-receiver.service", ROOT / "systemd" / "azazel-edge-snmp-poller.service"]

STUBS = {
    "getent": r"""#!/bin/bash
db="$FAKE_DB/$1"; [[ -f "$db" ]] || exit 2
line="$(grep -m1 "^$2:" "$db")" || exit 2
printf '%s\n' "$line"
""",
    "groupadd": r"""#!/bin/bash
echo "groupadd $*" >>"$FAKE_DB/log"
[[ "$1" == "--system" ]] || exit 9
echo "$2:x:990:" >>"$FAKE_DB/group"
""",
    "useradd": r"""#!/bin/bash
echo "useradd $*" >>"$FAKE_DB/log"
gid="" home="" shell="" system=0 nocreate=0
while (( $# > 1 )); do
  case "$1" in
    --system) system=1; shift ;;
    --no-create-home) nocreate=1; shift ;;
    --gid) gid="$2"; shift 2 ;;
    --home-dir) home="$2"; shift 2 ;;
    --shell) shell="$2"; shift 2 ;;
    *) exit 9 ;;
  esac
done
(( system && nocreate )) || exit 9
gidnum="$(grep -m1 "^$gid:" "$FAKE_DB/group" | cut -d: -f3)"
echo "$1:x:991:$gidnum::$home:$shell" >>"$FAKE_DB/passwd"
""",
    "id": r"""#!/bin/bash
[[ "$1" == "-nG" ]] || exit 9
pg="$(grep -m1 "^$2:" "$FAKE_DB/passwd" | cut -d: -f4)"
names="$(awk -F: -v g="$pg" '$3 == g { print $1 }' "$FAKE_DB/group")"
extra="$(awk -F: -v u="$2" '{ n = split($4, m, ","); for (i = 1; i <= n; i++) if (m[i] == u) print $1 }' "$FAKE_DB/group")"
echo $names $extra
""",
}


def _run(tmp_path: Path, passwd: str = "", group: str = "") -> tuple[subprocess.CompletedProcess, Path]:
    db, stubs = tmp_path / "db", tmp_path / "bin"
    db.mkdir()
    stubs.mkdir()
    (db / "passwd").write_text(passwd, encoding="utf-8")
    (db / "group").write_text(group, encoding="utf-8")
    for name, body in STUBS.items():
        (stubs / name).write_text(body, encoding="utf-8")
        (stubs / name).chmod(0o755)
    # The script's own root check is the only part not exercised: EUID is
    # read-only in bash.
    src = SCRIPT.read_text(encoding="utf-8")
    src, n = re.subn(r'if \[\[ "\$\{EUID\}" -ne 0 \]\]; then\n.*?\nfi\n', "", src, count=1, flags=re.S)
    assert n == 1
    script = tmp_path / "setup_sensor_account.sh"
    script.write_text(src, encoding="utf-8")
    env = {"PATH": f"{stubs}:/usr/bin:/bin", "FAKE_DB": str(db)}
    return subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True), db


def _log(db: Path) -> list[str]:
    log = db / "log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def test_the_units_and_the_script_name_the_same_account():
    src = SCRIPT.read_text(encoding="utf-8")
    assert 'SENSOR_USER="azazel-sensor"' in src and 'SENSOR_GROUP="azazel-sensor"' in src
    for unit in UNITS:
        text = unit.read_text(encoding="utf-8")
        assert "\nUser=azazel-sensor\n" in text and "\nGroup=azazel-sensor\n" in text, unit
        assert "\nUser=azazel\n" not in text and "\nGroup=azazel\n" not in text, unit


def test_a_missing_account_is_created_as_a_system_account_without_login_or_home(tmp_path):
    res, db = _run(tmp_path)
    assert res.returncode == 0, res.stderr
    log = _log(db)
    assert log[0] == "groupadd --system azazel-sensor"
    assert log[1].startswith("useradd --system --gid azazel-sensor --no-create-home --home-dir /nonexistent --shell ")
    assert log[1].split()[-2] in ("/usr/sbin/nologin", "/bin/false") and log[1].endswith(" azazel-sensor")
    assert len(log) == 2


def test_an_existing_matching_system_account_is_left_as_it_is(tmp_path):
    res, db = _run(tmp_path, passwd="azazel-sensor:x:991:990::/nonexistent:/usr/sbin/nologin\n",
                    group="azazel-sensor:x:990:\n")
    assert res.returncode == 0, res.stderr
    assert _log(db) == []
    assert "user azazel-sensor exists" in res.stdout


@pytest.mark.parametrize(
    "passwd, group, reason",
    [
        ("azazel-sensor:x:1001:1001::/nonexistent:/usr/sbin/nologin\n", "azazel-sensor:x:1001:\n", "not a system group"),
        ("azazel-sensor:x:1001:990::/nonexistent:/usr/sbin/nologin\n", "azazel-sensor:x:990:\n", "not a system account"),
        ("azazel-sensor:x:991:4::/nonexistent:/usr/sbin/nologin\n", "azazel-sensor:x:990:\nadm:x:4:\n", "primary group"),
        ("azazel-sensor:x:991:990::/nonexistent:/bin/bash\n", "azazel-sensor:x:990:\n", "login shell"),
        ("azazel-sensor:x:0:990::/nonexistent:/usr/sbin/nologin\n", "azazel-sensor:x:990:\n", "not a system account"),
    ],
)
def test_an_existing_azazel_sensor_that_is_not_the_system_account_stops_the_script(tmp_path, passwd, group, reason):
    res, db = _run(tmp_path, passwd=passwd, group=group)
    assert res.returncode != 0
    assert reason in res.stderr
    assert _log(db) == []


def test_an_existing_home_directory_stops_the_script(tmp_path):
    home = tmp_path / "home-azazel"
    home.mkdir()
    res, db = _run(tmp_path, passwd=f"azazel-sensor:x:991:990::{home}:/usr/sbin/nologin\n",
                   group="azazel-sensor:x:990:\n")
    assert res.returncode != 0 and "home directory" in res.stderr
    assert _log(db) == []


def test_the_login_account_azazel_is_left_alone(tmp_path):
    login = "azazel:x:1000:1000:,,,:/home/azazel:/bin/bash\n"
    res, db = _run(tmp_path, passwd=login, group="azazel:x:1000:\nsudo:x:27:azazel\n")
    assert res.returncode == 0, res.stderr
    log = _log(db)
    assert log[0] == "groupadd --system azazel-sensor" and log[1].endswith(" azazel-sensor") and len(log) == 2
    assert (db / "passwd").read_text(encoding="utf-8").startswith(login)
    src = SCRIPT.read_text(encoding="utf-8")
    assert not re.search(r"(getent (passwd|group)|usermod|userdel|groupmod|id -nG) \"?azazel\"?\s", src)


def test_install_sensors_creates_the_account_before_installing_either_unit():
    src = SENSORS.read_text(encoding="utf-8")
    call = src.index('"${REPO_ROOT}/installer/internal/setup_sensor_account.sh"')
    guard = src.rindex('if [[ "${ENABLE_SNMP}" == "1" || "${ENABLE_NETFLOW}" == "1" ]]; then', 0, call)
    assert guard < call
    for unit in ("azazel-edge-snmp-poller.service", "azazel-edge-netflow-receiver.service"):
        assert call < src.index(f"/etc/systemd/system/{unit}")
    assert SCRIPT.stat().st_mode & 0o111
