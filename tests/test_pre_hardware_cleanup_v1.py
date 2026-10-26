"""Small fixes found before the first hardware run (Edge#477, Edge#471).

- install_ai_runtime.sh is no longer placed under /opt/azazel-edge, where it
  resolved REPO_ROOT to "/" and could not run; an old copy is removed.
- install_security_stack.sh, run from its /opt/azazel-edge copy, gets the
  checkout as REPO_ROOT instead of depending on the current directory.
- verify_runtime_sync.sh outside a checkout (its installed copies) refuses to
  run without the checkout argument instead of comparing "/" or "/usr".
- azazel-edge-selftest exits non-zero on a critical failure, no longer ends
  early under set -e when the SD card is fast, checks the optional security
  units only when they are enabled, and install_all.sh runs it last.

Everything runs against stubs in a temporary directory: no systemctl, dd or
/var/log of the host is touched.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / "installer" / "internal"
TOOLS = INTERNAL / "install_migrated_tools.sh"
INSTALL_ALL = INTERNAL / "install_all.sh"
SYNC = INTERNAL / "verify_runtime_sync.sh"
SELFTEST = ROOT / "bin" / "azazel-edge-selftest"


# ------------------------------------------------- scripts placed under /opt

def _opt_placed_scripts() -> list[str]:
    src = TOOLS.read_text(encoding="utf-8")
    return re.findall(
        r'^install -m 0755 "\$REPO_ROOT/installer/internal/([a-z_]+\.sh)" /opt/azazel-edge/\1$', src, re.M)


def test_install_ai_runtime_is_not_placed_under_opt_and_an_old_copy_is_removed():
    src = TOOLS.read_text(encoding="utf-8")
    assert "install_ai_runtime.sh" not in _opt_placed_scripts()
    assert "/opt/azazel-edge/install_ai_runtime.sh\n" not in src.replace("rm -f -- /opt/azazel-edge/install_ai_runtime.sh\n", "")
    assert "rm -f -- /opt/azazel-edge/install_ai_runtime.sh\n" in src
    # install_all.sh runs it from the checkout.
    assert '"${REPO_ROOT}/installer/internal/install_ai_runtime.sh"' in INSTALL_ALL.read_text(encoding="utf-8")


def test_every_script_placed_under_opt_works_there():
    """A script copied to /opt/azazel-edge/<name>.sh that finds the checkout
    from its own location gets "/" there. Each one either does not need the
    checkout, or is run with it given explicitly."""
    placed = _opt_placed_scripts()
    assert placed, "no /opt/azazel-edge scripts found; the pattern is stale"
    src = TOOLS.read_text(encoding="utf-8")
    self_located = []
    for name in placed:
        body = (INTERNAL / name).read_text(encoding="utf-8")
        if "BASH_SOURCE[0]" in body and "/../.." in body:
            self_located.append(name)
    assert sorted(self_located) == ["install_security_stack.sh", "verify_runtime_sync.sh"]
    # install_security_stack.sh: REPO_ROOT from the environment overrides.
    assert 'REPO_ROOT="${REPO_ROOT:-$REPO_ROOT_DEFAULT}"' in (INTERNAL / "install_security_stack.sh").read_text(encoding="utf-8")
    calls = [c for c in re.findall(r"^.*/opt/azazel-edge/install_security_stack\.sh$", src, re.M)
             if not c.startswith("install ")]
    assert calls and all('REPO_ROOT="$REPO_ROOT"' in c for c in calls), calls
    # verify_runtime_sync.sh: the checkout is its first argument.
    calls = re.findall(r"^\s*/opt/azazel-edge/verify_runtime_sync\.sh .*$", src, re.M)
    assert calls and all(c.split()[1] == '"$REPO_ROOT"' for c in calls), calls


def test_verify_runtime_sync_outside_a_checkout_needs_the_checkout_argument(tmp_path):
    copy = tmp_path / "opt" / "azazel-edge" / "verify_runtime_sync.sh"
    copy.parent.mkdir(parents=True)
    copy.write_text(SYNC.read_text(encoding="utf-8"), encoding="utf-8")
    res = subprocess.run(["bash", str(copy)], capture_output=True, text=True)
    assert res.returncode == 2
    assert "not run from a repository checkout" in res.stderr
    assert "first argument" in res.stderr


def test_verify_runtime_sync_in_the_checkout_keeps_its_default():
    # Only the early check: a runtime root that does not exist ends it there.
    res = subprocess.run(["bash", str(SYNC)], capture_output=True, text=True,
                         env=dict(os.environ))
    assert "not run from a repository checkout" not in res.stderr


# -------------------------------------------------------------- selftest

def _selftest_env(tmp_path: Path, *, active: set[str], enabled: set[str]) -> tuple[Path, dict]:
    """A copy of the selftest with its fixed paths moved into tmp_path, and
    stubs for systemctl, dmesg, dd and stat (reporting an ext4 directory)."""
    log_dir, sd_dir, stubs = tmp_path / "log", tmp_path / "sd", tmp_path / "bin"
    for d in (log_dir, sd_dir, stubs):
        d.mkdir()
    src = SELFTEST.read_text(encoding="utf-8")
    for old, new in (
        ('LOG_DIR="/var/log/azazel-edge"', f'LOG_DIR="{log_dir}"'),
        ('SD_TEST_DIR="/var/lib/azazel-edge/selftest"', f'SD_TEST_DIR="{sd_dir}"'),
    ):
        assert src.count(old) == 1, old
        src = src.replace(old, new)
    script = tmp_path / "selftest"
    script.write_text(src, encoding="utf-8")
    (stubs / "systemctl").write_text(
        "#!/bin/sh\n"
        "verb=\"$1\"; shift\n"
        "[ \"$1\" = --quiet ] && shift\n"
        f"case \"$verb\" in is-active) list='{' '.join(sorted(active))}' ;; "
        f"is-enabled) list='{' '.join(sorted(enabled))}' ;; *) exit 1 ;; esac\n"
        "for u in $list; do [ \"$u\" = \"$1\" ] && exit 0; done\n"
        "exit 3\n", encoding="utf-8")
    (stubs / "dmesg").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    # An instant dd: a fast, healthy card (the case that used to end the
    # selftest early under set -e).
    (stubs / "dd").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (stubs / "stat").write_text("#!/bin/sh\necho ext2/ext3\n", encoding="utf-8")
    for p in stubs.iterdir():
        p.chmod(0o755)
    env = dict(os.environ, PATH=f"{stubs}:/usr/bin:/bin")
    return script, env


CORE = {"azazel-edge-web", "azazel-edge-control-daemon"}
SECURITY = {"azazel-edge-suricata", "azazel-edge-opencanary"}


@pytest.mark.parametrize(
    "active, enabled, rc, status, failures",
    [
        (CORE | SECURITY, SECURITY, 0, "warning", []),
        # Security stack not installed (ENABLE_SECURITY_STACK=0): a warning only.
        (CORE, set(), 0, "warning", []),
        # Enabled but not running: critical.
        (CORE, SECURITY, 1, "failed", ["service_inactive:azazel-edge-opencanary", "service_inactive:azazel-edge-suricata"]),
        ({"azazel-edge-control-daemon"}, set(), 1, "failed", ["service_inactive:azazel-edge-web"]),
    ],
)
def test_selftest_exit_status_follows_critical_failures(tmp_path, active, enabled, rc, status, failures):
    script, env = _selftest_env(tmp_path, active=active, enabled=enabled)
    res = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)
    assert res.returncode == rc, res.stdout + res.stderr
    result = json.loads((tmp_path / "log" / "selftest_latest.json").read_text(encoding="utf-8"))
    assert result["status"] == status
    assert sorted(result["failures"]) == failures
    # Fast card: no speed warning, and the run got past the SD check.
    assert not any(w.startswith("sd_write_speed_low") for w in result["warnings"])
    # The installer copies neither pytest nor /opt/azazel-edge/tests.
    assert "python_smoke_tests_missing" in result["warnings"]
    for f in failures:
        assert f"FAIL {f}" in res.stdout
    assert f"selftest status: {status}" in res.stdout + res.stderr
    assert sorted(p.name for p in (tmp_path / "sd").iterdir()) == []


def _function(name: str) -> str:
    src = SELFTEST.read_text(encoding="utf-8")
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def _run_sd_check(tmp_path: Path, prelude: str) -> tuple[subprocess.CompletedProcess, Path]:
    """check_sd_write_speed alone, under set -e, in tmp_path; `prelude`
    replaces any helper it needs to fake."""
    sd_dir = tmp_path / "sd"
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "dd").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    (stubs / "dd").chmod(0o755)
    script = (
        f'set -euo pipefail\nSD_TEST_DIR="{sd_dir}"\nSD_TEST_FILE=""\nFAILURES=()\nWARNINGS=()\n'
        + _function("warn") + _function("fail") + _function("cleanup_sd_test_file")
        + _function("now_usec") + _function("sd_test_dir_fstype")
        + prelude + _function("check_sd_write_speed")
        + 'check_sd_write_speed\necho "failures=${FAILURES[*]:-}"\necho "warnings=${WARNINGS[*]:-}"\n'
    )
    env = dict(os.environ, PATH=f"{stubs}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env), sd_dir


def test_selftest_sd_check_needs_no_time_binary():
    src = SELFTEST.read_text(encoding="utf-8")
    assert "' && warn \"sd_write_speed_low" not in src
    assert "/usr/bin/time" not in src and "TIME_BIN" not in src


def test_now_usec_counts_microseconds_in_bash():
    script = _function("now_usec") + 'a="$(now_usec)"; b="$(now_usec)"; echo "$a $b"\n'
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    a, b = (int(x) for x in res.stdout.split())
    assert a > 1_000_000_000_000_000 and b >= a  # microseconds since 1970


def test_sd_check_on_a_tmpfs_warns_that_it_cannot_measure_the_card(tmp_path):
    res, sd_dir = _run_sd_check(tmp_path, "sd_test_dir_fstype() { echo tmpfs; }\n")
    assert res.returncode == 0, res.stderr
    assert "failures=\n" in res.stdout
    assert "sd_write_test_skipped:not_on_sd:tmpfs" in res.stdout
    assert list(sd_dir.iterdir()) == []


def test_sd_check_without_dd_is_a_warning_not_a_failure(tmp_path):
    prelude = 'command() { [[ "${2:-}" == dd ]] && return 1; builtin command "$@"; }\n'
    res, _ = _run_sd_check(tmp_path, prelude)
    assert res.returncode == 0, res.stderr
    assert "failures=\n" in res.stdout
    assert "sd_write_test_skipped:dd_missing" in res.stdout


@pytest.mark.parametrize("elapsed_usec, warning", [(4_000_000, "sd_write_speed_low:2.50MBps"), (500_000, None)])
def test_sd_check_speed_from_bash_time(tmp_path, elapsed_usec, warning):
    flag = tmp_path / "started"
    prelude = (
        "sd_test_dir_fstype() { echo ext2/ext3; }\n"
        f'now_usec() {{ if [[ -e "{flag}" ]]; then echo {1_000_000 + elapsed_usec}; '
        f'else : > "{flag}"; echo 1000000; fi; }}\n'
    )
    res, sd_dir = _run_sd_check(tmp_path, prelude)
    assert res.returncode == 0, res.stderr
    assert "failures=\n" in res.stdout
    assert (warning in res.stdout) if warning else ("sd_write_speed_low" not in res.stdout)
    assert list(sd_dir.iterdir()) == []  # the test file is removed


# ---------------------------------------------------- install_all runs it

def _install_all_tail() -> str:
    src = INSTALL_ALL.read_text(encoding="utf-8")
    start = src.index("# Last: the selftest")
    return src[start:]


@pytest.mark.parametrize(
    "app, services, selftest_rc, arch, rc, ran, timer",
    [
        ("1", "1", 0, "aarch64", 0, True, True),
        # The timer is installed after a failed selftest too.
        ("1", "1", 1, "aarch64", 1, True, True),
        # install_selftest_timer.sh refuses other architectures: a notice.
        ("1", "1", 0, "x86_64", 0, True, False),
        ("0", "1", 1, "aarch64", 0, False, False),
        ("1", "0", 1, "aarch64", 0, False, False),
    ],
)
def test_install_all_runs_the_selftest_and_its_timer_last(tmp_path, app, services, selftest_rc, arch, rc, ran, timer):
    (tmp_path / "bin").mkdir()
    (tmp_path / "installer" / "internal").mkdir(parents=True)
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    log = tmp_path / "log"
    stub = tmp_path / "bin" / "azazel-edge-selftest"
    stub.write_text(f"#!/bin/sh\necho selftest-output\necho selftest >> '{log}'\nexit {selftest_rc}\n", encoding="utf-8")
    timer_stub = tmp_path / "installer" / "internal" / "install_selftest_timer.sh"
    timer_stub.write_text(f"#!/bin/sh\necho \"timer ENABLE_SERVICES=$ENABLE_SERVICES\" >> '{log}'\n", encoding="utf-8")
    (stubs / "uname").write_text(f"#!/bin/sh\necho {arch}\n", encoding="utf-8")
    for p in (stub, timer_stub, stubs / "uname"):
        p.chmod(0o755)
    script = f'set -euo pipefail\nREPO_ROOT="{tmp_path}"\nENABLE_APP_STACK="{app}"\n' + _install_all_tail()
    env = dict(os.environ, ENABLE_SERVICES=services, PATH=f"{stubs}:{os.environ['PATH']}")
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == rc, res.stdout + res.stderr
    steps = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    expected = (["selftest"] if ran else []) + (["timer ENABLE_SERVICES=1"] if timer else [])
    assert steps == expected  # the selftest first, then the timer
    assert ("selftest-output" in res.stdout) == ran
    assert ("supports aarch64" in res.stdout) == (ran and arch != "aarch64")
    assert ("Unified installation completed." in res.stdout) == (rc == 0)
    if rc:
        assert "critical failure" in res.stderr


def test_selftest_timer_installer_runs_from_the_checkout_and_matches_the_selftest():
    timer_installer = (INTERNAL / "install_selftest_timer.sh").read_text(encoding="utf-8")
    # Run from the checkout by install_all.sh, never placed under /opt.
    assert "install_selftest_timer.sh" not in _opt_placed_scripts()
    assert '"${REPO_ROOT}/installer/internal/install_selftest_timer.sh"' in INSTALL_ALL.read_text(encoding="utf-8")
    assert 'install -m 0755 "${REPO_ROOT}/bin/azazel-edge-selftest" /usr/local/bin/azazel-edge-selftest' in timer_installer
    unit = (ROOT / "systemd" / "azazel-edge-selftest.service").read_text(encoding="utf-8")
    assert "Type=oneshot" in unit and "ExecStart=/usr/local/bin/azazel-edge-selftest" in unit
    # Nothing in the unit keeps the selftest from writing its directories
    # or masks its exit status (a critical failure shows as a failed unit).
    for gone in ("ProtectSystem", "ReadOnlyPaths", "PrivateTmp", "SuccessExitStatus", "ExecStart=-"):
        assert gone not in unit, gone
    timer_unit = (ROOT / "systemd" / "azazel-edge-selftest.timer").read_text(encoding="utf-8")
    assert "OnBootSec=5min" in timer_unit and "OnCalendar=quarterly" in timer_unit


def test_install_all_selftest_is_the_last_step():
    src = INSTALL_ALL.read_text(encoding="utf-8")
    assert src.rstrip().endswith('echo "Unified installation completed."')
    assert src.index('"${REPO_ROOT}/bin/azazel-edge-selftest"') > src.index("install_sensors.sh")
