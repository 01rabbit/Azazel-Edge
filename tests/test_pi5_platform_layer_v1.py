"""Edge#471 / Edge#477: the Raspberry Pi 5 platform layer (found by the
pre-hardware audit).

- EPD: the venv did not see the apt hardware modules (spidev, gpiozero,
  lgpio), and a failed draw was swallowed (the refresh unit always passed);
- the installer installed python3-rpi.gpio, which does not drive the Pi 5
  GPIO (RP1) and removes python3-rpi-lgpio;
- SPI and the Wi-Fi country were never set (Raspberry Pi OS keeps Wi-Fi
  blocked without a country) and the internal AP failing was ignored;
- the internal AP passphrase defaulted to a fixed, published value;
- Wi-Fi scan/connect and the uplink disconnect used wlan0, which on a Pi 5
  is the internal AP, and the WAN was looked up after eth0 had been put
  into br0;
- sshd listens on the br0 address only and was not restarted when that
  address came late (exit 255 is not restarted by Debian's ssh.service).

The installer functions run here with stubs: no apt, nmcli, raspi-config or
systemctl is run. A container is not evidence from the device.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import venv
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

INTERNAL = ROOT / "installer" / "internal"
TOOLS = INTERNAL / "install_migrated_tools.sh"
NETWORK = INTERNAL / "install_internal_network.sh"
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="GNU coreutils (mv -T) are Linux-only")


def _function(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def _bash(script: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], capture_output=True, text=True,
                          timeout=60, **kw)


# ------------------------------------------------------------ GPIO packages


def test_the_installer_does_not_install_rpi_gpio_and_takes_lgpio_from_the_pi_repository():
    src = TOOLS.read_text(encoding="utf-8")
    assert "python3-rpi.gpio" not in re.sub(r"#.*", "", src)
    base = re.search(r'echo "\[1/16\] Install OS dependencies"\napt-get update\n(.*?)\n\n', src, re.S).group(1)
    assert "python3-spidev" in base and "python3-gpiozero" not in base
    gpio = re.search(r'^if apt_has_package python3-lgpio; then\n(.*?)^fi\n', src, re.S | re.M).group(1)
    assert "python3-lgpio python3-rpi-lgpio python3-gpiozero" in gpio and "EPD_GPIO_STACK=1" in gpio
    assert "NOTICE" in gpio  # the else branch says the EPD has no hardware output


@pytest.mark.parametrize("policy,found", [
    ("python3-lgpio:\n  Installed: (none)\n  Candidate: 0.2.2-1~rpt1+trixie\n", True),
    ("python3-lgpio:\n  Installed: (none)\n  Candidate: (none)\n", False),
    ("", False),
])
def test_apt_has_package_reads_the_candidate(policy, found):
    stub = f"apt-cache() {{\ncat <<'EOF'\n{policy}EOF\n}}\n"
    res = _bash(stub + _function(TOOLS, "apt_has_package") + "apt_has_package python3-lgpio && echo yes || echo no\n")
    assert res.stdout.strip() == ("yes" if found else "no")


def test_spi_is_enabled_on_raspberry_pi_os_only():
    src = TOOLS.read_text(encoding="utf-8")
    block = re.search(r'^if is_raspberry_pi_os; then\n(.*?)^fi\n', src, re.S | re.M).group(1)
    assert "raspi-config nonint do_spi 0" in block and "/dev/spidev0.0" in block
    fn = _function(TOOLS, "is_raspberry_pi_os")
    assert "command -v raspi-config" in fn and "/boot/firmware/config.txt" in fn


# ------------------------------------------------------------- EPD in venv


def _fake_dist_packages(base: Path, with_gpio: bool = True) -> Path:
    d = base / "dist-packages"
    d.mkdir()
    (d / "spidev.cpython-30-not-loadable.so").write_text("")  # never imported: see spidev.py
    (d / "spidev.py").write_text("SPIDEV = 'apt'\n")
    (d / "spidev-3.6.egg-info").write_text("Metadata-Version: 1.2\nName: spidev\nVersion: 3.6\n")
    (d / "numpy").mkdir()
    (d / "numpy" / "__init__.py").write_text("")
    if with_gpio:
        (d / "gpiozero" / "pins").mkdir(parents=True)
        (d / "gpiozero" / "__init__.py").write_text("")
        (d / "gpiozero" / "pins" / "__init__.py").write_text("")
        (d / "gpiozero" / "pins" / "lgpio.py").write_text("import lgpio\n")
        (d / "colorzero").mkdir()
        (d / "colorzero" / "__init__.py").write_text("")
        (d / "lgpio.py").write_text("")
        (d / "_lgpio.cpython-30-not-loadable.so").write_text("")
    return d


def _link(venv_dir: Path, dist: Path, gpio: str) -> subprocess.CompletedProcess:
    fn = _function(TOOLS, "link_system_hw_modules").replace("/usr/lib/python3/dist-packages", str(dist))
    return _bash(fn + f'link_system_hw_modules "{venv_dir}" {gpio}\n')


@pytest.fixture(scope="module")
def plain_venv(tmp_path_factory):
    d = tmp_path_factory.mktemp("venv") / "venv"
    venv.EnvBuilder(with_pip=False, system_site_packages=False).create(d)
    return d


def test_the_venv_sees_only_the_linked_hardware_modules(plain_venv, tmp_path):
    dist = _fake_dist_packages(tmp_path)
    res = _link(plain_venv, dist, "1")
    assert res.returncode == 0, res.stderr
    py = str(plain_venv / "bin" / "python")
    out = subprocess.run([py, "-c", "import spidev, gpiozero, lgpio, gpiozero.pins.lgpio; print(spidev.SPIDEV)"],
                         capture_output=True, text=True)
    assert out.returncode == 0 and out.stdout.strip() == "apt", out.stderr
    # Nothing else of the system packages comes along.
    assert subprocess.run([py, "-c", "import numpy"], capture_output=True).returncode != 0
    hw = plain_venv / "azazel-system-hw"
    assert sorted(p.name for p in hw.iterdir() if p.name != "__pycache__") == sorted(
        ["spidev.cpython-30-not-loadable.so", "spidev.py", "spidev-3.6.egg-info", "gpiozero", "colorzero",
         "lgpio.py", "_lgpio.cpython-30-not-loadable.so"])
    assert all((hw / n).is_symlink() for n in ("gpiozero", "lgpio.py", "spidev-3.6.egg-info"))
    pth = list(plain_venv.glob("lib/python3*/site-packages/azazel-system-hw.pth"))
    assert len(pth) == 1 and pth[0].read_text().strip() == str(hw)
    # A re-run rebuilds the directory: a stale link goes away.
    (hw / "stale.py").symlink_to(dist / "spidev.py")
    assert _link(plain_venv, dist, "1").returncode == 0
    assert not (hw / "stale.py").exists()


def test_the_venv_is_not_given_every_system_package():
    src = TOOLS.read_text(encoding="utf-8")
    assert 'python3 -m venv "$VENV_DIR"\n' in src and "--system-site-packages" not in re.sub(r"#.*", "", src)
    # Linked after the runtime requirements are installed.
    assert src.index('pip" install -r "$REPO_ROOT/requirements/runtime.txt"') < src.index(
        'link_system_hw_modules "$VENV_DIR" "$EPD_GPIO_STACK"')


def test_a_missing_hardware_module_stops_the_install(plain_venv, tmp_path):
    dist = _fake_dist_packages(tmp_path)
    shutil.rmtree(dist / "gpiozero")
    res = _link(plain_venv, dist, "1")
    assert res.returncode == 1 and "gpiozero is not in" in res.stderr


def test_without_the_gpio_stack_only_spidev_is_linked(plain_venv, tmp_path):
    dist = _fake_dist_packages(tmp_path, with_gpio=False)
    res = _link(plain_venv, dist, "0")
    assert res.returncode == 0, res.stderr
    assert not (plain_venv / "azazel-system-hw" / "gpiozero").exists()


# ----------------------------------------------------------- EPD refresh


@pytest.fixture
def epd_refresh(tmp_path, monkeypatch):
    import azazel_edge_epd_mode_refresh as refresh

    monkeypatch.setattr(refresh, "EPD_STATE", tmp_path / "epd_state.json")
    monkeypatch.setattr(refresh, "EPD_LAST_RENDER", tmp_path / "epd_last_render.json")
    monkeypatch.setattr(refresh, "RUNTIME_SNAPSHOT_CANDIDATES", ())
    monkeypatch.setattr(refresh, "read_snapshot_payload", lambda prefer_control_plane=True: ({}, "none"))
    (tmp_path / "epd_state.json").write_text('{"mode": "shield", "ssid": "x"}')
    root = tmp_path / "root"
    (root / "py").mkdir(parents=True)
    monkeypatch.setenv("AZAZEL_ROOT", str(root))
    return refresh, root / "py" / "azazel_edge_epd.py"


def test_a_failed_draw_is_reported_and_fails_the_unit(epd_refresh, capsys):
    refresh, renderer = epd_refresh
    renderer.write_text("import sys\nprint('ERROR: Failed to initialize EPD: no /dev/spidev0.0')\n"
                        "print('trace line', file=sys.stderr)\nsys.exit(1)\n")
    assert refresh.main() == 1
    err = capsys.readouterr().err
    assert "EPD renderer exited with status 1" in err
    assert "no /dev/spidev0.0" in err and "trace line" in err


def test_a_successful_draw_returns_zero_quietly(epd_refresh, capsys):
    refresh, renderer = epd_refresh
    renderer.write_text("print('Display updated')\n")
    assert refresh.main() == 0
    assert capsys.readouterr().err == ""


def test_a_missing_renderer_and_a_timeout_fail(epd_refresh, monkeypatch, capsys):
    refresh, renderer = epd_refresh
    assert refresh.main() == 1
    assert "EPD renderer not found" in capsys.readouterr().err
    renderer.write_text("")

    def timeout(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, 45)

    monkeypatch.setattr(refresh.subprocess, "run", timeout)
    assert refresh.main() == 1
    assert "timed out" in capsys.readouterr().err


def test_the_refresh_source_no_longer_swallows_failures():
    src = (ROOT / "py" / "azazel_edge_epd_mode_refresh.py").read_text(encoding="utf-8")
    assert "except Exception:\n        return 0\n    return 0" not in src
    unit = (ROOT / "systemd" / "azazel-edge-epd-refresh.service").read_text(encoding="utf-8")
    assert "StandardError=journal" in unit


# -------------------------------------------------- Wi-Fi country / rfkill


def _net(fn_names: list[str], body: str, rpi: bool = True, raspi_get: str = "", raspi_rc: int = 0,
         env: dict | None = None) -> subprocess.CompletedProcess:
    head = "".join(f"{k}={v!r}\n" for k, v in (env or {}).items())
    stubs = f'''
LOG=$(mktemp)
is_raspberry_pi_os() {{ return {0 if rpi else 1}; }}
raspi-config() {{ echo "raspi-config $*" >>"$LOG"; [[ "$2" == get_wifi_country ]] && {{ printf '%s' {raspi_get!r}; [[ -n {raspi_get!r} ]]; return; }}; return {raspi_rc}; }}
rfkill() {{ echo "rfkill $*" >>"$LOG"; }}
nmcli() {{ echo "nmcli $*" >>"$LOG"; }}
'''
    src = NETWORK.read_text(encoding="utf-8")
    consts = "\n".join(re.findall(r"^(?:AP_PSK_OLD_DEFAULT|ETH_LAN_IF|AP_IF|LAN_IF|WLAN_AP_CONN)=.*$", src, re.M))
    fns = "".join(_function(NETWORK, n) for n in fn_names)
    return _bash(head + consts + "\n" + fns + stubs + body + '\necho "--log--"; cat "$LOG"\n')


def test_the_wifi_country_is_required_on_raspberry_pi_os_before_any_change():
    none = _net(["check_wifi_country"], "WIFI_COUNTRY=''\ncheck_wifi_country\necho passed\n")
    assert none.returncode == 1 and "WIFI_COUNTRY=" in none.stderr and "rfkill" in none.stderr
    configured = _net(["check_wifi_country"], "WIFI_COUNTRY=''\ncheck_wifi_country\necho passed\n", raspi_get="JP")
    assert configured.returncode == 0 and "JP (already configured)" in configured.stdout
    given = _net(["check_wifi_country"], "WIFI_COUNTRY=DE\ncheck_wifi_country\necho passed\n")
    assert given.returncode == 0 and "passed" in given.stdout
    vm = _net(["check_wifi_country"], "WIFI_COUNTRY=''\ncheck_wifi_country\necho passed\n", rpi=False)
    assert vm.returncode == 0 and "raspi-config" not in vm.stdout.split("--log--")[1]


def test_the_country_is_set_and_wifi_unblocked_on_raspberry_pi_os():
    res = _net(["prepare_wifi_radio"], "WIFI_COUNTRY=JP\nprepare_wifi_radio\n")
    log = res.stdout.split("--log--")[1].split("\n")
    assert res.returncode == 0, res.stderr
    assert "raspi-config nonint do_wifi_country JP" in log and "rfkill unblock wifi" in log
    assert "nmcli radio wifi on" in log
    keep = _net(["prepare_wifi_radio"], "WIFI_COUNTRY=''\nprepare_wifi_radio\n")
    assert "do_wifi_country" not in keep.stdout and "rfkill unblock wifi" in keep.stdout
    bad = _net(["prepare_wifi_radio"], "WIFI_COUNTRY=XX\nprepare_wifi_radio\n", raspi_rc=1)
    assert bad.returncode == 1 and "did not accept WIFI_COUNTRY=XX" in bad.stderr
    vm = _net(["prepare_wifi_radio"], "WIFI_COUNTRY=JP\nprepare_wifi_radio\n", rpi=False)
    assert vm.returncode == 0 and vm.stdout.split("--log--")[1].strip() == ""


def test_the_internal_ap_failing_is_an_error():
    src = NETWORK.read_text(encoding="utf-8")
    assert 'nmcli con up "$WLAN_AP_CONN" || true' not in src
    assert "nmcli con up lan-wlan0-ap || true" not in src
    fn = ["activate_internal_ap"]
    failing = 'nmcli() { echo "nmcli $*" >>"$LOG"; [[ "$1 $2" != "con up" ]]; }\n'
    res = _net(fn, failing + "AP_IF=lo\nactivate_internal_ap\necho passed\n")
    assert res.returncode == 1 and "did not come up" in res.stderr and "passed" not in res.stdout
    ok = _net(fn, "AP_IF=lo\nactivate_internal_ap\necho passed\n")
    assert ok.returncode == 0 and "nmcli con up lan-wlan0-ap" in ok.stdout
    vm = _net(fn, "AP_IF=nosuch-wlan9\nactivate_internal_ap\necho passed\n", rpi=False)
    assert vm.returncode == 0 and "NOTICE" in vm.stdout and "con up" not in vm.stdout
    pi = _net(fn, "AP_IF=nosuch-wlan9\nactivate_internal_ap\necho passed\n")
    assert pi.returncode == 1 and "does not exist" in pi.stderr


def _runner(tmp_path: Path, ap_up_rc: int, with_wlan: bool) -> subprocess.CompletedProcess:
    src = NETWORK.read_text(encoding="utf-8")
    runner = re.search(r"cat > \"\$RUNNER_FILE\" <<'EOR'\n(.*?)^EOR$", src, re.S | re.M).group(1)
    sysnet = tmp_path / "net"
    (sysnet / ("wlan0" if with_wlan else "eth0")).mkdir(parents=True, exist_ok=True)
    runner = runner.replace("/sys/class/net/wlan0", str(sysnet / "wlan0"))
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "calls.log"
    for name, body in {
        "nmcli": f'echo "nmcli $*" >>{log}\n[ "$3" = lan-wlan0-ap ] && exit {ap_up_rc}\nexit 0',
        "systemctl": f'echo "systemctl $*" >>{log}',
        "rfkill": f'echo "rfkill $*" >>{log}',
        "sysctl": "exit 0",
        "nft": "exit 1",
        "rm": "exit 0",
        "ln": "exit 0",
    }.items():
        (bindir / name).write_text("#!/bin/sh\n" + body + "\n")
        (bindir / name).chmod(0o755)
    path = f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}"
    return subprocess.run(["bash", "-c", runner], capture_output=True, text=True, env={"PATH": path}, timeout=30)


def test_the_boot_runner_unblocks_wifi_and_fails_when_the_ap_does_not_come_up(tmp_path):
    up = _runner(tmp_path / "a", 0, True)
    calls = (tmp_path / "a" / "calls.log").read_text()
    assert up.returncode == 0, up.stderr
    assert calls.index("rfkill unblock wifi") < calls.index("nmcli con up lan-wlan0-ap")
    down = _runner(tmp_path / "b", 4, True)
    calls = (tmp_path / "b" / "calls.log").read_text()
    assert down.returncode == 1 and "did not come up" in down.stderr
    # The rest is still applied before it fails.
    assert "systemctl restart dnsmasq" in calls and "systemctl restart ssh" in calls
    vm = _runner(tmp_path / "c", 4, False)
    assert vm.returncode == 0 and "lan-wlan0-ap" not in (tmp_path / "c" / "calls.log").read_text()


# --------------------------------------------------------- AP passphrase


def test_the_old_default_passphrase_is_refused_and_bad_input_is_checked():
    fns = ["check_ap_psk", "validate_ap_credentials"]
    for env, rc, msg in (
        ({"AP_SSID": "x", "AP_PSK": "ChangeMe1234", "WIFI_COUNTRY": ""}, 1, "old built-in default"),
        ({"AP_SSID": "x", "AP_PSK": "short", "WIFI_COUNTRY": ""}, 1, "8..63"),
        ({"AP_SSID": "x", "AP_PSK": "", "WIFI_COUNTRY": "JPN"}, 1, "two-letter"),
        ({"AP_SSID": "x", "AP_PSK": "", "WIFI_COUNTRY": "jp"}, 0, ""),
        ({"AP_SSID": "x", "AP_PSK": "a-good-passphrase", "WIFI_COUNTRY": ""}, 0, ""),
    ):
        res = _net(fns, 'validate_ap_credentials\necho "country=$WIFI_COUNTRY"\n', env=env)
        assert res.returncode == rc, (env, res.stderr)
        assert msg in res.stderr
        if env["WIFI_COUNTRY"] == "jp":
            assert "country=JP" in res.stdout
    src = NETWORK.read_text(encoding="utf-8")
    assert 'AP_PSK="${AP_PSK:-}"' in src and 'AP_PSK="${AP_PSK:-ChangeMe1234}"' not in src


def _resolve(tmp_path: Path, env: dict, profile_psk: str | None) -> subprocess.CompletedProcess:
    psk_file = tmp_path / "etc" / "internal-ap.psk"
    profile = "" if profile_psk is None else (
        'nmcli() { case "$*" in "-t -f NAME con show") echo lan-wlan0-ap ;; '
        f'*802-11-wireless-security.psk*) printf "%s\\n" {profile_psk!r} ;; esac; }}\n')
    if profile_psk is None:
        profile = 'nmcli() { :; }\n'
    fns = "".join(_function(NETWORK, n) for n in ("check_ap_psk", "generate_ap_psk", "save_ap_psk", "resolve_ap_psk"))
    head = "".join(f"{k}={v!r}\n" for k, v in env.items())
    script = (head + f'AP_PSK_FILE={str(psk_file)!r}\nAP_PSK_OLD_DEFAULT=ChangeMe1234\nWLAN_AP_CONN=lan-wlan0-ap\n'
              + "chown() { :; }\n" + profile + fns + 'resolve_ap_psk\necho "source=$AP_PSK_SOURCE"\n')
    return _bash(script)


@LINUX_ONLY
def test_a_random_passphrase_is_generated_saved_0600_and_never_printed(tmp_path):
    psk_file = tmp_path / "etc" / "internal-ap.psk"
    res = _resolve(tmp_path, {"AP_PSK": ""}, None)
    assert res.returncode == 0, res.stderr
    psk = psk_file.read_text().strip()
    assert len(psk) == 20 and re.fullmatch(r"[A-HJ-NP-Za-km-z2-9]{20}", psk)
    assert stat.S_IMODE(psk_file.stat().st_mode) == 0o600
    assert psk not in res.stdout and psk not in res.stderr and "source=generated" in res.stdout
    # A re-run keeps it.
    again = _resolve(tmp_path, {"AP_PSK": ""}, None)
    assert again.returncode == 0 and psk_file.read_text().strip() == psk and "source=kept" in again.stdout


@LINUX_ONLY
def test_an_earlier_profile_passphrase_is_kept_unless_it_is_the_old_default(tmp_path):
    psk_file = tmp_path / "etc" / "internal-ap.psk"
    kept = _resolve(tmp_path, {"AP_PSK": ""}, "operator-set-psk")
    assert kept.returncode == 0 and psk_file.read_text().strip() == "operator-set-psk"
    assert "operator-set-psk" not in kept.stdout + kept.stderr
    psk_file.unlink()
    replaced = _resolve(tmp_path, {"AP_PSK": ""}, "ChangeMe1234")
    assert replaced.returncode == 0 and "source=generated" in replaced.stdout
    assert psk_file.read_text().strip() != "ChangeMe1234"
    given = _resolve(tmp_path, {"AP_PSK": "my-own-passphrase"}, None)
    assert given.returncode == 0 and psk_file.read_text().strip() == "my-own-passphrase"
    assert "my-own-passphrase" not in given.stdout + given.stderr


def test_the_passphrase_is_never_echoed_by_the_installer():
    src = NETWORK.read_text(encoding="utf-8")
    for line in src.splitlines():
        if re.search(r"\b(echo|printf)\b", line):
            assert not re.search(r"\$\{?AP_PSK\b(?!_)", line), line
    assert "set -x" not in src


# ------------------------------------------------------ uplink detection


def _wan(route: str, wan_env: str = "") -> subprocess.CompletedProcess:
    stub = f"ip() {{ printf '%s\\n' {route!r}; }}\nWAN_IF={wan_env!r}\n"
    return _net(["detect_wan_if"], stub + "detect_wan_if\n")


def test_the_uplink_must_not_be_a_port_of_the_internal_bridge():
    for dev in ("eth0", "wlan0", "br0"):
        res = _wan(f"default via 192.0.2.1 dev {dev} proto dhcp metric 100")
        assert res.returncode == 1 and "becomes part of the internal LAN" in res.stderr, dev
        assert "USB Ethernet or USB Wi-Fi" in res.stderr
    ok = _wan("default via 192.0.2.1 dev eth1 proto dhcp src 192.0.2.10 metric 100")
    assert ok.returncode == 0 and ok.stdout.split("--log--")[0].strip() == "eth1"
    assert _wan("", "wlan1").stdout.startswith("wlan1")
    none = _wan("")
    assert none.returncode == 1 and "no default route" in none.stderr


def test_the_uplink_is_found_before_anything_is_changed():
    src = NETWORK.read_text(encoding="utf-8")
    main = _function(NETWORK, "main")
    order = ["validate_ap_credentials", "check_wifi_country", 'WAN_IF_DETECTED="$(detect_wan_if)"',
             "install_packages", "ensure_services", "resolve_ap_psk", "prepare_wifi_radio",
             "configure_nm_internal_bridge", "configure_forwarding_and_nat"]
    positions = [main.index(step) for step in order]
    assert positions == sorted(positions)
    nat = _function(NETWORK, "configure_forwarding_and_nat")
    assert 'local wan_if="$WAN_IF_DETECTED"' in nat and "detect_wan_if" not in nat
    assert "rfkill" in re.search(r"^install_packages\(\) \{.*?^\}", src, re.S | re.M).group(0)


# -------------------------------------------------------------------- sshd


def test_sshd_retries_until_the_bridge_address_exists():
    src = NETWORK.read_text(encoding="utf-8")
    dropin = re.search(r"cat > \"\$SSH_DROPIN\" <<'EOD'\n(.*?)^EOD$", src, re.S | re.M).group(1)
    lines = [l for l in dropin.splitlines() if l and not l.startswith("#")]
    assert lines == ["[Unit]", "After=network-online.target", "Wants=network-online.target",
                     "StartLimitIntervalSec=0", "[Service]", "RestartPreventExitStatus=", "Restart=on-failure",
                     "RestartSec=5s"]
    assert "ip_nonlocal_bind" not in re.sub(r"#.*", "", src)
    fn = _function(NETWORK, "configure_sshd")
    assert fn.index('sshd -t -f "${SSHD_CONF}.tmp"') < fn.index('mv "${SSHD_CONF}.tmp" "$SSHD_CONF"')
    assert fn.index("install_ssh_dropin") < fn.index("systemctl daemon-reload") < fn.index("systemctl restart ssh")
    assert 'ListenAddress ${SSH_LISTEN_IP}' in fn


def test_a_config_sshd_rejects_is_not_installed(tmp_path):
    conf = tmp_path / "sshd_config"
    conf.write_text("Port 22\n")
    fn = _function(NETWORK, "configure_sshd")
    script = (f"SSHD_CONF={str(conf)!r}\nSSH_LISTEN_IP=172.16.0.254\nALLOW_EXTERNAL_SSH=false\n"
              "backup_file() { :; }\ninstall_ssh_dropin() { :; }\nsystemctl() { echo \"systemctl $*\"; }\n"
              "install() { echo \"install $*\"; }\n"
              "sshd() { return 255; }\n" + fn + "configure_sshd\n")
    res = _bash(script)
    assert res.returncode == 1 and "sshd rejects" in res.stderr
    assert conf.read_text() == "Port 22\n" and "systemctl restart" not in res.stdout
    ok = _bash(script.replace("sshd() { return 255; }", "sshd() { return 0; }"))
    assert ok.returncode == 0 and conf.read_text().endswith("ListenAddress 172.16.0.254\n")
    assert "systemctl restart ssh" in ok.stdout


@pytest.mark.parametrize("enabled,active,disabled", [("0", "1", True), ("1", "0", True), ("1", "1", False)])
def test_ssh_socket_which_ignores_listenaddress_is_turned_off(enabled, active, disabled):
    stub = (f'systemctl() {{ case "$1" in cat) return 0 ;; is-enabled) return {enabled} ;; '
            f'is-active) return {active} ;; *) echo "systemctl $*" ;; esac; }}\n')
    res = _bash(stub + _function(NETWORK, "use_ssh_service_not_socket") + "use_ssh_service_not_socket\n")
    assert res.returncode == 0
    assert ("systemctl disable --now ssh.socket" in res.stdout) is disabled
    services = _function(NETWORK, "ensure_services")
    assert services.index("use_ssh_service_not_socket") < services.index("systemctl enable --now ssh")


@pytest.mark.skipif(shutil.which("sshd") is None and not Path("/usr/sbin/sshd").exists(), reason="no sshd here")
def test_sshd_accepts_the_listenaddress_line(tmp_path):
    sshd = shutil.which("sshd") or "/usr/sbin/sshd"
    key = tmp_path / "host_ed25519"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    conf = tmp_path / "sshd_config"
    conf.write_text(f"HostKey {key}\nListenAddress 172.16.0.254\n")
    res = subprocess.run([sshd, "-t", "-f", str(conf)], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


# ------------------------------------------------- uplink wireless choice


IW_AP_ONLY = """phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\ttype AP
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
"""
IW_AP_AND_USB = IW_AP_ONLY + """phy#1
\tInterface wlan1
\t\tifindex 5
\t\twdev 0x100000001
\t\ttype managed
"""
IW_MANAGED = IW_AP_ONLY.replace("type AP", "type managed")


@pytest.fixture
def ws(monkeypatch, tmp_path):
    from azazel_edge_control import wifi_connect  # noqa: F401  (loads wifi_scan as the daemon does)

    module = sys.modules["wifi_scan"]
    sysnet = tmp_path / "net"
    sysnet.mkdir()
    monkeypatch.setattr(module, "SYS_CLASS_NET", sysnet)
    state = {"iw": IW_AP_ONLY, "profiles": {}}

    def fake_run(cmd, **kw):
        if cmd[:2] == ["iw", "dev"] and len(cmd) == 2:
            return subprocess.CompletedProcess(cmd, 0, stdout=state["iw"], stderr="")
        if cmd[:6] == ["nmcli", "-t", "-f", "NAME,TYPE", "con", "show"]:
            out = "".join(f"{n}:802-11-wireless\n" for n in state["profiles"])
            return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")
        if cmd[:3] == ["nmcli", "--escape", "no"]:
            mode, iface = state["profiles"][cmd[-1]]
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{mode}\n{iface}\n", stderr="")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    return module, state, sysnet


def test_the_internal_ap_is_never_the_uplink_wireless_interface(ws):
    module, state, sysnet = ws
    assert module.get_wireless_interface() is None
    assert module.no_wireless_interface_error() == module.NO_UPLINK_WIRELESS_ERROR
    assert "USB Wi-Fi" in module.NO_UPLINK_WIRELESS_ERROR
    state["iw"] = IW_AP_AND_USB
    assert module.get_wireless_interface() == "wlan1"


def test_a_bridge_port_or_an_ap_profile_keeps_wlan0_out_even_while_the_ap_is_down(ws):
    module, state, sysnet = ws
    state["iw"] = IW_MANAGED
    assert module.get_wireless_interface() == "wlan0"  # no internal LAN here: unchanged
    state["profiles"] = {"lan-wlan0-ap": ("ap", "wlan0"), "home": ("infrastructure", "")}
    assert module.get_wireless_interface() is None
    state["profiles"] = {}
    (sysnet / "wlan0" / "brport").mkdir(parents=True)
    (sysnet / "br0" / "bridge").mkdir(parents=True)
    assert module.internal_lan_interfaces() == {"wlan0", "br0"}
    assert module.get_wireless_interface() is None


def test_no_wireless_interface_at_all_keeps_the_old_message(ws):
    module, state, _ = ws
    state["iw"] = ""
    assert module.get_wireless_interface() is None
    assert module.no_wireless_interface_error() == "No wireless interface found"


def test_scan_and_connect_refuse_instead_of_using_the_ap(ws, monkeypatch):
    module, state, _ = ws
    res = module.scan_wifi()
    assert res["ok"] is False and res["error"] == module.NO_UPLINK_WIRELESS_ERROR
    from azazel_edge_control import wifi_connect

    states = []
    monkeypatch.setattr(wifi_connect, "update_state_json", lambda *a, **kw: states.append((a, kw)))
    monkeypatch.setattr(wifi_connect, "get_usb_interface", lambda: None)
    monkeypatch.setattr(wifi_connect, "connect_nm", lambda *a, **kw: pytest.fail("connect_nm called"))
    out = wifi_connect.connect_wifi("example-ssid", "WPA2", "fake-passphrase-123")
    assert out["ok"] is False and out["error"] == module.NO_UPLINK_WIRELESS_ERROR
    assert states[-1][0] == ("FAILED",) and states[-1][1]["wifi_error"] == module.NO_UPLINK_WIRELESS_ERROR


@pytest.fixture
def daemon_mod(ws):
    from azazel_edge_control import daemon as control_daemon

    return control_daemon


def test_the_wifi_sensor_never_scans_on_the_internal_ap(ws, daemon_mod, monkeypatch):
    module, state, _ = ws
    monkeypatch.delenv("AZAZEL_WIFI_SCAN_IFACE", raising=False)
    assert daemon_mod._wifi_sensor_interface() == ""
    monkeypatch.setenv("AZAZEL_WIFI_SCAN_IFACE", "wlan0")
    assert daemon_mod._wifi_sensor_interface() == ""
    state["iw"] = IW_AP_AND_USB
    monkeypatch.delenv("AZAZEL_WIFI_SCAN_IFACE", raising=False)
    assert daemon_mod._wifi_sensor_interface() == "wlan1"


def test_the_uplink_disconnect_refuses_an_internal_lan_interface(ws, daemon_mod, monkeypatch, tmp_path):
    module, state, sysnet = ws
    (sysnet / "wlan0" / "brport").mkdir(parents=True)
    monkeypatch.setattr(daemon_mod, "SYS_CLASS_NET", sysnet)
    monkeypatch.setattr(daemon_mod, "IP_COMMAND_CANDIDATES", ("/nonexistent/ip",))
    monkeypatch.delenv("AZAZEL_UP_IF", raising=False)  # the default, wlan0
    monkeypatch.setattr(daemon_mod, "rate_limit_error", lambda *a: None)
    res = daemon_mod.execute_action("uplink_disconnect", None, request={"action": "uplink_disconnect"})
    assert res["ok"] is False and res["error"] == "uplink_interface_serves_internal_lan:wlan0"


def test_suppress_auto_wifi_keeps_the_ap_profile_autoconnecting(ws, daemon_mod, monkeypatch):
    module, state, _ = ws
    state["iw"] = IW_AP_AND_USB
    state["profiles"] = {"lan-wlan0-ap": ("ap", "wlan0"), "home": ("infrastructure", "")}
    calls = []
    real = module.subprocess.run

    def run(cmd, **kw):
        if cmd[:3] in (["nmcli", "con", "mod"], ["nmcli", "dev", "disconnect"]):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
        if cmd[:4] == ["nmcli", "-t", "-f", "DEVICE"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="wlan0\nwlan1\n", stderr="")
        return real(cmd, **kw)

    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(daemon_mod, "update_state_json", lambda *a, **kw: None)
    daemon_mod.suppress_auto_wifi(True)
    assert ["nmcli", "con", "mod", "home", "connection.autoconnect", "no"] in calls
    assert not any("lan-wlan0-ap" in c for c in calls)
    assert ["nmcli", "dev", "disconnect", "wlan1"] in calls
