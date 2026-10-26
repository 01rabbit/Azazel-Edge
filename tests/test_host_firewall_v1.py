"""Edge#477: the host firewall (table inet azazel_host).

The WAN exposure audit found no input filter for the host and a forward
chain with ``policy accept`` that let new WAN->LAN connections through. The
host firewall adds, in its own table (the Rust core's enforcement table
``inet azazel_edge`` and the NAT table ``ip azazel_internal`` are never
touched), a default deny from the WAN for the host and a drop for new
WAN->LAN and WAN->published-container connections. The LAN is br0.

The helper (installer/internal/azazel-host-firewall) runs here on a copy
whose fixed paths point into a temporary directory, with nft, systemctl,
systemd-run and flock as stubs: nothing is loaded into a kernel. When a
real ``nft`` with CAP_NET_ADMIN is available the rules are also checked with
``nft -c``. A container is not evidence from the device.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / "installer" / "internal"
HELPER = INTERNAL / "azazel-host-firewall"
RULES = INTERNAL / "nft" / "azazel-host.nft"
REMOTE = INTERNAL / "nft" / "azazel-host-remote-access.nft"
NETWORK = INTERNAL / "install_internal_network.sh"
DEV_REMOTE = INTERNAL / "set_dev_remote_access.sh"
INSTALL_ALL = INTERNAL / "install_all.sh"
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="GNU coreutils (mv -T) and flock are Linux-only")


def _code(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith("#"))


def _chain(text: str, name: str) -> str:
    m = re.search(r"chain " + name + r" \{\n(.*?)\n  \}", text, re.S)
    assert m, name
    return m.group(1)


def _function(path: Path, name: str) -> str:
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", path.read_text(encoding="utf-8"), re.S | re.M)
    assert m, name
    return m.group(0)


def _emergency() -> str:
    m = re.search(r"^EMERGENCY_RULES='(.*?)'$", HELPER.read_text(encoding="utf-8"), re.S | re.M)
    assert m
    return m.group(1)


# ------------------------------------------------------------------ rules


def test_the_rules_use_their_own_table_and_never_flush():
    text = _code(RULES.read_text(encoding="utf-8"))
    assert re.findall(r"^table (\S+ \S+)", text, re.M) == ["inet azazel_host"]
    for other in ("azazel_edge", "azazel_internal", "flush"):
        assert other not in text


def test_the_host_input_is_default_deny_from_the_wan():
    rules = _chain(_code(RULES.read_text(encoding="utf-8")), "input")
    lines = [line.strip() for line in rules.splitlines() if line.strip()]
    assert lines[0] == "type filter hook input priority filter; policy drop;"
    assert 'iif "lo" accept' in lines and 'iifname "br0" accept' in lines
    assert "ct state { established, related } accept" in lines
    # No service port is opened to the WAN by the base rules.
    assert set(re.findall(r"\b(?:tcp|udp) dport (\S+)", rules)) == {"68", "546"}
    # DHCP replies, DHCPv6 replies from a link-local server, IPv6 ND and RA.
    assert "udp sport 67 udp dport 68 accept" in lines
    assert "ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept" in lines
    nd = next(line for line in lines if "nd-neighbor-solicit" in line)
    for t in ("nd-router-advert", "nd-neighbor-advert", "packet-too-big"):
        assert t in nd
    # Remote access is a separate chain, consulted last before the drop.
    assert lines[-2] == "jump wan_allow"
    assert lines[-1].startswith("counter")
    assert re.search(r"chain wan_allow \{\s*\}", _code(RULES.read_text(encoding="utf-8")))


def test_new_wan_to_lan_and_wan_to_published_container_connections_are_dropped():
    fwd = [line.strip() for line in _chain(_code(RULES.read_text(encoding="utf-8")), "forward").splitlines()]
    assert fwd[0] == "type filter hook forward priority filter; policy accept;"
    lan = fwd.index('iifname { "br0", "docker0" } accept')
    drop_lan = next(i for i, line in enumerate(fwd) if line.startswith('oifname "br0" ct state new') and "drop" in line)
    drop_dnat = next(i for i, line in enumerate(fwd) if line.startswith("ct status dnat ct state new") and "drop" in line)
    # LAN -> anywhere and replies are accepted (not dropped) before the drops.
    assert fwd.index("ct state { established, related } accept") < lan < drop_lan < drop_dnat


def test_remote_access_adds_only_wan_ssh_and_mdns():
    lines = [line for line in _code(REMOTE.read_text(encoding="utf-8")).splitlines() if line.strip()]
    assert len(lines) == 2
    assert all(line.startswith("add rule inet azazel_host wan_allow ") for line in lines)
    assert "tcp dport 22 accept" in lines[0] and "udp dport 5353 accept" in lines[1]
    # OpenCanary is not shown to the WAN (it listens on 127.0.0.1 only).
    assert "8081" not in REMOTE.read_text(encoding="utf-8")


def test_the_emergency_rules_deny_the_wan_and_keep_the_lan():
    em = _emergency()
    assert em.startswith("table inet azazel_host\ndelete table inet azazel_host\n")
    assert "policy drop;" in em and 'iifname "br0" accept' in em
    assert "wan_allow" not in em and "dport 22" not in em and "5353" not in em
    assert 'oifname "br0" ct state new drop' in em and "ct status dnat ct state new drop" in em
    assert "nd-neighbor-solicit" in em and "udp sport 67 udp dport 68 accept" in em


def _real_nft() -> str | None:
    nft = shutil.which("nft")
    if not nft or os.geteuid() != 0:
        return None
    probe = subprocess.run([nft, "-c", "-f", "-"], input="table inet azazel_probe {}\n", capture_output=True,
                           text=True, timeout=20)
    return nft if probe.returncode == 0 else None


@pytest.mark.skipif(_real_nft() is None, reason="needs nft and CAP_NET_ADMIN (nft -c)")
def test_the_rules_parse_with_nft():
    nft = _real_nft()
    head = "table inet azazel_host\ndelete table inet azazel_host\n"
    for ruleset in (
        head + RULES.read_text(encoding="utf-8"),
        head + RULES.read_text(encoding="utf-8") + REMOTE.read_text(encoding="utf-8"),
        _emergency(),
    ):
        res = subprocess.run([nft, "-c", "-f", "-"], input=ruleset, capture_output=True, text=True, timeout=20)
        assert res.returncode == 0, res.stderr


# ----------------------------------------------------------------- helper


class Helper:
    def __init__(self, tmp: Path, nft_fail_rules: bool = False, nft_fail_all: bool = False,
                 systemd_run_rc: int = 0, timer_active: bool = False):
        self.tmp = tmp
        self.conf = tmp / "etc" / "host-firewall"
        self.run = tmp / "run"
        self.log = tmp / "calls.log"
        self.loaded = tmp / "loaded"  # every ruleset given to nft -f, separated
        self.present = tmp / "table-present"
        self.conf.mkdir(parents=True)
        shutil.copy(RULES, self.conf / "azazel-host.nft")
        shutil.copy(REMOTE, self.conf / "remote-access.nft")
        src = HELPER.read_text(encoding="utf-8")
        for old, new in (
            ('CONF_DIR="/etc/azazel-edge/host-firewall"', f'CONF_DIR="{self.conf}"'),
            ('RUN_DIR="/run/azazel-edge"', f'RUN_DIR="{self.run}"'),
            ('[[ "${EUID}" -eq 0 ]]', "true"),
        ):
            assert src.count(old) == 1, old
            src = src.replace(old, new)
        self.script = tmp / "azazel-host-firewall"
        self.script.write_text(src)
        bindir = tmp / "bin"
        bindir.mkdir()
        fail_rules = "1" if nft_fail_rules else "0"
        fail_all = "1" if nft_fail_all else "0"
        stubs = {
            "nft": f"""echo "nft $*" >>{self.log}
case "$1" in
  -f) body="$(cat)"; printf '%s\\n----\\n' "$body" >>{self.loaded}
      if [ {fail_all} = 1 ]; then exit 1; fi
      case "$body" in *emergency*) ;; *) [ {fail_rules} = 1 ] && exit 1 ;; esac
      touch {self.present}; exit 0 ;;
  list) [ -e {self.present} ] ;;
  delete) rm -f {self.present} ;;
esac""",
            "systemctl": f'echo "systemctl $*" >>{self.log}\n'
                         f'[ "$1" = is-active ] && exit {0 if timer_active else 3}\nexit 0',
            "systemd-run": f'echo "systemd-run $*" >>{self.log}\nexit {systemd_run_rc}',
            "flock": "exit 0",
        }
        for name, body in stubs.items():
            (bindir / name).write_text("#!/bin/bash\n" + body + "\n")
            (bindir / name).chmod(0o755)
        self.env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}

    def __call__(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(self.script), *args], capture_output=True, text=True, env=self.env,
                              timeout=30)

    @property
    def state(self) -> str:
        f = self.conf / "state"
        return f.read_text().strip() if f.exists() else ""

    @property
    def calls(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    @property
    def rulesets(self) -> list[str]:
        if not self.loaded.exists():
            return []
        return [r for r in self.loaded.read_text().split("\n----\n") if r.strip()]


@LINUX_ONLY
def test_a_trial_loads_atomically_and_starts_the_rollback_timer(tmp_path):
    h = Helper(tmp_path)
    res = h("trial")
    assert res.returncode == 0, res.stderr
    assert h.state == "pending" and h.present.exists()
    (ruleset,) = h.rulesets
    assert ruleset.startswith("table inet azazel_host\ndelete table inet azazel_host\n")
    assert "jump wan_allow" in ruleset and "dport 22" not in ruleset
    run = next(line for line in h.calls.splitlines() if line.startswith("systemd-run"))
    assert "--unit=azazel-host-firewall-rollback" in run and "--on-active=120s" in run
    assert run.endswith("/usr/local/sbin/azazel-host-firewall rollback-unconfirmed")
    assert "confirm" in res.stdout and "NEW connection" in res.stdout


@LINUX_ONLY
def test_an_unconfirmed_trial_is_rolled_back(tmp_path):
    h = Helper(tmp_path)
    assert h("trial").returncode == 0
    res = h("rollback-unconfirmed")
    assert res.returncode == 0
    assert h.state == "rolled-back" and not h.present.exists()
    assert "nft delete table inet azazel_host" in h.calls and "not confirmed" in res.stderr
    # A rolled-back firewall is not loaded at the next boot.
    assert h("boot").returncode == 0 and not h.present.exists() and len(h.rulesets) == 1


@LINUX_ONLY
def test_a_confirmed_trial_stays_and_is_loaded_at_boot(tmp_path):
    h = Helper(tmp_path)
    assert h("trial").returncode == 0
    res = h("confirm")
    assert res.returncode == 0, res.stderr
    assert h.state == "enabled" and (h.run / "host-firewall.confirmed").exists()
    assert "systemctl stop azazel-host-firewall-rollback.timer" in h.calls
    # The timer firing late finds the confirmation and changes nothing.
    assert h("rollback-unconfirmed").returncode == 0 and h.state == "enabled" and h.present.exists()
    h.present.unlink()
    assert h("boot").returncode == 0 and h.present.exists()


@LINUX_ONLY
def test_a_confirmation_file_written_before_the_timer_fires_keeps_it(tmp_path):
    h = Helper(tmp_path)
    assert h("trial").returncode == 0
    (h.run / "host-firewall.confirmed").write_text("")
    assert h("rollback-unconfirmed").returncode == 0 and h.state == "enabled" and h.present.exists()


@LINUX_ONLY
def test_a_stale_confirmation_does_not_confirm_a_new_trial(tmp_path):
    h = Helper(tmp_path)
    h.run.mkdir()
    (h.run / "host-firewall.confirmed").write_text("")
    assert h("trial").returncode == 0
    assert h("rollback-unconfirmed").returncode == 0 and h.state == "rolled-back"


@LINUX_ONLY
def test_confirm_without_a_trial_is_refused(tmp_path):
    h = Helper(tmp_path)
    res = h("confirm")
    assert res.returncode == 1 and h.state == ""


@LINUX_ONLY
def test_no_timer_means_no_trial(tmp_path):
    h = Helper(tmp_path, systemd_run_rc=1)
    res = h("trial")
    assert res.returncode == 1 and not h.present.exists() and h.state == "off"
    assert "taken off again" in res.stderr


@LINUX_ONLY
def test_a_reboot_during_a_trial_rolls_it_back(tmp_path):
    h = Helper(tmp_path)
    assert h("trial").returncode == 0
    h.present.unlink()  # the reboot
    res = h("boot")
    assert res.returncode == 0 and h.state == "rolled-back" and not h.present.exists()
    assert len(h.rulesets) == 1


@LINUX_ONLY
def test_boot_started_by_hand_during_a_trial_does_not_roll_it_back(tmp_path):
    h = Helper(tmp_path, timer_active=True)
    assert h("trial").returncode == 0
    assert h("boot").returncode == 0 and h.state == "pending" and h.present.exists()


@LINUX_ONLY
def test_enabled_rules_that_do_not_load_fail_closed(tmp_path):
    h = Helper(tmp_path, nft_fail_rules=True)
    (h.conf / "state").write_text("enabled\n")
    res = h("boot")
    assert res.returncode == 1 and "emergency" in res.stderr
    assert len(h.rulesets) == 2 and "emergency" in h.rulesets[1] and h.present.exists()
    assert h("refresh").returncode == 1


@LINUX_ONLY
def test_a_missing_rules_file_never_loads_a_partial_ruleset(tmp_path):
    h = Helper(tmp_path)
    (h.conf / "state").write_text("enabled\n")
    (h.conf / "azazel-host.nft").unlink()
    res = h("boot")
    assert res.returncode == 1
    # Only the emergency ruleset reached nft: never "table; delete table" alone.
    (ruleset,) = h.rulesets
    assert "emergency" in ruleset


@LINUX_ONLY
def test_nothing_loads_when_both_fail_and_it_says_so(tmp_path):
    h = Helper(tmp_path, nft_fail_all=True)
    (h.conf / "state").write_text("enabled\n")
    res = h("refresh")
    assert res.returncode == 1 and "no WAN filter" in res.stderr


@LINUX_ONLY
@pytest.mark.parametrize("state", ["", "off", "rolled-back"])
def test_off_loads_nothing(tmp_path, state):
    h = Helper(tmp_path)
    if state:
        (h.conf / "state").write_text(state + "\n")
    assert h("refresh").returncode == 0 and h("boot").returncode == 0
    assert h.rulesets == []


@LINUX_ONLY
def test_a_failed_first_load_changes_nothing(tmp_path):
    h = Helper(tmp_path, nft_fail_rules=True)
    res = h("trial")
    assert res.returncode == 1 and h.state == "off" and not h.present.exists()
    assert "systemd-run" not in h.calls and all("emergency" not in r for r in h.rulesets)


@LINUX_ONLY
def test_a_second_trial_or_a_trial_when_enabled_is_refused(tmp_path):
    h = Helper(tmp_path)
    assert h("trial").returncode == 0
    assert h("trial").returncode == 1
    assert h("confirm").returncode == 0
    assert h("trial").returncode == 1 and h.state == "enabled"


@LINUX_ONLY
def test_remote_access_adds_and_removes_wan_ssh_and_mdns(tmp_path):
    h = Helper(tmp_path)
    (h.conf / "state").write_text("enabled\n")
    assert h("remote-access", "on").returncode == 0
    assert "tcp dport 22 accept" in h.rulesets[-1] and "udp dport 5353 accept" in h.rulesets[-1]
    assert h("remote-access", "off").returncode == 0
    assert "dport 22" not in h.rulesets[-1]
    assert h("remote-access", "maybe").returncode == 1


@LINUX_ONLY
def test_remote_access_while_off_only_records_it(tmp_path):
    h = Helper(tmp_path)
    assert h("remote-access", "on").returncode == 0
    assert h.rulesets == [] and (h.conf / "remote-access.on").exists()


@LINUX_ONLY
def test_disable_removes_the_table_and_the_state(tmp_path):
    h = Helper(tmp_path)
    assert h("trial").returncode == 0 and h("confirm").returncode == 0
    res = h("disable")
    assert res.returncode == 0 and h.state == "" and not h.present.exists()


@LINUX_ONLY
def test_status_is_read_only(tmp_path):
    h = Helper(tmp_path)
    res = h("status")
    assert res.returncode == 0 and "state=off" in res.stdout and h.rulesets == []
    assert "nft -f" not in h.calls and "nft delete" not in h.calls


def test_no_environment_variable_changes_what_the_helper_does():
    src = HELPER.read_text(encoding="utf-8")
    # Every upper-case variable the helper reads is set at its top (or is EUID).
    read = set(re.findall(r"\$\{?([A-Z_][A-Z0-9_]*)", src))
    own = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", src, re.M)) | {"EUID"}
    assert read - own == set(), read - own


@LINUX_ONLY
def test_unknown_commands_are_refused(tmp_path):
    h = Helper(tmp_path)
    assert h("open-everything").returncode == 1 and h.rulesets == []


# -------------------------------------------------------------- installer


def _runner(tmp_path: Path, fw_rc: int) -> tuple[subprocess.CompletedProcess, str]:
    src = NETWORK.read_text(encoding="utf-8")
    runner = re.search(r"cat > \"\$RUNNER_FILE\" <<'EOR'\n(.*?)^EOR$", src, re.S | re.M).group(1)
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True)
    log = tmp_path / "calls.log"
    helper = bindir / "azazel-host-firewall"
    runner = runner.replace("/usr/local/sbin/azazel-host-firewall", str(helper))
    runner = runner.replace("/sys/class/net/wlan0", str(tmp_path / "no-wlan0"))
    stubs = {
        "azazel-host-firewall": f'echo "fw $*" >>{log}\nexit {fw_rc}',
        "nmcli": f'echo "nmcli $*" >>{log}',
        "systemctl": f'echo "systemctl $*" >>{log}',
        "sysctl": "exit 0",
        "nft": f'echo "nft $*" >>{log}',
        "rm": "exit 0",
        "ln": "exit 0",
    }
    for name, body in stubs.items():
        (bindir / name).write_text("#!/bin/sh\n" + body + "\n")
        (bindir / name).chmod(0o755)
    env = {"PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    res = subprocess.run(["bash", "-c", runner], capture_output=True, text=True, env=env, timeout=30)
    return res, log.read_text()


def test_the_boot_runner_refreshes_the_host_firewall_first_and_fails_after_the_rest(tmp_path):
    ok, calls = _runner(tmp_path / "a", 0)
    assert ok.returncode == 0, ok.stderr
    assert calls.splitlines()[0] == "fw refresh"
    bad, calls = _runner(tmp_path / "b", 1)
    assert bad.returncode == 1 and "emergency ruleset" in bad.stderr
    assert "systemctl restart dnsmasq" in calls and "systemctl restart ssh" in calls


def _generated(marker: str) -> str:
    src = NETWORK.read_text(encoding="utf-8")
    m = re.search(r"cat > \"\$" + marker + r"\" <<'(\w+)'\n(.*?)^\1$", src, re.S | re.M)
    assert m, marker
    return m.group(2)


def test_the_boot_unit_loads_before_the_network():
    unit = _generated("HOST_FW_UNIT")
    assert "Before=network-pre.target" in unit and "Wants=network-pre.target" in unit
    assert "DefaultDependencies=no" in unit and "After=local-fs.target" in unit
    assert "ExecStart=/usr/local/sbin/azazel-host-firewall boot" in unit


def test_a_flush_by_nftables_service_is_followed_by_a_reload():
    dropin = _generated("HOST_FW_NFT_DROPIN")
    for key in ("ExecStartPost", "ExecReload", "ExecStopPost"):
        assert f"{key}=/usr/local/sbin/azazel-host-firewall refresh" in dropin


def test_the_installer_enables_it_only_by_an_option():
    src = NETWORK.read_text(encoding="utf-8")
    assert 'HOST_FW_ACTION="keep"' in src
    assert not re.search(r"\$\{HOST_FW\w*:?-", src)  # never taken from the environment
    fn = _function(NETWORK, "parse_args")
    res = subprocess.run(["bash", "-c", 'HOST_FW_ACTION=keep\nusage() { :; }\n' + fn
                          + 'parse_args "$@"; echo "$HOST_FW_ACTION"', "x", *[]],
                         capture_output=True, text=True, timeout=10)
    assert res.stdout.strip() == "keep"
    for args, want in ((["--enable-host-firewall"], "enable"), (["--disable-host-firewall"], "disable")):
        res = subprocess.run(["bash", "-c", 'HOST_FW_ACTION=keep\nusage() { :; }\n' + fn
                              + 'parse_args "$@"; echo "$HOST_FW_ACTION"', "x", *args],
                             capture_output=True, text=True, timeout=10)
        assert res.stdout.strip() == want
    res = subprocess.run(["bash", "-c", 'usage() { :; }\n' + fn + 'parse_args "$@"', "x", "--host-fw=off"],
                         capture_output=True, text=True, timeout=10)
    assert res.returncode == 1 and "unknown option" in res.stderr
    assert re.search(r"^main\(\) \{\n  parse_args \"\$@\"\n  require_root", src, re.M)


def _configure(tmp_path: Path, action: str, state: str, external: str = "false",
               sessions: str = "0") -> tuple[subprocess.CompletedProcess, str]:
    log = tmp_path / "calls.log"
    conf = tmp_path / "hf"
    conf.mkdir(parents=True)
    if state:
        (conf / "state").write_text(state + "\n")
    fns = "".join(_function(NETWORK, n) for n in ("configure_host_firewall", "start_host_firewall_trial"))
    script = f"""
HOST_FW_HELPER=fwstub
HOST_FW_DIR={conf}
HOST_FW_ACTION={action}
ALLOW_EXTERNAL_SSH={external}
fwstub() {{ echo "fw $*" >>{log}; }}
install_host_firewall_files() {{ echo install >>{log}; }}
uplink_ssh_sessions() {{ echo {sessions}; }}
{fns}
configure_host_firewall </dev/null
"""
    res = subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], capture_output=True, text=True, timeout=10)
    return res, log.read_text() if log.exists() else ""


@pytest.mark.parametrize("action,state,want", [
    ("keep", "", ["fw remote-access off"]),
    ("keep", "rolled-back", ["fw remote-access off"]),
    ("keep", "enabled", ["fw remote-access off", "fw refresh"]),
    ("enable", "", ["fw remote-access off", "fw trial"]),
    ("enable", "rolled-back", ["fw remote-access off", "fw trial"]),
    ("enable", "enabled", ["fw remote-access off", "fw refresh"]),
    ("disable", "enabled", ["fw remote-access off", "fw disable"]),
])
def test_what_the_installer_does_with_the_host_firewall(tmp_path, action, state, want):
    res, calls = _configure(tmp_path, action, state)
    assert res.returncode == 0, res.stderr
    assert calls.splitlines() == ["install"] + want
    if action == "keep" and state != "enabled":
        assert "--enable-host-firewall" in res.stdout


def test_allow_external_ssh_turns_remote_access_on(tmp_path):
    res, calls = _configure(tmp_path, "keep", "enabled", external="TRUE")
    assert res.returncode == 0 and "fw remote-access on" in calls


def test_no_confirmation_without_a_terminal_and_none_from_an_uplink_session(tmp_path):
    res, calls = _configure(tmp_path / "a", "enable", "")
    assert "fw confirm" not in calls and "no terminal" in res.stdout
    res, calls = _configure(tmp_path / "b", "enable", "", sessions="2")
    assert "fw confirm" not in calls and "came in through the uplink" in res.stdout


@pytest.mark.parametrize("ss_out,count", [
    ("", 0),
    ("0 0 172.16.0.254:22 172.16.0.101:50000\n", 0),
    ("0 0 [::ffff:172.16.0.254]:22 [::ffff:172.16.0.101]:50000\n", 0),
    ("0 0 127.0.0.1:22 127.0.0.1:50000\n", 0),
    ("0 0 10.96.0.203:22 10.96.0.3:50000\n", 1),
    ("0 0 [fd96::1b6]:22 [fd96::3]:50000\n0 0 172.16.0.254:22 172.16.0.5:1\n", 1),
])
def test_uplink_ssh_sessions_are_told_apart_from_lan_ones(ss_out, count):
    fn = _function(NETWORK, "uplink_ssh_sessions")
    script = f"SSH_LISTEN_IP=172.16.0.254\nss() {{ printf '%s' '{ss_out}'; }}\n{fn}uplink_ssh_sessions\n"
    res = subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], capture_output=True, text=True, timeout=10)
    assert res.stdout.strip() == str(count), res.stderr


def test_dev_remote_access_opens_and_closes_the_firewall_with_sshd_and_avahi():
    src = DEV_REMOTE.read_text(encoding="utf-8")
    open_block = re.search(r"\n    open\)\n(.*?);;", src, re.S).group(1)
    close_block = re.search(r"\n    close\)\n(.*?);;", src, re.S).group(1)
    assert "configure_host_firewall_remote on" in open_block
    assert "configure_host_firewall_remote off" in close_block
    fn = _function(DEV_REMOTE, "configure_host_firewall_remote")
    assert '"$HOST_FIREWALL" remote-access "$1"' in fn


def test_install_all_passes_only_the_host_firewall_options():
    src = INSTALL_ALL.read_text(encoding="utf-8")
    assert '--enable-host-firewall|--disable-host-firewall) INTERNAL_NETWORK_ARGS+=("$arg") ;;' in src
    assert 'install_internal_network.sh" "${INTERNAL_NETWORK_ARGS[@]}"' in src
    assert "unknown option" in src
