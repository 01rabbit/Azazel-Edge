"""WAN-side exposure: nginx, avahi, NetFlow and Vector stay on the LAN (Edge#477, #471).

Found by the pre-hardware WAN exposure audit: nginx (80/443) had no
allow/deny, avahi answered mDNS on every interface, and the optional NetFlow
receiver and Vector aggregator listened on 0.0.0.0. These tests pin the
LAN-only defaults; the host INPUT filter is a separate change.
"""
from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / "installer" / "internal"
HTTPS = INTERNAL / "install_https_proxy.sh"
AVAHI = INTERNAL / "configure_avahi_lan_only.sh"
INSTALL_ALL = INTERNAL / "install_all.sh"
SENSORS = INTERNAL / "install_sensors.sh"
VECTOR = INTERNAL / "install_vector.sh"
NETFLOW_UNIT = ROOT / "systemd" / "azazel-edge-netflow-receiver.service"
VECTOR_AGG = ROOT / "security" / "vector" / "vector-aggregator.toml"
DEV_REMOTE = INTERNAL / "set_dev_remote_access.sh"

sys.path.insert(0, str(ROOT / "py"))


def _func(src: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


# ------------------------------------------------------------------ nginx


def _https_src() -> str:
    return HTTPS.read_text(encoding="utf-8")


def _render_nginx(lan_cidr: str = "172.16.0.0/24") -> str:
    src = _https_src()
    m = re.search(r'^cat > "\$NGINX_SITE" <<EOF\n(.*?)^EOF\n', src, re.S | re.M)
    assert m
    script = (
        "AZAZEL_WEB_UPSTREAM_HOST=127.0.0.1\nAZAZEL_WEB_UPSTREAM_PORT=8084\n"
        "AZAZEL_TLS_CERT=/c\nAZAZEL_TLS_KEY=/k\nCA_EXPORT_PATH=/ca\n"
        f"LAN_CIDR={lan_cidr}\nDOCKER_BRIDGE_POOL=172.16.0.0/12\n"
        "cat <<EOF\n" + m.group(1) + "EOF\n"
    )
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return res.stdout


def _servers(conf: str) -> list[str]:
    """Bodies of the top-level `server {...}` blocks (brace-matched)."""
    out = []
    for m in re.finditer(r"^server \{", conf, re.M):
        depth, i = 1, m.end()
        while depth:
            depth += {"{": 1, "}": -1}.get(conf[i], 0)
            i += 1
        out.append(conf[m.end():i - 1])
    return out


def _own_directives(block: str) -> str:
    """The block's text without its nested blocks."""
    out, depth = [], 0
    for ch in block:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def _access(text: str) -> list[str]:
    return re.findall(r"^\s*((?:allow|deny) [^;]+);", text, re.M)


def test_both_nginx_servers_admit_only_this_device_and_the_lan():
    conf = _render_nginx("172.16.0.0/24")
    servers = _servers(conf)
    assert len(servers) == 2
    for body in servers:
        assert _access(_own_directives(body)) == [
            "allow 127.0.0.1", "allow ::1", "allow 172.16.0.0/24", "deny all"]


def test_only_the_slash_command_callback_also_admits_the_docker_bridge_pool():
    conf = _render_nginx("172.16.0.0/24")
    widened = []
    for body in _servers(conf):
        for loc in re.finditer(r"location\s+([^{]+)\{([^}]*)\}", body):
            rules = _access(loc.group(2))
            if rules:
                widened.append((loc.group(1).strip(), rules))
    # Every other location inherits the server's rules.
    assert widened == [("= /api/mattermost/command", [
        "allow 127.0.0.1", "allow ::1", "allow 172.16.0.0/24", "allow 172.16.0.0/12", "deny all"])]
    # The callback URL it serves is the one the provisioner registers.
    prov = (INTERNAL / "provision_mattermost_command.sh").read_text(encoding="utf-8")
    assert "http://172.16.0.254/api/mattermost/command" in prov


def test_no_response_is_sent_before_the_access_rules_are_checked():
    # `return` runs in nginx's rewrite phase, before allow/deny (access
    # phase): a `return` in the server or a normal location would still
    # answer the uplink. Only a named location reached after the access check
    # (try_files) may use it.
    conf = _render_nginx()
    for body in _servers(conf):
        own = _own_directives(body)
        assert not re.search(r"^\s*(return|rewrite)\b", own, re.M)
        for loc in re.finditer(r"location\s+([^{]+)\{([^}]*)\}", body):
            if re.search(r"^\s*(return|rewrite)\b", loc.group(2), re.M):
                assert loc.group(1).strip().startswith("@"), loc.group(1)
    assert "try_files /.azazel-edge-no-such-file @to_https;" in conf
    assert "location @to_https {\n    return 301 https://$host$request_uri;" in conf


def test_nginx_still_listens_on_every_address_so_a_late_lan_cannot_stop_it():
    conf = _render_nginx()
    assert re.findall(r"^\s*listen ([^;]+);", conf, re.M) == ["80", "443 ssl"]


def _detect_lan_cidr(tmp_path: Path, route_out: str):
    src = _https_src()
    fake_ip = tmp_path / "ip"
    fake_ip.write_text("#!/bin/sh\nprintf '%s' \"$FAKE_ROUTE\"\n", encoding="utf-8")
    fake_ip.chmod(0o755)
    script = 'LAN_IF="br0"\nLAN_CIDR_DEFAULT="172.16.0.0/24"\n' + _func(src, "detect_lan_cidr") + "detect_lan_cidr\n"
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "FAKE_ROUTE": route_out,
           # Not a setting: an override in the environment is not read.
           "AZAZEL_LAN_CIDR": "0.0.0.0/0", "LAN_CIDR": "0.0.0.0/0"}
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def test_the_lan_subnet_comes_from_br0(tmp_path):
    res = _detect_lan_cidr(tmp_path, "10.20.30.0/24 proto kernel scope link src 10.20.30.1\n")
    assert res.returncode == 0 and res.stdout == "10.20.30.0/24"


def test_without_a_br0_route_the_installer_lan_default_is_used(tmp_path):
    res = _detect_lan_cidr(tmp_path, "")
    assert res.returncode == 0 and res.stdout == "172.16.0.0/24"
    net = (INTERNAL / "install_internal_network.sh").read_text(encoding="utf-8")
    assert 'LAN_CIDR="172.16.0.0/24"' in net


@pytest.mark.parametrize("bad", ["0.0.0.0/0", "10.0.0.0/4", "any", "10.0.0.0", "10.0.0.0/24;allow"])
def test_a_wide_or_malformed_lan_subnet_stops_the_install(tmp_path, bad):
    res = _detect_lan_cidr(tmp_path, f"{bad} proto kernel scope link src 10.0.0.1\n")
    assert res.returncode == 1
    assert "IPv4 CIDR" in res.stderr


def test_the_lan_subnet_is_resolved_before_the_site_is_written():
    src = _https_src()
    assert 'LAN_CIDR="$(detect_lan_cidr)"' in src
    assert src.index('LAN_CIDR="$(detect_lan_cidr)"') < src.index('apt-get install -y nginx')
    assert src.index('LAN_CIDR="$(detect_lan_cidr)"') < src.index('cat > "$NGINX_SITE"')
    assert re.search(r"^set -euo pipefail$", src, re.M)


# ------------------------------------------------------------------ avahi


DEBIAN_AVAHI = """\
[server]
#host-name=foo
#domain-name=local
use-ipv4=yes
use-ipv6=yes
#allow-interfaces=eth0
#deny-interfaces=eth1
ratelimit-interval-usec=1000000

[wide-area]
enable-wide-area=yes

[rlimits]
"""


def _set_allow(tmp_path: Path, text: str) -> str:
    conf = tmp_path / "avahi-daemon.conf"
    conf.write_text(text, encoding="utf-8")
    conf.chmod(0o644)
    src = AVAHI.read_text(encoding="utf-8")
    script = _func(src, "set_allow_interfaces") + f'set_allow_interfaces "{conf}" br0\n'
    subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], check=True)
    assert (conf.stat().st_mode & 0o777) == 0o644
    return conf.read_text(encoding="utf-8")


def _server_section(text: str) -> list[str]:
    m = re.search(r"^\[server\]\n(.*?)(?=^\[|\Z)", text, re.S | re.M)
    assert m
    return m.group(1).splitlines()


def test_avahi_is_limited_to_br0_in_the_server_section(tmp_path):
    out = _set_allow(tmp_path, DEBIAN_AVAHI)
    assert "allow-interfaces=br0" in _server_section(out)
    assert len(re.findall(r"allow-interfaces", out)) == 1
    # Everything else is kept.
    for line in ("use-ipv6=yes", "#deny-interfaces=eth1", "[wide-area]", "[rlimits]"):
        assert line in out


def test_avahi_rewrite_is_idempotent_and_replaces_a_wider_list(tmp_path):
    once = _set_allow(tmp_path, DEBIAN_AVAHI)
    assert _set_allow(tmp_path, once) == once
    widened = DEBIAN_AVAHI.replace("#allow-interfaces=eth0", "allow-interfaces=br0,eth1")
    assert _set_allow(tmp_path, widened) == once


def test_avahi_without_a_server_section_gets_one(tmp_path):
    out = _set_allow(tmp_path, "[rlimits]\nrlimit-core=0\n")
    assert _server_section(out) == ["allow-interfaces=br0"]
    assert "rlimit-core=0" in out


def test_dev_remote_access_close_mode_matches_and_open_mode_is_the_only_widening():
    dev = DEV_REMOTE.read_text(encoding="utf-8")
    assert re.search(r'LAN_IF="\$\{LAN_IF:-br0\}"', dev)
    assert '"allow-interfaces" "${LAN_IF}"\n' in dev
    assert '"allow-interfaces" "${LAN_IF},${wan_if}"' in dev
    # The dev script's upsert matches the line this script writes.
    assert 'grep -Eq "^[#[:space:]]*${key}="' in dev


def test_install_all_scopes_avahi_right_after_the_network_baseline():
    src = INSTALL_ALL.read_text(encoding="utf-8")
    m = re.search(r'^if \[\[ "\$\{ENABLE_INTERNAL_NETWORK\}" == "1" \]\]; then\n(.*?)^else\n', src, re.S | re.M)
    assert m
    body = m.group(1)
    assert body.index("install_internal_network.sh") < body.index("configure_avahi_lan_only.sh")
    # Dev remote access (MODE=open widens avahi on purpose) runs later.
    assert src.index("configure_avahi_lan_only.sh") < src.index("set_dev_remote_access.sh")
    assert os.access(AVAHI, os.X_OK)


# --------------------------------------------------------------- NetFlow


def test_netflow_defaults_to_the_lan_address_everywhere():
    from azazel_edge.sensors import netflow_receiver as nf

    assert nf.DEFAULT_LISTEN_HOST == "172.16.0.254"
    assert nf.NetFlowV5Receiver().listen_host == "172.16.0.254"
    assert nf.NetFlowV5Receiver(listen_host="").listen_host == "172.16.0.254"
    unit = NETFLOW_UNIT.read_text(encoding="utf-8")
    assert 'Environment="NETFLOW_LISTEN_HOST=172.16.0.254"' in unit
    sensors = SENSORS.read_text(encoding="utf-8")
    assert 'NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-172.16.0.254}"' in sensors
    assert "NETFLOW_LISTEN_HOST=${NETFLOW_LISTEN_HOST}\n" in sensors
    assert 'NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-172.16.0.254}"' in INSTALL_ALL.read_text(encoding="utf-8")
    for text in (unit, sensors, Path(nf.__file__).read_text(encoding="utf-8")):
        assert "0.0.0.0" not in text


@pytest.mark.parametrize("value,rc", [("172.16.0.254", 0), ("10.0.0.5", 0), ("", 1), ("eth1", 1), ("0.0.0.0; x", 1)])
def test_install_sensors_checks_the_listen_host(value, rc):
    src = SENSORS.read_text(encoding="utf-8")
    m = re.search(r'^if \[\[ ! "\$\{NETFLOW_LISTEN_HOST\}" =~ .*?^fi\n', src, re.S | re.M)
    assert m
    assert src.index(m.group(0)) < src.index('cat > "${SENSOR_ENV_FILE}"')
    res = subprocess.run(["bash", "-c", f"NETFLOW_LISTEN_HOST={value!r}\n" + m.group(0) + "echo ok\n"],
                         capture_output=True, text=True)
    assert res.returncode == rc


def test_netflow_binds_with_freebind_to_the_configured_host():
    from azazel_edge.sensors import netflow_receiver as nf

    calls = []

    class _Sock:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def setsockopt(self, *args):
            calls.append(("setsockopt",) + args)

        def bind(self, addr):
            calls.append(("bind", addr))
            receiver.stop()

        def settimeout(self, *_a):
            return None

    receiver = nf.NetFlowV5Receiver(dispatch_fn=lambda _l: None)
    with patch.object(nf.socket, "socket", return_value=_Sock()), patch.object(nf.sys, "platform", "linux"):
        receiver.run_forever()
    assert ("bind", ("172.16.0.254", 2055)) in calls
    assert ("setsockopt", socket.IPPROTO_IP, nf._IP_FREEBIND, 1) in calls
    assert calls.index(("setsockopt", socket.IPPROTO_IP, nf._IP_FREEBIND, 1)) < calls.index(("bind", ("172.16.0.254", 2055)))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="IP_FREEBIND is Linux-only")
def test_freebind_lets_the_lan_address_bind_before_it_is_on_br0():
    from azazel_edge.sensors import netflow_receiver as nf

    # 192.0.2.0/24 (TEST-NET-1) is not on this host.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(OSError):
            s.bind(("192.0.2.254", 0))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.IPPROTO_IP, nf._IP_FREEBIND, 1)
        s.bind(("192.0.2.254", 0))
        assert s.getsockname()[0] == "192.0.2.254"


# ---------------------------------------------------------------- Vector


def test_vector_aggregator_listens_on_the_configured_address_only():
    toml = VECTOR_AGG.read_text(encoding="utf-8")
    assert re.findall(r'^address = "([^"]+)"', toml, re.M) == ["${VECTOR_AGGREGATOR_ADDRESS}"]
    assert "0.0.0.0" not in toml
    src = VECTOR.read_text(encoding="utf-8")
    assert 'VECTOR_AGGREGATOR_ADDRESS="${VECTOR_AGGREGATOR_ADDRESS:-172.16.0.254:5514}"' in src
    assert 'printf "VECTOR_AGGREGATOR_ADDRESS=%s\\n" "${VECTOR_AGGREGATOR_ADDRESS}" > /etc/default/azazel-edge-vector' in src
    unit = (ROOT / "systemd" / "azazel-edge-vector.service").read_text(encoding="utf-8")
    assert "EnvironmentFile=-/etc/default/azazel-edge-vector" in unit


@pytest.mark.parametrize("value,rc", [("172.16.0.254:5514", 0), ("", 1), ("0.0.0.0", 1), (":5514", 1), ("[::]:5514", 1)])
def test_install_vector_checks_the_aggregator_address_before_installing(value, rc):
    src = VECTOR.read_text(encoding="utf-8")
    m = re.search(r'^if \[\[ "\$\{VECTOR_MODE\}" == "aggregator" \]\]; then\n  if .*?^fi\n', src, re.S | re.M)
    assert m
    assert src.index(m.group(0)) < src.index("curl ")
    res = subprocess.run(
        ["bash", "-c", f"VECTOR_MODE=aggregator\nVECTOR_AGGREGATOR_ADDRESS={value!r}\n" + m.group(0) + "echo ok\n"],
        capture_output=True, text=True)
    assert res.returncode == rc
