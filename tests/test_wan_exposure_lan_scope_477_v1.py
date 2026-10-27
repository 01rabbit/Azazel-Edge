"""WAN-side exposure: nginx, avahi, NetFlow and Vector stay on the LAN (Edge#477, #471).

Found by the pre-hardware WAN exposure audit: nginx (80/443) had no
allow/deny, avahi answered mDNS on every interface, and the optional NetFlow
receiver and Vector aggregator listened on 0.0.0.0. These tests pin the
LAN-only defaults against the constants actually in the scripts; the host
INPUT filter is a separate change.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / "installer" / "internal"
HTTPS = INTERNAL / "install_https_proxy.sh"
AVAHI = INTERNAL / "configure_avahi_lan_only.sh"
INSTALL_ALL = INTERNAL / "install_all.sh"
SENSORS = INTERNAL / "install_sensors.sh"
VECTOR = INTERNAL / "install_vector.sh"
NETWORK = INTERNAL / "install_internal_network.sh"
NETFLOW_UNIT = ROOT / "systemd" / "azazel-edge-netflow-receiver.service"
VECTOR_AGG = ROOT / "security" / "vector" / "vector-aggregator.toml"
MM_COMPOSE = ROOT / "security" / "docker-compose.mattermost.yml"
DEV_REMOTE = INTERNAL / "set_dev_remote_access.sh"

sys.path.insert(0, str(ROOT / "py"))


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _func(src: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def _const(src: str, name: str) -> str:
    m = re.findall(rf'^{name}="([^"$]*)"$', src, re.M)
    assert len(m) == 1, name
    return m[0]


def _fake_ip(tmp_path: Path, out: str) -> dict:
    fake = tmp_path / "ip"
    fake.write_text("#!/bin/sh\nprintf '%s' \"$FAKE_IP_OUT\"\n", encoding="utf-8")
    fake.chmod(0o755)
    return {"PATH": f"{tmp_path}:/usr/bin:/bin", "FAKE_IP_OUT": out}


# --------------------------------------------------------- the constants


def test_the_lan_defaults_are_the_internal_network_settings():
    net = _read(NETWORK)
    lan_cidr = _const(net, "LAN_CIDR")
    lan_addr = _const(net, "SSH_LISTEN_IP")
    assert _const(net, "LAN_ADDR") == f"{lan_addr}/{lan_cidr.split('/')[1]}"
    assert _const(_read(HTTPS), "LAN_CIDR_DEFAULT") == lan_cidr
    for script in (SENSORS, VECTOR):
        assert _const(_read(script), "LAN_ADDR_DEFAULT") == lan_addr
    from azazel_edge.sensors import netflow_receiver as nf

    assert nf.DEFAULT_LISTEN_HOST == lan_addr
    assert f'Environment="NETFLOW_LISTEN_HOST={lan_addr}"' in _read(NETFLOW_UNIT)
    # The fallbacks are a real, private, narrow LAN.
    net_ = ipaddress.ip_network(lan_cidr)
    assert net_.is_private and net_.prefixlen >= 24
    assert ipaddress.ip_address(lan_addr) in net_


def _mm_subnet_from_compose() -> str:
    doc = yaml.safe_load(_read(MM_COMPOSE))
    for name in ("mattermost", "mattermost-db"):
        assert doc["services"][name]["networks"] == ["mattermost"], name
    cfg = doc["networks"]["mattermost"]["ipam"]["config"]
    assert len(cfg) == 1
    return cfg[0]["subnet"]


def test_the_mattermost_bridge_subnet_is_fixed_narrow_and_matches_nginx():
    subnet = _const(_read(HTTPS), "MATTERMOST_BRIDGE_SUBNET")
    assert _mm_subnet_from_compose() == subnet
    net = ipaddress.ip_network(subnet)
    assert net.is_private and net.prefixlen >= 24
    assert not net.overlaps(ipaddress.ip_network(_const(_read(HTTPS), "LAN_CIDR_DEFAULT")))
    # Not the project's default network, which the Ollama compose file shares.
    assert "default" not in yaml.safe_load(_read(MM_COMPOSE))["networks"]


# ------------------------------------------------------------------ nginx


def _render_nginx(lan_cidr: str | None = None) -> str:
    src = _read(HTTPS)
    m = re.search(r'^cat > "\$NGINX_SITE" <<EOF\n(.*?)^EOF\n', src, re.S | re.M)
    assert m
    lan = lan_cidr or _const(src, "LAN_CIDR_DEFAULT")
    script = (
        "set -euo pipefail\n"
        "AZAZEL_WEB_UPSTREAM_HOST=127.0.0.1\nAZAZEL_WEB_UPSTREAM_PORT=8084\n"
        "AZAZEL_TLS_CERT=/c\nAZAZEL_TLS_KEY=/k\nCA_EXPORT_PATH=/ca\n"
        # The script's own constant, not a copy.
        + re.search(r'^MATTERMOST_BRIDGE_SUBNET=.*\n', src, re.M).group(0)
        + f"LAN_CIDR={lan}\n"
        "cat <<EOF\n" + m.group(1) + "EOF\n"
    )
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert res.stderr == ""
    return res.stdout


def test_nothing_runs_inside_the_site_heredoc():
    src = _read(HTTPS)
    body = re.search(r'^cat > "\$NGINX_SITE" <<EOF\n(.*?)^EOF\n', src, re.S | re.M).group(1)
    assert "`" not in body
    assert "$(" not in body


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
    lan = _const(_read(HTTPS), "LAN_CIDR_DEFAULT")
    servers = _servers(_render_nginx())
    assert len(servers) == 2
    for body in servers:
        assert _access(_own_directives(body)) == ["allow 127.0.0.1", "allow ::1", f"allow {lan}", "deny all"]


def test_only_the_slash_command_callback_also_admits_the_mattermost_bridge():
    src = _read(HTTPS)
    lan = _const(src, "LAN_CIDR_DEFAULT")
    mm = _const(src, "MATTERMOST_BRIDGE_SUBNET")
    widened = []
    for body in _servers(_render_nginx()):
        for loc in re.finditer(r"location\s+([^{]+)\{([^}]*)\}", body):
            rules = _access(loc.group(2))
            if rules:
                widened.append((loc.group(1).strip(), rules))
    # Every other location inherits the server's rules.
    assert widened == [("= /api/mattermost/command",
                        ["allow 127.0.0.1", "allow ::1", f"allow {lan}", f"allow {mm}", "deny all"])]
    assert "http://172.16.0.254/api/mattermost/command" in _read(INTERNAL / "provision_mattermost_command.sh")


def test_every_allow_in_the_site_is_loopback_or_a_narrow_private_network():
    # Catches an edit to 0.0.0.0/0, "all", a /12 pool or a public range.
    rules = re.findall(r"^\s*(allow|deny) ([^;]+);", _render_nginx(), re.M)
    assert rules
    for verb, what in rules:
        if verb == "deny":
            assert what == "all"
            continue
        assert what != "all"
        net = ipaddress.ip_network(what, strict=True)
        assert net.is_loopback or (net.is_private and net.prefixlen >= 24), what


def test_no_response_is_sent_before_the_access_rules_are_checked():
    # `return` runs in nginx's rewrite phase, before allow/deny (access
    # phase): a `return` in the server or a normal location would still
    # answer the uplink. Only a named location reached after the access check
    # (try_files) may use it.
    conf = _render_nginx()
    for body in _servers(conf):
        assert not re.search(r"^\s*(return|rewrite)\b", _own_directives(body), re.M)
        for loc in re.finditer(r"location\s+([^{]+)\{([^}]*)\}", body):
            if re.search(r"^\s*(return|rewrite)\b", loc.group(2), re.M):
                assert loc.group(1).strip().startswith("@"), loc.group(1)
    assert "try_files /.azazel-edge-no-such-file @to_https;" in conf
    assert "location @to_https {\n    return 301 https://$host$request_uri;" in conf


def test_nginx_still_listens_on_every_address_so_a_late_lan_cannot_stop_it():
    assert re.findall(r"^\s*listen ([^;]+);", _render_nginx(), re.M) == ["80", "443 ssl"]


def _nginx_version() -> tuple[int, ...] | None:
    if shutil.which("nginx") is None:
        return None
    res = subprocess.run(["nginx", "-v"], capture_output=True, text=True)
    m = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", res.stderr + res.stdout)
    return tuple(int(x) for x in m.groups()) if m else None


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")
def test_the_generated_site_passes_nginx_t(tmp_path):
    version = _nginx_version()
    if version is None:
        pytest.skip("needs nginx")
    if version < (1, 25, 1):
        # The site uses `http2 on;` (nginx 1.25.1+; Debian trixie ships
        # 1.26), which an older nginx (e.g. a CI runner's) does not know.
        pytest.skip(f"nginx {'.'.join(map(str, version))} is older than 1.25.1 (no `http2 on;`)")
    site = _render_nginx().replace(" /c;", f" {tmp_path}/c;").replace(" /k;", f" {tmp_path}/k;")
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                    "-subj", "/CN=t", "-keyout", str(tmp_path / "k"), "-out", str(tmp_path / "c")],
                   check=True, capture_output=True)
    (tmp_path / "site.conf").write_text(site, encoding="utf-8")
    (tmp_path / "nginx.conf").write_text(
        f"pid {tmp_path}/nginx.pid;\nerror_log stderr;\nevents {{}}\n"
        f"http {{\n  access_log off;\n  client_body_temp_path {tmp_path};\n  proxy_temp_path {tmp_path};\n"
        f"  fastcgi_temp_path {tmp_path};\n  uwsgi_temp_path {tmp_path};\n  scgi_temp_path {tmp_path};\n"
        f"  include {tmp_path}/site.conf;\n}}\n", encoding="utf-8")
    res = subprocess.run(["nginx", "-t", "-p", str(tmp_path), "-c", str(tmp_path / "nginx.conf"), "-e", "stderr"],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr


def _detect_lan_cidr(tmp_path: Path, route_out: str):
    src = _read(HTTPS)
    script = ('LAN_IF="br0"\n' + re.search(r'^LAN_CIDR_DEFAULT=.*\n', src, re.M).group(0)
              + _func(src, "valid_ipv4_cidr") + _func(src, "detect_lan_cidr") + "detect_lan_cidr\n")
    env = _fake_ip(tmp_path, route_out)
    # Not settings: overrides in the environment are not read.
    env.update({"AZAZEL_LAN_CIDR": "0.0.0.0/0", "LAN_CIDR": "0.0.0.0/0"})
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def test_the_lan_subnet_comes_from_br0(tmp_path):
    res = _detect_lan_cidr(tmp_path, "10.20.30.0/24 proto kernel scope link src 10.20.30.1\n")
    assert (res.returncode, res.stdout, res.stderr) == (0, "10.20.30.0/24", "")


def test_without_a_br0_route_the_default_is_used_with_a_notice(tmp_path):
    res = _detect_lan_cidr(tmp_path, "")
    assert res.returncode == 0 and res.stdout == _const(_read(HTTPS), "LAN_CIDR_DEFAULT")
    assert res.stderr.startswith("NOTICE: br0 has no IPv4 subnet yet")


@pytest.mark.parametrize("cidr,ok", [
    ("172.16.0.0/24", True), ("10.0.0.0/8", True), ("10.0.0.0/7", False),
    ("192.0.2.1/32", True), ("192.0.2.1/33", False),
    ("223.255.255.0/24", True), ("224.0.0.0/8", False), ("256.1.1.0/24", False), ("10.0.0.256/24", False),
    ("0.0.0.0/0", False), ("0.0.0.0/8", False),
    ("172.016.0.0/24", False), ("10.0.0.00/24", False), ("10.0.0.0/08", False), ("10.0.0.0/0", False),
    ("any", False), ("10.0.0.0", False), ("10.0.0.0/24;allow", False),
])
def test_the_lan_subnet_check_boundaries(tmp_path, cidr, ok):
    res = _detect_lan_cidr(tmp_path, f"{cidr} proto kernel scope link src 10.0.0.1\n")
    assert (res.returncode == 0) is ok, res.stderr
    if not ok:
        assert "IPv4 CIDR" in res.stderr


def test_the_installer_tells_how_to_move_an_existing_mattermost():
    src = _read(HTTPS)
    assert re.search(r'^echo "NOTICE: Mattermost slash commands are admitted only from \$\{MATTERMOST_BRIDGE_SUBNET\}.*'
                     r'403 until Mattermost is recreated .*docker-compose\.mattermost\.yml up -d\)"$', src, re.M)


def test_the_lan_subnet_is_resolved_before_the_site_is_written():
    src = _read(HTTPS)
    at = src.index('LAN_CIDR="$(detect_lan_cidr)"')
    assert at < src.index("apt-get install -y nginx") and at < src.index('cat > "$NGINX_SITE"')
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


def _set_allow(tmp_path: Path, text: str | None) -> tuple[str, str]:
    conf = tmp_path / "avahi-daemon.conf"
    if text is not None:
        conf.write_text(text, encoding="utf-8")
        conf.chmod(0o644)
    src = _read(AVAHI)
    script = (_func(src, "render_allow_interfaces") + _func(src, "set_allow_interfaces")
              + f'set_allow_interfaces "{conf}" br0\n')
    res = subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], check=True, capture_output=True, text=True)
    assert (conf.stat().st_mode & 0o777) == 0o644
    return conf.read_text(encoding="utf-8"), res.stdout.strip()


def _server_section(text: str) -> list[str]:
    m = re.search(r"^\[server\]\n(.*?)(?=^\[|\Z)", text, re.S | re.M)
    assert m
    return m.group(1).splitlines()


def test_avahi_is_limited_to_br0_in_the_server_section(tmp_path):
    out, status = _set_allow(tmp_path, DEBIAN_AVAHI)
    assert status == "changed"
    assert "allow-interfaces=br0" in _server_section(out)
    assert len(re.findall(r"allow-interfaces", out)) == 1
    for line in ("use-ipv6=yes", "#deny-interfaces=eth1", "[wide-area]", "[rlimits]"):
        assert line in out


def test_avahi_rewrite_is_idempotent_and_keeps_one_backup(tmp_path):
    once, _ = _set_allow(tmp_path, DEBIAN_AVAHI)
    bak = tmp_path / "avahi-daemon.conf.azazel-edge.bak"
    assert bak.read_text(encoding="utf-8") == DEBIAN_AVAHI
    again, status = _set_allow(tmp_path, None)
    assert (again, status) == (once, "unchanged")
    # A wider list (dev MODE=open) is narrowed again; the backup stays the
    # original and no more are made.
    _set_allow(tmp_path, DEBIAN_AVAHI.replace("#allow-interfaces=eth0", "allow-interfaces=br0,eth1"))
    assert bak.read_text(encoding="utf-8") == DEBIAN_AVAHI
    assert sorted(p.name for p in tmp_path.iterdir()) == ["avahi-daemon.conf", "avahi-daemon.conf.azazel-edge.bak"]


def test_avahi_without_a_server_section_gets_one(tmp_path):
    out, _ = _set_allow(tmp_path, "[rlimits]\nrlimit-core=0\n")
    assert _server_section(out) == ["allow-interfaces=br0"]
    assert "rlimit-core=0" in out


def test_avahi_is_restarted_only_after_a_change():
    src = _read(AVAHI)
    assert 'if [[ "$result" == "changed" ]] && systemctl is-enabled avahi-daemon' in src
    assert ".bak.$(date" not in src


def test_dev_remote_access_close_mode_matches_and_open_mode_is_the_only_widening():
    dev = _read(DEV_REMOTE)
    assert re.search(r'LAN_IF="\$\{LAN_IF:-br0\}"', dev)
    assert '"allow-interfaces" "${LAN_IF}"\n' in dev
    assert '"allow-interfaces" "${LAN_IF},${wan_if}"' in dev
    assert 'grep -Eq "^[#[:space:]]*${key}="' in dev


def test_install_all_scopes_avahi_right_after_the_network_baseline():
    src = _read(INSTALL_ALL)
    m = re.search(r'^if \[\[ "\$\{ENABLE_INTERNAL_NETWORK\}" == "1" \]\]; then\n(.*?)^else\n', src, re.S | re.M)
    assert m
    assert m.group(1).index("install_internal_network.sh") < m.group(1).index("configure_avahi_lan_only.sh")
    assert src.index("configure_avahi_lan_only.sh") < src.index("set_dev_remote_access.sh")
    assert os.access(AVAHI, os.X_OK)


# ------------------------------------------- listen addresses (NetFlow, Vector)


@pytest.mark.parametrize("script", [SENSORS, VECTOR])
@pytest.mark.parametrize("addr,ok", [
    ("172.16.0.254", True), ("10.0.0.5", True), ("223.1.1.1", True), ("10.0.0.0", True),
    ("127.0.0.1", False), ("127.1.2.3", False), ("255.255.255.255", False),
    ("172.016.0.254", False), ("10.0.0.05", False), ("010.0.0.5", False),
    ("0.0.0.0", False), ("0.1.2.3", False), ("224.0.0.1", False), ("256.0.0.1", False),
    ("10.0.0.256", False), ("", False), ("eth1", False), ("0.0.0.0; x", False), ("::", False),
])
def test_listen_address_check(script, addr, ok):
    res = subprocess.run(["bash", "-c", _func(_read(script), "valid_listen_ipv4") + 'valid_listen_ipv4 "$1"', "_", addr],
                         capture_output=True, text=True)
    assert (res.returncode == 0) is ok


@pytest.mark.parametrize("script", [SENSORS, VECTOR])
def test_the_lan_address_comes_from_br0_with_a_notice_fallback(tmp_path, script):
    src = _read(script)
    body = ('LAN_IF="br0"\n' + re.search(r'^LAN_ADDR_DEFAULT=.*\n', src, re.M).group(0)
            + _func(src, "lan_ipv4") + "lan_ipv4\n")
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True,
                         env=_fake_ip(tmp_path, "5: br0    inet 10.20.30.1/24 brd 10.20.30.255 scope global br0\n"))
    assert (res.returncode, res.stdout, res.stderr) == (0, "10.20.30.1", "")
    res = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=_fake_ip(tmp_path, ""))
    assert res.stdout == _const(src, "LAN_ADDR_DEFAULT")
    assert res.stderr.startswith("NOTICE: br0 has no IPv4 address yet")


@pytest.mark.parametrize("value,rc,out", [
    ("", 0, "172.16.0.254"), ("10.0.0.5", 0, "10.0.0.5"), ("0.0.0.0", 1, None), ("eth1", 1, None),
])
def test_install_sensors_resolves_and_checks_the_listen_host(tmp_path, value, rc, out):
    src = _read(SENSORS)
    m = re.search(r'^\[\[ -n "\$\{NETFLOW_LISTEN_HOST\}" \]\] \|\| .*?^fi\n', src, re.S | re.M)
    assert m
    assert src.index(m.group(0)) < src.index('} > "${SENSOR_ENV_FILE}"')
    script = ('LAN_IF="br0"\n' + re.search(r'^LAN_ADDR_DEFAULT=.*\n', src, re.M).group(0)
              + _func(src, "lan_ipv4") + _func(src, "valid_listen_ipv4")
              + f"NETFLOW_LISTEN_HOST={value!r}\n" + m.group(0) + 'echo "=$NETFLOW_LISTEN_HOST"\n')
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=_fake_ip(tmp_path, ""))
    assert res.returncode == rc
    if out:
        assert res.stdout.strip().splitlines()[-1] == f"={out}"
    else:
        assert "not 0.0.0.0" in res.stdout


def test_netflow_defaults_to_the_lan_address_everywhere():
    from azazel_edge.sensors import netflow_receiver as nf

    assert nf.NetFlowV5Receiver().listen_host == nf.DEFAULT_LISTEN_HOST
    assert nf.NetFlowV5Receiver(listen_host="").listen_host == nf.DEFAULT_LISTEN_HOST
    sensors = _read(SENSORS)
    assert 'NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-}"' in sensors
    assert 'echo "NETFLOW_LISTEN_HOST=${NETFLOW_LISTEN_HOST}"\n' in sensors
    assert 'NETFLOW_LISTEN_HOST="${NETFLOW_LISTEN_HOST:-}"' in _read(INSTALL_ALL)
    for text in (_read(NETFLOW_UNIT), Path(nf.__file__).read_text(encoding="utf-8")):
        assert "0.0.0.0" not in text
    assert not re.search(r"=['\"]?0\.0\.0\.0", sensors)


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
    freebind = ("setsockopt", socket.IPPROTO_IP, nf._IP_FREEBIND, 1)
    bind = ("bind", (nf.DEFAULT_LISTEN_HOST, 2055))
    assert freebind in calls and bind in calls
    assert calls.index(freebind) < calls.index(bind)


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


def test_vector_aggregator_listens_on_the_configured_address_only():
    toml = _read(VECTOR_AGG)
    assert re.findall(r'^address = "([^"]+)"', toml, re.M) == ["${VECTOR_AGGREGATOR_ADDRESS}"]
    assert "0.0.0.0" not in toml
    src = _read(VECTOR)
    assert 'VECTOR_AGGREGATOR_ADDRESS="${VECTOR_AGGREGATOR_ADDRESS:-}"' in src
    assert 'printf "VECTOR_AGGREGATOR_ADDRESS=%s\\n" "${VECTOR_AGGREGATOR_ADDRESS}" > /etc/default/azazel-edge-vector' in src
    assert "EnvironmentFile=-/etc/default/azazel-edge-vector" in _read(ROOT / "systemd" / "azazel-edge-vector.service")


@pytest.mark.parametrize("value,rc,out", [
    ("", 0, "172.16.0.254:5514"), ("10.0.0.5:6000", 0, "10.0.0.5:6000"),
    ("0.0.0.0:5514", 1, None), ("0.0.0.0", 1, None), (":5514", 1, None), ("[::]:5514", 1, None),
    ("10.0.0.5:0", 1, None), ("10.0.0.5:65536", 1, None), ("10.0.0.5:65535", 0, "10.0.0.5:65535"),
])
def test_install_vector_resolves_and_checks_the_aggregator_address(tmp_path, value, rc, out):
    src = _read(VECTOR)
    m = re.search(r'^if \[\[ "\$\{VECTOR_MODE\}" == "aggregator" \]\]; then\n  \[\[ -n .*?^fi\n', src, re.S | re.M)
    assert m
    assert src.index(m.group(0)) < src.index("curl ")
    script = ('LAN_IF="br0"\n' + re.search(r'^LAN_ADDR_DEFAULT=.*\n', src, re.M).group(0)
              + re.search(r'^VECTOR_AGGREGATOR_PORT_DEFAULT=.*\n', src, re.M).group(0)
              + _func(src, "lan_ipv4") + _func(src, "valid_listen_ipv4")
              + f"VECTOR_MODE=aggregator\nVECTOR_AGGREGATOR_ADDRESS={value!r}\n" + m.group(0)
              + 'echo "=$VECTOR_AGGREGATOR_ADDRESS"\n')
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=_fake_ip(tmp_path, ""))
    assert res.returncode == rc
    if out:
        assert res.stdout.strip().splitlines()[-1] == f"={out}"
    else:
        assert "not 0.0.0.0" in res.stdout
