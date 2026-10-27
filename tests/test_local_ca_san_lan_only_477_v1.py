"""The Web UI certificate names the device only as the LAN reaches it (Edge#477, #471).

install_local_ca.sh used to put the source address of the route to 1.1.1.1
(MGMT_IP, the uplink side) in the server certificate's SAN, so the WAN side
could read the device's uplink address from the certificate although nginx
answers 80/443 to loopback and the LAN only. The SAN is now the br0 address,
the host name, localhost and 127.0.0.1, also with set_dev_remote_access.sh
MODE=open (which opens SSH and mDNS only). The SAN-building part of the script
is run here with stub `ip`/`hostname` commands, and, when openssl is present,
a real certificate is issued from its output.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / "installer" / "internal"
LOCAL_CA = INTERNAL / "install_local_ca.sh"
HTTPS = INTERNAL / "install_https_proxy.sh"
DEV_REMOTE = INTERNAL / "set_dev_remote_access.sh"
REMOTE_NFT = INTERNAL / "nft" / "azazel-host-remote-access.nft"

# Documentation addresses (RFC 5737) stand in for the uplink.
WAN_IP = "198.51.100.23"
WAN_GW = "198.51.100.1"
LAN_IP = "172.16.0.254"
FQDN = "edge-test.example.internal"
SHORT = "edge-test"

FAKE_IP = f"""#!/bin/sh
# Stub of iproute2 for the SAN tests: eth0 is the uplink, br0 the LAN.
case "$*" in
  *"route get"*) echo "1.1.1.1 via {WAN_GW} dev eth0 src {WAN_IP} uid 0" ;;
  *"route show default"*) echo "default via {WAN_GW} dev eth0 proto dhcp src {WAN_IP}" ;;
  *"addr show br0"*) echo "5: br0    inet {LAN_IP}/24 brd 172.16.0.255 scope global br0" ;;
  *"addr show"*) echo "2: eth0    inet {WAN_IP}/24 brd 198.51.100.255 scope global eth0"
                 echo "5: br0    inet {LAN_IP}/24 brd 172.16.0.255 scope global br0" ;;
esac
"""

FAKE_IP_NO_BR0 = FAKE_IP.replace(f'*"addr show br0"*) echo "5: br0    inet {LAN_IP}/24 brd 172.16.0.255 scope global br0" ;;', '*"addr show br0"*) ;;')

FAKE_HOSTNAME = f"""#!/bin/sh
case "$1" in
  -f) echo "{FQDN}" ;;
  -s) echo "{SHORT}" ;;
  *) echo "{SHORT}" ;;
esac
"""


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _san_part() -> str:
    """The variable lines and write_server_ext() exactly as the script has them."""
    src = _read(LOCAL_CA)
    lines = [
        line for line in src.splitlines()
        if re.match(r"^(CN|SHORT_NAME|INTERNAL_IP|EXTRA_SANS|MGMT_IP)=", line)
    ]
    m = re.search(r"^write_server_ext\(\) \{\n.*?^\}\n", src, flags=re.M | re.S)
    assert m, "write_server_ext() not found"
    return "\n".join(lines) + "\n" + m.group(0)


def _stub_bin(tmp_path: Path, fake_ip: str = FAKE_IP) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, body in (("ip", fake_ip), ("hostname", FAKE_HOSTNAME)):
        p = bindir / name
        p.write_text(body, encoding="utf-8")
        p.chmod(0o755)
    return bindir


def _ext(tmp_path: Path, env_extra: dict[str, str] | None = None, fake_ip: str = FAKE_IP) -> str:
    bindir = _stub_bin(tmp_path, fake_ip)
    out = tmp_path / "webui.ext"
    script = tmp_path / "san.sh"
    script.write_text(
        "set -euo pipefail\n" + _san_part() + 'write_server_ext "$1"\n', encoding="utf-8"
    )
    env = {
        "PATH": f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(tmp_path),
    }
    env.update(env_extra or {})
    subprocess.run(["bash", str(script), str(out)], check=True, env=env, cwd=tmp_path, timeout=30)
    return out.read_text(encoding="utf-8")


def _alt_names(ext: str) -> list[str]:
    section = ext.split("[alt_names]\n", 1)[1]
    return [line.split("=", 1)[1] for line in section.splitlines() if "=" in line]


# --- the generated openssl extension file ----------------------------------

def test_san_has_lan_hostname_and_loopback_but_not_the_wan(tmp_path):
    ext = _ext(tmp_path)
    names = _alt_names(ext)
    assert WAN_IP not in ext
    for want in (LAN_IP, FQDN, SHORT, "localhost", "127.0.0.1"):
        assert want in names, (want, names)
    assert "subjectAltName=@alt_names" in ext
    assert "extendedKeyUsage=serverAuth" in ext
    assert f"IP.1={LAN_IP}" in ext and "IP.2=127.0.0.1" in ext


def test_a_mgmt_ip_in_the_environment_is_not_put_in(tmp_path):
    # MGMT_IP used to be read from the environment (and the route to 1.1.1.1);
    # neither reaches the certificate now.
    ext = _ext(tmp_path, {"MGMT_IP": WAN_IP})
    assert WAN_IP not in ext
    assert "MGMT_IP" not in _read(LOCAL_CA)
    assert "route get" not in _read(LOCAL_CA)


def test_without_a_br0_address_only_names_and_loopback_remain(tmp_path):
    ext = _ext(tmp_path, fake_ip=FAKE_IP_NO_BR0)
    names = _alt_names(ext)
    assert WAN_IP not in ext and LAN_IP not in ext
    assert names == [FQDN, SHORT, "localhost", "127.0.0.1"]
    assert "br0 has no IPv4 address" in _read(LOCAL_CA)


def test_extra_sans_still_works_as_before(tmp_path):
    # AZAZEL_TLS_EXTRA_SANS is the existing operator setting, unchanged here.
    ext = _ext(tmp_path, {"AZAZEL_TLS_EXTRA_SANS": " edge.lan , 172.16.0.10 "})
    assert "DNS.10=edge.lan" in ext and "IP.10=172.16.0.10" in ext
    assert WAN_IP not in ext


def test_the_script_writes_the_ext_file_it_signs_with():
    src = _read(LOCAL_CA)
    call = src.index('write_server_ext "$SERVER_EXT"')
    sign = src.index("openssl x509 -req -sha256")
    assert call < sign
    assert '-extfile "$SERVER_EXT"' in src[sign:]
    # The distribution note no longer prints an uplink address.
    note = src.split("ca-distribution.txt <<EOF", 1)[1].split("\nEOF", 1)[0]
    assert "MGMT_IP" not in note and "INTERNAL_IP=${INTERNAL_IP}" in note


# --- re-issue on an existing device ----------------------------------------

def test_every_run_issues_a_new_server_cert_and_keeps_a_valid_ca():
    src = _read(LOCAL_CA)
    # The CA is recreated only when it is missing or not a CA.
    guard = src.index("if (( recreate_ca == 1 )); then")
    ca_block = src[guard:src.index("\nfi\n", guard)]
    assert 'openssl genrsa -out "$CA_KEY"' in ca_block
    assert src.count('openssl genrsa -out "$CA_KEY"') == 1
    # The server key and certificate are made on every run, outside that block.
    after = src[src.index("\nfi\n", guard):]
    assert 'openssl genrsa -out "$SERVER_KEY"' in after
    assert '-out "$SERVER_CERT"' in after
    # The installer runs it when ENABLE_LOCAL_CA=1 and then restarts nginx.
    tools = _read(INTERNAL / "install_migrated_tools.sh")
    assert tools.index("/opt/azazel-edge/install_local_ca.sh\nfi") < tools.index("/opt/azazel-edge/install_https_proxy.sh\nfi")
    assert "systemctl restart nginx.service" in _read(HTTPS)


# --- dev remote access (set_dev_remote_access.sh MODE=open) ----------------

def test_dev_open_mode_does_not_open_the_web_ui_to_the_wan():
    # open widens SSH and mDNS only; nginx keeps answering 80/443 to loopback
    # and the LAN, so the WAN address has no use in the certificate in either
    # mode, and the script does not touch the certificate.
    nft = _read(REMOTE_NFT)
    ports = set(re.findall(r"dport (\d+)", nft))
    assert ports == {"22", "5353"}
    dev = _read(DEV_REMOTE)
    for word in ("webui.crt", "install_local_ca", "nginx", "443"):
        assert word not in dev, word
    https = _read(HTTPS)
    for listen in ("listen 80;", "listen 443 ssl;"):
        block = https[https.index(listen):]
        block = block[:block.index("deny all;")]
        allows = re.findall(r"allow ([^;]+);", block)
        assert allows == ["127.0.0.1", "::1", "${LAN_CIDR}"], (listen, allows)


# --- a real certificate ----------------------------------------------------

@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not installed")
def test_a_certificate_issued_from_the_ext_file_has_that_san(tmp_path):
    ext_text = _ext(tmp_path)
    ext = tmp_path / "webui.ext"
    work = tmp_path / "pki"
    work.mkdir()

    def run(*args: str) -> str:
        res = subprocess.run(["openssl", *args], check=True, cwd=work, capture_output=True, text=True, timeout=60)
        return res.stdout

    run("genrsa", "-out", "ca.key", "2048")
    run("req", "-x509", "-new", "-nodes", "-sha256", "-key", "ca.key", "-days", "2",
        "-subj", "/CN=Azazel-Edge Local Root CA/O=Azazel-Edge",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
        "-out", "ca.crt")
    run("genrsa", "-out", "webui.key", "2048")
    run("req", "-new", "-key", "webui.key", "-subj", f"/CN={FQDN}", "-out", "webui.csr")
    run("x509", "-req", "-sha256", "-in", "webui.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
        "-CAcreateserial", "-CAserial", "ca.srl", "-out", "webui.crt", "-days", "2",
        "-extfile", str(ext))
    san = run("x509", "-in", "webui.crt", "-noout", "-ext", "subjectAltName")
    assert WAN_IP not in san and WAN_IP not in ext_text
    for want in (f"IP Address:{LAN_IP}", "IP Address:127.0.0.1", f"DNS:{FQDN}", f"DNS:{SHORT}", "DNS:localhost"):
        assert want in san, (want, san)
    run("verify", "-CAfile", "ca.crt", "webui.crt")
