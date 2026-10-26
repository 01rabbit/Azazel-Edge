"""Suricata rule set (security/suricata/azazel-lite.rules) contract.

Static half (always runs): the SIDs and messages that the tactical scorer,
config/attack_mapping.yaml, dummy_eve and the benchmark corpus are pinned to
stay present, and the constructs that Suricata 7 refuses to load (http
``flow:to_client`` with request buffers, ``alert arp``, ``dsize`` mixed with
app-layer matches, sticky buffers without a match) do not come back.

Suricata half (runs only where a ``suricata`` binary exists, e.g. the
``suricata-rules`` CI job on debian:trixie; skipped elsewhere): ``suricata -T``
must load every active rule (rc=0, no rule errors), and a pcap built with scapy
must make each active rule fire, while benign traffic must not.

A container or CI run is not evidence from the real device.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "security" / "suricata" / "azazel-lite.rules"
UNIT = ROOT / "systemd" / "azazel-edge-suricata.service"
PACKAGED_YAML = Path("/etc/suricata/suricata.yaml")

# SID -> msg, as pinned by py/azazel_edge/tactics_engine/scorer.py,
# py/azazel_edge/dummy_eve.py and tests/benchmark/corpus.
EXPECTED = {
    9901101: "AZAZEL OPENCANARY SSH probe",
    9901102: "AZAZEL OPENCANARY HTTP probe",
    9901103: "AZAZEL OPENCANARY repeated access",
    9901201: "AZAZEL DISASTER phishing - fake government domain",
    9901202: "AZAZEL DISASTER phishing - fake MyNumber portal",
    9901203: "AZAZEL DISASTER phishing - fake disaster relief site",
    9901211: "AZAZEL ARP spoof - gateway impersonation detected",
    9901221: "AZAZEL SCAN internal host rapid port scan",
    9901222: "AZAZEL SCAN external rapid port scan on shelter network",
    9901231: "AZAZEL DNS exfil - unusually long DNS query",
    9901232: "AZAZEL DNS tunnel - high-frequency DNS queries",
    9901241: "AZAZEL CREDENTIAL harvest - password field in GET request",
    9901251: "AZAZEL C2 beacon - periodic small HTTP POST",
    9901261: "AZAZEL SSH brute-force - repeated auth failures",
}

# Rules kept in the file but commented out because Suricata cannot express
# them (Suricata 7 has no ARP detection). Their SID stays reserved.
DISABLED = {9901211}

_RULE_RE = re.compile(r"^(#\s*)?(alert|drop|pass|reject)\s+(\S+)\s+.*\(.*\bsid:(\d+);", re.S)


def _rules():
    active, disabled = {}, {}
    for line in RULES.read_text(encoding="utf-8").splitlines():
        m = _RULE_RE.match(line.strip())
        if not m:
            continue
        sid = int(m.group(4))
        msg = re.search(r'msg:"([^"]*)"', line).group(1)
        (disabled if m.group(1) else active)[sid] = (m.group(3), msg, line.strip().lstrip("#").strip())
    return active, disabled


def _home_net() -> str:
    m = re.search(r'vars\.address-groups\.HOME_NET="(\[[^\]]*\])"', UNIT.read_text(encoding="utf-8"))
    assert m, "HOME_NET not found in the Suricata unit"
    return m.group(1)


def test_sids_and_messages_are_pinned():
    active, disabled = _rules()
    assert set(active) | set(disabled) == set(EXPECTED)
    assert not set(active) & set(disabled)
    assert set(disabled) == DISABLED
    for sid, (_proto, msg, _line) in {**active, **disabled}.items():
        assert msg == EXPECTED[sid], sid


def test_disabled_rules_explain_why():
    text = RULES.read_text(encoding="utf-8")
    for sid in DISABLED:
        idx = text.index(f"sid:{sid};")
        preceding = text[:idx].rsplit("\n# ---", 1)[-1]
        assert "Suricata" in preceding and "not" in preceding.lower(), sid


def test_no_constructs_suricata7_rejects():
    active, _ = _rules()
    for sid, (proto, _msg, line) in active.items():
        assert proto != "arp", sid
        if proto in {"http", "dns", "tls", "smb"}:
            # packet keywords cannot be mixed with app-layer state matching
            assert not re.search(r"\b(dsize|flags|ttl):", line), sid
        if proto == "http" and re.search(r"\bhttp[._](host|uri|method|content_len)\b", line):
            # request buffers only exist in the to_server direction
            assert "to_client" not in line, sid
        # a sticky buffer must be followed by a match before the next keyword group
        for m in re.finditer(r"\b(dns\.query|http\.host|http\.uri|http\.method|http\.content_len);\s*(\w+)", line):
            assert m.group(2) in {"content", "bsize", "pcre", "isdataat"}, (sid, m.group(0))


def test_phishing_rules_watch_shelter_clients_requests():
    active, _ = _rules()
    for sid in (9901201, 9901202, 9901203):
        line = active[sid][2]
        assert line.startswith("alert http $HOME_NET any -> any any"), sid
        assert "flow:established,to_server" in line, sid


# --------------------------------------------------------------------------
# Suricata half
# --------------------------------------------------------------------------

SURICATA = shutil.which("suricata")
needs_suricata = pytest.mark.skipif(SURICATA is None, reason="suricata binary not installed")


def _minimal_yaml(tmp: Path) -> Path:
    path = tmp / "minimal.yaml"
    classification = "/etc/suricata/classification.config"
    path.write_text(
        "%YAML 1.1\n---\n"
        "vars:\n"
        "  address-groups:\n"
        f'    HOME_NET: "{_home_net()}"\n'
        '    EXTERNAL_NET: "!$HOME_NET"\n'
        "  port-groups:\n"
        '    HTTP_PORTS: "80"\n'
        f"classification-file: {classification}\n"
        "outputs:\n"
        "  - eve-log:\n"
        "      enabled: yes\n"
        "      filetype: regular\n"
        "      filename: eve.json\n"
        "      types: [alert]\n",
        encoding="utf-8",
    )
    return path


def _unit_sets() -> list:
    return [
        "--set", f"vars.address-groups.HOME_NET={_home_net()}",
        "--set", "vars.address-groups.EXTERNAL_NET=!$HOME_NET",
    ]


def _assert_loads(cmd: list) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "error parsing signature" not in out, out


@needs_suricata
def test_suricata_t_minimal_yaml(tmp_path):
    _assert_loads([SURICATA, "-T", "-c", str(_minimal_yaml(tmp_path)), "-S", str(RULES), "-l", str(tmp_path)])


@needs_suricata
@pytest.mark.skipif(not PACKAGED_YAML.exists(), reason="no packaged suricata.yaml")
def test_suricata_t_packaged_yaml_as_unit(tmp_path):
    _assert_loads([SURICATA, "-T", "-c", str(PACKAGED_YAML), "-S", str(RULES), "-l", str(tmp_path), *_unit_sets()])


CLIENT = "172.16.0.50"  # inside HOME_NET
SERVER_EXT = "198.51.100.10"  # outside HOME_NET
RESOLVER = "172.16.0.1"


def _build_pcap(path: Path) -> None:
    scapy = pytest.importorskip("scapy.all")
    IP, TCP, UDP, DNS, DNSQR, Raw = scapy.IP, scapy.TCP, scapy.UDP, scapy.DNS, scapy.DNSQR, scapy.Raw
    pkts = []
    clock = [1_700_000_000.0]
    sport = [20000]

    def add(pkt):
        clock[0] += 0.01
        pkt.time = clock[0]
        pkts.append(pkt)

    def http(src, dst, request: bytes, response: bytes = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"):
        sport[0] += 1
        sp, cs, ss = sport[0], 1000, 5000
        add(IP(src=src, dst=dst) / TCP(sport=sp, dport=80, flags="S", seq=cs))
        add(IP(src=dst, dst=src) / TCP(sport=80, dport=sp, flags="SA", seq=ss, ack=cs + 1))
        add(IP(src=src, dst=dst) / TCP(sport=sp, dport=80, flags="A", seq=cs + 1, ack=ss + 1))
        add(IP(src=src, dst=dst) / TCP(sport=sp, dport=80, flags="PA", seq=cs + 1, ack=ss + 1) / Raw(request))
        add(IP(src=dst, dst=src) / TCP(sport=80, dport=sp, flags="PA", seq=ss + 1, ack=cs + 1 + len(request)) / Raw(response))
        add(IP(src=src, dst=dst) / TCP(sport=sp, dport=80, flags="FA", seq=cs + 1 + len(request), ack=ss + 1 + len(response)))
        add(IP(src=dst, dst=src) / TCP(sport=80, dport=sp, flags="FA", seq=ss + 1 + len(response), ack=cs + 2 + len(request)))
        add(IP(src=src, dst=dst) / TCP(sport=sp, dport=80, flags="A", seq=cs + 2 + len(request), ack=ss + 2 + len(response)))

    def get(src, host, uri):
        return f"GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: t\r\n\r\n".encode()

    def dns(src, qname, qid):
        sport[0] += 1
        add(IP(src=src, dst=RESOLVER) / UDP(sport=sport[0], dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname)))

    # phishing (9901201-9901203) from a shelter client to an outside server
    http(CLIENT, SERVER_EXT, get(CLIENT, "www.gov.example-fake.test", "/account/login"))
    http(CLIENT, SERVER_EXT, get(CLIENT, "MyNumber-Support.example.test", "/"))
    http(CLIENT, SERVER_EXT, get(CLIENT, "saigai-shien.example.test", "/donate"))
    # benign HTTP from another client: none of the phishing rules may fire
    http("172.16.0.60", SERVER_EXT, get("172.16.0.60", "www.example.test", "/index.html"))
    # C2 beacon (9901251): 12 small POSTs from one host within 60 s
    body = b"id=42&s=ok"
    post = (b"POST /b HTTP/1.1\r\nHost: c2.example.test\r\nContent-Length: %d\r\n\r\n" % len(body)) + body
    for _ in range(12):
        http("172.16.0.70", SERVER_EXT, post)
    # large POSTs (500-byte body) from another host: 9901251 must not fire
    big = b"x" * 500
    big_post = (b"POST /u HTTP/1.1\r\nHost: upload.example.test\r\nContent-Length: %d\r\n\r\n" % len(big)) + big
    for _ in range(12):
        http("172.16.0.71", SERVER_EXT, big_post)
    # DNS exfil (9901231): one query name longer than 100 bytes
    dns("172.16.0.80", ("a" * 60) + "." + ("b" * 50) + ".exfil.example.test", 1)
    # short query from another host: must not trigger 9901231
    dns("172.16.0.81", "www.example.test", 2)
    # DNS tunnel (9901232): 60 queries from one host within 10 s
    for i in range(60):
        dns("172.16.0.90", f"q{i}.t.example.test", 100 + i)

    scapy.wrpcap(str(path), pkts)


@needs_suricata
@pytest.mark.skipif(not PACKAGED_YAML.exists(), reason="no packaged suricata.yaml")
def test_rules_fire_on_crafted_pcap(tmp_path):
    pcap = tmp_path / "azazel-lite.pcap"
    _build_pcap(pcap)
    logdir = tmp_path / "log"
    logdir.mkdir()
    proc = subprocess.run(
        [SURICATA, "-c", str(PACKAGED_YAML), "-S", str(RULES), "-l", str(logdir), "-k", "none",
         "-r", str(pcap), *_unit_sets(), "--set", "outputs.1.eve-log.types=[alert]"],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    alerts = [json.loads(line) for line in (logdir / "eve.json").read_text().splitlines() if line.strip()]
    alerts = [a for a in alerts if a.get("event_type") == "alert"]
    fired = {}
    for a in alerts:
        fired.setdefault(a["alert"]["signature_id"], []).append(a)

    for sid in (9901201, 9901202, 9901203, 9901231, 9901232, 9901251):
        assert sid in fired, (sid, sorted(fired))
        assert fired[sid][0]["alert"]["signature"] == EXPECTED[sid]
    # the shelter client is the source of the phishing alerts
    for sid in (9901201, 9901202, 9901203):
        assert {a["src_ip"] for a in fired[sid]} == {CLIENT}, sid
    # benign HTTP, large POSTs and the short DNS query did not trigger anything
    assert not [a for a in alerts if a["src_ip"] in {"172.16.0.60", "172.16.0.71", "172.16.0.81"}]
    # threshold "type both": one alert per window per source
    assert len(fired[9901232]) == 1 and fired[9901232][0]["src_ip"] == "172.16.0.90"
    assert len(fired[9901251]) == 1 and fired[9901251][0]["src_ip"] == "172.16.0.70"
    assert {a["src_ip"] for a in fired[9901231]} == {"172.16.0.80"}
