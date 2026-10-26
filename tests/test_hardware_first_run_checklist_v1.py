"""The hardware first-run checklist must match the code it tells the operator to run.

docs/HARDWARE_FIRST_RUN_CHECKLIST.md (EN) and _JA.md list commands, paths,
accounts, ports and installer output for the first Raspberry Pi 5 run
(Edge#408, #372, #471, #477). These tests compare them with the repository:
links resolve, both language versions carry the same check IDs, every repo
path, device path, unit, account, port and quoted installer line exists in
the code, and the document holds no address other than the fixed LAN ones.

The checklist is written for main after #485-#488 and #490 are merged; #489
is a draft tried on its own branch. Items those PRs add are listed in
PENDING with their PR: while the item is not in this tree it is skipped
(never passed silently: the PR must be named in the checklist's
assumptions). Once the PR is merged the item is checked like any other.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
EN = DOCS / "HARDWARE_FIRST_RUN_CHECKLIST.md"
JA = DOCS / "HARDWARE_FIRST_RUN_CHECKLIST_JA.md"
CHECKLISTS = (EN, JA)

# Where the commands, paths and messages the checklist quotes come from.
CODE_DIRS = ("installer", "systemd", "py", "bin", "azazel_edge_web", "tools", "security", "config")
CODE_SUFFIXES = {".sh", ".py", ".service", ".timer", ".conf", ".yml", ".yaml", ".nft", ".toml", ".rules", ""}

# Items added by PRs that were open when the checklist was written. Each is
# checked once its PR is merged; until then it is skipped with the PR named.
PENDING = {
    # #485 ntfy and Mattermost exposure
    "installer/internal/mattermost_db_secret.sh": 485,
    "/etc/azazel-edge/mattermost-db.env": 485,
    "/etc/azazel-edge/mattermost-credentials.env": 485,
    "[ntfy] Service healthy on http://127.0.0.1:8081 (loopback only, anonymous access denied)": 485,
    "127.0.0.1:18065": 485,
    "/api/v4/system/ping": 485,
    "[ACTION REQUIRED]": 485,
    # #486 Raspberry Pi 5 layer
    "/etc/azazel-edge/internal-ap.psk": 486,
    "Wi-Fi country: ": 486,
    "ERROR: no Wi-Fi country is configured, ": 486,
    "ERROR: the uplink is ": 486,
    ", which becomes part of the internal LAN ": 486,
    "ERROR: the internal AP (lan-wlan0-ap on wlan0) did not come up": 486,
    "ERROR: sshd rejects the new configuration": 486,
    "AP passphrase: a new random one, saved root-only in /etc/azazel-edge/internal-ap.psk ": 486,
    "Uplink (WAN) interface: ": 486,
    "[1/16] Enable SPI for the EPD (Raspberry Pi OS)": 486,
    "NOTICE: SPI is enabled ": 486,
    " reboot before the EPD can draw.": 486,
    "ERROR: the AP passphrase is the old built-in default; ": 486,
    "/dev/spidev0.0": 486,
    "No wireless interface for the uplink: ": 486,
    "wifi sensor: not scanning: ": 486,
    "uplink_interface_serves_internal_lan:": 486,
    "azazel-edge-listen.conf": 486,
    "Cannot bind any address": 486,
    "azazel-edge-epd-refresh: ERROR: ": 486,
    # #487 installer and selftest cleanup
    "[all/8] Run selftest": 487,
    "ERROR: the selftest found a critical failure ": 487,
    "sd_write_test_skipped:not_on_sd:": 487,
    "python_smoke_tests_missing": 487,
    # #488 WAN exposure
    "installer/internal/configure_avahi_lan_only.sh": 488,
    "[avahi] allow-interfaces=br0 in /etc/avahi/avahi-daemon.conf (": 488,
    "[https] nginx TLS reverse proxy enabled on :443 (this device and ": 488,
    "172.31.250.0/24": 488,
    # #490 TUI permission and HIL fixes
    "(control.sock: permission denied)": 490,
    # #489 host firewall (draft, tried on its own branch)
    "azazel-host-firewall": 489,
    "--enable-host-firewall": 489,
    "/usr/local/sbin/azazel-host-firewall": 489,
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code_files():
    for top in CODE_DIRS:
        base = ROOT / top
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts:
                continue
            if path.suffix not in CODE_SUFFIXES:
                continue
            yield path


_ASSIGN = re.compile(r'^\s*(?:local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)="([^"]*)"\s*$')
_DEFAULT = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:-(.*)\}$")
_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def _expand_shell(text: str) -> str:
    """The script with simple variables replaced by their default values.

    Only `NAME="literal"` and `NAME="${OTHER:-literal}"` assignments count
    (the defaults the installer uses when nothing is set); a reference to
    anything else stays as it is, so a message built from it is not matched.
    """
    values: dict[str, str] = {}
    for line in text.splitlines():
        m = _ASSIGN.match(line)
        if not m or m.group(1) in values:
            continue
        value = m.group(2)
        d = _DEFAULT.match(value)
        if d:
            value = d.group(1)
        if "$(" in value or "`" in value:
            continue
        values[m.group(1)] = value

    def sub(s: str) -> str:
        return _REF.sub(lambda m: values.get(m.group(1) or m.group(2), m.group(0)), s)

    for _ in range(4):
        values = {k: sub(v) for k, v in values.items()}
    return sub(text)


@pytest.fixture(scope="module")
def corpus() -> str:
    parts = []
    for path in _code_files():
        try:
            text = _read(path)
        except UnicodeDecodeError:
            continue
        parts.append(text)
        if path.suffix == ".sh" or text.startswith("#!/usr/bin/env bash") or text.startswith("#!/bin/bash"):
            parts.append(_expand_shell(text))
    return "\n".join(parts)


class _Tally:
    """Collects what is missing so a failure lists every item at once."""

    def __init__(self) -> None:
        self.missing: list[str] = []
        self.pending: list[str] = []

    def check(self, item: str, corpus: str, where: str) -> None:
        if item in corpus:
            return
        pr = PENDING.get(item)
        if pr is None:
            self.missing.append(f"{where}: {item!r}")
            return
        for doc in CHECKLISTS:
            if f"#{pr}" not in _read(doc):
                self.missing.append(f"{item!r} is pending on #{pr}, which {doc.name} does not name")
        self.pending.append(f"{item!r} (#{pr})")

    def finish(self) -> None:
        if self.missing:
            pytest.fail("not in the code and not pending:\n" + "\n".join(sorted(set(self.missing))))
        if self.pending:
            pytest.skip("pending PRs not merged in this tree: " + "; ".join(sorted(set(self.pending))))


def _code_spans(text: str) -> list[str]:
    return re.findall(r"`([^`\n]+)`", text)


def _fenced_blocks(text: str) -> list[str]:
    return re.findall(r"```[a-z]*\n(.*?)```", text, flags=re.S)


def _section(text: str, start: str, end: str) -> str:
    i = text.index(start)
    j = text.index(end, i)
    return text[i:j]


# --- structure ------------------------------------------------------------

def test_both_language_versions_exist_and_link_each_other():
    assert EN.is_file() and JA.is_file()
    assert "(HARDWARE_FIRST_RUN_CHECKLIST_JA.md)" in _read(EN)
    assert "(HARDWARE_FIRST_RUN_CHECKLIST.md)" in _read(JA)


def test_index_and_language_policy_list_both_versions():
    index = _read(DOCS / "INDEX.md")
    policy = _read(DOCS / "DOCUMENT_LANGUAGE_POLICY.md")
    for name in (EN.name, JA.name):
        assert f"]({name})" in index
        assert f"`docs/{name}`" in policy


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation and symbols dropped,
    spaces to hyphens."""
    out = []
    for ch in heading.strip().lower():
        if ch in "-_":
            out.append(ch)
        elif ch == " ":
            out.append("-")
        elif unicodedata.category(ch)[0] in "LNM":
            out.append(ch)
    return "".join(out)


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_relative_links_and_anchors_resolve(doc):
    text = _read(doc)
    anchors = {_slug(h) for h in re.findall(r"^#{1,6} (.+)$", text, flags=re.M)}
    links = re.findall(r"\]\(([^)\s]+)\)", text)
    assert links, "expected links"
    for link in links:
        if re.match(r"^[a-z]+://", link):
            continue
        target, _, anchor = link.partition("#")
        if not target:
            assert anchor in anchors, f"{doc.name}: anchor #{anchor} not found"
            continue
        assert (doc.parent / target).resolve().exists(), f"{doc.name}: {link} does not exist"


def _check_ids(text: str) -> list[str]:
    return re.findall(r"^\| ([A-Z0-9]+-\d{2}) \|", text, flags=re.M)


def test_both_versions_carry_the_same_check_ids_in_the_same_order():
    en, ja = _check_ids(_read(EN)), _check_ids(_read(JA))
    assert len(en) >= 60
    assert en == ja
    assert len(set(en)) == len(en), "duplicate check id"


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_every_table_row_has_the_columns_of_its_header(doc):
    rows_seen = 0
    for block in re.split(r"\n(?!\|)", _read(doc)):
        lines = [ln for ln in block.splitlines() if ln.startswith("|")]
        if len(lines) < 2:
            continue
        width = lines[0].count("|")
        for ln in lines:
            assert ln.count("|") == width, f"{doc.name}: column count differs (a '|' in a cell?): {ln[:80]}"
            rows_seen += 1
    assert rows_seen > 60


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_check_tables_have_an_empty_result_column_and_a_reference(doc):
    for line in _read(doc).splitlines():
        m = re.match(r"^\| ([A-Z0-9]+-\d{2}) \|", line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        assert len(cells) == 6, line
        assert cells[4] == "", f"{m.group(1)}: the result column must be left empty"
        assert re.search(r"#\d{3}", cells[5]), f"{m.group(1)}: no PR/issue reference"


def test_the_pr_state_the_checklist_assumes_is_stated():
    for doc in CHECKLISTS:
        head = _read(doc)[:3000]
        for pr in ("#479", "#484", "#485", "#486", "#487", "#488", "#489", "#490"):
            assert pr in head, f"{doc.name}: {pr} missing from the assumptions"
    assert "None of it is" in _read(EN) and "device evidence" in _read(EN)
    assert "実機の" in _read(JA) and "証拠ではありません" in _read(JA)


# --- comparison with the code ----------------------------------------------

_REPO_PATH = re.compile(r"^(?:installer|tools|bin|docs|systemd|security|py|config)/[\w./-]+$")


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_repository_paths_exist(doc, corpus):
    tally = _Tally()
    paths = {s for s in _code_spans(_read(doc)) if _REPO_PATH.match(s)}
    for block in _fenced_blocks(_read(doc)):
        paths.update(re.findall(r"(?<![\w/~])((?:installer|tools|bin)/[\w./-]+)", block))
    assert "installer/internal/install_all.sh" in paths
    for rel in sorted(paths):
        if not (ROOT / rel).exists():
            tally.check(rel, "", f"{doc.name} path")
    tally.finish()


_DEVICE_PATH = re.compile(
    r"(/(?:etc|run|var/log|var/lib|opt|usr/local/s?bin)/azazel[\w.@-]*(?:/[\w.@-]+)*"
    r"|/var/lib/azazel-secrets\.img|/etc/avahi/avahi-daemon\.conf|/etc/suricata/[\w./-]+"
    r"|/etc/ssh/ssh_host_ed25519_key\.pub|/dev/spidev0\.0|/dev/mapper/azazel-secrets)"
)


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_device_paths_are_ones_the_code_uses(doc, corpus):
    found = set(_DEVICE_PATH.findall(_read(doc)))
    assert "/etc/azazel-edge/web_token.txt" in found
    tally = _Tally()
    # Device facts the code does not spell (OS files).
    os_paths = {"/etc/ssh/ssh_host_ed25519_key.pub"}
    for path in sorted(found - os_paths):
        tally.check(path.rstrip("."), corpus, f"{doc.name} device path")
    tally.finish()


def test_units_named_in_the_checklist_exist(corpus):
    text = _read(EN)
    units = set(re.findall(r"\b(azazel-edge-[a-z-]+)\.(?:service|timer)\b", text))
    units.update(re.findall(r"\b(azazel-edge-(?:control-daemon|core|web|ai-agent|suricata|opencanary))\b", text))
    assert {"azazel-edge-web", "azazel-edge-ai-agent", "azazel-edge-epd-refresh"} <= units
    shipped = {p.stem for p in (ROOT / "systemd").glob("*.service")} | {p.stem for p in (ROOT / "systemd").glob("*.timer")}
    # Named in section 5 because it is not shipped (an open question).
    not_shipped = {"azazel-edge-portal-viewer"}
    for unit in sorted(units - not_shipped):
        assert unit in shipped, f"unit {unit} is not shipped in systemd/"
    for unit in not_shipped:
        assert unit not in shipped, f"{unit} is shipped now; update section 5 of the checklist"
        assert re.search(rf"{unit}\.service` is started by the daemon but not shipped", text)
    # Units the installers write (not under systemd/).
    for generated in ("azazel-internal-apply",):
        assert generated in text
        assert f"{generated}.service" in corpus


def test_accounts_and_groups_are_the_installers(corpus):
    for name in ("azazel-web", "azazel-agent", "azazel-control", "azazel-sensor"):
        assert name in _read(EN) and name in _read(JA)
        assert re.search(rf"\b{name}\b", corpus), name
    unit_web = _read(ROOT / "systemd" / "azazel-edge-web.service")
    unit_agent = _read(ROOT / "systemd" / "azazel-edge-ai-agent.service")
    assert "User=azazel-web" in unit_web and "SupplementaryGroups=azazel-control" in unit_web
    assert "User=azazel-agent" in unit_agent
    for unit in ("azazel-edge-control-daemon.service", "azazel-edge-core.service"):
        assert "\nUser=" not in _read(ROOT / "systemd" / unit), f"{unit} is documented as root"


def test_socket_and_directory_modes_match_the_code():
    tmpfiles = _read(ROOT / "systemd" / "azazel-edge-agent.tmpfiles.conf")
    for path in ("/run/azazel-edge-agent", "/run/azazel-edge-agent-query", "/var/log/azazel-edge/ai"):
        assert re.search(rf"^d {re.escape(path)}\s+2750 azazel-agent azazel-web", tmpfiles, flags=re.M), path
    agent_unit = _read(ROOT / "systemd" / "azazel-edge-ai-agent.service")
    assert "RuntimeDirectory=azazel-edge-ai" in agent_unit and "RuntimeDirectoryMode=0700" in agent_unit
    assert "StateDirectoryMode=0750" in agent_unit
    agent = _read(ROOT / "py" / "azazel_edge_ai" / "agent.py")
    assert "SOCKET_MODE = 0o600" in agent and "QUERY_SOCKET_MODE = 0o660" in agent
    web_unit = _read(ROOT / "systemd" / "azazel-edge-web.service")
    for kind in ("RuntimeDirectoryMode", "StateDirectoryMode", "LogsDirectoryMode"):
        assert f"{kind}=0750" in web_unit
    daemon = _read(ROOT / "py" / "azazel_edge_control" / "daemon.py")
    assert '"AZAZEL_CONTROL_SOCKET_MODE", "0660"' in daemon
    setup = _read(ROOT / "installer" / "internal" / "setup_web_account.sh")
    assert "AZAZEL_RUNTIME_DIR_MODE=0750" in setup and "AZAZEL_RUNTIME_SOCKET_GROUP=$CONTROL_GROUP" in setup
    assert "chmod 0640" in setup
    text = _read(EN)
    for expect in ("`750 root:azazel-control`", "`660 root:azazel-control`", "`600 azazel-agent:azazel-agent`",
                   "`660 azazel-agent:azazel-web`", "`640 root:azazel-web`"):
        assert expect in text, expect


def test_ports_match_the_code():
    web_unit = _read(ROOT / "systemd" / "azazel-edge-web.service")
    assert 'AZAZEL_WEB_HOST=127.0.0.1"' in web_unit and 'AZAZEL_WEB_PORT=8084"' in web_unit
    canary = _read(ROOT / "security" / "opencanary" / "opencanary.conf")
    assert '"device.listen_addr": "127.0.0.1"' in canary
    assert '"http.port": 18080' in canary and '"ssh.port": 12222' in canary
    ollama = _read(ROOT / "security" / "docker-compose.ollama.yml")
    assert "127.0.0.1:11434" in ollama
    net = _read(ROOT / "installer" / "internal" / "install_internal_network.sh")
    assert 'SSH_LISTEN_IP="172.16.0.254"' in net and 'LAN_CIDR="172.16.0.0/24"' in net
    assert 'DHCP_RANGE_START="172.16.0.101"' in net and 'DHCP_RANGE_END="172.16.0.200"' in net
    ntfy = _read(ROOT / "installer" / "internal" / "install_ntfy.sh")
    assert "8081" in ntfy and "azg-alert-critical" in ntfy
    https = _read(ROOT / "installer" / "internal" / "install_https_proxy.sh")
    assert "listen 80;" in https and "listen 443 ssl;" in https
    text = _read(EN)
    for port in ("127.0.0.1:8084", "127.0.0.1:8081", "127.0.0.1:11434", "127.0.0.1:18080", "127.0.0.1:12222",
                 "172.16.0.254:22"):
        assert port in text, port


def test_installer_output_quoted_in_section_2_exists(corpus):
    """Every line the install table says to expect is printed by a script."""
    tally = _Tally()
    for doc in CHECKLISTS:
        text = _read(doc)
        start = "### 2.5"
        table = _section(text, start, "### 2.6")
        rows = [ln for ln in table.splitlines() if ln.startswith("| ") and not ln.startswith("| ---")][1:]
        spans = []
        for row in rows:
            cells = row.strip().strip("|").split("|")
            spans += _code_spans(cells[1])
            spans += [s for s in _code_spans(cells[2]) if s.startswith(("ERROR", "ENABLE_RUST_CORE", "WAN interface"))]
        spans += _code_spans(_section(text, "### 2.8", "## 3."))
        assert len(spans) > 25, doc.name
        for span in spans:
            if span.startswith(("ENABLE_*", "docker exec", "journalctl", "sudo ", "rfkill", "nmcli", "/var/log")):
                continue
            if span.startswith("[all/5]") or span.startswith("[all/7]") or span.startswith("[13/16]") or span.startswith("[16/16]"):
                tally.check(span, corpus, f"{doc.name} section 2.5")
                continue
            for fragment in re.split(r"…|<[^>]+>", span):
                if len(fragment.strip()) < 3:
                    continue
                tally.check(fragment, corpus, f"{doc.name} section 2.5/2.8")
    tally.finish()


# Messages and names section 3 tells the operator to look for.
SECTION_3_LITERALS = (
    "802.1X (WPA-Enterprise) networks are not supported here; set the profile up with NetworkManager directly",
    "No wireless interface for the uplink: ",
    "wifi sensor: not scanning: ",
    "uplink_interface_serves_internal_lan:",
    "azazel-wifi-pending-",
    "(control.sock: permission denied)",
    "azazel-edge-epd-refresh: ERROR: ",
    "azazel-edge-listen.conf",
    "Cannot bind any address",
    "ERROR: the AP passphrase is the old built-in default; ",
    "config_checksums_missing",
    "python_smoke_tests_missing",
    "sd_write_test_skipped:not_on_sd:",
    "sd_write_speed_low:",
    "lan-wlan0-ap",
    "lan-br0",
    "azg-alert-critical",
    "172.31.250.0/24",
    "127.0.0.1:18065",
    "qwen3.5:0.8b",
    "qwen3.5:2b",
    "/api/wifi/connect",
    "/touch",
    "/.well-known/azazel-edge-local-ca.crt",
    "/etc/azazel-edge/tls/webui.crt",
    "/run/azazel-edge/epd_last_render.json",
    "--allow-service-restart",
    "--no-update-repo",
    "azazelops",
    "soc-noc",
)


def test_messages_and_names_quoted_in_section_3_exist(corpus):
    tally = _Tally()
    for literal in SECTION_3_LITERALS:
        assert literal.strip() in _read(EN), f"not in the checklist: {literal!r}"
        tally.check(literal, corpus, "section 3")
    # The disconnect route (POST /api/action/<action>) and its action.
    app = _read(ROOT / "azazel_edge_web" / "app.py")
    assert '@app.route("/api/action/<action>", methods=["POST"])' in app
    assert '"disconnect": execute_disconnect_action' in app
    assert "https://127.0.0.1/api/action/disconnect" in _read(EN)
    # Trigger and alias of the slash command.
    cmd = _read(ROOT / "installer" / "internal" / "provision_mattermost_command.sh")
    assert ":-mio}" in cmd and ":-azops}" in cmd
    assert "`/mio <question>`" in _read(EN) and "`/azops`" in _read(EN)
    tally.finish()


def test_suricata_rule_count_is_the_rules_file():
    rules = _read(ROOT / "security" / "suricata" / "azazel-lite.rules")
    active = len(re.findall(r"^\s*(?:alert|drop|pass|reject)\b", rules, flags=re.M))
    assert re.search(r"^#.*sid:\s*9901211", rules, flags=re.M), "9901211 is documented as disabled"
    assert f"{active} active rules" in _read(EN)
    assert f"有効なルールは {active} 本" in _read(JA)


def test_selftest_facts_match_the_script():
    selftest = _read(ROOT / "bin" / "azazel-edge-selftest")
    assert "/var/log/azazel-edge/selftest_latest.json" in selftest or 'OUT_JSON="${LOG_DIR}/selftest_latest.json"' in selftest
    assert "/etc/azazel-edge/.config_checksums" in selftest
    assert "config_checksums_missing" in selftest
    # Nothing in the installers creates the checksum file (open question).
    installers = "\n".join(_read(p) for p in (ROOT / "installer").rglob("*.sh"))
    assert ".config_checksums" not in installers
    for doc in CHECKLISTS:
        assert "sudo bin/azazel-edge-selftest" in _read(doc)


def test_hil_exit_codes_match_the_bridge_doc():
    bridge = _read(DOCS / "R0_PI_HIL_BRIDGE.md")
    codes = re.findall(r"^\|\s*(\d+)\s*\|", bridge, flags=re.M)
    assert set(codes) == {"0", "1", "2", "3", "255"}
    for doc in CHECKLISTS:
        sentence = _section(_read(doc), "`full`", "| ID |")
        for code in codes:
            assert f"`{code}`" in sentence, f"{doc.name}: exit {code} missing"
    hil = _read(ROOT / "tools" / "hil" / "azazel_hil.py")
    for option in ("--target", "--user", "--session", "--no-update-repo", "--allow-service-restart", "--service"):
        assert f'"{option}"' in hil, option
    assert '"~/Azazel-Edge"' in hil
    assert "/opt/azazel-edge/venv/bin/python" in hil


def test_install_variables_are_the_installers():
    net = _read(ROOT / "installer" / "internal" / "install_internal_network.sh")
    for var in ("AP_SSID", "AP_PSK", "ALLOW_EXTERNAL_SSH"):
        assert f'{var}="${{{var}:-' in net, var
    tools = _read(ROOT / "installer" / "internal" / "install_migrated_tools.sh")
    assert 'SKIP_LUKS="${SKIP_LUKS:-0}"' in tools
    runtime = _read(ROOT / "installer" / "internal" / "install_ai_runtime.sh")
    assert 'ENABLE_MATTERMOST="${ENABLE_MATTERMOST:-1}"' in runtime
    assert 'ENABLE_OLLAMA="${ENABLE_OLLAMA:-1}"' in runtime
    storage = _read(ROOT / "installer" / "internal" / "install_encrypted_storage.sh")
    assert 'IMG_PATH="/var/lib/azazel-secrets.img"' in storage and 'MAPPER_NAME="azazel-secrets"' in storage
    assert "timeout=90s" in storage and "nofail" in storage


# --- what the document must not hold ----------------------------------------

ALLOWED_NETWORKS = [ipaddress.ip_network(n) for n in (
    "172.16.0.0/24",      # the fixed internal LAN
    "172.31.250.0/24",    # the fixed Mattermost bridge network
    "127.0.0.0/8",
    "0.0.0.0/32",
)]


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_no_address_other_than_the_fixed_ones(doc):
    for raw in re.findall(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?(?![\w.])", _read(doc)):
        addr = ipaddress.ip_address(raw)
        assert any(addr in net for net in ALLOWED_NETWORKS) or str(addr) == "1.1.1.1", f"{doc.name}: {raw}"
    assert not re.search(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", _read(doc), flags=re.I), "MAC address"


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_no_secret_is_put_on_a_command_line(doc):
    text = _read(doc)
    for block in _fenced_blocks(text) + _code_spans(text):
        assert not re.search(r"curl[^\n]*-H\s+['\"]?(?:X-Auth-Token|Authorization)", block), block
        assert not re.search(r"--passphrase(?!-stdin)\b|password\s+\S", block), block
        assert not re.search(r"\?token=[^`\s]", block), block
    # The token reaches curl on stdin only.
    assert "curl -sk -H @-" in text


def test_host_firewall_trial_matches_the_489_helper_when_present():
    """Section 3.13 runs the #489 branch; once #489 is in this tree, its
    helper and installer options must be the ones the checklist uses."""
    helper = ROOT / "installer" / "internal" / "azazel-host-firewall"
    text = _read(EN)
    for needle in ("--enable-host-firewall", "sudo azazel-host-firewall confirm", "sudo azazel-host-firewall status",
                   "sudo azazel-host-firewall disable", "state=enabled", "state=rolled-back", "state=off", "loaded=yes"):
        assert needle in text, needle
    if not helper.exists():
        pytest.skip("#489 not merged in this tree (the checklist tries it on its branch)")
    code = _read(helper)
    for sub in ("confirm) cmd_confirm", "status) cmd_status", "disable) cmd_disable"):
        assert sub in code, sub
    for state in ("enabled", "rolled-back"):
        assert f"write_state {state}" in code, state
    assert 'echo "state=${state:-off}"' in code and 'echo "loaded=${loaded}"' in code
    net = _read(ROOT / "installer" / "internal" / "install_internal_network.sh")
    assert "--enable-host-firewall)" in net and "--disable-host-firewall)" in net
