"""The hardware first-run checklist must match the code it tells the operator to run.

docs/HARDWARE_FIRST_RUN_CHECKLIST.md (EN) and _JA.md list commands, paths,
accounts, ports, expected values and installer output for the first
Raspberry Pi 5 run (Edge#408, #372, #471, #477). These tests compare them
with the repository: links resolve, both language versions carry the same
check IDs, every repo path, device path, unit, account, port, quoted
installer line (and the order the installer prints its steps), and the
expected values in the check tables (modes, exit codes, HTTP status, time
limits) are the code's, in both languages; and the document holds no address
other than the fixed LAN ones.

The checklist is written for main after #485-#488 and #490 are merged; #489
is a draft tried on its own branch. Items those PRs add are listed in
PENDING with their PR. While the PR is not in this tree (its own test file,
MERGE_MARKERS, is absent) such an item is skipped, and the PR must be named
in the checklist's assumptions. Once the PR is in the tree, every PENDING
entry of that PR FAILS until it is removed, so a forgotten entry cannot keep
an item unchecked; after removal the item is checked like any other.
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
PENDING: dict = {
    # #489 host firewall: in this tree (tests/test_host_firewall_v1.py), so
    # its items are checked against the code like any other.
}

# A PR counts as merged into this tree when its own test file is here.
MERGE_MARKERS = {
    485: "tests/test_external_exposure_477_v1.py",
    486: "tests/test_pi5_platform_layer_v1.py",
    487: "tests/test_pre_hardware_cleanup_v1.py",
    488: "tests/test_wan_exposure_lan_scope_477_v1.py",
    489: "tests/test_host_firewall_v1.py",
    490: "tests/test_rehearsal_small_fixes_v1.py",
}


def _merged(pr: int) -> bool:
    return (ROOT / MERGE_MARKERS[pr]).exists()


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
        pr = PENDING.get(item)
        if pr is not None and _merged(pr):
            self.missing.append(f"#{pr} is merged: remove {item!r} from PENDING")
            return
        if item in corpus:
            return
        if pr is None:
            self.missing.append(f"{where}: {item!r}")
            return
        for doc in CHECKLISTS:
            if f"#{pr}" not in _read(doc):
                self.missing.append(f"{item!r} is pending on #{pr}, which {doc.name} does not name")
        self.pending.append(f"{item!r} (#{pr})")

    def finish(self) -> None:
        if self.missing:
            pytest.fail("not in the code, or a stale PENDING entry:\n" + "\n".join(sorted(set(self.missing))))
        if self.pending:
            pytest.skip("pending PRs not merged in this tree: " + "; ".join(sorted(set(self.pending))))


def test_pending_entries_belong_to_unmerged_prs():
    assert set(PENDING.values()) <= set(MERGE_MARKERS)
    stale = sorted(f"#{pr}: {item!r}" for item, pr in PENDING.items() if _merged(pr))
    assert not stale, "these PRs are merged; remove their PENDING entries:\n" + "\n".join(stale)


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
        for pr in ("#479", "#488", "#489", "#490"):
            assert pr in head, f"{doc.name}: {pr} missing from the assumptions"
    assert "None of it is" in _read(EN) and "device evidence" in _read(EN)
    assert "実機の" in _read(JA) and "証拠ではありません" in _read(JA)


def test_the_489_precondition_is_checked_against_the_current_main():
    # #489 is rebased onto main; the precondition is that its branch still
    # contains main when the FW rows run (main moves on), checked with
    # merge-base, not the earlier "written on an earlier #486" state.
    check = "git merge-base --is-ancestor origin/main try-489"
    for doc, rebased, stale in (
        (EN, "has been\nrebased onto `main`", ("written on an", "conflicts with")),
        (JA, "rebase 済み", ("以前の\n#486 の上で書かれて", "が衝突します")),
    ):
        section = _read(doc).split("### 3.13", 1)[1].split("\n## ", 1)[0]
        assert check in section, doc.name
        assert rebased in section, doc.name
        for phrase in stale:
            assert phrase not in section, (doc.name, phrase)
    assert "`N/A (#489 not rebased)`" in _read(EN) and "`N/A（#489 未 rebase）`" in _read(JA)


def test_3_13_says_what_to_do_once_489_is_merged():
    # #489 merged: 3.13 runs on the main checkout; the branch steps do not apply.
    assert _merged(489)
    for doc, phrase in ((EN, "**If #489 is merged**"), (JA, "**#489 がマージ済みの場合**")):
        section = _read(doc).split("### 3.13", 1)[1].split("\n## ", 1)[0]
        assert phrase in section and "installer/internal/azazel-host-firewall" in section, doc.name
        assert (ROOT / "installer/internal/azazel-host-firewall").is_file()


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
        path = path.rstrip(".")
        # A file the code names by its directory and its name separately.
        head, _, name = path.rpartition("/")
        if path not in corpus and f'"{head}"' in corpus and f'"{name}"' in corpus:
            continue
        tally.check(path, corpus, f"{doc.name} device path")
    tally.finish()


def test_units_named_in_the_checklist_exist(corpus):
    text = _read(EN)
    units = set(re.findall(r"\b(azazel-edge-[a-z-]+)\.(?:service|timer)\b", text))
    units.update(re.findall(r"\b(azazel-edge-(?:control-daemon|core|web|ai-agent|suricata|opencanary))\b", text))
    assert {"azazel-edge-web", "azazel-edge-ai-agent", "azazel-edge-epd-refresh"} <= units
    shipped = {p.stem for p in (ROOT / "systemd").glob("*.service")} | {p.stem for p in (ROOT / "systemd").glob("*.timer")}
    for unit in sorted(units):
        assert unit in shipped, f"unit {unit} is not shipped in systemd/"
    # The portal viewer and the port 8082 status API had no provider and were
    # removed (Edge#477); the checklist no longer names them.
    for doc in (EN, JA):
        assert "portal-viewer" not in _read(doc) and "8082" not in _read(doc)
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
    for doc in CHECKLISTS:
        for expect in ("`750 root:azazel-control`", "`660 root:azazel-control`", "`600 azazel-agent:azazel-agent`",
                       "`660 azazel-agent:azazel-web`", "`640 root:azazel-web`", "`700 azazel-agent:azazel-agent`",
                       "`2750 azazel-agent:azazel-web`", "`750 azazel-agent:azazel-agent`", "`750 azazel-web:azazel-web`",
                       "`750 root:azazel-web`"):
            assert expect in _read(doc), (doc.name, expect)


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
    for doc in CHECKLISTS:
        for port in ("127.0.0.1:8084", "127.0.0.1:8081", "127.0.0.1:11434", "127.0.0.1:18080", "127.0.0.1:12222",
                     "172.16.0.254:22", "0.0.0.0:80", "0.0.0.0:443", "0.0.0.0:8065", "127.0.0.1:18065",
                     "172.16.0.101", "172.16.0.200"):
            assert port in _read(doc), (doc.name, port)


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
    # install_all.sh runs it, then installs it with its timer (aarch64 only).
    install_all = _read(ROOT / "installer" / "internal" / "install_all.sh")
    assert '"${REPO_ROOT}/bin/azazel-edge-selftest"' in install_all
    assert '"${REPO_ROOT}/installer/internal/install_selftest_timer.sh"' in install_all
    assert '"$(uname -m)" == "aarch64"' in install_all
    timer_installer = _read(ROOT / "installer" / "internal" / "install_selftest_timer.sh")
    assert "/usr/local/bin/azazel-edge-selftest" in timer_installer
    assert "systemctl enable --now azazel-edge-selftest.timer" in timer_installer
    assert "OnBootSec=5min" in _read(ROOT / "systemd" / "azazel-edge-selftest.timer")
    assert "OnCalendar=quarterly" in _read(ROOT / "systemd" / "azazel-edge-selftest.timer")
    for doc in CHECKLISTS:
        assert "sudo azazel-edge-selftest;" in _read(doc)
        assert "sudo bin/azazel-edge-selftest" not in _read(doc)
        assert "`[all/9] Install the periodic selftest timer`" in _read(doc)


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
        # 172.17.0.0 and 172.31.0.0: the bounds of Docker's default pools (FW-09).
        assert any(addr in net for net in ALLOWED_NETWORKS) or str(addr) in {"172.17.0.0", "172.31.0.0"}, \
            f"{doc.name}: {raw}"
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



# --- expected values in the check tables --------------------------------------

def _file(rel: str) -> str | None:
    path = ROOT / rel
    return _read(path) if path.exists() else None


# (text in both checklists, PR that adds the code or None, file, code that backs it)
EXPECTED_VALUES = (
    # SVC-05 / installer: the restart counter the installer itself watches
    ("`NRestarts=0`", None, "installer/internal/install_migrated_tools.sh", "NRestarts"),
    # SSH-02: the ssh.service drop-in
    ("`Restart=on-failure`", 486, "installer/internal/install_internal_network.sh", "Restart=on-failure"),
    ("`RestartUSec=5s`", 486, "installer/internal/install_internal_network.sh", "RestartSec=5s"),
    ("`listenaddress 172.16.0.254:22`", None, "installer/internal/install_internal_network.sh", 'SSH_LISTEN_IP="172.16.0.254"'),
    # WAN-01/02/08: nginx refuses with 403 and redirects port 80 with 301
    ("`301`", None, "installer/internal/install_https_proxy.sh", "return 301 https://"),
    ("`403`", 488, "installer/internal/install_https_proxy.sh", "deny all;"),
    # SOCK-07: ntfy's anonymous read
    ("`401`", 485, "installer/internal/install_ntfy.sh", '"$anon_status" != "401" && "$anon_status" != "403"'),
    # WIFI-09: the disconnect route answers 500 on failure
    ("`500`", None, "azazel_edge_web/app.py", "        return jsonify(result), 500"),
    # ST-01: the selftest exits 1 only on a critical failure
    ("`exit=0`", 487, "bin/azazel-edge-selftest", "Exit status: 1 when a critical check failed"),
    # 2.5: exit status 78 from a bad policy YAML
    ("78", None, "systemd/azazel-edge-ai-agent.service", "RestartPreventExitStatus=78"),
    # HIL-06: 15 s for a restarted unit
    (("15 s", "15 秒"), None, "tools/hil/azazel_hil_remote.py", "RESTART_SETTLE_SECONDS = 15"),
    # EPD-05: the renderer limit and the unit limit
    (("45 s", "45 秒"), None, "py/azazel_edge_epd_mode_refresh.py", "timeout=45,"),
    (("60 s", "60 秒"), None, "systemd/azazel-edge-epd-refresh.service", "TimeoutStartSec=60"),
    ("`Result=exit-code`", 486, "py/azazel_edge_epd_mode_refresh.py", "EPD renderer timed out after 45 s"),
    # 2.6: LUKS at boot
    (("90 s", "90 秒"), None, "installer/internal/install_encrypted_storage.sh", "timeout=90s"),
    # AP-04: a generated passphrase has 20 characters
    (("20 characters", "20 文字"), 486, "installer/internal/install_internal_network.sh", '"${raw:0:20}"'),
    # TCH-03 / TCH-05 / TCH-07: the touch console and nginx
    (("1.2 s", "1.2 秒"), None, "azazel_edge_web/static/touch.js", "var HOLD_MS = 1200;"),
    (("5 min", "5 分"), None, "azazel_edge_web/static/touch.js", "STREAM_USER_IDLE_MS = 5 * 60 * 1000"),
    (("120 s", "120 秒"), None, "installer/internal/install_https_proxy.sh", "proxy_read_timeout 120s;"),
    ("`X-Accel-Buffering: no`", None, "azazel_edge_web/app.py", '"X-Accel-Buffering": "no"'),
    # SVC-09: enforcement off in the core unit
    ("`AZAZEL_DEFENSE_ENFORCE=false`", None, "systemd/azazel-edge-core.service", 'Environment="AZAZEL_DEFENSE_ENFORCE=false"'),
    ("`AZAZEL_DEFENSE_DRY_RUN=true`", None, "systemd/azazel-edge-core.service", 'Environment="AZAZEL_DEFENSE_DRY_RUN=true"'),
    ("ssh_bruteforce", None, "py/azazel_edge/dummy_eve.py", '"ssh_bruteforce"'),
    ("`port_scan`", None, "py/azazel_edge/dummy_eve.py", '"port_scan"'),
    # SVC-10 / SVC-11
    ("azg-info-status", None, "installer/internal/install_ntfy.sh", "azg-info-status"),
    ("/api/events/stream", None, "azazel_edge_web/app.py", '@app.route("/api/events/stream")'),
    ("/api/state", None, "azazel_edge_web/app.py", '@app.route("/api/state")'),
    ("`not_checked`", None, "azazel_edge_web/app.py", '"container_check": "not_checked"'),
    # SVC-12: the sensor units run as azazel-sensor and are enabled only with ENABLE_SERVICES=1
    ("`User=azazel-sensor`", None, "systemd/azazel-edge-netflow-receiver.service", "User=azazel-sensor"),
    ("ENABLE_SERVICES=1", None, "installer/internal/install_sensors.sh", 'ENABLE_SERVICES="${ENABLE_SERVICES:-0}"'),
    # 2.5: the order of the units the installer waits for
    ("`[12/16] Enable services`", None, "installer/internal/install_migrated_tools.sh", "wait_active azazel-edge-control-daemon.service\n  wait_active azazel-edge-ai-agent.service\n  wait_active azazel-edge-web.service"),
    # FW rows (#489): trial prompt, timer and states
    ("100 s", 489, "installer/internal/install_internal_network.sh", "read -r -t 100"),
    ("`Host firewall not kept.`", 489, "installer/internal/install_internal_network.sh", 'echo "Host firewall not kept."'),
    ("`remote_access=off`", 489, "installer/internal/azazel-host-firewall", 'echo "remote_access=${remote}"'),
    ("`loaded=no`", 489, "installer/internal/azazel-host-firewall", 'echo "loaded=${loaded}"'),
    ("`DEVICE_HOSTNAME`", 489, "installer/internal/set_dev_remote_access.sh", 'hostnamectl set-hostname "${DEVICE_HOSTNAME}"'),
)


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_expected_values_in_the_tables_are_the_codes(doc):
    text = _read(doc)
    missing, pending = [], []
    for needle, pr, rel, code in EXPECTED_VALUES:
        if isinstance(needle, tuple):
            needle = needle[0] if doc is EN else needle[1]
        assert needle in text, f"{doc.name}: {needle!r} not in the checklist"
        body = _file(rel)
        if body is not None and code in body:
            continue
        if pr is not None and not _merged(pr):
            pending.append(f"{needle} (#{pr})")
            continue
        missing.append(f"{needle!r}: {rel} lacks {code!r}")
    assert not missing, "\n".join(missing)
    if pending:
        pytest.skip("pending PRs not merged in this tree: " + "; ".join(pending))


def test_trial_timer_is_the_helpers_when_present():
    helper = _file("installer/internal/azazel-host-firewall")
    for doc in CHECKLISTS:
        assert "120" in _section(_read(doc), "### 3.13", "## 4.")
    if helper is None:
        pytest.skip("#489 not merged in this tree")
    assert "TRIAL_SECONDS=120" in helper


# --- the order the installer prints its steps ------------------------------------

_SCRIPT_CALL = re.compile(r'(?:\$\{?REPO_ROOT\}?/installer/internal/|/opt/azazel-edge/)([a-z_]+\.sh)')


def _inlined(rel: str, depth: int = 0) -> str:
    """The script with the installer scripts it runs put in place of the call."""
    out = []
    for line in _expand_shell(_read(ROOT / rel)).splitlines():
        out.append(line)
        stripped = line.strip()
        if depth >= 2 or stripped.startswith(("#", "install ", "echo", "rm ")) or "echo " in stripped:
            continue
        for name in _SCRIPT_CALL.findall(stripped):
            target = ROOT / "installer" / "internal" / name
            if target.exists() and name != Path(rel).name:
                out.append(_inlined(f"installer/internal/{name}", depth + 1))
    return "\n".join(out)


_STEP = re.compile(r"^(?:\[(?:all/\d|\d+(?:\.\d+)?/1[67]|ai/\d|ntfy|https|avahi|DONE)\][^…<]*|Installed Azazel-Edge stack |Unified installation completed\.)")


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_install_steps_are_listed_in_the_order_the_installer_prints_them(doc):
    table = _section(_read(doc), "### 2.5", "### 2.6")
    steps = []
    for row in table.splitlines():
        if row.startswith("| ") and not row.startswith("| ---"):
            cells = row.strip().strip("|").split("|")
            steps += [m.group(0).rstrip(" (") for s in _code_spans(cells[1]) if (m := _STEP.match(s))]
    assert len(steps) >= 20, steps
    flow = _inlined("installer/internal/install_all.sh")
    pos, out_of_order, pending = 0, [], []
    for step in steps:
        found = flow.find(step, pos)
        if found >= 0:
            pos = found + len(step)
            continue
        if step in flow:
            out_of_order.append(step)
        else:
            pending.append(step)
    assert not out_of_order, f"{doc.name}: listed out of the printed order: {out_of_order}"
    unmerged = [pr for pr in (485, 486, 487, 488) if not _merged(pr)]
    if pending:
        assert unmerged, f"{doc.name}: not printed by the installer: {pending}"
        pytest.skip(f"printed by #{unmerged} only: {pending}")


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_internal_network_lines_are_in_the_order_main_prints_them(doc):
    row = next(ln for ln in _section(_read(doc), "### 2.5", "### 2.6").splitlines() if "`[all/2]" in ln)
    order = ("Uplink (WAN) interface", "Wi-Fi country: <CC>", "===== verify =====",
             "Internal AP + DHCP baseline applied.", "AP SSID", "AP passphrase", "SSH listen scope",
             "From internal host", "[avahi]")
    idx = [row.find(x) for x in order]
    assert all(i >= 0 for i in idx) and idx == sorted(idx), (doc.name, list(zip(order, idx)))
    if not _merged(486):
        pytest.skip("#486 not merged in this tree")
    net = _read(ROOT / "installer" / "internal" / "install_internal_network.sh")
    main = net[net.index("\nmain() {"):]
    calls = ("check_wifi_country", 'echo "Uplink (WAN) interface', "install_packages", "prepare_wifi_radio",
             "verify_state", 'echo "Internal AP + DHCP baseline applied."', 'echo "AP SSID', "AP passphrase",
             "SSH listen scope", 'echo "From internal host')
    where = [main.find(c) for c in calls]
    assert all(i >= 0 for i in where) and where == sorted(where), list(zip(calls, where))
    assert 'echo "Wi-Fi country: $WIFI_COUNTRY"' in net[net.index("prepare_wifi_radio() {"):]


def _row(doc: Path, check_id: str) -> str:
    rows = [ln for ln in _read(doc).splitlines() if ln.startswith(f"| {check_id} |")]
    assert len(rows) == 1, (doc.name, check_id)
    return rows[0]


# (check ID, text in that row (EN, JA), PR that adds the code or None, file, code that backs it,
#  True when the code must be ABSENT)
ROW_VALUES = (
    ("TCH-07", ("120 s", "120 秒"), None, "installer/internal/install_https_proxy.sh", "proxy_read_timeout 120s;", False),
    ("TCH-07", ("`X-Accel-Buffering: no`",) * 2, None, "azazel_edge_web/app.py", '"X-Accel-Buffering": "no"', False),
    ("SVC-12", ("`User=azazel-sensor`",) * 2, None, "systemd/azazel-edge-netflow-receiver.service", "User=azazel-sensor", False),
    # Result=success / no sensor: the receiver module has no entry point; the row is stale once it gets one.
    ("SVC-12", ("`Result=success`",) * 2, None, "py/azazel_edge/sensors/netflow_receiver.py", "__main__", True),
    ("SVC-12", ("`ENABLE_SERVICES=1`",) * 2, None, "installer/internal/install_sensors.sh", 'ENABLE_SERVICES="${ENABLE_SERVICES:-0}"', False),
    ("SVC-10", ("`200`",) * 2, 485, "installer/internal/install_ntfy.sh", '"$auth_status" != "200"', False),
    ("SVC-09", ("`AZAZEL_DEFENSE_ENFORCE=false`",) * 2, None, "systemd/azazel-edge-core.service", 'Environment="AZAZEL_DEFENSE_ENFORCE=false"', False),
    ("SVC-09", ("`AZAZEL_DEFENSE_DRY_RUN=true`",) * 2, None, "systemd/azazel-edge-core.service", 'Environment="AZAZEL_DEFENSE_DRY_RUN=true"', False),
    ("SVC-05", ("`NRestarts=0`",) * 2, None, "installer/internal/install_migrated_tools.sh", "NRestarts", False),
    # Azazel-Edge does not turn the watchdog on.
    ("ST-05", ("`RuntimeWatchdogUSec=0`",) * 2, None, "installer/internal/install_migrated_tools.sh", "RuntimeWatchdogSec", True),
    ("ST-05", ("`RuntimeWatchdogUSec=0`",) * 2, None, "installer/internal/install_all.sh", "RuntimeWatchdogSec", True),
    ("WIFI-09", ("`500`",) * 2, None, "azazel_edge_web/app.py", "        return jsonify(result), 500", False),
    ("WIFI-09", ("`uplink_interface_serves_internal_lan:wlan0`",) * 2, 486, "py/azazel_edge_control/daemon.py", "uplink_interface_serves_internal_lan:", False),
    ("SOCK-07", ("`401`",) * 2, 485, "installer/internal/install_ntfy.sh", '"$anon_status" != "401" && "$anon_status" != "403"', False),
    ("HIL-06", ("15 s", "15 秒"), None, "tools/hil/azazel_hil_remote.py", "RESTART_SETTLE_SECONDS = 15", False),
    ("EPD-05", ("45 s", "45 秒"), None, "py/azazel_edge_epd_mode_refresh.py", "timeout=45,", False),
    ("EPD-05", ("60 s", "60 秒"), None, "systemd/azazel-edge-epd-refresh.service", "TimeoutStartSec=60", False),
    ("ST-06", ("`Result=success`",) * 2, None, "systemd/azazel-edge-selftest.service", "Type=oneshot", False),
    ("ST-06", ("`failed`",) * 2, None, "bin/azazel-edge-selftest", "Exit status: 1 when a critical check failed", False),
    ("SSH-02", ("`RestartUSec=5s`",) * 2, 486, "installer/internal/install_internal_network.sh", "RestartSec=5s", False),
    ("AP-07", ("`172.16.0.101`",) * 2, None, "installer/internal/install_internal_network.sh", 'DHCP_RANGE_START="172.16.0.101"', False),
    # FW-11: the reload flushes the ruleset; azazel-internal-apply puts the NAT table back.
    ("FW-11", ("`ip azazel_internal`",) * 2, None, "installer/internal/install_internal_network.sh", "nft -f /etc/nftables.d/azazel-internal.nft", False),
    ("FW-11", ("`inet azazel_host`",) * 2, 489, "installer/internal/install_internal_network.sh", "ExecReload=/usr/local/sbin/azazel-host-firewall refresh", False),
    ("FW-06", ("120 s", "120 秒"), 489, "installer/internal/azazel-host-firewall", "TRIAL_SECONDS=120", False),
    ("FW-06", ("`state=rolled-back`",) * 2, 489, "installer/internal/azazel-host-firewall", "write_state rolled-back", False),
    ("FW-01", ("`remote_access=off`",) * 2, 489, "installer/internal/azazel-host-firewall", 'echo "remote_access=${remote}"', False),
    # WAN-10: the certificate names br0, not the uplink (Edge#477).
    ("WAN-10", ("`172.16.0.254`",) * 2, None, "installer/internal/install_local_ca.sh", "ip -4 -o addr show br0", False),
    ("WAN-10", ("`Azazel-Edge.local`",) * 2, None, "installer/internal/install_local_ca.sh", '"${SHORT_NAME}.local"', False),
    ("WAN-10", ("not the WAN address", "WAN のアドレスを含まない"), None, "installer/internal/install_local_ca.sh", "ip -4 route get", True),
    ("WAN-10", ("(the CA is kept)", "（CA はそのまま）"), None, "installer/internal/install_local_ca.sh", 'if (( recreate_ca == 1 )); then', False),
)


@pytest.mark.parametrize("doc", CHECKLISTS, ids=lambda p: p.name)
def test_expected_values_are_in_their_rows_and_backed_by_the_code(doc):
    missing, pending = [], []
    for check_id, needles, pr, rel, code, absent in ROW_VALUES:
        needle = needles[0] if doc is EN else needles[1]
        assert needle in _row(doc, check_id), f"{doc.name} {check_id}: {needle!r} not in the row"
        body = _file(rel)
        if absent:
            if body is not None and code in body:
                missing.append(f"{check_id}: {rel} now has {code!r}; the row is stale")
            continue
        if body is not None and code in body:
            continue
        if pr is not None and not _merged(pr):
            pending.append(f"{check_id} {needle} (#{pr})")
            continue
        missing.append(f"{check_id} {needle!r}: {rel} lacks {code!r}")
    assert not missing, "\n".join(missing)
    if pending:
        pytest.skip("pending PRs not merged in this tree: " + "; ".join(pending))


def test_host_firewall_stages_run_in_the_documented_order():
    for doc in CHECKLISTS:
        ids = [i for i in _check_ids(_section(_read(doc), "### 3.13", "## 4.")) if i.startswith("FW-")]
        assert ids[0] == "FW-01" and ids[-1] == "FW-06", (doc.name, ids)
        section = _section(_read(doc), "### 3.13", "## 4.")
        assert section.count("sudo azazel-host-firewall status") >= 4, doc.name
        assert "</dev/null" in section and "azazel-internal-apply" in section
