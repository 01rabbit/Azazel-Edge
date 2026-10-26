"""Edge#471: a fresh install by the installer alone starts (Pi 5, trixie).

Found by the pre-hardware audit:

- the launchers the installer copies to /usr/local/bin looked for the code in
  their own parent (/usr/local/py) and did not start; the control daemon unit
  started one of them;
- the Rust core build copied only main.rs (its `mod` files were missing) and
  had no Cargo.lock; the core unit was enabled before its binary existed and
  ENABLE_RUST_CORE changed nothing;
- the encrypted storage step ran by default, asks for a passphrase on a
  terminal, and wrote a crypttab line that can hold a headless boot;
- config/ was not installed and the SOC policy / ATT&CK mapping defaults
  were relative to the working directory (/ under systemd);
- the sensor units used ${VAR:-default}, which systemd does not expand, and
  had no PYTHONPATH;
- the AI runtime used `docker compose` without installing compose, and its
  Mattermost defaults were written only when the env file did not exist.
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
TOOLS = INTERNAL / "install_migrated_tools.sh"
SYNC = INTERNAL / "verify_runtime_sync.sh"
SECURITY = INTERNAL / "install_security_stack.sh"
LUKS = INTERNAL / "install_encrypted_storage.sh"
AI_RUNTIME = INTERNAL / "install_ai_runtime.sh"
SYSTEMD = ROOT / "systemd"
INSTALL_ROOT = "/opt/azazel-edge"


def _function(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(r"^\s*" + name + r"\(\) \{\n.*?^\s*\}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def _installed_launchers() -> list[str]:
    """bin/ files the installer copies into /usr/local/bin."""
    src = TOOLS.read_text(encoding="utf-8")
    names = re.findall(r'^install -m 0755 "\$REPO_ROOT/bin/([\w-]+)" /usr/local/bin/\1$', src, re.M)
    assert len(names) >= 10
    return names


def _unit(name: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in (SYSTEMD / name).read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#") and not line.startswith("["):
            key, value = line.split("=", 1)
            out.setdefault(key, []).append(value)
    return out


def _env_of(unit: dict[str, list[str]]) -> dict[str, str]:
    env: dict[str, str] = {}
    for value in unit.get("Environment", []):
        key, val = value.strip('"').split("=", 1)
        env[key] = val
    return env


# --------------------------------------------------------------- launchers


@pytest.fixture()
def installed_layout(tmp_path):
    """A /usr/local/bin and an install root like the installer leaves them.

    The launchers are copied (not linked) into <tmp>/usr/local/bin, whose
    parent holds no code, and the literal /opt/azazel-edge in each copy is
    pointed at <tmp>/opt/azazel-edge, which holds the repo's code. Nothing is
    read from the checkout through the launcher's own location.
    """
    bindir = tmp_path / "usr" / "local" / "bin"
    bindir.mkdir(parents=True)
    root = tmp_path / "opt" / "azazel-edge"
    root.mkdir(parents=True)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    for sub in ("py", "azazel_edge_web", "config"):
        shutil.copytree(ROOT / sub, root / sub, ignore=ignore)
    for name in _installed_launchers():
        text = (ROOT / "bin" / name).read_text(encoding="utf-8")
        (bindir / name).write_text(text.replace(INSTALL_ROOT, str(root)), encoding="utf-8")
        (bindir / name).chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = f"{Path(sys.executable).parent}:{env.get('PATH', '/usr/bin:/bin')}"
    for key in ("PYTHONPATH", "AZAZEL_VENV_PYTHON", "AZAZEL_EDGE_SCENARIO_BOOTSTRAPPED"):
        env.pop(key, None)
    return bindir, root, env


def test_the_installed_launchers_find_the_install_root_from_another_directory(installed_layout, tmp_path):
    bindir, root, env = installed_layout
    # A python that reports what it was asked to run, so the daemons are not
    # started; every launcher that takes AZAZEL_VENV_PYTHON is checked.
    probe = tmp_path / "probe-python"
    probe.write_text('#!/bin/sh\nprintf "%s\\n%s\\n%s\\n" "$1" "$PYTHONPATH" "$2"\n', encoding="utf-8")
    probe.chmod(0o755)
    checked = 0
    for name in _installed_launchers():
        text = (bindir / name).read_text(encoding="utf-8")
        if "AZAZEL_VENV_PYTHON" not in text or not text.startswith("#!/usr/bin/env bash"):
            continue
        res = subprocess.run([str(bindir / name)], env={**env, "AZAZEL_VENV_PYTHON": str(probe)},
                             capture_output=True, text=True, timeout=30, cwd="/")
        assert res.returncode == 0, (name, res.stderr)
        script, pythonpath, second = res.stdout.splitlines()[:3]
        if script == "-m":  # `python -m pkg.mod`: the module must be in the install root
            script = str(root / "py" / (second.replace(".", "/") + ".py"))
        assert script.startswith(str(root) + "/") and Path(script).is_file(), (name, script)
        assert f"{root}/py" in pythonpath.split(":"), (name, pythonpath)
        assert "/usr/local/py" not in pythonpath, name
        checked += 1
    assert checked >= 6


def test_the_installed_launchers_really_start_from_another_directory(installed_layout, tmp_path):
    bindir, root, env = installed_layout
    runs = {
        "azazel-edge-dummy-eve": ["list"],
        "azazel-edge-audit-review": ["--help"],
        "azazel-edge-scenario-replay": ["list"],
    }
    for name, args in runs.items():
        assert name in _installed_launchers()
        res = subprocess.run([str(bindir / name), *args], env=env, capture_output=True, text=True,
                             timeout=120, cwd=str(tmp_path))
        assert res.returncode == 0, (name, res.stdout[-2000:], res.stderr[-2000:])
        assert res.stdout.strip(), name


def test_a_launcher_without_code_anywhere_stops_with_a_clear_message(installed_layout):
    bindir, root, env = installed_layout
    shutil.rmtree(root / "py")
    for name in ("azazel-edge-control-daemon", "azazel-edge-dummy-eve", "azazel-edge-scenario-replay"):
        res = subprocess.run([str(bindir / name)], env=env, capture_output=True, text=True, timeout=30)
        assert res.returncode != 0, name
        assert "Azazel-Edge code not found" in res.stderr, (name, res.stderr)


def test_a_launcher_in_a_checkout_still_runs_the_checkout_code():
    for name in ("azazel-edge-control-daemon", "azazel-edge-web", "azazel-edge-ai-agent"):
        text = (ROOT / "bin" / name).read_text(encoding="utf-8")
        checkout_first = text.index('ROOT_DIR="$(cd "${SELF_DIR}/.." && pwd)"')
        assert checkout_first < text.index('ROOT_DIR="/opt/azazel-edge"'), name
        # No environment variable chooses where the code is read from.
        assert not re.search(r'ROOT_DIR="\$\{[A-Z_]+', text), name


def test_the_injector_runs_the_dummy_eve_next_to_it():
    text = (ROOT / "bin" / "azazel-edge-injector").read_text(encoding="utf-8")
    assert 'DUMMY_EVE="${SELF_DIR}/azazel-edge-dummy-eve"' in text


def test_the_control_daemon_unit_names_the_install_root_and_its_venv():
    unit = _unit("azazel-edge-control-daemon.service")
    assert unit["ExecStart"] == [f"{INSTALL_ROOT}/venv/bin/python {INSTALL_ROOT}/py/azazel_edge_control/daemon.py"]
    assert (ROOT / "py" / "azazel_edge_control" / "daemon.py").is_file()
    assert _env_of(unit)["PYTHONPATH"] == f"{INSTALL_ROOT}:{INSTALL_ROOT}/py"


# ------------------------------------------------------------ Rust core


def test_the_installer_copies_every_core_source_and_the_lock_file():
    src = TOOLS.read_text(encoding="utf-8")
    assert '"$REPO_ROOT/rust/azazel-edge-core/src/"*.rs' in src
    assert '"$REPO_ROOT/rust/azazel-edge-core/Cargo.lock"' in src
    assert "cargo build --release --locked --manifest-path" in src
    main = (ROOT / "rust" / "azazel-edge-core" / "src" / "main.rs").read_text(encoding="utf-8")
    mods = re.findall(r"^mod (\w+);", main, re.M)
    assert mods
    for mod in mods:
        assert (ROOT / "rust" / "azazel-edge-core" / "src" / f"{mod}.rs").is_file(), mod
    assert (ROOT / "rust" / "azazel-edge-core" / "Cargo.lock").is_file()


def test_the_core_is_built_before_it_is_enabled_and_only_when_asked_for():
    src = TOOLS.read_text(encoding="utf-8")
    assert "enable --now azazel-edge-core" not in src
    build = src.index("cargo build --release --locked")
    placed = src.index("/usr/local/bin/azazel-edge-core\n")
    enable = src.index("systemctl enable azazel-edge-core.service")
    restart = src.index("systemctl restart azazel-edge-core.service")
    assert build < placed < enable < restart
    # Every core step sits under ENABLE_RUST_CORE == 1.
    for needle in ("apt-get install -y rustc cargo", "cargo build", "systemd/azazel-edge-core.service",
                   "systemctl enable azazel-edge-core.service"):
        pos = src.index(needle)
        guard = src.rfind('if [[ "$ENABLE_RUST_CORE" == "1" ]]; then', 0, pos)
        assert guard != -1 and not re.search(r"\n\s*fi\n", src[guard:pos]), needle
    assert re.search(r'^ENABLE_RUST_CORE="\$\{ENABLE_RUST_CORE:-1\}"$', src, re.M)  # default unchanged
    all_src = (INTERNAL / "install_all.sh").read_text(encoding="utf-8")
    assert re.search(r'ENABLE_RUST_CORE="\$\{ENABLE_RUST_CORE\}"[^\n]*\n?[^\n]*install_migrated_tools\.sh', all_src)


def test_the_runtime_sync_check_follows_enable_rust_core(tmp_path):
    src = SYNC.read_text(encoding="utf-8")
    assert "rust/azazel-edge-core/Cargo.lock" in src and "rust/azazel-edge-core/src" in src
    res = subprocess.run(["bash", str(SYNC), str(ROOT), str(tmp_path), "bogus"], capture_output=True, text=True)
    assert res.returncode == 2 and "with-rust-core or without-rust-core" in res.stderr
    tools = TOOLS.read_text(encoding="utf-8")
    assert '/opt/azazel-edge/verify_runtime_sync.sh "$REPO_ROOT" /opt/azazel-edge with-rust-core' in tools
    assert '/opt/azazel-edge/verify_runtime_sync.sh "$REPO_ROOT" /opt/azazel-edge without-rust-core' in tools


# ------------------------------------------------------ encrypted storage


def test_the_encrypted_storage_stays_on_by_default_and_a_failure_stops():
    # Edge#206: on unless SKIP_LUKS=1; fail-closed.
    src = SECURITY.read_text(encoding="utf-8")
    assert "ENABLE_ENCRYPTED_STORAGE" not in src
    assert 'SKIP_LUKS="${SKIP_LUKS:-0}"' in src
    call = src.index('"${ASSET_ROOT}/installer/internal/install_encrypted_storage.sh"')
    guard = src.rindex('if [[ "${SKIP_LUKS}" != "1" ]]; then', 0, call)
    assert guard < call and not re.search(r"\n\s*fi\n", src[guard:call])
    line = src[call:src.index("\n", call)]
    assert "|| true" not in line
    tools = TOOLS.read_text(encoding="utf-8")
    assert 'SKIP_LUKS="$SKIP_LUKS" /opt/azazel-edge/install_security_stack.sh' in tools


_PREFLIGHT_RE = r"^if \[\[ [^\n]*SKIP_LUKS[^\n]*(?:\n[^\n]*)*?\n  exit 1\nfi\n"


@pytest.mark.parametrize("script,env", [
    (INTERNAL / "install_all.sh", {"ENABLE_APP_STACK": "1"}),
    (TOOLS, {"ENABLE_SECURITY_STACK": "1"}),
    (SECURITY, {}),
])
def test_an_install_without_a_terminal_stops_before_changing_anything(script, env):
    src = script.read_text(encoding="utf-8")
    m = re.search(_PREFLIGHT_RE, src, re.M)
    assert m, script.name
    # Before any package install, network change or file copy.
    for first in ("apt-get", "install_internal_network.sh", "install -d", "install -m"):
        if first in src:
            assert m.start() < src.index(first), (script.name, first)
    body = "".join(f"{k}={v}\n" for k, v in env.items()) + m.group(0) + "echo reached\n"
    res = subprocess.run(["bash", "-c", body], stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert res.returncode == 1 and "reached" not in res.stdout, script.name
    assert "interactive terminal" in res.stderr and "SKIP_LUKS=1" in res.stderr, script.name
    # An explicit SKIP_LUKS=1 is the only way past it.
    res = subprocess.run(["bash", "-c", "SKIP_LUKS=1\n" + body], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True)
    assert res.returncode == 0 and "reached" in res.stdout, script.name


def test_the_encrypted_storage_stops_without_a_terminal():
    script = _function(LUKS, "require_tty") + 'require_tty "test step"\necho reached\n'
    res = subprocess.run(["bash", "-c", script], stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert res.returncode == 1 and "reached" not in res.stdout
    assert "interactive terminal" in res.stderr and "SKIP_LUKS=1" in res.stderr
    src = LUKS.read_text(encoding="utf-8")
    first_tty = src.index('require_tty "setting up the encrypted volume"')
    assert first_tty < src.index("dd if=/dev/zero") < src.index("cryptsetup luksFormat")
    assert "set -x" not in src


def _gnu_sed_shim() -> str:
    """A bash prefix that makes `sed -i` (GNU form, as the installer runs it
    on Debian) work with the BSD sed of macOS, which needs a suffix argument
    after -i. Empty where sed is GNU sed."""
    try:
        gnu = subprocess.run(["sed", "--version"], capture_output=True).returncode == 0
    except OSError:
        gnu = False
    if gnu:
        return ""
    return 'sed() { if [[ "$1" == -i ]]; then shift; command sed -i \'\' "$@"; else command sed "$@"; fi; }\n'


def test_the_crypttab_line_does_not_hold_a_headless_boot(tmp_path):
    src = LUKS.read_text(encoding="utf-8")
    opts = re.search(r'^CRYPTTAB_OPTIONS="([^"]+)"$', src, re.M).group(1).split(",")
    assert "luks" in opts and "nofail" in opts
    assert any(o.startswith("timeout=") and o != "timeout=0" for o in opts)
    assert any(o.startswith("x-systemd.device-timeout=") for o in opts)
    block = re.search(r'^if ! grep -q "\$\{IMG_PATH\}" /etc/crypttab.*?^fi\n', src, re.S | re.M).group(0)
    crypttab = tmp_path / "crypttab"
    head = (f'IMG_PATH=/var/lib/azazel-secrets.img\nMAPPER_NAME=azazel-secrets\n'
            f'CRYPTTAB_OPTIONS="{",".join(opts)}"\n')
    script = _gnu_sed_shim() + head + block.replace("/etc/crypttab", str(crypttab))
    want = f"azazel-secrets /var/lib/azazel-secrets.img none {','.join(opts)}\n"
    # New line.
    subprocess.run(["bash", "-c", script], check=True)
    assert crypttab.read_text() == want
    # A re-run finds the current line: no change, no notice.
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert crypttab.read_text() == want and res.stderr == ""
    # The line an earlier install wrote is bounded too.
    crypttab.write_text("other /dev/x none luks\nazazel-secrets /var/lib/azazel-secrets.img none luks\n")
    subprocess.run(["bash", "-c", script], check=True)
    assert crypttab.read_text() == "other /dev/x none luks\n" + want
    # An operator's own line is left alone.
    own = "azazel-secrets /var/lib/azazel-secrets.img /root/key luks,discard\n"
    crypttab.write_text(own)
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert crypttab.read_text() == own and "not changed" in res.stderr


def test_no_unit_requires_the_encrypted_mount():
    for unit in SYSTEMD.glob("*.service"):
        assert "/etc/azazel-edge/secrets" not in unit.read_text(encoding="utf-8"), unit.name


# ------------------------------------------------------------ config


def _run_py(code: str, cwd: Path, **extra: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.startswith("AZAZEL_")}
    env["PYTHONPATH"] = str(ROOT / "py")
    env.update(extra)
    return subprocess.run([sys.executable, "-c", code], cwd=str(cwd), env=env, capture_output=True, text=True, timeout=120)


def test_the_default_config_paths_do_not_depend_on_the_working_directory(tmp_path):
    code = (
        "import json\n"
        "from azazel_edge import policy\n"
        "from azazel_edge.knowledge import attack_mapping as am\n"
        "p = policy.load_soc_policy(); m = am.load_attack_mapping()\n"
        "hits = am.map_attack_techniques({'attrs': {'sid': 9901201, 'attack_type': 'phishing', 'category': 'social-engineering'}}, m)\n"
        "print(json.dumps({'policy': p['path'], 'source': p.get('source'), 'mapping': m['path'],\n"
        "  'rules': len(m['rules']), 'ids': [h['technique_id'] for h in hits]}))\n"
    )
    res = _run_py(code, tmp_path)
    assert res.returncode == 0, res.stderr
    import json
    out = json.loads(res.stdout)
    assert out["policy"] == str(ROOT / "config" / "soc_policy.yaml") and out["source"] != "default"
    assert out["mapping"] == str(ROOT / "config" / "attack_mapping.yaml") and out["rules"] > 0
    assert "T1566" in out["ids"]


def test_the_environment_still_overrides_the_config_paths(tmp_path):
    mapping = tmp_path / "m.yaml"
    mapping.write_text("rules:\n  - {technique_id: T9999, technique_name: x, tactic: y, confidence: 50, sid: [1]}\n")
    code = (
        "from azazel_edge.knowledge import attack_mapping as am\n"
        "from azazel_edge import policy\n"
        "print(am.load_attack_mapping()['rules'][0]['technique_id'], policy.load_soc_policy()['source'])\n"
    )
    res = _run_py(code, tmp_path, AZAZEL_ATTACK_MAPPING_PATH=str(mapping),
                  AZAZEL_SOC_POLICY_PATH=str(tmp_path / "missing.yaml"))
    assert res.returncode == 0, res.stderr
    assert res.stdout.split() == ["T9999", "default"]


def test_a_missing_config_file_is_warned_about_once(tmp_path, caplog):
    from azazel_edge import policy
    from azazel_edge.knowledge import attack_mapping as am

    with caplog.at_level("WARNING"):
        for _ in range(3):
            assert policy.load_soc_policy(tmp_path / "none.yaml")["source"] == "default"
            assert am.load_attack_mapping(tmp_path / "none2.yaml")["rules"] == []
    messages = [r.getMessage() for r in caplog.records]
    assert sum("none.yaml" in m for m in messages) == 1
    assert sum("none2.yaml" in m for m in messages) == 1


def test_a_broken_config_file_is_a_clear_error_not_the_defaults(tmp_path):
    from azazel_edge import policy
    from azazel_edge.knowledge import attack_mapping as am

    broken = tmp_path / "broken.yaml"
    broken.write_text("action_mapping: [unclosed\n", encoding="utf-8")
    with pytest.raises(ValueError, match="soc_policy_invalid:unreadable:.*broken.yaml"):
        policy.load_soc_policy(broken)
    with pytest.raises(ValueError, match="attack_mapping_invalid:unreadable:.*broken.yaml"):
        am.load_attack_mapping(broken)


def test_the_agent_stops_with_ex_config_on_a_broken_policy_and_is_not_restarted(tmp_path):
    broken = tmp_path / "broken.yaml"
    broken.write_text("action_mapping: [unclosed\n", encoding="utf-8")
    code = f"import runpy; runpy.run_path({str(ROOT / 'py' / 'azazel_edge_ai' / 'agent.py')!r}, run_name='not_main')"
    res = _run_py(code, tmp_path, AZAZEL_SOC_POLICY_PATH=str(broken),
                  AZAZEL_DECISION_LOG_DIR=str(tmp_path / "decisions"))
    assert res.returncode == 78, (res.returncode, res.stderr[-2000:])
    assert "configuration error, not starting" in res.stderr
    assert _unit("azazel-edge-ai-agent.service")["RestartPreventExitStatus"] == ["78"]


def test_the_installer_installs_the_two_config_files_root_owned_and_read_only():
    src = TOOLS.read_text(encoding="utf-8")
    assert "install -d -o root -g root -m 0755 /opt/azazel-edge/config\n" in src
    for name in ("soc_policy.yaml", "attack_mapping.yaml"):
        assert f'install -m 0644 -o root -g root "$REPO_ROOT/config/{name}" /opt/azazel-edge/config/{name}\n' in src
        assert f"config/{name}\n" in SYNC.read_text(encoding="utf-8")
    # The TI feeds and Sigma rules change the SOC scores: not installed here.
    assert "config/ti" not in src and "config/sigma" not in src


def test_the_installed_tree_root_is_where_the_modules_look():
    from azazel_edge import policy
    from azazel_edge.knowledge import attack_mapping as am
    from azazel_edge.evaluators import soc

    assert policy.INSTALL_ROOT == am.INSTALL_ROOT == ROOT
    # evaluators/soc.py reads config/ti and config/sigma from parents[3],
    # the same root (not the directory above it).
    assert Path(soc.__file__).resolve().parents[3] == ROOT


# ------------------------------------------------------------ sensors


@pytest.mark.parametrize("name,module", [
    ("azazel-edge-snmp-poller.service", "azazel_edge.sensors.snmp_poller"),
    ("azazel-edge-netflow-receiver.service", "azazel_edge.sensors.netflow_receiver"),
])
def test_the_sensor_units_use_only_what_systemd_expands(name, module, tmp_path):
    unit = _unit(name)
    exec_start = unit["ExecStart"][0]
    assert ":-" not in exec_start
    env = _env_of(unit)
    for var in re.findall(r"\$\{(\w+)\}", exec_start):
        assert var in env, (name, var)
    assert env["PYTHONPATH"] == f"{INSTALL_ROOT}/py"
    assert f"-m {module} " in exec_start
    assert unit["User"] == ["azazel-sensor"]
    # The module imports from the working directory systemd uses (/) with the
    # unit's PYTHONPATH (pointed at this checkout).
    res = subprocess.run([sys.executable, "-c", f"import {module}"], cwd="/",
                         env={"PATH": os.environ.get("PATH", ""),
                              "PYTHONPATH": env["PYTHONPATH"].replace(INSTALL_ROOT, str(ROOT))},
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr


# ------------------------------------------------------------ AI runtime


def test_the_ai_runtime_installs_compose_and_uses_the_wrapper():
    src = AI_RUNTIME.read_text(encoding="utf-8")
    apt = [l for l in src.splitlines() if "apt-get install" in l]
    assert any(" docker.io " in l and " docker-compose " in l for l in apt)
    assert not re.search(r"^\s*docker compose ", src, re.M)
    assert 'install -m 0755 "${REPO_ROOT}/bin/azazel-edge-compose" /usr/local/bin/azazel-edge-compose' in src
    assert src.count('"${COMPOSE}" -f docker-compose.') == 2


def _seed(tmp_path: Path, web_env: Path) -> subprocess.CompletedProcess:
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    (stubs / "chown").write_text("#!/bin/sh\nexit 0\n")
    (stubs / "chown").chmod(0o755)
    script = "set -euo pipefail\n" + _function(AI_RUNTIME, "seed_web_env_defaults") + f'seed_web_env_defaults "{web_env}"\n'
    return subprocess.run(["bash", "-c", script], env={"PATH": f"{stubs}:{os.environ.get('PATH', '')}"},
                          capture_output=True, text=True)


def test_the_mattermost_defaults_are_added_per_missing_key(tmp_path):
    web_env = tmp_path / "azazel-edge-web"
    # What install_migrated_tools.sh leaves (touch + two keys), plus one
    # Mattermost key the operator set.
    web_env.write_text("AZAZEL_WEB_TOKEN_FILE=/etc/azazel-edge/web_token.txt\nAZAZEL_AUTH_FAIL_OPEN=0\n"
                       "AZAZEL_MATTERMOST_HOST=10.9.9.9")
    web_env.chmod(0o644)
    res = _seed(tmp_path, web_env)
    assert res.returncode == 0, res.stderr
    lines = web_env.read_text().splitlines()
    assert lines[:3] == ["AZAZEL_WEB_TOKEN_FILE=/etc/azazel-edge/web_token.txt", "AZAZEL_AUTH_FAIL_OPEN=0",
                         "AZAZEL_MATTERMOST_HOST=10.9.9.9"]
    assert "AZAZEL_MATTERMOST_PORT=8065" in lines and "AZAZEL_RUNBOOK_ENABLE_CONTROLLED_EXEC=0" in lines
    assert sum(l.startswith("AZAZEL_MATTERMOST_HOST=") for l in lines) == 1
    assert (web_env.stat().st_mode & 0o777) == 0o600
    # Idempotent.
    before = web_env.read_text()
    assert _seed(tmp_path, web_env).returncode == 0
    assert web_env.read_text() == before


def test_the_mattermost_defaults_create_a_missing_file_0600(tmp_path):
    web_env = tmp_path / "azazel-edge-web"
    res = _seed(tmp_path, web_env)
    assert res.returncode == 0, res.stderr
    assert web_env.read_text().splitlines()[0] == "AZAZEL_MATTERMOST_HOST=172.16.0.254"
    assert (web_env.stat().st_mode & 0o777) == 0o600


# ------------------------------------------------------- review follow-ups


def test_install_all_checks_enable_rust_core_before_changing_anything():
    src = (INTERNAL / "install_all.sh").read_text(encoding="utf-8")
    m = re.search(r'^case "\$\{ENABLE_RUST_CORE\}" in\n.*?^esac\n', src, re.S | re.M)
    assert m
    assert m.start() < src.index("install_internal_network.sh\"\n")
    assert m.start() < src.index('if [[ "${ENABLE_APP_STACK}" == "1" && "${ENABLE_SECURITY_STACK:-1}"')
    for value, rc in (("1", 0), ("0", 0), ("yes", 1), ("", 1)):
        res = subprocess.run(["bash", "-c", f"ENABLE_RUST_CORE={value!r}\n" + m.group(0) + "echo ok\n"],
                             capture_output=True, text=True)
        assert res.returncode == rc, value
        if rc:
            assert "ENABLE_RUST_CORE must be 0 or 1" in res.stderr


def _with_pty_stdin(args: list[str]) -> subprocess.CompletedProcess:
    import pty

    master, slave = pty.openpty()
    try:
        # stdin is a terminal; stdout/stderr are pipes (like `2>&1 | tee`).
        return subprocess.run(args, stdin=slave, capture_output=True, text=True, timeout=30)
    finally:
        os.close(master)
        os.close(slave)


@pytest.mark.parametrize("script,env", [
    (INTERNAL / "install_all.sh", {"ENABLE_APP_STACK": "1"}),
    (TOOLS, {"ENABLE_SECURITY_STACK": "1"}),
    (SECURITY, {}),
])
def test_the_terminal_check_reads_stdin_only_so_output_can_be_logged(script, env):
    src = script.read_text(encoding="utf-8")
    m = re.search(_PREFLIGHT_RE, src, re.M)
    assert "[[ ! -t 0 ]]" in m.group(0) and "-t 1" not in m.group(0) and "-t 2" not in m.group(0)
    body = "".join(f"{k}={v}\n" for k, v in env.items()) + m.group(0) + "echo reached\n"
    res = _with_pty_stdin(["bash", "-c", body])
    assert res.returncode == 0 and "reached" in res.stdout, (script.name, res.stderr)


def test_require_tty_guards_luksformat_and_open_and_accepts_a_terminal_stdin():
    src = LUKS.read_text(encoding="utf-8")
    fn = _function(LUKS, "require_tty")
    assert "[[ ! -t 0 ]]" in fn and "-t 2" not in fn and "/dev/tty" in src  # the reason is in the comment
    for call, command in (('require_tty "luksFormat of ${IMG_PATH}"', "cryptsetup luksFormat"),
                          ('require_tty "opening ${IMG_PATH}"', "cryptsetup open")):
        pos = src.index(call)
        assert pos < src.index(command)
        block_start = src.rindex("\nif ", 0, pos)
        assert block_start < src.index(command) and not re.search(r"\nfi\n", src[block_start:pos])
    res = _with_pty_stdin(["bash", "-c", fn + 'require_tty "x"\necho reached\n'])
    assert res.returncode == 0 and "reached" in res.stdout
    res = subprocess.run(["bash", "-c", fn + 'require_tty "x"\necho reached\n'], stdin=subprocess.DEVNULL,
                         capture_output=True, text=True)
    assert res.returncode == 1 and "script -c" in res.stderr and "SKIP_LUKS=1" in res.stderr


def test_a_core_left_failed_is_reset_before_it_is_enabled_and_restarted():
    src = TOOLS.read_text(encoding="utf-8")
    reset = src.index("systemctl reset-failed azazel-edge-core.service")
    assert src.index("cargo build --release --locked") < reset
    assert reset < src.index("systemctl enable azazel-edge-core.service") < src.index("systemctl restart azazel-edge-core.service")


def _wait_active(tmp_path: Path, states: str, restarts: str, status: str) -> subprocess.CompletedProcess:
    """Run wait_active with a systemctl that answers from the given lists
    (one value per call, the last one repeated; counters in files, since
    wait_active calls it in command substitutions)."""
    d = tmp_path / f"wa{len(list(tmp_path.iterdir()))}"
    d.mkdir()
    stub = f'''
D={d}
STATES=({states}); RESTARTS=({restarts})
echo 0 >"$D/s"; echo 0 >"$D/r"
sleep() {{ echo "slept $1" >>"$D/sleeps"; }}
_next() {{ local -n arr=$1; local n; n=$(<"$D/$2"); echo $((n + 1)) >"$D/$2"
  (( n < ${{#arr[@]}} )) || n=$(( ${{#arr[@]}} - 1 )); echo "${{arr[$n]}}"; }}
systemctl() {{
  case "$1 $2" in
    "is-active --quiet") [[ "$(_next STATES s)" == active ]] ;;
    "is-active "*) echo "${{STATES[-1]}}"; [[ "${{STATES[-1]}}" == active ]] ;;
    "show -p") if [[ "$3" == NRestarts ]]; then _next RESTARTS r; else echo "{status}"; fi ;;
  esac
}}
'''
    script = stub + _function(TOOLS, "wait_active") + "wait_active demo.service\necho returned\n"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)


def test_the_installer_waits_for_each_service_to_stay_active(tmp_path):
    ok = _wait_active(tmp_path, "activating active active", "0 0", "0")
    assert ok.returncode == 0 and "returned" in ok.stdout
    # The stability window after the unit is active is 10 s.
    sleeps = sorted(tmp_path.glob("wa*/sleeps"))[-1].read_text().splitlines()
    assert sleeps[-1] == "slept 10"
    loop = _wait_active(tmp_path, "active active", "0 1", "1")
    assert loop.returncode == 1 and "did not stay active" in loop.stderr and "returned" not in loop.stdout
    never = _wait_active(tmp_path, "failed", "0", "1")
    assert never.returncode == 1 and "did not stay active" in never.stderr
    config = _wait_active(tmp_path, "failed", "0", "78")
    assert config.returncode == 1 and "SOC policy or ATT&CK mapping YAML" in config.stderr
    src = TOOLS.read_text(encoding="utf-8")
    last_restart = src.index("systemctl restart azazel-edge-core.service")
    for unit in ("control-daemon", "ai-agent", "web", "core"):
        assert last_restart < src.index(f"wait_active azazel-edge-{unit}.service"), unit
    guard = src.rindex('if [[ "$ENABLE_RUST_CORE" == "1" ]]; then', 0, src.index("wait_active azazel-edge-core.service"))
    assert guard > last_restart


def test_the_fstab_line_of_an_earlier_install_gets_the_device_timeout(tmp_path):
    src = LUKS.read_text(encoding="utf-8")
    block = re.search(r'^FSTAB_OPTIONS=.*?^fi\n', src, re.S | re.M).group(0)
    fstab = tmp_path / "fstab"
    script = _gnu_sed_shim() + "UUID=abcd-1\nMOUNT_POINT=/etc/azazel-edge/secrets\n" + block.replace("/etc/fstab", str(fstab))
    want = "UUID=abcd-1 /etc/azazel-edge/secrets ext4 defaults,nofail,x-systemd.device-timeout=30s 0 2\n"
    fstab.write_text("")
    subprocess.run(["bash", "-c", script], check=True)
    assert fstab.read_text() == want
    # A re-run finds the current line: no change, no notice.
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert fstab.read_text() == want and res.stderr == ""
    fstab.write_text("/dev/root / ext4 defaults 0 1\nUUID=abcd-1 /etc/azazel-edge/secrets ext4 defaults,nofail 0 2\n")
    subprocess.run(["bash", "-c", script], check=True)
    assert fstab.read_text() == "/dev/root / ext4 defaults 0 1\n" + want
    own = "UUID=abcd-1 /srv/secrets ext4 noatime,nofail 0 2\n"
    fstab.write_text(own)
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    assert fstab.read_text() == own and "not changed" in res.stderr


def test_the_mattermost_defaults_see_keys_in_every_form_systemd_reads(tmp_path):
    web_env = tmp_path / "azazel-edge-web"
    web_env.write_text("  AZAZEL_MATTERMOST_HOST=10.1.1.1\nAZAZEL_MATTERMOST_PORT = 9000\n"
                       "AZAZEL_MATTERMOST_TEAM =x\n")
    assert _seed(tmp_path, web_env).returncode == 0
    text = web_env.read_text()
    for key in ("AZAZEL_MATTERMOST_HOST", "AZAZEL_MATTERMOST_PORT", "AZAZEL_MATTERMOST_TEAM"):
        assert len(re.findall(rf"^\s*{key}\s*=", text, re.M)) == 1, key
    assert "AZAZEL_MATTERMOST_CHANNEL=soc-noc" in text


def test_an_export_line_does_not_count_as_set(tmp_path):
    # systemd 257 ignores `export KEY=value` in an EnvironmentFile ("Ignoring
    # invalid environment assignment"; checked in a Debian 13 systemd
    # container), so the key is still unset for the unit: the default is
    # added and the operator's line is left as it is.
    web_env = tmp_path / "azazel-edge-web"
    web_env.write_text("export AZAZEL_MATTERMOST_PORT=9000\n")
    assert _seed(tmp_path, web_env).returncode == 0
    lines = web_env.read_text().splitlines()
    assert lines[0] == "export AZAZEL_MATTERMOST_PORT=9000" and "AZAZEL_MATTERMOST_PORT=8065" in lines


@pytest.mark.skipif(Path(INSTALL_ROOT).exists(), reason="a real /opt/azazel-edge exists here")
def test_a_symlinked_launcher_does_not_run_the_checkout_it_points_at(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name in ("azazel-edge-dummy-eve", "azazel-edge-scenario-replay"):
        (bindir / name).symlink_to(ROOT / "bin" / name)
        res = subprocess.run([str(bindir / name), "list"], capture_output=True, text=True, timeout=60,
                             env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
        # The link's own directory has no code next to it, and the checkout
        # it points at is not used: the installed tree is (absent here).
        assert res.returncode != 0, name
        assert f"or in {INSTALL_ROOT}" in res.stderr, (name, res.stderr)


def test_the_path_schema_launcher_resolves_its_root_like_the_others(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    # From a checkout, from another directory: the checkout's code.
    res = subprocess.run([sys.executable, str(ROOT / "bin" / "azazel-edge-path-schema"), "status"],
                         capture_output=True, text=True, cwd=tmp_path, env=env, timeout=60)
    assert res.returncode == 0 and '"active_schema"' in res.stdout, res.stderr
    src = (ROOT / "bin" / "azazel-edge-path-schema").read_text(encoding="utf-8")
    assert ".resolve()" not in src and src.count("sys.path.insert") == 1


@pytest.mark.skipif(Path(INSTALL_ROOT).exists(), reason="a real /opt/azazel-edge exists here")
def test_a_symlinked_path_schema_launcher_does_not_run_the_checkout(tmp_path):
    link = tmp_path / "azazel-edge-path-schema"
    link.symlink_to(ROOT / "bin" / "azazel-edge-path-schema")
    res = subprocess.run([sys.executable, str(link), "status"], capture_output=True, text=True, timeout=60,
                         env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
    assert res.returncode != 0 and f"or in {INSTALL_ROOT}" in res.stderr, res.stderr
