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


def test_the_encrypted_storage_runs_only_when_asked_for_and_a_failure_stops():
    src = SECURITY.read_text(encoding="utf-8")
    assert 'ENABLE_ENCRYPTED_STORAGE="${ENABLE_ENCRYPTED_STORAGE:-0}"' in src
    call = src.index('"${ASSET_ROOT}/installer/internal/install_encrypted_storage.sh"')
    guard = src.rindex('if [[ "${ENABLE_ENCRYPTED_STORAGE}" == "1" && "${SKIP_LUKS}" != "1" ]]; then', 0, call)
    assert guard < call
    line = src[call:src.index("\n", call)]
    assert "|| true" not in line


def test_the_encrypted_storage_stops_without_a_terminal():
    script = _function(LUKS, "require_tty") + 'require_tty "test step"\necho reached\n'
    res = subprocess.run(["bash", "-c", script], stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert res.returncode == 1 and "reached" not in res.stdout
    assert "needs a passphrase typed on a terminal" in res.stderr
    src = LUKS.read_text(encoding="utf-8")
    first_tty = src.index('require_tty "setting up the encrypted volume"')
    assert first_tty < src.index("dd if=/dev/zero") < src.index("cryptsetup luksFormat")
    assert "set -x" not in src


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
    script = head + block.replace("/etc/crypttab", str(crypttab))
    want = f"azazel-secrets /var/lib/azazel-secrets.img none {','.join(opts)}\n"
    # New line.
    subprocess.run(["bash", "-c", script], check=True)
    assert crypttab.read_text() == want
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
