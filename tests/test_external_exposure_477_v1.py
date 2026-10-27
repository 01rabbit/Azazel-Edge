"""Edge#477: external exposure found by the audit before the device run.

- ntfy listens on loopback only, anonymous clients get nothing (deny-all),
  and the anonymous read-write grants of earlier installs are removed.
- Mattermost publishes on loopback only; LAN clients go through an nginx
  site that admits the LAN and loopback only.
- No fixed Mattermost database or admin password in the code: both are
  random per device and kept in 0600 files.
- The Mattermost image is a fixed release, not `latest`.

All secrets here are fakes made by the tests. A container run of these
checks is not evidence from the device.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
INTERNAL = ROOT / "installer" / "internal"
NTFY = INTERNAL / "install_ntfy.sh"
COMPOSE = ROOT / "security" / "docker-compose.mattermost.yml"
DB_SECRET = INTERNAL / "mattermost_db_secret.sh"
PROVISION = INTERNAL / "provision_mattermost_workspace.sh"
COMMAND = INTERNAL / "provision_mattermost_command.sh"
AI_RUNTIME = INTERNAL / "install_ai_runtime.sh"
NETWORK = INTERNAL / "install_internal_network.sh"
DEVSTACK = ROOT / "bin" / "azazel-edge-devstack"
MACDEV = ROOT / "tools" / "macdev" / "provision-mattermost.sh"

HEX48 = re.compile(r"^[0-9a-f]{48}$")


def _function(path: Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def _gnu_mv() -> bool:
    return subprocess.run(["mv", "--version"], capture_output=True).returncode == 0


needs_gnu_mv = pytest.mark.skipif(not _gnu_mv(), reason="mv -T is GNU coreutils (Debian); run in Linux")


def _gnu_mktemp() -> bool:
    return subprocess.run(["mktemp", "--version"], capture_output=True).returncode == 0


# macOS mktemp -d ignores TMPDIR, so the scratch directory cannot be checked
# for being removed from it; the scripts run on Debian (GNU coreutils).
needs_gnu_mktemp = pytest.mark.skipif(
    not _gnu_mktemp(), reason="mktemp -d honouring TMPDIR is GNU coreutils (Debian); run in Linux")


def _tracked_text_files():
    skip = {".git", ".venv", "target", "node_modules", "__pycache__", ".pytest_cache"}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                yield str(path.relative_to(ROOT)), path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue


# --------------------------------------------------------------------- ntfy


def _ntfy_server_yml(port: str = "8081") -> dict:
    """Render the server.yml heredoc of install_ntfy.sh as bash would."""
    src = NTFY.read_text(encoding="utf-8")
    m = re.search(r'^cat > "\$SERVER_CFG" <<EOF\n(.*?)^EOF\n', src, re.S | re.M)
    assert m, "server.yml heredoc"
    listen = re.search(r'^NTFY_LISTEN_ADDR="([^"]*)"$', src, re.M)
    assert listen, "NTFY_LISTEN_ADDR"
    script = f'NTFY_LISTEN_ADDR="{listen.group(1)}"\nNTFY_PORT="$1"\ncat <<EOF\n{m.group(1)}EOF\n'
    out = subprocess.run(["bash", "-c", script, "bash", port], capture_output=True, text=True, check=True)
    return yaml.safe_load(out.stdout)


def test_ntfy_listens_on_loopback_only():
    cfg = _ntfy_server_yml()
    assert cfg["listen-http"] == "127.0.0.1:8081"
    assert cfg["base-url"] == "http://127.0.0.1:8081"
    # The address is fixed in the script, not taken from the environment.
    src = NTFY.read_text(encoding="utf-8")
    assert re.search(r'^NTFY_LISTEN_ADDR="127\.0\.0\.1"$', src, re.M)
    assert "MGMT_IP" not in src


def test_ntfy_denies_anonymous_access_by_default():
    cfg = _ntfy_server_yml()
    assert cfg["auth-default-access"] == "deny-all"
    assert cfg["auth-file"] == "/var/lib/ntfy/user.db"
    assert cfg["web-root"] == "disable"


def test_ntfy_grants_nothing_to_everyone_and_removes_old_grants():
    src = NTFY.read_text(encoding="utf-8")
    grants = re.findall(r"^\s*ntfy access (\S+) .*$", src, re.M)
    assert grants, "no ntfy access lines"
    for line in re.findall(r"^\s*ntfy access .*$", src, re.M):
        if re.search(r"\b(everyone|\*)\b", line):
            # Only resets or reads of the anonymous entries, never a grant.
            assert "--reset" in line or re.search(r"ntfy access everyone 2>", line), line
    assert 'ntfy access --reset everyone "$TOPIC_ALERT"' in src
    assert 'ntfy access --reset everyone "$TOPIC_INFO"' in src
    # The Edge account's grants must not be ignored when they fail.
    assert re.search(r'^ntfy access "\$NTFY_USER" "\$TOPIC_ALERT" read-write >/dev/null$', src, re.M)
    assert re.search(r'^ntfy access "\$NTFY_USER" "\$TOPIC_INFO" read-write >/dev/null$', src, re.M)


def test_ntfy_install_checks_anonymous_refusal_and_token_without_argv():
    src = NTFY.read_text(encoding="utf-8")
    assert 'anon_status' in src and '"401"' in src and '"403"' in src
    # The token reaches curl on stdin (-H @-), never as an argument.
    assert "-H @-" in src
    assert not re.search(r'-H "Authorization: Bearer \$\{?token', src)
    # The token is never echoed.
    for line in re.findall(r"^\s*echo .*$", src, re.M):
        assert "$token" not in line and "${token}" not in line, line


def test_web_ui_ntfy_health_tries_loopback_first(monkeypatch):
    import azazel_edge_web.app as webapp

    tried = []

    def fake_urlopen(url, timeout=0):
        tried.append(url)
        raise OSError("refused")

    monkeypatch.setattr(webapp, "urlopen", fake_urlopen)
    monkeypatch.setenv("MGMT_IP", "10.0.0.9")
    assert webapp._ntfy_health_ok() is False
    assert tried[0] == "http://127.0.0.1:8081/v1/health"
    assert tried[-1] == "http://10.0.0.9:8081/v1/health"


def test_cli_ntfy_health_tries_loopback_first(monkeypatch):
    from azazel_edge import cli_unified

    tried = []

    class Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b'{"healthy":true}'

    def fake_urlopen(url, timeout=0):
        tried.append(url)
        if "127.0.0.1" in url:
            return Resp()
        raise OSError("refused")

    monkeypatch.setattr(cli_unified, "urlopen", fake_urlopen)
    monkeypatch.setenv("MGMT_IP", "10.0.0.9")
    assert cli_unified._ntfy_health_ok() is True
    assert tried == ["http://127.0.0.1:8081/v1/health"]


def test_web_ui_ntfy_bridge_sends_the_token(monkeypatch):
    import threading

    import azazel_edge_web.app as webapp

    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["auth"] = req.get_header("Authorization")
        raise OSError("stop here")

    monkeypatch.setattr(webapp, "urlopen", fake_urlopen)
    with pytest.raises(OSError):
        next(webapp._iter_ntfy_sse_events("http://127.0.0.1:8081/t/sse", "tk_fake", threading.Event()))
    assert seen["auth"] == "Bearer tk_fake"


# --------------------------------------------------------------- Mattermost


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def test_mattermost_publishes_on_loopback_only():
    services = _compose()["services"]
    assert services["mattermost"]["ports"] == ["127.0.0.1:18065:8065"]
    assert "ports" not in services["mattermost-db"]
    for name, svc in services.items():
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), (name, port)


def test_mattermost_compose_holds_no_password():
    services = _compose()["services"]
    env_file = "${AZAZEL_MATTERMOST_DB_ENV_FILE:-/etc/azazel-edge/mattermost-db.env}"
    for name in ("mattermost-db", "mattermost"):
        env = services[name].get("environment", {})
        assert "POSTGRES_PASSWORD" not in env, name
        assert "MM_SQLSETTINGS_DATASOURCE" not in env, name
        assert services[name]["env_file"] == [env_file], name
    text = COMPOSE.read_text(encoding="utf-8")
    assert not re.search(r"postgres://[^@\s]*:[^@\s]*@", text)


def test_mattermost_image_is_pinned():
    image = _compose()["services"]["mattermost"]["image"]
    assert image == "mattermost/mattermost-team-edition:12.0.1"
    assert not image.endswith(":latest")
    # amd64 only upstream; the compose file says so and keeps the platform.
    assert _compose()["services"]["mattermost"]["platform"] == "linux/amd64"
    assert "16K" in COMPOSE.read_text(encoding="utf-8")


def test_no_fixed_mattermost_password_left_in_the_repository():
    former_admin = "7030024adfd5d729d1d9540d3a49fd1bc699f5de35dbe8f6841b5cbaba5fcd2e"
    former_db = "mm-password-" + "change"  # split so this file does not match itself
    bad = []
    for rel, text in _tracked_text_files():
        if former_db in text:
            bad.append(rel)
        for word in set(re.findall(r"[A-Za-z][A-Za-z0-9]{5,}!\d{4}", text)):
            if hashlib.sha256(word.encode()).hexdigest() == former_admin:
                bad.append(rel)
    assert bad == []


def test_ai_runtime_makes_the_db_secret_before_starting_the_stack():
    src = AI_RUNTIME.read_text(encoding="utf-8")
    secret = src.index("mattermost_db_secret.sh")
    up = src.index("docker-compose.mattermost.yml up -d")
    assert secret < up
    assert '"${REPO_ROOT}/installer/internal/mattermost_db_secret.sh" /etc/azazel-edge/mattermost-db.env' in src


def test_installer_clients_use_the_loopback_port():
    assert 'MATTERMOST_API_URL="${AZAZEL_MATTERMOST_API_URL:-http://127.0.0.1:18065}"' in PROVISION.read_text(encoding="utf-8")
    assert 'MATTERMOST_URL_DEFAULT="${AZAZEL_MATTERMOST_URL:-http://127.0.0.1:18065}"' in COMMAND.read_text(encoding="utf-8")
    dev = DEVSTACK.read_text(encoding="utf-8")
    assert 'MM_URL="http://localhost:18065"' in dev
    assert "mattermost_db_secret.sh" in dev
    assert 'API_URL="${AZAZEL_MATTERMOST_API_URL:-http://127.0.0.1:18065}"' in MACDEV.read_text(encoding="utf-8")


# ----------------------------------------------------- mattermost_db_secret.sh


def _fake_docker(tmp_path: Path, mode: str) -> Path:
    """A `docker` stub. mode: 'absent' (daemon down), 'running' (a container
    of an earlier install), 'psql_fails'. It logs argv and psql's stdin."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker.argv"
    stdin_log = tmp_path / "psql.stdin"
    script = f"""#!/bin/bash
printf '%s\\n' "$*" >> {log}
mode={mode}
case "$1" in
  info) [[ $mode == absent ]] && exit 1; exit 0 ;;
  container)
    [[ "$2" == inspect ]] || exit 1
    if [[ "$3" == -f ]]; then echo true; fi
    exit 0 ;;
  exec)
    if [[ "$2" == -i ]]; then
      cat > {stdin_log}
      [[ $mode == psql_fails ]] && exit 2
      exit 0
    fi
    exit 0 ;;
  *) exit 0 ;;
esac
"""
    stub = bindir / "docker"
    stub.write_text(script, encoding="utf-8")
    stub.chmod(0o755)
    return bindir


def _run_secret(tmp_path: Path, env_file: Path, mode: str) -> subprocess.CompletedProcess:
    bindir = _fake_docker(tmp_path, mode)
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    return subprocess.run(["bash", str(DB_SECRET), str(env_file)], capture_output=True, text=True, env=env)


def _password(env_file: Path) -> str:
    m = re.search(r"^POSTGRES_PASSWORD=(.*)$", env_file.read_text(encoding="utf-8"), re.M)
    assert m
    return m.group(1)


def test_db_secret_new_file_is_random_0600_and_not_printed(tmp_path):
    env_file = tmp_path / "etc" / "mattermost-db.env"
    res = _run_secret(tmp_path, env_file, "absent")
    assert res.returncode == 0, res.stderr
    pw = _password(env_file)
    assert HEX48.match(pw)
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(env_file.parent.stat().st_mode) == 0o750
    assert (
        f"MM_SQLSETTINGS_DATASOURCE=postgres://mmuser:{pw}@mattermost-db:5432/mattermost"
        "?sslmode=disable&connect_timeout=10"
    ) in env_file.read_text(encoding="utf-8")
    assert pw not in res.stdout + res.stderr
    assert [p.name for p in env_file.parent.iterdir()] == [env_file.name]
    if os.geteuid() == 0:
        assert env_file.stat().st_uid == 0 and env_file.stat().st_gid == 0

    other = tmp_path / "other"
    other.mkdir()
    env2 = other / "mattermost-db.env"
    assert _run_secret(other, env2, "absent").returncode == 0
    assert _password(env2) != pw


def test_db_secret_keeps_an_existing_file_and_narrows_its_mode(tmp_path):
    env_file = tmp_path / "mattermost-db.env"
    content = "POSTGRES_PASSWORD=keepme\nMM_SQLSETTINGS_DATASOURCE=postgres://mmuser:keepme@x/y\n"
    env_file.write_text(content, encoding="utf-8")
    env_file.chmod(0o644)
    res = _run_secret(tmp_path, env_file, "running")
    assert res.returncode == 0, res.stderr
    assert env_file.read_text(encoding="utf-8") == content
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    # The database is left alone.
    assert not (tmp_path / "psql.stdin").exists()


def test_db_secret_refuses_an_incomplete_file_and_a_symlink(tmp_path):
    env_file = tmp_path / "mattermost-db.env"
    env_file.write_text("POSTGRES_PASSWORD=x\n", encoding="utf-8")
    res = _run_secret(tmp_path, env_file, "absent")
    assert res.returncode != 0
    assert env_file.read_text(encoding="utf-8") == "POSTGRES_PASSWORD=x\n"

    link_dir = tmp_path / "l"
    link_dir.mkdir()
    target = link_dir / "victim"
    target.write_text("victim\n", encoding="utf-8")
    link = link_dir / "mattermost-db.env"
    link.symlink_to(target)
    res = _run_secret(link_dir, link, "absent")
    assert res.returncode != 0
    assert target.read_text(encoding="utf-8") == "victim\n"


def test_db_secret_changes_an_existing_database_password_via_stdin(tmp_path):
    env_file = tmp_path / "mattermost-db.env"
    res = _run_secret(tmp_path, env_file, "running")
    assert res.returncode == 0, res.stderr
    pw = _password(env_file)
    sql = (tmp_path / "psql.stdin").read_text(encoding="utf-8")
    assert sql == f"ALTER USER mmuser WITH PASSWORD '{pw}';\n"
    argv = (tmp_path / "docker.argv").read_text(encoding="utf-8")
    assert pw not in argv
    assert "exec -i azazel-edge-mm-db psql -v ON_ERROR_STOP=1 -q -U mmuser -d mattermost" in argv


def test_db_secret_writes_nothing_when_the_password_change_fails(tmp_path):
    env_file = tmp_path / "mattermost-db.env"
    res = _run_secret(tmp_path, env_file, "psql_fails")
    assert res.returncode != 0
    assert not env_file.exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".")] == []


# ------------------------------------------- provision_mattermost_workspace.sh


def _admin_password_script(cred_env: Path, *, env_password: str = "") -> str:
    funcs = "".join(
        _function(PROVISION, name)
        for name in ("write_private_file", "write_credentials", "stored_admin_password", "resolve_admin_password")
    )
    return (
        "set -euo pipefail\numask 022\n"
        f"CRED_ENV='{cred_env}'\n"
        "MATTERMOST_USERNAME=u MATTERMOST_EMAIL=e@example.local PUBLIC_BASE_URL=http://x:8065\n"
        "MATTERMOST_TEAM=t MATTERMOST_CHANNEL=c\n"
        f"AZAZEL_MATTERMOST_PASSWORD='{env_password}'\n"
        + funcs
        + 'resolve_admin_password\nprintf "%s" "$MATTERMOST_PASSWORD" > "$CRED_ENV.out"\n'
    )


def _cred_password(path: Path) -> str:
    m = re.search(r"^MATTERMOST_PASSWORD=(.*)$", path.read_text(encoding="utf-8"), re.M)
    assert m
    return m.group(1)


@needs_gnu_mv
def test_admin_password_is_random_kept_0600_and_not_printed(tmp_path):
    cred = tmp_path / "mattermost-credentials.env"
    res = subprocess.run(["bash", "-c", _admin_password_script(cred)], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    used = (tmp_path / "mattermost-credentials.env.out").read_text(encoding="utf-8")
    assert re.fullmatch(r"[0-9a-f]{48}-Az", used)
    assert _cred_password(cred) == used
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600
    assert used not in res.stdout + res.stderr
    assert str(cred) in res.stdout  # the location is shown instead

    # A second run reuses the kept password instead of making a new one.
    res2 = subprocess.run(["bash", "-c", _admin_password_script(cred)], capture_output=True, text=True)
    assert res2.returncode == 0, res2.stderr
    assert (tmp_path / "mattermost-credentials.env.out").read_text(encoding="utf-8") == used


@needs_gnu_mv
def test_admin_password_from_the_environment_wins(tmp_path):
    cred = tmp_path / "mattermost-credentials.env"
    cred.write_text("MATTERMOST_PASSWORD=stored-fake\n", encoding="utf-8")
    script = _admin_password_script(cred, env_password="env-fake-1")
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert (tmp_path / "mattermost-credentials.env.out").read_text(encoding="utf-8") == "env-fake-1"


def test_former_default_admin_password_is_detected_by_hash_only():
    src = PROVISION.read_text(encoding="utf-8")
    m = re.search(r'^FORMER_DEFAULT_PASSWORD_SHA256="([0-9a-f]{64})"$', src, re.M)
    assert m
    func = _function(PROVISION, "is_former_default_password")
    fake_hash = hashlib.sha256(b"fake-old-default").hexdigest()

    def check(candidate: str) -> bool:
        script = f'FORMER_DEFAULT_PASSWORD_SHA256="{fake_hash}"\n{func}is_former_default_password "$1"\n'
        return subprocess.run(["bash", "-c", script, "bash", candidate]).returncode == 0

    assert check("fake-old-default")
    assert not check("something-else")
    # The message names the file, never the password.
    warn = re.search(r'echo "\[ACTION REQUIRED\] The Mattermost admin account.*?>&2', src, re.S)
    assert warn and "MATTERMOST_PASSWORD}" not in warn.group(0)


def test_api_bodies_go_on_stdin_and_are_json_escaped():
    src = PROVISION.read_text(encoding="utf-8")
    api = _function(PROVISION, "api_call")
    assert "--data-binary @-" in api
    assert '--data "${body}"' not in api
    assert '\\"password\\"' not in src  # no hand-built JSON with the password
    func = _function(PROVISION, "json_object")
    script = func + 'JSON_login_id=a@b JSON_password="$1" json_object login_id password\n'
    tricky = 'p"w\\x{}'
    out = subprocess.run(["bash", "-c", script, "bash", tricky], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == {"login_id": "a@b", "password": tricky}


def _lan_proxy_block() -> str:
    src = PROVISION.read_text(encoding="utf-8")
    start = src.index("# Print the nginx site that puts")
    end = src.index("\n# Files below are private")
    return src[start:end] + "\n" + _function(PROVISION, "print_rerun_hint")


def test_lan_proxy_site_admits_lan_and_loopback_only():
    src = PROVISION.read_text(encoding="utf-8")
    cidr = re.search(r'^MATTERMOST_LAN_CIDR="([^"]+)"$', src, re.M).group(1)
    net_cidr = re.search(r'^LAN_CIDR="([^"]+)"$', NETWORK.read_text(encoding="utf-8"), re.M).group(1)
    assert cidr == net_cidr
    script = (
        f'MATTERMOST_PORT_PUBLIC=8065\nMATTERMOST_LAN_CIDR="{cidr}"\n'
        + _lan_proxy_block()
        + "\nrender_lan_proxy_site 127.0.0.1:18065\n"
    )
    site = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    assert "listen 8065;" in site
    rules = re.findall(r"^\s*(allow|deny) ([^;]+);", site, re.M)
    assert rules == [("allow", "127.0.0.1"), ("allow", "172.16.0.0/24"), ("deny", "all")]
    assert "proxy_pass http://127.0.0.1:18065;" in site
    assert "proxy_set_header Upgrade $http_upgrade;" in site
    assert "map $http_upgrade $azazel_mm_connection_upgrade" in site


def _run_lan_proxy(tmp_path: Path, ss_out: str, nginx_rc: int = 0, filler_lines: int = 0) -> subprocess.CompletedProcess:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    filler = (f"\nfor ((i=0;i<{filler_lines};i++)); do echo 'LISTEN 0 4096 0.0.0.0:8065 0.0.0.0:* "
              f"users:((\"docker-proxy\",pid=7,fd=4))'; done\n") if filler_lines else ""
    (bindir / "ss").write_text(f"#!/bin/bash\nprintf '%s\\n' '{ss_out}'{filler}\n", encoding="utf-8")
    (bindir / "nginx").write_text(f"#!/bin/bash\nexit {nginx_rc}\n", encoding="utf-8")
    (bindir / "systemctl").write_text(f"#!/bin/bash\necho \"$*\" >> {tmp_path}/systemctl.log\n", encoding="utf-8")
    for f in bindir.iterdir():
        f.chmod(0o755)
    avail = tmp_path / "sites-available"
    enabled = tmp_path / "sites-enabled"
    avail.mkdir()
    enabled.mkdir()
    script = (
        "set -euo pipefail\n"
        "MATTERMOST_API_URL=http://127.0.0.1:18065\nMATTERMOST_PORT_PUBLIC=8065\n"
        'MATTERMOST_LAN_CIDR="172.16.0.0/24"\n'
        f"NGINX_MM_SITE={avail}/azazel-edge-mattermost.conf\nNGINX_MM_LINK={enabled}/azazel-edge-mattermost.conf\n"
        + _lan_proxy_block()
        + "\nensure_lan_proxy\n"
    )
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def test_lan_proxy_is_enabled_and_nginx_reloaded(tmp_path):
    res = _run_lan_proxy(tmp_path, "")
    assert res.returncode == 0, res.stderr
    link = tmp_path / "sites-enabled" / "azazel-edge-mattermost.conf"
    assert link.is_symlink()
    site = tmp_path / "sites-available" / "azazel-edge-mattermost.conf"
    assert stat.S_IMODE(site.stat().st_mode) == 0o644
    assert "reload nginx.service" in (tmp_path / "systemctl.log").read_text(encoding="utf-8")


def test_lan_proxy_fails_while_an_old_container_holds_the_port(tmp_path):
    held = 'LISTEN 0 4096 0.0.0.0:8065 0.0.0.0:* users:(("docker-proxy",pid=7,fd=4))'
    res = _run_lan_proxy(tmp_path, held)
    assert res.returncode != 0
    assert "[ERROR] Port 8065 is held" in res.stderr
    assert "installer/internal/install_ai_runtime.sh" in res.stderr
    assert not (tmp_path / "sites-enabled" / "azazel-edge-mattermost.conf").exists()

    # nginx itself on the port is not "held" (a re-run).
    tmp2 = tmp_path / "again"
    tmp2.mkdir()
    own = 'LISTEN 0 511 0.0.0.0:8065 0.0.0.0:* users:(("nginx",pid=9,fd=6))'
    assert _run_lan_proxy(tmp2, own).returncode == 0
    assert (tmp2 / "sites-enabled" / "azazel-edge-mattermost.conf").is_symlink()


def test_lan_proxy_sees_a_held_port_in_a_long_listing_under_pipefail(tmp_path):
    held = 'LISTEN 0 4096 0.0.0.0:8065 0.0.0.0:* users:(("docker-proxy",pid=7,fd=4))'
    res = _run_lan_proxy(tmp_path, held, filler_lines=20000)
    assert res.returncode != 0
    assert "[ERROR] Port 8065 is held" in res.stderr
    assert not (tmp_path / "sites-enabled" / "azazel-edge-mattermost.conf").exists()


def test_lan_proxy_rejected_by_nginx_is_left_disabled(tmp_path):
    res = _run_lan_proxy(tmp_path, "", nginx_rc=1)
    assert res.returncode != 0
    assert not (tmp_path / "sites-enabled" / "azazel-edge-mattermost.conf").exists()
    assert not (tmp_path / "systemctl.log").exists()


# ------------------------------------------- install_ntfy.sh, run with stubs
#
# The script runs as written except that its absolute /etc and /var paths
# are moved under tmp_path and the root check is skipped; apt-get,
# systemctl, ntfy, curl, chown and getent are stubs that log what they get.

NEW_TOKEN = "tk_fakenewtoken0123456789abcd"
OLD_TOKEN = "tk_fakeoldtoken0123456789abcd"


def _run_install_ntfy(tmp_path: Path, *, mode: str = "", web_group: bool = True, old_token: bool = False):
    root = tmp_path / "root"
    for d in ("etc/ntfy", "var/lib/ntfy"):
        (root / d).mkdir(parents=True)
    (root / "var/lib/ntfy/user.db").write_text("", encoding="utf-8")
    if old_token:
        (root / "etc/azazel-edge").mkdir(mode=0o750)
        (root / "etc/azazel-edge/ntfy.token").write_text(OLD_TOKEN + "\n", encoding="utf-8")
    log = tmp_path / "calls.log"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stubs = {
        "apt-get": "exit 0",
        "systemctl": f'echo "systemctl $*" >> {log}',
        "chown": f'echo "chown $*" >> {log}',
        "getent": "exit 0" if web_group else "exit 2",
        "ntfy": f"""echo "ntfy $*" >> {log}
mode='{mode}'
case "$1 $2" in
  "access everyone")
    [[ $mode == acl_list_fails ]] && exit 1
    if [[ $mode == anon_left ]]; then echo "- read-write access to topic azg-alert-critical"
    else echo "- no access to any (other) topics (server config)"; fi ;;
  "access azazel-notify") [[ $mode == grant_fails ]] && exit 1 ;;
  "token add") echo "token {NEW_TOKEN} created for user azazel-notify, never expires" ;;
esac
exit 0""",
        "curl": f"""echo "curl $*" >> {log}
mode='{mode}'
args="$*"
if [[ $args == *"/v1/health"* ]]; then
  [[ $mode == unhealthy ]] && exit 7
  echo '{{"healthy":true}}'
  # A long reply: a reader that stops early must not turn this into a failure.
  # (exec: a reader that closes early kills it with SIGPIPE, like curl)
  [[ $mode == big_health ]] && exec awk 'BEGIN {{ for (i = 0; i < 200000; i++) print "xxxxxxxxxxxxxxxx" }}'
  exit 0
fi
if [[ $args == *"-H @-"* ]]; then
  hdr="$(cat)"
  echo "stdin $hdr" >> {log}.stdin
  if [[ $hdr == "Authorization: Bearer {NEW_TOKEN}" && $mode != auth_401 ]]; then printf 200; else printf 401; fi
  exit 0
fi
if [[ $mode == anon_200 ]]; then printf 200; else printf 403; fi""",
    }
    for name, body in stubs.items():
        f = bindir / name
        f.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
        f.chmod(0o755)
    src = NTFY.read_text(encoding="utf-8")
    src = src.replace('if [[ "${EUID}" -ne 0 ]]; then', "if false; then", 1)
    src = src.replace("/etc/", f"{root}/etc/").replace("/var/", f"{root}/var/")
    script = tmp_path / "install_ntfy.sh"
    script.write_text(src, encoding="utf-8")
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    res = subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)
    calls = log.read_text(encoding="utf-8") if log.exists() else ""
    return res, root, calls


def test_ntfy_install_succeeds_with_a_private_token(tmp_path):
    res, root, calls = _run_install_ntfy(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    for rel in ("etc/azazel-edge/ntfy.token", "etc/azazel/ntfy.token"):
        tok = root / rel
        assert tok.read_text(encoding="utf-8") == NEW_TOKEN + "\n"
        assert stat.S_IMODE(tok.stat().st_mode) == 0o640
        assert f"chown root:azazel-web {tok}" in calls
    # The token is never in the output and never on a command line.
    assert NEW_TOKEN not in res.stdout + res.stderr
    assert NEW_TOKEN not in calls
    assert f"Authorization: Bearer {NEW_TOKEN}" in (tmp_path / "calls.log.stdin").read_text(encoding="utf-8")
    assert "ntfy access --reset everyone azg-alert-critical" in calls
    assert "ntfy access --reset everyone azg-info-status" in calls
    assert re.search(r"^ntfy access everyone \S+ (rw|read|write|read-write)", calls, re.M) is None
    # The root-run ntfy CLI left the auth database to root; it is handed back
    # to _ntfy after the last CLI call and before the restart.
    lines = calls.splitlines()
    chown = lines.index(f"chown -R _ntfy:_ntfy {root}/var/lib/ntfy")
    assert chown > max(i for i, l in enumerate(lines) if l.startswith("ntfy "))
    assert "systemctl restart ntfy.service" in lines[chown + 1:]


def test_ntfy_health_check_reads_a_long_reply_under_pipefail(tmp_path):
    res, _root, _calls = _run_install_ntfy(tmp_path, mode="big_health")
    assert res.returncode == 0, res.stdout + res.stderr
    assert "Service healthy" in res.stdout


def test_no_pipe_into_an_early_reader_in_the_exposure_scripts():
    # Under pipefail, `cmd | grep -q`, `cmd | head` or an awk that exits early
    # fail when the reader stops first (the writer gets SIGPIPE).
    # (tools/macdev/provision-mattermost.sh: its grep -q is fixed by #486.)
    for path in (NTFY, PROVISION, COMMAND, DB_SECRET):
        for line in path.read_text(encoding="utf-8").splitlines():
            code = line.split("#", 1)[0]
            assert not re.search(r"\|\s*grep\b[^|]*\s-\w*q", code), (path.name, line)
            assert not re.search(r"\|\s*head\b", code), (path.name, line)
            assert not re.search(r"\|\s*awk\b.*\bexit\b", code), (path.name, line)


def test_stored_admin_password_takes_the_first_line_of_a_long_file(tmp_path):
    cred = tmp_path / "cred.env"
    cred.write_text("MATTERMOST_PASSWORD=first-fake\n" + "MATTERMOST_PASSWORD=later\n" * 50000, encoding="utf-8")
    script = "set -euo pipefail\n" + _function(PROVISION, "stored_admin_password") + \
        f"CRED_ENV='{cred}'\nv=\"$(stored_admin_password)\"\nprintf '%s' \"$v\"\n"
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert res.stdout == "first-fake"


def test_ntfy_token_is_0600_root_without_the_web_group(tmp_path):
    res, root, calls = _run_install_ntfy(tmp_path, web_group=False)
    assert res.returncode == 0, res.stdout + res.stderr
    for rel in ("etc/azazel-edge/ntfy.token", "etc/azazel/ntfy.token"):
        tok = root / rel
        assert stat.S_IMODE(tok.stat().st_mode) == 0o600
        assert f"chown root:root {tok}" in calls


def test_ntfy_install_revokes_the_previous_token(tmp_path):
    res, _root, calls = _run_install_ntfy(tmp_path, old_token=True)
    assert res.returncode == 0, res.stdout + res.stderr
    assert f"ntfy token remove azazel-notify {OLD_TOKEN}" in calls
    assert OLD_TOKEN not in res.stdout + res.stderr


@pytest.mark.parametrize(
    "mode, why",
    [
        ("anon_left", "anonymous grant left in the auth database"),
        ("anon_200", "anonymous read answered 200"),
        ("auth_401", "the Edge token refused"),
        ("grant_fails", "the Edge account grant failed"),
        ("acl_list_fails", "the anonymous ACL could not be listed"),
        ("unhealthy", "the health check never passed"),
    ],
)
def test_ntfy_install_fails_closed(tmp_path, mode, why):
    res, _root, _calls = _run_install_ntfy(tmp_path, mode=mode)
    assert res.returncode != 0, why
    assert "Service healthy" not in res.stdout, why
    assert NEW_TOKEN not in res.stdout + res.stderr


# ------------------------------- mattermost_db_secret.sh, failure paths


def _fake_docker_volume(tmp_path: Path, *, psql_fails: bool) -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "docker.argv"
    script = f"""#!/bin/bash
printf '%s\\n' "$*" >> {log}
case "$1" in
  info) exit 0 ;;
  container) exit 1 ;;
  volume) echo security_mattermost_db ;;
  exec)
    if [[ "$2" == -i ]]; then cat >/dev/null; {"exit 2" if psql_fails else "exit 0"}; fi
    exit 0 ;;
  *) exit 0 ;;
esac
"""
    (bindir / "docker").write_text(script, encoding="utf-8")
    (bindir / "docker").chmod(0o755)
    return bindir


@pytest.mark.parametrize("psql_fails", [False, True])
def test_db_secret_volume_only_uses_and_removes_a_temporary_container(tmp_path, psql_fails):
    bindir = _fake_docker_volume(tmp_path, psql_fails=psql_fails)
    env_file = tmp_path / "mattermost-db.env"
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
    res = subprocess.run(["bash", str(DB_SECRET), str(env_file)], capture_output=True, text=True, env=env)
    argv = (tmp_path / "docker.argv").read_text(encoding="utf-8")
    assert "run -d --name azazel-edge-mm-db-password-change --network none -v security_mattermost_db:" in argv
    assert argv.rstrip().splitlines()[-1] == "rm -f azazel-edge-mm-db-password-change"
    if psql_fails:
        assert res.returncode != 0
        assert not env_file.exists()
    else:
        assert res.returncode == 0, res.stderr
        assert HEX48.match(_password(env_file))
        assert _password(env_file) not in argv


def test_db_secret_waits_with_a_real_query():
    src = DB_SECRET.read_text(encoding="utf-8")
    wait = _function(DB_SECRET, "wait_ready")
    code = "\n".join(l for l in wait.splitlines() if not l.strip().startswith("#"))
    assert 'psql -q -tA -U "${DB_USER}" -d "${DB_NAME}" -c \'select 1\'' in code
    assert "pg_isready" not in code
    # Every password change is checked; none is allowed to fail silently.
    for line in re.findall(r"^.*set_db_password .*$", src, re.M):
        if line.startswith("set_db_password()"):
            continue
        assert "die" in line or "ok=0" in line, line


# ------------------------------- provision: no success without LAN access


def test_lan_proxy_site_trusts_no_client_supplied_address():
    script = 'MATTERMOST_PORT_PUBLIC=8065\nMATTERMOST_LAN_CIDR="172.16.0.0/24"\n' + _lan_proxy_block() + \
        "\nrender_lan_proxy_site 127.0.0.1:18065\n"
    site = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    # allow/deny must see the real peer, never an address from a header.
    for word in ("real_ip", "set_real_ip_from", "real_ip_header", "realip"):
        assert word not in site


def test_lan_proxy_fails_without_nginx(tmp_path):
    import shutil

    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("bash", "dirname", "mktemp", "rm", "cat"):
        path = shutil.which(tool)
        if path:
            (bindir / tool).symlink_to(path)
    if shutil.which("nginx", path=str(bindir)):
        pytest.skip("nginx on PATH")
    script = (
        "MATTERMOST_API_URL=http://127.0.0.1:18065\nMATTERMOST_PORT_PUBLIC=8065\n"
        + _lan_proxy_block() + "\nensure_lan_proxy\necho REACHED\n"
    )
    res = subprocess.run([str(bindir / "bash"), "-c", script], capture_output=True, text=True,
                         env={"PATH": str(bindir)})
    assert res.returncode != 0
    assert "REACHED" not in res.stdout
    assert "install_https_proxy.sh" in res.stderr


def test_provision_ends_non_zero_while_the_former_admin_password_is_in_use():
    src = PROVISION.read_text(encoding="utf-8")
    tail = src[src.index("\nresolve_admin_password\n"):]
    assert tail.index("require_changed_admin_password") < tail.index('echo "[OK] Mattermost workspace provisioned"')
    func = (_function(PROVISION, "require_changed_admin_password") + _function(PROVISION, "is_former_default_password")
            + _function(PROVISION, "print_rerun_hint"))
    fake_hash = hashlib.sha256(b"fake-old-default").hexdigest()
    base = f'FORMER_DEFAULT_PASSWORD_SHA256="{fake_hash}"\nMATTERMOST_USERNAME=u\nCRED_ENV=/x/cred.env\n' + func

    res = subprocess.run(["bash", "-c", base + 'MATTERMOST_PASSWORD="fake-old-default"\nrequire_changed_admin_password\necho OK\n'],
                         capture_output=True, text=True)
    assert res.returncode == 3
    assert "OK" not in res.stdout
    assert "[ACTION REQUIRED]" in res.stderr and "/x/cred.env" in res.stderr
    # The way back is the AI runtime installer (slash command, restarts),
    # not this script alone.
    assert "sudo ENABLE_OLLAMA=0 ENABLE_MATTERMOST=1 installer/internal/install_ai_runtime.sh" in res.stderr
    assert "install_all.sh" in res.stderr and "install_sensors.sh" in res.stderr
    assert "fake-old-default" not in res.stderr  # the password itself is not shown

    res = subprocess.run(["bash", "-c", base + 'MATTERMOST_PASSWORD="new-random"\nrequire_changed_admin_password\necho OK\n'],
                         capture_output=True, text=True)
    assert res.returncode == 0 and res.stdout == "OK\n"


CURL_RECORDER = """#!/bin/bash
# The permission bits of a file: GNU stat (Debian) or BSD stat (macOS).
mode_of() {{ stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null; }}
printf 'argv %s\\n' "$*" >> {log}
mode='{mode}'
prev=""
for a in "$@"; do
  if [[ $prev == -H && $a == @* ]]; then
    printf 'hdrfile %s %s\\n' "$(mode_of "${{a#@}}")" "$(cat "${{a#@}}")" >> {log}
    printf 'workdir %s\\n' "$(dirname "${{a#@}}")" >> {log}
    printf 'workdirmode %s\\n' "$(mode_of "$(dirname "${{a#@}}")")" >> {log}
  fi
  if [[ $prev == -D ]]; then printf 'Token: x\\r\\n' > "$a"; fi
  prev="$a"
done
printf 'stdin %s\\n' "$(cat)" >> {log}
case $mode in
  fail) exit 7 ;;
  hang) echo started >> {log}.started; sleep 30 ;;
esac
printf 200
"""


def _curl_recorder(tmp_path: Path, mode: str = "ok") -> Path:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "curl").write_text(CURL_RECORDER.format(log=tmp_path / "curl.log", mode=mode), encoding="utf-8")
    (bindir / "curl").chmod(0o755)
    return bindir


TOKEN = "faketoken0123456789"


def _workspace_api_script(calls: str) -> str:
    return (
        "set -euo pipefail\nMATTERMOST_API_URL=http://127.0.0.1:18065\nAUTH_TOKEN=''\numask 077\n"
        + _function(PROVISION, "setup_work_dir") + _function(PROVISION, "api_call")
        + "setup_work_dir\n" + calls
    )


def _command_api_script(calls: str) -> str:
    return (
        f"set -euo pipefail\nMATTERMOST_URL=http://127.0.0.1:18065\nBOT_TOKEN={TOKEN}\n"
        + _function(COMMAND, "setup_work_dir") + _function(COMMAND, "api")
        + "setup_work_dir\n" + calls
    )


def _check_off_argv(tmp_path: Path, expected_headers: int) -> str:
    text = (tmp_path / "curl.log").read_text(encoding="utf-8")
    argv = "\n".join(l for l in text.splitlines() if l.startswith("argv "))
    assert TOKEN not in argv
    assert text.count(f"hdrfile 600 Authorization: Bearer {TOKEN}") == expected_headers
    # The private scratch directory the header file lives in is 0700.
    modes = {l.split()[1] for l in text.splitlines() if l.startswith("workdirmode ")}
    assert modes == {"700"}, modes
    workdirs = {l.split()[1] for l in text.splitlines() if l.startswith("workdir ")}
    assert len(workdirs) == 1
    workdir = Path(workdirs.pop())
    assert workdir.parent == tmp_path and not workdir.exists()  # removed on exit
    # Nothing is left behind in TMPDIR.
    assert sorted(p.name for p in tmp_path.iterdir() if p.name not in ("bin", "curl.log", "curl.log.started")) == []
    return text


@needs_gnu_mktemp
def test_api_call_keeps_the_token_off_the_command_line(tmp_path):
    bindir = _curl_recorder(tmp_path)
    script = _workspace_api_script(
        f'api_call GET /api/v4/users/me "" {TOKEN}\napi_call POST /x \'{{"a":1}}\' {TOKEN}\necho "$LAST_STATUS"\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    text = _check_off_argv(tmp_path, 2)
    assert 'stdin {"a":1}' in text
    assert "Authorization: Bearer" not in PROVISION.read_text(encoding="utf-8").replace(
        "printf 'Authorization: Bearer %s\\n'", "")


@needs_gnu_mktemp
def test_api_call_curl_failure_exits_1_and_removes_the_files(tmp_path):
    bindir = _curl_recorder(tmp_path, "fail")
    script = _workspace_api_script(f'api_call GET /api/v4/users/me "" {TOKEN}\necho REACHED\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 1
    assert "REACHED" not in res.stdout and "curl exit 7" in res.stderr
    _check_off_argv(tmp_path, 1)


def _signal_while_curl_runs(tmp_path: Path, script: str, sig: int) -> int:
    import signal
    import time

    bindir = _curl_recorder(tmp_path, "hang")
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    proc = subprocess.Popen(["bash", "-c", script], env=env, start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    started = tmp_path / "curl.log.started"
    deadline = time.monotonic() + 10
    while not started.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert started.exists(), "curl stub did not start"
    os.killpg(proc.pid, sig)
    return proc.wait(timeout=10)


@needs_gnu_mktemp
@pytest.mark.parametrize("signame, code", [("SIGTERM", 143), ("SIGINT", 130)])
def test_workspace_scratch_dir_is_removed_on_a_signal(tmp_path, signame, code):
    import signal

    script = _workspace_api_script(f'api_call POST /x \'{{"a":1}}\' {TOKEN}\n')
    assert _signal_while_curl_runs(tmp_path, script, getattr(signal, signame)) == code
    _check_off_argv(tmp_path, 1)


@needs_gnu_mktemp
def test_command_api_keeps_the_bot_token_off_the_command_line(tmp_path):
    bindir = _curl_recorder(tmp_path)
    script = _command_api_script('api GET /api/v4/teams/name/t >/dev/null\napi POST /api/v4/commands \'{"b":2}\' >/dev/null\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    text = _check_off_argv(tmp_path, 2)
    assert 'stdin {"b":2}' in text
    src = COMMAND.read_text(encoding="utf-8")
    assert "Authorization: Bearer ${BOT_TOKEN}\"" not in src and '-H "Authorization' not in src
    # setup_work_dir runs once the token is known, before the first request.
    assert src.index("\nsetup_work_dir\n") < src.index('TEAM_JSON="$(api GET')
    assert src.index('BOT_TOKEN="${AZAZEL_MATTERMOST_BOT_TOKEN:-}"') < src.index("\nsetup_work_dir\n")


@needs_gnu_mktemp
@pytest.mark.parametrize("signame, code", [("SIGTERM", 143), ("SIGINT", 130)])
def test_command_scratch_dir_is_removed_on_a_signal(tmp_path, signame, code):
    import signal

    script = _command_api_script("api GET /api/v4/teams/name/t\n")
    assert _signal_while_curl_runs(tmp_path, script, getattr(signal, signame)) == code
    _check_off_argv(tmp_path, 1)


@needs_gnu_mktemp
def test_command_api_curl_failure_stops_the_script(tmp_path):
    # A failed request (curl exit 7, as for a refused connection) is not
    # taken as an empty reply: the script stops at once with curl's code,
    # also inside a command substitution as the script uses it, and the
    # scratch directory is removed.
    bindir = _curl_recorder(tmp_path, "fail")
    script = _command_api_script('TEAM_JSON="$(api GET /api/v4/teams/name/t)"\necho REACHED\n')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 7, (res.returncode, res.stderr)
    assert "REACHED" not in res.stdout
    _check_off_argv(tmp_path, 1)
    # -f: an HTTP error status (4xx/5xx) is a curl failure too.
    assert re.search(r"^argv -fsS ", (tmp_path / "curl.log").read_text(encoding="utf-8"), re.M)


@needs_gnu_mktemp
def test_command_api_body_goes_on_stdin_not_argv(tmp_path):
    bindir = _curl_recorder(tmp_path)
    body = '{"trigger":"mio","marker":"body-marker-4711"}'
    script = _command_api_script(f"api POST /api/v4/commands '{body}' >/dev/null\n")
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", TMPDIR=str(tmp_path))
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, res.stderr
    text = _check_off_argv(tmp_path, 1)
    argv = [l for l in text.splitlines() if l.startswith("argv ")]
    assert len(argv) == 1
    assert "--data-binary @-" in argv[0]
    assert "body-marker-4711" not in argv[0]
    assert f"stdin {body}" in text


# ---------------- exit codes reach the caller (install_ai_runtime, install_all)


def _stub(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8")
    path.chmod(0o755)


def _run_ai_runtime(tmp_path: Path, *, secret_rc: int = 0, provision_rc: int = 0, command_rc: int = 0,
                    arch: str = "x86_64", mattermost: str | None = None):
    repo = tmp_path / "repo"
    sysroot = tmp_path / "sys"
    log = tmp_path / "calls.log"
    internal = repo / "installer" / "internal"
    src = AI_RUNTIME.read_text(encoding="utf-8")
    src = src.replace('if [[ "${EUID}" -ne 0 ]]; then', "if false; then", 1)
    for prefix in ("/opt/", "/etc/", "/usr/local/bin/"):
        src = src.replace(prefix, f"{sysroot}{prefix}")
    internal.mkdir(parents=True)
    (internal / "install_ai_runtime.sh").write_text(src, encoding="utf-8")
    _stub(internal / "mattermost_db_secret.sh", f'echo "db_secret $*" >> {log}; exit {secret_rc}')
    _stub(internal / "provision_mattermost_workspace.sh", f'echo "provision_workspace" >> {log}; exit {provision_rc}')
    _stub(internal / "provision_mattermost_command.sh", f'echo "provision_command" >> {log}; exit {command_rc}')
    _stub(repo / "bin" / "azazel-edge-compose", f'echo "compose $*" >> {log}')
    for name in ("docker-compose.ollama.yml", "docker-compose.mattermost.yml", ".env"):
        (repo / "security").mkdir(exist_ok=True)
        (repo / "security" / name).write_text("", encoding="utf-8")
    (sysroot / "opt" / "azazel-edge").mkdir(parents=True)
    (sysroot / "usr" / "local" / "bin").mkdir(parents=True)
    bindir = tmp_path / "bin"
    for name in ("apt-get", "systemctl", "chown", "docker"):
        _stub(bindir / name, f'echo "{name} $*" >> {log}')
    _stub(bindir / "uname", f'echo "{arch}"')
    _stub(bindir / "getconf", 'echo 16384')
    env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}", ENABLE_OLLAMA="0", ENABLE_SERVICES="0")
    env.pop("ENABLE_MATTERMOST", None)
    if mattermost is not None:
        env["ENABLE_MATTERMOST"] = mattermost
    res = subprocess.run(["bash", str(internal / "install_ai_runtime.sh")], capture_output=True, text=True, env=env)
    calls = log.read_text(encoding="utf-8") if log.exists() else ""
    return res, calls


@needs_gnu_mv
def test_ai_runtime_runs_the_mattermost_steps_in_order(tmp_path):
    res, calls = _run_ai_runtime(tmp_path)
    assert res.returncode == 0, res.stdout + res.stderr
    order = [l.split()[0] for l in calls.splitlines() if l.split()[0] in
             ("db_secret", "compose", "provision_workspace", "provision_command")]
    assert order == ["db_secret", "compose", "provision_workspace", "provision_command"]
    assert re.search(r"^db_secret \S*/sys/etc/azazel-edge/mattermost-db\.env$", calls, re.M)


@needs_gnu_mv
@pytest.mark.parametrize("rc", [1, 3])
def test_ai_runtime_stops_with_the_provision_exit_code(tmp_path, rc):
    res, calls = _run_ai_runtime(tmp_path, provision_rc=rc)
    assert res.returncode == rc
    assert "provision_command" not in calls
    assert "[DONE]" not in res.stdout


@needs_gnu_mv
def test_ai_runtime_stops_when_the_db_secret_fails(tmp_path):
    res, calls = _run_ai_runtime(tmp_path, secret_rc=1)
    assert res.returncode == 1
    assert not re.search(r"^(compose|provision_workspace)", calls, re.M)


# Mattermost's image is amd64 only; on aarch64 (Raspberry Pi 5, 16K-page
# kernel) it is off by default and installed only when asked for (Edge#477).

_MM_STEPS = ("db_secret", "compose", "provision_workspace", "provision_command")


def _mm_steps(calls: str) -> list[str]:
    return [l.split()[0] for l in calls.splitlines() if l.split()[0] in _MM_STEPS]


@needs_gnu_mv
def test_ai_runtime_skips_mattermost_by_default_on_aarch64(tmp_path):
    res, calls = _run_ai_runtime(tmp_path, arch="aarch64")
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mm_steps(calls) == []
    assert "[ai/5] Skip Mattermost (off by default on aarch64; ENABLE_MATTERMOST=1 installs it" in res.stdout
    assert "[ai/5] Start Mattermost stack" not in res.stdout
    assert "NOTICE" not in res.stdout + res.stderr
    assert "[DONE] AI runtime stack installed." in res.stdout


@needs_gnu_mv
@pytest.mark.parametrize("value", ["0", ""])
def test_ai_runtime_on_aarch64_with_mattermost_off_or_empty(tmp_path, value):
    res, calls = _run_ai_runtime(tmp_path, arch="aarch64", mattermost=value)
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mm_steps(calls) == []
    assert "[ai/5] Skip Mattermost" in res.stdout


@needs_gnu_mv
def test_ai_runtime_installs_mattermost_on_aarch64_when_asked_with_a_notice(tmp_path):
    res, calls = _run_ai_runtime(tmp_path, arch="aarch64", mattermost="1")
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mm_steps(calls) == list(_MM_STEPS)
    notice = [l for l in res.stdout.splitlines() if l.startswith("NOTICE:")]
    assert len(notice) == 1, res.stdout
    assert "amd64 only" in notice[0] and "qemu-user" in notice[0] and "16K-page" in notice[0]
    assert "page size here: 16384" in notice[0]
    # Printed before anything is installed.
    assert res.stdout.index("NOTICE:") < res.stdout.index("[ai/1]")
    assert "[ai/5] Start Mattermost stack" in res.stdout


@needs_gnu_mv
def test_ai_runtime_keeps_mattermost_on_by_default_on_x86_64(tmp_path):
    res, calls = _run_ai_runtime(tmp_path, arch="x86_64")
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mm_steps(calls) == list(_MM_STEPS)
    assert "NOTICE" not in res.stdout + res.stderr
    assert "Skip Mattermost" not in res.stdout


@needs_gnu_mv
def test_ai_runtime_on_x86_64_with_mattermost_off(tmp_path):
    res, calls = _run_ai_runtime(tmp_path, arch="x86_64", mattermost="0")
    assert res.returncode == 0, res.stdout + res.stderr
    assert _mm_steps(calls) == []
    assert "[ai/5] Skip Mattermost (ENABLE_MATTERMOST=0)" in res.stdout


def test_ai_runtime_reads_no_new_variable_for_the_mattermost_default():
    # Only ENABLE_MATTERMOST's default changes: no other variable decides it.
    src = AI_RUNTIME.read_text(encoding="utf-8")
    assert re.findall(r'ENABLE_MATTERMOST="\$\{ENABLE_MATTERMOST:-(\d)\}"', src) == ["0", "1"]
    block = src[src.index('machine_arch="$(uname -m)"'):src.index('echo "[ai/1]')]
    assert set(re.findall(r"\$\{(\w+)", block)) == {"machine_arch", "ENABLE_MATTERMOST"}


@pytest.mark.parametrize("rc", [1, 3])
def test_install_all_passes_the_ai_runtime_exit_code_on(tmp_path, rc):
    internal = tmp_path / "repo" / "installer" / "internal"
    internal.mkdir(parents=True)
    src = (INTERNAL / "install_all.sh").read_text(encoding="utf-8")
    src = src.replace('if [[ "${EUID}" -ne 0 ]]; then', "if false; then", 1)
    (internal / "install_all.sh").write_text(src, encoding="utf-8")
    log = tmp_path / "after.log"
    _stub(internal / "install_ai_runtime.sh", f"exit {rc}")
    for name in ("set_dev_remote_access.sh", "install_vector.sh", "install_sensors.sh"):
        _stub(internal / name, f'echo "{name}" >> {log}')
    env = dict(os.environ, ENABLE_INTERNAL_NETWORK="0", ENABLE_APP_STACK="0", ENABLE_AI_RUNTIME="1",
               ENABLE_DEV_REMOTE_ACCESS="1", ENABLE_VECTOR="1")
    res = subprocess.run(["bash", str(internal / "install_all.sh")], capture_output=True, text=True,
                         env=env, stdin=subprocess.DEVNULL)
    assert res.returncode == rc, res.stdout + res.stderr
    assert not log.exists()  # nothing after the AI runtime ran


@needs_gnu_mv
def test_ai_runtime_stops_when_the_slash_command_step_fails(tmp_path):
    res, calls = _run_ai_runtime(tmp_path, command_rc=4)
    assert res.returncode == 4
    assert "[DONE]" not in res.stdout
