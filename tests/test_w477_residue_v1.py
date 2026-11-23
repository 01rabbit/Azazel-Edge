"""Edge#477 residue: the macdev tools create and replace secret files 0600.

The Mattermost provisioner and env.sh wrote the credential file, the web env,
the slash-command token and the web token under the caller's umask, and
truncated an existing (possibly 0644) file before chmod. The functions run
here under umask 022 with a pre-existing 0644 target. A `mv` spy records, at
the moment the new content is moved into place, the mode of the file that
holds it and the content still in the target.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "macdev" / "provision-mattermost.sh"
ENV_SH = ROOT / "tools" / "macdev" / "env.sh"


def _function(name: str, path: Path = SCRIPT) -> str:
    m = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", path.read_text(encoding="utf-8"), re.S | re.M)
    assert m, name
    return m.group(0)


def _helpers() -> str:
    return _function("macdev_require_private_parent", ENV_SH) + _function("macdev_write_private_file", ENV_SH)


def _bash(script: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], cwd=cwd, capture_output=True, text=True, check=check)


def _prelude(tmp: Path, log: Path) -> str:
    return f"""
set -eu
umask 022
mv() {{ if [[ "$1" == -f ]]; then shift; fi; if [[ "$1" == -- ]]; then shift; fi
  printf 'src=%s mode=%s dstold=%s\\n' "$1" "$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1")" "$(cat "$2" 2>/dev/null)" >> "{log}"
  command mv -f "$1" "$2"; }}
{_helpers()}
CRED_ENV="{tmp}/cred.env"; WEB_ENV="{tmp}/web.env"
MM_USERNAME=u; MM_EMAIL=e@x; MM_PASSWORD=pw; BASE_URL=http://x; MM_TEAM=t; MM_CHANNEL=c
WEBHOOK_URL=w; BOT_TOKEN=tok; CHANNEL_ID=i; COMMAND_TOKEN_FILE=f
api_call() {{ LAST_STATUS=200; LAST_BODY='[{{"trigger":"azops","token":"cmdtok"}}]'; }}
json_get() {{ :; }}; info() {{ :; }}; fail() {{ exit 1; }}
"""


def _seed_loose(*paths: Path) -> dict:
    inodes = {}
    for p in paths:
        p.write_text("OLD\n")
        p.chmod(0o644)
        inodes[p] = p.stat().st_ino
    return inodes


def _check(tmp: Path, log: Path, targets: list, inodes: dict) -> None:
    lines = log.read_text().splitlines()
    assert len(lines) == len(targets)
    for line in lines:
        # The new content sat in a 0600 file while the old target was untouched.
        assert " mode=600 " in line and line.endswith("dstold=OLD"), line
    for p in targets:
        assert (p.stat().st_mode & 0o777) == 0o600
        assert p.read_text() != "OLD\n"
        assert p.stat().st_ino != inodes[p]


def test_credential_and_web_env_replace_a_0644_file_through_a_0600_one(tmp_path: Path) -> None:
    log = tmp_path / "log"
    inodes = _seed_loose(tmp_path / "cred.env", tmp_path / "web.env")
    _bash(_prelude(tmp_path, log) + _function("write_outputs") + "\nwrite_outputs\n", tmp_path)
    _check(tmp_path, log, [tmp_path / "cred.env", tmp_path / "web.env"], inodes)


def test_slash_command_token_replaces_a_0644_file_through_a_0600_one(tmp_path: Path) -> None:
    log = tmp_path / "log"
    inodes = _seed_loose(tmp_path / "tok")
    body = "TEAM_ID=tm; COMMAND_URL=x\n" + _function("ensure_command") + f"\nensure_command azops {tmp_path}/tok\n"
    _bash(_prelude(tmp_path, log) + body, tmp_path)
    _check(tmp_path, log, [tmp_path / "tok"], inodes)
    assert (tmp_path / "tok").read_text() == "cmdtok\n"


def test_first_password_save_replaces_a_0644_file_through_a_0600_one(tmp_path: Path) -> None:
    log = tmp_path / "log"
    inodes = _seed_loose(tmp_path / "cred.env")
    text = SCRIPT.read_text(encoding="utf-8")
    m = re.search(r"^if \[\[ -z \"\$\{MM_PASSWORD\}\" \]\]; then\n.*?^fi\n", text, re.S | re.M)
    assert m
    _bash(_prelude(tmp_path, log) + "MM_PASSWORD=\n" + m.group(0), tmp_path)
    _check(tmp_path, log, [tmp_path / "cred.env"], inodes)
    assert "MATTERMOST_PASSWORD=" in (tmp_path / "cred.env").read_text()


def test_start_up_web_token_is_created_0600(tmp_path: Path) -> None:
    state = tmp_path / "state"
    out = _bash(f'umask 022; AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; umask', tmp_path)
    token = state / "web_token.txt"
    assert (token.stat().st_mode & 0o777) == 0o600 and token.read_text().strip()
    assert out.stdout.strip() == "0022"


def test_start_up_web_token_replaces_an_empty_0644_file(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / "web_token.txt").touch()
    (state / "web_token.txt").chmod(0o644)
    _bash(f'umask 022; AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"', tmp_path)
    assert ((state / "web_token.txt").stat().st_mode & 0o777) == 0o600


def test_a_failed_write_under_set_e_leaves_umask_and_the_existing_file_untouched(tmp_path: Path) -> None:
    cred = tmp_path / "cred.env"
    cred.write_text("OLD\n")
    cred.chmod(0o644)
    # WEB_ENV is a directory: the second write must fail, the first has landed.
    (tmp_path / "web.env").mkdir()
    script = f"""set -eu; umask 022
{_helpers()}
CRED_ENV="{tmp_path}/cred.env"; WEB_ENV="{tmp_path}/web.env"
MM_USERNAME=u MM_EMAIL=e MM_PASSWORD=p BASE_URL=b MM_TEAM=t MM_CHANNEL=c
BOT_TOKEN=b WEBHOOK_URL=w CHANNEL_ID=i COMMAND_TOKEN_FILE=f
{_function("write_outputs")}
(write_outputs)
echo not-reached"""
    out = _bash(script, tmp_path, check=False)
    assert out.returncode != 0 and "not-reached" not in out.stdout
    assert (tmp_path / "web.env").is_dir() and list((tmp_path / "web.env").iterdir()) == []
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("web.env.")]


def test_a_failed_write_keeps_the_old_content_and_mode(tmp_path: Path) -> None:
    target = tmp_path / "t"
    target.write_text("OLD\n")
    target.chmod(0o644)
    # chmod of the temp file fails: nothing may land and the target is untouched.
    script = f"""set -eu; umask 022
chmod() {{ return 1; }}
{_helpers()}
umask_before="$(umask)"
echo NEW | macdev_write_private_file "{target}" || echo refused
[[ "$(umask)" == "$umask_before" ]] && echo umask-kept"""
    out = _bash(script, tmp_path)
    assert "refused" in out.stdout and "umask-kept" in out.stdout
    assert target.read_text() == "OLD\n" and (target.stat().st_mode & 0o777) == 0o644
    assert sorted(p.name for p in tmp_path.iterdir()) == ["t"]


def test_a_directory_or_symlink_target_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.write_text("KEEP\n")
    (tmp_path / "dir").mkdir()
    (tmp_path / "linkdir").symlink_to(tmp_path / "dir")
    (tmp_path / "linkfile").symlink_to(real)
    for name in ("dir", "linkdir", "linkfile"):
        script = f"""{_helpers()}
echo NEW | macdev_write_private_file "{tmp_path}/{name}" """
        out = _bash(script, tmp_path, check=False)
        assert out.returncode != 0 and "refusing" in out.stderr, name
    assert real.read_text() == "KEEP\n"
    assert list((tmp_path / "dir").iterdir()) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dir", "linkdir", "linkfile", "real"]


def test_a_non_empty_0644_web_token_is_tightened_not_regenerated(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    token = state / "web_token.txt"
    token.write_text("KEEPME\n")
    token.chmod(0o644)
    out = _bash(f'umask 022; AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; echo rc=$?', tmp_path)
    assert "rc=0" in out.stdout
    assert token.read_text() == "KEEPME\n" and (token.stat().st_mode & 0o777) == 0o600


def test_a_symlinked_or_non_regular_web_token_is_refused_by_source(tmp_path: Path) -> None:
    for kind in ("symlink", "dir"):
        state = tmp_path / kind
        state.mkdir()
        token = state / "web_token.txt"
        real = tmp_path / f"real-{kind}"
        real.write_text("SECRET\n")
        real.chmod(0o644)
        if kind == "symlink":
            token.symlink_to(real)
        else:
            token.mkdir()
        out = _bash(f'AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; echo rc=$?', tmp_path)
        assert "rc=1" in out.stdout and "refusing" in out.stderr, kind
        assert (real.stat().st_mode & 0o777) == 0o644 and real.read_text() == "SECRET\n"


def test_source_fails_without_set_e_when_the_token_cannot_be_saved(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    (fakebin / "python3").write_text("#!/bin/sh\nexit 3\n")
    (fakebin / "python3").chmod(0o755)
    out = _bash(f'PATH="{fakebin}:$PATH" AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; echo rc=$?', tmp_path)
    assert "rc=1" in out.stdout
    assert not (state / "web_token.txt").exists()
    (fakebin / "python3").write_text("#!/bin/sh\nexit 0\n")
    out = _bash(f'PATH="{fakebin}:$PATH" AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; echo rc=$?', tmp_path)
    assert "rc=1" in out.stdout and not (state / "web_token.txt").exists()


def _api_call_script(tmp_path: Path, tmpdir: Path, curl: str, cat: str = "") -> str:
    return f"""set -u; export TMPDIR="{tmpdir}"
{curl}
{cat}
API_URL=http://x; AUTH_TOKEN=a
{_function("api_call")}
api_call GET /p || echo failed
echo status=${{LAST_STATUS:-}}"""


def test_a_curl_failure_removes_the_api_temp_files(tmp_path: Path) -> None:
    tmpdir = tmp_path / "t"
    tmpdir.mkdir()
    out = _bash(_api_call_script(tmp_path, tmpdir, "curl() { return 7; }"), tmp_path)
    assert "failed" in out.stdout and os.listdir(tmpdir) == []


def test_a_cat_failure_under_set_e_removes_the_api_temp_files(tmp_path: Path) -> None:
    tmpdir = tmp_path / "t"
    tmpdir.mkdir()
    script = _api_call_script(
        tmp_path, tmpdir, "curl() { echo 200; }", "cat() { return 1; }"
    ).replace("set -u;", "set -eu;")
    out = _bash(script, tmp_path, check=False)
    assert "failed" in out.stdout and os.listdir(tmpdir) == []


def test_api_call_still_reports_status_headers_and_body(tmp_path: Path) -> None:
    tmpdir = tmp_path / "t"
    tmpdir.mkdir()
    curl = 'curl() { printf "H: 1\\n" > "$3"; printf "BODY" > "$5"; printf 200; }'
    script = _api_call_script(tmp_path, tmpdir, curl).replace(
        "echo status=", 'echo "$LAST_HEADERS|$LAST_BODY"; echo status='
    )
    out = _bash(script, tmp_path)
    assert "H: 1|BODY" in out.stdout and "status=200" in out.stdout and os.listdir(tmpdir) == []


def test_a_group_or_other_writable_parent_is_refused_and_nothing_is_written(tmp_path: Path) -> None:
    for mode in (0o770, 0o707):
        parent = tmp_path / f"p{mode:o}"
        parent.mkdir()
        parent.chmod(mode)
        out = _bash(f"""{_helpers()}
echo NEW | macdev_write_private_file "{parent}/secret" """, tmp_path, check=False)
        assert out.returncode != 0 and str(parent) in out.stderr, mode
        assert list(parent.iterdir()) == []


def test_a_symlinked_parent_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    real.chmod(0o700)
    (tmp_path / "link").symlink_to(real)
    out = _bash(f"""{_helpers()}
echo NEW | macdev_write_private_file "{tmp_path}/link/secret" """, tmp_path, check=False)
    assert out.returncode != 0 and list(real.iterdir()) == []


def test_web_token_is_not_generated_or_tightened_in_a_writable_state_dir(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o775)
    out = _bash(f'AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; echo rc=$?', tmp_path)
    assert "rc=1" in out.stdout and str(state) in out.stderr
    assert not (state / "web_token.txt").exists()
    (state / "web_token.txt").write_text("K\n")
    (state / "web_token.txt").chmod(0o644)
    _bash(f'AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"', tmp_path, check=False)
    assert ((state / "web_token.txt").stat().st_mode & 0o777) == 0o644


def test_a_private_parent_still_works(tmp_path: Path) -> None:
    parent = tmp_path / "ok"
    parent.mkdir()
    parent.chmod(0o755)
    _bash(f"""{_helpers()}
echo NEW | macdev_write_private_file "{parent}/secret" """, tmp_path)
    assert (parent / "secret").read_text() == "NEW\n" and ((parent / "secret").stat().st_mode & 0o777) == 0o600


def test_a_new_state_dir_is_0700_under_umask_002_and_the_token_is_written(tmp_path: Path) -> None:
    state = tmp_path / "newstate"
    out = _bash(f'umask 002; AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"; echo rc=$?', tmp_path)
    assert "rc=0" in out.stdout
    assert (state.stat().st_mode & 0o777) == 0o700
    assert ((state / "web_token.txt").stat().st_mode & 0o777) == 0o600


def test_an_existing_state_dir_is_not_chmoded(tmp_path: Path) -> None:
    state = tmp_path / "old"
    state.mkdir()
    state.chmod(0o755)
    _bash(f'umask 022; AZAZEL_DEV_STATE="{state}" source "{ENV_SH}"', tmp_path)
    assert (state.stat().st_mode & 0o777) == 0o755


def test_a_find_that_cannot_judge_fails_closed(tmp_path: Path) -> None:
    out = _bash(f"""find() {{ return 2; }}
{_helpers()}
echo NEW | macdev_write_private_file "{tmp_path}/secret" """, tmp_path, check=False)
    assert out.returncode != 0 and str(tmp_path) in out.stderr
    assert sorted(p.name for p in tmp_path.iterdir()) == []
