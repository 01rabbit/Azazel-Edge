"""Small faults found in the integration rehearsal (container, not hardware).

Pinned here:
- a user outside ``azazel-control`` cannot look up /run/azazel-edge/control.sock
  (the directory is 0750); that is a clear ``permission_denied`` failure, not a
  traceback, and it is never written to ``ui_command.json`` (it is not
  "daemon not reached"); ``watch_snapshots`` ends with ``permission_denied``;
  both TUIs keep running and say so;
- HIL ``command()`` records a missing program (no sudo) as exit 127, so
  ``postconditions.tc_nft_read_only`` is ``unobserved``, not ``failed``;
- HIL ``prepare --no-update-repo`` names the real reason (not on main, local
  changes) instead of "refusing repository update".
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from _control_daemon_inproc import short_tmpdir  # noqa: E402
from azazel_edge import control_plane  # noqa: E402


class _DeniedPath:
    """A socket path whose lookup is refused, like /run/azazel-edge/control.sock
    for a user outside azazel-control."""

    def __init__(self, text: str = "/run/azazel-edge/control.sock") -> None:
        self._text = text

    def exists(self) -> bool:
        raise PermissionError(13, "Permission denied", self._text)

    def __str__(self) -> str:
        return self._text

    def __fspath__(self) -> str:
        return self._text


@pytest.fixture
def tmpdir_short():
    path = short_tmpdir("rh")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


# ------------------------------------------------------------- C: control.sock

def test_lookup_refused_is_permission_denied_not_a_traceback():
    res = control_plane.send_action("get_snapshot", socket_path=_DeniedPath())
    assert res["ok"] is False and res["permission_denied"] is True
    assert "transport_error" not in res and "delivery_unknown" not in res
    assert "azazel-control" in res["error"]


def test_permission_denied_is_not_written_to_the_command_file(monkeypatch, tmp_path):
    monkeypatch.setattr(control_plane, "send_action",
                        lambda action, params=None: control_plane._socket_request(
                            {"action": action}, socket_path=_DeniedPath()))
    cmd = tmp_path / "ui_command.json"
    res = control_plane.send_action_with_fallback("reprobe", fallback_cmd_path=cmd)
    assert res["ok"] is False and res["permission_denied"] is True
    assert "undelivered" not in res and not cmd.exists()


def test_connect_refused_is_permission_denied(monkeypatch, tmpdir_short):
    path = tmpdir_short / "c.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))

    class _Sock:
        def __init__(self, *a, **k): pass
        def settimeout(self, t): pass
        def connect(self, p): raise PermissionError(13, "Permission denied")
        def close(self): pass

    try:
        monkeypatch.setattr(control_plane.socket, "socket", _Sock)
        res = control_plane.send_action("reprobe", socket_path=path)
        errors: list = []
        assert list(control_plane.watch_snapshots(socket_path=path, errors=errors)) == []
    finally:
        srv.close()
    assert res["permission_denied"] is True and "transport_error" not in res
    assert errors == ["permission_denied"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_a_real_0750_directory_is_permission_denied(tmpdir_short):
    run = tmpdir_short / "run"
    run.mkdir()
    path = run / "control.sock"
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    run.chmod(0o000)
    try:
        res = control_plane.send_action("get_snapshot", socket_path=path)
        errors: list = []
        assert list(control_plane.watch_snapshots(socket_path=path, errors=errors)) == []
        assert control_plane.control_socket_access_error(path)
    finally:
        run.chmod(0o750)
        srv.close()
    assert res["permission_denied"] is True
    assert errors == ["permission_denied"]


def test_watch_snapshots_reports_permission_denied():
    errors: list = []
    assert list(control_plane.watch_snapshots(socket_path=_DeniedPath(), errors=errors)) == []
    assert errors == ["permission_denied"]


def test_snapshot_read_falls_back_quietly():
    assert control_plane.read_snapshot_from_control_plane(socket_path=_DeniedPath()) is None


def test_access_error_helper(tmpdir_short):
    assert "azazel-control" in control_plane.control_socket_access_error(_DeniedPath())
    assert control_plane.control_socket_access_error(tmpdir_short / "none.sock") is None


def test_cli_wording_for_permission_denied():
    line = control_plane.describe_action_failure({"ok": False, "permission_denied": True, "error": "x"}, "reprobe")
    assert line == ("• action not sent: reprobe (no permission for the control socket; "
                    "the user must be in the azazel-control group)")


def test_curses_snapshot_says_permission_denied(monkeypatch):
    from azazel_edge import cli_unified

    monkeypatch.setattr(cli_unified, "read_snapshot_payload",
                        lambda prefer_control_plane=True: (cli_unified.default_snapshot(), "FILE:x"))
    monkeypatch.setattr(cli_unified, "control_socket_access_error", lambda: "permission denied: x")
    snap = cli_unified.load_snapshot()
    assert "permission denied" in snap.source
    assert any("control socket not usable" in line for line in snap.evidence)


def test_textual_status_line_says_permission_denied(monkeypatch):
    pytest.importorskip("textual")
    from azazel_edge import cli_unified_textual as tui

    monkeypatch.setattr(tui, "control_socket_access_error", lambda: "permission denied: x")
    app = tui.AzazelTextualApp(load_snapshot_fn=lambda: object(), send_command_fn=lambda a: {},
                               update_epd_fn=lambda s, e: None, epd_fingerprint_fn=lambda s: None,
                               unicode_mode=False, enable_epd=False)
    monkeypatch.setattr(app, "_render_status_line", lambda: None)
    monkeypatch.setattr(app, "_render_panels", lambda: None)
    asyncio.run(app._refresh_snapshot(initial=True))
    assert "permission denied" in app._status_message and "azazel-control" in app._status_message


# ------------------------------------------------------------------ D/E: HIL

def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


remote = _load("azazel_hil_remote_rehearsal", "tools/hil/azazel_hil_remote.py")


@pytest.fixture()
def rec(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return remote.Recorder("rehearsal-test")


def _ends(rec) -> dict:
    rows = [json.loads(line) for line in rec.events.read_text().splitlines()]
    return {row["test_id"]: row for row in rows if row["kind"] == "test_end"}


def test_command_records_a_missing_program(rec):
    code, out = remote.command(rec, "x", ["/nonexistent/azazel-no-such-program", "list"])
    assert code == 127 and out["not_runnable"] is True
    assert "command not found" in out["stderr"]


def test_no_sudo_makes_nft_unobserved_not_failed(rec, monkeypatch):
    real_run = remote.subprocess.run

    def fake_run(argv, **kwargs):
        if argv[0] == "sudo":
            raise FileNotFoundError(2, "No such file or directory", "sudo")
        return real_run(["true"], **kwargs)

    monkeypatch.setattr(remote.subprocess, "run", fake_run)
    monkeypatch.setattr(remote, "find_tool", lambda name: f"/usr/sbin/{name}")
    monkeypatch.setattr(remote.os, "access", lambda path, mode: path == "/usr/sbin/nft")
    remote.postconditions(rec)
    end = _ends(rec)["postconditions.tc_nft_read_only"]
    assert end["status"] == "unobserved"
    assert end["detail"]["nft"]["observed"] is False
    assert "command not found: sudo" in end["detail"]["reason"]


@pytest.mark.parametrize("update_repo", [True, False])
@pytest.mark.parametrize("porcelain,branch,why", [
    ("", "feature\n", "checkout must be on main"),
    (" M x\n", "main\n", "uncommitted/untracked"),
])
def test_prepare_names_the_real_reason(rec, monkeypatch, tmp_path, update_repo, porcelain, branch, why):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def fake(rec_, test_id, argv, timeout=30):
        out = porcelain if "status" in argv else branch
        return 0, {"argv": argv, "stdout": out, "stderr": "", "exit_code": 0}

    monkeypatch.setattr(remote, "command", fake)
    remote.prepare(rec, repo, update_repo, {"path": "python3", "source": "test"})
    detail = _ends(rec)["prepare.repository"]["detail"]
    assert why in detail["reason"]
    assert ("refusing repository update" in detail["reason"]) is update_repo
    assert detail["update_requested"] is update_repo
