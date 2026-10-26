"""Edge#471 stage 2: the AI agent runs as the non-root account azazel-agent.

Pinned here:
- the agent writes only in its own directories (runtime, logs, state) and
  never chmods or writes the shared /run/azazel-edge; an unsafe directory or
  an audit log that cannot be opened stops it (no /tmp fallback);
- the control daemon is the only writer of the shared ui_snapshot.json and
  merges a fixed set of the agent's fields from the agent's own file;
- readers follow (daemon advisory path, Web UI defaults, status view, the AI
  log runbook);
- the query socket accepts the setgid directory tmpfiles.d creates;
- moving the core-decision audit chain and the P0 queue keeps the relay's
  reconcile cursor (no replay), and the carry refuses anything it cannot
  prove;
- the unit, tmpfiles.d and installer.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "py", ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.notify import migrate_audit_path  # noqa: E402
from azazel_edge.notify.p0_alert import attach_p0_alert_relay  # noqa: E402
from azazel_edge_ai import agent as agent_mod  # noqa: E402
from azazel_edge_control import daemon as control_daemon  # noqa: E402

import azazel_edge_web.app as webapp  # noqa: E402

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


# ------------------------------------------------------------ the defaults

def test_the_agent_writes_only_in_its_own_directories_by_default():
    src = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    assert agent_mod.AGENT_RUNTIME_DIR == Path("/run/azazel-edge-agent")
    assert agent_mod.AGENT_LOG_DIR == Path("/var/log/azazel-edge/ai")
    assert agent_mod.AGENT_STATE_DIR == Path("/var/lib/azazel-edge-agent")
    for var, default in [
        ("AZAZEL_AI_ADVISORY", 'str(AGENT_RUNTIME_DIR / "ai_advisory.json")'),
        ("AZAZEL_AI_METRICS", 'str(AGENT_RUNTIME_DIR / "ai_metrics.json")'),
        ("AZAZEL_AI_POLICY", 'str(AGENT_RUNTIME_DIR / "ai_runtime_policy.json")'),
        ("AZAZEL_AI_EVENT_LOG", 'str(AGENT_LOG_DIR / "ai-events.jsonl")'),
        ("AZAZEL_AI_LLM_LOG", 'str(AGENT_LOG_DIR / "ai-llm.jsonl")'),
        ("AZAZEL_AI_DEFERRED_LOG", 'str(AGENT_LOG_DIR / "ai-deferred.jsonl")'),
        ("AZAZEL_AI_AUDIT_LOG", 'str(AGENT_LOG_DIR / "ai-audit.jsonl")'),
    ]:
        assert f'os.environ.get("{var}", {default})' in src, var
    # Its snapshot fields go beside its advisory, not into the shared file.
    assert agent_mod.SNAPSHOT_PATH == agent_mod.ADVISORY_PATH.parent / "ai_snapshot.json"
    assert "AZAZEL_UI_SNAPSHOT" not in src.split("SNAPSHOT_PATH =", 1)[1].split("\n", 1)[0]
    # Only the pre-#462 socket location is still named (to refuse it).
    assert [l for l in src.splitlines() if '"/run/azazel-edge/' in l] == [
        'LEGACY_SOCKET_PATH = Path("/run/azazel-edge/ai-bridge.sock")']
    assert '"/tmp' not in src
    assert "AZAZEL_RUNTIME_DIR_MODE" not in src
    # The audit chain and the P0 queue follow the audit log's directory.
    assert agent_mod.CORE_DECISION_AUDIT_PATH.parent == agent_mod.AI_AUDIT_PATH.parent
    assert agent_mod.P0_ALERT_QUEUE_PATH.parent == agent_mod.AI_AUDIT_PATH.parent


def test_readers_follow_the_agent():
    dsrc = (ROOT / "py" / "azazel_edge_control" / "daemon.py").read_text(encoding="utf-8")
    assert 'os.environ.get("AZAZEL_AI_ADVISORY", "/run/azazel-edge-agent/ai_advisory.json")' in dsrc
    assert control_daemon.AGENT_SNAPSHOT_PATH == control_daemon.AI_ADVISORY_PATH.parent / "ai_snapshot.json"
    wsrc = (ROOT / "azazel_edge_web" / "app.py").read_text(encoding="utf-8")
    for var, default in [
        ("AZAZEL_AI_ADVISORY", 'str(AGENT_RUNTIME_DIR / "ai_advisory.json")'),
        ("AZAZEL_AI_METRICS", 'str(AGENT_RUNTIME_DIR / "ai_metrics.json")'),
        ("AZAZEL_AI_EVENT_LOG", 'str(AGENT_LOG_DIR / "ai-events.jsonl")'),
        ("AZAZEL_AI_LLM_LOG", 'str(AGENT_LOG_DIR / "ai-llm.jsonl")'),
    ]:
        assert f'os.environ.get("{var}", {default})' in wsrc, var
    runbook = (ROOT / "runbooks" / "ops" / "rb.ops.logs.ai.recent.yaml").read_text(encoding="utf-8")
    assert "/var/log/azazel-edge/ai/ai-llm.jsonl" in runbook
    from azazel_edge.tactics_engine.decision_logger import DecisionLogger
    assert "/var/lib/azazel-edge-agent/decisions" in Path(sys.modules[DecisionLogger.__module__].__file__).read_text(
        encoding="utf-8")


def test_the_web_ui_reads_the_status_view_beside_the_agents_files(monkeypatch, tmp_path):
    monkeypatch.setattr(webapp, "AI_ADVISORY_PATH", tmp_path / "ai_advisory.json")
    assert webapp.read_status_view() is None
    (tmp_path / "ui_status_view.json").write_text('{"product": "edge"}', encoding="utf-8")
    assert webapp.read_status_view() == {"product": "edge"}


# ------------------------------------------------ the agent's directories

def test_a_missing_runtime_directory_is_created_0750(tmp_path):
    d = tmp_path / "agent"
    agent_mod._prepare_runtime_dir(d)
    assert stat.S_IMODE(os.lstat(d).st_mode) == 0o750


@pytest.mark.parametrize("mode", [0o750, 0o700, 0o2750, 0o755])
def test_an_existing_safe_directory_is_used_as_it_is(tmp_path, mode):
    d = tmp_path / "agent"
    d.mkdir()
    os.chmod(d, mode)
    agent_mod._prepare_runtime_dir(d)
    assert stat.S_IMODE(os.lstat(d).st_mode) == mode  # never chmod'ed


@pytest.mark.parametrize("mode", [0o770, 0o2770, 0o777, 0o757])
def test_a_writable_shared_directory_is_refused_and_not_changed(tmp_path, mode):
    d = tmp_path / "shared"
    d.mkdir()
    os.chmod(d, mode)
    with pytest.raises(agent_mod.AgentDirError, match="writable"):
        agent_mod._prepare_runtime_dir(d)
    assert stat.S_IMODE(os.lstat(d).st_mode) == mode


def test_a_symlinked_directory_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(agent_mod.AgentDirError, match="not a real directory"):
        agent_mod._prepare_runtime_dir(tmp_path / "link")


@pytest.mark.skipif(not IS_ROOT, reason="needs root to make a directory owned by another account")
def test_a_directory_owned_by_another_account_is_refused(tmp_path):
    d = tmp_path / "other"
    d.mkdir()
    os.chmod(d, 0o750)
    os.chown(d, 61003, -1)
    if os.geteuid() == 61003:
        pytest.skip("same uid")
    with pytest.raises(agent_mod.AgentDirError, match="owned by uid 61003"):
        agent_mod._prepare_runtime_dir(d)


def test_the_audit_log_has_no_tmp_fallback_and_stops_the_service(monkeypatch, tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("", encoding="utf-8")
    monkeypatch.setattr(agent_mod, "AI_AUDIT_PATH", blocker / "ai-audit.jsonl")
    assert agent_mod._build_ai_audit_logger() is None
    assert "cannot be opened" in agent_mod.AI_AUDIT_ERROR
    for name in ("ADVISORY_PATH", "METRICS_PATH", "POLICY_PATH"):
        monkeypatch.setattr(agent_mod, name, tmp_path / "run" / f"{name}.json")
    monkeypatch.setattr(agent_mod, "AI_AUDIT", None)
    monkeypatch.setattr(agent_mod, "_prepare_ai_socket_dir", lambda p: pytest.fail("went past the audit check"))
    with pytest.raises(SystemExit, match="cannot be opened"):
        agent_mod._serve()


def test_an_unsafe_runtime_directory_stops_the_service(monkeypatch, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o770)
    for name in ("ADVISORY_PATH", "METRICS_PATH", "POLICY_PATH"):
        monkeypatch.setattr(agent_mod, name, shared / f"{name}.json")
    monkeypatch.setattr(agent_mod, "_prepare_ai_socket_dir", lambda p: pytest.fail("went past the directory check"))
    with pytest.raises(SystemExit, match="writable"):
        agent_mod._serve()
    assert stat.S_IMODE(shared.stat().st_mode) == 0o770


def test_the_query_socket_accepts_the_setgid_directory_tmpfiles_makes(monkeypatch, tmp_path):
    gid = os.getegid()
    monkeypatch.setattr(agent_mod, "_query_account_ids", lambda: (54321, gid))
    d = Path("/tmp") / f"azq2-{os.getpid()}"
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir()
    try:
        os.chown(d, -1, gid)
        os.chmod(d, 0o2750)
        srv = agent_mod._setup_query_socket(d / "agent-query.sock")
        assert srv is not None
        srv.close()
        assert stat.S_IMODE(os.lstat(d).st_mode) == 0o2750
        os.unlink(d / "agent-query.sock")
        for bad in (0o2770, 0o770, 0o2755):
            os.chmod(d, bad)
            assert agent_mod._setup_query_socket(d / "agent-query.sock") is None
            assert stat.S_IMODE(os.lstat(d).st_mode) == bad
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------ one snapshot writer

def test_the_agent_writes_its_own_snapshot_file_only(monkeypatch, tmp_path):
    shared = tmp_path / "shared" / "ui_snapshot.json"
    shared.parent.mkdir()
    shared.write_text('{"keep": 1}', encoding="utf-8")
    monkeypatch.setenv("AZAZEL_UI_SNAPSHOT", str(shared))
    monkeypatch.setattr(agent_mod, "SNAPSHOT_PATH", tmp_path / "agent" / "ai_snapshot.json")
    monkeypatch.setattr(agent_mod, "_default_route_info", lambda: {"up_if": "-", "uplink_type": "unknown"})
    agent_mod._update_ui_snapshot({"suricata_severity": 1, "suricata_sid": 9, "risk_score": 80,
                                   "user_state": "LIMITED", "recommendation": "Look", "ts": 1.0})
    mine = json.loads((tmp_path / "agent" / "ai_snapshot.json").read_text(encoding="utf-8"))
    assert mine["suricata_critical"] == 1 and mine["user_state"] == "LIMITED"
    assert json.loads(shared.read_text(encoding="utf-8")) == {"keep": 1}


@pytest.fixture
def agent_snapshot(monkeypatch, tmp_path):
    path = tmp_path / "agent" / "ai_snapshot.json"
    path.parent.mkdir()
    monkeypatch.setattr(control_daemon, "AGENT_SNAPSHOT_PATH", path)
    return path


def test_the_daemon_merges_only_the_agents_fields(agent_snapshot):
    agent_snapshot.write_text(json.dumps({
        "user_state": "LIMITED", "recommendation": "Look", "suricata_critical": 3, "evidence": ["a"],
        "attack": {"suricata_alert": True}, "llm": {"status": "done"},
        "monitoring": {"suricata": "ON", "ntfy": "FORGED"},
        "up_if": "forged0", "connection": {"wifi_state": "FORGED"}, "mode": {"current_mode": "forged"},
        "network_health": {"status": "FORGED"},
    }), encoding="utf-8")
    shared = {"up_if": "eth9", "connection": {"wifi_state": "N/A(ETH)"}, "monitoring": {"ntfy": "ON"},
              "user_state": "SAFE", "network_health": {"status": "SAFE"}}
    merged = control_daemon._overlay_agent_snapshot(shared)
    assert merged["user_state"] == "LIMITED" and merged["suricata_critical"] == 3
    assert merged["evidence"] == ["a"] and merged["attack"] == {"suricata_alert": True}
    assert merged["monitoring"] == {"ntfy": "ON", "suricata": "ON"}
    assert merged["up_if"] == "eth9" and merged["connection"] == {"wifi_state": "N/A(ETH)"}
    assert "mode" not in merged and merged["network_health"] == {"status": "SAFE"}
    assert shared["user_state"] == "SAFE"  # not modified in place


def test_the_daemon_ignores_a_missing_symlinked_or_oversized_agent_file(agent_snapshot, monkeypatch, tmp_path):
    base = {"user_state": "SAFE"}
    assert control_daemon._overlay_agent_snapshot(base) == base
    target = tmp_path / "elsewhere.json"
    target.write_text('{"user_state": "CONTAINED"}', encoding="utf-8")
    agent_snapshot.symlink_to(target)
    assert control_daemon._overlay_agent_snapshot(base) == base
    agent_snapshot.unlink()
    # A complete object within the first bytes, but the file is over the bound:
    # ignored as a whole, not read in part.
    monkeypatch.setattr(control_daemon, "AGENT_SNAPSHOT_MAX_BYTES", 40)
    agent_snapshot.write_text('{"user_state": "CONTAINED"}' + " " * 100, encoding="utf-8")
    assert control_daemon._overlay_agent_snapshot(base) == base
    monkeypatch.setattr(control_daemon, "AGENT_SNAPSHOT_MAX_BYTES", 1024)
    assert control_daemon._overlay_agent_snapshot(base)["user_state"] == "CONTAINED"


def test_the_daemon_builds_the_shared_snapshot_with_the_agents_fields(agent_snapshot, monkeypatch, tmp_path):
    shared = tmp_path / "ui_snapshot.json"
    shared.write_text('{"user_state": "CHECKING", "up_if": "eth9"}', encoding="utf-8")
    agent_snapshot.write_text('{"user_state": "LIMITED", "suricata_warning": 2}', encoding="utf-8")
    monkeypatch.setattr(control_daemon, "_snapshot_candidates", lambda: [shared])
    monkeypatch.setattr(control_daemon, "_enrich_snapshot", lambda data: dict(data))
    monkeypatch.setattr(control_daemon, "_snapshot_cache_set", lambda payload: None)
    payload = control_daemon._build_fresh_snapshot_payload({})
    assert payload["snapshot"]["user_state"] == "LIMITED" and payload["snapshot"]["suricata_warning"] == 2
    persisted = json.loads(shared.read_text(encoding="utf-8"))
    assert persisted["user_state"] == "LIMITED" and persisted["up_if"] == "eth9"
    assert json.loads(agent_snapshot.read_text(encoding="utf-8")) == {"user_state": "LIMITED", "suricata_warning": 2}


# ------------------------------------------ moving the audit chain + queue

def _rows(path: Path) -> list:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _statuses(path: Path, event: str) -> list:
    return [r for r in _rows(path) if r.get("record_type") == "relay_status" and r.get("event") == event]


def _alerted_then_down(old: Path):
    audit_path, queue = old / "core-decision-audit.jsonl", old / "p0-alert-queue.jsonl"
    audit = P0AuditLogger(audit_path)
    relay = attach_p0_alert_relay(audit, queue)
    assert relay.ready.wait(5)
    for did in ("a", "b"):
        audit.log_action_decision(did, "s", action="isolate")
    assert audit.wait_durable_listeners(10) and relay.wait_idle(10)
    relay.stop()
    # Written while the relay was down (e.g. the agent stopped for the upgrade).
    P0AuditLogger(audit_path).log_action_decision("while-down", "s", action="isolate")
    return audit_path, queue


def _move(old: Path, new: Path) -> None:
    new.mkdir(exist_ok=True)
    for name in ("core-decision-audit.jsonl", "p0-alert-queue.jsonl"):
        os.replace(old / name, new / name)


def test_a_moved_chain_resumes_from_its_cursor(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    audit_path, _ = _alerted_then_down(old)
    _move(old, new)
    result = migrate_audit_path.carry_cursor(new / "p0-alert-queue.jsonl", audit_path, new / "core-decision-audit.jsonl")
    assert result["carried"] is True, result
    again = attach_p0_alert_relay(P0AuditLogger(new / "core-decision-audit.jsonl"), new / "p0-alert-queue.jsonl")
    assert again.ready.wait(5)
    again.stop()
    started = _statuses(new / "p0-alert-queue.jsonl", "started")[-1]
    assert started["reconcile"] == "cursor_found", started
    assert started["reconciled"] == 1 and started["unreconcilable"] == 0
    alerts = [r for r in _rows(new / "p0-alert-queue.jsonl") if r.get("record_type") == "alert"]
    # a and b once each (two channels), and the decision taken while down.
    assert sorted({r["decision_id"] for r in alerts}) == ["a", "b", "while-down"]
    assert sum(1 for r in alerts if r["decision_id"] == "a") == 2
    migrated = _statuses(new / "p0-alert-queue.jsonl", "audit_path_migrated")
    assert len(migrated) == 1 and migrated[0]["audit_path"] == os.path.abspath(new / "core-decision-audit.jsonl")


def test_without_the_carry_the_moved_chain_is_a_fresh_chain(tmp_path):
    """Why the carry exists: the relay does not recognise the moved file."""
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    _alerted_then_down(old)
    _move(old, new)
    again = attach_p0_alert_relay(P0AuditLogger(new / "core-decision-audit.jsonl"), new / "p0-alert-queue.jsonl")
    assert again.ready.wait(5)
    again.stop()
    assert _statuses(new / "p0-alert-queue.jsonl", "started")[-1]["reconcile"] == "fresh_chain"


def test_the_carry_refuses_what_it_cannot_prove(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    audit_path, _ = _alerted_then_down(old)
    _move(old, new)
    queue, new_audit = new / "p0-alert-queue.jsonl", new / "core-decision-audit.jsonl"
    before = queue.read_bytes()
    # Another chain at the new path (not the moved one).
    other = tmp_path / "other" / "core-decision-audit.jsonl"
    P0AuditLogger(other).log_action_decision("x", "s", action="isolate")
    assert migrate_audit_path.carry_cursor(queue, audit_path, other)["reason"] == "chain_id_differs"
    # A queue with no cursor of the old path.
    assert migrate_audit_path.carry_cursor(queue, tmp_path / "nowhere.jsonl", new_audit)["reason"] == \
        "no_cursor_for_old_path"
    assert migrate_audit_path.carry_cursor(queue, new_audit, new_audit)["reason"] == "same_path"
    assert queue.read_bytes() == before
    # A chain cut back so it no longer has the cursor.
    rows = new_audit.read_text(encoding="utf-8").splitlines()
    new_audit.write_text(rows[0] + "\n", encoding="utf-8")
    assert migrate_audit_path.carry_cursor(queue, audit_path, new_audit)["reason"] == "cursor_not_in_moved_chain"
    assert queue.read_bytes() == before


def test_the_carry_runs_once(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    audit_path, _ = _alerted_then_down(old)
    _move(old, new)
    args = (new / "p0-alert-queue.jsonl", audit_path, new / "core-decision-audit.jsonl")
    assert migrate_audit_path.carry_cursor(*args)["carried"] is True
    assert migrate_audit_path.carry_cursor(*args)["reason"] == "new_path_already_has_a_cursor"
    assert len(_statuses(new / "p0-alert-queue.jsonl", "audit_path_migrated")) == 1


# ------------------------------------------------ unit, tmpfiles, installer

def _unit(name: str) -> dict:
    out: dict = {}
    for line in (ROOT / "systemd" / name).read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.startswith("#") and not line.startswith("["):
            k, v = line.split("=", 1)
            out.setdefault(k, []).append(v)
    return out


def test_the_agent_unit_is_non_root_and_hardened():
    u = _unit("azazel-edge-ai-agent.service")
    assert u["User"] == ["azazel-agent"] and u["Group"] == ["azazel-agent"]
    assert "SupplementaryGroups" not in u
    assert u["NoNewPrivileges"] == ["yes"] and u["CapabilityBoundingSet"] == [""] and u["AmbientCapabilities"] == [""]
    assert u["ProtectSystem"] == ["strict"] and u["ProtectHome"] == ["yes"] and u["PrivateTmp"] == ["yes"]
    assert u["RestrictAddressFamilies"] == ["AF_UNIX AF_INET AF_INET6 AF_NETLINK"]
    assert u["RuntimeDirectory"] == ["azazel-edge-ai"] and u["RuntimeDirectoryMode"] == ["0700"]
    assert u["StateDirectory"] == ["azazel-edge-agent"]
    assert u["ReadWritePaths"] == ["/run/azazel-edge-agent /run/azazel-edge-agent-query /var/log/azazel-edge/ai"]
    assert u["UMask"] == ["0027"]
    assert "WorkingDirectory" not in u  # owner decision: unchanged
    assert u["ExecStartPre"] == ["+/usr/bin/systemd-tmpfiles --create /etc/tmpfiles.d/azazel-edge-agent.conf"]


def test_tmpfiles_creates_the_shared_directories_setgid_for_the_web_ui():
    lines = [l.split() for l in (ROOT / "systemd" / "azazel-edge-agent.tmpfiles.conf").read_text(
        encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
    assert lines == [
        ["d", "/run/azazel-edge-agent", "2750", "azazel-agent", "azazel-web", "-"],
        ["d", "/run/azazel-edge-agent-query", "2750", "azazel-agent", "azazel-web", "-"],
        ["d", "/var/log/azazel-edge/ai", "2750", "azazel-agent", "azazel-web", "-"],
    ]


def test_the_installer_wires_stage_2():
    tools = (ROOT / "installer" / "internal" / "install_migrated_tools.sh").read_text(encoding="utf-8")
    assert "/etc/tmpfiles.d/azazel-edge-agent.conf" in tools
    stop = tools.index("systemctl stop azazel-edge-ai-agent.service")
    assert stop < tools.index("\n/opt/azazel-edge/setup_agent_account.sh") > tools.index("\n/opt/azazel-edge/setup_web_account.sh")
    order = [tools.index(f"systemctl restart {u}") for u in
             ("azazel-edge-control-daemon.service", "azazel-edge-ai-agent.service", "azazel-edge-web.service")]
    assert order == sorted(order)
    wazuh = (ROOT / "installer" / "internal" / "install_wazuh_agent.sh").read_text(encoding="utf-8")
    assert "'/var/lib/azazel-edge-agent'" in wazuh and "'/var/log/azazel-edge'" in wazuh
    script = (ROOT / "installer" / "internal" / "setup_agent_account.sh").read_text(encoding="utf-8")
    assert "azazel_edge.notify.migrate_audit_path" in script
    assert "AZAZEL_VENV_PYTHON" not in script and "PYTHONPATH" not in script
    assert '"$PYTHON" -I -c' in script and "--audit-log-setting" in script
    assert "core-decision-audit.fabric.jsonl" in migrate_audit_path.CHAIN_FILES


def test_the_runbook_loader_reports_an_unreadable_directory(monkeypatch, caplog):
    from azazel_edge import runbooks

    class Denied(type(Path())):
        def exists(self, *a, **k):
            raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(runbooks, "RUNBOOK_DIRS", [Denied("/etc/azazel-edge/runbooks"), runbooks.PROJECT_ROOT / "runbooks"])
    runbooks._UNREADABLE_RUNBOOK_DIRS.clear()
    with caplog.at_level("WARNING"):
        files = list(runbooks._iter_runbook_files())
    assert files  # the shipped runbooks still load
    assert any("not readable" in r.getMessage() for r in caplog.records)


# ------------------------------------------------ review follow-ups

import threading  # noqa: E402


def test_a_fifo_at_the_agent_snapshot_path_does_not_block_the_daemon(agent_snapshot):
    os.mkfifo(agent_snapshot)
    result = {}
    t = threading.Thread(target=lambda: result.update(out=control_daemon._overlay_agent_snapshot({"user_state": "SAFE"})),
                         daemon=True)
    t.start()
    t.join(3)
    assert not t.is_alive(), "the snapshot thread blocked on a FIFO"
    assert result["out"] == {"user_state": "SAFE"}


def test_a_directory_at_the_agent_snapshot_path_is_ignored(agent_snapshot, caplog):
    agent_snapshot.mkdir()
    control_daemon._AGENT_SNAPSHOT_DROPPED["last"] = ""
    with caplog.at_level("WARNING"):
        assert control_daemon._overlay_agent_snapshot({"user_state": "SAFE"}) == {"user_state": "SAFE"}
    assert any("not a regular file" in r.getMessage() for r in caplog.records)


def test_a_fifo_is_reported_as_not_a_regular_file(agent_snapshot, caplog):
    os.mkfifo(agent_snapshot)
    control_daemon._AGENT_SNAPSHOT_DROPPED["last"] = ""
    with caplog.at_level("WARNING"):
        control_daemon._overlay_agent_snapshot({})
    assert any("not a regular file" in r.getMessage() for r in caplog.records)


def test_a_name_that_appears_during_the_move_is_not_replaced(tmp_path, monkeypatch):
    """The move uses link + unlink, which never replaces a name, so even a
    file created after the check (a race) survives."""
    old, new, _ = _old_state(tmp_path)
    (new / "p0-alert-queue.jsonl").write_text("theirs\n", encoding="utf-8")
    real = migrate_audit_path._present
    monkeypatch.setattr(migrate_audit_path, "_present",
                        lambda path: False if Path(path).parent == new else real(path))
    with pytest.raises(FileExistsError):
        migrate_audit_path.migrate_chain(old, new)
    assert (new / "p0-alert-queue.jsonl").read_text(encoding="utf-8") == "theirs\n"
    assert (old / "p0-alert-queue.jsonl").exists()


def test_fields_of_the_wrong_type_are_dropped_and_counted(agent_snapshot):
    agent_snapshot.write_text(json.dumps({
        "user_state": {"nested": "x"}, "recommendation": "ok", "suricata_critical": "9", "suricata_warning": True,
        "suricata_info": 2, "reasons": ["a", 3], "evidence": ["e"] * 40, "llm": ["not", "a", "dict"],
        "advisory_epoch": "now", "attack": {"suricata_alert": True}, "monitoring": {"suricata": {"x": 1}},
        "internal": {"pad": "x" * 70000},
    }), encoding="utf-8")
    before = control_daemon._AGENT_SNAPSHOT_DROPPED["total"]
    merged = control_daemon._overlay_agent_snapshot({"user_state": "SAFE", "monitoring": {"suricata": "UNKNOWN"}})
    assert merged["user_state"] == "SAFE" and merged["recommendation"] == "ok"
    assert merged["suricata_info"] == 2 and merged["attack"] == {"suricata_alert": True}
    for key in ("suricata_critical", "suricata_warning", "reasons", "evidence", "llm", "advisory_epoch", "internal"):
        assert key not in merged, key
    assert merged["monitoring"] == {"suricata": "UNKNOWN"}
    assert control_daemon._AGENT_SNAPSHOT_DROPPED["total"] - before == 9  # 8 fields + monitoring.suricata


def test_every_merged_key_has_a_validator():
    assert set(control_daemon.AGENT_SNAPSHOT_KEYS) == set(control_daemon.AGENT_SNAPSHOT_VALIDATORS)


def _old_state(tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    old.mkdir()
    new.mkdir()
    audit_path, queue = _alerted_then_down(old)
    return old, new, audit_path


def _relay_start(new: Path) -> dict:
    again = attach_p0_alert_relay(P0AuditLogger(new / "core-decision-audit.jsonl"), new / "p0-alert-queue.jsonl")
    assert again.ready.wait(5)
    again.stop()
    return _statuses(new / "p0-alert-queue.jsonl", "started")[-1]


def test_migrate_chain_moves_the_set_and_carries_the_cursor(tmp_path):
    old, new, _ = _old_state(tmp_path)
    out = migrate_audit_path.migrate_chain(old, new)
    assert out["state"] == "moved" and out["carry"]["carried"] is True
    assert not (old / "core-decision-audit.jsonl").exists() and not (old / "p0-alert-queue.jsonl").exists()
    assert _relay_start(new)["reconcile"] == "cursor_found"
    again = migrate_audit_path.migrate_chain(old, new)  # idempotent
    assert again["state"] == "already_moved" and again["carry"]["reason"] == "new_path_already_has_a_cursor"


def test_migrate_chain_finishes_a_move_interrupted_after_the_chain(tmp_path):
    old, new, _ = _old_state(tmp_path)
    os.rename(old / "core-decision-audit.jsonl", new / "core-decision-audit.jsonl")  # crash: queue not moved
    out = migrate_audit_path.migrate_chain(old, new)
    assert out["state"] == "resumed" and "p0-alert-queue.jsonl" in out["moved"]
    assert "core-decision-audit.jsonl" in out["kept_in_new"] and "core-decision-audit.jsonl" not in out["moved"]
    assert out["carry"]["carried"] is True
    assert _relay_start(new)["reconcile"] == "cursor_found"


def test_migrate_chain_finishes_a_move_interrupted_between_link_and_unlink(tmp_path):
    old, new, _ = _old_state(tmp_path)
    os.link(old / "p0-alert-queue.jsonl", new / "p0-alert-queue.jsonl")  # crash before the unlink
    out = migrate_audit_path.migrate_chain(old, new)
    assert out["state"] == "resumed" and out["carry"]["carried"] is True
    assert not (old / "p0-alert-queue.jsonl").exists()


def test_migrate_chain_never_overwrites_the_new_place(tmp_path):
    old, new, _ = _old_state(tmp_path)
    (new / "p0-alert-queue.jsonl").write_text("{}\n", encoding="utf-8")  # another queue already there
    before_old = {n: (old / n).read_bytes() for n in ("core-decision-audit.jsonl", "p0-alert-queue.jsonl")}
    out = migrate_audit_path.migrate_chain(old, new)
    assert out["state"] == "clash" and out["clash"] == ["p0-alert-queue.jsonl"] and out["moved"] == []
    assert (new / "p0-alert-queue.jsonl").read_text(encoding="utf-8") == "{}\n"
    assert not (new / "core-decision-audit.jsonl").exists()
    assert {n: (old / n).read_bytes() for n in before_old} == before_old
    assert migrate_audit_path.main(["--old-dir", str(old), "--new-dir", str(new)]) == 2


def test_migrate_chain_refuses_a_symlink_in_the_set(tmp_path):
    old, new, _ = _old_state(tmp_path)
    target = tmp_path / "elsewhere.jsonl"
    target.write_text("", encoding="utf-8")
    (old / "core-decision-audit.jsonl.1").symlink_to(target)
    out = migrate_audit_path.migrate_chain(old, new)
    assert out["state"] == "not_regular" and out["moved"] == []
    assert (old / "core-decision-audit.jsonl").exists()


@pytest.mark.parametrize("setting", ["/srv/custom/ai-audit.jsonl", '"/srv/custom/ai-audit.jsonl"'])
def test_migrate_chain_moves_nothing_for_a_custom_audit_log(tmp_path, setting):
    old, new, _ = _old_state(tmp_path)
    out = migrate_audit_path.migrate_chain(old, new, setting)
    assert out["state"] == "custom_audit_log" and out["moved"] == []
    assert (old / "core-decision-audit.jsonl").exists() and list(new.iterdir()) == []


@pytest.mark.parametrize("setting", ["", "/var/log/azazel-edge/ai-audit.jsonl", "/var/log/azazel-edge/ai/ai-audit.jsonl"])
def test_migrate_chain_moves_for_a_default_audit_log(tmp_path, setting):
    old, new, _ = _old_state(tmp_path)
    assert migrate_audit_path.migrate_chain(old, new, setting)["state"] == "moved"


def _installer_function(name: str) -> str:
    import re
    src = (ROOT / "installer" / "internal" / "setup_agent_account.sh").read_text(encoding="utf-8")
    m = re.search(r"^" + name + r"\(\) \{\n.*?^\}\n", src, re.S | re.M)
    assert m, name
    return m.group(0)


def test_copy_once_never_writes_through_a_symlink(tmp_path):
    src = tmp_path / "src.json"
    src.write_text('{"a": 1}', encoding="utf-8")
    victim = tmp_path / "victim.json"  # a dangling link's target
    dst = tmp_path / "dst.json"
    dst.symlink_to(victim)
    owner = f"{os.getuid()}:{os.getgid()}"
    script = ("say() { echo \"$*\"; }\n" + _installer_function("copy_once")
              + f'copy_once "{src}" "{dst}" "{owner}" 0640\n')
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert "not written" in res.stdout
    assert not victim.exists() and dst.is_symlink()
    # A normal destination is written, owned and moded.
    dst.unlink()
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0 and not dst.is_symlink() and dst.read_text(encoding="utf-8") == '{"a": 1}'
    assert stat.S_IMODE(dst.stat().st_mode) == 0o640


def test_move_once_never_replaces_a_symlink(tmp_path):
    src = tmp_path / "src.jsonl"
    src.write_text("x\n", encoding="utf-8")
    dst = tmp_path / "dst.jsonl"
    dst.symlink_to(tmp_path / "victim")
    script = "say() { echo \"$*\"; }\n" + _installer_function("move_once") + f'move_once "{src}" "{dst}"\n'
    res = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert res.returncode == 0 and "keep" in res.stdout
    assert src.exists() and dst.is_symlink() and not (tmp_path / "victim").exists()
