"""Rust core decisions reach the P0 alert queue in the running service (Edge#412, Edge#414 SO-03).

The Rust ``azazel-edge-core`` is the authoritative decision and enforcement
path (owner decision on Edge#412). It forwards every decision event to the AI
socket; the AI agent service (``systemd/azazel-edge-ai-agent.service``) is the
receiver. These tests check that the service the unit's ExecStart starts
records the core's P0 decisions and relays them to the P0 queue, that the
event it reads is the shape the core writes (``tests/fixtures/
rust_core_event_v1.json``, pinned on the Rust side by
``the_core_event_has_the_shape_the_agent_is_tested_against``), and that a
failure of the record or the relay never stops the event handling.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.notify.p0_alert import attach_p0_alert_relay  # noqa: E402
from azazel_edge.service_objectives import so03_alert_queue  # noqa: E402
from azazel_edge_ai import agent  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "rust_core_event_v1.json"
UNIT = ROOT / "systemd" / "azazel-edge-ai-agent.service"


def core_event(action: str = "redirect", trace_id: str = "trace-0x1", sid: int = 9300001, mode: str = "dry_run") -> dict:
    event = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event["defense"]["action"] = action
    event["enforcement"]["trace_id"] = trace_id
    event["enforcement"]["mode"] = mode
    event["normalized"]["sid"] = sid
    return event


def _rows(path: Path) -> list:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    return [json.loads(x) for x in data.split(b"\n")[:-1] if x]


def _wait(pred, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return bool(pred())


def _send(sock_path: Path, value: dict) -> None:
    # As the core delivers: one connection per line, write, close.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.connect(str(sock_path))
        conn.sendall((json.dumps(value) + "\n").encode("utf-8"))


def _accepting(sock_path: Path) -> bool:
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(sock_path))
        return True
    except OSError:
        return False


# ------------------------------------------------- the service of the unit


@pytest.fixture
def agent_service(tmp_path):
    """The agent unit's ExecStart script, run as its own process with the
    unit's Environment (paths moved into a scratch directory)."""

    env = dict(os.environ)
    env.update(so03_alert_queue.agent_environment(tmp_path))
    argv = so03_alert_queue.unit_exec_start(UNIT)
    script = so03_alert_queue.agent_service_script(UNIT)
    proc = subprocess.Popen([sys.executable, str(script)], env=env, cwd=str(tmp_path), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = Path(env["AZAZEL_AI_SOCKET"])
    try:
        assert _wait(lambda: _accepting(sock) or proc.poll() is not None), "agent did not start"
        assert proc.poll() is None, "agent exited"
        yield {
            "argv": argv,
            "socket": sock,
            "chain": tmp_path / "log" / "core-decision-audit.jsonl",
            "queue": tmp_path / "log" / "p0-alert-queue.jsonl",
            "proc": proc,
        }
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)


def test_unit_execstart_runs_the_agent_script():
    argv = so03_alert_queue.unit_exec_start(UNIT)
    assert argv[-1] == "/opt/azazel-edge/py/azazel_edge_ai/agent.py"
    assert so03_alert_queue.agent_service_script(UNIT) == ROOT / "py" / "azazel_edge_ai" / "agent.py"


def test_the_service_relays_core_p0_decisions_to_the_queue(agent_service):
    """Rust core event format -> agent service of the unit -> durable chain -> P0 queue."""

    sock, chain, queue = agent_service["socket"], agent_service["chain"], agent_service["queue"]
    _send(sock, core_event("notify", "trace-0xa", 9300010))
    _send(sock, core_event("observe", "trace-0xb", 9300011))
    _send(sock, core_event("redirect", "trace-0xc", 9300012))
    _send(sock, core_event("isolate", "trace-0xd", 9300013, mode="policy_gated"))
    assert _wait(lambda: len([r for r in _rows(queue) if r.get("record_type") == "alert"]) >= 4)
    alerts = [r for r in _rows(queue) if r.get("record_type") == "alert"]
    by_decision: dict = {}
    for r in alerts:
        by_decision.setdefault(r["decision_id"], []).append(r)
    # Only the P0 decisions: notify and observe (no SOC label) are not P0.
    assert set(by_decision) == {"trace-0xc", "trace-0xd"}
    for decision_id, action, mode in (("trace-0xc", "redirect", "dry_run"), ("trace-0xd", "isolate", "policy_gated")):
        rows = by_decision[decision_id]
        assert sorted(r["channel"] for r in rows) == ["visual", "voice"]
        assert all(r["p0_basis"] == f"enforcement:{action}" and r["decision_source"] == "azazel-edge-core" for r in rows)
        assert all(r["enforcement_mode"] == mode and r["effective_action"] == "redirect" for r in rows)
        assert all(r["decision_record_durable"] is True for r in rows)
    records = _rows(chain)
    # One connection per line, each handled on its own thread: any order.
    assert sorted((r["kind"], r["trace_id"], r["sid"]) for r in records) == [
        ("action_decision", "trace-0xc", 9300012),
        ("action_decision", "trace-0xd", 9300013),
    ]
    assert all(r["enforce_enabled"] is False and r["enforce_dry_run"] is True for r in records)
    assert P0AuditLogger.verify_chain(chain)["ok"] is True


def test_the_service_reports_core_forward_losses_in_the_queue(agent_service):
    sock, queue = agent_service["socket"], agent_service["queue"]
    _send(sock, {"schema": "azazel-edge/forward-stats/v1", "dropped": 0, "failed": 0, "sent": 5, "since": 1790000000})
    _send(sock, {"schema": "azazel-edge/forward-stats/v1", "dropped": 3, "failed": 1, "sent": 9, "since": 1790000000})
    assert _wait(lambda: any(r.get("event") == "core_forward_loss" for r in _rows(queue)))
    losses = [r for r in _rows(queue) if r.get("event") == "core_forward_loss"]
    assert len(losses) == 1
    assert losses[0]["record_type"] == "relay_status"
    assert (losses[0]["core_forward_dropped"], losses[0]["core_forward_failed"]) == (3, 1)


# ------------------------------------------------------ in-process checks


@pytest.fixture
def handler_paths(tmp_path, monkeypatch):
    for name in ("ADVISORY_PATH", "EVENT_LOG_PATH", "SNAPSHOT_PATH", "METRICS_PATH", "POLICY_PATH",
                 "LLM_DEFERRED_LOG_PATH", "LLM_RESULT_LOG_PATH"):
        monkeypatch.setattr(agent, name, tmp_path / name.lower())
    monkeypatch.setattr(agent, "_route_llm", lambda event, advisory: None)
    return tmp_path


def test_payload_is_the_cores_decision_copied_not_redecided():
    trace_id, payload = agent._core_decision_payload(core_event("throttle", "trace-0x9", 9300020))
    assert trace_id == "trace-0x9"
    assert payload["action"] == "throttle"
    assert payload["effective_action"] == "redirect"  # the fixture's selected_action, as the core sent it
    assert payload["enforcement_mode"] == "dry_run" and payload["enforcement_result"] == "planned_not_applied"
    assert payload["sid"] == 9300020 and payload["core_pipeline"] == "rust_event_engine_v1"
    for broken in (
        dict(core_event(), source="other"),
        dict(core_event(), pipeline="rust_release_engine_v1"),
        {k: v for k, v in core_event().items() if k != "enforcement"},
        {"action": "manual_query"},
    ):
        assert agent._core_decision_payload(broken) is None


def test_nothing_is_recorded_until_the_service_starts(handler_paths, monkeypatch):
    monkeypatch.setattr(agent, "CORE_DECISION_AUDIT", None)
    agent._handle_event(core_event("isolate"))
    assert not (handler_paths / "log").exists()


class _Broken:
    def log_action_decision(self, **kwargs):
        raise OSError(28, "No space left on device")


def test_a_failed_record_never_stops_the_event_handling(handler_paths, monkeypatch):
    monkeypatch.setattr(agent, "CORE_DECISION_AUDIT", _Broken())
    agent._handle_event(core_event("isolate"))
    assert (handler_paths / "event_log_path").read_text(encoding="utf-8").count("\n") == 1
    assert json.loads((handler_paths / "advisory_path").read_text(encoding="utf-8"))


def test_a_failed_relay_keeps_the_decision_for_the_next_start(handler_paths, monkeypatch, tmp_path):
    """The relay cannot enqueue (its queue path is unusable): the event is
    handled, the decision stays in the chain, and the next start's reconcile
    (#458) puts it in the queue."""

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    broken_queue = blocker / "q.jsonl"
    with pytest.raises(OSError):
        attach_p0_alert_relay(audit, broken_queue)
    monkeypatch.setattr(agent, "CORE_DECISION_AUDIT", audit)
    agent._handle_event(core_event("redirect", "trace-0xe", 9300030))
    assert (handler_paths / "event_log_path").read_text(encoding="utf-8").count("\n") == 1
    assert [r["trace_id"] for r in _rows(audit.path)] == ["trace-0xe"]
    good_queue = tmp_path / "p0-alert-queue.jsonl"
    relay = attach_p0_alert_relay(P0AuditLogger(audit.path), good_queue)
    try:
        assert relay.ready.wait(10)
        alerts = [r for r in _rows(good_queue) if r.get("record_type") == "alert"]
        assert sorted(r["channel"] for r in alerts) == ["visual", "voice"]
        assert all(r["decision_id"] == "trace-0xe" and r["decision_record_durability"].startswith("reconciled") for r in alerts)
    finally:
        relay.stop()


def test_the_relay_failing_after_start_is_counted_and_handling_goes_on(handler_paths, monkeypatch, tmp_path):
    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    try:
        assert relay.ready.wait(10)

        def refuse(*a, **k):
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(relay.queue, "enqueue", refuse)
        monkeypatch.setattr(agent, "CORE_DECISION_AUDIT", audit)
        for n in range(3):
            agent._handle_event(core_event("throttle", f"trace-0x{n}", 9300040 + n))
        assert audit.wait_durable_listeners(10) and relay.wait_idle(10)
        assert relay.metrics()["enqueue_failed_total"] == 3
        assert (handler_paths / "event_log_path").read_text(encoding="utf-8").count("\n") == 3
        assert len(_rows(audit.path)) == 3
    finally:
        relay.stop()


def test_the_start_path_is_idempotent_and_survives_an_unusable_directory(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(agent, "CORE_DECISION_AUDIT", None)
    monkeypatch.setattr(agent, "CORE_P0_RELAY", None)
    monkeypatch.setattr(agent, "CORE_DECISION_AUDIT_PATH", blocker / "core-decision-audit.jsonl")
    monkeypatch.setattr(agent, "P0_ALERT_QUEUE_PATH", blocker / "p0-alert-queue.jsonl")
    assert agent._start_core_p0_path() is None
    assert agent.CORE_DECISION_AUDIT is None
    monkeypatch.setattr(agent, "CORE_DECISION_AUDIT_PATH", tmp_path / "core-decision-audit.jsonl")
    monkeypatch.setattr(agent, "P0_ALERT_QUEUE_PATH", tmp_path / "p0-alert-queue.jsonl")
    relay = agent._start_core_p0_path()
    try:
        assert relay is not None and agent._start_core_p0_path() is relay
        assert relay.on_durable_record in agent.CORE_DECISION_AUDIT._durable_listeners
    finally:
        relay.stop()

