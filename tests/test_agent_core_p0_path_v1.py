"""Rust core decisions reach the P0 alert queue in the running service (Edge#412, Edge#414 SO-03).

The Rust ``azazel-edge-core`` is the authoritative decision and enforcement
path (owner decision on Edge#412). It forwards every decision event to the AI
socket; the AI agent service (``systemd/azazel-edge-ai-agent.service``) is the
receiver. These tests check that the service the unit's ExecStart starts
records the core's P0 decisions and relays them to the P0 queue, that the
event it reads is the shape the core writes (``tests/fixtures/
rust_core_event_v1.json``, pinned on the Rust side by
``the_core_event_has_the_shape_the_agent_is_tested_against``), and that a
failure of the record or the relay never stops the event handling. P0 is
classified by what the core does (``enforcement.selected_action``); decisions
the core took while the agent was down are reconciled from the core's
normalized event log at start, once.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.notify import core_decisions  # noqa: E402
from azazel_edge.notify.core_decisions import CoreDecisionRecorder  # noqa: E402
from azazel_edge.notify.p0_alert import attach_p0_alert_relay  # noqa: E402
from azazel_edge.service_objectives import so03_alert_queue  # noqa: E402
from azazel_edge_ai import agent as agent_mod  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "rust_core_event_v1.json"
UNIT = ROOT / "systemd" / "azazel-edge-ai-agent.service"


def core_event(action: str = "redirect", trace_id: str = "trace-0x1", sid: int = 9300001, mode: str = "dry_run",
               effective: str | None = None) -> dict:
    """The core's event (fixture) with its decided and effective action set."""

    event = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event["defense"]["action"] = action
    event["enforcement"]["selected_action"] = action if effective is None else effective
    event["enforcement"]["trace_id"] = trace_id
    event["enforcement"]["mode"] = mode
    event["normalized"]["sid"] = sid
    return event


def _alerts(queue: Path) -> list:
    return [r for r in _rows(queue) if r.get("record_type") == "alert"]


def _statuses(queue: Path, event: str) -> list:
    return [r for r in _rows(queue) if r.get("record_type") == "relay_status" and r.get("event") == event]


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


class _Agent:
    """The agent unit's ExecStart script, run as its own process with the
    unit's Environment (paths moved into ``work``). Can be stopped and
    started again on the same files."""

    def __init__(self, work: Path):
        self.work = work
        self.env = dict(os.environ)
        self.env.update(so03_alert_queue.agent_environment(work))
        self.socket = Path(self.env["AZAZEL_AI_SOCKET"])
        self.chain = work / "log" / "core-decision-audit.jsonl"
        self.queue = work / "log" / "p0-alert-queue.jsonl"
        self.proc: subprocess.Popen | None = None

    def start(self) -> "_Agent":
        script = so03_alert_queue.agent_service_script(UNIT)
        self.proc = subprocess.Popen([sys.executable, str(script)], env=self.env, cwd=str(self.work),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert _wait(lambda: _accepting(self.socket) or self.proc.poll() is not None), "agent did not start"
        assert self.proc.poll() is None, "agent exited"
        return self

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=10)


@pytest.fixture
def agent_service(tmp_path):
    svc = _Agent(tmp_path).start()
    try:
        yield svc
    finally:
        svc.stop()


class _Core:
    """The release core binary with its unit's Environment (paths in ``work``)."""

    def __init__(self, binary: Path, work: Path, socket_path: Path, **env: str):
        self.work = work
        self.eve = work / "eve.json"
        self.log = work / "normalized-events.jsonl"
        self.eve.write_text("", encoding="utf-8")
        environ = so03_alert_queue.core_environment(work, socket_path)
        environ.update(env)
        self.stderr = work / "core.stderr"
        self._err = self.stderr.open("w", encoding="utf-8")
        self.proc = subprocess.Popen([str(binary)], cwd=str(work), env=environ, stdout=subprocess.DEVNULL, stderr=self._err)
        assert _wait(lambda: "azazel-edge-core started" in self.stderr.read_text(encoding="utf-8", errors="replace"))
        self.n = 0

    def alert(self, severity: int, port: int = 22) -> int:
        self.n += 1
        sid = 9_310_000 + self.n
        with self.eve.open("a", encoding="utf-8") as fh:
            fh.write(so03_alert_queue._eve_line(self.n, severity, port, sid) + "\n")
        return sid

    def logged(self) -> int:
        return len(_rows(self.log))

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)
        self._err.close()


def test_unit_execstart_runs_the_agent_script():
    argv = so03_alert_queue.unit_exec_start(UNIT)
    assert argv[-1] == "/opt/azazel-edge/py/azazel_edge_ai/agent.py"
    assert so03_alert_queue.agent_service_script(UNIT) == ROOT / "py" / "azazel_edge_ai" / "agent.py"


def test_the_service_relays_core_p0_decisions_to_the_queue(agent_service):
    """Rust core event format -> agent service of the unit -> durable chain -> P0 queue."""

    sock, chain, queue = agent_service.socket, agent_service.chain, agent_service.queue
    _send(sock, core_event("notify", "trace-0xa", 9300010))
    _send(sock, core_event("observe", "trace-0xb", 9300011))
    _send(sock, core_event("redirect", "trace-0xc", 9300012))
    _send(sock, core_event("isolate", "trace-0xd", 9300013, mode="policy_gated"))
    # A redirect the policy turned into notify: no enforcement, not P0.
    _send(sock, core_event("redirect", "trace-0xe", 9300014, effective="notify"))
    # A redirect the policy turned into isolate: P0, as isolate.
    _send(sock, core_event("redirect", "trace-0xf", 9300015, effective="isolate"))
    assert _wait(lambda: len(_alerts(queue)) >= 6)
    time.sleep(0.5)  # anything else would have arrived by now
    by_sid: dict = {}
    for r in _rows(chain):
        by_sid[r["sid"]] = r
    assert set(by_sid) == {9300012, 9300013, 9300015}
    assert (by_sid[9300015]["action"], by_sid[9300015]["decided_action"]) == ("isolate", "redirect")
    by_decision: dict = {}
    for r in _alerts(queue):
        by_decision.setdefault(r["decision_id"], []).append(r)
    assert len(by_decision) == 3
    for sid, basis, mode in ((9300012, "redirect", "dry_run"), (9300013, "isolate", "policy_gated"), (9300015, "isolate", "dry_run")):
        rows = by_decision[by_sid[sid]["trace_id"]]
        assert sorted(r["channel"] for r in rows) == ["visual", "voice"]
        assert all(r["p0_basis"] == f"enforcement:{basis}" and r["decision_source"] == "azazel-edge-core" for r in rows)
        assert all(r["enforcement_mode"] == mode and r["effective_action"] == basis for r in rows)
        assert all(r["decision_record_durable"] is True for r in rows)
    assert all(r["enforce_enabled"] is False and r["enforce_dry_run"] is True for r in by_sid.values())
    assert P0AuditLogger.verify_chain(chain)["ok"] is True


def test_the_same_core_event_twice_is_one_alert(agent_service):
    event = core_event("throttle", "trace-0x7", 9300020)
    _send(agent_service.socket, event)
    _send(agent_service.socket, event)
    other_port = core_event("throttle", "trace-0x7", 9300020)
    other_port["normalized"]["target_port"] = 2222  # same core trace id, another port: another event
    _send(agent_service.socket, other_port)
    assert _wait(lambda: len(_alerts(agent_service.queue)) >= 4)
    time.sleep(0.5)
    assert len(_rows(agent_service.chain)) == 2
    assert len(_alerts(agent_service.queue)) == 4


def test_the_service_reports_core_forward_losses_in_the_queue(agent_service):
    sock, queue = agent_service.socket, agent_service.queue
    _send(sock, {"schema": "azazel-edge/forward-stats/v1", "dropped": 0, "failed": 0, "sent": 5, "since": 1790000000})
    _send(sock, {"schema": "azazel-edge/forward-stats/v1", "dropped": 3, "failed": 1, "sent": 9, "since": 1790000000})
    assert _wait(lambda: bool(_statuses(queue, "core_forward_loss")))
    losses = _statuses(queue, "core_forward_loss")
    assert len(losses) == 1
    assert (losses[0]["core_forward_dropped"], losses[0]["core_forward_failed"]) == (3, 1)


# ------------------------------------------- with the real core binary


def test_a_redirect_the_policy_turns_into_notify_is_not_p0(tmp_path, rust_core_bin):
    policy = tmp_path / "redirect_policy.yaml"
    policy.write_text("redirect_policy:\n  enabled: false\n", encoding="utf-8")
    agent = _Agent(tmp_path).start()
    core = _Core(rust_core_bin, tmp_path, agent.socket, AZAZEL_REDIRECT_POLICY_PATH=str(policy))
    try:
        redirect_sid = core.alert(2, 22)
        isolate_sid = core.alert(1, 22)
        assert _wait(lambda: core.logged() == 2)
        assert _wait(lambda: len(_alerts(agent.queue)) >= 2)
        time.sleep(0.5)
        logged = {r["normalized"]["sid"]: r for r in _rows(core.log)}
        assert (logged[redirect_sid]["defense"]["action"], logged[redirect_sid]["enforcement"]["selected_action"]) == ("redirect", "notify")
        assert logged[redirect_sid]["enforcement"]["mode"] == "disabled"
        assert [r["sid"] for r in _rows(agent.chain)] == [isolate_sid]
        assert {r["p0_basis"] for r in _alerts(agent.queue)} == {"enforcement:isolate"}
    finally:
        core.stop()
        agent.stop()


def test_dry_run_computes_the_effective_action(tmp_path, rust_core_bin):
    agent = _Agent(tmp_path).start()
    core = _Core(rust_core_bin, tmp_path, agent.socket)
    try:
        sids = {core.alert(2, 22): "redirect", core.alert(2, 443): "isolate", core.alert(3): "throttle"}
        assert _wait(lambda: core.logged() == 3)
        for r in _rows(core.log):
            assert r["enforcement"]["mode"] == "dry_run"
            assert r["enforcement"]["selected_action"] == sids[r["normalized"]["sid"]]
        assert _wait(lambda: len(_rows(agent.chain)) == 3)
        assert {r["sid"]: r["action"] for r in _rows(agent.chain)} == sids
    finally:
        core.stop()
        agent.stop()


def test_decisions_taken_while_the_agent_is_down_are_reconciled_once(tmp_path, rust_core_bin):
    agent = _Agent(tmp_path)
    core = _Core(rust_core_bin, tmp_path, agent.socket)
    try:
        # The agent is down: the core decides, logs, and cannot forward.
        down = [core.alert(1), core.alert(3), core.alert(4)]  # isolate, throttle, notify
        assert _wait(lambda: core.logged() == 3)
        agent.start()
        assert _wait(lambda: len(_rows(agent.chain)) == 2)
        records = _rows(agent.chain)
        assert sorted(r["sid"] for r in records) == sorted(down[:2])
        assert all(r["recorded_by"] == "startup_reconcile" for r in records)
        assert _wait(lambda: len(_alerts(agent.queue)) == 4)
        first = _statuses(agent.queue, "core_reconcile")
        assert len(first) == 1 and first[0]["core_reconciled"] == 2 and first[0]["core_reconcile"] == "done"
        # Live again.
        live = core.alert(3)
        assert _wait(lambda: len(_rows(agent.chain)) == 3)
        assert _rows(agent.chain)[-1]["sid"] == live and _rows(agent.chain)[-1]["recorded_by"] == "live"
        # Restart: everything in the log is already in the chain.
        agent.stop()
        agent.start()
        assert _wait(lambda: len(_statuses(agent.queue, "core_reconcile")) == 2)
        second = _statuses(agent.queue, "core_reconcile")[-1]
        assert second["core_reconciled"] == 0 and second["core_reconcile_newest_chain_decision_in_log"] is True
        time.sleep(0.5)
        assert len(_rows(agent.chain)) == 3
        assert len(_alerts(agent.queue)) == 6
        assert len({r["decision_id"] for r in _alerts(agent.queue)}) == 3
    finally:
        core.stop()
        agent.stop()


# ------------------------------------------------------ in-process checks


@pytest.fixture
def handler_paths(tmp_path, monkeypatch):
    for name in ("ADVISORY_PATH", "EVENT_LOG_PATH", "SNAPSHOT_PATH", "METRICS_PATH", "POLICY_PATH",
                 "LLM_DEFERRED_LOG_PATH", "LLM_RESULT_LOG_PATH"):
        monkeypatch.setattr(agent_mod, name, tmp_path / name.lower())
    monkeypatch.setattr(agent_mod, "_route_llm", lambda event, advisory: None)
    return tmp_path


def test_payload_is_the_cores_decision_copied_not_redecided():
    trace_id, payload = core_decisions.core_decision_payload(core_event("redirect", "trace-0x9", 9300020, effective="isolate"))
    assert trace_id == "core-" + payload["core_event_key"][:32]
    assert payload["core_trace_id"] == "trace-0x9"
    assert (payload["action"], payload["decided_action"], payload["effective_action"]) == ("isolate", "redirect", "isolate")
    assert payload["enforcement_mode"] == "dry_run" and payload["enforcement_result"] == "planned_not_applied"
    assert payload["sid"] == 9300020 and payload["target_port"] == 22 and payload["core_pipeline"] == "rust_event_engine_v1"
    assert core_decisions.is_p0(payload)
    _, fallback = core_decisions.core_decision_payload(core_event("redirect", effective="notify"))
    assert not core_decisions.is_p0(fallback)
    for broken in (
        dict(core_event(), source="other"),
        dict(core_event(), pipeline="rust_release_engine_v1"),
        {k: v for k, v in core_event().items() if k != "enforcement"},
        {"action": "manual_query"},
    ):
        assert core_decisions.core_decision_payload(broken) is None


def test_the_event_key_is_built_from_the_core_events_fields():
    base = core_event()
    assert core_decisions.core_event_key(base) == core_decisions.core_event_key(core_event())
    for path, value in ((("normalized", "ts"), "x"), (("normalized", "sid"), 1), (("normalized", "src_ip"), "x"),
                        (("normalized", "dst_ip"), "x"), (("normalized", "target_port"), 1),
                        (("normalized", "protocol"), "UDP"), (("defense", "action"), "throttle")):
        other = core_event()
        other[path[0]][path[1]] = value
        assert core_decisions.core_event_key(other) != core_decisions.core_event_key(base), path


def test_nothing_is_recorded_until_the_service_starts(handler_paths, monkeypatch):
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", None)
    agent_mod._handle_event(core_event("isolate"))
    assert not (handler_paths / "log").exists()


class _Broken:
    def submit(self, event):
        raise OSError(28, "No space left on device")


def test_a_failed_hand_off_never_stops_the_event_handling(handler_paths, monkeypatch):
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", _Broken())
    agent_mod._handle_event(core_event("isolate"))
    assert (handler_paths / "event_log_path").read_text(encoding="utf-8").count("\n") == 1
    assert json.loads((handler_paths / "advisory_path").read_text(encoding="utf-8"))


def test_a_failed_relay_keeps_the_decision_for_the_next_start(tmp_path):
    """No relay (its queue path is unusable): the decision stays in the chain,
    and the next start's relay reconcile (#458) puts it in the queue."""

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    recorder = CoreDecisionRecorder(audit, None, None).start()
    try:
        recorder.submit(core_event("redirect", "trace-0xe", 9300030))
        assert recorder.wait_idle(10)
    finally:
        recorder.stop()
    assert [r["core_trace_id"] for r in _rows(audit.path)] == ["trace-0xe"]
    good_queue = tmp_path / "p0-alert-queue.jsonl"
    relay = attach_p0_alert_relay(P0AuditLogger(audit.path), good_queue)
    try:
        assert relay.ready.wait(10)
        alerts = _alerts(good_queue)
        assert sorted(r["channel"] for r in alerts) == ["visual", "voice"]
        assert all(r["decision_record_durability"].startswith("reconciled") for r in alerts)
    finally:
        relay.stop()


def test_a_failed_chain_write_is_counted_in_the_queue(tmp_path, monkeypatch):
    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    recorder = CoreDecisionRecorder(audit, relay, None).start()
    try:
        assert recorder.ready.wait(10)

        def refuse(**kwargs):
            raise OSError(5, "Input/output error")

        monkeypatch.setattr(audit, "log_action_decision", refuse)
        for n in range(3):
            recorder.submit(core_event("throttle", f"trace-0x{n}", 9300040 + n))
        assert recorder.wait_idle(10)
        assert _wait(lambda: any(s.get("core_record_failed_total") == 3 for s in _statuses(relay.queue.path, "core_record_loss")))
    finally:
        recorder.stop()
        relay.stop()


def test_slow_fsync_never_holds_the_receiver_and_overflow_is_counted(tmp_path, monkeypatch):
    """Load: every fsync takes 50 ms. Handing 120 P0 decisions from 6
    threads never waits on a write; what the bounded queue cannot take is
    counted and written to the P0 queue, never dropped silently."""

    real_fsync = os.fsync

    def slow_fsync(fd):
        time.sleep(0.05)
        return real_fsync(fd)

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    recorder = CoreDecisionRecorder(audit, relay, None, max_pending=8).start()
    try:
        assert recorder.ready.wait(10) and relay.ready.wait(10)
        monkeypatch.setattr(os, "fsync", slow_fsync)
        waits: list = []
        lock = threading.Lock()

        def hand(base: int) -> None:
            for n in range(20):
                t0 = time.monotonic()
                recorder.submit(core_event("throttle", f"trace-{base}-{n}", 9_400_000 + base * 100 + n))
                with lock:
                    waits.append(time.monotonic() - t0)

        threads = [threading.Thread(target=hand, args=(b,)) for b in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert max(waits) < 0.05, max(waits)  # never one fsync long
        assert recorder.wait_idle(60)
        m = recorder.metrics()
        assert m["core_record_handoff_dropped_total"] > 0
        assert m["core_recorded_total"] + m["core_record_handoff_dropped_total"] == 120
        assert len(_rows(audit.path)) == m["core_recorded_total"]
        assert _wait(lambda: any(
            s.get("core_record_handoff_dropped_total") == m["core_record_handoff_dropped_total"]
            for s in _statuses(relay.queue.path, "core_record_loss")
        ), timeout=30)
    finally:
        monkeypatch.setattr(os, "fsync", real_fsync)
        recorder.stop()
        relay.stop()


def test_reconcile_counts_what_it_could_not_read(tmp_path):
    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    log = tmp_path / "normalized-events.jsonl"
    lines = [json.dumps(core_event("isolate", f"t{n}", 9300100 + n)) for n in range(5)]
    log.write_text("not json\n" + "\n".join(lines) + "\n" + '{"torn": ', encoding="utf-8")
    recorder = CoreDecisionRecorder(audit, relay, log, max_reconcile=3).start()
    try:
        assert recorder.ready.wait(10)
        status = recorder.last_reconcile
        assert (status["core_reconciled"], status["core_reconcile_skipped"], status["core_reconcile_unparseable"]) == (3, 2, 1)
        # The newest three, as #458 replays the newest.
        assert sorted(r["sid"] for r in _rows(audit.path)) == [9300102, 9300103, 9300104]
    finally:
        recorder.stop()
        relay.stop()
    missing = CoreDecisionRecorder(P0AuditLogger(tmp_path / "other.jsonl"), None, tmp_path / "absent.jsonl")
    assert missing.reconcile()["core_reconcile"] == "normalized_log_missing"


def test_the_start_path_is_idempotent_and_survives_an_unusable_directory(monkeypatch, tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(agent_mod, "CORE_DECISION_AUDIT", None)
    monkeypatch.setattr(agent_mod, "CORE_P0_RELAY", None)
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", None)
    monkeypatch.setattr(agent_mod, "CORE_NORMALIZED_EVENT_LOG", tmp_path / "normalized-events.jsonl")
    monkeypatch.setattr(agent_mod, "CORE_DECISION_AUDIT_PATH", blocker / "core-decision-audit.jsonl")
    monkeypatch.setattr(agent_mod, "P0_ALERT_QUEUE_PATH", blocker / "p0-alert-queue.jsonl")
    assert agent_mod._start_core_p0_path() is None
    assert agent_mod.CORE_DECISION_AUDIT is None and agent_mod.CORE_RECORDER is None
    monkeypatch.setattr(agent_mod, "CORE_DECISION_AUDIT_PATH", tmp_path / "core-decision-audit.jsonl")
    monkeypatch.setattr(agent_mod, "P0_ALERT_QUEUE_PATH", tmp_path / "p0-alert-queue.jsonl")
    relay = agent_mod._start_core_p0_path()
    try:
        assert relay is not None and agent_mod._start_core_p0_path() is relay
        assert relay.on_durable_record in agent_mod.CORE_DECISION_AUDIT._durable_listeners
        assert agent_mod.CORE_RECORDER.ready.wait(10)
    finally:
        agent_mod.CORE_RECORDER.stop()
        relay.stop()
