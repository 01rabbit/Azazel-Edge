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
from datetime import datetime, timezone
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


def _now_ts(offset_s: float = 0.0) -> str:
    return datetime.fromtimestamp(time.time() + offset_s, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def fresh(event: dict, offset_s: float = 0.0) -> dict:
    """The event as if Suricata had stamped it ``offset_s`` seconds from now."""

    event["normalized"]["ts"] = _now_ts(offset_s)
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
        # Marked as not live, with the event's own time.
        assert all(r["reconciled"] is True and r["recorded_by"] == "startup_reconcile" and r["event_ts"] for r in _alerts(agent.queue))
        # Within the lease: current alerts, not past decisions.
        assert all(r["stale"] is False and r["presentation"] == "current" for r in _alerts(agent.queue))
        first = _statuses(agent.queue, "core_reconcile")
        assert len(first) == 1 and first[0]["core_reconciled"] == 2 and first[0]["core_reconcile"] == "done"
        # Live again.
        live = core.alert(3)
        assert _wait(lambda: len(_rows(agent.chain)) == 3)
        assert _rows(agent.chain)[-1]["sid"] == live and _rows(agent.chain)[-1]["recorded_by"] == "live"
        assert _wait(lambda: len(_alerts(agent.queue)) == 6)
        assert [r["reconciled"] for r in _alerts(agent.queue)[-2:]] == [False, False]
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
    lines = [json.dumps(fresh(core_event("isolate", f"t{n}", 9300100 + n))) for n in range(5)]
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


def _stale_log(tmp_path: Path) -> tuple:
    log = tmp_path / "normalized-events.jsonl"
    old = [fresh(core_event("isolate", f"o{n}", 9300200 + n), -3600 - n) for n in range(4)]
    just_over = fresh(core_event("throttle", "o9", 9300209), -core_decisions.DEFAULT_RECONCILE_MAX_AGE_S - 5)
    undated = core_event("isolate", "u", 9300210)
    undated["normalized"]["ts"] = "not a time"
    undated["normalized"].pop("ingest_epoch")
    recent = fresh(core_event("throttle", "r", 9300211), -30)
    log.write_text("".join(json.dumps(e) + "\n" for e in old + [just_over, undated, recent]), encoding="utf-8")
    return log, recent


def test_reconcile_alerts_stale_decisions_as_past_decisions(tmp_path):
    """First start (empty chain) on an old log (Edge#462 item 5, option b):
    decisions older than the bound, or of unknown time, are recorded and
    alerted, marked stale and presented as past decisions; the recent one is
    a current (reconciled) alert."""

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    log, recent = _stale_log(tmp_path)
    recorder = CoreDecisionRecorder(audit, relay, log).start()
    try:
        assert recorder.ready.wait(10)
        status = recorder.last_reconcile
        assert status["core_reconcile_stale"] == 6 and status["core_reconciled_stale"] == 6
        assert status["core_reconciled"] == 7
        assert status["core_reconcile_max_age_s"] == core_decisions.DEFAULT_RECONCILE_MAX_AGE_S
        assert recorder.metrics()["core_reconciled_stale_total"] == 6
        chain = _rows(audit.path)
        assert [r["sid"] for r in chain] == list(range(9300200, 9300204)) + [9300209, 9300210, 9300211]
        assert all(r["recorded_by"] == "startup_reconcile" for r in chain)
        assert [r.get("reconcile_stale") is True for r in chain] == [True] * 6 + [False]
        assert chain[0]["reconcile_event_age_s"] >= 3599 and chain[5]["reconcile_event_age_s"] is None
        assert _wait(lambda: len(_alerts(relay.queue.path)) == 14)
        alerts = _alerts(relay.queue.path)
        assert all(r["reconciled"] is True for r in alerts)
        current = [r for r in alerts if r["event_ts"] == recent["normalized"]["ts"]]
        assert len(current) == 2
        assert all(r["stale"] is False and r["presentation"] == "current" for r in current)
        assert all(not r["display_text"].startswith("【過去の判定") for r in current)
        assert [r["voice_urgent"] for r in current if r["channel"] == "voice"] == [True]
        past = [r for r in alerts if r not in current]
        assert len(past) == 12
        assert all(r["stale"] is True and r["presentation"] == "historical" and r["event_ts"] for r in past)
        assert all(r["voice_urgent"] is False for r in past if r["channel"] == "voice")
        assert all(r["display_text"].startswith("【過去の判定（") for r in past if r["channel"] == "visual")
        assert all(r["display_text"].startswith("過去の判定（") and "現在の警報ではありません" in r["display_text"]
                   for r in past if r["channel"] == "voice")
        assert sum("時刻不明" in r["display_text"] for r in past) == 2  # the undated one, both channels
        assert _statuses(relay.queue.path, "core_reconcile")[0]["core_reconciled_stale"] == 6
    finally:
        recorder.stop()
        relay.stop()


def test_stale_decisions_are_alerted_once_across_restarts(tmp_path):
    """A stale decision is in the chain under its core event key after the
    first start: the next start neither records nor alerts it again, and the
    relay's chain cursor resumes where it was."""

    chain_path = tmp_path / "core-decision-audit.jsonl"
    queue_path = tmp_path / "p0-alert-queue.jsonl"
    log, _ = _stale_log(tmp_path)
    for start in range(3):
        audit = P0AuditLogger(chain_path)
        relay = attach_p0_alert_relay(audit, queue_path)
        recorder = CoreDecisionRecorder(audit, relay, log).start()
        try:
            assert recorder.ready.wait(10) and relay.ready.wait(10)
            assert recorder.wait_idle(10) and relay.wait_idle(10)
            status = recorder.last_reconcile
            if start == 0:
                assert status["core_reconciled"] == 7 and status["core_reconciled_stale"] == 6
            else:
                assert status["core_reconciled"] == 0 and status["core_reconciled_stale"] == 0
                assert status["core_reconcile_stale"] == 0
            assert _wait(lambda: len(_alerts(queue_path)) == 14)
        finally:
            recorder.stop()
            relay.stop()
    assert len(_rows(chain_path)) == 7
    started = _statuses(queue_path, "started")
    assert [s["reconcile"] for s in started] == ["fresh_queue", "cursor_found", "cursor_found"]
    assert all(s["reconciled"] == 0 and s["unreconcilable"] == 0 for s in started)
    time.sleep(0.3)
    assert len(_alerts(queue_path)) == 14
    assert len({r["decision_id"] for r in _alerts(queue_path)}) == 7


def test_a_long_outage_does_not_flood_the_queue(tmp_path):
    """Stale and fresh decisions share the one reconcile bound: the newest
    ``max_reconcile`` are recorded, the rest counted as skipped."""

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    log = tmp_path / "normalized-events.jsonl"
    events = [fresh(core_event("isolate", f"x{n}", 9300600 + n), -7200 + n) for n in range(10)]
    events.append(fresh(core_event("throttle", "y", 9300699), -10))
    log.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    recorder = CoreDecisionRecorder(audit, relay, log, max_reconcile=4).start()
    try:
        assert recorder.ready.wait(10)
        status = recorder.last_reconcile
        assert status["core_reconcile_stale"] == 10 and status["core_reconcile_skipped"] == 7
        assert status["core_reconciled"] == 4 and status["core_reconciled_stale"] == 3
        assert [r["sid"] for r in _rows(audit.path)] == [9300607, 9300608, 9300609, 9300699]
    finally:
        recorder.stop()
        relay.stop()
    assert core_decisions.DEFAULT_MAX_RECONCILE == 256


def _replayed_by_the_relay(tmp_path: Path, offset_s: float, mutate=None) -> list:
    """A decision recorded live (in the chain) whose enqueue was lost; the
    relay's own reconcile replays it into a fresh queue."""

    ev = fresh(core_event("isolate", "z", 9300900), offset_s)
    tid, payload = core_decisions.core_decision_payload(ev)
    payload["recorded_by"] = "live"
    if mutate is not None:
        mutate(payload)
    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    audit.log_action_decision(trace_id=tid, source=core_decisions.CORE_DECISION_SOURCE, **payload)
    queue = tmp_path / "q.jsonl"
    relay = attach_p0_alert_relay(P0AuditLogger(audit.path), queue)
    try:
        assert relay.ready.wait(10)
        assert _wait(lambda: len(_alerts(queue)) == 2)
        alerts = _alerts(queue)
    finally:
        relay.stop()
    assert all(r["reconciled"] is True and r["recorded_by"] == "live" for r in alerts)
    return alerts


def test_an_old_live_decision_replayed_by_the_relay_is_a_past_decision(tmp_path):
    """Review of #468 (F1): a live-recorded decision an hour old, replayed by
    the relay's reconcile, is presented as a past decision, not as current."""

    alerts = _replayed_by_the_relay(tmp_path, -3600)
    assert all(r["stale"] is True and r["presentation"] == "historical" for r in alerts)
    assert [r["voice_urgent"] for r in alerts if r["channel"] == "voice"] == [False]
    assert all("過去の判定（" in r["display_text"] for r in alerts)


def test_a_recent_live_decision_replayed_by_the_relay_stays_current(tmp_path):
    alerts = _replayed_by_the_relay(tmp_path, -30)
    assert all(r["stale"] is False and r["presentation"] == "current" for r in alerts)
    assert [r["voice_urgent"] for r in alerts if r["channel"] == "voice"] == [True]


@pytest.mark.parametrize("ingest_offset,expect_stale", [(-30, False), (-3600, True), (None, None)])
def test_relay_replay_age_falls_back_when_the_event_time_is_unreadable(tmp_path, ingest_offset, expect_stale):
    """No readable event_ts: the core's ingest stamp, else the record's own
    ts (written now, so current)."""

    def mutate(payload):
        payload["event_ts"] = "not a time"
        payload["core_ingest_epoch"] = None if ingest_offset is None else time.time() + ingest_offset

    alerts = _replayed_by_the_relay(tmp_path, -3600, mutate)
    want = False if expect_stale is None else expect_stale
    assert all(r["stale"] is want for r in alerts)


def test_build_treats_an_unreadable_replayed_record_as_past_and_never_touches_live():
    from azazel_edge.notify.p0_alert import (
        DURABILITY_FSYNCED, DURABILITY_RECONCILED, DURABILITY_RECONCILED_FSYNCED, STALE_AFTER_S, build_p0_alerts,
    )

    assert core_decisions.DEFAULT_RECONCILE_MAX_AGE_S == STALE_AFTER_S == 300.0
    timeless = {"trace_id": "d", "action": "isolate", "event_ts": "", "ts": "?"}
    for durability in (DURABILITY_RECONCILED, DURABILITY_RECONCILED_FSYNCED):
        assert all(e["stale"] is True for e in build_p0_alerts(timeless, "enforcement:isolate", durability, None))
    old = dict(timeless, event_ts="2000-01-01T00:00:00.000000+0000")
    live = build_p0_alerts(old, "enforcement:isolate", DURABILITY_FSYNCED, 1)
    assert all(e["stale"] is False and e["presentation"] == "current" for e in live)
    assert [e["voice_urgent"] for e in live if e["channel"] == "voice"] == [True]
    edge = {"trace_id": "d", "action": "isolate", "event_ts": "2026-10-26T00:00:00.000000+0000"}
    t0 = 1792972800.0  # 2026-10-26T00:00:00Z
    assert build_p0_alerts(edge, "b", DURABILITY_RECONCILED, None, now=t0 + STALE_AFTER_S)[0]["stale"] is False
    assert build_p0_alerts(edge, "b", DURABILITY_RECONCILED, None, now=t0 + STALE_AFTER_S + 1)[0]["stale"] is True


_FUTURE_TS = ["2036-01-01T00:00:00.000000+0000", "9999-12-31T23:59:59.000000+0000"]


def test_reconcile_treats_future_and_non_finite_times_as_past(tmp_path):
    """Review of #468 (L1, L2): core event times are not authenticated. A time
    more than the clock-skew tolerance in the future, or a NaN/inf ingest
    stamp with no readable event time, cannot make a decision current; one
    just within the tolerance stays current."""

    from azazel_edge.notify.p0_alert import CLOCK_SKEW_TOLERANCE_S

    events = []
    for n, ts in enumerate(_FUTURE_TS):
        ev = core_event("isolate", f"f{n}", 9301000 + n)
        ev["normalized"]["ts"] = ts
        events.append(ev)
    events.append(fresh(core_event("isolate", "f2", 9301002), CLOCK_SKEW_TOLERANCE_S + 30))
    for n, bad in enumerate([float("nan"), float("inf"), float("-inf")]):
        ev = core_event("isolate", f"n{n}", 9301010 + n)
        ev["normalized"]["ts"] = "not a time"
        ev["normalized"]["ingest_epoch"] = bad
        events.append(ev)
    events.append(fresh(core_event("throttle", "s", 9301020), CLOCK_SKEW_TOLERANCE_S - 20))
    log = tmp_path / "normalized-events.jsonl"
    log.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    recorder = CoreDecisionRecorder(audit, relay, log).start()
    try:
        assert recorder.ready.wait(10)
        status = recorder.last_reconcile
        assert status["core_reconciled"] == 7 and status["core_reconciled_stale"] == 6
        chain = {r["sid"]: r for r in _rows(audit.path)}
        assert chain[9301020].get("reconcile_stale") is None
        assert all(chain[sid]["reconcile_stale"] is True for sid in (9301000, 9301001, 9301002, 9301010, 9301011, 9301012))
        assert all(chain[sid]["core_ingest_epoch"] is None for sid in (9301010, 9301011, 9301012))
        assert _wait(lambda: len(_alerts(relay.queue.path)) == 14)
        for r in _alerts(relay.queue.path):
            want = r["decision_id"] != chain[9301020]["trace_id"]
            assert r["stale"] is want and r["presentation"] == ("historical" if want else "current")
            if r["channel"] == "voice":
                assert r["voice_urgent"] is (not want)
    finally:
        recorder.stop()
        relay.stop()


def test_relay_replay_treats_future_and_non_finite_times_as_past_and_live_is_unaffected():
    from azazel_edge.notify.p0_alert import (
        CLOCK_SKEW_TOLERANCE_S, DURABILITY_FSYNCED, DURABILITY_RECONCILED, build_p0_alerts,
    )

    t0 = 1792972800.0  # 2026-10-26T00:00:00Z

    def ts(epoch: float) -> str:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")

    def stale(record, durability=DURABILITY_RECONCILED):
        entries = build_p0_alerts(dict({"trace_id": "d", "action": "isolate", "ts": "?"}, **record), "b", durability, None, now=t0)
        voice = [e["voice_urgent"] for e in entries if e["channel"] == "voice"]
        assert voice == [not entries[0]["stale"]]
        return entries[0]["stale"]

    for future in _FUTURE_TS:
        assert stale({"event_ts": future}) is True
    assert stale({"event_ts": ts(t0 + CLOCK_SKEW_TOLERANCE_S + 1)}) is True
    assert stale({"event_ts": ts(t0 + CLOCK_SKEW_TOLERANCE_S)}) is False
    assert stale({"event_ts": ts(t0 + CLOCK_SKEW_TOLERANCE_S - 20)}) is False
    for bad in (float("nan"), float("inf"), float("-inf")):
        assert stale({"event_ts": "", "core_ingest_epoch": bad}) is True
    assert stale({"event_ts": "", "core_ingest_epoch": t0 - 30}) is False
    # A non-finite ingest stamp is unreadable: the record's own ts is next.
    iso = lambda e: datetime.fromtimestamp(e, timezone.utc).isoformat(timespec="milliseconds")
    assert stale({"event_ts": "", "core_ingest_epoch": float("nan"), "ts": iso(t0 - 30)}) is False
    assert stale({"event_ts": "", "core_ingest_epoch": float("inf"), "ts": iso(t0 - 3600)}) is True
    # The live path is never judged by time, whatever the record says.
    for record in ({"event_ts": _FUTURE_TS[1]}, {"event_ts": "", "core_ingest_epoch": float("nan")}):
        assert stale(record, DURABILITY_FSYNCED) is False


def test_is_past_decision_rejects_non_finite_and_future_times():
    from azazel_edge.notify.p0_alert import CLOCK_SKEW_TOLERANCE_S, STALE_AFTER_S, is_past_decision

    now = 1792972800.0
    for bad in (None, float("nan"), float("inf"), float("-inf"), True):
        assert is_past_decision(bad, now) is True
    assert is_past_decision(now + CLOCK_SKEW_TOLERANCE_S + 0.001, now) is True
    assert is_past_decision(now + CLOCK_SKEW_TOLERANCE_S, now) is False
    assert is_past_decision(now - STALE_AFTER_S, now) is False
    assert is_past_decision(now - STALE_AFTER_S - 0.001, now) is True


def test_non_finite_numbers_are_not_read():
    assert core_decisions._num(float("nan")) is None
    assert core_decisions._num(float("inf")) is None and core_decisions._num(float("-inf")) is None
    assert core_decisions._num(True) is None and core_decisions._num(1.5) == 1.5
    assert core_decisions._num(10 ** 400) is None


def test_relay_replay_of_an_overflowing_ingest_time_is_past_not_dropped():
    from azazel_edge.notify.p0_alert import DURABILITY_RECONCILED, build_p0_alerts, finite_epoch, is_past_decision

    assert finite_epoch(10 ** 400) is None and is_past_decision(10 ** 400, 0.0) is True
    alerts = build_p0_alerts({"trace_id": "o", "action": "isolate", "core_ingest_epoch": 10 ** 400},
                             "b", DURABILITY_RECONCILED, None)
    assert alerts and all(a["stale"] is True for a in alerts)


def test_render_collapses_and_bounds_untrusted_text():
    from azazel_edge.notify.p0_alert import DISPLAY_FIELD_MAX, render_p0_alert

    out = render_p0_alert({"action": "isolate", "target": "a\nb\x00\tc", "reason": "r\r\n\x1b[31m  x" + "y" * 500,
                           "channel": "visual"})
    text = out["text"]
    assert "\n" not in text and "\x00" not in text and "\x1b" not in text and "\r" not in text
    assert "target=a b c " in text
    reason = text.split(" reason=", 1)[1]
    assert reason.startswith("r [31m x") and len(reason) == DISPLAY_FIELD_MAX


def test_render_marks_past_decisions_and_never_makes_them_urgent():
    from azazel_edge.notify.p0_alert import render_p0_alert

    base = {"action": "isolate", "target": "t", "reason": "r", "event_ts": "2026-10-26T01:02:03.000000+0000"}
    live = render_p0_alert(dict(base, channel="voice", stale=False, presentation="current"))
    assert live == {"text": "P0 isolate target=t reason=r", "urgent": True, "presentation": "current"}
    visual = render_p0_alert(dict(base, channel="visual", stale=True, presentation="historical"))
    assert visual["text"] == "【過去の判定（2026-10-26 01:02:03 UTC）】P0 isolate target=t reason=r"
    assert visual["urgent"] is False and visual["presentation"] == "historical"
    voice = render_p0_alert(dict(base, channel="voice", stale=True))
    assert voice["text"].startswith("過去の判定（2026-10-26 01:02:03 UTC）です。現在の警報ではありません。")
    assert voice["urgent"] is False
    odd = render_p0_alert(dict(base, channel="visual", stale=True, event_ts="<b>now</b>"))
    assert "時刻不明" in odd["text"] and "<b>" not in odd["text"]


def test_live_alerts_are_not_marked_reconciled(tmp_path):
    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    recorder = CoreDecisionRecorder(audit, relay, None).start()
    try:
        recorder.submit(core_event("isolate", "l", 9300300))
        assert _wait(lambda: len(_alerts(relay.queue.path)) == 2)
        assert all(r["reconciled"] is False and r["recorded_by"] == "live" for r in _alerts(relay.queue.path))
        assert all(r["stale"] is False and r["presentation"] == "current" for r in _alerts(relay.queue.path))
        assert [r["voice_urgent"] for r in _alerts(relay.queue.path) if r["channel"] == "voice"] == [True]
    finally:
        recorder.stop()
        relay.stop()


def test_stop_drains_within_its_bound_and_counts_the_rest(tmp_path, monkeypatch):
    real_fsync = os.fsync

    def slow_fsync(fd):
        time.sleep(0.2)
        return real_fsync(fd)

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    recorder = CoreDecisionRecorder(audit, relay, None).start()
    assert recorder.ready.wait(10) and relay.ready.wait(10)
    monkeypatch.setattr(os, "fsync", slow_fsync)
    try:
        for n in range(10):
            recorder.submit(core_event("throttle", f"s{n}", 9300400 + n))
        t0 = time.monotonic()
        undrained = recorder.stop(timeout=0.5)
        assert time.monotonic() - t0 < 1.5
        assert undrained > 0
    finally:
        monkeypatch.setattr(os, "fsync", real_fsync)
    assert _wait(lambda: any(s["core_record_undrained"] == undrained for s in _statuses(relay.queue.path, "core_recorder_stopped")))
    assert recorder.stop() == recorder.pending()  # idempotent: one status record
    relay.stop()


def test_sigterm_drains_the_p0_path_before_the_service_exits(agent_service):
    for n in range(20):
        _send(agent_service.socket, core_event("isolate", f"t{n}", 9300500 + n))
    agent_service.proc.send_signal(15)
    assert agent_service.proc.wait(timeout=30) is not None
    assert len(_rows(agent_service.chain)) == 20
    stopped = _statuses(agent_service.queue, "core_recorder_stopped")
    assert len(stopped) == 1 and stopped[0]["core_record_undrained"] == 0
    assert len(_alerts(agent_service.queue)) == 40
