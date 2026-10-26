"""Edge#462 items 1, 3 and 4: the core decision chain rotates without
breaking the reconcile cursor, the cursor is per chain, and P0 decisions a
hand-off dropped are recovered without a restart.

Observation and notification only: nothing here decides or enforces; the Rust
core (``decide_defense`` -> ``maybe_enforce``) stays the only enforcement
authority.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.audit import P0AuditLogger  # noqa: E402
from azazel_edge.audit import segments  # noqa: E402
from azazel_edge.audit.segments import read_chain, segment_path  # noqa: E402
from azazel_edge.notify.core_decisions import CoreDecisionRecorder  # noqa: E402
from azazel_edge.notify.p0_alert import P0AlertQueue, attach_p0_alert_relay  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "rust_core_event_v1.json"


# ---------------------------------------------------------------- helpers
def _all_rows(path: Path) -> list:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return []
    out = []
    for line in data.split(b"\n"):
        if line.strip():
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def _alerts(path: Path) -> list:
    return [r for r in _all_rows(path) if r.get("record_type") == "alert"]


def _statuses(path: Path, event: str) -> list:
    return [r for r in _all_rows(path) if r.get("record_type") == "relay_status" and r.get("event") == event]


def _chain_rows(path: Path) -> list:
    return P0AlertQueue._parse(read_chain(path)["lines"])


def _wait(pred, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return bool(pred())


def _settle(audit, relay) -> None:
    assert audit.wait_durable_listeners(10)
    assert relay.wait_idle(10)


def _contiguous(rows: list) -> bool:
    return all(rows[i]["chain_prev"] == rows[i - 1]["chain_hash"] for i in range(1, len(rows)))


def core_event(action: str, trace_id: str, sid: int, offset_s: float = 0.0) -> dict:
    event = json.loads(FIXTURE.read_text(encoding="utf-8"))
    event["defense"]["action"] = action
    event["enforcement"]["selected_action"] = action
    event["enforcement"]["trace_id"] = trace_id
    event["enforcement"]["mode"] = "dry_run"
    event["normalized"]["sid"] = sid
    event["normalized"]["ts"] = datetime.fromtimestamp(time.time() + offset_s, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%f+0000")
    event["normalized"]["ingest_epoch"] = time.time() + offset_s
    return event


# ------------------------------------------------- item 1: rotation (logger)
def test_rotation_is_bounded_and_the_chain_continues_across_files(tmp_path):
    path = tmp_path / "core-decision-audit.jsonl"
    audit = P0AuditLogger(path, max_bytes=1500, keep=1)
    written = [audit.log_action_decision(f"d{n}", "s", action="isolate") for n in range(40)]
    record_size = max(len(json.dumps(r, separators=(",", ":"))) + 1 for r in written)
    assert audit.rotated_total >= 5 and audit.rotate_failed_total == 0
    # Bounded: the active file and one rotated file, each at most max_bytes
    # plus one record.
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith(path.name)) == [path.name, path.name + ".1"]
    for p in (path, segment_path(path, 1)):
        assert p.stat().st_size < 1500 + record_size
    # One chain over both files: the active file's first record continues the
    # rotated one's last, and names the chain (the genesis record's hash).
    rotated = [json.loads(x) for x in segment_path(path, 1).read_text().splitlines()]
    active = [json.loads(x) for x in path.read_text().splitlines()]
    assert active[0]["chain_prev"] == rotated[-1]["chain_hash"]
    assert active[0]["chain_id"] == written[0]["chain_hash"] == audit.chain_id
    assert rotated[0]["chain_id"] == audit.chain_id
    assert all("chain_id" not in r for r in active[1:])
    verified = P0AuditLogger.verify_rotated_chain(path)
    assert verified["ok"] is True and verified["anchored"] is True and verified["segments"] == 2
    assert verified["entries"] == len(rotated) + len(active)
    assert verified["chain_id"] == audit.chain_id
    # The newest records are all retained, in order.
    assert [r["trace_id"] for r in _chain_rows(path)] == [r["trace_id"] for r in written[-(len(rotated) + len(active)):]]


def test_a_tampered_rotated_chain_does_not_verify(tmp_path):
    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path, max_bytes=800, keep=2)
    for n in range(12):
        audit.log_action_decision(f"d{n}", "s", action="isolate")
    rotated = segment_path(path, 1)
    lines = rotated.read_text().splitlines()
    row = json.loads(lines[-1])
    row["action"] = "observe"
    lines[-1] = json.dumps(row, separators=(",", ":"))
    rotated.write_text("\n".join(lines) + "\n")
    verified = P0AuditLogger.verify_rotated_chain(path)
    assert verified["ok"] is False and "chain_hash_mismatch" in verified["error"]


def test_a_restart_after_rotation_continues_the_same_chain(tmp_path):
    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path, max_bytes=600, keep=1)
    for n in range(6):
        audit.log_action_decision(f"d{n}", "s", action="isolate")
    # Rotated and not written since: the active file is gone.
    os.replace(path, segment_path(path, 1))
    again = P0AuditLogger(path, max_bytes=600, keep=1)
    assert again.chain_id == audit.chain_id
    nxt = again.log_action_decision("after", "s", action="isolate")
    assert nxt["chain_prev"] == audit._last_chain_hash and nxt["chain_id"] == audit.chain_id
    assert P0AuditLogger.verify_rotated_chain(path)["ok"] is True


def test_a_failed_rotation_never_loses_the_record(tmp_path, monkeypatch):
    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path, max_bytes=100, keep=1)
    audit.log_action_decision("d0", "s", action="isolate")
    real = os.replace

    def broken(src, dst):
        if str(dst).endswith(".1"):
            raise OSError(28, "no space")
        return real(src, dst)

    monkeypatch.setattr(os, "replace", broken)
    out = audit.log_action_decision("d1", "s", action="isolate")
    monkeypatch.setattr(os, "replace", real)
    assert audit.rotate_failed_total == 1 and audit.rotated_total == 0
    assert [r["trace_id"] for r in _chain_rows(path)] == ["d0", "d1"]
    assert out["chain_prev"] and P0AuditLogger.verify_chain(path)["ok"] is True


def test_a_non_rotating_logger_writes_what_it_always_wrote(tmp_path):
    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path)
    for n in range(30):
        audit.log_action_decision(f"d{n}", "s", action="isolate", chain_id="caller-supplied")
    assert not segment_path(path, 1).exists()
    assert all("chain_id" not in r for r in _chain_rows(path))
    assert P0AuditLogger.verify_chain(path)["ok"] is True
    with pytest.raises(ValueError):
        P0AuditLogger(tmp_path / "x.jsonl", max_bytes=0)
    with pytest.raises(ValueError):
        P0AuditLogger(tmp_path / "x.jsonl", max_bytes=10, keep=0)


def test_a_foreign_rotated_file_is_not_read_as_part_of_the_chain(tmp_path):
    """A file named like a rotated file that does not continue the chain (a
    host logrotate copy, a leftover) is not read."""

    path = tmp_path / "c.jsonl"
    other = P0AuditLogger(tmp_path / "other.jsonl")
    other.log_action_decision("foreign", "s", action="isolate")
    os.replace(other.path, segment_path(path, 1))
    audit = P0AuditLogger(path)
    audit.log_action_decision("mine", "s", action="isolate")
    snapshot = read_chain(path)
    assert snapshot["segments"] == 1 and snapshot["unlinked_segments"] == 1
    assert [r["trace_id"] for r in P0AlertQueue._parse(snapshot["lines"])] == ["mine"]


def test_snapshots_taken_while_the_chain_rotates_are_contiguous(tmp_path):
    """Readers racing the writer's rotation see one contiguous chain every
    time, never a predecessor missing in the middle or a file twice."""

    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path, max_bytes=700, keep=3)
    stop = threading.Event()

    def write():
        n = 0
        while not stop.is_set():
            audit.log("evaluation", f"e{n}", "s", n=n)
            n += 1

    writer = threading.Thread(target=write)
    writer.start()
    seen = 0
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            snapshot = read_chain(path)
            rows = P0AlertQueue._parse(snapshot["lines"])
            assert _contiguous(rows), [r.get("n") for r in rows]
            ns = [r["n"] for r in rows]
            assert ns == sorted(set(ns))
            seen += 1
    finally:
        stop.set()
        writer.join()
    assert seen > 20 and audit.rotated_total > 20


def test_a_rotation_between_opening_two_files_is_never_read_as_one_chain(tmp_path, monkeypatch):
    """Deterministic race: the writer rotates right after the reader opened
    the active file and before it opened ``.1``. The first attempt would
    read the same file twice; the reader notices and takes a new snapshot."""

    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path, max_bytes=500, keep=2)
    for n in range(8):
        audit.log_action_decision(f"d{n}", "s", action="isolate")
    real = segments._open
    raced = []

    def opening(p):
        fd = real(p)
        if not raced and p == path:
            raced.append(1)
            while path.exists() and path.stat().st_size < 500:
                audit.log_action_decision("fill", "s", action="isolate")
            audit.log_action_decision("rotates", "s", action="isolate")  # active -> .1
        return fd

    monkeypatch.setattr(segments, "_open", opening)
    snapshot = read_chain(path)
    rows = P0AlertQueue._parse(snapshot["lines"])
    assert raced and _contiguous(rows)
    assert len({r["chain_hash"] for r in rows}) == len(rows)
    assert rows[-1]["trace_id"] == "rotates"


def test_the_snapshot_retries_when_a_rotation_moves_files_under_it(tmp_path, monkeypatch):
    path = tmp_path / "c.jsonl"
    audit = P0AuditLogger(path, max_bytes=500, keep=2)
    for n in range(10):
        audit.log_action_decision(f"d{n}", "s", action="isolate")
    real = segments._open_snapshot
    calls = []

    def racing(base):
        fds, consistent = real(base)
        if not calls:
            calls.append(1)
            return fds, False  # as if a rotation had moved a file in between
        return fds, consistent

    monkeypatch.setattr(segments, "_open_snapshot", racing)
    snapshot = read_chain(path)
    assert snapshot["consistent"] is True and calls == [1]
    assert _contiguous(P0AlertQueue._parse(snapshot["lines"]))


# --------------------------------------- item 1: rotation and the cursor
def test_a_cursor_in_the_rotated_predecessor_is_found(tmp_path):
    """The relay's cursor is in ``.1`` after rotation: the next start finds
    it there and replays only what came after (never cursor_not_in_chain)."""

    path, qpath = tmp_path / "c.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(path, max_bytes=2000, keep=1)
    relay = attach_p0_alert_relay(audit, qpath)
    assert relay.ready.wait(5)
    audit.log_action_decision("live", "s", action="isolate")
    _settle(audit, relay)
    relay.stop()
    plain = P0AuditLogger(path, max_bytes=2000, keep=1)
    n = 0
    while not segment_path(path, 1).exists() or path.stat().st_size == 0:
        plain.log_action_decision(f"down-{n}", "s", action="observe")
        n += 1
    plain.log_action_decision("missed", "s", action="throttle")
    cursor = _alerts(qpath)[-1]["audit_cursor_chain_hash"]
    assert cursor not in {r["chain_hash"] for r in _all_rows(path)}  # only in .1
    again = attach_p0_alert_relay(P0AuditLogger(path, max_bytes=2000, keep=1), qpath)
    assert again.ready.wait(5)
    again.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "cursor_found" and started["unreconcilable"] == 0
    assert started["chain_segments"] == 2
    assert [r["decision_id"] for r in _alerts(qpath)[::2]] == ["live", "missed"]


def test_a_cursor_rotated_out_replays_the_retained_chain_bounded(tmp_path):
    """The cursor's file was removed by rotation while the relay was down:
    every retained record is after it, so the retained P0 decisions are
    replayed (newest first, bounded), none counted unreconcilable."""

    path, qpath = tmp_path / "c.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(path, max_bytes=1200, keep=1)
    relay = attach_p0_alert_relay(audit, qpath)
    assert relay.ready.wait(5)
    audit.log_action_decision("live", "s", action="isolate")
    _settle(audit, relay)
    relay.stop()
    plain = P0AuditLogger(path, max_bytes=1200, keep=1)
    for n in range(30):
        plain.log_action_decision(f"down-{n}", "s", action="isolate")
    assert plain.rotated_total >= 3
    retained = [r["trace_id"] for r in _chain_rows(path)]
    assert "live" not in retained and len(retained) > 3
    again = attach_p0_alert_relay(P0AuditLogger(path, max_bytes=1200, keep=1), qpath, max_reconcile=3)
    assert again.ready.wait(5)
    again.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "cursor_rotated_out" and started["chain_anchored"] is True
    assert started["unreconcilable"] == 0
    assert started["reconciled"] == 3 and started["reconcile_skipped"] == len(retained) - 3
    assert [r["decision_id"] for r in _alerts(qpath)[::2]] == ["live"] + retained[-3:]


def test_a_replaced_unanchored_chain_with_the_old_cursor_is_unreconcilable(tmp_path):
    """Failure case: the chain id matches but the cursor is in no retained
    file and the chain starts at its genesis (it was cut back, not rotated):
    nothing is replayed."""

    path, qpath = tmp_path / "c.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(path)
    relay = attach_p0_alert_relay(audit, qpath)
    assert relay.ready.wait(5)
    audit.log_action_decision("a", "s", action="isolate")
    audit.log_action_decision("b", "s", action="isolate")
    _settle(audit, relay)
    relay.stop()
    # Cut back to the genesis record only (a restore from an older copy).
    path.write_text(path.read_text().splitlines()[0] + "\n")
    again = attach_p0_alert_relay(P0AuditLogger(path), qpath)
    assert again.ready.wait(5)
    again.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "cursor_not_in_chain" and started["cursor_scope"] == "chain"


def test_the_recorder_reads_the_rotated_chain_for_its_keys(tmp_path):
    """A decision recorded in the rotated predecessor is not recorded again
    by the next start's reconcile."""

    path, qpath = tmp_path / "c.jsonl", tmp_path / "q.jsonl"
    log = tmp_path / "normalized-events.jsonl"
    events = [core_event("isolate", f"t{n}", 9_462_000 + n, -10) for n in range(8)]
    log.write_text("".join(json.dumps(e) + "\n" for e in events))
    for start in range(2):
        audit = P0AuditLogger(path, max_bytes=4000, keep=1)
        relay = attach_p0_alert_relay(audit, qpath)
        recorder = CoreDecisionRecorder(audit, relay, log).start()
        try:
            assert recorder.ready.wait(10) and recorder.wait_idle(10)
            status = recorder.last_reconcile
            assert status["core_reconciled"] == (8 if start == 0 else 0)
        finally:
            recorder.stop()
            relay.stop()
        if start == 0:
            assert segment_path(path, 1).exists()  # some keys are only in .1
    assert len(_chain_rows(path)) == 8


# -------------------------------------------- item 3: cursor per chain
def test_two_chains_sharing_a_queue_keep_their_own_cursors(tmp_path):
    qpath = tmp_path / "q.jsonl"
    a_path, b_path = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    a, b = P0AuditLogger(a_path), P0AuditLogger(b_path)
    relay_a = attach_p0_alert_relay(a, qpath)
    relay_b = attach_p0_alert_relay(b, qpath)
    assert relay_a.ready.wait(5) and relay_b.ready.wait(5)
    a.log_action_decision("a1", "s", action="isolate")
    _settle(a, relay_a)
    b.log_action_decision("b1", "s", action="throttle")  # the queue's last cursor is b's
    _settle(b, relay_b)
    relay_a.stop()
    relay_b.stop()
    assert relay_a.chain_id and relay_b.chain_id and relay_a.chain_id != relay_b.chain_id
    P0AuditLogger(a_path).log_action_decision("a2", "s", action="redirect")  # missed by a
    P0AuditLogger(b_path).log_action_decision("b2", "s", action="isolate")  # missed by b
    again_a = attach_p0_alert_relay(P0AuditLogger(a_path), qpath)
    assert again_a.ready.wait(5)
    again_a.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "cursor_found" and started["cursor_scope"] == "chain"
    assert started["reconciled"] == 1 and started["unreconcilable"] == 0
    assert started["audit_chain_id"] == relay_a.chain_id
    again_b = attach_p0_alert_relay(P0AuditLogger(b_path), qpath)
    assert again_b.ready.wait(5)
    again_b.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "cursor_found" and started["reconciled"] == 1 and started["unreconcilable"] == 0
    ids = [r["decision_id"] for r in _alerts(qpath)[::2]]
    assert sorted(ids) == ["a1", "a2", "b1", "b2"] and len(ids) == 4
    by_id = {r["decision_id"]: r["audit_chain_id"] for r in _alerts(qpath)}
    assert by_id["a1"] == by_id["a2"] == relay_a.chain_id
    assert by_id["b1"] == by_id["b2"] == relay_b.chain_id


def test_a_second_chain_on_a_shared_queue_starts_as_a_fresh_chain(tmp_path):
    qpath = tmp_path / "q.jsonl"
    a = P0AuditLogger(tmp_path / "a.jsonl")
    relay_a = attach_p0_alert_relay(a, qpath)
    assert relay_a.ready.wait(5)
    a.log_action_decision("a1", "s", action="isolate")
    _settle(a, relay_a)
    relay_a.stop()
    b_path = tmp_path / "b.jsonl"
    P0AuditLogger(b_path).log_action_decision("b-before", "s", action="isolate")
    relay_b = attach_p0_alert_relay(P0AuditLogger(b_path), qpath)
    assert relay_b.ready.wait(5)
    relay_b.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "fresh_chain" and started["reconciled"] == 1 and started["unreconcilable"] == 0


# ------------------------------------- item 4: loss recovery, recorder
def _blocking_recorder(tmp_path, monkeypatch, **kw):
    """A recorder whose writer blocks on its first chain write until
    ``gate`` is set; the hand-off holds ``max_pending`` decisions."""

    audit = P0AuditLogger(tmp_path / "core-decision-audit.jsonl")
    relay = attach_p0_alert_relay(audit, tmp_path / "p0-alert-queue.jsonl")
    log = tmp_path / "normalized-events.jsonl"
    recorder = CoreDecisionRecorder(audit, relay, log, max_pending=2, loss_recover_interval_s=0.0, **kw).start()
    assert recorder.ready.wait(10) and relay.ready.wait(10)
    gate, inside = threading.Event(), threading.Event()
    real = audit.log_action_decision
    first = [True]

    def blocking(*a, **k):
        if first[0]:
            first[0] = False
            inside.set()
            assert gate.wait(10)
        return real(*a, **k)

    monkeypatch.setattr(audit, "log_action_decision", blocking)
    return audit, relay, recorder, log, gate, inside


def test_decisions_the_hand_off_dropped_are_recovered_without_a_restart(tmp_path, monkeypatch):
    audit, relay, recorder, log, gate, inside = _blocking_recorder(tmp_path, monkeypatch)
    try:
        events = [core_event("isolate", f"t{n}", 9_462_100 + n, -5) for n in range(6)]
        old = core_event("isolate", "old", 9_462_199, -3600)  # older than the lease
        recorder.submit(events[0])
        assert inside.wait(10)
        for e in events[1:] + [old]:
            recorder.submit(e)
        assert recorder.metrics()["core_record_handoff_dropped_total"] == 4  # events 3..5 and old
        # The core wrote every decision to its log before forwarding it.
        log.write_text("".join(json.dumps(e) + "\n" for e in events + [old]))
        gate.set()
        assert _wait(lambda: recorder.metrics()["core_loss_recovered_total"] == 4)
        assert recorder.wait_idle(10)
        _settle(audit, relay)
        chain = _chain_rows(audit.path)
        assert sorted(r["sid"] for r in chain) == sorted(e["normalized"]["sid"] for e in events + [old])
        by_sid = {r["sid"]: r for r in chain}
        assert [by_sid[9_462_100 + n]["recorded_by"] for n in range(6)] == ["live"] * 3 + ["loss_reconcile"] * 3
        assert by_sid[9_462_199]["recorded_by"] == "loss_reconcile" and by_sid[9_462_199]["reconcile_stale"] is True
        assert all("reconcile_stale" not in by_sid[9_462_100 + n] for n in range(6))
        status = recorder.last_loss_reconcile
        assert (status["core_loss_recovered"], status["core_loss_recovered_stale"], status["core_loss_not_found"]) == (4, 1, 0)
        assert _statuses(relay.queue.path, "core_loss_reconcile")
        assert _wait(lambda: len(_alerts(relay.queue.path)) == 14)
        alerts = {(r["event_ts"], r["channel"]): r for r in _alerts(relay.queue.path)}
        old_voice = alerts[(old["normalized"]["ts"], "voice")]
        assert old_voice["stale"] is True and old_voice["presentation"] == "historical"
        assert old_voice["voice_urgent"] is False and old_voice["reconciled"] is True
        recovered_fresh = alerts[(events[5]["normalized"]["ts"], "voice")]
        assert recovered_fresh["reconciled"] is True and recovered_fresh["presentation"] == "current"
        live = alerts[(events[0]["normalized"]["ts"], "voice")]
        assert live["reconciled"] is False
    finally:
        gate.set()
        recorder.stop()
        relay.stop()
    # A later start records none of them again (deduplicated by event key).
    audit2 = P0AuditLogger(audit.path)
    relay2 = attach_p0_alert_relay(audit2, relay.queue.path)
    again = CoreDecisionRecorder(audit2, relay2, log).start()
    try:
        assert again.ready.wait(10)
        assert again.last_reconcile["core_reconciled"] == 0
    finally:
        again.stop()
        relay2.stop()
    assert len(_chain_rows(audit.path)) == 7


def test_dropped_decisions_the_log_does_not_have_are_counted_unrecovered(tmp_path, monkeypatch):
    audit, relay, recorder, log, gate, inside = _blocking_recorder(tmp_path, monkeypatch)
    try:
        events = [core_event("isolate", f"t{n}", 9_462_300 + n, -5) for n in range(5)]
        recorder.submit(events[0])
        assert inside.wait(10)
        for e in events[1:]:
            recorder.submit(e)
        log.write_text(json.dumps(events[0]) + "\n")  # the dropped ones are not in the tail
        gate.set()
        assert _wait(lambda: recorder.metrics()["core_loss_unrecovered_total"] == 2)
        assert recorder.metrics()["core_loss_recovered_total"] == 0
        assert recorder.last_loss_reconcile["core_loss_not_found"] == 2
    finally:
        gate.set()
        recorder.stop()
        relay.stop()


def test_a_loss_pass_shares_the_reconcile_bound(tmp_path, monkeypatch):
    audit, relay, recorder, log, gate, inside = _blocking_recorder(tmp_path, monkeypatch, max_reconcile=2)
    try:
        events = [core_event("isolate", f"t{n}", 9_462_400 + n, -5) for n in range(7)]
        recorder.submit(events[0])
        assert inside.wait(10)
        for e in events[1:]:
            recorder.submit(e)
        log.write_text("".join(json.dumps(e) + "\n" for e in events))
        gate.set()
        assert _wait(lambda: recorder.last_loss_reconcile.get("core_loss_recovered") == 2)
        status = recorder.last_loss_reconcile
        assert status["core_loss_skipped"] == 2
        # The newest two of the four dropped.
        assert sorted(r["sid"] for r in _chain_rows(audit.path))[-2:] == [9_462_405, 9_462_406]
        assert recorder.metrics()["core_loss_unrecovered_total"] == 2
    finally:
        gate.set()
        recorder.stop()
        relay.stop()


def test_no_loss_pass_runs_while_the_hand_off_is_still_overloaded(tmp_path):
    recorder = CoreDecisionRecorder(P0AuditLogger(tmp_path / "c.jsonl"), None, tmp_path / "n.jsonl",
                                    max_pending=4, loss_recover_interval_s=0.0)
    for n in range(4):
        recorder.submit(core_event("isolate", f"t{n}", 9_462_500 + n))
    recorder.submit(core_event("isolate", "dropped", 9_462_599))
    assert recorder.metrics()["core_record_handoff_dropped_total"] == 1
    recorder._maybe_recover_losses()
    assert recorder.last_loss_reconcile == {} and len(recorder._lost) == 1
    while not recorder._pending.empty():
        recorder._pending.get_nowait()
    recorder._maybe_recover_losses()
    assert recorder.last_loss_reconcile["core_loss_keys"] == 1


# --------------------------------------- item 4: loss recovery, relay
def test_records_the_relay_hand_off_dropped_are_alerted_without_a_restart(tmp_path, monkeypatch):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(apath)
    relay = attach_p0_alert_relay(audit, qpath, max_pending=1, loss_recover_interval_s=0.0)
    assert relay.ready.wait(5)
    gate, inside = threading.Event(), threading.Event()
    real = relay.queue.enqueue
    first = [True]

    def blocking(*a, **k):
        if first[0]:
            first[0] = False
            inside.set()
            assert gate.wait(10)
        return real(*a, **k)

    monkeypatch.setattr(relay.queue, "enqueue", blocking)
    try:
        audit.log_action_decision("d0", "s", action="isolate")
        assert inside.wait(10)
        for n in range(1, 5):
            audit.log_action_decision(f"d{n}", "s", action="isolate")
        assert audit.wait_durable_listeners(10)
        assert relay.metrics()["handoff_dropped_total"] == 3
        gate.set()
        assert _wait(lambda: relay.metrics()["loss_recovered_total"] == 3)
        _settle(audit, relay)
    finally:
        gate.set()
        relay.stop()
    rows = _alerts(qpath)
    assert sorted(r["decision_id"] for r in rows[::2]) == [f"d{n}" for n in range(5)]
    recovered = [r for r in rows if r["decision_id"] in ("d2", "d3", "d4")]
    assert all(r["reconciled"] is True and r["presentation"] == "current" for r in recovered)
    assert all(r["decision_record_durability"] == "reconciled_from_chain_fsynced" for r in recovered)
    assert all("audit_cursor_chain_hash" not in r for r in recovered)  # the cursor never moves back
    assert _statuses(qpath, "loss_recovery")[-1]["loss_recovered"] == 3
    # The next start finds the cursor and alerts nothing twice.
    again = attach_p0_alert_relay(P0AuditLogger(apath), qpath)
    assert again.ready.wait(5)
    again.stop()
    started = _statuses(qpath, "started")[-1]
    assert started["reconcile"] == "cursor_found" and started["reconciled"] == 0
    assert len(_alerts(qpath)) == 10


def test_records_the_audit_listener_hand_off_dropped_are_alerted(tmp_path):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(apath)
    audit._durable_handoff_max = 1
    gate, inside = threading.Event(), threading.Event()

    def slow_listener(record, durability, stamp):
        if not inside.is_set():
            inside.set()
            gate.wait(10)

    audit.add_durable_listener(slow_listener)  # holds the dispatcher
    relay = attach_p0_alert_relay(audit, qpath, loss_recover_interval_s=0.0)
    assert relay.ready.wait(5)
    try:
        audit.log_action_decision("d0", "s", action="isolate")
        assert inside.wait(10)
        for n in range(1, 4):
            audit.log_action_decision(f"d{n}", "s", action="isolate")
        assert audit.durable_handoff_dropped_total == 2
        gate.set()
        assert _wait(lambda: relay.metrics()["loss_recovered_total"] == 2)
        _settle(audit, relay)
    finally:
        gate.set()
        relay.stop()
    assert sorted(r["decision_id"] for r in _alerts(qpath)[::2]) == ["d0", "d1", "d2", "d3"]


def test_the_agent_opens_the_core_decision_chain_rotating(monkeypatch, tmp_path):
    from azazel_edge.notify import core_decisions
    from azazel_edge_ai import agent as agent_mod

    monkeypatch.setattr(agent_mod, "CORE_DECISION_AUDIT", None)
    monkeypatch.setattr(agent_mod, "CORE_P0_RELAY", None)
    monkeypatch.setattr(agent_mod, "CORE_RECORDER", None)
    monkeypatch.setattr(agent_mod, "CORE_NORMALIZED_EVENT_LOG", tmp_path / "normalized-events.jsonl")
    monkeypatch.setattr(agent_mod, "CORE_DECISION_AUDIT_PATH", tmp_path / "core-decision-audit.jsonl")
    monkeypatch.setattr(agent_mod, "P0_ALERT_QUEUE_PATH", tmp_path / "p0-alert-queue.jsonl")
    relay = agent_mod._start_core_p0_path()
    try:
        audit = agent_mod.CORE_DECISION_AUDIT
        assert audit.max_bytes == core_decisions.DEFAULT_CHAIN_SEGMENT_MAX_BYTES == 16 * 1024 * 1024
        assert audit.keep == core_decisions.DEFAULT_CHAIN_SEGMENTS_KEPT == 1
        # The retained chain (two files) fits the recorder's key window.
        assert 2 * audit.max_bytes <= agent_mod.CORE_RECORDER.chain_key_max_bytes
        assert agent_mod.CORE_RECORDER.ready.wait(10)
    finally:
        agent_mod.CORE_RECORDER.stop()
        relay.stop()
