"""SO-03 P0 alert path (Edge#414, owner decisions 2026-10-25).

P0 = enforcement-bearing decision (throttle, redirect, isolate) or SOC
critical, built by the notify layer from the audit-chain decision record and
enqueued into one durable JSONL queue, visual and voice by ``channel``.

The path is observation and notification only: these tests also check that
it never changes what the audit logger writes, returns or raises, and that a
broken queue never reaches the decision path. The harness/validator tests take
a record away, or make it disagree, and expect the row to become
not_measurable or fail -- never pass -- and the former gaps to come back.
The harness runs the real Rust core binary (built by the ``rust_core_bin``
fixture) into the AI agent service script its unit's ExecStart runs.
"""

from __future__ import annotations

import copy
import errno
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.audit import AuditDurabilityError, P0AuditLogger  # noqa: E402
import azazel_edge.audit.logger as logger_mod  # noqa: E402
from azazel_edge.notify import p0_alert  # noqa: E402
from azazel_edge.notify.p0_alert import (  # noqa: E402
    P0AlertQueue,
    P0AlertRelay,
    attach_p0_alert_relay,
    classify_p0,
)
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so03_alert_queue  # noqa: E402

PART = "decision_durable_to_alert_enqueued"
GAPS = ("SO03-NO-VISUAL-VOICE-QUEUE", "SO03-NO-P0-ALERT-PATH")
CORE_GAP = "SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS"
ALL_GAPS = GAPS + (CORE_GAP,)


def _decision(action="throttle", label="high", **extra):
    row = {"kind": "action_decision", "trace_id": "d-1", "chain_hash": "h" * 64, "action": action,
           "reason": "r", "decision_trace": {"suspicion_label": label}}
    row.update(extra)
    return row


def _all_rows(path):
    """Every complete line of a JSONL file, parsed strictly.

    The relay thread may be appending while a test reads, so a trailing line
    without its newline is not yet a record and is left out (as the product
    reader does). A complete line that does not parse still fails the test.
    """

    data = Path(path).read_bytes()
    return [json.loads(x) for x in data.split(b"\n")[:-1] if x]


def _settle(audit, relay):
    """Deterministic wait: every durable record handed to the listeners, and
    every record handed to the relay, has been relayed (enqueue returned)."""

    assert audit.wait_durable_listeners(10)
    assert relay.wait_idle(10)


def _rows(path):
    """The alert entries only (relay_status and overflow_alarm records left out)."""

    return [r for r in _all_rows(path) if r.get("record_type") == "alert"]


def _status(path):
    return [r for r in _all_rows(path) if r.get("record_type") == "relay_status"]


def _wait(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


# ------------------------------------------------------------- classifier


@pytest.mark.parametrize(
    "record,basis",
    [
        (_decision("throttle"), "enforcement:throttle"),
        (_decision("redirect"), "enforcement:redirect"),
        (_decision("isolate", "low"), "enforcement:isolate"),
        (_decision("notify", "critical"), "soc_critical"),
        (_decision("observe", "critical"), "soc_critical"),
        (_decision("notify", "high"), ""),
        (_decision("observe", "low"), ""),
        (_decision("notify", "CRITICAL"), ""),
        ({"kind": "action_decision", "redirect": True, "trace_id": "oc"}, "enforcement:redirect"),
        ({"kind": "action_decision", "action": "notify", "redirect": True}, ""),
        (dict(_decision("throttle"), kind="notification"), ""),
        ({"kind": "action_decision", "action": ["throttle"]}, ""),
        ("throttle", ""),
        (None, ""),
    ],
)
def test_classifier_is_the_owner_rule(record, basis):
    assert classify_p0(record) == basis
    assert classify_p0(copy.deepcopy(record)) == basis  # a pure function of the record


# ------------------------------------------------------------------ queue


def _alerts(decision_id="d-1"):
    return p0_alert.build_p0_alerts(_decision(trace_id=decision_id), "enforcement:throttle", "fsynced", 5)


def test_enqueue_writes_both_channels_and_fsyncs(tmp_path, monkeypatch):
    qpath = tmp_path / "q.jsonl"
    synced = []
    real = os.fsync

    def spy(fd):
        st = os.fstat(fd)
        synced.append(((st.st_dev, st.st_ino), os.pread(fd, 1 << 20, 0) if stat.S_ISREG(st.st_mode) else b""))
        return real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    before = time.monotonic_ns()
    result = P0AlertQueue(qpath).enqueue(_alerts())
    after = time.monotonic_ns()
    rows = _rows(qpath)
    assert result["ok"] and result["durability"] == "fsynced"
    assert [r["channel"] for r in rows] == ["visual", "voice"]
    assert [r["seq"] for r in rows] == [1, 2]
    for r in rows:
        assert r["schema"] == p0_alert.QUEUE_SCHEMA and r["decision_id"] == "d-1"
        assert r["p0_class"] == "P0" and r["p0_rule"] == p0_alert.P0_RULE
        assert before <= r["enqueued_monotonic_ns"] <= after
    st = os.stat(qpath)
    # The file was fsynced with both entries in it, and (new file) its directory.
    assert any(key == (st.st_dev, st.st_ino) and content.count(b"\n") == 2 for key, content in synced)
    dst = os.stat(tmp_path)
    assert any(key == (dst.st_dev, dst.st_ino) for key, _ in synced)


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_queue_and_lock_are_private_and_loose_modes_are_tightened(tmp_path):
    qpath = tmp_path / "q.jsonl"
    P0AlertQueue(qpath).enqueue(_alerts())
    assert stat.S_IMODE(os.stat(qpath).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "q.jsonl.lock").st_mode) == 0o600
    os.chmod(qpath, 0o644)
    P0AlertQueue(qpath).enqueue(_alerts("d-2"))
    assert stat.S_IMODE(os.stat(qpath).st_mode) == 0o600


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW") or os.name != "posix", reason="POSIX O_NOFOLLOW")
@pytest.mark.parametrize("which", ["queue", "lock"])
def test_symlinks_are_refused(tmp_path, which):
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    qpath = tmp_path / "q.jsonl"
    link = qpath if which == "queue" else tmp_path / "q.jsonl.lock"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        P0AlertQueue(qpath).enqueue(_alerts())
    assert victim.read_text(encoding="utf-8") == "keep"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX fifo")
def test_non_regular_queue_file_is_refused(tmp_path):
    qpath = tmp_path / "q.jsonl"
    os.mkdir(qpath)
    with pytest.raises(OSError):
        P0AlertQueue(qpath).enqueue(_alerts())


def test_torn_tail_is_repaired_and_recorded(tmp_path):
    qpath = tmp_path / "q.jsonl"
    queue = P0AlertQueue(qpath)
    queue.enqueue(_alerts("d-1"))
    with open(qpath, "ab") as fh:
        fh.write(b'{"schema":"azazel-edge/p0-alert-queue/v1","seq":3,"decis')
    result = queue.enqueue(_alerts("d-2"))
    rows = _rows(qpath)  # every line parses again
    assert [r["decision_id"] for r in rows] == ["d-1", "d-1", "d-2", "d-2"]
    assert [r["seq"] for r in rows] == [1, 2, 3, 4]
    assert result["torn_tail_repaired_bytes"] > 0
    assert rows[-1]["torn_tail_repaired_bytes"] == result["torn_tail_repaired_bytes"]
    assert rows[0]["torn_tail_repaired_bytes"] == 0


def test_overflow_evicts_whole_decisions_and_compacts_only_at_2x(tmp_path, monkeypatch):
    qpath = tmp_path / "q.jsonl"
    queue = P0AlertQueue(qpath, max_entries=4)
    replaces = []
    real_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda a, b: (replaces.append(b), real_replace(a, b))[1])
    for i in range(4):  # 8 lines: 2 x the bound, appended, never rewritten
        queue.enqueue(_alerts(f"d-{i}"))
    assert replaces == [] and len(_all_rows(qpath)) == 8
    result = queue.enqueue(_alerts("d-4"))
    assert len(replaces) == 1  # one compaction
    rows = _all_rows(qpath)
    # Whole decisions evicted, oldest first, never the new alert; both
    # channels of every kept decision are kept together.
    assert [(r["record_type"], r.get("decision_id")) for r in rows] == [
        ("alert", "d-3"), ("alert", "d-3"), ("overflow_alarm", None), ("alert", "d-4"), ("alert", "d-4"),
    ]
    alarm = rows[2]
    assert alarm["evicted_decisions"] == 3 and alarm["evicted_alerts"] == 6
    assert alarm["evicted_decision_ids"] == ["d-0", "d-1", "d-2"]
    assert alarm["overflow_evicted_total"] == 6 and alarm["overflow_policy"] == p0_alert.OVERFLOW_POLICY
    assert result["evicted"] == 6
    assert rows[-1]["overflow_evicted"] == 6 and rows[-1]["overflow_evicted_total"] == 6
    assert [r["seq"] for r in rows] == sorted(r["seq"] for r in rows)
    # Appends resume without a rewrite until 2x again; the total accumulates.
    queue.enqueue(_alerts("d-5"))
    assert len(replaces) == 1
    for i in range(6, 8):
        queue.enqueue(_alerts(f"d-{i}"))
    assert len(replaces) == 2
    assert _rows(qpath)[-1]["overflow_evicted_total"] == 6 + 4  # d-3 and d-4 at the second compaction
    assert len([r for r in _all_rows(qpath) if r["record_type"] == "overflow_alarm"]) == 1  # the newest alarm
    assert stat.S_IMODE(os.stat(qpath).st_mode) == 0o600
    assert not list(tmp_path.glob("*.tmp"))


def test_full_queue_enqueue_latency_is_bounded(tmp_path):
    queue = P0AlertQueue(tmp_path / "q.jsonl")  # default bound
    i = 0
    while (i + 1) * 2 <= queue.max_lines:
        queue.enqueue(_alerts(f"d-{i}"))
        i += 1
    t0 = time.monotonic()
    queue.enqueue(_alerts("compacting"))
    compact_s = time.monotonic() - t0
    assert queue.compactions == 1
    t0 = time.monotonic()
    queue.enqueue(_alerts("after"))
    append_s = time.monotonic() - t0
    # Far below the SO-03 bound even on a slow disk; the harness reports the
    # measured values in its record notes.
    assert compact_s < 1.0 and append_s < 1.0
    assert len(_rows(tmp_path / "q.jsonl")) <= queue.max_entries + 2


def test_another_writer_is_noticed(tmp_path):
    qpath = tmp_path / "q.jsonl"
    a, b = P0AlertQueue(qpath), P0AlertQueue(qpath)
    a.enqueue(_alerts("d-1"))
    b.enqueue(_alerts("d-2"))
    a.enqueue(_alerts("d-3"))  # a's cache is stale: it rereads, seq continues
    assert [r["seq"] for r in _rows(qpath)] == [1, 2, 3, 4, 5, 6]


def test_reader_skips_and_counts_a_partial_trailing_line(tmp_path):
    qpath = tmp_path / "q.jsonl"
    queue = P0AlertQueue(qpath)
    queue.enqueue(_alerts("d-1"))
    with open(qpath, "ab") as fh:
        fh.write(b"not json\n")  # complete but unparseable
        fh.write(b'{"schema":"azazel-edge/p0-alert-queue/v1","seq":9}')  # parses, but no newline yet
    rows = queue.read_entries()
    assert [r["decision_id"] for r in rows] == ["d-1", "d-1"]
    assert queue.read_partial_tail_total == 1 and queue.read_unparseable_total == 1


def test_reader_counts_a_torn_tail_and_a_bad_line_once_across_re_reads(tmp_path):
    qpath = tmp_path / "q.jsonl"
    queue = P0AlertQueue(qpath)
    queue.enqueue(_alerts("d-1"))
    with open(qpath, "ab") as fh:
        fh.write(b"garbage\n")
        fh.write(b'{"partial":')
    for _ in range(3):
        assert len(queue.read_entries()) == 2
    assert queue.read_partial_tail_total == 1 and queue.read_unparseable_total == 1
    with open(qpath, "ab") as fh:
        fh.write(b' 1}\n{"again')  # the old tail completes; a new torn tail appears further on
    queue.read_entries()
    queue.read_entries()
    assert queue.read_partial_tail_total == 2 and queue.read_unparseable_total == 1


def test_read_counters_are_in_relay_metrics_and_status(tmp_path):
    qpath = tmp_path / "q.jsonl"
    qpath.write_bytes(b"garbage\n" + b'{"partial":')
    os.chmod(qpath, 0o600)
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    relay = attach_p0_alert_relay(audit, qpath)
    assert relay.ready.wait(5)
    relay.stop()
    metrics = relay.metrics()
    assert metrics["queue_read_partial_tail_total"] == 1 and metrics["queue_read_unparseable_total"] == 1
    # The garbage line stays in the file; read it through the product reader.
    started = [r for r in P0AlertQueue(qpath).read_entries() if r.get("event") == "started"][-1]
    assert started["queue_read_partial_tail_total"] == 1 and started["queue_read_unparseable_total"] == 1


def test_registration_cut_missing_from_the_chain_is_recorded(tmp_path):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    plain = P0AuditLogger(apath)
    plain.log_action_decision("p-1", "s", action="isolate")
    plain.log_action_decision("p-2", "s", action="observe")
    relay = P0AlertRelay(P0AlertQueue(qpath), audit_path=apath)
    relay.reconcile_until = "f" * 64  # the chain was replaced after registration
    status = relay.reconcile()
    assert status["reconcile"] == "registration_cut_not_found"
    assert status["unreconcilable"] == 1 and status["reconciled"] == 0
    assert _rows(qpath) == []
    assert _started(qpath)[-1]["reconcile"] == "registration_cut_not_found"


def test_readers_never_crash_while_the_relay_appends(tmp_path):
    """A reader racing the writer sees only complete entries, in order."""

    qpath = tmp_path / "q.jsonl"
    writer = P0AlertQueue(qpath)
    reader = P0AlertQueue(qpath)
    writer.enqueue(_alerts("seed"))
    big = [dict(a, evidence_ids=[f"ev-{k}" for k in range(400)]) for a in _alerts("big")]  # > PIPE_BUF per write
    stop = threading.Event()
    seen_errors = []

    def write():
        for i in range(150):
            writer.enqueue([dict(a, decision_id=f"w-{i}") for a in big])
        stop.set()

    def read():
        while not stop.is_set():
            try:
                rows = reader.read_entries()
                assert [r["seq"] for r in rows] == list(range(1, len(rows) + 1))
                _all_rows(qpath)
            except Exception as exc:  # pragma: no cover - the assertion reports it
                seen_errors.append(exc)
                return

    threads = [threading.Thread(target=write)] + [threading.Thread(target=read) for _ in range(3)]
    [t.start() for t in threads]
    [t.join(60) for t in threads]
    assert not seen_errors, seen_errors[:1]
    assert reader.read_unparseable_total == 0
    assert len(reader.read_entries()) == 2 + 300


def test_queue_too_small_for_one_alert_is_refused(tmp_path):
    with pytest.raises(ValueError):
        P0AlertQueue(tmp_path / "q.jsonl", max_entries=1)


def test_fsync_error_raises_from_enqueue(tmp_path, monkeypatch):
    def eio(fd):
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "fsync", eio)
    with pytest.raises(OSError):
        P0AlertQueue(tmp_path / "q.jsonl").enqueue(_alerts())


def test_concurrent_enqueues_keep_every_entry(tmp_path):
    qpath = tmp_path / "q.jsonl"
    errors = []

    def worker(i):
        q = P0AlertQueue(qpath)
        for j in range(20):
            try:
                q.enqueue(_alerts(f"{i}-{j}"))
            except Exception as exc:  # pragma: no cover - the assertion reports it
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    rows = _rows(qpath)
    assert not errors
    assert len(rows) == 160
    assert [r["seq"] for r in rows] == list(range(1, 161))


# ------------------------------------------------------- logger listener


def test_listener_gets_a_copy_after_the_fsync(tmp_path, monkeypatch):
    path = tmp_path / "a.jsonl"
    audit = P0AuditLogger(path)
    seen = []
    events = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (events.append("fsync"), real(fd))[1])

    def listener(record, durability, stamp):
        events.append("listener")
        seen.append((record, durability, stamp))
        record["action"] = "tampered"

    audit.add_durable_listener(listener)
    before = time.monotonic_ns()
    out = audit.log_action_decision("d-1", "s", action="throttle")
    after = time.monotonic_ns()
    audit.log_evaluation("e-1", "s")  # not a durable kind: no call
    assert audit.wait_durable_listeners()
    assert len(seen) == 1
    record, durability, stamp = seen[0]
    assert durability == "fsynced" and before <= stamp <= after
    assert record["chain_hash"] == out["chain_hash"]
    assert events.index("listener") > events.index("fsync")
    assert out["action"] == "throttle" and _all_rows(path)[0]["action"] == "throttle"
    assert P0AuditLogger.verify_chain(path)["ok"] is True


def test_listener_failure_never_reaches_the_decision_path(tmp_path):
    plain = P0AuditLogger(tmp_path / "plain.jsonl")
    hooked = P0AuditLogger(tmp_path / "hooked.jsonl")

    def broken(*a):
        raise RuntimeError("listener down")

    hooked.add_durable_listener(broken)
    a = plain.log_action_decision("d-1", "s", action="isolate", reason="r")
    b = hooked.log_action_decision("d-1", "s", action="isolate", reason="r")
    strip = lambda r: {k: v for k, v in r.items() if k not in ("ts", "chain_hash")}  # noqa: E731
    assert strip(a) == strip(b)
    assert P0AuditLogger.verify_chain(tmp_path / "hooked.jsonl")["ok"] is True


def test_fsync_failure_still_raises_and_tells_the_listener(tmp_path, monkeypatch):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    seen = []
    audit.add_durable_listener(lambda record, durability, stamp: seen.append(durability))

    def eio(fd):
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "fsync", eio)
    with pytest.raises(AuditDurabilityError):
        audit.log_action_decision("d-1", "s", action="throttle")
    monkeypatch.undo()
    assert audit.wait_durable_listeners()
    assert seen == ["fsync_failed"]


def test_slow_listener_never_stalls_writers_and_keeps_chain_order(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    release = threading.Event()
    seen = []

    def slow(record, durability, stamp):
        release.wait(10)
        seen.append(record["trace_id"])

    audit.add_durable_listener(slow)
    durations = []
    errors = []

    def writer(w):
        for j in range(10):
            t0 = time.monotonic()
            try:
                audit.log_action_decision(f"w{w}-{j}", "s", action="observe")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)
            durations.append(time.monotonic() - t0)

    threads = [threading.Thread(target=writer, args=(w,)) for w in range(3)]
    [t.start() for t in threads]
    [t.join(10) for t in threads]
    # Every writer finished while the listener was still blocked.
    assert not errors and len(durations) == 30 and max(durations) < 1.0
    assert seen == []
    release.set()
    assert audit.wait_durable_listeners(10)
    assert seen == [r["trace_id"] for r in _all_rows(tmp_path / "a.jsonl")]  # chain order


def test_full_listener_handoff_is_counted_not_blocking(tmp_path, monkeypatch):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    release = threading.Event()
    audit.add_durable_listener(lambda *a: release.wait(10))
    audit._durable_handoff_max = 2
    for j in range(6):
        audit.log_action_decision(f"d-{j}", "s", action="observe")
    assert audit.durable_handoff_dropped_total >= 3
    release.set()
    assert audit.wait_durable_listeners(10)
    assert len(_all_rows(tmp_path / "a.jsonl")) == 6  # the chain is complete regardless


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_listener_shutdown_signal_is_not_swallowed_and_writers_go_on(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")

    def stop(*a):
        raise SystemExit(0)

    audit.add_durable_listener(stop)
    audit.log_action_decision("d-1", "s", action="observe")
    assert _wait(lambda: not audit._durable_dispatcher.is_alive())
    out = audit.log_action_decision("d-2", "s", action="observe")
    assert out["trace_id"] == "d-2" and P0AuditLogger.verify_chain(tmp_path / "a.jsonl")["ok"]


# ------------------------------------------------------------------ relay


def test_attached_path_enqueues_p0_decisions_only(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    qpath = tmp_path / "q.jsonl"
    relay = attach_p0_alert_relay(audit, qpath)
    try:
        audit.log_action_decision("d-obs", "s", action="observe", decision_trace={"suspicion_label": "high"})
        audit.log_action_decision("d-thr", "s", action="throttle", target_ip="192.0.2.9")
        audit.log_action_decision("d-crit", "s", action="notify", decision_trace={"suspicion_label": "critical"})
        audit.log_notification("t", "s", decision="sent")
        _settle(audit, relay)
        assert relay.enqueued_total == 2
    finally:
        relay.stop()
    rows = _rows(qpath)
    chain = {r["trace_id"]: r["chain_hash"] for r in _all_rows(tmp_path / "a.jsonl")}
    assert [(r["decision_id"], r["channel"], r["p0_basis"]) for r in rows] == [
        ("d-thr", "visual", "enforcement:throttle"), ("d-thr", "voice", "enforcement:throttle"),
        ("d-crit", "visual", "soc_critical"), ("d-crit", "voice", "soc_critical"),
    ]
    assert rows[0]["target"] == "192.0.2.9"
    assert all(r["decision_chain_hash"] == chain[r["decision_id"]] for r in rows)
    assert all(r["decision_record_durability"] == "fsynced" for r in rows)


def test_broken_queue_is_counted_and_never_reaches_log(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    qpath = tmp_path / "q.jsonl"
    os.mkdir(qpath)  # every enqueue fails
    relay = attach_p0_alert_relay(audit, qpath)
    try:
        out = audit.log_action_decision("d-1", "s", action="isolate")
        assert out["action"] == "isolate"
        _settle(audit, relay)
        assert relay.enqueue_failed_total == 1
    finally:
        relay.stop()
    os.rmdir(qpath)
    relay.relay(_decision("redirect", trace_id="d-2"), "fsynced", 1)
    assert _rows(qpath)[-1]["relay_enqueue_failed_total"] == 1


def test_losses_are_written_as_standalone_status_records(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    qpath = tmp_path / "q.jsonl"
    relay = attach_p0_alert_relay(audit, qpath)
    try:
        assert relay.ready.wait(5)
        with relay._counters_lock:
            relay.handoff_dropped_total += 3  # as on_durable_record counts a full hand-off
        assert _wait(lambda: any(r.get("event") == "loss" for r in _status(qpath)))
    finally:
        relay.stop()
    loss = [r for r in _status(qpath) if r.get("event") == "loss"][-1]
    assert loss["handoff_dropped_total"] == 3
    assert _rows(qpath) == []  # no P0 was needed to surface it


def test_non_durable_decision_is_alerted_and_marked_non_durable(tmp_path, monkeypatch):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    qpath = tmp_path / "q.jsonl"
    relay = attach_p0_alert_relay(audit, qpath)
    assert relay.ready.wait(5)
    real = os.fsync
    audit_ino = None

    def eio_on_audit(fd):
        if os.fstat(fd).st_ino == audit_ino:
            raise OSError(errno.EIO, "io")
        return real(fd)

    audit.log_action_decision("d-0", "s", action="observe")
    audit_ino = os.stat(tmp_path / "a.jsonl").st_ino
    monkeypatch.setattr(os, "fsync", eio_on_audit)
    try:
        with pytest.raises(AuditDurabilityError):
            audit.log_action_decision("d-1", "s", action="isolate")
        _settle(audit, relay)
    finally:
        relay.stop()
    rows = _rows(qpath)
    assert len(rows) == 2
    assert all(r["decision_record_durable"] is False and r["decision_record_durability"] == "fsync_failed" for r in rows)


def _crash_and_restart(tmp_path, before, missed, **kw):
    """A relay sees ``before``; decisions ``missed`` are written with no relay
    attached (a crash); a new logger + relay on the same files starts."""

    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(apath)
    relay = attach_p0_alert_relay(audit, qpath)
    for did, action in before:
        audit.log_action_decision(did, "s", action=action)
    _settle(audit, relay)
    assert relay.enqueued_total == sum(1 for _, a in before if a != "observe")
    relay.stop()
    plain = P0AuditLogger(apath)
    for did, action in missed:
        plain.log_action_decision(did, "s", action=action)
    audit2 = P0AuditLogger(apath)
    relay2 = attach_p0_alert_relay(audit2, qpath, **kw)
    assert relay2.ready.wait(5)
    return audit2, relay2, qpath


def test_restart_reconciles_p0_decisions_missed_while_down(tmp_path):
    audit, relay, qpath = _crash_and_restart(
        tmp_path, [("d-1", "throttle")], [("d-2", "observe"), ("d-3", "isolate"), ("d-4", "redirect")]
    )
    try:
        audit.log_action_decision("d-5", "s", action="throttle")
        _settle(audit, relay)
    finally:
        relay.stop()
    rows = _rows(qpath)
    assert len(rows) == 8
    assert [r["decision_id"] for r in rows[::2]] == ["d-1", "d-3", "d-4", "d-5"]
    assert {r["decision_record_durability"] for r in rows if r["decision_id"] in ("d-3", "d-4")} == {"reconciled_from_chain_fsynced"}
    started = [r for r in _status(qpath) if r.get("event") == "started"]
    assert started[-1]["cursor_found"] is True and started[-1]["reconciled"] == 2


def test_reconcile_is_bounded_and_counts_the_rest(tmp_path):
    audit, relay, qpath = _crash_and_restart(
        tmp_path, [("d-0", "throttle")], [(f"m-{i}", "isolate") for i in range(5)], max_reconcile=2
    )
    relay.stop()
    assert [r["decision_id"] for r in _rows(qpath)[::2]] == ["d-0", "m-3", "m-4"]  # the newest
    started = [r for r in _status(qpath) if r.get("event") == "started"][-1]
    assert started["reconciled"] == 2 and started["reconcile_skipped"] == 3


def _started(qpath):
    return [r for r in _status(qpath) if r.get("event") == "started"]


def test_fresh_queue_replays_the_newest_p0_decisions_bounded(tmp_path):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    plain = P0AuditLogger(apath)
    for i in range(4):
        plain.log_action_decision(f"old-{i}", "s", action="isolate")
    plain.log_action_decision("obs", "s", action="observe")
    relay = attach_p0_alert_relay(P0AuditLogger(apath), qpath, max_reconcile=3)
    assert relay.ready.wait(5)
    relay.stop()
    assert [r["decision_id"] for r in _rows(qpath)[::2]] == ["old-1", "old-2", "old-3"]
    started = _started(qpath)[-1]
    assert started["reconcile"] == "fresh_queue"
    assert started["reconciled"] == 3 and started["reconcile_skipped"] == 1 and started["unreconcilable"] == 0


def test_rotated_chain_counts_unreconcilable_and_next_start_replays_only_new(tmp_path):
    qpath = tmp_path / "q.jsonl"
    old = P0AuditLogger(tmp_path / "old.jsonl")
    first = attach_p0_alert_relay(old, qpath)
    assert first.ready.wait(5)
    old.log_action_decision("before-rotation", "s", action="isolate")
    _settle(old, first)
    first.stop()
    # The chain is replaced (rotated): the queue's cursor is not in it.
    apath = tmp_path / "a.jsonl"
    plain = P0AuditLogger(apath)
    plain.log_action_decision("q1", "s", action="throttle")
    plain.log_action_decision("q-obs", "s", action="observe")
    second = attach_p0_alert_relay(P0AuditLogger(apath), qpath)
    assert second.ready.wait(5)
    second.stop()
    started = _started(qpath)[-1]
    assert started["reconcile"] == "cursor_not_in_chain"
    assert started["unreconcilable"] == 1 and started["reconciled"] == 0
    assert [r["decision_id"] for r in _rows(qpath)[::2]] == ["before-rotation"]
    # Unrelated advance while down, then one new P0: the next start resumes at
    # the chain tail recorded by the previous start and replays only q2.
    plain.log_action_decision("q-obs-2", "s", action="observe")
    plain.log_action_decision("q2", "s", action="redirect")
    third = attach_p0_alert_relay(P0AuditLogger(apath), qpath)
    assert third.ready.wait(5)
    third.stop()
    started = _started(qpath)[-1]
    assert started["reconcile"] == "cursor_found" and started["reconciled"] == 1
    assert [r["decision_id"] for r in _rows(qpath)[::2]] == ["before-rotation", "q2"]


@pytest.mark.parametrize("fsync_ok,label,durable", [(True, "reconciled_from_chain_fsynced", True), (False, "reconciled_from_chain", False)])
def test_reconciled_durability_follows_the_fsync_result(tmp_path, monkeypatch, fsync_ok, label, durable):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    P0AuditLogger(apath).log_action_decision("old", "s", action="isolate")
    real = P0AlertQueue._fsync_fd
    monkeypatch.setattr(P0AlertQueue, "_fsync_fd", staticmethod(lambda fd: real(fd) and fsync_ok))
    relay = attach_p0_alert_relay(P0AuditLogger(apath), qpath)
    assert relay.ready.wait(5)
    relay.stop()
    rows = _rows(qpath)
    assert len(rows) == 2
    assert all(r["decision_record_durability"] == label and r["decision_record_durable"] is durable for r in rows)


def test_attach_reconciles_only_up_to_the_listener_registration(tmp_path):
    """Records written after attach reach the relay through the listener (with
    their durable stamp), never through the startup reconcile, however late the
    relay thread gets to run."""

    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    P0AuditLogger(apath).log_action_decision("before", "s", action="isolate")
    audit = P0AuditLogger(apath)
    gate = threading.Event()
    real = P0AlertRelay.reconcile

    def late(self):
        gate.wait(5)  # the relay thread is starved until after the live decision
        return real(self)

    import unittest.mock as mock

    with mock.patch.object(P0AlertRelay, "reconcile", late):
        relay = attach_p0_alert_relay(audit, qpath)
        audit.log_action_decision("live", "s", action="throttle")
        gate.set()
        _settle(audit, relay)
    relay.stop()
    rows = {r["decision_id"]: r for r in _rows(qpath)}
    assert rows["before"]["decision_record_durability"] == "reconciled_from_chain_fsynced"
    assert rows["live"]["decision_record_durability"] == "fsynced"
    assert isinstance(rows["live"]["decision_durable_monotonic_ns"], int)
    assert len(_rows(qpath)) == 4


def test_listener_before_reconcile_window_never_enqueues_twice(tmp_path):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    audit = P0AuditLogger(apath)
    relay = P0AlertRelay(P0AlertQueue(qpath), audit_path=apath, audit_logger=audit)
    audit.add_durable_listener(relay.on_durable_record)
    # Written after the listener is registered and before the relay starts:
    # the record is both in the hand-off and in the chain reconcile reads.
    audit.log_action_decision("both", "s", action="isolate")
    assert audit.wait_durable_listeners()
    assert relay.pending() == 1
    relay.start()
    assert relay.ready.wait(5) and relay.wait_idle(5)
    relay.stop()
    assert [r["decision_id"] for r in _rows(qpath)] == ["both", "both"]


def test_reconcile_never_re_enqueues_what_the_queue_already_has(tmp_path):
    apath, qpath = tmp_path / "a.jsonl", tmp_path / "q.jsonl"
    plain = P0AuditLogger(apath)
    a = plain.log_action_decision("a", "s", action="isolate")
    b = plain.log_action_decision("b", "s", action="isolate")
    queue = P0AlertQueue(qpath)
    P0AlertRelay(queue).relay(b, "fsynced", 1)
    queue.append_status({"event": "test", "audit_cursor_chain_hash": a["chain_hash"]})  # a stale cursor
    relay = attach_p0_alert_relay(P0AuditLogger(apath), qpath)
    assert relay.ready.wait(5)
    relay.stop()
    assert [r["decision_id"] for r in _rows(qpath)] == ["b", "b"]
    assert _started(qpath)[-1]["reconcile"] == "cursor_found"


def test_pending_and_wait_idle_are_public(tmp_path):
    relay = P0AlertRelay(P0AlertQueue(tmp_path / "q.jsonl"))
    relay.on_durable_record(_decision("isolate", chain_hash="c" * 64), "fsynced", 1)
    assert relay.pending() == 1 and relay.wait_idle(0.05) is False
    relay.start()
    assert relay.wait_idle(5) and relay.pending() == 0
    relay.stop()


def test_attach_is_idempotent_per_logger(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    first = attach_p0_alert_relay(audit, tmp_path / "q.jsonl")
    try:
        assert attach_p0_alert_relay(audit, tmp_path / "q.jsonl") is first
        assert audit._durable_listeners == [first.on_durable_record]
    finally:
        first.stop()


def test_production_opencanary_controller_attaches_the_relay(tmp_path):
    from azazel_edge.opencanary_redirect import OpenCanaryRedirectController

    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    controller = OpenCanaryRedirectController(
        audit, state_path=tmp_path / "state.json", redirect_log_path=tmp_path / "redirect.jsonl"
    )
    try:
        assert isinstance(controller.p0_alert_relay, P0AlertRelay)
        assert controller.p0_alert_relay.on_durable_record in audit._durable_listeners
        assert controller.p0_alert_relay.queue.path == tmp_path / "p0-alert-queue.jsonl"
        out = controller.apply({"redirect": True, "trace_id": "oc-1", "target_ip": "192.0.2.7", "reason": "r"})
        assert out["applied"] is True
        qpath = tmp_path / "p0-alert-queue.jsonl"
        _settle(audit, controller.p0_alert_relay)
        rows = _rows(qpath)
        assert len(rows) == 2
        assert {r["channel"] for r in rows} == {"visual", "voice"}
        assert all(r["decision_id"] == "oc-1" and r["p0_basis"] == "enforcement:redirect" for r in rows)
    finally:
        controller.p0_alert_relay.stop()


def test_opencanary_controller_works_when_the_relay_cannot_attach(tmp_path):
    from azazel_edge.opencanary_redirect import OpenCanaryRedirectController

    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    controller = OpenCanaryRedirectController(
        audit, state_path=tmp_path / "state.json", redirect_log_path=tmp_path / "redirect.jsonl",
        p0_alert_queue_path=blocker / "q.jsonl",  # parent is a file: cannot be created
    )
    assert controller.p0_alert_relay is None
    out = controller.apply({"redirect": True, "trace_id": "oc-1", "target_ip": "192.0.2.7", "reason": "r"})
    assert out["applied"] is True


def test_full_handoff_is_counted_and_recorded(tmp_path):
    queue = P0AlertQueue(tmp_path / "q.jsonl")
    relay = P0AlertRelay(queue, max_pending=1)  # not started: the hand-off fills
    relay.on_durable_record(_decision("throttle", trace_id="a", chain_hash="a" * 64), "fsynced", 1)
    relay.on_durable_record(_decision("throttle", trace_id="b", chain_hash="b" * 64), "fsynced", 2)
    assert relay.handoff_dropped_total == 1
    relay.start()
    relay.stop()
    rows = _rows(tmp_path / "q.jsonl")
    assert [r["decision_id"] for r in rows] == ["a", "a"]
    assert _status(tmp_path / "q.jsonl")[0]["handoff_dropped_total"] == 1


def test_on_relayed_failure_is_contained(tmp_path):
    def broken(decision_id, result):
        raise RuntimeError("observer down")

    relay = P0AlertRelay(P0AlertQueue(tmp_path / "q.jsonl"), on_relayed=broken)
    assert relay.relay(_decision("isolate"), "fsynced", 1)["ok"] is True


# ---------------------------------------------------------------- harness
#
# The harness drives the real path: the Rust core binary (rust_core_bin, see
# conftest.py) decides, forwards to the AI agent service script the unit's
# ExecStart runs, and the agent's relay enqueues. Each test below takes one
# piece of that path away, or makes it disagree, and expects the row to lose
# its pass.


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(
        rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True}
    )


@pytest.fixture
def small_row(monkeypatch):
    """The SO-03 row with a small sample count, for mechanics only."""

    row = dict(rec.OBJECTIVE_SPECS["SO-03"][PART])
    row["required_samples"] = 9
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-03", {PART: row})
    return row


def _part(record):
    return record["parts"][0]


def _prereqs(record):
    return {p["id"]: p["met"] for p in _part(record)["prerequisites"]}


def _gaps(record):
    return [g["id"] for g in _part(record)["gaps"]]


def _run(core, samples=8, seed=3):
    return so03_alert_queue.run(core_bin=core, samples=samples, seed=seed)


def test_without_the_core_binary_nothing_is_measured(clean_owner, tmp_path):
    record = so03_alert_queue.run(core_bin=tmp_path / "absent-core", samples=4)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _part(record)["samples"] == []
    assert _prereqs(record)["core_binary_present"] is False
    assert _gaps(record) == list(ALL_GAPS)


def test_the_measured_agent_is_the_units_execstart_script():
    unit = ROOT / "systemd" / "azazel-edge-ai-agent.service"
    assert so03_alert_queue.agent_service_script(unit) == ROOT / "py" / "azazel_edge_ai" / "agent.py"
    core_env = so03_alert_queue.unit_environment(ROOT / "systemd" / "azazel-edge-core.service")
    assert core_env["AZAZEL_DEFENSE_ENFORCE"] == "false" and core_env["AZAZEL_DEFENSE_DRY_RUN"] == "true"
    env = so03_alert_queue.core_environment(Path("/w"), Path("/w/s.sock"))
    assert env["AZAZEL_DEFENSE_ENFORCE"] == "false" and env["AZAZEL_DEFENSE_DRY_RUN"] == "true"
    assert env["AZAZEL_DEFENSE_ENFORCE_LEVEL"] == core_env["AZAZEL_DEFENSE_ENFORCE_LEVEL"]


def test_slow_enqueue_fails(clean_owner, small_row, rust_core_bin, monkeypatch):
    real = P0AlertQueue.enqueue
    calls = {"n": 0}

    def slow(self, alerts, extra=None):
        calls["n"] += 1
        if calls["n"] == 4:
            time.sleep(2.05)
        return real(self, alerts, extra)

    monkeypatch.setattr(P0AlertQueue, "enqueue", slow)
    record = _run(rust_core_bin, samples=9)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_FAIL
    assert _part(record)["pass_rule"]["evaluated"]["violations"] == 1
    assert _gaps(record) == []


def test_relay_not_attached_by_the_service_is_not_measurable(clean_owner, rust_core_bin, monkeypatch):
    def refuse(*a, **k):
        raise OSError("relay refused")

    # The agent service imports the attach function when it is loaded.
    monkeypatch.setattr(p0_alert, "attach_p0_alert_relay", refuse)
    record = _run(rust_core_bin, samples=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["agent_service_relay_attached"] is False
    assert _part(record)["samples"] == []
    assert _gaps(record) == list(ALL_GAPS)


def test_enqueue_without_a_record_is_not_measurable(clean_owner, rust_core_bin, monkeypatch):
    monkeypatch.setattr(P0AlertQueue, "enqueue", lambda self, alerts, extra=None: {"ok": True, "durability": "fsynced"})
    record = _run(rust_core_bin, samples=6)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert all(s["end_monotonic_ns"] is None for s in _part(record)["samples"])
    assert _gaps(record) == list(ALL_GAPS)


def test_not_p0_decisions_are_not_alerted_and_not_measurable(clean_owner, rust_core_bin, monkeypatch):
    monkeypatch.setattr(so03_alert_queue, "END_WAIT_S", 1.0)
    monkeypatch.setattr(p0_alert, "classify_p0", lambda record: "")
    record = _run(rust_core_bin, samples=4)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert all(s["queue_records"] == [] for s in _part(record)["samples"])
    assert _gaps(record) == list(ALL_GAPS)


def test_wrong_p0_basis_keeps_the_path_gaps(clean_owner, rust_core_bin, monkeypatch):
    real = p0_alert.build_p0_alerts
    monkeypatch.setattr(
        p0_alert, "build_p0_alerts",
        lambda record, basis, durability, durable_ns: real(record, "enforcement:throttle", durability, durable_ns),
    )
    record = _run(rust_core_bin, samples=6)
    assert rec.validate_record(record) == []
    assert _prereqs(record)["enqueue_record_classifies_p0"] is False
    assert _gaps(record) == ["SO03-NO-P0-ALERT-PATH", CORE_GAP]


def test_alert_without_the_cores_enforcement_mode_keeps_the_core_gap(clean_owner, rust_core_bin, monkeypatch):
    real = p0_alert.build_p0_alerts
    monkeypatch.setattr(p0_alert, "build_p0_alerts", lambda *a: [dict(x, enforcement_mode="") for x in real(*a)])
    record = _run(rust_core_bin, samples=6)
    assert rec.validate_record(record) == []
    assert all(_prereqs(record).values())
    assert _gaps(record) == [CORE_GAP]


def test_one_channel_only_keeps_all_gaps(clean_owner, rust_core_bin, monkeypatch):
    real = p0_alert.build_p0_alerts
    monkeypatch.setattr(p0_alert, "build_p0_alerts", lambda *a: real(*a)[:1])
    record = _run(rust_core_bin, samples=6)
    assert rec.validate_record(record) == []
    assert _prereqs(record)["visual_voice_delivery_queue_declared"] is False
    assert _gaps(record) == list(ALL_GAPS)


def test_entries_naming_another_decision_are_not_this_samples(clean_owner, rust_core_bin, monkeypatch):
    real = p0_alert.build_p0_alerts

    def other(record, *a):
        return [dict(x, decision_id="trace-0x0") for x in real(record, *a)]

    monkeypatch.setattr(p0_alert, "build_p0_alerts", other)
    record = _run(rust_core_bin, samples=6)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_names_decision_id"] is False


def test_decision_record_not_durable_is_not_measurable(clean_owner, rust_core_bin, monkeypatch):
    monkeypatch.setattr(logger_mod, "DURABLE_KINDS", frozenset({"notification"}))
    monkeypatch.setattr(so03_alert_queue, "END_WAIT_S", 1.0)  # nothing is ever relayed
    record = _run(rust_core_bin, samples=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["decision_and_enqueue_records_fsynced"] is False


def test_queue_not_fsynced_is_not_measurable(clean_owner, rust_core_bin, monkeypatch):
    monkeypatch.setattr(P0AlertQueue, "_fsync_fd", staticmethod(lambda fd: True))
    monkeypatch.setattr(p0_alert, "fsync_path", lambda path: True)
    record = _run(rust_core_bin, samples=6)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["decision_and_enqueue_records_fsynced"] is False
    assert _gaps(record) == list(ALL_GAPS)


def test_broken_chain_is_not_measurable(clean_owner, rust_core_bin, monkeypatch):
    real = P0AuditLogger.verify_chain
    monkeypatch.setattr(P0AuditLogger, "verify_chain", classmethod(lambda cls, path: dict(real(path), ok=False, error="x")))
    record = _run(rust_core_bin, samples=4)
    assert _prereqs(record)["alert_audit_chain_verifies"] is False


# -------------------------------------------------------------- validator


@pytest.fixture(scope="module")
def genuine_pass(rust_core_bin):
    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True})
        record = so03_alert_queue.run(core_bin=rust_core_bin, seed=5)
        yield record
    finally:
        mp.undo()


def test_full_run_through_the_core_is_a_pass(genuine_pass):
    record = genuine_pass
    assert rec.validate_record(record) == []
    assert len(_part(record)["samples"]) == 200
    assert _gaps(record) == []
    assert all(_prereqs(record).values()), _prereqs(record)
    assert record["verdict"] == rec.VERDICT_PASS
    samples = _part(record)["samples"]
    assert {s["action"] for s in samples} == {"isolate", "redirect", "throttle"}
    assert {s["core_enforcement_mode"] for s in samples} == {"dry_run"}
    assert all(s["decision_source"] == "azazel-edge-core" and s["core_sid"] == s["harness_sid"] for s in samples)
    assert max(s["elapsed_ms"] for s in samples) <= 2000.0


@pytest.mark.parametrize(
    "mutate,prereq",
    [
        (lambda s: s["queue_records"][0].__setitem__("decision_id", "trace-0x0"), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][1].__setitem__("decision_chain_hash", "0" * 64), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][0].__setitem__("enqueued_monotonic_ns", 1), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][0].__setitem__("decision_durable_monotonic_ns", 1), "enqueue_record_names_decision_id"),
        (lambda s: s.__setitem__("edge_decision_durable_monotonic_ns", 1), "enqueue_record_names_decision_id"),
        (lambda s: s.__setitem__("harness_eve_append_monotonic_ns", s["start_monotonic_ns"] + 1), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"].pop(), "visual_voice_delivery_queue_declared"),
        (lambda s: s["queue_records"][1].__setitem__("channel", "visual"), "visual_voice_delivery_queue_declared"),
        (lambda s: s["queue_records"][0].__setitem__("schema", "other"), "visual_voice_delivery_queue_declared"),
        (lambda s: s["queue_records"][0].__setitem__("extra", 1), "visual_voice_delivery_queue_declared"),
        (lambda s: s["queue_records"][0].__setitem__("p0_basis", "soc_critical"), "enqueue_record_classifies_p0"),
        (lambda s: s["queue_records"][0].__setitem__("p0_rule", "x"), "enqueue_record_classifies_p0"),
        (lambda s: (s.__setitem__("action", "notify"), s.__setitem__("decision_suspicion_label", "high")), "enqueue_record_classifies_p0"),
        (lambda s: s.__setitem__("decision_record_fsynced", False), "decision_and_enqueue_records_fsynced"),
        (lambda s: s.__setitem__("enqueue_record_fsynced", False), "decision_and_enqueue_records_fsynced"),
        (lambda s: s.__setitem__("enqueue_result_durability", "fsync_unsupported"), "decision_and_enqueue_records_fsynced"),
        (lambda s: s["queue_records"][0].__setitem__("decision_record_durable", False), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][0].__setitem__("record_type", "relay_status"), "visual_voice_delivery_queue_declared"),
    ],
)
def test_validator_recomputes_from_samples(genuine_pass, mutate, prereq):
    forged = copy.deepcopy(genuine_pass)
    mutate(forged["parts"][0]["samples"][42])
    errors = rec.validate_record(forged)
    assert any(f"prerequisite {prereq!r} declared met but the samples do not show it" in e for e in errors), errors
    # The closed gaps re-open: leaving them out is now refused.
    assert any("mandatory gap 'SO03-NO-P0-ALERT-PATH' omitted" in e for e in errors), errors
    assert any(f"mandatory gap {CORE_GAP!r} omitted" in e for e in errors), errors


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.__setitem__("decision_source", "so03_harness_arbiter"),
        lambda s: s.__setitem__("core_pipeline", "python_arbiter"),
        lambda s: s.__setitem__("core_sid", s["harness_sid"] + 1),
        lambda s: s.__setitem__("core_sid", None),
        lambda s: s.__setitem__("harness_expected_action", "notify"),
        lambda s: s.__setitem__("core_enforcement_mode", "unknown"),
        lambda s: s["queue_records"][1].__setitem__("enforcement_mode", "enforced"),
        lambda s: s["queue_records"][0].__setitem__("effective_action", "observe"),
    ],
)
def test_core_gap_closes_only_on_core_decisions(genuine_pass, mutate):
    forged = copy.deepcopy(genuine_pass)
    mutate(forged["parts"][0]["samples"][17])
    errors = rec.validate_record(forged)
    assert any(f"mandatory gap {CORE_GAP!r} omitted" in e for e in errors), errors
    assert not any("mandatory gap 'SO03-NO-P0-ALERT-PATH' omitted" in e for e in errors), errors


def test_an_applied_enforcement_is_never_a_measurement(genuine_pass):
    forged = copy.deepcopy(genuine_pass)
    sample = forged["parts"][0]["samples"][3]
    sample["core_enforcement_mode"] = "enforced"
    for r in sample["queue_records"]:
        r["enforcement_mode"] = "enforced"
    errors = rec.validate_record(forged)
    assert any("prerequisite 'core_enforcement_not_applied' declared met but the samples do not show it" in e for e in errors), errors


def test_validator_refuses_an_end_without_a_durable_enqueue_record(genuine_pass):
    forged = copy.deepcopy(genuine_pass)
    forged["parts"][0]["samples"][7]["queue_records"] = []
    errors = rec.validate_record(forged)
    assert any("samples[7]: end given but the observed fields do not show a durable enqueue record" in e for e in errors), errors


def test_validator_p0_rule_is_independent_of_the_product():
    for action, label in [("throttle", "low"), ("redirect", ""), ("isolate", None), ("notify", "critical"),
                          ("observe", "critical"), ("notify", "high"), ("observe", "low")]:
        record = {"kind": "action_decision", "action": action, "decision_trace": {"suspicion_label": label}}
        assert rec.so03_expected_p0_basis(action, label) == classify_p0(record)
    assert rec.SO03_P0_RULE == p0_alert.P0_RULE and rec.SO03_QUEUE_SCHEMA == p0_alert.QUEUE_SCHEMA


def test_fixed_row_bound_and_samples_are_unchanged():
    row = rec.OBJECTIVE_SPECS["SO-03"][PART]
    assert row["bound_ms"] == 2000.0 and row["required_samples"] == 200 and row["kind"] == rec.RULE_EVERY_SAMPLE_MAX
    assert set(row["gaps"]) == set(ALL_GAPS) and set(row["gaps_closed_by_samples"]) == set(ALL_GAPS)
    assert {g for g in rec.GAP_CLOSERS if g.startswith("SO03-")} == set(ALL_GAPS)
    assert rec.GAP_CLOSERS["SO03-NO-VISUAL-VOICE-QUEUE"] is rec.so03_visual_voice_queue_observed
    assert rec.GAP_CLOSERS["SO03-NO-P0-ALERT-PATH"] is rec.so03_p0_alert_path_observed
    assert rec.GAP_CLOSERS[CORE_GAP] is rec.so03_core_decisions_relayed
    assert set(rec.so03_observed_prerequisites([{}])) <= set(row["prerequisites"])
    # Run health is never excused in CI.
    assert rec.CI_DECLARED_PREREQUISITES["SO-03"] == frozenset()
