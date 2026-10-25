"""SO-03 records (Edge#414): the decision record is durable, and the
DecisionNotifier/OfflineQueueNotifier enqueue record names the decision and
carries a record-only alert class. The SO-03 harness and validator now measure
the P0 alert path (tests/test_service_objectives_so03_p0_queue_v1.py).

Most tests take a record away, or make it disagree, and expect the row to
become not_measurable or fail -- never pass.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge.audit import P0AuditLogger  # noqa: E402
import azazel_edge.audit.logger as logger_mod  # noqa: E402
from azazel_edge.notify import DecisionNotifier, OfflineQueueNotifier  # noqa: E402
import azazel_edge.notify.delivery as delivery  # noqa: E402

CRITICAL = {"action": "notify", "reason": "soc_high_but_noc_fragile", "chosen_evidence_ids": ["ev-1"]}
WARNING = {"action": "notify", "reason": "noc_degraded_requires_operator_attention", "chosen_evidence_ids": ["ev-2"]}


class _Spy:
    """Records the inode of every fsync, and the file's content at that moment."""

    def __init__(self, monkeypatch):
        self.calls = []
        real = os.fsync

        def spy(fd):
            st = os.fstat(fd)
            self.calls.append((st.st_dev, st.st_ino))
            return real(fd)

        monkeypatch.setattr(os, "fsync", spy)

    def synced(self, path: Path) -> int:
        st = os.stat(path)
        return self.calls.count((st.st_dev, st.st_ino))


# ----------------------------------------------------------------- records


def test_enqueue_and_notification_records_name_the_decision(tmp_path):
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    queue = OfflineQueueNotifier(tmp_path / "queue.jsonl", delegate=None)
    before = time.monotonic_ns()
    result = DecisionNotifier([queue], audit).notify(CRITICAL, {"operator_wording": "w"}, target="192.0.2.1", decision_id="dec-1")
    after = time.monotonic_ns()
    assert result["ok"] is True
    entry = json.loads((tmp_path / "queue.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert entry["decision_id"] == "dec-1"
    assert entry["alert_class"] == "P0"
    assert before <= entry["enqueued_monotonic_ns"] <= after
    assert isinstance(entry["enqueued_monotonic_ns"], int)
    row = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert row["kind"] == "notification" and row["decision"] == "sent"
    assert row["decision_id"] == "dec-1" and row["alert_class"] == "P0"
    assert row["alert_class_rule"] == delivery.ALERT_CLASS_RULE
    # The existing key is unchanged: the record is still traced by target.
    assert row["trace_id"] == "192.0.2.1"
    assert P0AuditLogger.verify_chain(tmp_path / "audit.jsonl")["ok"] is True


def test_alert_class_is_only_p0_for_notify_at_critical(tmp_path):
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    notifier = DecisionNotifier([OfflineQueueNotifier(tmp_path / "q.jsonl", delegate=None)], audit)
    warn = notifier.notify(WARNING, {}, target="t", decision_id="d-w")
    skip = notifier.notify({"action": "throttle", "reason": "x"}, {}, target="t", decision_id="d-t")
    assert warn["payload"]["level"] == "warning" and warn["payload"]["alert_class"] == ""
    assert skip["skipped"] is True
    rows = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["decision"] == "skipped" and rows[-1]["alert_class"] == "" and rows[-1]["decision_id"] == "d-t"


class _Recorder:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, payload):
        self.sent.append(dict(payload))
        if self.fail:
            raise RuntimeError("down")
        return {"ok": True, "adapter": "rec", "status": 200}


@pytest.mark.parametrize("arbiter", [CRITICAL, WARNING, {"action": "observe", "reason": "baseline"}])
def test_alert_class_changes_no_routing_level_or_outcome(tmp_path, monkeypatch, arbiter):
    """Whatever the class says, the same adapters are tried in the same order
    with the same level and the outcome is the same."""

    outcomes = []
    for i, forced in enumerate(("P0", "", "anything")):
        monkeypatch.setattr(delivery, "classify_alert", lambda action, level, forced=forced: forced)
        first, second = _Recorder(fail=True), _Recorder()
        audit = P0AuditLogger(tmp_path / f"a{i}.jsonl")
        result = DecisionNotifier([first, second], audit).notify(arbiter, {"operator_wording": "w"}, target="t", decision_id="d")
        strip = lambda p: {k: v for k, v in p.items() if k != "alert_class"}  # noqa: E731
        outcomes.append(
            (
                result.get("ok"), result.get("skipped"), result.get("adapter"),
                [strip(p) for p in first.sent], [strip(p) for p in second.sent],
                (result.get("payload") or {}).get("level"),
            )
        )
    assert outcomes[0] == outcomes[1] == outcomes[2]


def test_notify_without_decision_id_names_nothing(tmp_path):
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    queue = OfflineQueueNotifier(tmp_path / "queue.jsonl", delegate=None)
    DecisionNotifier([queue], audit).notify(CRITICAL, {}, target="t")
    entry = json.loads((tmp_path / "queue.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert entry["decision_id"] == ""


def test_logger_fsyncs_decision_and_notification_after_close(tmp_path, monkeypatch):
    path = tmp_path / "sub" / "audit.jsonl"
    audit = P0AuditLogger(path)
    audit.log_event_receive("t", "s")
    lines_at_fsync = []
    real = os.fsync

    def spy(fd):
        if os.fstat(fd).st_ino == os.stat(path).st_ino:
            lines_at_fsync.append(path.read_text(encoding="utf-8").count("\n"))
        return real(fd)

    monkeypatch.setattr(os, "fsync", spy)
    audit.log_event_receive("t2", "s")
    assert lines_at_fsync == []  # high-rate kinds are not fsynced
    audit.log_action_decision("d", "s")
    audit.log_notification("d", "s")
    # One fsync per durable record, each after its record is complete in the file.
    assert lines_at_fsync == [3, 4]
    assert P0AuditLogger.verify_chain(path)["ok"] is True


def test_logger_fsyncs_the_directory_of_a_new_file(tmp_path, monkeypatch):
    spy = _Spy(monkeypatch)
    path = tmp_path / "audit.jsonl"
    audit = P0AuditLogger(path)
    audit.log_action_decision("d", "s")
    assert spy.synced(path) == 1 and spy.synced(tmp_path) == 1
    audit.log_action_decision("d2", "s")
    assert spy.synced(path) == 2 and spy.synced(tmp_path) == 1


def test_logger_raises_when_fsync_fails_but_keeps_the_chain(tmp_path, monkeypatch):
    import errno

    path = tmp_path / "audit.jsonl"
    audit = P0AuditLogger(path)

    def eio(fd):
        raise OSError(errno.EIO, "io")

    monkeypatch.setattr(os, "fsync", eio)
    with pytest.raises(OSError):
        audit.log_action_decision("d", "s")
    monkeypatch.undo()
    audit.log_action_decision("d2", "s")
    assert P0AuditLogger.verify_chain(path)["ok"] is True


def test_logger_tolerates_a_file_system_that_cannot_sync_and_says_so(tmp_path, monkeypatch, caplog):
    import errno

    def einval(fd):
        raise OSError(errno.EINVAL, "no sync here")

    monkeypatch.setattr(os, "fsync", einval)
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    with caplog.at_level("WARNING", logger="azazel_edge.audit.logger"):
        _, durability = audit.log_reporting_durability("action_decision", "d", "s")
    assert durability == logger_mod.DURABILITY_UNSUPPORTED
    assert audit.fsync_unsupported_count == 1
    assert any("fsync_unsupported" in r.getMessage() for r in caplog.records)
    # A kind outside DURABLE_KINDS says so instead of claiming durability.
    assert audit.log_reporting_durability("event_receive", "e", "s")[1] == logger_mod.DURABILITY_NOT_REQUIRED


def test_queue_is_replaced_durably(tmp_path, monkeypatch):
    events = []
    real_fsync, real_replace = os.fsync, os.replace
    qpath = tmp_path / "queue.jsonl"

    def fsync(fd):
        st = os.fstat(fd)
        events.append(("fsync", "dir" if st.st_ino == os.stat(tmp_path).st_ino else "file"))
        return real_fsync(fd)

    def replace(a, b):
        events.append(("replace", Path(b).name))
        return real_replace(a, b)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    queue = OfflineQueueNotifier(qpath, delegate=None)
    assert queue.send({"action": "notify", "decision_id": "d1"})["ok"] is True
    assert events == [("fsync", "file"), ("replace", "queue.jsonl"), ("fsync", "dir")]
    assert list(tmp_path.glob("*.tmp")) == []
    assert queue.queue_depth() == 1


# ------------------------------------------- send vs. record (review of #438)


class _Counting:
    def __init__(self, fail=False):
        self.n = 0
        self.fail = fail

    def send(self, payload):
        self.n += 1
        if self.fail:
            raise RuntimeError("down")
        return {"ok": True, "adapter": "x", "status": 200}


def _eio(fd):
    import errno

    raise OSError(errno.EIO, "io")


def _rows(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def test_notification_fsync_failure_does_not_resend_or_raise(tmp_path, monkeypatch):
    first, second = _Counting(), _Counting()
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    monkeypatch.setattr(os, "fsync", _eio)
    result = DecisionNotifier([first, second], audit).notify(CRITICAL, {}, target="t", decision_id="d1")
    monkeypatch.undo()
    assert (first.n, second.n) == (1, 0)  # sent once, not re-sent on the next adapter
    assert result["ok"] is True and result["adapter"] == "x"
    assert result["audit_record"] == "not_durable" and "audit_record_not_durable" in result["audit_error"]
    rows = _rows(tmp_path / "audit.jsonl")
    assert [(r["kind"], r["decision"]) for r in rows] == [("notification", "sent")]
    assert P0AuditLogger.verify_chain(tmp_path / "audit.jsonl")["ok"] is True


def test_failed_send_stays_failed_when_its_record_is_not_durable(tmp_path, monkeypatch):
    down = _Counting(fail=True)
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    monkeypatch.setattr(os, "fsync", _eio)
    result = DecisionNotifier([down], audit).notify(CRITICAL, {}, target="t", decision_id="d1")
    monkeypatch.undo()
    assert down.n == 1
    assert result["ok"] is False and result["audit_record"] == "not_durable"
    assert [r["decision"] for r in _rows(tmp_path / "audit.jsonl")] == ["failed"]


def test_notification_record_write_failure_is_reported_not_raised(tmp_path, monkeypatch):
    first, second = _Counting(), _Counting()
    audit = P0AuditLogger(tmp_path / "audit.jsonl")

    def broken(self, *a, **k):
        raise OSError(28, "no space")

    monkeypatch.setattr(P0AuditLogger, "log_reporting_durability", broken)
    result = DecisionNotifier([first, second], audit).notify(CRITICAL, {}, target="t", decision_id="d1")
    assert (first.n, second.n) == (1, 0)
    assert result["ok"] is True and result["audit_record"] == "not_written"


def test_durable_notification_record_is_reported(tmp_path):
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    result = DecisionNotifier([_Counting()], audit).notify(CRITICAL, {}, target="t", decision_id="d1")
    assert result["audit_record"] == "durable" and "audit_error" not in result
    skipped = DecisionNotifier([_Counting()], audit).notify({"action": "observe"}, {}, target="t", decision_id="d2")
    assert skipped["ok"] is False and skipped["skipped"] is True and skipped["audit_record"] == "durable"


def test_notification_on_a_file_system_that_cannot_sync_is_reported_not_durable(tmp_path, monkeypatch):
    import errno

    def einval(fd):
        raise OSError(errno.EINVAL, "no sync here")

    first, second = _Counting(), _Counting()
    audit = P0AuditLogger(tmp_path / "audit.jsonl")
    monkeypatch.setattr(os, "fsync", einval)
    result = DecisionNotifier([first, second], audit).notify(CRITICAL, {}, target="t", decision_id="d1")
    assert (first.n, second.n) == (1, 0)
    assert result["ok"] is True
    assert result["audit_record"] == "not_durable" and result["audit_error"] == logger_mod.DURABILITY_UNSUPPORTED


def test_concurrent_sends_keep_every_entry(tmp_path):
    import threading

    qpath = tmp_path / "q.jsonl"
    queues = [OfflineQueueNotifier(qpath, delegate=None) for _ in range(2)]
    errors = []

    def worker(i):
        for j in range(30):
            r = queues[i % 2].send({"action": "notify", "decision_id": f"{i}-{j}"})
            if not r["ok"]:
                errors.append(r["error"])

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ids = sorted(e["decision_id"] for e in _rows(qpath))
    assert errors == []
    assert ids == sorted(f"{i}-{j}" for i in range(4) for j in range(30))
    assert list(tmp_path.glob("*.tmp")) == []


def test_failed_queue_write_removes_its_temp_file(tmp_path, monkeypatch):
    def refuse(a, b):
        raise OSError(13, "denied")

    monkeypatch.setattr(os, "replace", refuse)
    result = OfflineQueueNotifier(tmp_path / "q.jsonl", delegate=None).send({"action": "notify"})
    assert result["ok"] is False
    assert list(tmp_path.glob("*.tmp")) == []


def test_flush_keeps_entries_enqueued_while_delivering(tmp_path):
    qpath = tmp_path / "q.jsonl"

    class Delegate:
        def __init__(self):
            self.queue = None

        def send(self, entry):
            if entry.get("decision_id") == "a":
                self.queue.send({"action": "notify", "decision_id": "late"})
            return {"ok": True}

    d = Delegate()
    queue = OfflineQueueNotifier(qpath, delegate=d)
    d.queue = OfflineQueueNotifier(qpath, delegate=None)
    queue.send({"action": "notify", "decision_id": "a"})
    queue.send({"action": "notify", "decision_id": "b"})
    result = queue.flush()
    assert result == {"flushed": 2, "failed": 0, "remaining": 1}
    assert [e["decision_id"] for e in _rows(qpath)] == ["late"]


def test_flush_keeps_entries_whose_delivery_failed(tmp_path):
    qpath = tmp_path / "q.jsonl"

    class Delegate:
        def send(self, entry):
            if entry.get("decision_id") == "refused":
                return {"ok": False, "error": "refused"}
            if entry.get("decision_id") == "raises":
                raise RuntimeError("down")
            return {"ok": True}

    queue = OfflineQueueNotifier(qpath, delegate=Delegate())
    for did in ("a", "refused", "b", "raises"):
        queue.send({"action": "notify", "decision_id": did})
    result = queue.flush()
    assert result == {"flushed": 2, "failed": 2, "remaining": 2}
    assert [e["decision_id"] for e in _rows(qpath)] == ["refused", "raises"]


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW") or os.name != "posix", reason="POSIX O_NOFOLLOW")
def test_symlinked_lock_file_is_refused(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    qpath = tmp_path / "q.jsonl"
    (tmp_path / "q.jsonl.lock").symlink_to(victim)
    result = OfflineQueueNotifier(qpath, delegate=None).send({"action": "notify", "decision_id": "d"})
    assert result["ok"] is False
    assert victim.read_text(encoding="utf-8") == "keep"
    assert not qpath.exists()


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW") or os.name != "posix", reason="POSIX O_NOFOLLOW")
def test_symlinked_temp_file_is_refused(tmp_path, monkeypatch):
    import threading

    victim = tmp_path / "victim"
    victim.write_text("keep", encoding="utf-8")
    qpath = tmp_path / "q.jsonl"
    tmp = tmp_path / f"q.jsonl.{os.getpid()}.{threading.get_ident()}.tmp"
    tmp.symlink_to(victim)
    result = OfflineQueueNotifier(qpath, delegate=None).send({"action": "notify", "decision_id": "d"})
    assert result["ok"] is False
    assert victim.read_text(encoding="utf-8") == "keep"
    assert not qpath.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_queue_and_lock_files_are_private(tmp_path):
    import stat

    qpath = tmp_path / "q.jsonl"
    OfflineQueueNotifier(qpath, delegate=None).send({"action": "notify", "decision_id": "d"})
    assert stat.S_IMODE(os.stat(qpath).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(tmp_path / "q.jsonl.lock").st_mode) == 0o600


def test_log_action_decision_documents_the_duplicate_on_retry():
    doc = P0AuditLogger.log_action_decision.__doc__ or ""
    assert "AuditDurabilityError" in doc and "after" in doc and "second time" in doc
