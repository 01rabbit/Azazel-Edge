"""SO-03 records (Edge#414): the decision record is durable, the enqueue record
names the decision and carries a record-only P0 class, and the harness and
validator measure from those records instead of from declarations.

Most tests take a record away, or make it disagree, and expect the row to
become not_measurable or fail -- never pass.
"""

from __future__ import annotations

import copy
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
from azazel_edge.service_objectives import record as rec  # noqa: E402
from azazel_edge.service_objectives import so03_alert_queue  # noqa: E402

PART = "decision_durable_to_alert_enqueued"
CRITICAL = {"action": "notify", "reason": "soc_high_but_noc_fragile", "chosen_evidence_ids": ["ev-1"]}
WARNING = {"action": "notify", "reason": "noc_degraded_requires_operator_attention", "chosen_evidence_ids": ["ev-2"]}


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(
        rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True}
    )


@pytest.fixture
def closed_table(monkeypatch):
    """The SO-03 row as it would be once the visual/voice queue and the P0 alert
    path exist: same bound and sample count, those two gaps and the queue
    prerequisite removed, every record prerequisite kept."""

    row = dict(rec.OBJECTIVE_SPECS["SO-03"][PART])
    row["prerequisites"] = tuple(p for p in row["prerequisites"] if p != "visual_voice_delivery_queue_declared")
    row["gaps"] = ()
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-03", {PART: row})
    return row


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


def _part(record):
    return record["parts"][0]


def _prereqs(record):
    return {p["id"]: p["met"] for p in _part(record)["prerequisites"]}


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


def test_logger_tolerates_a_file_system_that_cannot_sync(tmp_path, monkeypatch):
    import errno

    def einval(fd):
        raise OSError(errno.EINVAL, "no sync here")

    monkeypatch.setattr(os, "fsync", einval)
    P0AuditLogger(tmp_path / "audit.jsonl").log_action_decision("d", "s")


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
    assert not (tmp_path / "queue.jsonl.tmp").exists()
    assert queue.queue_depth() == 1


# ----------------------------------------------------------------- harness


def test_closed_table_full_run_passes(clean_owner, closed_table):
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_PASS, _prereqs(record)
    assert len(_part(record)["samples"]) == 200
    assert all(_prereqs(record).values())


def test_real_table_full_run_is_not_measurable_only_for_what_does_not_exist():
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    unmet = [k for k, v in _prereqs(record).items() if not v]
    assert unmet == ["visual_voice_delivery_queue_declared"]
    assert [g["id"] for g in _part(record)["gaps"]] == ["SO03-NO-VISUAL-VOICE-QUEUE", "SO03-NO-P0-ALERT-PATH"]


def test_slow_enqueue_fails(clean_owner, closed_table, monkeypatch):
    real = OfflineQueueNotifier.send
    calls = {"n": 0}

    def slow(self, payload):
        calls["n"] += 1
        if calls["n"] == 7:
            time.sleep(2.05)
        return real(self, payload)

    monkeypatch.setattr(OfflineQueueNotifier, "send", slow)
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_FAIL
    assert _part(record)["pass_rule"]["evaluated"]["violations"] == 1


def _without_decision_id(self, payload):
    out = _real_summary(self, payload)
    out["decision_id"] = ""
    return out


_real_summary = OfflineQueueNotifier._summary_payload


def test_enqueue_record_missing_is_not_measurable(clean_owner, closed_table, monkeypatch):
    monkeypatch.setattr(OfflineQueueNotifier, "send", lambda self, payload: {"ok": True, "adapter": "offline_queue"})
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_names_decision_id"] is False
    # Each sample whose end event never happened is unfinished, not fast.
    assert all(s["end_monotonic_ns"] is None for s in _part(record)["samples"])


def test_enqueue_record_without_prerequisite_would_fail_not_pass(clean_owner, closed_table, monkeypatch):
    # Even with the naming prerequisite dropped from the table, a sample with
    # no record naming its decision is unfinished and the rule fails.
    row = dict(closed_table)
    row["prerequisites"] = ()
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-03", {PART: row})
    monkeypatch.setattr(OfflineQueueNotifier, "_summary_payload", _without_decision_id)
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_FAIL


def test_enqueue_record_naming_another_decision_is_not_measurable(clean_owner, closed_table, monkeypatch):
    def other(self, payload):
        out = _real_summary(self, payload)
        out["decision_id"] = "so03-decision-9999"
        return out

    monkeypatch.setattr(OfflineQueueNotifier, "_summary_payload", other)
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_names_decision_id"] is False


def test_notification_record_not_naming_the_decision_is_not_measurable(clean_owner, closed_table, monkeypatch):
    real_log = P0AuditLogger.log

    def log(self, kind, trace_id, source, **payload):
        if kind == "notification":
            payload["decision_id"] = ""
        return real_log(self, kind, trace_id, source, **payload)

    monkeypatch.setattr(P0AuditLogger, "log", log)
    record = so03_alert_queue.run(seed=3)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_names_decision_id"] is False


def test_stale_enqueue_stamp_is_not_this_samples_record(clean_owner, closed_table, monkeypatch):
    def stale(self, payload):
        out = _real_summary(self, payload)
        out["enqueued_monotonic_ns"] = 1
        return out

    monkeypatch.setattr(OfflineQueueNotifier, "_summary_payload", stale)
    record = so03_alert_queue.run(seed=3)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_names_decision_id"] is False


def test_missing_p0_class_is_not_measurable(clean_owner, closed_table, monkeypatch):
    monkeypatch.setattr(delivery, "classify_alert", lambda action, level: "")
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_classifies_p0"] is False


def test_decision_record_not_fsynced_is_not_measurable(clean_owner, closed_table, monkeypatch):
    monkeypatch.setattr(logger_mod, "DURABLE_KINDS", frozenset({"notification"}))
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["decision_and_enqueue_records_fsynced"] is False


def test_enqueue_record_not_fsynced_is_not_measurable(clean_owner, closed_table, monkeypatch):
    monkeypatch.setattr(delivery, "fsync_path", lambda path: None)
    record = so03_alert_queue.run(seed=3)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["decision_and_enqueue_records_fsynced"] is False


def test_broken_chain_is_not_measurable(clean_owner, closed_table, monkeypatch):
    real = P0AuditLogger.verify_chain
    monkeypatch.setattr(P0AuditLogger, "verify_chain", classmethod(lambda cls, path: dict(real(path), ok=False, error="x")))
    record = so03_alert_queue.run(seed=3, samples=5)
    assert _prereqs(record)["alert_audit_chain_verifies"] is False


# --------------------------------------------------------------- validator


@pytest.fixture(scope="module")
def genuine_pass():
    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True})
        row = dict(rec.OBJECTIVE_SPECS["SO-03"][PART])
        row["prerequisites"] = tuple(p for p in row["prerequisites"] if p != "visual_voice_delivery_queue_declared")
        row["gaps"] = ()
        mp.setitem(rec.OBJECTIVE_SPECS, "SO-03", {PART: row})
        record = so03_alert_queue.run(seed=5)
        assert record["verdict"] == rec.VERDICT_PASS
        yield record, row
    finally:
        mp.undo()


@pytest.mark.parametrize(
    "field,value,prereq",
    [
        ("enqueue_record_decision_id", "so03-decision-9999", "enqueue_record_names_decision_id"),
        ("notification_audit_decision_id", None, "enqueue_record_names_decision_id"),
        ("edge_enqueued_monotonic_ns", 1, "enqueue_record_names_decision_id"),
        ("enqueue_record_alert_class", "", "enqueue_record_classifies_p0"),
        ("decision_record_fsynced", False, "decision_and_enqueue_records_fsynced"),
        ("enqueue_record_fsynced", False, "decision_and_enqueue_records_fsynced"),
    ],
)
def test_validator_recomputes_record_prerequisites_from_samples(genuine_pass, monkeypatch, field, value, prereq):
    record, row = genuine_pass
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-03", {PART: row})
    forged = copy.deepcopy(record)
    forged["parts"][0]["samples"][42][field] = value
    errors = rec.validate_record(forged)
    assert any(f"prerequisite {prereq!r} declared met but the samples do not show it" in e for e in errors), errors
    assert any("record supports 'not_measurable'" in e for e in errors), errors


def test_validator_accepts_the_genuine_pass(genuine_pass, monkeypatch):
    record, row = genuine_pass
    monkeypatch.setitem(rec.OBJECTIVE_SPECS, "SO-03", {PART: row})
    assert rec.validate_record(record) == []


def test_fixed_row_bound_and_samples_are_unchanged():
    row = rec.OBJECTIVE_SPECS["SO-03"][PART]
    assert row["bound_ms"] == 2000.0 and row["required_samples"] == 200 and row["kind"] == rec.RULE_EVERY_SAMPLE_MAX
    assert set(rec.so03_observed_prerequisites([{}])) <= set(row["prerequisites"])
