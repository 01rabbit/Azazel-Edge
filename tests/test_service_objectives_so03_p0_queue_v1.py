"""SO-03 P0 alert path (Edge#414, owner decisions 2026-10-25).

P0 = enforcement-bearing decision (throttle, redirect, isolate) or SOC
critical, built by the notify layer from the audit-chain decision record and
enqueued into one durable JSONL queue, visual and voice by ``channel``.

The path is observation and notification only: these tests also check that
it never changes what the audit logger writes, returns or raises, and that a
broken queue never reaches the decision path. The harness/validator tests take
a record away, or make it disagree, and expect the row to become
not_measurable or fail -- never pass -- and the two former gaps to come back.
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


def _decision(action="throttle", label="high", **extra):
    row = {"kind": "action_decision", "trace_id": "d-1", "chain_hash": "h" * 64, "action": action,
           "reason": "r", "decision_trace": {"suspicion_label": label}}
    row.update(extra)
    return row


def _rows(path):
    return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines()]


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


def test_overflow_evicts_oldest_and_records_it(tmp_path):
    qpath = tmp_path / "q.jsonl"
    queue = P0AlertQueue(qpath, max_entries=4)
    for i in range(3):
        result = queue.enqueue(_alerts(f"d-{i}"))
    rows = _rows(qpath)
    assert len(rows) == 4
    # The newest alert is never the one dropped.
    assert [r["decision_id"] for r in rows] == ["d-1", "d-1", "d-2", "d-2"]
    assert result["evicted"] == 2
    assert rows[-1]["overflow_evicted"] == 2 and rows[-1]["overflow_evicted_total"] == 2
    assert rows[-1]["overflow_policy"] == p0_alert.OVERFLOW_POLICY
    queue.enqueue(_alerts("d-3"))
    assert _rows(qpath)[-1]["overflow_evicted_total"] == 4
    assert stat.S_IMODE(os.stat(qpath).st_mode) == 0o600
    assert not list(tmp_path.glob("*.tmp"))


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
    assert len(seen) == 1
    record, durability, stamp = seen[0]
    assert durability == "fsynced" and before <= stamp <= after
    assert record["chain_hash"] == out["chain_hash"]
    assert events.index("listener") > events.index("fsync")
    assert out["action"] == "throttle" and _rows(path)[0]["action"] == "throttle"
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
    assert seen == ["fsync_failed"]


# ------------------------------------------------------------------ relay


def _wait(pred, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


def test_attached_path_enqueues_p0_decisions_only(tmp_path):
    audit = P0AuditLogger(tmp_path / "a.jsonl")
    qpath = tmp_path / "q.jsonl"
    relay = attach_p0_alert_relay(audit, qpath)
    try:
        audit.log_action_decision("d-obs", "s", action="observe", decision_trace={"suspicion_label": "high"})
        audit.log_action_decision("d-thr", "s", action="throttle", target_ip="192.0.2.9")
        audit.log_action_decision("d-crit", "s", action="notify", decision_trace={"suspicion_label": "critical"})
        audit.log_notification("t", "s", decision="sent")
        assert _wait(lambda: relay.enqueued_total == 2)
    finally:
        relay.stop()
    rows = _rows(qpath)
    chain = {r["trace_id"]: r["chain_hash"] for r in _rows(tmp_path / "a.jsonl")}
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
        assert _wait(lambda: relay.enqueue_failed_total == 1)
    finally:
        relay.stop()
    os.rmdir(qpath)
    relay.relay(_decision("redirect", trace_id="d-2"), "fsynced", 1)
    assert _rows(qpath)[-1]["relay_enqueue_failed_total"] == 1


def test_full_handoff_is_counted_and_recorded(tmp_path):
    queue = P0AlertQueue(tmp_path / "q.jsonl")
    relay = P0AlertRelay(queue, max_pending=1)  # not started: the hand-off fills
    relay.on_durable_record(_decision("throttle", trace_id="a"), "fsynced", 1)
    relay.on_durable_record(_decision("throttle", trace_id="b"), "fsynced", 2)
    assert relay.handoff_dropped_total == 1
    relay.start()
    relay.stop()
    rows = _rows(tmp_path / "q.jsonl")
    assert [r["decision_id"] for r in rows] == ["a", "a"]
    assert rows[-1]["relay_handoff_dropped_total"] == 1


def test_on_relayed_failure_is_contained(tmp_path):
    def broken(decision_id, result):
        raise RuntimeError("observer down")

    relay = P0AlertRelay(P0AlertQueue(tmp_path / "q.jsonl"), on_relayed=broken)
    assert relay.relay(_decision("isolate"), "fsynced", 1)["ok"] is True


# ---------------------------------------------------------------- harness


@pytest.fixture
def clean_owner(monkeypatch):
    monkeypatch.setattr(
        rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True}
    )


def _part(record):
    return record["parts"][0]


def _prereqs(record):
    return {p["id"]: p["met"] for p in _part(record)["prerequisites"]}


def _gaps(record):
    return [g["id"] for g in _part(record)["gaps"]]


def test_full_run_passes_and_closes_both_gaps(clean_owner):
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_PASS, _prereqs(record)
    assert len(_part(record)["samples"]) == 200
    assert _gaps(record) == []
    assert all(_prereqs(record).values())


def test_slow_enqueue_fails(clean_owner, monkeypatch):
    real = P0AlertQueue.enqueue
    calls = {"n": 0}

    def slow(self, alerts, extra=None):
        calls["n"] += 1
        if calls["n"] == 7:
            time.sleep(2.05)
        return real(self, alerts, extra)

    monkeypatch.setattr(P0AlertQueue, "enqueue", slow)
    record = so03_alert_queue.run(seed=3)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_FAIL
    assert _part(record)["pass_rule"]["evaluated"]["violations"] == 1


def test_enqueue_without_a_record_is_not_measurable(clean_owner, monkeypatch):
    monkeypatch.setattr(P0AlertQueue, "enqueue", lambda self, alerts, extra=None: {"ok": True, "durability": "fsynced"})
    record = so03_alert_queue.run(seed=3, samples=10)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert all(s["end_monotonic_ns"] is None for s in _part(record)["samples"])
    assert _gaps(record) == list(GAPS)


def test_not_p0_decisions_are_not_alerted_and_not_measurable(clean_owner, monkeypatch):
    monkeypatch.setattr(p0_alert, "classify_p0", lambda record: "")
    record = so03_alert_queue.run(seed=3, samples=8)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert all(s["queue_records"] == [] for s in _part(record)["samples"])
    assert _gaps(record) == list(GAPS)


def test_wrong_p0_basis_keeps_the_path_gap(clean_owner, monkeypatch):
    real = p0_alert.build_p0_alerts
    monkeypatch.setattr(
        p0_alert, "build_p0_alerts",
        lambda record, basis, durability, durable_ns: real(record, "enforcement:throttle", durability, durable_ns),
    )
    record = so03_alert_queue.run(seed=3, samples=8)
    assert rec.validate_record(record) == []
    assert _prereqs(record)["enqueue_record_classifies_p0"] is False
    assert _gaps(record) == ["SO03-NO-P0-ALERT-PATH"]


def test_one_channel_only_keeps_both_gaps(clean_owner, monkeypatch):
    real = p0_alert.build_p0_alerts
    monkeypatch.setattr(p0_alert, "build_p0_alerts", lambda *a: real(*a)[:1])
    record = so03_alert_queue.run(seed=3, samples=8)
    assert rec.validate_record(record) == []
    assert _prereqs(record)["visual_voice_delivery_queue_declared"] is False
    assert _gaps(record) == list(GAPS)


def test_entries_naming_another_decision_are_not_this_samples(clean_owner, monkeypatch):
    real = p0_alert.build_p0_alerts

    def other(record, *a):
        return [dict(x, decision_id="so03-decision-9999") for x in real(record, *a)]

    monkeypatch.setattr(p0_alert, "build_p0_alerts", other)
    record = so03_alert_queue.run(seed=3, samples=8)
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["enqueue_record_names_decision_id"] is False


def test_decision_record_not_durable_is_not_measurable(clean_owner, monkeypatch):
    monkeypatch.setattr(logger_mod, "DURABLE_KINDS", frozenset({"notification"}))
    monkeypatch.setattr(so03_alert_queue, "END_WAIT_S", 0.2)  # nothing is ever relayed
    record = so03_alert_queue.run(seed=3, samples=4)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["decision_and_enqueue_records_fsynced"] is False


def test_queue_not_fsynced_is_not_measurable(clean_owner, monkeypatch):
    monkeypatch.setattr(P0AlertQueue, "_fsync_fd", staticmethod(lambda fd: True))
    monkeypatch.setattr(p0_alert, "fsync_path", lambda path: True)
    record = so03_alert_queue.run(seed=3, samples=8)
    assert rec.validate_record(record) == []
    assert record["verdict"] == rec.VERDICT_NOT_MEASURABLE
    assert _prereqs(record)["decision_and_enqueue_records_fsynced"] is False
    assert _gaps(record) == list(GAPS)


def test_broken_chain_is_not_measurable(clean_owner, monkeypatch):
    real = P0AuditLogger.verify_chain
    monkeypatch.setattr(P0AuditLogger, "verify_chain", classmethod(lambda cls, path: dict(real(path), ok=False, error="x")))
    record = so03_alert_queue.run(seed=3, samples=5)
    assert _prereqs(record)["alert_audit_chain_verifies"] is False


# -------------------------------------------------------------- validator


@pytest.fixture(scope="module")
def genuine_pass():
    mp = pytest.MonkeyPatch()
    try:
        mp.setattr(rec, "owner_block", lambda: {"repository": rec.OWNING_REPOSITORY, "commit": "a" * 40, "worktree_clean": True})
        record = so03_alert_queue.run(seed=5)
        assert record["verdict"] == rec.VERDICT_PASS
        yield record
    finally:
        mp.undo()


@pytest.mark.parametrize(
    "mutate,prereq",
    [
        (lambda s: s["queue_records"][0].__setitem__("decision_id", "so03-decision-9999"), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][1].__setitem__("decision_chain_hash", "0" * 64), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][0].__setitem__("enqueued_monotonic_ns", 1), "enqueue_record_names_decision_id"),
        (lambda s: s["queue_records"][0].__setitem__("decision_durable_monotonic_ns", 1), "enqueue_record_names_decision_id"),
        (lambda s: s.__setitem__("edge_decision_durable_monotonic_ns", 1), "enqueue_record_names_decision_id"),
        (lambda s: s.__setitem__("harness_log_returned_monotonic_ns", s["start_monotonic_ns"] - 1), "enqueue_record_names_decision_id"),
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
    ],
)
def test_validator_recomputes_from_samples(genuine_pass, mutate, prereq):
    forged = copy.deepcopy(genuine_pass)
    mutate(forged["parts"][0]["samples"][42])
    errors = rec.validate_record(forged)
    assert any(f"prerequisite {prereq!r} declared met but the samples do not show it" in e for e in errors), errors
    # The closed gaps re-open: leaving them out is now refused.
    assert any("mandatory gap 'SO03-NO-P0-ALERT-PATH' omitted" in e for e in errors), errors
    assert any("record supports 'not_measurable'" in e or "record supports 'fail'" in e for e in errors), errors


def test_validator_refuses_an_end_without_a_durable_enqueue_record(genuine_pass):
    forged = copy.deepcopy(genuine_pass)
    forged["parts"][0]["samples"][7]["queue_records"] = []
    errors = rec.validate_record(forged)
    assert any("samples[7]: end given but the observed fields do not show a durable enqueue record" in e for e in errors), errors


def test_validator_accepts_the_genuine_pass(genuine_pass):
    assert rec.validate_record(genuine_pass) == []


def test_validator_p0_rule_is_independent_of_the_product():
    for action, label in [("throttle", "low"), ("redirect", ""), ("isolate", None), ("notify", "critical"),
                          ("observe", "critical"), ("notify", "high"), ("observe", "low")]:
        record = {"kind": "action_decision", "action": action, "decision_trace": {"suspicion_label": label}}
        assert rec.so03_expected_p0_basis(action, label) == classify_p0(record)
    assert rec.SO03_P0_RULE == p0_alert.P0_RULE and rec.SO03_QUEUE_SCHEMA == p0_alert.QUEUE_SCHEMA


def test_fixed_row_bound_and_samples_are_unchanged():
    row = rec.OBJECTIVE_SPECS["SO-03"][PART]
    assert row["bound_ms"] == 2000.0 and row["required_samples"] == 200 and row["kind"] == rec.RULE_EVERY_SAMPLE_MAX
    assert set(row["gaps"]) == set(GAPS) == set(row["gaps_closed_by_samples"])
    assert set(rec.so03_observed_prerequisites([{}])) <= set(row["prerequisites"])
