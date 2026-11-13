"""Fresh final accounting: real temporary bytes and SYNTHETIC process lifecycle."""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

import pytest
from azazel_edge.service_objectives import ingress_final_audit as f
from azazel_edge.service_objectives import so11_quota_load as so11
from azazel_edge.service_objectives import so03_alert_queue as so03
from azazel_edge.service_objectives import record
from test_service_objectives_so11_v1 import _summary, _obs, _record, _part


def wire(rows):
    return b"".join(
        json.dumps(r, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        + b"\n"
        for r in rows
    )


class Process:
    def __init__(self, mode="graceful", on_wait=lambda: None):
        self.mode = mode
        self.returncode = 0 if mode == "early" else None
        self.calls = []
        self.on_wait = on_wait
        self.waits = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        self.calls.append("terminate")

    def kill(self):
        self.calls.append("kill")
        self.returncode = -9

    def wait(self, *, timeout):
        self.waits += 1
        self.calls.append("wait")
        if self.waits == 1 and self.mode == "forced":
            raise subprocess.TimeoutExpired("SYNTHETIC core", timeout)
        if self.waits == 1 and self.mode == "error":
            raise OSError("SYNTHETIC wait error")
        if self.returncode is None:
            self.on_wait()
            self.returncode = 1 if self.mode == "nonzero" else 0
        return self.returncode


def prepare(tmp_path, *, absent=False, writer_error=None):
    initial = [_summary(10, 10)]
    if not absent:
        (tmp_path / f.AUDIT).write_bytes(wire(initial))
    (tmp_path / "core.stderr").write_bytes(b"")
    out = dict(
        window_end_monotonic_ns=time.monotonic_ns(),
        writer_error=writer_error,
        core_alive_at_load_end=True,
    )
    capture = f.FinalAudit(out)
    capture.before_stop(
        tmp_path, writer_joined=True, writer_joined_ns=time.monotonic_ns()
    )
    return capture, out, initial


@pytest.mark.parametrize("absent", [False, True])
def test_final_read_follows_actual_wait_and_preserves_original_prefix(tmp_path, absent):
    capture, out, initial = prepare(tmp_path, absent=absent)
    tail = _summary(0, 10 if not absent else 0, examined=17)
    tail["ingress_shed"]["interval_end"] = "shutdown"
    final = ([] if absent else initial) + [tail]
    process = Process(on_wait=lambda: (tmp_path / f.AUDIT).write_bytes(wire(final)))
    capture.finish(tmp_path, f.bounded_stop(process))
    assert process.calls == ["terminate", "wait"]
    assert out["ingress_audit"] == final
    assert out["ingress_audit_finalization"]["raw_utf8"].encode() == wire(final)
    assert out["ingress_audit_finalization"]["pre_stop_binding"] == (
        "created_after_observed_absence" if absent else "same_file_prefix"
    )
    assert f.finalization_problems(out) == []
    if absent:
        assert all(
            out["ingress_audit_pre_stop"][key] is None
            for key in (
                "records",
                "records_read",
                "raw_bytes",
                "raw_sha256",
                "raw_utf8",
                "file_identity",
            )
        )
    else:
        assert out["ingress_audit_pre_stop"]["records"] == initial
    assert out["core_alive_at_load_end"] is True


@pytest.mark.parametrize("mode", ["forced", "nonzero", "early", "error"])
def test_non_graceful_stop_never_reads_or_reuses_pre_stop_as_final(
    tmp_path, monkeypatch, mode
):
    capture, out, initial = prepare(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("final read before graceful zero exit")

    monkeypatch.setattr(f, "snapshot", forbidden)
    process = Process(mode)
    stop = f.bounded_stop(process)
    capture.finish(tmp_path, stop)
    assert (
        out["ingress_audit"]
        is out["ingress_audit_records_read"]
        is out["ingress_audit_rotated"]
        is None
    )
    assert out["ingress_audit_finalization"]["read_started_ns"] is None
    assert out["ingress_audit_pre_stop"]["records"] == initial
    assert out["ingress_audit_finalization"]["error"]
    assert f.finalization_problems(out)
    if mode in ("forced", "error"):
        assert process.calls.count("kill") == 1


@pytest.mark.parametrize(
    "fault",
    [
        "writer_error",
        "join_timeout",
        "missing",
        "rotated",
        "replaced",
        "shrink",
        "malformed",
        "partial",
        "utf8",
        "write_error",
    ],
)
def test_failed_finalization_retains_pre_stop_and_never_manufactures_counts(
    tmp_path, fault
):
    capture, out, initial = prepare(tmp_path)

    def change():
        path = tmp_path / f.AUDIT
        if fault == "missing":
            path.unlink()
        elif fault == "rotated":
            (tmp_path / (f.AUDIT + ".1")).write_bytes(path.read_bytes())
        elif fault == "replaced":
            path.rename(tmp_path / "original")
            path.write_bytes(wire(initial))
        elif fault == "shrink":
            path.write_bytes(b"")
        elif fault == "malformed":
            path.write_bytes(wire(initial) + b"{bad}\n")
        elif fault == "partial":
            path.write_bytes(wire(initial) + b"{bad")
        elif fault == "utf8":
            path.write_bytes(wire(initial) + b"\xff\n")
        elif fault == "write_error":
            (tmp_path / "core.stderr").write_bytes(
                b"ingress audit write failed (/synthetic): denied\n"
            )

    if fault == "writer_error":
        out["writer_error"] = "SYNTHETIC os.write failed"
    if fault == "join_timeout":
        capture.writer_joined = False
        capture.writer_joined_ns = None
    capture.finish(tmp_path, f.bounded_stop(Process(on_wait=change)))
    assert out["ingress_audit_finalization"]["error"]
    assert out["ingress_audit"] is None
    assert out["ingress_audit_pre_stop"]["records"] == initial
    assert f.finalization_problems(out)
    if fault in (
        "missing",
        "rotated",
        "replaced",
        "shrink",
        "malformed",
        "partial",
        "utf8",
    ):
        assert out["ingress_audit_failed_final_snapshot"]["error"]


@pytest.mark.parametrize(
    "raw",
    [
        b"{}\n",
        b'{"ingress_shed":{}}\n',
        b'{"x":1,"x":2}\n',
        b"[]\n",
        b"\n",
        b"\xff\n",
        b"{}\r\n",
    ],
)
def test_strict_reader_rejects_unknown_partial_or_malformed_bytes(tmp_path, raw):
    (tmp_path / f.AUDIT).write_bytes(raw)
    result = f.snapshot(tmp_path)
    assert result.metadata["error"] and result.metadata["disposition"] == "unavailable"


def test_stderr_event_text_does_not_fake_write_error_diagnostic(tmp_path):
    capture, out, _ = prepare(tmp_path)
    (tmp_path / "core.stderr").write_bytes(
        b'{"event":"ingress audit write failed (text)"}\n'
    )
    capture.finish(tmp_path, f.bounded_stop(Process()))
    assert f.finalization_problems(out) == []


@pytest.mark.parametrize(
    "fault",
    [
        "missing_profile",
        "bool_join_clock",
        "forced",
        "nonzero",
        "row_tamper",
        "raw_tamper",
        "hash_tamper",
        "empty_final",
        "duplicate_shutdown",
        "periodic_after_shutdown",
    ],
)
def test_fresh_record_revalidation_rejects_imported_metadata_or_row_tampering(fault):
    obs = _obs(1.2)
    if fault == "missing_profile":
        obs.pop("ingress_audit_finalization")
    elif fault == "bool_join_clock":
        obs["ingress_audit_finalization"]["writer_joined_ns"] = True
    elif fault == "forced":
        obs["ingress_audit_finalization"]["stop"]["forced"] = True
    elif fault == "nonzero":
        obs["ingress_audit_finalization"]["stop"]["returncode"] = 1
    elif fault == "row_tamper":
        obs["ingress_audit"][0]["ingress_shed"]["examined"] += 1
    elif fault == "raw_tamper":
        obs["ingress_audit_finalization"]["raw_utf8"] += "{}\n"
    elif fault == "hash_tamper":
        obs["ingress_audit_finalization"]["raw_sha256"] = "e" * 64
    else:
        if fault == "empty_final":
            rows = []
        else:
            rows = deepcopy(obs["ingress_audit"])
            rows[0]["ingress_shed"]["interval_end"] = "shutdown"
            if fault == "duplicate_shutdown":
                rows[1]["ingress_shed"]["interval_end"] = "shutdown"
        raw = wire(rows)
        # A newly retained synthetic complete snapshot, not stale bad hashes.
        obs["ingress_audit"] = rows
        obs["ingress_audit_records_read"] = len(rows)
        obs["ingress_audit_pre_stop"].update(
            disposition="observed_absent",
            records=None,
            records_read=None,
            raw_bytes=None,
            raw_sha256=None,
            raw_utf8=None,
            file_identity=None,
        )
        obs["ingress_audit_finalization"].update(
            raw_utf8=raw.decode(),
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            raw_bytes=len(raw),
            pre_stop_binding="created_after_observed_absence",
        )
    problems = so11.quota_load_problems([], obs, 1.2)
    assert problems["core_ingress_audit_consistent"]


def test_legacy_record_cannot_keep_declared_met_prerequisite():
    result = _record()
    part = _part(result, "so04_start_at_120pct_of_quota")
    part["quota_load"].pop("ingress_audit_finalization")
    errors = record.validate_record(result)
    assert any(
        "core_ingress_audit_consistent" in error and "declared met" in error
        for error in errors
    )


@pytest.mark.parametrize("examined,accepted", [(9800, True), (9799, False)])
def test_original_98_percent_boundary_is_unchanged(examined, accepted):
    obs = _obs(1.2, seconds=10000 / 3000)
    obs["written"] = {kind: 2500 for kind in so11.NON_ALERT_KINDS}
    rows = [_summary(100, 100, examined=examined)]
    raw = wire(rows)
    obs.update(ingress_audit=rows, ingress_audit_records_read=1)
    obs["ingress_audit_pre_stop"].update(
        disposition="observed_absent",
        records=None,
        records_read=None,
        raw_bytes=None,
        raw_sha256=None,
        raw_utf8=None,
        file_identity=None,
    )
    obs["ingress_audit_finalization"].update(
        raw_utf8=raw.decode(),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        raw_bytes=len(raw),
        pre_stop_binding="created_after_observed_absence",
    )
    assert (
        not so11.quota_load_problems([], obs, 1.2)["core_ingress_audit_consistent"]
    ) is accepted


def test_so03_optional_after_core_runs_after_wait_inside_work_lifetime(
    tmp_path, monkeypatch
):
    calls = []
    process = Process(on_wait=lambda: calls.append("wait-exit"))
    monkeypatch.setattr(
        so03,
        "subprocess",
        SimpleNamespace(
            Popen=lambda *a, **k: process,
            DEVNULL=None,
            PIPE=None,
            TimeoutExpired=subprocess.TimeoutExpired,
        ),
    )
    monkeypatch.setattr(so03, "_wait", lambda *a: True)

    def after(work, facts):
        assert work == tmp_path and work.exists()
        assert process.returncode == 0 and calls == ["wait-exit"]
        assert facts["forced"] is False and facts["returncode"] == 0
        calls.append("after_core")

    rows = so03._run_core(
        Path("/synthetic/core"),
        tmp_path,
        tmp_path / "socket",
        0,
        lambda *a: None,
        {},
        after_core=after,
    )
    assert rows == [] and calls == ["wait-exit", "after_core"]


def test_applied_joins_writer_before_pre_stop_snapshot(monkeypatch, tmp_path):
    events = []
    out = {}
    capture = f.FinalAudit(out)

    class Load:
        def __init__(self, *a):
            self.stop = SimpleNamespace(
                wait=lambda *a: None, set=lambda: events.append("stop")
            )
            self.error = None
            self.window = {}
            self.written = {}
            self.written_bytes = 0

        def start(self):
            events.append("start")

        def join(self, **kw):
            events.append("join")

        def is_alive(self):
            return False

    monkeypatch.setattr(so11, "QuotaLoad", Load)
    monkeypatch.setattr(
        so11,
        "time",
        SimpleNamespace(sleep=lambda *a: None, monotonic_ns=time.monotonic_ns),
    )
    with so11.applied(
        tmp_path / "eve",
        tmp_path,
        1.2,
        {"value": 2500, "audit_interval_ms": 1000},
        out,
        core_started=True,
        core_alive=lambda: True,
        final_audit=capture,
    ):
        events.append("body")
    assert events == ["start", "body", "stop", "join"]
    assert capture.writer_joined is True
    assert capture.writer_joined_ns <= capture.pre.metadata["read_started_ns"]
    assert out["core_alive_at_load_end"] is True
    assert out["ingress_audit"] is None


def test_pre_stop_absence_never_hides_an_existing_rotation(tmp_path):
    (tmp_path / (f.AUDIT + ".1")).write_bytes(wire([_summary(1, 1)]))
    taken = f.snapshot(tmp_path, allow_absent=True)
    assert taken.metadata["disposition"] == "unavailable"
    assert taken.metadata["rotated"] is True and taken.metadata["error"]


@pytest.mark.parametrize(
    "unsafe", ["symlink", "hardlink", "writable", "directory", "fifo"]
)
def test_strict_snapshot_refuses_unsafe_actual_file_objects(tmp_path, unsafe):
    path = tmp_path / f.AUDIT
    raw = wire([_summary(1, 1)])
    if unsafe == "symlink":
        target = tmp_path / "original"
        target.write_bytes(raw)
        path.symlink_to(target)
    elif unsafe == "directory":
        path.mkdir()
    elif unsafe == "fifo":
        os.mkfifo(path)
    else:
        path.write_bytes(raw)
        if unsafe == "hardlink":
            os.link(path, tmp_path / "other-name")
        else:
            path.chmod(0o620)
    taken = f.snapshot(tmp_path)
    assert taken.metadata["disposition"] == "unavailable" and taken.metadata["error"]


@pytest.mark.parametrize(
    "mutation", ["growth", "truncate", "same_size_edit", "replace", "rotation"]
)
def test_original_fd_path_and_metadata_are_fenced_through_read(
    tmp_path, monkeypatch, mutation
):
    path = tmp_path / f.AUDIT
    original = wire([_summary(1, 1)])
    path.write_bytes(original)
    inode = path.stat().st_ino
    real_read = os.read
    changed = False

    def injected_read(fd, size):
        nonlocal changed
        value = real_read(fd, size)
        if not changed and os.fstat(fd).st_ino == inode:
            changed = True
            if mutation == "growth":
                path.write_bytes(original + wire([_summary(0, 1)]))
            elif mutation == "truncate":
                path.write_bytes(b"")
            elif mutation == "same_size_edit":
                altered = original.replace(
                    b'"emitted_epoch":1.0', b'"emitted_epoch":2.0'
                )
                assert altered != original and len(altered) == len(original)
                path.write_bytes(altered)
            elif mutation == "replace":
                path.rename(tmp_path / "old-original")
                path.write_bytes(original)
            else:
                (tmp_path / (f.AUDIT + ".1")).write_bytes(original)
        return value

    monkeypatch.setattr(f.os, "read", injected_read)
    taken = f.snapshot(tmp_path)
    assert changed
    assert taken.metadata["disposition"] == "unavailable" and taken.metadata["error"]


def test_actual_descriptor_is_closed_even_when_close_reports_failure(
    tmp_path, monkeypatch
):
    path = tmp_path / f.AUDIT
    path.write_bytes(wire([_summary(1, 1)]))
    inode = path.stat().st_ino
    real_close = os.close
    attempts = []

    def reported_close_failure(fd):
        is_ours = os.fstat(fd).st_ino == inode
        real_close(fd)
        if is_ours:
            attempts.append(fd)
            raise OSError("SYNTHETIC post-close failure")

    monkeypatch.setattr(f.os, "close", reported_close_failure)
    taken = f.snapshot(tmp_path)
    assert len(attempts) == 1
    assert taken.metadata["disposition"] == "unavailable"
    assert "close" in taken.metadata["error"]
    with pytest.raises(OSError):
        os.fstat(attempts[0])


@pytest.mark.parametrize(
    "form",
    [
        "duplicate",
        "nan",
        "infinite_float",
        "missing_counter",
        "unknown_counter",
        "wrong_source",
        "wrong_pipeline",
        "bool_counter",
    ],
)
def test_strict_snapshot_rejects_malformed_summary_body_and_headers(tmp_path, form):
    row = _summary(1, 1)
    if form == "missing_counter":
        row["ingress_shed"].pop("examined")
    elif form == "unknown_counter":
        row["ingress_shed"]["invented_count"] = 0
    elif form == "wrong_source":
        row["source"] = "other"
    elif form == "wrong_pipeline":
        row["pipeline"] = "other"
    elif form == "bool_counter":
        row["ingress_shed"]["alerts_shed"] = False
    raw = wire([row])
    if form == "duplicate":
        raw = raw.replace(b'"examined":3000', b'"examined":3000,"examined":3000')
    elif form == "nan":
        raw = raw.replace(b'"emitted_epoch":1.0', b'"emitted_epoch":NaN')
    elif form == "infinite_float":
        raw = raw.replace(b'"emitted_epoch":1.0', b'"emitted_epoch":1e9999')
    (tmp_path / f.AUDIT).write_bytes(raw)
    taken = f.snapshot(tmp_path)
    assert taken.metadata["disposition"] == "unavailable" and taken.metadata["error"]


@pytest.mark.parametrize(
    "fault",
    [
        "final_identity_missing",
        "final_identity_changed",
        "final_identity_bool",
        "raw_missing",
        "raw_size_bool",
        "record_count_bool",
        "typed_row_float",
        "typed_row_bool",
        "pre_raw_edit",
        "pre_hash_edit",
        "pre_clock_bool",
        "exit_clock_reversed",
        "read_before_exit",
        "writer_join_clock_missing",
    ],
)
def test_imported_finalization_requires_exact_original_typed_bytes_identity_and_clocks(
    fault,
):
    obs = _obs(1.2)
    final, pre = obs["ingress_audit_finalization"], obs["ingress_audit_pre_stop"]
    if fault == "final_identity_missing":
        final.pop("file_identity", None)
    elif fault == "final_identity_changed":
        final["file_identity"] = dict(device=1, inode=999)
    elif fault == "final_identity_bool":
        final["file_identity"] = dict(device=True, inode=2)
    elif fault == "raw_missing":
        final.pop("raw_utf8")
    elif fault == "raw_size_bool":
        final["raw_bytes"] = True
    elif fault == "record_count_bool":
        obs["ingress_audit_records_read"] = True
    elif fault == "typed_row_float":
        obs["ingress_audit"][0]["ingress_shed"]["examined"] = float(
            obs["ingress_audit"][0]["ingress_shed"]["examined"]
        )
    elif fault == "typed_row_bool":
        obs["ingress_audit"][0]["ingress_shed"]["alerts_shed"] = False
    elif fault == "pre_raw_edit":
        pre["raw_utf8"] += "\n"
    elif fault == "pre_hash_edit":
        pre["raw_sha256"] = "e" * 64
    elif fault == "pre_clock_bool":
        pre["read_ended_ns"] = True
    elif fault == "exit_clock_reversed":
        final["stop"]["exited_ns"] = final["stop"]["requested_ns"] - 1
    elif fault == "read_before_exit":
        final["read_started_ns"] = final["stop"]["exited_ns"] - 1
    else:
        final.pop("writer_joined_ns")
    assert f.finalization_problems(obs)


def test_shutdown_suffix_allows_zero_or_one_per_kind_not_a_required_fake_marker(
    tmp_path,
):
    capture, out, initial = prepare(tmp_path)
    capture.finish(tmp_path, f.bounded_stop(Process()))
    assert f.finalization_problems(out) == []
    assert out["ingress_audit"] == initial
    assert all(
        row["ingress_shed"]["interval_end"] == "audit_interval" for row in initial
    )


def test_finish_is_one_shot_and_second_call_does_not_publish_another_final_read(
    tmp_path, monkeypatch
):
    capture, out, initial = prepare(tmp_path)
    stop = f.bounded_stop(Process())
    capture.finish(tmp_path, stop)
    assert f.finalization_problems(out) == []

    def forbidden(*args, **kwargs):
        pytest.fail("second finalization must not read again")

    saved = deepcopy(out)
    monkeypatch.setattr(f, "snapshot", forbidden)
    capture.finish(tmp_path, stop)
    assert out == saved
    assert f.finalization_problems(out) == []
    assert out["ingress_audit_pre_stop"]["records"] == initial


@pytest.mark.parametrize(
    "fault", ["no_progress", "unexpected_exception", "close_error"]
)
def test_quota_writer_failures_are_explicit_and_owned_fd_is_closed(
    tmp_path, monkeypatch, fault
):
    """SYNTHETIC writer scheduling/faults; real private file and descriptor."""
    eve = tmp_path / "eve.json"
    eve.write_bytes(b"")
    writer = so11.QuotaLoad(eve, len(so11.NON_ALERT_KINDS))
    writer.stop.set()
    ticks = iter([0.0, 1.0])
    monkeypatch.setattr(
        so11,
        "time",
        SimpleNamespace(monotonic=lambda: next(ticks), monotonic_ns=time.monotonic_ns),
    )
    owned = []
    closed = []

    def opened(*args):
        fd = os.open(*args)
        owned.append(fd)
        return fd

    def write(fd, data):
        assert fd == owned[0]
        if fault == "no_progress":
            return 0
        if fault == "unexpected_exception":
            raise ValueError("SYNTHETIC unexpected writer failure")
        return os.write(fd, data)

    def close(fd):
        closed.append(fd)
        os.close(fd)
        if fault == "close_error":
            raise OSError("SYNTHETIC post-close failure")

    monkeypatch.setattr(
        so11,
        "os",
        SimpleNamespace(
            open=opened,
            write=write,
            close=close,
            O_WRONLY=os.O_WRONLY,
            O_APPEND=os.O_APPEND,
            O_CLOEXEC=os.O_CLOEXEC,
        ),
    )
    writer.run()
    assert writer.error is not None
    expected = {
        "no_progress": "no write progress",
        "unexpected_exception": "ValueError",
        "close_error": "writer close OSError",
    }
    assert expected[fault] in writer.error
    assert closed == owned and len(owned) == 1
    with pytest.raises(OSError):
        os.fstat(owned[0])
    if fault != "close_error":
        assert writer.written_bytes == 0
        assert eve.read_bytes() == b""


@pytest.mark.parametrize("invalid_error", [False, 0, ""])
def test_false_like_writer_error_is_not_clean_proof(tmp_path, invalid_error):
    capture, out, _ = prepare(tmp_path)
    out["writer_error"] = invalid_error
    capture.finish(tmp_path, f.bounded_stop(Process()))
    assert f.finalization_problems(out)
    assert out["ingress_audit"] is None


def test_failed_first_finish_cannot_be_repaired_by_replacing_file(
    tmp_path, monkeypatch
):
    capture, out, initial = prepare(tmp_path)
    (tmp_path / f.AUDIT).write_bytes(b"partial")
    stop = f.bounded_stop(Process())
    capture.finish(tmp_path, stop)
    assert f.finalization_problems(out)
    saved = deepcopy(out)
    (tmp_path / f.AUDIT).write_bytes(wire(initial))

    def forbidden(*args, **kwargs):
        pytest.fail("failed first finalization cannot retry the read")

    monkeypatch.setattr(f, "snapshot", forbidden)
    capture.finish(tmp_path, stop)
    assert out == saved


def test_duplicate_before_stop_preserves_original_snapshot(tmp_path, monkeypatch):
    capture, out, _ = prepare(tmp_path)
    saved = deepcopy(out)
    original = capture.pre

    def forbidden(*args, **kwargs):
        pytest.fail("duplicate pre-stop capture cannot read again")

    monkeypatch.setattr(f, "snapshot", forbidden)
    with pytest.raises(ValueError):
        capture.before_stop(tmp_path, writer_joined=False, writer_joined_ns=0)
    assert out == saved
    assert capture.pre is original


@pytest.mark.parametrize("side", ["pre", "final"])
def test_original_text_character_bound_is_checked_before_hashing(
    tmp_path, monkeypatch, side
):
    obs = _obs(1.2)
    final = obs["ingress_audit_finalization"]
    pre = obs["ingress_audit_pre_stop"]
    limit = len(final["raw_utf8"]) + 1
    monkeypatch.setattr(f, "MAX_BYTES", limit)
    target = pre if side == "pre" else final
    oversized = "x" * (limit + 1)
    target["raw_utf8"] = oversized
    target["raw_bytes"] = 0
    original_hash = hashlib.sha256

    def bounded_hash(raw):
        assert len(raw) <= limit, "oversized imported text reached byte hashing"
        return original_hash(raw)

    monkeypatch.setattr(f, "hashlib", SimpleNamespace(sha256=bounded_hash))
    assert f.finalization_problems(obs)


def test_pre_stop_row_limit_is_checked_before_comparing_imported_tree(monkeypatch):
    obs = _obs(1.2)
    pre = obs["ingress_audit_pre_stop"]
    monkeypatch.setattr(f, "MAX_ROWS", 2)
    pre["records"] = pre["records"] + [deepcopy(pre["records"][0])]
    pre["records_read"] = 3
    original_same = f._same

    def bounded_same(a, b):
        assert not (type(a) is list and len(a) > 2)
        assert not (type(b) is list and len(b) > 2)
        return original_same(a, b)

    monkeypatch.setattr(f, "_same", bounded_same)
    assert f.finalization_problems(obs)


@pytest.mark.parametrize(
    "left,right,expected",
    [
        (True, 1, False),
        (1, 1.0, False),
        (False, 0.0, False),
        (-0.0, 0.0, False),
        (-0.0, -0.0, True),
        (1.0, 1.0, True),
        ({"a": [1]}, {"a": [1.0]}, False),
    ],
)
def test_typed_comparison_uses_no_imported_json_serialization(
    monkeypatch, left, right, expected
):
    def forbidden(*args, **kwargs):
        pytest.fail("comparison must not serialize imported objects")

    monkeypatch.setattr(f.json, "dumps", forbidden)
    assert f._same(left, right) is expected


def test_hostile_imported_nested_rows_do_not_reach_json_dumps(monkeypatch):
    obs = _obs(1.2)
    cycle = []
    cycle.append(cycle)
    obs["ingress_audit"][0]["ingress_shed"]["quota"] = cycle

    def forbidden(*args, **kwargs):
        pytest.fail("untrusted imported rows must not be serialized")

    monkeypatch.setattr(f.json, "dumps", forbidden)
    assert f.finalization_problems(obs)


def test_rejected_final_evidence_never_reaches_legacy_audit_analyzer(monkeypatch):
    obs = _obs(1.2)
    obs["ingress_audit_finalization"]["raw_sha256"] = "e" * 64

    def forbidden(*args, **kwargs):
        pytest.fail("legacy analyzer must not consume rejected final rows")

    from azazel_edge.service_objectives import so04_hostile_load

    monkeypatch.setattr(so04_hostile_load, "_audit_problems", forbidden)
    problems = so11.quota_load_problems([], obs, 1.2)
    assert problems["core_ran_through_load"] == []
    assert problems["core_ingress_audit_consistent"]
    assert problems["alerts_never_shed"]
    assert problems[so11.SO11_OVERLOAD_PREREQUISITE]
