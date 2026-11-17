"""Synthetic component checks; no live memfd/actor capture matrix."""

import io
import json
import os
from types import SimpleNamespace

import pytest

import capture_close_lab as lab


def gate_plan():
    return dict(gate_id="SYNTHETIC-gate", gate_token="SYNTHETIC-token", attempts=[
        {"id": name} for name in [f"a{index:02}" for index in range(16)] + ["late0", "late1"]])


def jobs():
    return [dict(id=f"a{index:02}", seq=index, payload_hex=("SYNTHETIC-" + str(index)).encode().hex())
            for index in range(16)]


def test_gate_cannot_admit_until_enrollment_is_closed_and_late_attempts_use_same_gate():
    ready = False
    plan = gate_plan()
    gate = lab.AdmissionGate(plan, lambda: ready)
    with pytest.raises(RuntimeError):
        gate.attempt("a00", plan["gate_id"], plan["gate_token"])
    assert gate.attempts["a00"]["decision"] == "not_attempted"
    assert gate.attempts["a00"]["attempt_started_ns"] is None
    ready = True
    for job in jobs():
        assert gate.attempt(job["id"], plan["gate_id"], plan["gate_token"]) is True
    C = gate.close(plan["gate_id"], plan["gate_token"])
    for identifier in ("late0", "late1"):
        assert gate.attempt(identifier, plan["gate_id"], plan["gate_token"]) is False
        assert C["finished_ns"] <= gate.attempts[identifier]["attempt_started_ns"]
    assert C["admitted_ids"] == [f"a{index:02}" for index in range(16)]
    assert all(gate.attempts[name]["decision"] == "rejected_closed" for name in ("late0", "late1"))


def test_wrong_gate_or_token_and_duplicate_attempt_never_change_frontier():
    plan = gate_plan()
    gate = lab.AdmissionGate(plan, lambda: True)
    with pytest.raises(ValueError):
        gate.attempt("a00", "another-gate", plan["gate_token"])
    with pytest.raises(ValueError):
        gate.attempt("a00", plan["gate_id"], "another-token")
    assert gate.attempt("a00", plan["gate_id"], plan["gate_token"])
    before = dict(gate.attempts["a00"])
    with pytest.raises(ValueError):
        gate.attempt("a00", plan["gate_id"], plan["gate_token"])
    assert gate.attempts["a00"] == before
    with pytest.raises(ValueError):
        gate.close(plan["gate_id"], "another-token")
    assert gate.closed is False


@pytest.mark.parametrize("case,records,lost", [("clean", 16, []), ("explicit_loss", 15, ["a07"]),
    ("missing_loss_counter", 16, [])])
def test_source_raw_records_and_footer_claims_are_independently_recountable(tmp_path, case, records, lost):
    path = tmp_path / "SYNTHETIC-new-capture"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        frames = lab.SourceFrames(fd, "SYNTHETIC-run", "SYNTHETIC-capture", case)
        for row in jobs():
            frames.data(row)
        footer = frames.terminal()
    finally:
        os.close(fd)
    raw = path.read_bytes()
    lines = raw.splitlines(keepends=True)
    decoded = [json.loads(line) for line in lines]
    assert len(decoded) == records + 1
    previous = "0" * 64
    for line, row in zip(lines, decoded):
        assert row["prev_sha256"] == previous
        assert lab.wire(row) == line
        previous = lab.sha(line)
    assert footer == lines[-1]
    assert decoded[-1]["declared_records"] == records
    assert decoded[-1]["lost_ids"] == lost
    if case == "missing_loss_counter":
        assert "declared_lost" not in decoded[-1]
    else:
        assert decoded[-1]["declared_lost"] == len(lost)
    assert ("a07" not in {row.get("attempt_id") for row in decoded}) == (case == "explicit_loss")


def test_bypass_is_an_actual_extra_append_not_a_counter_only_claim(tmp_path):
    path = tmp_path / "SYNTHETIC-bypass"
    with path.open("xb") as stream:
        frames = lab.SourceFrames(stream.fileno(), "SYNTHETIC-run", "SYNTHETIC-capture", "late_bypass")
        for row in jobs():
            frames.data(row)
        before = stream.tell()
        frames.data(dict(id="late0", seq=16, payload_hex=b"SYNTHETIC-late".hex()))
        assert stream.tell() > before
        frames.terminal()
    data = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert data[-2]["attempt_id"] == "late0" and data[-2]["seq"] == 16
    assert data[-1]["declared_records"] == 17


def test_source_starts_blocked_and_does_not_emit_footer_until_finish_permit(tmp_path, monkeypatch):
    path = tmp_path / "SYNTHETIC-worker-component"
    replies, calls = [], []
    assigned = iter([dict(command="start", case_id="clean", run_id="SYNTHETIC", capture_id="SYNTHETIC", jobs=jobs()),
                     dict(command="drain"), dict(command="finish")])

    def command():
        calls.append(True)
        if len(calls) == 1:
            assert replies == [{"kind": "blocked", "role": "source", "pid": os.getpid()}]
            assert path.stat().st_size == 0
        elif len(calls) == 2:
            assert replies[-1]["kind"] == "prefix"
            assert len(path.read_bytes().splitlines()) == 8
        else:
            assert replies[-1]["kind"] == "drained"
            assert len(path.read_bytes().splitlines()) == 16
        return next(assigned)

    monkeypatch.setattr(lab, "boundary", lambda: None)
    monkeypatch.setattr(lab, "reply", replies.append)
    monkeypatch.setattr(lab, "receive_command", command)
    with path.open("xb") as stream:
        lab.source_worker(stream.fileno())
    assert replies[-1]["kind"] == "footer"
    assert len(path.read_bytes().splitlines()) == 17


def test_abrupt_control_requests_real_exit7_after_prefix_and_finish_only(tmp_path, monkeypatch):
    class ExitRequested(BaseException):
        pass
    actual_os, exits, replies = lab.os, [], []
    class SourceOS:
        def __getattr__(self, name):
            return getattr(actual_os, name)

        def _exit(self, value):
            exits.append(value)
            raise ExitRequested

    commands = iter([dict(command="start", case_id="abrupt_writer", run_id="SYNTHETIC", capture_id="SYNTHETIC", jobs=jobs()),
                     dict(command="finish")])
    monkeypatch.setattr(lab, "os", SourceOS())
    monkeypatch.setattr(lab, "boundary", lambda: None)
    monkeypatch.setattr(lab, "reply", replies.append)
    monkeypatch.setattr(lab, "receive_command", lambda: next(commands))
    path = tmp_path / "SYNTHETIC-abrupt-prefix"
    with path.open("xb") as stream, pytest.raises(ExitRequested):
        lab.source_worker(stream.fileno())
    assert exits == [7]
    assert len(path.read_bytes().splitlines()) == 8
    assert [row["kind"] for row in replies] == ["blocked", "prefix"]


@pytest.mark.parametrize("role", ["source", "collector"])
def test_actor_exec_passes_only_assigned_capture_descriptor_and_no_source_output_path(monkeypatch, tmp_path, role):
    calls = []
    class Pipe(io.BytesIO):
        def fileno(self):
            return 123
    process = SimpleNamespace(stdin=Pipe(), stdout=Pipe(), stderr=Pipe())
    def launch(argv, **kwargs):
        calls.append((argv, kwargs))
        return process
    class Selector:
        def register(self, *args):
            pass
    class ActorOS:
        def __getattr__(self, name):
            return getattr(os, name)

        def set_blocking(self, *args):
            pass
    monkeypatch.setattr(lab, "subprocess", SimpleNamespace(Popen=launch, PIPE=-1))
    monkeypatch.setattr(lab, "selectors", SimpleNamespace(DefaultSelector=Selector, EVENT_READ=1))
    monkeypatch.setattr(lab, "os", ActorOS())
    lab.Actor(role, 77, tmp_path)
    argv, kwargs = calls[0]
    assert kwargs["pass_fds"] == (77,) and kwargs["close_fds"] is True
    assert ("--output" in argv) == (role == "collector")


def test_closed_original_read_is_bounded_nofollow_and_does_not_overwrite(tmp_path):
    path = tmp_path / "receipt.json"
    lab.save(path, b'{"SYNTHETIC":true}\n')
    assert lab.read_closed(path) == b'{"SYNTHETIC":true}\n'
    with pytest.raises(FileExistsError):
        lab.save(path, b"replacement forbidden")
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        lab.read_closed(alias)
    assert path.read_bytes() == b'{"SYNTHETIC":true}\n'
