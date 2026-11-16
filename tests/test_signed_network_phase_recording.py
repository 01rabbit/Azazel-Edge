"""Synthetic timing metadata and delegated calls; no actual trial or confinement claim."""

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_phase_recording as r


META = dict(run_id="synthetic-run", arm="instrumented_on", role="observer",
            input_sha256="1" * 64, code_sha256="2" * 64,
            core_sha256="3" * 64, interpreter_sha256="4" * 64)


@pytest.fixture(autouse=True)
def synthetic_identity(monkeypatch):
    monkeypatch.setattr(r, "_identity", lambda: dict(
        pid=123, start_ticks=456, native_tid=123, boot_id="12345678-1234-1234-1234-123456789abc",
        clock_domain=dict(time_namespace_device=1, time_namespace_inode=2,
                          timens_offsets=[dict(clock=c, seconds=0, nanoseconds=0)
                                          for c in ("monotonic", "boottime")], established=True),
        clock_ticks_per_second=100,
        clock_resolutions={name: 1e-9 for name in ("monotonic", "process_time", "thread_time")},
    ))


def make(tmp_path, **kwargs):
    path = tmp_path / "trace.jsonl"
    return r.PhaseRecording(path, metadata=META, **kwargs), path


def rows(path):
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def test_actual_call_once_nested_metadata_only_and_canonical_chain(tmp_path):
    recorder, path = make(tmp_path)
    token = object()
    calls = []

    def original(secret):
        calls.append(secret)
        return recorder.call("finalize_due", lambda: token)

    assert recorder.call("observation", original, "SECRET_PAYLOAD") is token
    recorder.close(normal_return=True)
    assert calls == ["SECRET_PAYLOAD"]
    raw = path.read_bytes()
    assert b"SECRET" not in raw
    previous = "0" * 64
    parsed = rows(path)
    assert [row["kind"] for row in parsed] == ["header", "intent", "intent", "span", "span", "end"]
    for sequence, line in enumerate(raw.splitlines(keepends=True), 1):
        row = json.loads(line)
        assert line == r.canonical(row)
        assert row["seq"] == sequence and row["prev"] == previous
        previous = hashlib.sha256(line).hexdigest()
    spans = [row["data"] for row in parsed if row["kind"] == "span"]
    assert spans[0]["parent_id"] == spans[1]["span_id"]
    assert all(s["start_ns"] <= s["end_ns"] for s in spans)
    assert parsed[0]["data"]["pid"] > 0
    assert parsed[-1]["data"]["unallocated_footer_flush_overhead"] is True


@pytest.mark.parametrize("failure", ["write", "clock", "bounds"])
def test_recorder_failure_never_changes_same_original_exception(tmp_path, monkeypatch, failure):
    recorder, path = make(tmp_path, max_rows=2 if failure == "bounds" else 4096)
    original = OSError("SECRET_EXCEPTION")
    if failure == "write":
        monkeypatch.setattr(r, "os", r.ModuleProxy(r.os, write=lambda *a: (_ for _ in ()).throw(OSError("loss"))))
    elif failure == "clock":
        monkeypatch.setattr(r, "_clocks", lambda: (_ for _ in ()).throw(ValueError("no clock")))

    def fail():
        raise original

    with pytest.raises(OSError) as error:
        recorder.call("observation", fail)
    assert error.value is original
    recorder.close(normal_return=True)
    assert recorder.incomplete
    assert all(row["kind"] != "end" for row in rows(path))
    assert b"SECRET_EXCEPTION" not in path.read_bytes()


def test_no_normal_return_no_end_and_invalid_enum_cannot_change_result(tmp_path):
    recorder, path = make(tmp_path)
    sentinel = object()
    assert recorder.call("observation", lambda: sentinel, operation="SECRET") is sentinel
    recorder.close(normal_return=True)
    assert recorder.incomplete
    assert [row["kind"] for row in rows(path)] == ["header"]


def test_socket_proxy_same_fd_same_recv_bytes_flags_exception_and_close(tmp_path, monkeypatch):
    recorder, path = make(tmp_path)
    expected = b"original bytes"
    error = OSError("original recv")
    observed = []

    class Socket:
        def __enter__(self):
            observed.append("enter")
            return self

        def __exit__(self, *args):
            observed.append("close")

        def fileno(self):
            return 77

        def recv(self, *args, **kwargs):
            observed.append((args, kwargs))
            if len(observed) > 2:
                raise error
            return expected

    def factory(*args, **kwargs):
        observed.append(("socket", args, kwargs))
        return Socket()

    monkeypatch.setattr(r.input_live, "socket", SimpleNamespace(socket=factory))
    original_binding = r.input_live.socket
    with r.record_receiver(recorder, 77):
        with r.input_live.socket.socket(fileno=77) as sock:
            # The factory constructs once and never dup/detach/extra-read.
            assert sock.fileno() == 77
            # observed length already 2; explicit fake returns on first recv.
            observed.pop()
            assert sock.recv(123, 64) is expected
            with pytest.raises(OSError) as caught:
                sock.recv(456, flags=0)
            assert caught.value is error
        with pytest.raises(ValueError):
            r.input_live.socket.socket(fileno=77)
    assert r.input_live.socket is original_binding
    assert observed[-1] == "close"
    assert len([v for v in observed if type(v) is tuple and v[0] == "socket"]) == 1
    recorder.close(normal_return=True)
    assert len([row for row in rows(path) if row["kind"] == "span" and row["data"]["phase"] == "input_receive"]) == 2


def test_source_sign_wraps_actual_original_sign_once(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    recorder, path = make(tmp_path)
    private = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
    body = {"seq": 7, "private_content": "NEVER_RECORD_THIS"}
    expected = r.input_auth.sign(private, r.input_auth.SOURCE_DOMAIN, body)
    with r.record_receiver(recorder, 77):
        assert r.input_auth.sign(private, r.input_auth.SOURCE_DOMAIN, body) == expected
    recorder.close(normal_return=True)
    spans = [row["data"] for row in rows(path) if row["kind"] == "span"]
    assert [row["phase"] for row in spans] == ["source_sign"]
    assert spans[0]["event_seq"] == 7
    assert b"NEVER_RECORD_THIS" not in path.read_bytes()
    assert expected.encode() not in path.read_bytes()


def test_local_os_proxy_does_not_patch_global_os(tmp_path, monkeypatch):
    recorder, _ = make(tmp_path)
    original_os = r.input_auth.os
    calls = []
    fake_os = r.ModuleProxy(original_os, fsync=lambda fd: calls.append(fd))
    monkeypatch.setattr(r.input_auth, "os", fake_os)
    with r.record_receiver(recorder, 99):
        r.input_auth.os.fsync(12)
        assert r.os is original_os
    assert r.input_auth.os is fake_os
    assert calls == [12]
    recorder.close(normal_return=True)


def test_observer_original_argument_result_and_binding_restoration(tmp_path, monkeypatch):
    recorder, path = make(tmp_path)
    calls = []
    sentinel = object()

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return sentinel

    monkeypatch.setattr(r.input_resume, "observe_input", original)
    with r.record_observer(recorder):
        assert r.input_resume.observe_input(1, 2, live_floor=3, now=4) is sentinel
    assert r.input_resume.observe_input is original
    assert calls == [((1, 2), {"live_floor": 3, "now": 4})]
    recorder.close(normal_return=True)
    assert any(row["kind"] == "span" and row["data"]["phase"] == "observation" for row in rows(path))


def test_sidecar_baseexception_does_not_replace_original_return(tmp_path, monkeypatch):
    recorder, path = make(tmp_path)
    original = object()
    monkeypatch.setattr(r, "_clocks", lambda: (_ for _ in ()).throw(KeyboardInterrupt()))
    assert recorder.call("finalize_due", lambda: original) is original
    recorder.close(normal_return=True)
    assert recorder.incomplete
    assert not any(row["kind"] == "end" for row in rows(path))


def test_real_witness_sign_has_original_signature_and_bounded_operation(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    recorder, path = make(tmp_path)
    key = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
    body = {"private_material": "DO_NOT_COPY"}
    expected = r.input_witness.sign(key, r.input_witness.ANCHOR_DOMAIN, body)
    with r.record_witness(recorder):
        assert r.input_witness.sign(key, r.input_witness.ANCHOR_DOMAIN, body) == expected
    recorder.close(normal_return=True)
    spans = [row["data"] for row in rows(path) if row["kind"] == "span"]
    assert [(row["phase"], row["operation"]) for row in spans] == [("witness_sign", "anchor")]
    assert b"DO_NOT_COPY" not in path.read_bytes()
    assert expected.encode() not in path.read_bytes()


def test_concurrent_witness_calls_use_unique_spans_and_thread_local_parents(tmp_path):
    import threading

    recorder, path = make(tmp_path)
    barrier = threading.Barrier(2)

    def outer():
        barrier.wait()
        return recorder.call("witness_sign", lambda: 7)

    threads = [threading.Thread(target=lambda: recorder.call("witness_request", outer)) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    recorder.close(normal_return=True)
    spans = [row["data"] for row in rows(path) if row["kind"] == "span"]
    by_id = {span["span_id"]: span for span in spans}
    assert len(spans) == len(by_id) == 4
    for span in spans:
        if span["parent_id"] is not None:
            assert span["native_tid"] == by_id[span["parent_id"]]["native_tid"]
    assert rows(path)[-1]["kind"] == "end"


def test_recorder_wire_replays_in_independent_analyzer(tmp_path):
    from azazel_edge.benchmark.timing_cost_attribution import analyze_trace

    recorder, path = make(tmp_path)
    assert recorder.call("observation", lambda: recorder.call("finalize_due", lambda: 7)) == 7
    recorder.close(normal_return=True)
    result = analyze_trace(path.read_bytes(), expected=META)
    assert result["normal_return_confirmed"] is True
    assert result["status"] == "complete_descriptive_trace"
    assert len(result["complete_spans"]) == 2
    assert result["active_window_finalization_wait_ns"] is None
    assert result["inclusive_spans_additive"] is False
