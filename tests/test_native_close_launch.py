"""Mocked trusted-parent channel ownership; no core/key/Source or OS role run."""

import base64
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_edge.outcome import input_live
from azazel_edge.outcome import native_close_receipts as receipts


@pytest.fixture
def launch(monkeypatch):
    def run(*, enabled=True, receiver_timeout=False):
        policy = SimpleNamespace(
            data={"producer_uid": 61001, "origin_registration_sha256": "b" * 64},
            digest="c" * 64,
        )
        environment = {
            "AZAZEL_DEFENSE_RELEASE_LEDGER": "/fixed/ledger",
            "AZAZEL_LIVE_ORIGIN_ACCOUNTING": "v1",
            "AZAZEL_EVENT_STDOUT": "off",
        }
        if enabled:
            environment["AZAZEL_LIVE_ORIGIN_CLOSE_RECEIPTS"] = "v1"
        registration = dict(
            schema_version="outcome-live-origin-registration/v4",
            environment=environment,
        )
        calls, emitted = [], []
        ready = b'{"ready":true}\n'
        receiver_tail = b'{"receiver_diagnostic":true}\n'
        native_raw = b'{"native_diagnostic":true}\n'

        class Channel:
            def __init__(self, fd):
                self.fd = fd

            def fileno(self):
                return self.fd

            def close(self):
                pass

        class Worker:
            pid = 71
            returncode = 0

            def __init__(self):
                self.stdout = io.BytesIO(ready + receiver_tail)
                self.timed_out = False

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if receiver_timeout and timeout == 5 and not self.timed_out:
                    self.timed_out = True
                    raise input_live.subprocess.TimeoutExpired("fixed-worker", timeout)
                return self.returncode

            def kill(self):
                self.returncode = -9

        class Core:
            pid = 72
            returncode = 0
            stdout = io.BytesIO(native_raw) if enabled else None

            def poll(self):
                return self.returncode

        worker = Worker()
        core = Core()

        def popen(argv, **kwargs):
            calls.append((argv, kwargs))
            return worker if len(calls) == 1 else core

        def stream(pipe, *, initial=b"", limit, exited, **kwargs):
            assert exited
            raw = initial + (pipe.read() if pipe is not None else b"")
            return dict(
                raw_b64=base64.b64encode(raw[:limit]).decode(),
                eof=True,
                over_limit=len(raw) > limit,
            )

        monkeypatch.setattr(input_live.sys, "platform", "linux")
        monkeypatch.setattr(input_live.os, "geteuid", lambda: 0)
        monkeypatch.setattr(input_live.os, "close", lambda fd: None)
        monkeypatch.setattr(
            input_live.TrustPolicy, "from_file", lambda *args, **kwargs: policy
        )
        monkeypatch.setattr(input_live, "registration", lambda *args: registration)
        monkeypatch.setattr(
            input_live,
            "CoreLease",
            lambda *args: SimpleNamespace(fd=7, close=lambda: None),
        )
        monkeypatch.setattr(input_live, "sealed_image", lambda r: 9)
        monkeypatch.setattr(input_live, "native_gate", lambda *args: None)
        monkeypatch.setattr(input_live, "native_arguments", lambda *args: [])
        monkeypatch.setattr(
            input_live.socket, "socketpair", lambda *args: (Channel(10), Channel(11))
        )
        monkeypatch.setattr(input_live.subprocess, "Popen", popen)
        monkeypatch.setattr(input_live.signal, "signal", lambda *args: None)
        monkeypatch.setattr(
            input_live.select, "select", lambda *args: ([worker.stdout], [], [])
        )
        monkeypatch.setattr(receipts, "first_line", lambda pipe: pipe.readline())
        monkeypatch.setattr(receipts, "stream", stream)
        monkeypatch.setattr(
            receipts, "emit", lambda value, limit: emitted.append(value)
        )
        monkeypatch.setattr(receipts, "stdout_object", lambda: None)
        code = input_live.launch(
            Path("/fixed/policy"),
            Path("/fixed/registration"),
            Path("/private/not-read"),
            "fixed-boot",
        )
        return SimpleNamespace(
            code=code,
            calls=calls,
            emitted=emitted,
            ready=ready,
            receiver_tail=receiver_tail,
            native_raw=native_raw,
        )

    return run


def test_opt_in_parent_owns_distinct_pipes_and_retains_exact_readiness(launch):
    result = launch()
    assert result.code == 0
    worker, core = [kwargs for _, kwargs in result.calls]
    assert worker["stdout"] == core["stdout"] == input_live.subprocess.PIPE
    assert worker["close_fds"] is core["close_fds"] is True
    assert worker["pass_fds"] == (11,) and core["pass_fds"] == (9, 10, 7)
    assert 1 not in worker["pass_fds"] and 1 not in core["pass_fds"]
    receipt = result.emitted[0]
    assert receipt["core_pid"] == 72 and receipt["receiver_pid"] == 71
    assert (
        base64.b64decode(receipt["receiver_stream"]["raw_b64"])
        == result.ready + result.receiver_tail
    )
    assert base64.b64decode(receipt["native_stream"]["raw_b64"]) == result.native_raw


def test_actual_killed_receiver_wait_stays_minus_nine_separate_from_aggregate(launch):
    result = launch(receiver_timeout=True)
    assert result.code == 1
    receipt = result.emitted[0]
    assert receipt["receiver_wait_timed_out"] is True
    assert receipt["receiver_returncode"] == -9 and receipt["core_returncode"] == 0


def test_legacy_core_stdout_and_no_close_publication_remain_unchanged(launch):
    result = launch(enabled=False)
    assert result.code == 0 and result.emitted == []
    assert result.calls[1][1]["stdout"] == input_live.subprocess.DEVNULL
