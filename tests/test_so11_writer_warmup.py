"""Deterministic writer-start anchoring; no wall-time allowance or repaired stamps."""

from types import SimpleNamespace
import pytest
from azazel_edge.service_objectives import so11_quota_load as so11


class Load:
    def __init__(
        self,
        clock,
        *,
        start=250_000_000,
        offset=0,
        missing=False,
        early=False,
        late=False,
    ):
        self.clock = clock
        self.window = {}
        self.error = None
        self.alive = True
        self.stopped = False
        self.waits = []
        self.ready_waits = []
        self.start = start
        self.offset = offset
        self.missing = missing
        self.early = early
        self.late = late
        self.ready = SimpleNamespace(wait=self.publish)
        self.stop = SimpleNamespace(wait=self.wait, is_set=lambda: self.stopped)

    def publish(self, timeout):
        self.ready_waits.append(timeout)
        if self.missing:
            return False
        self.window["window_start_monotonic_ns"] = self.start
        self.clock.now = self.start + self.offset if type(self.start) is int else 0
        return True

    def wait(self, seconds):
        self.waits.append(seconds)
        self.clock.now += round(seconds * 1_000_000_000)
        if self.early and len(self.waits) == 1:
            self.clock.now -= 1
        if self.late:
            self.clock.now += 500
        return False

    def is_alive(self):
        return self.alive


def clock(monkeypatch):
    value = SimpleNamespace(now=0)
    monkeypatch.setattr(so11, "time", SimpleNamespace(monotonic_ns=lambda: value.now))
    return value


def test_delayed_writer_start_gets_full_unchanged_3000ms(monkeypatch):
    timer = clock(monkeypatch)
    load = Load(timer)
    so11._wait_warmup(load)
    assert load.ready_waits == [so11.START_WAIT_S]
    assert load.waits == [3.0]
    assert timer.now == 3_250_000_000 > 3_000_000_000
    assert load.window["window_start_monotonic_ns"] == 250_000_000
    assert load.error is None
    assert so11.WARMUP_MS == 3000


@pytest.mark.parametrize(
    "offset,waits", [(2_999_999_999, [1e-9]), (3_000_000_000, []), (3_000_000_001, [])]
)
def test_exact_actual_start_boundary_not_parent_elapsed_time(
    monkeypatch, offset, waits
):
    timer = clock(monkeypatch)
    load = Load(timer, offset=offset)
    so11._wait_warmup(load)
    assert load.waits == waits
    assert timer.now >= load.start + 3_000_000_000
    assert load.window["window_start_monotonic_ns"] == load.start


@pytest.mark.parametrize("late", [False, True])
def test_early_or_late_wakeup_rechecks_clock_without_rewriting_start(monkeypatch, late):
    timer = clock(monkeypatch)
    load = Load(timer, early=not late, late=late)
    so11._wait_warmup(load)
    assert timer.now == load.start + 3_000_000_000 + (500 if late else 0)
    assert len(load.waits) == (1 if late else 2)
    assert load.window == {"window_start_monotonic_ns": 250_000_000}


@pytest.mark.parametrize(
    "fault",
    [
        "timeout",
        "missing_start",
        "bool_start",
        "future_start",
        "error",
        "dead",
        "stopped",
    ],
)
def test_unestablished_readiness_never_satisfies_warmup_and_is_sticky(
    monkeypatch, fault
):
    timer = clock(monkeypatch)
    load = Load(timer, missing=fault == "timeout")
    real = load.publish

    def publish(timeout):
        result = real(timeout)
        if fault == "missing_start":
            load.window.clear()
        elif fault == "bool_start":
            load.window["window_start_monotonic_ns"] = True
        elif fault == "future_start":
            load.window["window_start_monotonic_ns"] = timer.now + 1
        elif fault == "error":
            load.error = "original writer error"
        elif fault == "dead":
            load.alive = False
        elif fault == "stopped":
            load.stopped = True
        return result

    load.ready = SimpleNamespace(wait=publish)
    with pytest.raises(RuntimeError):
        so11._wait_warmup(load)
    assert load.error
    assert load.waits == []
    if fault == "error":
        assert load.error == "original writer error"


@pytest.mark.parametrize("fault", ["error", "dead", "stopped"])
def test_writer_failure_during_wait_is_not_a_successful_early_wake(monkeypatch, fault):
    timer = clock(monkeypatch)
    load = Load(timer)

    def stop_wait(seconds):
        timer.now = load.start + 3_000_000_000
        if fault == "error":
            load.error = "writer failed"
        elif fault == "dead":
            load.alive = False
        else:
            load.stopped = True
        return True

    load.stop = SimpleNamespace(wait=stop_wait, is_set=lambda: load.stopped)
    with pytest.raises(RuntimeError):
        so11._wait_warmup(load)
    assert load.error


def test_real_writer_open_failure_publishes_failure_not_an_actual_start(
    monkeypatch, tmp_path
):
    writer = so11.QuotaLoad(tmp_path / "missing-parent" / "eve", 2500)
    writer.run()
    assert writer.ready.is_set() and writer.error
    assert writer.window == {}
    with pytest.raises(RuntimeError):
        so11._wait_warmup(writer)


def test_applied_timeout_has_no_body_and_still_stops_joins_and_snapshots(
    monkeypatch, tmp_path
):
    calls = []
    out = {}

    class FailedLoad:
        def __init__(self, *args):
            self.ready = SimpleNamespace(wait=lambda timeout: False)
            self.stop = SimpleNamespace(set=lambda: calls.append("stop"))
            self.error = None
            self.window = {}
            self.written = {}
            self.written_bytes = 0

        def start(self):
            calls.append("start")

        def join(self, **kwargs):
            calls.append("join")

        def is_alive(self):
            return False

    final = SimpleNamespace(pre=None)

    def before_stop(*args, **kwargs):
        calls.append("snapshot")
        final.pre = SimpleNamespace(metadata=dict(error=None))

    final.before_stop = before_stop
    monkeypatch.setattr(so11, "QuotaLoad", FailedLoad)
    monkeypatch.setattr(
        so11,
        "time",
        SimpleNamespace(monotonic_ns=lambda: 100, sleep=lambda seconds: None),
    )
    with pytest.raises(RuntimeError, match="readiness timeout"):
        with so11.applied(
            tmp_path / "eve",
            tmp_path,
            1.2,
            {"value": 2500, "audit_interval_ms": 1000},
            out,
            core_started=True,
            core_alive=lambda: True,
            final_audit=final,
        ):
            pytest.fail("samples began without actual ready start")
    assert calls == ["start", "stop", "join", "snapshot"]
    assert out["writer_error"] == "load writer readiness timeout"
