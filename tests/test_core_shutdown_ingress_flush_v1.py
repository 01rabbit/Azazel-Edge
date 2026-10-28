"""The core writes its last ingress interval once when it is stopped (Edge#414 SO-11).

Runs the release ``azazel-edge-core`` (built by the ``rust_core_bin``
fixture) on a temporary EVE file and stops it with a real signal. Checks
that it exits 0, writes the last interval's ``ingress_shed`` summary exactly
once (``interval_end: "shutdown"``), and stops within a bound even with a
poll interval far longer than that bound. This is a container/CI check of
the stop path, not a hardware measurement.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from pathlib import Path

import pytest

# Three polls' worth of non-alert lines (examine_per_poll is 6000): the first
# poll writes a summary at once, the next two shed within the same interval
# and leave counts pending; the core then sleeps for the long poll interval.
FLOOD_LINES = 18000
LONG_POLL_MS = 10000
# The stop must not wait for the poll interval: the loop sleeps in 50 ms
# slices. Generous for a loaded CI runner, far below LONG_POLL_MS.
STOP_BOUND_S = 3.0


def _env(work: Path, poll_ms: int) -> dict:
    return {
        "PATH": os.environ.get("PATH", ""),
        "AZAZEL_EVE_PATH": str(work / "eve.json"),
        "AZAZEL_NORMALIZED_EVENT_LOG": str(work / "normalized-events.jsonl"),
        "AZAZEL_FORWARD_AI": "0",
        "AZAZEL_EVENT_STDOUT": "off",
        "AZAZEL_DEFENSE_RELEASE_LEDGER": str(work / "release-ledger.json"),
        "AZAZEL_EVE_FROM_START": "1",
        "AZAZEL_EVE_POLL_MS": str(poll_ms),
    }


def _summaries(work: Path) -> list:
    path = work / "ingress-audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["ingress_shed"] for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and "ingress_shed" in json.loads(line)]


def _wait_for(cond, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(0.02)
    return cond()


def _start(core: Path, work: Path, lines: int, poll_ms: int):
    with (work / "eve.json").open("w", encoding="utf-8") as fh:
        for n in range(lines):
            fh.write('{"event_type":"flow","n":%d}\n' % n)
    err = (work / "core.stderr").open("w", encoding="utf-8")
    proc = subprocess.Popen([str(core)], cwd=str(work), env=_env(work, poll_ms),
                            stdout=subprocess.DEVNULL, stderr=err)
    return proc, err


def _stop(proc, signals) -> tuple[int, float]:
    sent = time.monotonic()
    for i, sig in enumerate(signals):
        if i:
            time.sleep(0.01)
        proc.send_signal(sig)
    try:
        rc = proc.wait(timeout=STOP_BOUND_S * 4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)
        pytest.fail("the core did not stop on the signal")
    return rc, time.monotonic() - sent


@pytest.mark.parametrize("signals", [
    pytest.param([signal.SIGTERM], id="SIGTERM"),
    pytest.param([signal.SIGINT], id="SIGINT"),
    pytest.param([signal.SIGTERM, signal.SIGTERM], id="SIGTERM twice"),
])
def test_a_stop_writes_the_last_interval_once_and_is_not_held_by_the_poll_interval(rust_core_bin, tmp_path, signals):
    proc, err = _start(rust_core_bin, tmp_path, FLOOD_LINES, LONG_POLL_MS)
    try:
        assert _wait_for(lambda: len(_summaries(tmp_path)) >= 1, 20.0), "no first summary"
        time.sleep(0.5)  # the flood is read; the core sleeps its 10 s interval
        before = _summaries(tmp_path)
        assert all(s["interval_end"] == "audit_interval" for s in before)
        rc, took = _stop(proc, signals)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        err.close()
    assert rc == 0
    assert took < STOP_BOUND_S, f"the stop took {took:.2f} s with a {LONG_POLL_MS} ms poll interval"
    after = _summaries(tmp_path)
    shutdown = [s for s in after if s["interval_end"] == "shutdown"]
    assert len(shutdown) == 1, [s["interval_end"] for s in after]
    assert after[-1]["interval_end"] == "shutdown"
    assert after[:-1] == before
    last = shutdown[0]
    assert last["shed_total"] > 0 and last["alerts_shed"] == 0
    # Nothing lost between the summaries, nothing counted twice.
    assert sum(s["shed_total"] for s in after) == last["cumulative_shed_total"]
    assert sum(s["examined"] for s in after) == FLOOD_LINES
    stderr = (tmp_path / "core.stderr").read_text(encoding="utf-8")
    assert stderr.count("azazel-edge-core stopping: 1 ingress summary record(s)") == 1


def test_a_stop_with_nothing_pending_writes_nothing(rust_core_bin, tmp_path):
    # 100 lines are admitted whole: nothing is shed, so no summary at all.
    proc, err = _start(rust_core_bin, tmp_path, 100, 200)
    try:
        assert _wait_for(lambda: "azazel-edge-core started" in (tmp_path / "core.stderr").read_text(encoding="utf-8"), 20.0)
        time.sleep(0.5)
        rc, took = _stop(proc, [signal.SIGTERM])
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
        err.close()
    assert rc == 0 and took < STOP_BOUND_S
    assert _summaries(tmp_path) == []
    assert "stopping: 0 ingress summary record(s)" in (tmp_path / "core.stderr").read_text(encoding="utf-8")
