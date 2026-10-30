"""Real-process test of the Edge-owned undelivered-decision spool (S-10).

The release core runs with the settings of the normal (Nexus) unit:
enforcement off, dry run, ``AZAZEL_FORWARD_LOG=false`` -- so no decision is
written to the normalized log -- and its decisions forwarded to an intake
socket. With the intake down, many alerts, a clean restart and a SIGKILL,
every decision is either in the spool or counted as lost, and the counts,
the time range and the unclean stops survive restarts. With the intake up,
nothing is spooled. The spool is bounded: past its cap one rotated segment
is kept and what it drops is counted.

Unprivileged; it needs the release core build (``rust_core_bin``). Container
and runner timings are never hardware evidence.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest


def _alert(n: int) -> str:
    return json.dumps({
        "timestamp": "2026-10-30T00:00:00.%06d+0000" % (n % 1_000_000),
        "event_type": "alert", "src_ip": "203.0.113.%d" % (n % 250 + 1), "dest_ip": "192.0.2.10",
        "dest_port": 22, "proto": "TCP",
        "alert": {"signature_id": 9_800_000 + n, "signature": "spool", "category": "test", "severity": 1 + n % 4},
    })


class Core:
    def __init__(self, core_bin: Path, work: Path, cap: int | None = None, from_start: bool = True):
        self.spool = work / "state" / "undelivered-decisions.jsonl"
        self.state = work / "state" / "undelivered-decisions.state.json"
        self.eve = work / "eve.json"
        self.socket = work / "intake.sock"
        if not self.eve.exists():
            self.eve.write_text("", encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AZAZEL_EVE_PATH": str(self.eve), "AZAZEL_EVE_FROM_START": "true" if from_start else "false",
            "AZAZEL_EVE_POLL_MS": "50",
            # The normal unit: observe-only, no normalized log, forward on.
            "AZAZEL_DEFENSE_ENFORCE": "false", "AZAZEL_DEFENSE_DRY_RUN": "true",
            "AZAZEL_DEFENSE_ENFORCE_LEVEL": "advisory",
            "AZAZEL_FORWARD_LOG": "false", "AZAZEL_FORWARD_AI": "true", "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_NORMALIZED_EVENT_LOG": str(work / "log" / "normalized-events.jsonl"),
            "AZAZEL_AI_SOCKET": str(self.socket),
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(work / "state" / "release-ledger.json"),
            "AZAZEL_UNDELIVERED_SPOOL": str(self.spool),
        }
        if cap is not None:
            env["AZAZEL_UNDELIVERED_SPOOL_CAP_BYTES"] = str(cap)
        self.proc = subprocess.Popen([str(core_bin)], cwd=str(work), env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        assert self.proc.poll() is None, self.proc.stderr.read()

    def append(self, start: int, count: int):
        with self.eve.open("a", encoding="utf-8") as fh:
            for n in range(start, start + count):
                fh.write(_alert(n) + "\n")

    def read_state(self) -> dict:
        try:
            return json.loads(self.state.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def wait(self, predicate, timeout: float = 30.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.1)
        return predicate()

    def stop(self, sig=signal.SIGTERM):
        self.proc.send_signal(sig)
        self.proc.wait(timeout=20)


def _accounted(state: dict) -> int:
    return state.get("spooled_total", 0) + state.get("lost_before_spool_total", 0)


def _spooled_sids(core: Core) -> list:
    sids = []
    for name in (core.spool.name + ".1", core.spool.name):
        path = core.spool.with_name(name)
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                if "normalized" in record:
                    sids.append(record["normalized"]["sid"])
    return sids


def test_observe_only_decisions_survive_an_intake_outage_restarts_and_a_kill(tmp_path, rust_core_bin):
    core = Core(rust_core_bin, tmp_path)
    try:
        core.append(0, 3000)
        # Every decision is spooled or counted lost, though nothing reaches
        # the normalized log (FORWARD_LOG=false) and the intake is down.
        assert core.wait(lambda: _accounted(core.read_state()) >= 3000), core.read_state()
    finally:
        core.stop()
    state = core.read_state()
    assert state["clean_shutdown"] is True and state["runs"] == 1 and state["unclean_stops"] == 0
    assert _accounted(state) == 3000, state
    sids = _spooled_sids(core)
    assert len(sids) == state["spooled_total"] == len(set(sids))
    assert set(sids) <= {9_800_000 + n for n in range(3000)}
    assert state["first_undelivered_epoch"] <= state["last_undelivered_epoch"]
    assert not (tmp_path / "log" / "normalized-events.jsonl").exists()
    # Observe-only decisions (dry run) are what is kept.
    record = json.loads(core.spool.read_text(encoding="utf-8").splitlines()[0])
    assert record["enforcement"]["mode"] in ("dry_run", "disabled")

    # A restart continues the counts; a SIGKILL is counted at the next start.
    core = Core(rust_core_bin, tmp_path, from_start=False)
    try:
        core.append(3000, 500)
        assert core.wait(lambda: _accounted(core.read_state()) >= 3200)
        time.sleep(1.5)  # past one flush
    finally:
        core.stop(signal.SIGKILL)
    killed = core.read_state()
    assert killed["clean_shutdown"] is False and killed["runs"] == 2
    core = Core(rust_core_bin, tmp_path, from_start=False)
    try:
        started = core.wait(lambda: core.read_state().get("runs") == 3 and core.read_state())
        assert started["unclean_stops"] == 1
        assert started["spooled_total"] >= killed["spooled_total"] >= state["spooled_total"]

        # The intake is back: delivered decisions are not spooled.
        got = []
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(core.socket))
        listener.listen(64)

        def accept():
            listener.settimeout(20)
            try:
                while True:
                    conn, _ = listener.accept()
                    data = b""
                    while chunk := conn.recv(65536):
                        data += chunk
                    conn.close()
                    got.extend(l for l in data.decode().splitlines() if '"normalized"' in l)
            except OSError:
                pass

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        before = core.read_state()["spooled_total"]
        core.append(4000, 50)
        assert core.wait(lambda: len(got) >= 50, 20), len(got)
        time.sleep(1.5)
        assert core.read_state()["spooled_total"] == before
        listener.close()
    finally:
        core.stop()


def test_the_spool_is_bounded_and_counts_what_its_cap_drops(tmp_path, rust_core_bin):
    core = Core(rust_core_bin, tmp_path, cap=64 * 1024)
    try:
        core.append(0, 600)
        assert core.wait(lambda: _accounted(core.read_state()) >= 600)
    finally:
        core.stop()
    state = core.read_state()
    kept = len(_spooled_sids(core))
    assert state["rotated_out_total"] > 0, state
    # Every spooled line is either in the two kept segments or counted out.
    assert kept + state["rotated_out_total"] == state["spooled_total"], (kept, state)
    for name in (core.spool.name, core.spool.name + ".1"):
        assert core.spool.with_name(name).stat().st_size <= 64 * 1024 + 4096
