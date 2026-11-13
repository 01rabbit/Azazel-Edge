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
    def __init__(self, core_bin: Path, work: Path, cap: int | None = None, from_start: bool = True, spool_directory: Path | None = None):
        # Except for the isolated storage-failure case, test the default
        # beside the ledger (the Nexus unit's writable state directory).
        spool_directory = spool_directory if spool_directory is not None else work / "state"
        self.spool = spool_directory / "undelivered-decisions.jsonl"
        self.state = spool_directory / "undelivered-decisions.state.json"
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
        }
        if cap is not None:
            env["AZAZEL_UNDELIVERED_SPOOL_CAP_BYTES"] = str(cap)
        if spool_directory != work / "state":
            env["AZAZEL_UNDELIVERED_SPOOL"] = str(self.spool)
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
    # Spooled, lost, or still on its way at a clean stop (unconfirmed).
    return state.get("spooled_total", 0) + state.get("lost_total", 0) + state.get("unconfirmed_at_stop_total", 0)


def _spooled_records(core: Core) -> list:
    records = []
    for name in (core.spool.name + ".1", core.spool.name):
        path = core.spool.with_name(name)
        if path.exists():
            records.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines())
    return records


def _partition(records, *, allow_stats=False):
    decisions, audits, stats = [], [], []
    for record in records:
        if "normalized" in record:
            decisions.append(record)
        elif record.get("schema") == "azazel-edge/forward-stats/v1":
            assert allow_stats, "forward statistics must never enter the event spool"
            assert set(record) == {"schema", "dropped", "failed", "sent", "since"}
            assert all(type(record[key]) is int and record[key] >= 0
                       for key in ("dropped", "failed", "sent", "since"))
            stats.append(record)
        else:
            assert record.get("schema") == "azazel-edge/ingress-shed/v1", record
            assert record["interval_end"] == "shutdown", record
            audits.append(record)
    return decisions, audits, stats


def _shutdown_audit(core: Core, examined: int):
    rows = [json.loads(line) for line in
            (core.eve.parent / "log" / "ingress-audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1, rows
    assert rows[0]["source"] == "core_ingress"
    assert rows[0]["pipeline"] == "rust_ingress_v1"
    audit = rows[0]["ingress_shed"]
    assert audit["interval_end"] == "shutdown"
    assert audit["examined"] == audit["admitted"] == audit["alerts_admitted"] == examined
    assert audit["shed_total"] == audit["alerts_shed"] == 0
    return audit


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
    audit = _shutdown_audit(core, 3000)
    assert _accounted(state) == 3000 + 1, state
    decisions, audits, _ = _partition(_spooled_records(core))
    sids = [record["normalized"]["sid"] for record in decisions]
    assert audits == [audit]
    assert len(sids) + len(audits) == state["spooled_total"]
    assert len(sids) == len(set(sids))
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
                    got.extend(line for line in data.decode().splitlines() if '"normalized"' in line)
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
    audit = _shutdown_audit(core, 600)
    kept_records = _spooled_records(core)
    decisions, audits, _ = _partition(kept_records)
    sids = [record["normalized"]["sid"] for record in decisions]
    assert len(sids) == len(set(sids))
    assert set(sids) <= {9_800_000 + n for n in range(600)}
    assert audits == [audit]
    assert _accounted(state) == 600 + 1, state
    kept = len(kept_records)
    assert state["rotated_out_total"] > 0, state
    # Every spooled line is either in the two kept segments or counted out.
    assert kept + state["rotated_out_total"] == state["spooled_total"], (kept, state)
    for name in (core.spool.name, core.spool.name + ".1"):
        assert core.spool.with_name(name).stat().st_size <= 64 * 1024 + 4096


def test_a_wedged_intake_at_shutdown_leaves_every_decision_delivered_spooled_or_counted(tmp_path, rust_core_bin):
    """Re521c-07: an intake that accepts nothing (its backlog fills and the
    forwarder blocks mid-delivery) and a SIGTERM: each decision is delivered
    (read later from the backlog), spooled, or counted lost -- the one being
    delivered included -- and the stop is not clean when lines were lost."""
    work = tmp_path
    sock = work / "intake.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(sock))
    listener.listen(2)
    core = Core(rust_core_bin, work)
    try:
        core.append(0, 60)
        time.sleep(4)
    finally:
        core.stop()
    delivered_records = []
    listener.setblocking(False)
    while True:
        try:
            conn, _ = listener.accept()
        except BlockingIOError:
            break
        conn.settimeout(1)
        data = b""
        try:
            while chunk := conn.recv(65536):
                data += chunk
        except OSError:
            pass
        delivered_records.extend(json.loads(line) for line in data.decode().splitlines())
        conn.close()
    listener.close()
    state = core.read_state()
    audit = _shutdown_audit(core, 60)
    delivered_decisions, delivered_audits, delivered_stats = _partition(delivered_records, allow_stats=True)
    spooled_decisions, spooled_audits, _ = _partition(_spooled_records(core))
    sids = [record["normalized"]["sid"] for record in delivered_decisions + spooled_decisions]
    assert len(sids) == len(set(sids))
    assert set(sids) <= {9_800_000 + n for n in range(60)}
    assert len(delivered_audits + spooled_audits) <= 1
    assert all(row == audit for row in delivered_audits + spooled_audits)
    # Generic counters do not identify the type of a lost/unconfirmed line.
    # Conserve all 60 decisions AND the independently observed generated audit.
    # Forward::Stats uses a separate, non-accounted delivery path; its exact
    # closed shape is checked above rather than treating it as a decision.
    assert len(delivered_records) == len(delivered_decisions) + len(delivered_audits) + len(delivered_stats)
    delivered_events = len(delivered_decisions) + len(delivered_audits)
    assert delivered_events + _accounted(state) == 60 + 1, (delivered_records, state)
    # Lines still on their way at the stop (queued, or blocked mid-delivery)
    # are counted once, as unconfirmed, not silently dropped.
    assert state["unconfirmed_at_stop_total"] > 0, state


def test_an_unwritable_spool_directory_never_stops_the_core(tmp_path, rust_core_bin):
    """Re521c-04: where the spool cannot be created, the core runs on, decides
    and says on stderr how many undelivered decisions were not kept."""
    # Evidence storage must fail independently of the mandatory native
    # singleton/release-state directory. No lockless fallback is permitted.
    state_dir = tmp_path / "unwritable-spool"
    state_dir.mkdir()
    os.chmod(state_dir, 0o500)
    if os.access(state_dir, os.W_OK):
        os.chmod(state_dir, 0o700)
        pytest.skip("the directory stays writable for this user (root)")
    try:
        core = Core(rust_core_bin, tmp_path, spool_directory=state_dir)
        try:
            core.append(0, 20)
            time.sleep(2)
            assert core.proc.poll() is None, "the core stopped"
        finally:
            core.stop()
        err = core.proc.stderr.read()
        assert "undelivered spool unavailable" in err, err[-500:]
        _shutdown_audit(core, 20)
        # Legacy stderr calls every forwarded record a decision: 20 actual
        # normalized decisions plus the distinct generated shutdown audit.
        assert "21 undelivered decision(s) not kept" in err, err[-800:]
    finally:
        os.chmod(state_dir, 0o700)
