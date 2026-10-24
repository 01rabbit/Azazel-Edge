"""SO-07 (process-kill variant): audit ordering -- durable before reported complete.

Definition (assignment section 3, SO-07): for every record type the chain
writes, interrupt between "record written" and "reported complete", at minimum
by killing the process after the report and before the flush. On restart,
enumerate every action reported complete and check its record exists. Pass:
**zero** instances of "reported complete, record absent", at every injection
point. A durable record for an action never reported complete is permitted.

What is measured here
---------------------
* The chain: Edge's decision audit chain, ``P0AuditLogger``
  (``py/azazel_edge/audit/logger.py``).
* Record types: every kind in ``VALID_KINDS``, read from the code at run time,
  so a kind added later is covered without editing this harness.
* "Reported complete": ``P0AuditLogger.log()`` has returned and the child has
  written ``COMPLETE`` on its stdout pipe. The parent reads that pipe; it never
  looks inside the child.
* Injection points (each run for every kind, at two record sizes so both of
  Python's buffering regimes are crossed):

  - ``after_report``: SIGKILL the instant the parent reads a ``COMPLETE``.
  - ``random_time``: SIGKILL at a random instant while records stream.
  - ``between_write_and_close``: the record is in the file handle's buffer and
    the handle is not yet closed.
  - ``after_close_before_return``: the file is closed, ``log()`` has not
    returned (nothing reported yet).
  - ``during_fabric_projection``: the Fabric side-projection has run,
    ``log()`` has not returned.

* Restart: a fresh process constructs ``P0AuditLogger`` on the same file (as
  Edge does at start), writes one record, and lists every ``trace_id``
  present. Chain integrity after restart is recorded as a diagnostic; it is not
  this row's pass rule.

This is the process-kill variant only. The power-cut variant is hardware-only
(R7). ``P0AuditLogger`` closes but does not ``fsync``, so a process kill cannot
lose a closed record (the kernel holds it) while a power cut can; that is a
note for the R7 variant, not a result of this one.
"""

from __future__ import annotations

import json
import os
import random
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .record import (
    RULE_ZERO_VIOLATIONS,
    SO07_INJECTION_POINTS,
    SO07_RECORD_PADS,
    so07_sample_violations,
    spec_for,
    build_part,
    build_record,
    gap,
    prerequisite,
    utc_now,
)

OBJECTIVE_ID = "SO-07"
TITLE = "Audit ordering -- durable before reported complete (process-kill variant)"
INJECTION_POINTS = SO07_INJECTION_POINTS
PAUSE_POINTS = {"between_write_and_close", "after_close_before_return", "during_fabric_projection"}
RECORD_PADS = SO07_RECORD_PADS
SPEC = spec_for("SO-07", "reported_complete_implies_record_present")
PY_ROOT = Path(__file__).resolve().parents[2]


class _Child:
    """A worker process whose stdout lines are read on a thread."""

    def __init__(self, argv: List[str]):
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([str(PY_ROOT), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "azazel_edge.service_objectives._so07_worker", *argv],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self.lines: List[Tuple[int, str]] = []
        self._cv = threading.Condition()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for raw in self.proc.stdout:
            with self._cv:
                self.lines.append((time.monotonic_ns(), raw.rstrip("\n")))
                self._cv.notify_all()
        with self._cv:
            self._cv.notify_all()

    def wait_for(self, predicate, timeout: float) -> Optional[str]:
        deadline = time.monotonic() + timeout
        seen = 0
        with self._cv:
            while True:
                while seen < len(self.lines):
                    line = self.lines[seen][1]
                    seen += 1
                    if predicate(line):
                        return line
                remaining = deadline - time.monotonic()
                if remaining <= 0 or (self.proc.poll() is not None and seen >= len(self.lines) and not self._reader.is_alive()):
                    return None
                self._cv.wait(timeout=min(remaining, 0.05))

    def kill(self) -> int:
        t = time.monotonic_ns()
        try:
            self.proc.send_signal(signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.proc.wait(timeout=10)
        self._reader.join(timeout=5)
        return t

    def completed(self) -> List[str]:
        out = []
        for _, line in self.lines:
            if line.startswith("COMPLETE "):
                out.append(line.split(" ", 2)[2])
        return out

    def stderr_tail(self) -> str:
        try:
            assert self.proc.stderr is not None
            return self.proc.stderr.read()[-500:]
        except Exception:
            return ""


def _restart_and_enumerate(audit: Path, prefix: str) -> Tuple[Optional[List[str]], Dict[str, Any], str]:
    child = _Child(["--audit", str(audit), "--prefix", prefix, "--restart"])
    try:
        child.proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        child.kill()
        return None, {}, "restart_timeout"
    child._reader.join(timeout=5)
    present: Optional[List[str]] = None
    chain: Dict[str, Any] = {}
    for _, line in child.lines:
        if line.startswith("PRESENT "):
            present = json.loads(line[len("PRESENT "):])
        elif line.startswith("CHAIN "):
            chain = json.loads(line[len("CHAIN "):])
    err = "" if child.proc.returncode == 0 else f"restart_exit_{child.proc.returncode}:{child.stderr_tail()}"
    return present, chain, err


def _one_injection(work: Path, kind: str, point: str, pad: int, rng: random.Random, idx: int) -> Dict[str, Any]:
    audit = work / f"audit-{idx:04d}.jsonl"
    prefix = f"so07-{idx:04d}"
    count = 40
    argv = ["--audit", str(audit), "--prefix", prefix, "--kind", kind, "--count", str(count), "--pad", str(pad)]
    pause_at = 0
    if point in PAUSE_POINTS:
        pause_at = rng.randint(2, 8)
        argv += ["--point", point, "--pause-at", str(pause_at)]
    elif point == "random_time":
        argv += ["--interval-ms", "2"]
    child = _Child(argv)
    problems: List[str] = []
    if child.wait_for(lambda l: l == "READY", timeout=30) is None:
        problems.append("child_never_ready:" + child.stderr_tail())
        kill_ns = child.kill()
    elif point == "after_report":
        target = rng.randint(1, 10)
        hit = child.wait_for(lambda l: l.startswith(f"COMPLETE {target} "), timeout=30)
        kill_ns = child.kill()
        if hit is None:
            problems.append("report_never_seen")
    elif point == "random_time":
        time.sleep(rng.uniform(0.005, 0.06))
        kill_ns = child.kill()
    else:
        hit = child.wait_for(lambda l: l.startswith("PAUSE "), timeout=30)
        kill_ns = child.kill()
        if hit is None:
            problems.append("pause_point_never_reached")
    reported = child.completed()
    present, chain, err = _restart_and_enumerate(audit, prefix)
    end_ns = time.monotonic_ns()
    if err:
        problems.append(err)
    if present is None:
        problems.append("restart_did_not_enumerate")
        absent = None
    else:
        present_set = set(present)
        absent = [t for t in reported if t not in present_set]
    unreported_but_present = None
    if present is not None:
        rep = set(reported)
        unreported_but_present = sum(1 for t in present if t.startswith(prefix + "-0") and t not in rep)
    # A sample that could not observe is malformed (violations = -1), which the
    # pass rule counts against the run rather than silently ignoring it.
    sample = {
        "sample_id": f"{kind}/{point}/pad{pad}",
        "record_kind": kind,
        "injection_point": point,
        "record_pad_bytes": pad,
        "pause_at_seq": pause_at or None,
        "start_monotonic_ns": kill_ns,
        "end_monotonic_ns": end_ns,
        "elapsed_ms": round((end_ns - kill_ns) / 1e6, 3),
        "start_event": "SIGKILL delivered to the writer process",
        "end_event": "restarted process enumerated the chain",
        "reported_complete": len(reported),
        "reported_complete_record_absent": absent if absent is not None else None,
        "unreported_record_present": unreported_but_present,
        "problems": problems,
        "chain_after_restart": chain,
    }
    sample["violations"] = so07_sample_violations(sample)
    return sample


def run(*, repeats: int = 1, seed: Optional[int] = None, kinds: Optional[List[str]] = None) -> Dict[str, Any]:
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    from azazel_edge.audit.logger import VALID_KINDS

    all_kinds = sorted(VALID_KINDS)
    use_kinds = sorted(kinds) if kinds else all_kinds
    rng = random.Random(seed)
    samples: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="so07-") as tmp:
        work = Path(tmp)
        idx = 0
        for _ in range(max(1, int(repeats))):
            for kind in use_kinds:
                for point in INJECTION_POINTS:
                    for pad in RECORD_PADS:
                        idx += 1
                        samples.append(_one_injection(work, kind, point, pad, rng, idx))

    covered = {(s["record_kind"], s["injection_point"]) for s in samples if not s["problems"]}
    missing = [f"{k}/{p}" for k in all_kinds for p in INJECTION_POINTS if (k, p) not in covered]
    reported_total = sum(s["reported_complete"] for s in samples)
    after_report_reports = sum(s["reported_complete"] for s in samples if s["injection_point"] == "after_report")
    prerequisites = [
        prerequisite(
            "every_record_kind_at_every_injection_point",
            not missing,
            "covered all kinds x points" if not missing else "not covered: " + ", ".join(missing),
        ),
        prerequisite(
            "kill_landed_after_a_report",
            after_report_reports > 0,
            f"{after_report_reports} completions were reported before an after_report kill",
        ),
    ]
    chain_broken = [s["sample_id"] for s in samples if s["chain_after_restart"] and not s["chain_after_restart"].get("ok")]
    part = build_part(
        name="reported_complete_implies_record_present",
        pass_rule={
            "kind": RULE_ZERO_VIOLATIONS,
            "description": "zero instances of 'reported complete, record absent', at every injection point",
        },
        required_samples=SPEC["required_samples"],
        samples=samples,
        prerequisites=prerequisites,
        gaps=[],
    )
    notes = [
        "P0AuditLogger closes the file but does not fsync. A process kill cannot lose a closed record; "
        "a power cut can. The power-cut variant is hardware-only (R7) and is not measured here.",
        f"{reported_total} completions were reported across all injections.",
    ]
    if chain_broken:
        notes.append(
            "diagnostic (not this row's pass rule): verify_chain failed after restart for "
            + ", ".join(chain_broken)
        )
    return build_record(
        objective_id=OBJECTIVE_ID,
        title=TITLE,
        started_monotonic_ns=started_ns,
        started_at=started_at,
        product_configuration={
            "product": "azazel-edge",
            "chain": "decision audit chain (P0AuditLogger, py/azazel_edge/audit/logger.py)",
            "record_kinds": all_kinds,
            "fabric_projection": "enabled when azazel_fabric is importable (side file, not chained)",
            "interface_identity": "not_applicable: no interface is involved in this row",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "host": "harness host (writer, killer and restart run on one host)",
            "note": "sample times bound each injection; the row is a property, not a latency",
        },
        sample_rule={
            "definition": "for every record type the chain writes, interrupt at every injection point",
            "injection_points": list(INJECTION_POINTS),
            "record_pad_bytes": list(RECORD_PADS),
            "repeats": max(1, int(repeats)),
        },
        parts=[part],
        method="process-kill fault injection with SIGKILL, restart enumeration from a fresh process",
        notes=notes,
    )
