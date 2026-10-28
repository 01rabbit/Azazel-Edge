"""SO-11: hostile load -- the SO-03, SO-04 and SO-07 pass rules at the declared ingress quota.

Definition (assignment section 3, SO-11, class virtual-lab): at each declared
ingress quota the referenced service objectives keep their pass rules, and at
120% of the quota the quota actually sheds.

Edge declares one ingress quota (OF-06, ``config/service_objectives/
ingress_quota.json``): the Rust core's EVE reader, ``core_eve_reader``, a
quota on **non-alert** lines (alerts are never shed and never rate-limited).
This harness re-runs, against the real core binary, unmodified:

* SO-03 (P0 alert queued after the core's decision, 200 samples) through the
  SO-03 harness itself, with the load written into the EVE file that core
  reads;
* the SO-04 start half (lease-expiry rollback starts, 50 leases per action
  type) with the SO-04 harness's lease, tail and sample code, the load
  written into that core's EVE file in place of the SO-04 hostile-load
  profile;
* SO-07 (process-kill audit ordering, 110 injections) through the SO-07
  harness itself, while a core on the same host reads the load;

each twice: with non-alert lines offered at 100% of the quota and at 120% of
it. That is six parts; each keeps the referenced row's rule, bound, sample
count and prerequisites (``record.OBJECTIVE_SPECS["SO-11"]`` copies them from
the referenced rows) and adds what the load must show, recomputed by the
validator from the part's ``quota_load`` observation (``quota_load_problems``):

* ``ingress_load_offered_at_level``: the observation cites the quota file at
  its current SHA-256, every non-alert class was written at its share of the
  level's rate, and every sample started after the warm-up and ended before
  the load stopped;
* ``core_ingress_audit_consistent``: the core's own ``ingress_shed``
  summaries carry the declared quota and add up;
* ``alerts_never_shed``: no summary sheds an alert;
* ``quota_shed_at_overload`` (120% parts only): the core shed non-alert lines
  for the rate.

The load is non-alert lines only (flow, dns, stats, http in equal parts,
about 600 bytes each, as the SO-11 probe and the SO-04 profile write them):
the quota covers nothing else, and an alert flood is the SO-04 profile's
``alert_flood`` phase. SO-03's own alerts and SO-04's leases are the samples.

The verdict stays ``not_measurable``: the quota is provisional and
container-derived (gap ``SO11-QUOTA-PROVISIONAL``, which no recomputation
closes), and the SO-04 completion half is not re-run here
(``SO11-SO04-COMPLETION-NOT-RERUN``). A container run is not hardware
evidence. The record carries no address, MAC, boot id or host name: the
SO-04 samples carry whether the lease and its start record are in the same
boot instead of the boot ids, and ``run.host`` is not recorded.

Nothing here changes what the core reads, sheds or decides, or the quota.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from .declarations import load_ingress_quotas
from .record import (
    REPO_ROOT,
    SO11_INGRESS,
    SO11_LEVELS,
    SO11_OVERLOAD_PREREQUISITE,
    build_part,
    build_record,
    gap,
    gap_closed,
    prerequisite,
    spec_for,
    utc_now,
)

OBJECTIVE_ID = "SO-11"
TITLE = "Hostile load -- SO-03, SO-04 (start) and SO-07 pass rules at 100% and 120% of the declared ingress quota"
DEFAULT_CORE_BIN = REPO_ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
NON_ALERT_KINDS = ("flow", "dns", "stats", "http")
LINE_BYTES = 600
# Long enough for the 1500-token bucket to empty at 120% (net 500 lines/s):
# the samples are taken in the steady state the level produces.
WARMUP_MS = 3000
# A class's written rate may differ from its share by this fraction. The
# writer counts its lines from the start, so the real error is about one line;
# 2% keeps the 100% (2450-2550 lines/s) and 120% (2940-3060) ranges apart.
RATE_TOLERANCE = 0.02
# At 120% the core sheds until the load stops, so its summaries cover every
# line it examined: the non-alert lines they count must match the lines
# written to within this fraction (at 100% they can only be at most that).
EXAMINED_TOLERANCE = 0.02
AUDIT_FILE = "ingress-audit.jsonl"
START_WAIT_S = 15.0
SO04_LEASES_PER_TYPE = 50
# Leases are written before the core starts; the load starts once it has.
SO04_STARTUP_SLACK_S = 3.0
SO04_FIRST_DUE_AFTER_S = SO04_STARTUP_SLACK_S + WARMUP_MS / 1000.0 + 0.5
SO04_LEASE_SPACING_S = 0.1
SO04_LEASE_JITTER_S = 0.05
SO04_TAIL_SLACK_S = 30.0

_BOOT_ID_FIELDS = ("lease_boot_id", "start_record_boot_id")


# ------------------------------------------------------------------- the load


def _boottime_ns() -> Optional[int]:
    from .so04_lease_rollback import boottime_ns

    return boottime_ns()


def _line(kind: str, n: int) -> bytes:
    head = (
        '{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"%s","src_ip":"203.0.113.%d","dest_ip":"192.0.2.10",'
        '"dest_port":53,"proto":"UDP","%s":{"n":%d},"pad":"' % (kind, n % 250 + 1, kind, n)
    )
    return (head + "x" * max(0, LINE_BYTES - len(head) - 3) + '"}\n').encode("ascii")


class QuotaLoad(threading.Thread):
    """Appends non-alert lines to the core's EVE file at ``rate_per_s`` until stopped.

    One ``write`` per batch of whole lines on an ``O_APPEND`` descriptor, so a
    harness appending its own lines to the same file never splits one. The
    targets are counted from the start, so the average rate is exact however
    late a batch is; the window ends at the last write.
    """

    def __init__(self, eve: Path, rate_per_s: float):
        super().__init__(daemon=True)
        self.eve = eve
        self.rate = float(rate_per_s)
        self.stop = threading.Event()
        self.written = {k: 0 for k in NON_ALERT_KINDS}
        self.written_bytes = 0
        self.window: Dict[str, Optional[int]] = {}
        self.error: Optional[str] = None

    def run(self) -> None:
        try:
            fd = os.open(str(self.eve), os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        except OSError as exc:
            self.error = f"{exc.__class__.__name__}"
            return
        share = self.rate / len(NON_ALERT_KINDS)
        t0 = time.monotonic()
        self.window = {
            "window_start_monotonic_ns": time.monotonic_ns(),
            "window_start_boottime_ns": _boottime_ns(),
            "window_end_monotonic_ns": None,
            "window_end_boottime_ns": None,
        }
        try:
            while True:
                stopping = self.stop.is_set()
                elapsed = time.monotonic() - t0
                chunk: List[bytes] = []
                for kind in NON_ALERT_KINDS:
                    target = int(elapsed * share)
                    while self.written[kind] < target:
                        chunk.append(_line(kind, self.written[kind]))
                        self.written[kind] += 1
                if chunk:
                    data = memoryview(b"".join(chunk))
                    while data:
                        n = os.write(fd, data)
                        data = data[n:]
                    self.written_bytes += sum(len(c) for c in chunk)
                if chunk or stopping:
                    # After the stop was asked for, one last batch up to that
                    # instant: the window then ends after every sample taken
                    # under the load.
                    self.window["window_end_monotonic_ns"] = time.monotonic_ns()
                    self.window["window_end_boottime_ns"] = _boottime_ns()
                if stopping:
                    break
                self.stop.wait(0.01)
        except OSError as exc:
            self.error = f"{exc.__class__.__name__}"
        finally:
            os.close(fd)


def read_audit(work: Path) -> Tuple[List[Dict[str, Any]], bool]:
    from .so04_hostile_load import read_audit as _read

    return _read(work)


@contextmanager
def applied(
    eve: Path, work: Path, factor: float, quota: Mapping[str, Any], out: Dict[str, Any],
    *, core_started: bool, core_alive: Callable[[], bool],
) -> Iterator[QuotaLoad]:
    """Offer ``factor`` x the quota to the core reading ``eve`` for the body of the block.

    Waits ``WARMUP_MS`` before the body, and after it one audit interval for
    the core's last summary; ``out`` then holds the observation, with whether
    the core had started and was still running at that point.
    """

    load = QuotaLoad(eve, float(quota["value"]) * factor)
    load.start()
    try:
        load.stop.wait(WARMUP_MS / 1000.0)
        yield load
    finally:
        load.stop.set()
        load.join(timeout=10)
        time.sleep(int(quota["audit_interval_ms"]) / 1000.0 + 0.5)
        out.update(observation(load, work, factor, core_started=core_started, core_alive_at_load_end=bool(core_alive())))


def observation(
    load: Optional[QuotaLoad], work: Path, factor: float, *, core_started: bool = False, core_alive_at_load_end: bool = False,
) -> Dict[str, Any]:
    """The part's ``quota_load`` block: what was offered, and what the core recorded."""

    decl = load_ingress_quotas()
    quota = decl["quotas"].get(SO11_INGRESS) or {}
    audit, rotated = read_audit(work)
    window = dict(load.window) if load is not None else {}
    return {
        "core_started": bool(core_started),
        "core_alive_at_load_end": bool(core_alive_at_load_end),
        # What the harness read from the core's audit file, kept beside the
        # summaries so a summary removed from or added to the list shows.
        "ingress_audit_records_read": len(audit),
        "ingress": SO11_INGRESS,
        "quota_path": decl["path"],
        "quota_sha256": decl["sha256"],
        "quota_value": quota.get("value"),
        "quota_status": quota.get("status"),
        "quota_hardware_class": quota.get("hardware_class"),
        "load_factor": factor,
        "offered_non_alert_lines_per_s": float(quota["value"]) * factor if quota.get("value") else None,
        "non_alert_kinds": list(NON_ALERT_KINDS),
        "line_bytes": LINE_BYTES,
        "warmup_ms": WARMUP_MS,
        "window_start_monotonic_ns": window.get("window_start_monotonic_ns"),
        "window_end_monotonic_ns": window.get("window_end_monotonic_ns"),
        "window_start_boottime_ns": window.get("window_start_boottime_ns"),
        "window_end_boottime_ns": window.get("window_end_boottime_ns"),
        "written": dict(load.written) if load is not None else {},
        "written_bytes": load.written_bytes if load is not None else 0,
        "writer_error": load.error if load is not None else "no load was started",
        "ingress_audit": audit,
        "ingress_audit_rotated": rotated,
    }


# ------------------------------------------------------------- recomputation


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _offered_problems(samples: Sequence[Mapping[str, Any]], obs: Mapping[str, Any], factor: float, quota: Mapping[str, Any], decl: Mapping[str, Any]) -> List[str]:
    problems: List[str] = []
    if obs.get("ingress") != SO11_INGRESS:
        problems.append(f"ingress is not {SO11_INGRESS}")
    if obs.get("quota_path") != decl.get("path") or obs.get("quota_sha256") != decl.get("sha256"):
        problems.append(f"does not cite {decl.get('path')} at its current sha256")
    if obs.get("load_factor") != factor:
        problems.append(f"load_factor {obs.get('load_factor')!r} is not the part's {factor}")
    if obs.get("warmup_ms") != WARMUP_MS:
        problems.append(f"warmup_ms is not {WARMUP_MS}")
    if obs.get("writer_error"):
        problems.append(f"writer error {obs.get('writer_error')}")
    rate = float(quota["value"]) * factor
    start, end = obs.get("window_start_monotonic_ns"), obs.get("window_end_monotonic_ns")
    if not (_int(start) and _int(end) and end - start > WARMUP_MS * 1_000_000):
        problems.append("load window missing or not longer than the warm-up")
        return problems
    seconds = (end - start) / 1e9
    written = obs.get("written") if isinstance(obs.get("written"), dict) else {}
    if sorted(written) != sorted(NON_ALERT_KINDS):
        problems.append(f"written classes {sorted(written)} are not {sorted(NON_ALERT_KINDS)}")
    share = rate / len(NON_ALERT_KINDS)
    for kind in NON_ALERT_KINDS:
        n = written.get(kind)
        if not _int(n) or abs(n / seconds - share) > RATE_TOLERANCE * share:
            problems.append(f"{kind} written at {n!r} lines in {seconds:.2f} s, not {share:.0f}/s within {RATE_TOLERANCE:.0%}")
    warm = WARMUP_MS * 1_000_000
    boot_start, boot_end = obs.get("window_start_boottime_ns"), obs.get("window_end_boottime_ns")
    outside = 0
    for s in samples:
        if s.get("sample_clock") == "CLOCK_BOOTTIME":
            lo, hi = boot_start, boot_end
        else:
            lo, hi = start, end
        s_start, s_end = s.get("start_monotonic_ns"), s.get("end_monotonic_ns")
        if not (_int(lo) and _int(hi) and _int(s_start)) or s_start < lo + warm or (_int(s_end) and s_end > hi):
            outside += 1
    if outside or not samples:
        problems.append(f"{outside}/{len(samples)} samples not inside the load window after the warm-up")
    return problems


def quota_load_problems(samples: Sequence[Mapping[str, Any]], quota_load: Any, factor: float) -> Dict[str, List[str]]:
    """What is wrong, per SO-11 load prerequisite, recomputed from the part only.

    The quota is read from the tree, never from the observation. An empty
    list means the prerequisite holds.
    """

    from .so04_hostile_load import _audit_problems

    decl = load_ingress_quotas()
    quota = decl["quotas"].get(SO11_INGRESS)
    ids = ("core_ran_through_load", "ingress_load_offered_at_level", "core_ingress_audit_consistent", "alerts_never_shed")
    if factor > 1.0:
        ids += (SO11_OVERLOAD_PREREQUISITE,)
    if quota is None:
        return {i: [f"no valid {SO11_INGRESS} quota declared: {decl.get('problems')}"] for i in ids}
    if not isinstance(quota_load, dict):
        return {i: ["no quota_load observation"] for i in ids}
    out: Dict[str, List[str]] = {i: [] for i in ids}
    if quota_load.get("core_started") is not True:
        out["core_ran_through_load"].append("the core did not start before the load")
    if quota_load.get("core_alive_at_load_end") is not True:
        out["core_ran_through_load"].append("the core was not running when the load ended")
    out["ingress_load_offered_at_level"] = _offered_problems(list(samples), quota_load, factor, quota, decl)
    audit = quota_load.get("ingress_audit")
    if not isinstance(audit, list):
        audit = []
        out["core_ingress_audit_consistent"].append("ingress_audit is not a list")
    if quota_load.get("ingress_audit_records_read") != len(audit):
        out["core_ingress_audit_consistent"].append(
            f"ingress_audit holds {len(audit)} record(s); the harness read {quota_load.get('ingress_audit_records_read')!r}"
        )
    shed, problems = _audit_problems(audit, quota)
    written = quota_load.get("written") if isinstance(quota_load.get("written"), dict) else {}
    written_total = sum(v for v in written.values() if _int(v))
    examined = sum(int(r["examined"]) - int(r["alerts_admitted"]) for r in shed)
    if shed and examined > written_total:
        out["core_ingress_audit_consistent"].append(f"the core counts {examined} non-alert lines examined; only {written_total} were written")
    if factor > 1.0 and shed and examined < (1.0 - EXAMINED_TOLERANCE) * written_total:
        out["core_ingress_audit_consistent"].append(
            f"the core counts {examined} non-alert lines examined of {written_total} written (under {1.0 - EXAMINED_TOLERANCE:.0%})"
        )
    out["alerts_never_shed"] = [p for p in problems if "alerts_shed" in p]
    out["alerts_never_shed"] += [
        f"ingress_shed shed_by_type.alert is {r.get('shed_by_type', {}).get('alert')!r}"
        for r in shed
        if isinstance(r.get("shed_by_type"), dict) and r["shed_by_type"].get("alert", 0) != 0
    ]
    out["core_ingress_audit_consistent"] += [p for p in problems if "alerts_shed" not in p]
    if quota_load.get("ingress_audit_rotated"):
        out["core_ingress_audit_consistent"].append("the ingress audit was rotated during the run")
    if factor > 1.0:
        total = sum(int(r["shed_total"]) for r in shed)
        rate_shed = sum(int((r.get("shed_by_reason") or {}).get("non_alert_rate", 0) or 0) for r in shed)
        if total <= 0 or rate_shed <= 0:
            out[SO11_OVERLOAD_PREREQUISITE].append(f"the core recorded {total} lines shed ({rate_shed} for the rate) at {factor:.0%} of the quota")
    return out


def quota_load_prerequisites(samples: Sequence[Mapping[str, Any]], quota_load: Any, factor: float) -> Dict[str, bool]:
    return {k: not v for k, v in quota_load_problems(samples, quota_load, factor).items()}


def strip_boot_ids(sample: Mapping[str, Any]) -> Dict[str, Any]:
    """An SO-04 sample without boot ids: whether lease and start record share a boot instead."""

    row = {k: v for k, v in sample.items() if k not in _BOOT_ID_FIELDS}
    lease_boot = sample.get("lease_boot_id")
    row["same_boot_as_lease"] = bool(isinstance(lease_boot, str) and lease_boot and sample.get("start_record_boot_id") == lease_boot)
    return row


# --------------------------------------------------------- the referenced rows


def _core_version(core: Path) -> Optional[str]:
    from .so04_lease_rollback import _version

    return _version(core) if core.is_file() and os.access(core, os.X_OK) else None


def _so03(core: Path, factor: float, quota: Mapping[str, Any], seed: Optional[int], samples: Optional[int] = None) -> Dict[str, Any]:
    from . import so03_alert_queue

    obs: Dict[str, Any] = {}

    def during_core(work: Path, eve: Path, alive: Callable[[], bool]):  # type: ignore[no-untyped-def]
        # Entered only once the core has started (so03_alert_queue._run_core).
        return applied(eve, work, factor, quota, obs, core_started=True, core_alive=alive)

    kwargs: Dict[str, Any] = {"core_bin": core, "seed": seed, "during_core": during_core}
    if samples is not None:
        kwargs["samples"] = samples
    record = so03_alert_queue.run(**kwargs)
    part = record["parts"][0]
    return {"samples": part["samples"], "prerequisites": part["prerequisites"], "quota_load": obs or observation(None, Path("/nonexistent"), factor), "notes": record.get("notes", [])[:2]}


def _standalone_core(core: Path, work: Path) -> Tuple[subprocess.Popen, Path, Any]:
    eve = work / "eve.json"
    eve.write_bytes(b"")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AZAZEL_")}
    env.update({
        "AZAZEL_EVE_PATH": str(eve),
        "AZAZEL_NORMALIZED_EVENT_LOG": str(work / "normalized-events.jsonl"),
        "AZAZEL_FORWARD_AI": "false",
        "AZAZEL_EVENT_STDOUT": "off",
        "AZAZEL_DEFENSE_RELEASE_LEDGER": str(work / "release-ledger.json"),
        "AZAZEL_REDIRECT_POLICY_PATH": str(REPO_ROOT / "config" / "redirect_policy.yaml"),
    })
    err = (work / "core.stderr").open("w", encoding="utf-8")
    proc = subprocess.Popen([str(core)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err)
    return proc, eve, err


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


def _wait_started(proc: subprocess.Popen, stderr_path: Path) -> bool:
    deadline = time.monotonic() + START_WAIT_S
    while time.monotonic() < deadline and proc.poll() is None:
        if "azazel-edge-core started" in stderr_path.read_text(encoding="utf-8", errors="replace"):
            return True
        time.sleep(0.05)
    return False


def _so07(core: Path, factor: float, quota: Mapping[str, Any], seed: Optional[int], kinds: Optional[List[str]] = None) -> Dict[str, Any]:
    from . import so07_audit_ordering

    obs: Dict[str, Any] = {}
    started = False
    rows: List[Dict[str, Any]] = []
    prereqs: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="so11-so07-") as tmp:
        work = Path(tmp)
        proc, eve, err = _standalone_core(core, work)
        try:
            started = _wait_started(proc, work / "core.stderr")
            if started:
                with applied(eve, work, factor, quota, obs, core_started=True, core_alive=lambda: proc.poll() is None):
                    record = so07_audit_ordering.run(seed=seed, kinds=kinds)
                part = record["parts"][0]
                rows, prereqs = part["samples"], part["prerequisites"]
            started = started and proc.poll() is None
        finally:
            _stop(proc)
            err.close()
    if not started:
        obs = obs or observation(None, Path("/nonexistent"), factor)
    return {"samples": rows, "prerequisites": prereqs, "quota_load": obs, "core_started": started}


def _so04_start(core: Path, factor: float, quota: Mapping[str, Any], seed: Optional[int], leases_per_type: int = SO04_LEASES_PER_TYPE) -> Dict[str, Any]:
    """The SO-04 start half under the level's load, with the SO-04 harness's own lease, tail and sample code."""

    from . import so04_lease_rollback as so04

    rng = random.Random(seed)
    obs: Dict[str, Any] = {}
    prereqs: List[Dict[str, Any]] = []
    samples: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="so11-so04-") as tmp:
        work = Path(tmp)
        ledger = work / "release-ledger.json"
        events = work / "normalized-events.jsonl"
        eve = work / "eve.json"
        eve.write_bytes(b"")
        offset0 = time.time_ns() - time.monotonic_ns()
        created = time.time()
        created_boot = so04.boottime_ns()
        this_boot = so04.boot_id()
        monotonic = created_boot is not None and bool(this_boot)
        leases: List[Dict[str, Any]] = []
        order = [(a, i) for i in range(leases_per_type) for a in so04.ACTION_TYPES]
        for j, (action, index) in enumerate(order):
            due = created + SO04_FIRST_DUE_AFTER_S + j * SO04_LEASE_SPACING_S + rng.uniform(0.0, SO04_LEASE_JITTER_S)
            if monotonic:
                lease = so04.make_lease(action, index, created, due, due_boottime_ns=created_boot + round((due - created) * 1e9), due_boot_id=this_boot)
            else:
                lease = so04.make_lease(action, index, created, due)
            lease["_phase"] = f"so11 non-alert load at {factor:.0%} of the {SO11_INGRESS} quota"
            leases.append(lease)
        ledger.write_text(json.dumps({
            "schema_version": so04.LEDGER_SCHEMA,
            "tasks": [{k: v for k, v in l.items() if not k.startswith("_")} for l in leases],
        }), encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith("AZAZEL_")}
        env.update({
            "AZAZEL_EVE_PATH": str(eve),
            "AZAZEL_FORWARD_AI": "false",
            "AZAZEL_NORMALIZED_EVENT_LOG": str(events),
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(ledger),
            "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_REDIRECT_POLICY_PATH": str(REPO_ROOT / "config" / "redirect_policy.yaml"),
        })
        chain = so04.rollback_audit_path(ledger)
        tail = so04._Tail(events, chain, {l["task_id"] for l in leases})
        tail.start()
        stderr_path = work / "core.stderr"
        with stderr_path.open("w", encoding="utf-8") as err_fh:
            proc = subprocess.Popen([str(core)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err_fh)
            try:
                # The load starts once the core has started, as for SO-03 and SO-07.
                core_started = _wait_started(proc, stderr_path)
                with applied(eve, work, factor, quota, obs, core_started=core_started, core_alive=lambda: proc.poll() is None):
                    deadline = max(l["due_epoch"] for l in leases) + SO04_TAIL_SLACK_S
                    while time.time() < deadline and not tail.done() and proc.poll() is None:
                        time.sleep(0.01)
                tail.stop.set()
                tail.join(timeout=5)
                exited_early = proc.poll()
            finally:
                _stop(proc)
        drift_ns = (time.time_ns() - time.monotonic_ns()) - offset0
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        raw = so04.build_samples(leases, tail.starts, tail.outcomes, offset0)
        record_prereqs, offset_steps = so04.start_record_prerequisites(leases, tail.starts, raw, chain, offset0)
        samples = [strip_boot_ids(s) for s in raw]
        started = "azazel-edge-core started" in stderr_text
        early = [s["sample_id"] for s in samples if s.get("observed_before_expiry")]
        prereqs = [
            prerequisite("core_daemon_started", started, "startup line seen on stderr" + (f"; exited before the harness stopped it: {exited_early}" if exited_early is not None else "")),
            prerequisite(
                "wall_clock_stable_during_run",
                abs(drift_ns) <= so04.CLOCK_STEP_TOLERANCE_NS and not offset_steps,
                f"wall-minus-monotonic drift {drift_ns / 1e6:.3f} ms; start records off by more: {len(offset_steps)}",
            ),
            prerequisite("no_release_record_before_expiry", not early, "none" if not early else f"{len(early)} start record(s) observed before the declared expiry"),
        ] + record_prereqs
    return {"samples": samples, "prerequisites": prereqs, "quota_load": obs, "monotonic_leases": monotonic}


# ------------------------------------------------------------------ the record

_GAP_TEXT = {
    "SO11-QUOTA-PROVISIONAL": (
        "The ingress quota is provisional and container-derived (container-aarch64, not hardware). SO-11 needs each "
        "declared quota with its hardware class; a container run is not that evidence.",
        ["config/service_objectives/ingress_quota.json", "OF-06"],
    ),
    "SO11-SO04-COMPLETION-NOT-RERUN": (
        "Only the SO-04 start half is re-run under the quota load. The completion half needs owned tc/nft state and "
        "root, and its bounds are provisional (SO04-COMPLETION-BOUND-PROVISIONAL).",
        ["config/service_objectives/rollback_completion_bounds.json", "OF-05"],
    ),
    "SO04-LEASE-EXPIRY-ON-WALL-CLOCK": (
        "Not every sample shows its lease expiring on its monotonic deadline in the boot the lease was written in.",
        ["rust/azazel-edge-core/src/release.rs (lease_expiry)"],
    ),
    "SO03-NO-VISUAL-VOICE-QUEUE": ("Not every sample ended on a durable P0AlertQueue enqueue on both channels.", ["py/azazel_edge/notify/p0_alert.py"]),
    "SO03-NO-P0-ALERT-PATH": ("Not every sample's alert was built from its audit-chain decision record and classified P0.", ["py/azazel_edge/notify/p0_alert.py"]),
    "SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS": ("Not every sample's alert came from a Rust core decision relayed by the AI agent service.", ["Edge#412"]),
}


def _detail(problems: Sequence[str], ok: str) -> str:
    return ok if not problems else "; ".join(list(problems)[:6]) + (f" (+{len(problems) - 6} more)" if len(problems) > 6 else "")


def build_so11_part(name: str, taken: Mapping[str, Any]) -> Dict[str, Any]:
    """One SO-11 part from a referenced row's run under the level's load."""

    spec = spec_for(OBJECTIVE_ID, name)
    factor = float(spec["load_factor"])
    samples = list(taken.get("samples") or [])
    obs = taken.get("quota_load") or {}
    by_id = {p.get("id"): p for p in taken.get("prerequisites") or [] if isinstance(p, dict)}
    load = quota_load_problems(samples, obs, factor)
    prereqs: List[Dict[str, Any]] = []
    for pid in spec["prerequisites"]:
        if pid in load:
            prereqs.append(prerequisite(pid, not load[pid], _detail(load[pid], f"recomputed from quota_load at {factor:.0%} of the quota")))
        elif pid == "core_binary_present":
            prereqs.append(prerequisite(pid, bool(taken.get("core_version")), f"version {taken.get('core_version')}"))
        elif pid in by_id:
            p = by_id[pid]
            prereqs.append(prerequisite(pid, bool(p.get("met")), str(p.get("detail", ""))))
        else:
            prereqs.append(prerequisite(pid, False, "not evaluated: the referenced row did not run"))
    part_view = {"quota_load": obs}
    gaps = []
    for gid in spec["gaps"]:
        if gid in spec.get("gaps_closed_by_samples", ()) and samples and gap_closed(OBJECTIVE_ID, gid, samples, part_view):
            continue
        summary, refs = _GAP_TEXT.get(gid, ("", []))
        gaps.append(gap(gid, summary or gid, refs=refs))
    ref_obj, ref_part = spec["references"]
    ref_spec = spec_for(ref_obj, ref_part)
    rule: Dict[str, Any] = {
        "kind": spec["kind"],
        "description": f"the {ref_obj} {ref_part} pass rule, unchanged, with non-alert lines offered at {factor:.0%} of the declared quota",
    }
    if spec["bound_ms"] is not None:
        rule["bound_ms"] = spec["bound_ms"]
    return build_part(
        name=name,
        pass_rule=rule,
        required_samples=ref_spec["required_samples"],
        samples=samples,
        prerequisites=prereqs,
        gaps=gaps,
        per_action_required=spec.get("per_action_samples", 0),
        quota_load=obs,
    )


def _drivers() -> Dict[str, Callable[..., Dict[str, Any]]]:
    return {"SO-03": _so03, "SO-04": _so04_start, "SO-07": _so07}


def run(*, core_bin: Optional[Path] = None, seed: Optional[int] = None) -> Dict[str, Any]:
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    core = Path(core_bin or os.environ.get("AZAZEL_EDGE_CORE_BIN") or DEFAULT_CORE_BIN).resolve()
    version = _core_version(core)
    decl = load_ingress_quotas()
    quota = decl["quotas"].get(SO11_INGRESS)
    from .record import OBJECTIVE_SPECS

    parts: List[Dict[str, Any]] = []
    drivers = _drivers()
    for name, spec in OBJECTIVE_SPECS[OBJECTIVE_ID].items():
        taken: Dict[str, Any] = {"core_version": version}
        if version is not None and quota is not None:
            taken.update(drivers[spec["references"][0]](core, float(spec["load_factor"]), quota, seed))
        parts.append(build_so11_part(name, taken))
    record = build_record(
        objective_id=OBJECTIVE_ID,
        title=TITLE,
        started_monotonic_ns=started_ns,
        started_at=started_at,
        product_configuration={
            "product": "azazel-edge",
            "row_class": "virtual-lab",
            "hardware_evidence": False,
            "core_binary": core.name,
            "core_version": version,
            "ingress_quota": {
                "ingress": SO11_INGRESS,
                "path": decl["path"],
                "sha256": decl["sha256"],
                "value": (quota or {}).get("value"),
                "unit": (quota or {}).get("unit"),
                "status": (quota or {}).get("status"),
                "hardware_class": (quota or {}).get("hardware_class"),
                "problems": decl["problems"],
            },
            "levels": [{"name": n, "non_alert_factor": f} for n, f in SO11_LEVELS],
            "load": f"non-alert EVE lines ({', '.join(NON_ALERT_KINDS)} in equal parts, about {LINE_BYTES} bytes) appended to the core's EVE file; warm-up {WARMUP_MS} ms before the first sample",
            "enforcement": "Edge defaults for every core started here: enforcement off, dry run on; the harness never applies enforcement",
            "referenced_rows": {n: "/".join(s["references"]) for n, s in OBJECTIVE_SPECS[OBJECTIVE_ID].items()},
            "interface_identity": "not_applicable: no interface is involved",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "note": "SO-03 and SO-07 parts on the harness CLOCK_MONOTONIC; SO-04 parts on CLOCK_BOOTTIME (each sample's sample_clock). The load window is stamped on both.",
        },
        sample_rule={
            "parts": {n: spec_for(*s["references"])["required_samples"] for n, s in OBJECTIVE_SPECS[OBJECTIVE_ID].items()},
            "levels": [n for n, _ in SO11_LEVELS],
        },
        parts=parts,
        method="real azazel-edge-core binary; SO-03 and SO-07 through their own harnesses, the SO-04 start half with the SO-04 harness's lease/tail/sample code; non-alert load at 100% and 120% of the declared ingress quota written into the core's EVE input; the core's ingress audit read from outside",
        notes=[
            "Container or VM numbers are not hardware evidence. The quota is provisional (SO11-QUOTA-PROVISIONAL), so this record is never gate evidence.",
            "The load replaces the SO-04 hostile-load profile in the SO-04 parts; the profile's own phases are SO-04's record, not this one.",
            "No address, MAC, boot id or host name is recorded: SO-04 samples carry same_boot_as_lease instead of boot ids.",
        ],
    )
    record["run"]["host"] = "not recorded"
    return record


__all__ = [
    "QuotaLoad",
    "applied",
    "build_so11_part",
    "observation",
    "quota_load_prerequisites",
    "quota_load_problems",
    "run",
    "strip_boot_ids",
]
