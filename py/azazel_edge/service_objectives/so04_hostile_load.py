"""SO-04 hostile load: the declared profile, applied to the real core, and its recomputation.

The SO-04 sample rule asks for leases expiring under hostile load. Edge
declares that load in ``config/service_objectives/hostile_load_profile.json``
(``declarations.load_hostile_load_profile``): each phase's rates are derived
from the OF-06 ingress quota, which the Rust core enforces (Edge#412: the core
is the enforcement authority, so the load is offered to it, through its EVE
input).

Two halves live here:

* **the driver** (``HostileLoad``, ``schedule``, ``AlertCounter``,
  ``observation``): the harness writes each phase's lines into the core's EVE
  file at the declared rates during the phase's window, schedules some leases
  to expire inside each window, counts the alerts the core decided per phase,
  and keeps the core's own ``ingress-audit.jsonl`` summaries;
* **the recomputation** (``hostile_load_problems``): what the validator
  (``record.PART_GAP_CLOSERS``) runs before ``SO04-HOSTILE-LOAD-UNDECLARED``
  may be left out of a part. It re-reads the profile from the tree and checks,
  from the part's observation and samples only, that every phase was applied as
  declared: lines written at the declared rate per class, the core's shed
  summaries showing it shed over-quota non-alert lines, skipped every oversized
  line and never shed an alert, every alert written decided, the core running
  the declared quota, and every hostile sample's lease expiring inside its
  phase's window after the warm-up.

Nothing here changes how the core reads, sheds or decides; the core never reads
the profile. The numbers are container numbers, not hardware evidence.
"""

from __future__ import annotations

import json
import math
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from .declarations import (
    CONFIRMED,
    HOSTILE_LINE_CLASSES,
    ROLLBACK_ACTION_TYPES,
    load_hostile_load_profile,
)

NOMINAL = "nominal"
CLOCK = "CLOCK_BOOTTIME"
LEASE_SPACING_S = 0.1
LEASE_JITTER_S = 0.05
# Leases of a phase start expiring this long after the warm-up ends, so a
# driver that starts a window a little late still has the bucket empty.
WINDOW_MARGIN_S = 0.5
ALERT_SID_BASE = 2_100_000
ALERT_SID_PHASE_STRIDE = 1000
ALERT_SID_VARIANTS = 50
AUDIT_FILE = "ingress-audit.jsonl"
_QUOTA_BLOCK_KEYS = {
    "non_alert_per_sec": "value",
    "non_alert_burst": "non_alert_burst",
    "alerts_per_poll": "alerts_per_poll",
    "examine_per_poll": "examine_per_poll",
    "poll_work_limit_ms": "poll_work_limit_ms",
    "max_line_bytes": "max_line_bytes",
    "backlog_bound_bytes": "backlog_bound_bytes",
    "alert_backlog_bound_bytes": "alert_backlog_bound_bytes",
}
_NON_ALERT_COUNTED = ("flow", "dns", "stats", "http", "invalid_utf8")


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


# ------------------------------------------------------------- recomputation


def _audit_problems(audit: Sequence[Any], quota: Mapping[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The core's ``ingress_shed`` summaries, and what is wrong with the audit as a whole."""

    problems: List[str] = []
    shed: List[Dict[str, Any]] = []
    for idx, rec in enumerate(audit):
        inner = None
        if isinstance(rec, dict):
            inner = rec.get("ingress_shed") if isinstance(rec.get("ingress_shed"), dict) else rec.get("ingress_alert_backlog")
        if not isinstance(inner, dict):
            problems.append(f"ingress_audit[{idx}]: not an ingress_shed or ingress_alert_backlog summary")
            continue
        if inner.get("alerts_shed") != 0:
            problems.append(f"ingress_audit[{idx}]: alerts_shed is {inner.get('alerts_shed')!r}")
        block = inner.get("quota")
        if not isinstance(block, dict) or any(block.get(k) != quota.get(q) for k, q in _QUOTA_BLOCK_KEYS.items()):
            problems.append(f"ingress_audit[{idx}]: the core's quota block differs from the declared quota")
        if isinstance(rec.get("ingress_shed"), dict):
            fields = ("emitted_epoch", "shed_total", "oversized_lines_skipped", "oversized_possible_alerts", "cumulative_shed_total", "cumulative_oversized_lines_skipped")
            if not all(_num(inner.get(k)) for k in fields) or not _int(inner.get("shed_total")):
                problems.append(f"ingress_audit[{idx}]: ingress_shed summary lacks its counts")
                continue
            if inner.get("oversized_possible_alerts") != 0:
                problems.append(f"ingress_audit[{idx}]: oversized_possible_alerts is {inner.get('oversized_possible_alerts')!r}; the profile writes no oversized alert")
            shed.append(inner)
    # Cumulative totals: a summary missing from the audit shows as a jump.
    if shed:
        last = shed[-1]
        if last.get("cumulative_shed_total") != sum(int(r["shed_total"]) for r in shed):
            problems.append("ingress_audit: shed_total summed over the summaries differs from the core's cumulative_shed_total")
        if last.get("cumulative_oversized_lines_skipped") != sum(int(r["oversized_lines_skipped"]) for r in shed):
            problems.append("ingress_audit: oversized_lines_skipped summed differs from the core's cumulative count")
    return shed, problems


def hostile_load_problems(
    samples: Sequence[Mapping[str, Any]],
    hostile_load: Any,
    profile: Optional[Mapping[str, Any]] = None,
) -> List[str]:
    """Why these samples do not show the declared hostile load applied. Empty: they do.

    ``profile`` defaults to the tree's declaration (the validator never takes
    the record's word for it).
    """

    profile = profile if profile is not None else load_hostile_load_profile()
    if profile.get("problems") or not profile.get("phases"):
        return [f"the hostile-load profile is not valid: {profile.get('problems')}"]
    if not isinstance(hostile_load, dict):
        return ["the part carries no hostile_load observation"]
    problems: List[str] = []
    if hostile_load.get("profile_path") != profile["path"] or hostile_load.get("profile_sha256") != profile["sha256"]:
        problems.append(f"the observation does not cite {profile['path']} at sha256 {profile['sha256']}")
    if hostile_load.get("quota_path") != profile["quota_path"] or hostile_load.get("quota_sha256") != profile["quota_sha256"]:
        problems.append(f"the observation does not cite {profile['quota_path']} at sha256 {profile['quota_sha256']}")
    if hostile_load.get("clock") != CLOCK:
        problems.append(f"the load windows are not on {CLOCK}")
    if hostile_load.get("ingress_audit_rotated") is not False:
        problems.append("the core's ingress audit was rotated or not read whole")
    quota = profile["quota"]
    audit = hostile_load.get("ingress_audit")
    shed, audit_problems = _audit_problems(audit if isinstance(audit, list) else [None], quota)
    problems += audit_problems
    observed = {p.get("name"): p for p in hostile_load.get("phases") or [] if isinstance(p, dict)}
    tol = float(profile["rate_tolerance"])
    shed_tol = float(profile["shed_tolerance"])
    warmup_ns = int(profile["warmup_ms"]) * 1_000_000
    slack_s = int(profile["audit_attribution_slack_ms"]) / 1000.0
    windows: Dict[str, Tuple[int, int]] = {}
    for decl in profile["phases"]:
        name = decl["name"]
        obs = observed.get(name)
        where = f"phase {name}"
        if obs is None:
            problems.append(f"{where}: not applied (no observation)")
            continue
        ws, we = obs.get("window_start_boottime_ns"), obs.get("window_end_boottime_ns")
        wws, wwe = obs.get("window_start_wall_epoch"), obs.get("window_end_wall_epoch")
        written = obs.get("written")
        if not (_int(ws) and _int(we) and _num(wws) and _num(wwe) and we > ws and wwe >= wws and isinstance(written, dict)):
            problems.append(f"{where}: window or written counts malformed")
            continue
        windows[name] = (ws, we)
        duration = (we - ws) / 1e9
        if duration * 1000 < int(profile["warmup_ms"]):
            problems.append(f"{where}: applied for {duration:.3f} s, shorter than the warm-up")
        counts: Dict[str, int] = {}
        for cls in HOSTILE_LINE_CLASSES:
            n = written.get(cls)
            if not _int(n) or n < 0:
                problems.append(f"{where}: written.{cls} missing")
                n = 0
            counts[cls] = n
            want = float(decl["rates_per_s"][cls]) * duration
            if abs(n - want) > max(1.0, tol * want):
                problems.append(f"{where}: {n} {cls} lines in {duration:.3f} s, declared {decl['rates_per_s'][cls]}/s (+/-{tol:.0%})")
        if obs.get("alerts_decided") != counts["alert"]:
            problems.append(f"{where}: {counts['alert']} alerts written, {obs.get('alerts_decided')!r} decided by the core")
        mine = [r for r in shed if wws <= float(r["emitted_epoch"]) <= wwe + slack_s]
        if decl["non_alert_lines_per_s"] > quota["value"]:
            non_alert = sum(counts[c] for c in _NON_ALERT_COUNTED)
            # The excess no bucket could admit over the window, and the floor
            # the core's shedding must reach (profile rule "shed").
            excess = non_alert - (quota["value"] * duration + quota["non_alert_burst"])
            floor = max(1, math.ceil((1.0 - shed_tol) * excess))
            got = sum(int(r["shed_total"]) for r in mine)
            by_rate = sum(int((r.get("shed_by_reason") or {}).get("non_alert_rate") or 0) for r in mine)
            admitted = sum(int(r.get("admitted") or 0) - int(r.get("alerts_admitted") or 0) for r in mine)
            ceiling = quota["value"] * (duration + slack_s) + quota["non_alert_burst"]
            if excess <= 0 or got < floor or by_rate < 1:
                problems.append(
                    f"{where}: the core's summaries show {got} non-alert lines shed ({by_rate} for the rate) of {non_alert} "
                    f"written; the excess over the {quota['value']}/s quota is {excess:.0f}, so at least {floor} expected"
                )
            if admitted > ceiling:
                problems.append(f"{where}: the core admitted {admitted} non-alert lines, above the quota's {ceiling:.0f}")
            if decl.get("backlog_phase"):
                by_backlog = sum(int((r.get("shed_by_reason") or {}).get("backlog") or 0) for r in mine)
                level = max((int(r.get("max_shed_level") or 0) for r in mine), default=0)
                if by_backlog < 1 or level < 1:
                    problems.append(
                        f"{where}: a backlog phase, but the core's summaries show {by_backlog} lines shed for the backlog "
                        f"at shed level {level}; its backlog shedding did not act"
                    )
        skipped = sum(int(r["oversized_lines_skipped"]) for r in mine)
        if skipped != counts["oversized"]:
            problems.append(f"{where}: {counts['oversized']} oversized lines written, the core's summaries count {skipped} skipped")
    per_phase: Dict[Tuple[str, str], int] = {}
    hostile_n = 0
    for idx, s in enumerate(samples):
        cond = s.get("condition") if isinstance(s, dict) else None
        load = cond.get("load") if isinstance(cond, dict) else None
        if load == NOMINAL:
            continue
        if load not in observed and load not in {p["name"] for p in profile["phases"]}:
            problems.append(f"sample {idx}: load {load!r} is neither nominal nor a declared phase")
            continue
        per_phase[(load, s.get("action_type"))] = per_phase.get((load, s.get("action_type")), 0) + 1
        hostile_n += 1
        if load not in windows:
            continue
        ws, we = windows[load]
        start = s.get("start_monotonic_ns")
        if s.get("sample_clock") != CLOCK or not _int(start) or not (ws + warmup_ns <= start <= we):
            problems.append(f"sample {s.get('sample_id')}: its lease did not expire inside the {load} window after the warm-up")
    need = int(profile["leases_per_phase_per_action"])
    for decl in profile["phases"]:
        for action in ROLLBACK_ACTION_TYPES:
            n = per_phase.get((decl["name"], action), 0)
            if n < need:
                problems.append(f"phase {decl['name']}: {n} {action} leases expired under it, at least {need} declared")
    share = float(profile["min_hostile_share"])
    if not samples or hostile_n < share * len(samples):
        problems.append(f"{hostile_n} of {len(samples)} samples under a declared phase, below the declared share {share:.0%}")
    return problems


def hostile_load_applied(samples: Sequence[Mapping[str, Any]], hostile_load: Any) -> bool:
    """Closes ``SO04-HOSTILE-LOAD-UNDECLARED`` (see ``hostile_load_problems``)."""

    items = list(samples)
    return bool(items) and all(isinstance(s, dict) for s in items) and not hostile_load_problems(items, hostile_load)


def profile_confirmed_problems(hostile_load: Any, profile: Optional[Mapping[str, Any]] = None) -> List[str]:
    """Why ``SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL`` stays. Empty: it may be left out.

    As for the completion bounds, the declaration is read from the tree, never
    from the record: the profile must be valid, declare status ``confirmed``
    (with its owner defaults no longer pending), and be the very file the
    record's load was taken against (same path and SHA-256).
    """

    profile = profile if profile is not None else load_hostile_load_profile()
    if profile.get("problems") or not profile.get("phases"):
        return [f"the hostile-load profile is not valid: {profile.get('problems')}"]
    problems = []
    if profile.get("status") != CONFIRMED:
        problems.append(f"{profile['path']} has status {profile.get('status')!r}; its factors await the owner's confirmation")
    if not isinstance(hostile_load, dict) or hostile_load.get("profile_path") != profile["path"] or hostile_load.get("profile_sha256") != profile["sha256"]:
        problems.append(f"the part's load was not taken against {profile['path']} at sha256 {profile['sha256']}")
    return problems


def profile_confirmed(samples: Sequence[Mapping[str, Any]], hostile_load: Any) -> bool:
    """Closes ``SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL`` (see ``profile_confirmed_problems``)."""

    return bool(list(samples)) and not profile_confirmed_problems(hostile_load)


# -------------------------------------------------------------------- driver


def plan(leases_per_type: int, profile: Mapping[str, Any]) -> List[Tuple[str, int, str]]:
    """(action, index, condition) per lease: nominal first, then each phase in order.

    Each declared phase gets the profile's ``leases_per_phase_per_action``
    leases per action type and nominal takes the rest (a smaller run, as in
    tests, splits evenly instead). Without a valid profile every lease is
    nominal.
    """

    names = [p["name"] for p in profile.get("phases") or []]
    per_phase = 0
    if names:
        per_phase = int(profile.get("leases_per_phase_per_action") or 0)
        if per_phase < 1 or per_phase * len(names) > leases_per_type:
            per_phase = max(1, leases_per_type // (len(names) + 1))
    nominal = max(0, leases_per_type - per_phase * len(names))
    out: List[Tuple[str, int, str]] = []
    index = 0
    for cond, count in [(NOMINAL, nominal)] + [(n, per_phase) for n in names]:
        for _ in range(count):
            for action in ROLLBACK_ACTION_TYPES:
                out.append((action, index, cond))
            index += 1
    return out


def schedule(
    conditions: Sequence[str], base: float, rng, profile: Mapping[str, Any]
) -> Tuple[List[float], List[Tuple[str, float, float]]]:
    """Wall-clock deadlines aligned with ``conditions``, and each phase's (name, start, end) window.

    Nominal leases expire from ``base``, ``LEASE_SPACING_S`` apart. Each phase
    then starts ``quiet_gap_ms`` after the previous one ends (or after the
    last nominal expiry), its leases expire after ``warmup_ms`` plus a margin,
    and it ends ``hold_after_ms`` after its last expiry.
    """

    dues: List[Optional[float]] = [None] * len(conditions)
    nominal = [i for i, c in enumerate(conditions) if c == NOMINAL]
    for j, i in enumerate(nominal):
        dues[i] = base + j * LEASE_SPACING_S + rng.uniform(0.0, LEASE_JITTER_S)
    cursor = base + len(nominal) * LEASE_SPACING_S
    windows: List[Tuple[str, float, float]] = []
    for phase in profile.get("phases") or []:
        mine = [i for i, c in enumerate(conditions) if c == phase["name"]]
        if not mine:
            continue
        start = cursor + profile["quiet_gap_ms"] / 1000.0
        first = start + profile["warmup_ms"] / 1000.0 + WINDOW_MARGIN_S
        for j, i in enumerate(mine):
            dues[i] = first + j * LEASE_SPACING_S + rng.uniform(0.0, LEASE_JITTER_S)
        end = max(dues[i] for i in mine) + profile["hold_after_ms"] / 1000.0
        windows.append((phase["name"], start, end))
        cursor = end
    if any(d is None for d in dues):
        raise ValueError("a lease names a condition the profile does not declare")
    return [float(d) for d in dues], windows


def alert_sid_base(phase_index: int) -> int:
    return ALERT_SID_BASE + phase_index * ALERT_SID_PHASE_STRIDE


class _Lines:
    """Line makers for one phase. Every line but an oversized one is about ``line_bytes`` long."""

    def __init__(self, phase_index: int, line_bytes: int, oversized_bytes: int):
        self.sid_base = alert_sid_base(phase_index)
        self.line_bytes = line_bytes
        self.oversized_bytes = oversized_bytes

    def _pad(self, head: str) -> bytes:
        # head ends with '"pad":"'; close the string and the object.
        fill = max(0, self.line_bytes - len(head) - 3)
        return (head + "x" * fill + '"}\n').encode("ascii")

    def make(self, cls: str, n: int) -> bytes:
        ip = f"203.0.113.{n % 250 + 1}"
        if cls == "alert":
            return self._pad(
                '{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"alert","src_ip":"%s","dest_ip":"192.0.2.10",'
                '"dest_port":22,"proto":"TCP","alert":{"signature_id":%d,"signature":"so04 hostile load","category":"load",'
                '"severity":%d},"pad":"' % (ip, self.sid_base + n % ALERT_SID_VARIANTS, 1 + n % 3)
            )
        if cls == "invalid_utf8":
            # Bytes that are not UTF-8 ahead of the object: the core decodes
            # lossily, the JSON does not parse, and the line is unparseable.
            return b"\xff\xfe\xc3(" + self._pad('{"event_type":"flow","n":%d,"pad":"' % n)
        if cls == "oversized":
            # A non-alert line longer than max_line_bytes, never an alert.
            head = b'{"event_type":"flow","n":%d,"pad":"' % n
            return head + b"y" * (self.oversized_bytes - len(head) - 3) + b'"}\n'
        return self._pad(
            '{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"%s","src_ip":"%s","dest_ip":"192.0.2.10",'
            '"dest_port":53,"proto":"UDP","%s":{"n":%d},"pad":"' % (cls, ip, cls, n)
        )


class HostileLoad(threading.Thread):
    """Writes each declared phase's lines into the EVE file during its window."""

    def __init__(self, eve: Path, profile: Mapping[str, Any], windows: Sequence[Tuple[str, float, float]], boottime: Callable[[], Optional[int]]):
        super().__init__(daemon=True)
        self.eve = eve
        self.profile = profile
        self.phases = {p["name"]: (i, p) for i, p in enumerate(profile.get("phases") or [])}
        self.windows = list(windows)
        self.boottime = boottime
        self.stop = threading.Event()
        self.observed: List[Dict[str, Any]] = []
        self.finished = threading.Event()

    def _run_window(self, fh, name: str, end_wall: float) -> None:
        index, phase = self.phases[name]
        rates = phase["rates_per_s"]
        # A burst phase writes every class once per interval, all at once.
        burst_s = int(phase.get("burst_interval_ms") or 0) / 1000.0
        lines = _Lines(index, int(self.profile["line_bytes"]), int(phase["oversized_line_bytes"]))
        written = {c: 0 for c in HOSTILE_LINE_CLASSES}
        nbytes = 0
        t0 = time.monotonic()
        start_boot, start_wall = self.boottime(), time.time()
        last_boot, last_wall = start_boot, start_wall
        while not self.stop.is_set():
            elapsed = time.monotonic() - t0
            if burst_s:
                elapsed = math.floor(elapsed / burst_s) * burst_s
            chunk: List[bytes] = []
            for cls in HOSTILE_LINE_CLASSES:
                target = int(elapsed * float(rates[cls]))
                while written[cls] < target:
                    chunk.append(lines.make(cls, written[cls]))
                    written[cls] += 1
            if chunk:
                data = b"".join(chunk)
                fh.write(data)
                fh.flush()
                nbytes += len(data)
                # The window ends at the last write, so the rate is counted
                # over the time the lines were actually written in.
                last_boot, last_wall = self.boottime(), time.time()
            if time.time() >= end_wall:
                break
            time.sleep(0.01)
        self.observed.append({
            "name": name,
            "window_start_boottime_ns": start_boot,
            "window_end_boottime_ns": last_boot,
            "window_start_wall_epoch": start_wall,
            "window_end_wall_epoch": last_wall,
            "written": written,
            "written_bytes": nbytes,
            "alert_sid_base": lines.sid_base,
            "alerts_decided": None,
        })

    def run(self) -> None:
        try:
            with self.eve.open("ab") as fh:
                for name, start, end in self.windows:
                    while not self.stop.is_set() and time.time() < start:
                        time.sleep(0.005)
                    if self.stop.is_set():
                        return
                    self._run_window(fh, name, end)
        finally:
            self.finished.set()

    def written_total(self) -> int:
        return sum(sum(o["written"].values()) for o in self.observed)


class AlertCounter:
    """Counts, per phase, the alerts the core decided (by signature id), tailing the normalized log."""

    def __init__(self, normalized: Path):
        self.path = normalized
        self.offset = 0
        self.pending = b""
        self.by_sid_base: Dict[int, int] = {}

    def poll(self) -> None:
        try:
            with self.path.open("rb") as fh:
                fh.seek(self.offset)
                chunk = fh.read()
        except FileNotFoundError:
            return
        self.offset += len(chunk)
        lines = (self.pending + chunk).split(b"\n")
        self.pending = lines.pop()
        for raw in lines:
            if b'"rust_event_engine_v1"' not in raw:
                continue
            try:
                sid = int((json.loads(raw).get("normalized") or {}).get("sid"))
            except (ValueError, TypeError, AttributeError):
                continue
            if sid < ALERT_SID_BASE:
                continue
            base = ALERT_SID_BASE + (sid - ALERT_SID_BASE) // ALERT_SID_PHASE_STRIDE * ALERT_SID_PHASE_STRIDE
            if sid - base < ALERT_SID_VARIANTS:
                self.by_sid_base[base] = self.by_sid_base.get(base, 0) + 1

    def caught_up(self, observed: Sequence[Mapping[str, Any]]) -> bool:
        self.poll()
        return all(self.by_sid_base.get(o["alert_sid_base"], 0) >= o["written"]["alert"] for o in observed)


def drain(counter: AlertCounter, load: HostileLoad, *, timeout_s: float, audit_interval_s: float, alive: Callable[[], bool]) -> None:
    """Wait (bounded) until the core has decided every alert written, then for its last shed summary."""

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and alive() and not counter.caught_up(load.observed):
        time.sleep(0.2)
    # A summary is emitted at most once per interval; let the last one out.
    end = time.monotonic() + audit_interval_s + 0.5
    while time.monotonic() < end and alive():
        time.sleep(0.05)
    counter.poll()


def read_audit(work: Path) -> Tuple[List[Dict[str, Any]], bool]:
    """The core's ingress summaries in the work directory, and whether the file was rotated."""

    path = work / AUDIT_FILE
    rotated = (work / (AUDIT_FILE + ".1")).exists()
    out: List[Dict[str, Any]] = []
    try:
        raw = path.read_bytes()
    except OSError:
        return out, rotated
    for line in raw.split(b"\n"):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and ("ingress_shed" in rec or "ingress_alert_backlog" in rec):
            out.append(rec)
    return out, rotated


def observation(profile: Mapping[str, Any], load: Optional[HostileLoad], counter: Optional[AlertCounter], work: Path, *, monotonic: bool) -> Dict[str, Any]:
    """The part's ``hostile_load`` block: what was applied and what the core recorded."""

    audit, rotated = read_audit(work)
    phases = []
    for o in (load.observed if load is not None else []):
        row = dict(o)
        row["written"] = dict(o["written"])
        row["alerts_decided"] = counter.by_sid_base.get(o["alert_sid_base"], 0) if counter is not None else None
        phases.append(row)
    return {
        "profile_path": profile.get("path"),
        "profile_sha256": profile.get("sha256"),
        "quota_path": profile.get("quota_path"),
        "quota_sha256": profile.get("quota_sha256"),
        "clock": CLOCK if monotonic else "CLOCK_MONOTONIC (no CLOCK_BOOTTIME on this host)",
        "phases": phases,
        "ingress_audit": audit,
        "ingress_audit_rotated": rotated,
    }


def phase_summary(hostile_load: Mapping[str, Any]) -> str:
    """One line per phase for prerequisite details and notes."""

    parts = []
    for o in hostile_load.get("phases") or []:
        try:
            dur = (o["window_end_boottime_ns"] - o["window_start_boottime_ns"]) / 1e9
        except (KeyError, TypeError):
            dur = float("nan")
        w = o.get("written") or {}
        parts.append(
            f"{o.get('name')}: {sum(w.values())} lines in {dur:.2f} s "
            f"({', '.join(f'{k}={v}' for k, v in w.items() if v)}), alerts decided {o.get('alerts_decided')}"
        )
    shed = [r["ingress_shed"] for r in hostile_load.get("ingress_audit") or [] if isinstance(r.get("ingress_shed"), dict)]
    total = shed[-1].get("cumulative_shed_total") if shed else 0
    over = shed[-1].get("cumulative_oversized_lines_skipped") if shed else 0
    return "; ".join(parts) + f"; core ingress audit: {len(shed)} ingress_shed summaries, {total} lines shed, {over} oversized skipped"


def check_records(paths: Sequence[Path]) -> List[str]:
    """CI: in every SO-04 record, both parts show the declared load applied
    (the validator's recomputation) and keep no gap but the declared
    provisional ones. Empty: they do. Reads only; changes no verdict."""

    allowed = {"SO04-COMPLETION-BOUND-PROVISIONAL", "SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL"}
    problems: List[str] = []
    records = [p for p in paths if p.is_file()] + [q for p in paths if p.is_dir() for q in sorted(p.glob("SO-04-*.json"))]
    if not records:
        return ["no SO-04 record found"]
    for path in records:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append(f"{path}: unreadable: {exc}")
            continue
        if record.get("objective_id") != "SO-04":
            continue
        for part in record.get("parts") or []:
            where = f"{path.name} {part.get('name')}"
            found = hostile_load_problems(part.get("samples") or [], part.get("hostile_load"))
            problems += [f"{where}: {p}" for p in found[:10]]
            extra = sorted({g.get("id") for g in part.get("gaps") or []} - allowed)
            if extra:
                problems.append(f"{where}: gaps beyond the declared provisional ones: {extra}")
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="Check SO-04 records: the declared hostile load applied, only provisional gaps left.")
    ap.add_argument("paths", nargs="+", type=Path)
    args = ap.parse_args(argv)
    problems = check_records(args.paths)
    for p in problems:
        print(p, file=sys.stderr)
    print("SO-04 hostile load: " + ("applied as declared in every part; only provisional gaps remain" if not problems else f"{len(problems)} problem(s)"))
    return 0 if not problems else 1


__all__ = [
    "check_records",
    "HostileLoad",
    "AlertCounter",
    "drain",
    "hostile_load_applied",
    "profile_confirmed",
    "profile_confirmed_problems",
    "hostile_load_problems",
    "observation",
    "phase_summary",
    "plan",
    "read_audit",
    "schedule",
]


if __name__ == "__main__":
    raise SystemExit(main())
