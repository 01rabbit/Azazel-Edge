"""SO-04: lease-expiry rollback starts (within 5 seconds of expiry).

Definition (assignment section 3, SO-04):

* start -- the lease's declared expiry instant, taken from the lease record
  itself, not the moment a sweeper noticed it;
* end -- an audit-chain record naming that lease id states that rollback has
  begun;
* clock -- the issuing node's monotonic clock;
* samples -- 50 leases per declared action type, including leases expiring
  under hostile load and while the operator plane is unavailable;
* pass -- every sample starts <= 5 seconds after expiry;
* completion -- "action-specific" (OF-05): measured by
  ``so04_rollback_completion`` against the per-action bounds Edge declares in
  ``config/service_objectives/rollback_completion_bounds.json``. Those bounds
  are provisional, so that half stays ``not_measurable``.

What is measured here
--------------------
Edge's enforcement lease is the Rust core's release task
(``rust/azazel-edge-core/src/release.rs``). It declares two deadlines:
``due_epoch`` on the wall clock and ``due_boottime_ns`` on ``CLOCK_BOOTTIME``,
tied to the boot (``due_boot_id``) it was read in. The core's sweep
(``process_due_releases_with_runner``) attempts rollback once either has passed
-- the earlier wins (section 4.3) -- and counts the monotonic deadline as
passed in another boot or when the boot cannot be checked. A lease without the
monotonic fields (written before they existed) keeps wall-clock-only expiry. Immediately before the first rollback command of each attempt, the core
appends a ``rollback_started`` record naming the lease (``release_task_id``) and
the decision (``trace_id``) to its rollback audit chain,
``<ledger dir>/<ledger stem>.rollback-audit.jsonl``, and fsyncs it. That chain
is in ``P0AuditLogger``'s format and verifies with ``verify_chain``. After the
attempt, ``process_release_events`` (``src/main.rs``) appends the attempt's
outcome, a ``rust_release_engine_v1`` record, to the normalized-event JSONL.

The harness runs the **real, unmodified core binary** as a daemon. It writes
active leases for each declared action type (``throttle``, ``isolate``,
``redirect`` -- the only ones ``build_release_task`` accepts) into the release
ledger before the daemon starts, exactly in the ledger's own schema, with both
deadlines when this host exposes ``CLOCK_BOOTTIME`` and a boot id, then tails
both files from outside. A sample's start is the lease's monotonic deadline
and its end the instant, on this host's ``CLOCK_BOOTTIME``, at which the
harness first sees the ``rollback_started`` record naming that lease in the
chain (without ``CLOCK_BOOTTIME``: the wall deadline mapped onto
``CLOCK_MONOTONIC``); when the harness then sees the lease's
outcome in the JSONL, it checks that the start record was already there. It
never enables enforcement; the daemon runs with Edge's defaults (enforcement
off, dry-run on), and its rollback commands run against no owned state.

That the record is durable *before the rollback command runs* is a property of
the core's code, not something an outside observer can see, so it is shown by
the core's own tests (``release.rs``), which stand a command runner in for
``tc``/``nft`` and look at the chain and the fsync count when it is first called.

Hostile load (``so04_hostile_load``)
-----------------------------------
Leases expire both unloaded (``nominal``) and under each phase of the
declared hostile-load profile (``config/service_objectives/hostile_load_profile.json``):
non-alert lines at 120% of the OF-06 quota, alerts at the per-poll cap, a
mix of invalid UTF-8 and oversized lines, and bursts of non-alert lines at 12
times the quota that push the core into backlog shedding. The harness writes each phase into the
core's EVE input at the declared rates for its window, and every phase lease
expires after the warm-up that empties the core's non-alert bucket. The part
carries the observation (``hostile_load``): what was written per class and
when, the alerts the core decided, and the core's own ``ingress_shed``
summaries.

Gaps
----
The observed numbers are reported, but the part cannot be gate evidence while
a gap remains:

* ``SO04-LEASE-EXPIRY-ON-WALL-CLOCK`` is reported unless **every** sample shows
  that its lease expired on its monotonic deadline: the start record says
  ``expiry_clock: monotonic``, its own ``CLOCK_BOOTTIME`` stamp is at or after
  the lease's monotonic deadline, the boot matches, and the wall deadline did
  not fire first. The validator recomputes this from the samples
  (``record.so04_monotonic_expiry_observed``); a record cannot drop the gap by
  saying so;
* ``SO04-HOSTILE-LOAD-UNDECLARED`` is reported unless the validator's
  recomputation (``record.so04_hostile_load_applied``) shows the declared
  profile applied for every sample: every phase written at its declared rate,
  the core shedding over-quota non-alert lines, skipping every oversized line,
  never shedding an alert and deciding every alert written, under the declared
  quota, with every phase sampled for every action type inside its window.

* ``SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL`` is reported until the profile in
  the tree declares status ``confirmed`` and is the file the load was taken
  against (``record.so04_hostile_load_profile_confirmed``). Its factors are
  defaults awaiting the owner's confirmation, and what is measured under it is
  container evidence, not hardware evidence.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ..audit.logger import P0AuditLogger
from . import so04_hostile_load
from .declarations import load_hostile_load_profile
from .record import (
    REPO_ROOT,
    RULE_EVERY_SAMPLE_MAX,
    build_part,
    build_record,
    gap,
    prerequisite,
    so04_monotonic_expiry_observed,
    spec_for,
    utc_now,
)

OBJECTIVE_ID = "SO-04"
TITLE = "Lease-expiry rollback starts (within 5 seconds of expiry)"
SPEC_START = spec_for("SO-04", "rollback_start_after_expiry")
SPEC_COMPLETION = spec_for("SO-04", "rollback_completion")
BOUND_MS = SPEC_START["bound_ms"]
ACTION_TYPES = ("throttle", "isolate", "redirect")
LEASES_PER_TYPE = 50
LEDGER_SCHEMA = "azazel-release-ledger/v1"
DEFAULT_CORE_BIN = REPO_ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
CLOCK_STEP_TOLERANCE_NS = 50_000_000
IFACE = "br0"
ROLLBACK_STARTED_KIND = "rollback_started"
ROLLBACK_STARTED_SCHEMA = "azazel-edge/rollback-started/v1"
_START_RECORD_INT_FIELDS = ("attempt", "lease_due_epoch_ns", "started_monotonic_ns", "started_wall_epoch_ns")
BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def boottime_ns() -> Optional[int]:
    """``CLOCK_BOOTTIME``, the clock the core declares a lease's monotonic deadline on; ``None`` where absent."""

    clock = getattr(time, "CLOCK_BOOTTIME", None)
    if clock is None:
        return None
    try:
        return time.clock_gettime_ns(clock)
    except OSError:
        return None


def boot_id() -> str:
    """This boot's id, as the core reads it; empty where the kernel does not expose one."""

    try:
        return BOOT_ID_PATH.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def rollback_audit_path(ledger: Path) -> Path:
    """Where the core writes its rollback audit chain (``release::rollback_audit_path``)."""

    return ledger.with_name(f"{ledger.stem or 'release-ledger'}.rollback-audit.jsonl")


def _fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def make_lease(
    action: str,
    index: int,
    created_epoch: float,
    due_epoch: float,
    *,
    due_boottime_ns: Optional[int] = None,
    due_boot_id: str = "",
    iface: str = IFACE,
) -> Dict[str, Any]:
    """A release task as ``build_release_task`` + ``activate_release_task`` leave it.

    Without ``due_boottime_ns`` and ``due_boot_id`` it is a legacy lease, as the
    core writes one when it cannot read ``CLOCK_BOOTTIME`` or the boot id.
    """

    trace_id = f"so04-{action}-{index:03d}"
    source_ip = f"198.51.100.{(index % 250) + 1}"
    destination_port = 22
    redirect_port = 2222
    resource_key = {
        "throttle": f"tc:root:{iface}",
        "isolate": f"nft:inet:azazel_edge:input:{source_ip}",
        "redirect": f"nft:inet:azazel_edge:prerouting:{source_ip}:tcp:{destination_port}",
    }[action]
    task_id = "release-%016x" % _fnv1a64(f"{trace_id}|{action}|{resource_key}".encode())
    owner_token = f"azazel-edge:{task_id}"
    tc_handle = "%x:" % ((_fnv1a64(owner_token.encode()) % 0xFFFE) + 1) if action == "throttle" else ""
    throttle = action == "throttle"
    return {
        "task_id": task_id,
        "trace_id": trace_id,
        "action": action,
        "resource_key": resource_key,
        "owner_token": owner_token,
        "iface": iface,
        "tc_handle": tc_handle,
        "source_ip": source_ip,
        "destination_port": destination_port,
        "redirect_port": redirect_port,
        "expected_rate_bps": 256_000 if throttle else 0,
        "expected_burst_bytes": 4096 if throttle else 0,
        "expected_latency_us": 100_000 if throttle else 0,
        "due_epoch": due_epoch,
        "next_attempt_epoch": due_epoch,
        "created_epoch": created_epoch,
        "updated_epoch": created_epoch,
        "status": "active",
        "attempts": 0,
        "last_error": "",
        **({"due_boottime_ns": due_boottime_ns, "due_boot_id": due_boot_id} if due_boottime_ns is not None and due_boot_id else {}),
    }


class _Tail(threading.Thread):
    """Timestamps, on the harness monotonic clock, the first start record and outcome per lease.

    The chain is read before the JSONL on every pass, and again when an
    outcome names a lease whose start record has not been seen yet: the core
    writes the start record before the attempt and the outcome after it, so a
    start record missing at that second read was not there when the outcome was.
    """

    def __init__(self, events: Path, chain: Path, wanted: set[str]):
        super().__init__(daemon=True)
        self.events = events
        self.chain = chain
        self.wanted = set(wanted)
        self.starts: Dict[str, Dict[str, Any]] = {}
        self.outcomes: Dict[str, Dict[str, Any]] = {}
        self.stop = threading.Event()
        self._offsets = {"chain": 0, "events": 0}
        self._pending = {"chain": b"", "events": b""}
        self._chain_lines = 0

    def _read(self, name: str, path: Path) -> tuple[List[bytes], int, Optional[int]]:
        try:
            with path.open("rb") as fh:
                fh.seek(self._offsets[name])
                chunk = fh.read()
        except FileNotFoundError:
            chunk = b""
        # Taken after the read returns, so an observation is never earlier
        # than the write it observed.
        now = time.monotonic_ns()
        now_boot = boottime_ns()
        if not chunk:
            return [], now, now_boot
        self._offsets[name] += len(chunk)
        lines = (self._pending[name] + chunk).split(b"\n")
        self._pending[name] = lines.pop()
        return lines, now, now_boot

    def poll_chain(self) -> None:
        lines, now, now_boot = self._read("chain", self.chain)
        for raw in lines:
            line_no = self._chain_lines
            self._chain_lines += 1
            try:
                row = json.loads(raw)
            except Exception:
                continue
            if not isinstance(row, dict) or row.get("kind") != ROLLBACK_STARTED_KIND:
                continue
            tid = str(row.get("release_task_id") or "")
            if tid in self.wanted and tid not in self.starts:
                self.starts[tid] = {"observed_monotonic_ns": now, "observed_boottime_ns": now_boot, "chain_line": line_no, "row": row}

    def poll_events(self) -> None:
        lines, now, _ = self._read("events", self.events)
        for raw in lines:
            if b"rust_release_engine_v1" not in raw:
                continue
            try:
                event = json.loads(raw)
            except Exception:
                continue
            release = event.get("release") or {}
            tid = str(release.get("release_task_id") or "")
            if tid not in self.wanted or tid in self.outcomes:
                continue
            if tid not in self.starts:
                self.poll_chain()
            self.outcomes[tid] = {
                "observed_monotonic_ns": now,
                "release": release,
                "start_record_seen": tid in self.starts,
            }

    def done(self) -> bool:
        return bool(self.wanted) and len(self.starts) == len(self.wanted) and len(self.outcomes) == len(self.wanted)

    def run(self) -> None:
        while not self.stop.is_set():
            self.poll_chain()
            self.poll_events()
            if self.done():
                return
            time.sleep(0.002)


def start_record_problems(row: Mapping[str, Any], lease: Mapping[str, Any]) -> List[str]:
    """What is wrong with a ``rollback_started`` record for this lease, if anything."""

    problems = []
    if row.get("record_schema") != ROLLBACK_STARTED_SCHEMA:
        problems.append("record_schema")
    if row.get("release_task_id") != lease["task_id"]:
        problems.append("release_task_id")
    if row.get("trace_id") != lease["trace_id"]:
        problems.append("trace_id")
    for key in _START_RECORD_INT_FIELDS:
        value = row.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            problems.append(key)
    due = row.get("lease_due_epoch_ns")
    if isinstance(due, int) and abs(due - round(lease["due_epoch"] * 1e9)) > 1000:
        problems.append("lease_due_epoch_ns disagrees with the ledger")
    if "due_boottime_ns" in lease:
        if row.get("lease_due_boottime_ns") != lease["due_boottime_ns"]:
            problems.append("lease_due_boottime_ns disagrees with the ledger")
        if row.get("lease_boot_id") != lease.get("due_boot_id"):
            problems.append("lease_boot_id disagrees with the ledger")
        stamp = row.get("started_boottime_ns")
        if not isinstance(stamp, int) or isinstance(stamp, bool):
            problems.append("started_boottime_ns")
    elif row.get("lease_due_boottime_ns") is not None:
        problems.append("lease_due_boottime_ns given for a lease without one")
    return problems


def lease_start(lease: Mapping[str, Any], offset0: int) -> tuple[int, bool, str]:
    """A sample's start for this lease: (instant, on CLOCK_BOOTTIME?, start_event).

    Both SO-04 halves start here, so their starts are identical.
    """

    if isinstance(lease.get("due_boottime_ns"), int):
        return int(lease["due_boottime_ns"]), True, "lease due_boottime_ns (its monotonic deadline, CLOCK_BOOTTIME) from the release-ledger record"
    return (
        round(lease["due_epoch"] * 1e9) - offset0,
        False,
        "lease due_epoch from the release-ledger record, mapped onto the harness monotonic clock",
    )


def build_samples(
    leases: List[Dict[str, Any]],
    starts: Mapping[str, Mapping[str, Any]],
    outcomes: Mapping[str, Mapping[str, Any]],
    offset0: int,
) -> List[Dict[str, Any]]:
    """One sample per lease, from what the tail observed. Pure, so it is testable without a core."""

    samples: List[Dict[str, Any]] = []
    for lease in leases:
        start_ns, monotonic, start_event = lease_start(lease, offset0)
        row: Dict[str, Any] = {
            "sample_id": lease["task_id"],
            "action_type": lease["action"],
            "condition": {"load": lease.get("_phase", "nominal"), "operator_plane": "unavailable (no operator service running)"},
            "due_epoch": lease["due_epoch"],
            "sample_clock": "CLOCK_BOOTTIME" if monotonic else "CLOCK_MONOTONIC",
            "lease_due_boottime_ns": lease["due_boottime_ns"] if monotonic else None,
            "lease_boot_id": lease.get("due_boot_id", "") if monotonic else "",
            "start_monotonic_ns": start_ns,
            "start_event": start_event,
            "end_event": "first rollback_started audit-chain record naming release_task_id, observed in the core's rollback audit chain",
        }
        seen = starts.get(lease["task_id"])
        observed = seen.get("observed_boottime_ns" if monotonic else "observed_monotonic_ns") if seen else None
        if seen and isinstance(observed, int):
            end = max(observed, start_ns)
            record = seen["row"]

            def _stamp(key: str) -> Optional[int]:
                value = record.get(key)
                return value if isinstance(value, int) and not isinstance(value, bool) else None

            row.update({
                "end_monotonic_ns": end,
                "elapsed_ms": round((end - start_ns) / 1e6, 3),
                "start_record_chain_line": seen["chain_line"],
                "start_record_attempt": record.get("attempt"),
                "edge_recorded_start_monotonic_ns": _stamp("started_monotonic_ns"),
                "edge_recorded_start_boottime_ns": _stamp("started_boottime_ns"),
                "edge_recorded_start_wall_epoch_ns": _stamp("started_wall_epoch_ns"),
                "expiry_clock": str(record.get("expiry_clock") or ""),
                "start_record_boot_id": str(record.get("boot_id") or ""),
                "observed_before_expiry": observed < start_ns,
            })
        else:
            row.update({"end_monotonic_ns": None, "elapsed_ms": None})
        outcome = outcomes.get(lease["task_id"])
        if outcome:
            release = outcome["release"]
            row.update({
                "attempted_at_epoch": release.get("attempted_at_epoch"),
                "edge_reported_start_after_expiry_ms": round((float(release.get("attempted_at_epoch", 0)) - lease["due_epoch"]) * 1000, 3),
                "release_status": release.get("status"),
                "release_result": release.get("result"),
                "start_record_before_outcome": bool(outcome["start_record_seen"]),
            })
        else:
            row["start_record_before_outcome"] = None
        samples.append(row)
    return samples


def start_record_prerequisites(
    leases: List[Dict[str, Any]],
    starts: Mapping[str, Mapping[str, Any]],
    samples: List[Dict[str, Any]],
    chain: Path,
    offset0: int,
) -> tuple[List[Dict[str, Any]], List[str]]:
    """The two start-record prerequisites, and clock-offset findings for the wall-clock check."""

    verified = P0AuditLogger.verify_chain(chain) if chain.exists() else {"ok": False, "entries": 0, "error": "no chain written"}
    bad: List[str] = []
    offsets: List[str] = []
    for lease in leases:
        seen = starts.get(lease["task_id"])
        if not seen:
            continue
        record = seen["row"]
        problems = start_record_problems(record, lease)
        stamp = record.get("started_monotonic_ns")
        if isinstance(stamp, int) and stamp > int(seen["observed_monotonic_ns"]):
            problems.append("started_monotonic_ns later than the harness saw the record")
        boot_stamp, boot_seen = record.get("started_boottime_ns"), seen.get("observed_boottime_ns")
        if isinstance(boot_stamp, int) and isinstance(boot_seen, int) and boot_stamp > boot_seen:
            problems.append("started_boottime_ns later than the harness saw the record")
        wall = record.get("started_wall_epoch_ns")
        if isinstance(stamp, int) and isinstance(wall, int) and abs((wall - stamp) - offset0) > CLOCK_STEP_TOLERANCE_NS:
            offsets.append(lease["task_id"])
        if problems:
            bad.append(f"{lease['task_id']}: {', '.join(problems)}")
    chain_ok = bool(verified.get("ok")) and int(verified.get("entries") or 0) > 0 and not bad
    chain_detail = (
        f"verify_chain {verified}; {len(starts)} start record(s) for {len(leases)} lease(s)"
        + ("" if not bad else "; malformed: " + "; ".join(bad[:10]))
    )
    reversed_ = [s["sample_id"] for s in samples if s.get("start_record_before_outcome") is not True]
    order_ok = bool(samples) and not reversed_
    order_detail = (
        "every lease's start record was in the chain when its outcome appeared in the JSONL"
        if order_ok
        else "start record absent when the outcome appeared, or no outcome seen: " + ", ".join(reversed_[:20])
    )
    return (
        [
            prerequisite("rollback_start_chain_verifies", chain_ok, chain_detail),
            prerequisite("rollback_start_recorded_before_outcome", order_ok, order_detail),
        ],
        offsets,
    )


def _expiry_clock_counts(samples: List[Dict[str, Any]]) -> str:
    counts: Dict[str, int] = {}
    for s in samples:
        key = str(s.get("expiry_clock") or "unobserved")
        counts[key] = counts.get(key, 0) + 1
    return ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "no samples"


def _version(core_bin: Path) -> Optional[str]:
    try:
        out = subprocess.run([str(core_bin), "--version"], capture_output=True, text=True, timeout=10, env={"PATH": os.environ.get("PATH", "")})
    except Exception:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def hostile_load_gap(samples: List[Dict[str, Any]], hostile_load: Optional[Mapping[str, Any]], profile: Mapping[str, Any]) -> List[Dict[str, Any]]:
    """``SO04-HOSTILE-LOAD-UNDECLARED``, unless the validator's own recomputation
    (``so04_hostile_load.hostile_load_problems``) shows the declared profile
    applied for every sample. Shared by both halves."""

    out: List[Dict[str, Any]] = []
    pending = so04_hostile_load.profile_confirmed_problems(hostile_load, profile) if samples else ["no samples"]
    if pending:
        out.append(gap(
            "SO04-HOSTILE-LOAD-PROFILE-PROVISIONAL",
            "The hostile-load profile is provisional: its factors (owner_defaults) are defaults awaiting the owner's "
            "confirmation, and what was measured under it is container evidence, not hardware evidence. It stays "
            "until the owner changes the declaration in the tree: " + "; ".join(pending[:3]),
            refs=["config/service_objectives/hostile_load_profile.json", "OF-06"],
        ))
    problems = so04_hostile_load.hostile_load_problems(samples, hostile_load, profile) if samples else ["no samples"]
    if not problems:
        return out
    return out + [gap(
        "SO04-HOSTILE-LOAD-UNDECLARED",
        "The sample rule requires leases expiring under hostile load. The declared profile "
        "(config/service_objectives/hostile_load_profile.json, derived from the OF-06 ingress quota) is not shown "
        "applied to every sample: " + "; ".join(problems[:8]) + (f" (+{len(problems) - 8} more)" if len(problems) > 8 else ""),
        refs=["config/service_objectives/hostile_load_profile.json", "OF-06"],
    )]


def run(
    *,
    core_bin: Optional[Path] = None,
    leases_per_type: int = LEASES_PER_TYPE,
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    rng = random.Random(seed)
    profile = load_hostile_load_profile()
    # Absolute, because the daemon is started with the scratch directory as cwd.
    core = Path(core_bin or os.environ.get("AZAZEL_EDGE_CORE_BIN") or DEFAULT_CORE_BIN).resolve()
    version = _version(core) if core.is_file() and os.access(core, os.X_OK) else None
    prerequisites = [
        prerequisite(
            "core_binary_present",
            version is not None,
            f"{core}: version {version}" if version else f"{core}: missing or not runnable (build rust/azazel-edge-core first)",
        )
    ]
    samples: List[Dict[str, Any]] = []
    daemon_info: Dict[str, Any] = {}
    hostile: Optional[Dict[str, Any]] = None
    drift_ns: Optional[int] = None
    monotonic_leases = False
    if version is not None:
        with tempfile.TemporaryDirectory(prefix="so04-") as tmp:
            work = Path(tmp)
            ledger = work / "release-ledger.json"
            events = work / "normalized-events.jsonl"
            eve = work / "eve.json"
            eve.write_text("", encoding="utf-8")
            offset0 = time.time_ns() - time.monotonic_ns()
            created = time.time()
            created_boot = boottime_ns()
            this_boot = boot_id()
            monotonic_leases = created_boot is not None and bool(this_boot)
            leases: List[Dict[str, Any]] = []
            plan = so04_hostile_load.plan(leases_per_type, profile)
            # Expiries start 3 s after the ledger is written: nominal leases
            # first, then each declared hostile-load phase in its own window.
            dues, windows = so04_hostile_load.schedule([p[2] for p in plan], created + 3.0, rng, profile)
            for (action, index, phase), due in zip(plan, dues):
                if monotonic_leases:
                    # As build_release_task does: both deadlines are the same
                    # TTL added to clocks read together at creation.
                    lease = make_lease(
                        action, index, created, due,
                        due_boottime_ns=created_boot + round((due - created) * 1e9),
                        due_boot_id=this_boot,
                    )
                else:
                    lease = make_lease(action, index, created, due)
                lease["_phase"] = phase
                leases.append(lease)
            ledger.write_text(json.dumps({
                "schema_version": LEDGER_SCHEMA,
                "tasks": [{k: v for k, v in l.items() if not k.startswith("_")} for l in leases],
            }), encoding="utf-8")
            env = dict(os.environ)
            env.update({
                "AZAZEL_EVE_PATH": str(eve),
                "AZAZEL_FORWARD_AI": "false",
                "AZAZEL_NORMALIZED_EVENT_LOG": str(events),
                "AZAZEL_DEFENSE_RELEASE_LEDGER": str(ledger),
                "AZAZEL_EVENT_STDOUT": "off",
                "AZAZEL_REDIRECT_POLICY_PATH": str(REPO_ROOT / "config" / "redirect_policy.yaml"),
            })
            for key in ("AZAZEL_DEFENSE_ENFORCE", "AZAZEL_DEFENSE_DRY_RUN", "AZAZEL_DEFENSE_ENFORCE_LEVEL", "AZAZEL_EVE_POLL_MS", "AZAZEL_EVE_FROM_START"):
                env.pop(key, None)
            chain = rollback_audit_path(ledger)
            tail = _Tail(events, chain, {l["task_id"] for l in leases})
            tail.start()
            load = so04_hostile_load.HostileLoad(eve, profile, windows, boottime_ns)
            counter = so04_hostile_load.AlertCounter(events)
            stderr_path = work / "core.stderr"
            with stderr_path.open("w", encoding="utf-8") as err_fh:
                proc = subprocess.Popen([str(core)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err_fh)
                load.start()
                last_end = max([w[2] for w in windows] + [l["due_epoch"] for l in leases])
                deadline = last_end + 30.0
                while time.time() < deadline and not (tail.done() and load.finished.is_set()):
                    if proc.poll() is not None:
                        break
                    time.sleep(0.01)
                load.stop.set()
                load.join(timeout=10)
                so04_hostile_load.drain(
                    counter, load, timeout_s=90.0,
                    audit_interval_s=profile["quota"]["audit_interval_ms"] / 1000.0 if profile.get("quota") else 1.0,
                    alive=lambda: proc.poll() is None,
                )
                tail.stop.set()
                tail.join(timeout=5)
                exited_early = proc.poll()
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
            hostile = so04_hostile_load.observation(profile, load, counter, work, monotonic=monotonic_leases)
            drift_ns = (time.time_ns() - time.monotonic_ns()) - offset0
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
            daemon_info = {
                "started": "azazel-edge-core started" in stderr_text,
                "exited_before_harness_stopped_it": exited_early,
                "stderr_tail": stderr_text[-800:],
                "default_poll_ms": 200,
            }
            samples = build_samples(leases, tail.starts, tail.outcomes, offset0)
            record_prereqs, offset_steps = start_record_prerequisites(leases, tail.starts, samples, chain, offset0)
            prerequisites.append(
                prerequisite("core_daemon_started", daemon_info["started"], "startup line seen on stderr" if daemon_info["started"] else "no startup line: " + stderr_text[-300:])
            )
            prerequisites.append(
                prerequisite(
                    "wall_clock_stable_during_run",
                    abs(drift_ns) <= CLOCK_STEP_TOLERANCE_NS and not offset_steps,
                    f"wall-minus-monotonic drift {drift_ns / 1e6:.3f} ms (tolerance {CLOCK_STEP_TOLERANCE_NS / 1e6:.0f} ms); "
                    f"start records whose own wall/monotonic pair is off by more: {len(offset_steps)}; "
                    "a step would move the lease's wall deadline, which can still fire first",
                )
            )
            early = [s["sample_id"] for s in samples if s.get("observed_before_expiry")]
            prerequisites.append(
                prerequisite(
                    "no_release_record_before_expiry",
                    not early,
                    "none" if not early else "start record observed before the declared expiry (clamped to 0 ms): " + ", ".join(early),
                )
            )
            prerequisites.extend(record_prereqs)
            prerequisites.append(load_prerequisite(profile, hostile))
    else:
        for pid in (
            "core_daemon_started",
            "wall_clock_stable_during_run",
            "no_release_record_before_expiry",
            "load_phase_applied",
            "rollback_start_chain_verifies",
            "rollback_start_recorded_before_outcome",
        ):
            prerequisites.append(prerequisite(pid, False, "not evaluated: the core binary is not runnable"))
    required = SPEC_START["required_samples"]
    start_gaps = []
    if not so04_monotonic_expiry_observed(samples):
        start_gaps.append(gap(
            "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
            "Not every sample shows its lease expiring on its monotonic deadline (CLOCK_BOOTTIME, same boot, "
            "expiry_clock monotonic, the core's start stamp at or after the deadline, the wall deadline not first). "
            "Without that, a sample's start is not the issuer's monotonic expiry that the definition and section 4.3 "
            "require. Samples by expiry_clock: " + _expiry_clock_counts(samples) + ".",
            refs=["rust/azazel-edge-core/src/release.rs (lease_expiry)"],
        ))
    start_gaps += hostile_load_gap(samples, hostile, profile)
    start_part = build_part(
        name="rollback_start_after_expiry",
        pass_rule={"kind": RULE_EVERY_SAMPLE_MAX, "bound_ms": BOUND_MS, "description": "every sample starts <= 5 seconds after expiry"},
        required_samples=required,
        samples=samples,
        prerequisites=prerequisites,
        gaps=start_gaps,
        per_action_required=SPEC_START.get("per_action_samples", 0),
        hostile_load=hostile,
    )
    from . import so04_rollback_completion

    completion_part = so04_rollback_completion.measure(
        core=core, version=version, leases_per_type=leases_per_type, seed=seed, profile=profile
    )
    return build_record(
        objective_id=OBJECTIVE_ID,
        title=TITLE,
        started_monotonic_ns=started_ns,
        started_at=started_at,
        product_configuration={
            "product": "azazel-edge",
            "core_binary": str(core),
            "core_version": version,
            "declared_action_types": list(ACTION_TYPES),
            "enforcement": "Edge defaults: AZAZEL_DEFENSE_ENFORCE unset (off), dry-run on; the harness never applies enforcement",
            "release_sweep_poll_ms": "Edge default (200)",
            "leases": "written as active into the release ledger before the daemon starts",
            "interface_identity": "not commissioned: Edge has no commissioning record; leases name iface 'br0' and no interface is touched",
            "hostile_load_profile": {
                "path": profile.get("path"),
                "sha256": profile.get("sha256"),
                "quota": profile.get("quota_path"),
                "phases": [p["name"] for p in profile.get("phases") or []],
                "problems": profile.get("problems"),
                "status": "provisional; factors are defaults awaiting owner confirmation; container numbers, not hardware",
            },
            "daemon": daemon_info,
        },
        clock={
            "name": "CLOCK_BOOTTIME" if monotonic_leases else "CLOCK_MONOTONIC",
            "source": (
                "harness time.clock_gettime_ns(CLOCK_BOOTTIME) on the node running the core"
                if monotonic_leases
                else "harness time.monotonic_ns() on the node running the core"
            ),
            "lease_clock": (
                "earlier of the wall deadline (due_epoch) and the monotonic deadline (due_boottime_ns, CLOCK_BOOTTIME, this boot)"
                if monotonic_leases
                else "wall clock only: this host exposes no CLOCK_BOOTTIME or boot id, so the leases are legacy -- see SO04-LEASE-EXPIRY-ON-WALL-CLOCK"
            ),
            "end_clock": "harness clock (above) when the rollback_started record first appears in the chain; the record's own started_boottime_ns / started_monotonic_ns are the core's CLOCK_BOOTTIME / CLOCK_MONOTONIC on the same host",
            "wall_minus_monotonic_drift_ns": drift_ns,
        },
        sample_rule={
            "required_samples": required,
            "per_action_type": LEASES_PER_TYPE,
            "taken": len(samples),
            "conditions": ["nominal"]
            + [f"{p['name']} (declared hostile load, {profile.get('path')})" for p in profile.get("phases") or []]
            + ["operator plane unavailable (all samples)"],
        },
        parts=[start_part, completion_part],
        method="real azazel-edge-core daemon; leases injected into its release ledger; the declared hostile-load profile written into its EVE input; rollback audit chain, JSONL and ingress audit read from outside",
        notes=[
            "Rollback commands run against no owned state (no tc/nft privileges in the harness), so each first record is "
            "an attempt outcome such as release_attempt_failed/retry_pending or owned_state_already_absent. The row "
            "measures when rollback starts, not whether it succeeds.",
            "The hostile-load profile is provisional: its rates are derived from the OF-06 ingress quota, its factors "
            "are defaults awaiting the owner's confirmation, and the numbers measured under it are container numbers, "
            "not hardware evidence.",
        ],
    )


def load_prerequisite(profile: Mapping[str, Any], hostile: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """``load_phase_applied``: every declared phase was driven into the core (run health).

    Whether it was driven *as declared* is the hostile-load gap's recomputation,
    not this prerequisite.
    """

    phases = [p["name"] for p in profile.get("phases") or []]
    observed = {o.get("name"): o for o in (hostile or {}).get("phases") or []}
    driven = bool(phases) and all(sum((observed.get(n) or {}).get("written", {}).values() or [0]) > 0 for n in phases)
    if not phases:
        detail = f"no valid hostile-load profile: {profile.get('problems')}"
    else:
        detail = so04_hostile_load.phase_summary(hostile or {})
    return prerequisite("load_phase_applied", driven, detail)
