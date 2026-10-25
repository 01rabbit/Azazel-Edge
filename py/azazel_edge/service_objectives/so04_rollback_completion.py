"""SO-04 completion half: lease-expiry rollback completes within its declared bound.

The assignment leaves completion "action-specific" (OF-05). Edge declares a
per-action bound in ``config/service_objectives/rollback_completion_bounds.json``
(read by ``declarations.load_rollback_completion_bounds``); this module measures
against it.

* start -- the lease's declared expiry, computed by the start half's own
  ``lease_start``: its monotonic deadline (``due_boottime_ns``,
  ``CLOCK_BOOTTIME``) where the host has one, so both halves start identically;
* end -- the first ``rust_release_engine_v1`` outcome naming the lease with
  ``status: released`` and ``result: rollback_applied_and_absence_verified``,
  observed in the normalized-event JSONL, on the clock the start is on.
  That outcome is the core stating that it deleted the lease's owned state and
  read back its absence;
* pass -- every sample's elapsed time is within the bound declared for its
  action type. A sample whose action type declares no bound is a violation, and
  the ``per_action_completion_bound_declared`` prerequisite is unmet, so a
  missing declaration never passes.

How it is measured
------------------
Rollback can only complete if there is owned state to roll back. The harness
therefore installs, before the core starts, the state each lease owns: a TBF
root qdisc with the lease's handle on a dummy interface per throttle lease, and
an ``inet azazel_edge`` rule tagged with the lease's owner token per isolate and
redirect lease. It reads each back before the core starts and again after the
run, so the core's "absence verified" is checked from outside. This needs
root, ``CAP_NET_ADMIN`` and the dummy link type (a container started with
``--cap-add NET_ADMIN``). Where they are missing, or where an ``inet
azazel_edge`` table already exists -- a live node's firewall, which the harness
never touches -- nothing is installed and the part is ``not_measurable``.

The core runs with Edge's defaults, as in the start half: enforcement off,
dry-run on. The release sweep runs regardless, which is what is measured. The
harness removes the interfaces and the table it created when it finishes.

Why it is still ``not_measurable``
----------------------------------
The declared bounds are provisional: derived from a container run plus margin,
not from hardware (gap ``SO04-COMPLETION-BOUND-PROVISIONAL``, which no sample
can close). The leases expire under the same declared hostile-load profile as
the start half's (``so04_hostile_load``), and ``SO04-HOSTILE-LOAD-UNDECLARED``
is dropped only by the same recomputation. ``SO04-LEASE-EXPIRY-ON-WALL-CLOCK``
is dropped only when every sample shows, by the start half's recomputation,
that its lease expired on its monotonic deadline -- an unfinished sample never
does.

A run killed by SIGTERM, SIGHUP or SIGINT stops the core and removes the
interfaces and the table it created; nothing else is removed.
"""

from __future__ import annotations

import atexit
import json
import os
import signal
import random
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from . import so04_hostile_load
from .declarations import (
    HARNESS_DRAIN_TIMEOUT_MS,
    ROLLBACK_ACTION_TYPES,
    load_hostile_load_profile,
    load_rollback_completion_bounds,
    undeclared_action_types,
)
from .record import (
    REPO_ROOT,
    RULE_EVERY_SAMPLE_MAX_PER_ACTION,
    build_part,
    gap,
    prerequisite,
    so04_monotonic_expiry_observed,
    spec_for,
)

SPEC = spec_for("SO-04", "rollback_completion")
COMPLETED_STATUS = "released"
COMPLETED_RESULT = "rollback_applied_and_absence_verified"
NFT_TABLE = "azazel_edge"
IFACE_PREFIX = "so04c"
TRUSTED_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")
CLOCK_STEP_TOLERANCE_NS = 50_000_000
END_EVENT = (
    "first rust_release_engine_v1 outcome naming release_task_id with status released and result "
    "rollback_applied_and_absence_verified, observed in the normalized-event JSONL"
)


def throttle_iface(index: int) -> str:
    return f"{IFACE_PREFIX}{index:03d}"


def _tool(name: str) -> Optional[str]:
    for d in TRUSTED_DIRS:
        candidate = Path(d) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


TIMEOUT_RC = 124


def _run(argv: List[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run a tool; a timeout is a failure (``TIMEOUT_RC``), never an exception."""

    try:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, TIMEOUT_RC, "", "timed out")


class OwnedState:
    """The owned state the leases name, created and removed by the harness only.

    Nothing is removed that the harness did not verifiably create: the table
    with ``nft create`` (which fails if one exists, even one that appeared
    after ``unavailable_reason`` looked), and each interface only when it was
    absent just before the harness added it.
    """

    def __init__(self) -> None:
        self.tc = _tool("tc")
        self.nft = _tool("nft")
        self.ip = _tool("ip")
        self.created_ifaces: List[str] = []
        self.created_table = False

    def unavailable_reason(self) -> Optional[str]:
        if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            return "not running as root: owned tc/nft state cannot be installed"
        missing = [n for n, p in (("tc", self.tc), ("nft", self.nft), ("ip", self.ip)) if p is None]
        if missing:
            return f"{', '.join(missing)} not found in {list(TRUSTED_DIRS)}"
        if _run([self.nft, "list", "table", "inet", NFT_TABLE]).returncode == 0:
            return f"an inet {NFT_TABLE} table already exists; the harness never touches a live node's firewall"
        probe = f"{IFACE_PREFIX}probe"
        out = _run([self.ip, "link", "add", probe, "type", "dummy"])
        if out.returncode != 0:
            return f"cannot create a dummy interface (CAP_NET_ADMIN and the dummy link type are needed): {out.stderr.strip()[:200]}"
        _run([self.ip, "link", "del", probe])
        return None

    def _iface_exists(self, iface: str) -> bool:
        return _run([self.ip, "link", "show", "dev", iface]).returncode == 0

    def install(self, leases: List[Mapping[str, Any]]) -> List[str]:
        """Install every lease's owned state. Returns problems; empty means all installed."""

        problems: List[str] = []
        out = _run([self.nft, "create", "table", "inet", NFT_TABLE])
        if out.returncode != 0:
            # Exists (perhaps since the check) or cannot be made: touch nothing.
            return [f"nft create table inet {NFT_TABLE}: {out.stderr.strip()[:300]}"]
        self.created_table = True
        script = [
            f"create chain inet {NFT_TABLE} input {{ type filter hook input priority 0; policy accept; }}",
            f"create chain inet {NFT_TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}",
        ]
        for lease in leases:
            if lease["action"] == "isolate":
                script.append(f'add rule inet {NFT_TABLE} input ip saddr {lease["source_ip"]} drop comment "{lease["owner_token"]}"')
            elif lease["action"] == "redirect":
                script.append(
                    f'add rule inet {NFT_TABLE} prerouting ip saddr {lease["source_ip"]} tcp dport {lease["destination_port"]} '
                    f'redirect to :{lease["redirect_port"]} comment "{lease["owner_token"]}"'
                )
        out = _run([self.nft, "-f", "-"], stdin="\n".join(script) + "\n")
        if out.returncode != 0:
            problems.append(f"nft: {out.stderr.strip()[:300]}")
        for lease in leases:
            if lease["action"] != "throttle":
                continue
            iface = lease["iface"]
            if not iface.startswith(IFACE_PREFIX):
                problems.append(f"{iface}: not a harness interface name")
                continue
            if self._iface_exists(iface):
                problems.append(f"{iface}: already exists; not the harness's to use")
                continue
            out = _run([self.ip, "link", "add", iface, "type", "dummy"])
            if out.returncode != 0:
                # Absent a moment ago: if a timed-out add left it behind, it is ours.
                if out.returncode == TIMEOUT_RC and self._iface_exists(iface):
                    self.created_ifaces.append(iface)
                problems.append(f"{iface}: {out.stderr.strip()[:200]}")
                continue
            self.created_ifaces.append(iface)
            _run([self.ip, "link", "set", iface, "up"])
            latency_ms = max(1, int(lease["expected_latency_us"]) // 1000)
            out = _run([
                self.tc, "qdisc", "add", "dev", iface, "root", "handle", lease["tc_handle"], "tbf",
                "rate", f"{int(lease['expected_rate_bps']) // 1000}kbit",
                "burst", str(int(lease["expected_burst_bytes"])),
                "latency", f"{latency_ms}ms",
            ])
            if out.returncode != 0:
                problems.append(f"{iface} tbf: {out.stderr.strip()[:200]}")
        return problems

    def _nft_owned(self, chain: str) -> Optional[set]:
        out = _run([self.nft, "-j", "list", "chain", "inet", NFT_TABLE, chain])
        if out.returncode != 0:
            return None
        try:
            entries = json.loads(out.stdout).get("nftables", [])
        except ValueError:
            return None
        return {e["rule"].get("comment") for e in entries if isinstance(e, dict) and isinstance(e.get("rule"), dict)}

    def present(self, leases: List[Mapping[str, Any]]) -> Dict[str, Optional[bool]]:
        """Per lease: is its owned state there? None when it could not be read."""

        chains = {"input": self._nft_owned("input"), "prerouting": self._nft_owned("prerouting")}
        out: Dict[str, Optional[bool]] = {}
        for lease in leases:
            if lease["action"] == "throttle":
                res = _run([self.tc, "-j", "qdisc", "show", "dev", lease["iface"]])
                if res.returncode != 0:
                    out[lease["task_id"]] = None
                    continue
                try:
                    items = json.loads(res.stdout)
                except ValueError:
                    out[lease["task_id"]] = None
                    continue
                out[lease["task_id"]] = any(
                    isinstance(i, dict) and i.get("root") is True and i.get("handle") == lease["tc_handle"] for i in items
                )
            else:
                owned = chains["input" if lease["action"] == "isolate" else "prerouting"]
                out[lease["task_id"]] = None if owned is None else lease["owner_token"] in owned
        return out

    def cleanup(self) -> None:
        """Remove what this harness created, and nothing else. Safe to call twice."""

        ifaces, self.created_ifaces = self.created_ifaces, []
        for iface in ifaces:
            _run([self.ip, "link", "del", iface])
        if self.created_table:
            self.created_table = False
            _run([self.nft, "delete", "table", "inet", NFT_TABLE])


class _CleanupOnSignal:
    """While active, SIGTERM and SIGHUP raise ``SystemExit`` so ``finally`` blocks
    run (SIGINT already raises ``KeyboardInterrupt``), and ``atexit`` covers an
    interpreter exit that skips them. Only the main thread can set handlers;
    elsewhere only ``atexit`` is used."""

    SIGNALS = tuple(getattr(signal, n) for n in ("SIGTERM", "SIGHUP") if hasattr(signal, n))

    def __init__(self, cleanup):
        self.cleanup = cleanup
        self.previous: Dict[int, Any] = {}

    @staticmethod
    def _raise(signum, _frame):
        raise SystemExit(128 + signum)

    def __enter__(self):
        atexit.register(self.cleanup)
        if threading.current_thread() is threading.main_thread():
            for sig in self.SIGNALS:
                self.previous[sig] = signal.signal(sig, self._raise)
        return self

    def __exit__(self, *exc):
        try:
            self.cleanup()
        finally:
            for sig, handler in self.previous.items():
                signal.signal(sig, handler)
            atexit.unregister(self.cleanup)
        return False


class _CompletionTail(threading.Thread):
    """Per lease: its first rollback_started record, every release outcome, and
    when the first completing outcome was seen (CLOCK_MONOTONIC and CLOCK_BOOTTIME)."""

    def __init__(self, events: Path, chain: Path, wanted: set[str], boottime):
        super().__init__(daemon=True)
        self.paths = {"events": events, "chain": chain}
        self.wanted = set(wanted)
        self.boottime = boottime
        self.starts: Dict[str, Dict[str, Any]] = {}
        self.outcomes: Dict[str, List[Dict[str, Any]]] = {}
        self.completed: Dict[str, Dict[str, Any]] = {}
        self.stop = threading.Event()
        self._offset = {"events": 0, "chain": 0}
        self._pending = {"events": b"", "chain": b""}

    def _read(self, name: str):
        try:
            with self.paths[name].open("rb") as fh:
                fh.seek(self._offset[name])
                chunk = fh.read()
        except FileNotFoundError:
            chunk = b""
        # Taken after the read, so an observation is never earlier than the write.
        now, now_boot = time.monotonic_ns(), self.boottime()
        if not chunk:
            return [], now, now_boot
        self._offset[name] += len(chunk)
        lines = (self._pending[name] + chunk).split(b"\n")
        self._pending[name] = lines.pop()
        return lines, now, now_boot

    def poll(self) -> None:
        lines, _, _ = self._read("chain")
        for raw in lines:
            try:
                row = json.loads(raw)
            except Exception:
                continue
            if not isinstance(row, dict) or row.get("kind") != "rollback_started":
                continue
            tid = str(row.get("release_task_id") or "")
            if tid in self.wanted and tid not in self.starts:
                self.starts[tid] = row
        lines, now, now_boot = self._read("events")
        for raw in lines:
            if b"rust_release_engine_v1" not in raw:
                continue
            try:
                release = json.loads(raw).get("release") or {}
            except Exception:
                continue
            tid = str(release.get("release_task_id") or "")
            if tid not in self.wanted:
                continue
            self.outcomes.setdefault(tid, []).append(release)
            if (
                tid not in self.completed
                and release.get("status") == COMPLETED_STATUS
                and release.get("result") == COMPLETED_RESULT
            ):
                self.completed[tid] = {"observed_monotonic_ns": now, "observed_boottime_ns": now_boot, "release": release}

    def done(self) -> bool:
        return bool(self.wanted) and len(self.completed) == len(self.wanted)

    def run(self) -> None:
        while not self.stop.is_set():
            self.poll()
            if self.done():
                return
            time.sleep(0.002)


def _int_or_none(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def build_samples(
    leases: List[Mapping[str, Any]],
    completed: Mapping[str, Mapping[str, Any]],
    outcomes: Mapping[str, List[Mapping[str, Any]]],
    installed: Mapping[str, Optional[bool]],
    absent_after: Mapping[str, Optional[bool]],
    bounds_ms: Mapping[str, float],
    offset0: int,
    starts: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """One sample per lease. Pure, so it is testable without a core or privileges.

    The start is ``so04_lease_rollback.lease_start``, the start half's own, and
    the end is read on the same clock as that start.
    """

    from .so04_lease_rollback import lease_start

    starts = starts or {}
    samples: List[Dict[str, Any]] = []
    for lease in leases:
        tid = lease["task_id"]
        start_ns, monotonic, start_event = lease_start(lease, offset0)
        seen = outcomes.get(tid) or []
        record = starts.get(tid) or {}
        row: Dict[str, Any] = {
            "sample_id": tid,
            "action_type": lease["action"],
            "condition": {"load": lease.get("_phase", "nominal"), "operator_plane": "unavailable (no operator service running)"},
            "due_epoch": lease["due_epoch"],
            "sample_clock": "CLOCK_BOOTTIME" if monotonic else "CLOCK_MONOTONIC",
            "lease_due_boottime_ns": lease["due_boottime_ns"] if monotonic else None,
            "lease_boot_id": lease.get("due_boot_id", "") if monotonic else "",
            "start_monotonic_ns": start_ns,
            "start_event": start_event,
            "end_event": END_EVENT,
            "expiry_clock": str(record.get("expiry_clock") or ""),
            "start_record_boot_id": str(record.get("boot_id") or ""),
            "edge_recorded_start_boottime_ns": _int_or_none(record.get("started_boottime_ns")),
            "edge_recorded_start_wall_epoch_ns": _int_or_none(record.get("started_wall_epoch_ns")),
            "completion_bound_ms": bounds_ms.get(lease["action"]),
            "completion_attempts": len(seen),
            "owned_state_installed": installed.get(tid) is True,
            "owned_state_absent_after_run": absent_after.get(tid) is False,
        }
        done = completed.get(tid)
        observed = _int_or_none(done.get("observed_boottime_ns" if monotonic else "observed_monotonic_ns")) if done else None
        if done and observed is not None:
            end = max(observed, start_ns)
            row.update({
                "end_monotonic_ns": end,
                "elapsed_ms": round((end - start_ns) / 1e6, 3),
                "completion_result": done["release"].get("result"),
                "observed_before_expiry": observed < start_ns,
            })
        else:
            last = seen[-1] if seen else {}
            row.update({
                "end_monotonic_ns": None,
                "elapsed_ms": None,
                "completion_result": last.get("result"),
                "observed_before_expiry": False,
            })
        samples.append(row)
    return samples


def _gaps(samples: List[Mapping[str, Any]], hostile_load: Optional[Mapping[str, Any]] = None, profile: Optional[Mapping[str, Any]] = None) -> List[Dict[str, Any]]:
    out = [
        gap(
            "SO04-COMPLETION-BOUND-PROVISIONAL",
            "The per-action completion bounds are provisional: derived from container (aarch64) runs plus a margin, "
            "not from hardware. They make the completion half measurable against a declared number; they are not "
            "evidence that the number is right for any hardware class.",
            refs=["config/service_objectives/rollback_completion_bounds.json", "OF-05"],
        ),
    ]
    # Closed exactly as for the start half, and only by the same recomputation
    # (record.so04_monotonic_expiry_observed), which the validator repeats.
    if not so04_monotonic_expiry_observed(samples):
        out.append(gap(
            "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
            "Not every sample shows its lease expiring on its monotonic deadline with the completion read on the same "
            "clock (an unfinished sample never shows it). The start is the start half's (lease_start).",
            refs=["rust/azazel-edge-core/src/release.rs (lease_expiry)"],
        ))
    # Closed exactly as for the start half: only when the validator's own
    # recomputation shows the declared profile applied for every sample.
    from .so04_lease_rollback import hostile_load_gap

    out += hostile_load_gap(list(samples), hostile_load, profile if profile is not None else load_hostile_load_profile())
    return out


def pass_rule(declaration: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "kind": RULE_EVERY_SAMPLE_MAX_PER_ACTION,
        "bounds_ms": dict(declaration.get("bounds_ms") or {}),
        "declaration": declaration.get("path"),
        "declaration_sha256": declaration.get("sha256"),
        "description": "every sample completes within the bound its action type declares; an undeclared action type is a violation",
    }


def declared_prerequisite(declaration: Mapping[str, Any]) -> Dict[str, Any]:
    missing = undeclared_action_types(declaration)
    detail = (
        f"{declaration.get('path')}: bounds_ms {declaration.get('bounds_ms')}, statuses {declaration.get('statuses')}"
        + ("" if not missing else f"; no valid bound for {missing}")
        + ("" if not declaration.get("problems") else f"; problems: {declaration.get('problems')}")
    )
    return prerequisite("per_action_completion_bound_declared", not missing, detail)


def build_completion_part(
    declaration: Mapping[str, Any],
    samples: List[Dict[str, Any]],
    prerequisites: List[Dict[str, Any]],
    hostile_load: Optional[Mapping[str, Any]] = None,
    profile: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return build_part(
        name="rollback_completion",
        pass_rule=pass_rule(declaration),
        required_samples=SPEC["required_samples"],
        samples=samples,
        prerequisites=prerequisites,
        gaps=_gaps(samples, hostile_load, profile),
        per_action_required=SPEC["per_action_samples"],
        hostile_load=hostile_load,
    )


def unmeasured_part(reason: str) -> Dict[str, Any]:
    """The completion part of a run that measured nothing: every run prerequisite unmet."""

    decl = load_rollback_completion_bounds()
    prereqs = [declared_prerequisite(decl)] + [
        prerequisite(pid, False, f"not evaluated: {reason}") for pid in SPEC["prerequisites"] if pid != "per_action_completion_bound_declared"
    ]
    return build_completion_part(decl, [], prereqs)


def measure(
    *,
    core: Path,
    version: Optional[str],
    leases_per_type: int,
    seed: Optional[int] = None,
    declaration: Optional[Mapping[str, Any]] = None,
    profile: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the core against leases with real owned state and build the completion part."""

    from . import so04_lease_rollback as so04

    decl = dict(declaration) if declaration is not None else load_rollback_completion_bounds()
    profile = profile if profile is not None else load_hostile_load_profile()
    hostile: Optional[Dict[str, Any]] = None
    bounds = decl.get("bounds_ms") or {}
    prerequisites = [declared_prerequisite(decl)]
    samples: List[Dict[str, Any]] = []
    rng = random.Random(None if seed is None else seed + 1)
    owned = OwnedState()
    reason = "the core binary is not runnable" if version is None else owned.unavailable_reason()
    if reason is None:
        with _CleanupOnSignal(owned.cleanup):
            samples, run_prereqs, hostile = _measure_with_owned_state(so04, owned, core, leases_per_type, rng, profile, bounds)
        prerequisites.extend(run_prereqs)
    else:
        prerequisites.append(prerequisite("core_binary_present", version is not None, f"{core}: version {version}"))
        for pid in (
            "core_daemon_started",
            "owned_state_installed_before_expiry",
            "completion_confirmed_by_readback",
            "load_phase_applied",
            "wall_clock_stable_during_run",
        ):
            prerequisites.append(prerequisite(pid, False, f"not evaluated: {reason}"))
    return build_completion_part(decl, samples, prerequisites, hostile, profile)


def _measure_with_owned_state(so04, owned: OwnedState, core: Path, leases_per_type: int, rng, profile, bounds):
    prerequisites = [prerequisite("core_binary_present", True, f"{core}")]
    with tempfile.TemporaryDirectory(prefix="so04c-") as tmp:
        work = Path(tmp)
        ledger = work / "release-ledger.json"
        events = work / "normalized-events.jsonl"
        eve = work / "eve.json"
        eve.write_text("", encoding="utf-8")
        offset0 = time.time_ns() - time.monotonic_ns()
        # As in the start half: both deadlines are one TTL added to clocks read together.
        created = time.time()
        created_boot = so04.boottime_ns()
        this_boot = so04.boot_id()
        monotonic_leases = created_boot is not None and bool(this_boot)
        plan = so04_hostile_load.plan(leases_per_type, profile)
        # Installing state takes a while; expiries are set once it is done.
        leases: List[Dict[str, Any]] = []
        for action, index, phase in plan:
            iface = throttle_iface(index) if action == "throttle" else so04.IFACE
            lease = so04.make_lease(action, index, created, created + 1.0, iface=iface)
            lease["_phase"] = phase
            leases.append(lease)
        install_problems = owned.install(leases)
        installed = owned.present(leases)
        not_there = [l["task_id"] for l in leases if installed.get(l["task_id"]) is not True]
        prerequisites.append(
            prerequisite(
                "owned_state_installed_before_expiry",
                not install_problems and not not_there,
                f"{len(leases) - len(not_there)}/{len(leases)} leases' owned state read back present before the core started"
                + ("" if not install_problems else f"; problems: {install_problems[:5]}"),
            )
        )
        if not owned.created_table:
            # The table could not be created (one exists, perhaps since the
            # check, or it cannot be made): nothing to measure against, and the
            # core is never started.
            for pid in ("core_daemon_started", "completion_confirmed_by_readback", "load_phase_applied", "wall_clock_stable_during_run"):
                prerequisites.append(prerequisite(pid, False, "not evaluated: the harness could not create its inet azazel_edge table"))
            return [], prerequisites, None
        dues, windows = so04_hostile_load.schedule([l["_phase"] for l in leases], time.time() + 3.0, rng, profile)
        for lease, due in zip(leases, dues):
            lease["due_epoch"] = due
            lease["next_attempt_epoch"] = due
            if monotonic_leases:
                lease["due_boottime_ns"] = created_boot + round((due - created) * 1e9)
                lease["due_boot_id"] = this_boot
        ledger.write_text(json.dumps({
            "schema_version": so04.LEDGER_SCHEMA,
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
        tail = _CompletionTail(events, so04.rollback_audit_path(ledger), {l["task_id"] for l in leases}, so04.boottime_ns)
        tail.start()
        load = so04_hostile_load.HostileLoad(eve, profile, windows, so04.boottime_ns)
        counter = so04_hostile_load.AlertCounter(events)
        stderr_path = work / "core.stderr"
        with stderr_path.open("w", encoding="utf-8") as err_fh:
            proc = subprocess.Popen([str(core)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err_fh)
            try:
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
                    counter, load, timeout_s=HARNESS_DRAIN_TIMEOUT_MS / 1000.0,
                    audit_interval_s=profile["quota"]["audit_interval_ms"] / 1000.0 if profile.get("quota") else 1.0,
                    alive=lambda: proc.poll() is None,
                )
            finally:
                # Also on a signal: the core is stopped before the state it
                # would roll back is removed.
                load.stop.set()
                tail.stop.set()
                tail.join(timeout=5)
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
        load.join(timeout=10)
        tail.poll()
        hostile = so04_hostile_load.observation(profile, load, counter, work, monotonic=monotonic_leases)
        drift_ns = (time.time_ns() - time.monotonic_ns()) - offset0
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        absent_after = owned.present(leases)
        samples = build_samples(leases, tail.completed, tail.outcomes, installed, absent_after, bounds, offset0, tail.starts)
    started = "azazel-edge-core started" in stderr_text
    prerequisites.append(prerequisite("core_daemon_started", started, "startup line seen on stderr" if started else stderr_text[-300:]))
    unconfirmed = [s["sample_id"] for s in samples if s["end_monotonic_ns"] is not None and not s["owned_state_absent_after_run"]]
    prerequisites.append(
        prerequisite(
            "completion_confirmed_by_readback",
            bool(samples) and not unconfirmed,
            "the harness's own readback after the run finds no owned state for every lease the core reported complete"
            if not unconfirmed
            else "owned state still read back after a reported completion: " + ", ".join(unconfirmed[:10]),
        )
    )
    prerequisites.append(so04.load_prerequisite(profile, hostile))
    early = [s["sample_id"] for s in samples if s.get("observed_before_expiry")]
    prerequisites.append(
        prerequisite(
            "wall_clock_stable_during_run",
            abs(drift_ns) <= CLOCK_STEP_TOLERANCE_NS and not early,
            f"wall-minus-monotonic drift {drift_ns / 1e6:.3f} ms (tolerance {CLOCK_STEP_TOLERANCE_NS / 1e6:.0f} ms); "
            f"completions observed before the declared expiry: {len(early)}",
        )
    )
    return samples, prerequisites, hostile


def per_action_summary(samples: List[Mapping[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Observed numbers per action type: what a provisional bound is derived from."""

    out: Dict[str, Dict[str, Any]] = {}
    for action in ROLLBACK_ACTION_TYPES:
        mine = [s for s in samples if s.get("action_type") == action]
        done = [float(s["elapsed_ms"]) for s in mine if isinstance(s.get("elapsed_ms"), (int, float))]
        results: Dict[str, int] = {}
        for s in mine:
            key = str(s.get("completion_result"))
            results[key] = results.get(key, 0) + 1
        out[action] = {
            "samples": len(mine),
            "completed": len(done),
            "max_elapsed_ms": max(done) if done else None,
            "results": results,
        }
    return out


__all__ = ["measure", "build_samples", "build_completion_part", "unmeasured_part", "per_action_summary", "OwnedState", "throttle_iface"]
