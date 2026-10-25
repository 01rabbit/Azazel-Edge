"""SO-04 completion half: lease-expiry rollback completes within its declared bound.

The assignment leaves completion "action-specific" (OF-05). Edge declares a
per-action bound in ``config/service_objectives/rollback_completion_bounds.json``
(read by ``declarations.load_rollback_completion_bounds``); this module measures
against it.

* start -- the lease's declared expiry, exactly as the start half takes it;
* end -- the first ``rust_release_engine_v1`` outcome naming the lease with
  ``status: released`` and ``result: rollback_applied_and_absence_verified``,
  observed in the normalized-event JSONL on this host's ``CLOCK_MONOTONIC``.
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
not from hardware (gap ``SO04-COMPLETION-BOUND-PROVISIONAL``). The start half's
wall-clock lease expiry and undeclared hostile load apply here too, because the
start event and sample rule are the same.
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

from .declarations import (
    ROLLBACK_ACTION_TYPES,
    load_rollback_completion_bounds,
    undeclared_action_types,
)
from .record import (
    REPO_ROOT,
    RULE_EVERY_SAMPLE_MAX_PER_ACTION,
    build_part,
    gap,
    prerequisite,
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


def _run(argv: List[str], stdin: Optional[str] = None) -> subprocess.CompletedProcess:
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=20)


class OwnedState:
    """The owned state the leases name, created and removed by the harness only."""

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

    def install(self, leases: List[Mapping[str, Any]]) -> List[str]:
        """Install every lease's owned state. Returns problems; empty means all installed."""

        problems: List[str] = []
        script = [
            f"add table inet {NFT_TABLE}",
            f"add chain inet {NFT_TABLE} input {{ type filter hook input priority 0; policy accept; }}",
            f"add chain inet {NFT_TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}",
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
        else:
            self.created_table = True
        for lease in leases:
            if lease["action"] != "throttle":
                continue
            iface = lease["iface"]
            out = _run([self.ip, "link", "add", iface, "type", "dummy"])
            if out.returncode != 0:
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
        for iface in self.created_ifaces:
            _run([self.ip, "link", "del", iface])
        self.created_ifaces = []
        if self.created_table:
            _run([self.nft, "delete", "table", "inet", NFT_TABLE])
            self.created_table = False


class _OutcomeTail(threading.Thread):
    """Every release outcome per lease, and when the first completing one was seen."""

    def __init__(self, events: Path, wanted: set[str]):
        super().__init__(daemon=True)
        self.events = events
        self.wanted = set(wanted)
        self.outcomes: Dict[str, List[Dict[str, Any]]] = {}
        self.completed: Dict[str, Dict[str, Any]] = {}
        self.stop = threading.Event()
        self._offset = 0
        self._pending = b""

    def poll(self) -> None:
        try:
            with self.events.open("rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read()
        except FileNotFoundError:
            chunk = b""
        now = time.monotonic_ns()
        if not chunk:
            return
        self._offset += len(chunk)
        lines = (self._pending + chunk).split(b"\n")
        self._pending = lines.pop()
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
                self.completed[tid] = {"observed_monotonic_ns": now, "release": release}

    def done(self) -> bool:
        return bool(self.wanted) and len(self.completed) == len(self.wanted)

    def run(self) -> None:
        while not self.stop.is_set():
            self.poll()
            if self.done():
                return
            time.sleep(0.002)


def build_samples(
    leases: List[Mapping[str, Any]],
    completed: Mapping[str, Mapping[str, Any]],
    outcomes: Mapping[str, List[Mapping[str, Any]]],
    installed: Mapping[str, Optional[bool]],
    absent_after: Mapping[str, Optional[bool]],
    bounds_ms: Mapping[str, float],
    offset0: int,
) -> List[Dict[str, Any]]:
    """One sample per lease. Pure, so it is testable without a core or privileges."""

    samples: List[Dict[str, Any]] = []
    for lease in leases:
        tid = lease["task_id"]
        start_ns = round(lease["due_epoch"] * 1e9) - offset0
        seen = outcomes.get(tid) or []
        row: Dict[str, Any] = {
            "sample_id": tid,
            "action_type": lease["action"],
            "condition": {"load": lease.get("_phase", "nominal"), "operator_plane": "unavailable (no operator service running)"},
            "due_epoch": lease["due_epoch"],
            "start_monotonic_ns": start_ns,
            "start_event": "lease due_epoch from the release-ledger record, mapped onto the harness monotonic clock",
            "end_event": END_EVENT,
            "completion_bound_ms": bounds_ms.get(lease["action"]),
            "completion_attempts": len(seen),
            "owned_state_installed": installed.get(tid) is True,
            "owned_state_absent_after_run": absent_after.get(tid) is False,
        }
        done = completed.get(tid)
        if done:
            end = max(int(done["observed_monotonic_ns"]), start_ns)
            row.update({
                "end_monotonic_ns": end,
                "elapsed_ms": round((end - start_ns) / 1e6, 3),
                "completion_result": done["release"].get("result"),
                "observed_before_expiry": int(done["observed_monotonic_ns"]) < start_ns,
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


def _gaps() -> List[Dict[str, Any]]:
    return [
        gap(
            "SO04-COMPLETION-BOUND-PROVISIONAL",
            "The per-action completion bounds are provisional: derived from container (aarch64) runs plus a margin, "
            "not from hardware. They make the completion half measurable against a declared number; they are not "
            "evidence that the number is right for any hardware class.",
            refs=["config/service_objectives/rollback_completion_bounds.json", "OF-05"],
        ),
        gap(
            "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
            "The start event is the lease's due_epoch, which is wall clock; see the start half.",
            refs=["rust/azazel-edge-core/src/main.rs (now_epoch)"],
        ),
        gap(
            "SO04-HOSTILE-LOAD-UNDECLARED",
            "The sample rule requires leases expiring under hostile load; no hostile-load profile or ingress quota "
            "is declared (OF-06). The eve_flood phase is a harness-chosen load.",
            refs=["OF-06"],
        ),
    ]


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


def measure(
    *,
    core: Path,
    version: Optional[str],
    leases_per_type: int,
    seed: Optional[int] = None,
    flood_rate_per_s: int = 2000,
    declaration: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Run the core against leases with real owned state and build the completion part."""

    from . import so04_lease_rollback as so04

    decl = dict(declaration) if declaration is not None else load_rollback_completion_bounds()
    bounds = decl.get("bounds_ms") or {}
    prerequisites = [declared_prerequisite(decl)]
    samples: List[Dict[str, Any]] = []
    rng = random.Random(None if seed is None else seed + 1)
    owned = OwnedState()
    reason = "the core binary is not runnable" if version is None else owned.unavailable_reason()
    if reason is None:
        try:
            samples, run_prereqs = _measure_with_owned_state(so04, owned, core, leases_per_type, rng, flood_rate_per_s, bounds)
            prerequisites.extend(run_prereqs)
        finally:
            owned.cleanup()
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
    return build_part(
        name="rollback_completion",
        pass_rule=pass_rule(decl),
        required_samples=SPEC["required_samples"],
        samples=samples,
        prerequisites=prerequisites,
        gaps=_gaps(),
    )


def _measure_with_owned_state(so04, owned: OwnedState, core: Path, leases_per_type: int, rng, flood_rate_per_s: int, bounds):
    prerequisites = [prerequisite("core_binary_present", True, f"{core}")]
    per_phase = max(1, leases_per_type // 2)
    with tempfile.TemporaryDirectory(prefix="so04c-") as tmp:
        work = Path(tmp)
        ledger = work / "release-ledger.json"
        events = work / "normalized-events.jsonl"
        eve = work / "eve.json"
        eve.write_text("", encoding="utf-8")
        offset0 = time.time_ns() - time.monotonic_ns()
        created = time.time()
        plan = []
        for phase_idx, phase in enumerate(("nominal", "eve_flood")):
            count = per_phase if phase_idx == 0 else max(1, leases_per_type - per_phase)
            for k in range(count):
                for action in ROLLBACK_ACTION_TYPES:
                    plan.append((action, phase_idx * per_phase + k, phase))
        nominal_n = sum(1 for p in plan if p[2] == "nominal")
        # Installing state takes a while; expiries start once it is done.
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
        base = time.time() + 3.0
        for j, lease in enumerate(leases):
            slot = j if lease["_phase"] == "nominal" else j + 20
            due = base + slot * 0.1 + rng.uniform(0.0, 0.05)
            lease["due_epoch"] = due
            lease["next_attempt_epoch"] = due
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
        for key in ("AZAZEL_DEFENSE_ENFORCE", "AZAZEL_DEFENSE_DRY_RUN", "AZAZEL_DEFENSE_ENFORCE_LEVEL", "AZAZEL_EVE_POLL_MS"):
            env.pop(key, None)
        tail = _OutcomeTail(events, {l["task_id"] for l in leases})
        tail.start()
        flood = so04._EveFlood(eve, flood_rate_per_s)
        flood.start()
        stderr_path = work / "core.stderr"
        with stderr_path.open("w", encoding="utf-8") as err_fh:
            proc = subprocess.Popen([str(core)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err_fh)
            flood_start = base + (nominal_n + 18) * 0.1
            last_due = max(l["due_epoch"] for l in leases)
            deadline = last_due + 30.0
            while time.time() < deadline and not tail.done():
                now = time.time()
                if flood_start <= now <= last_due + 2.0:
                    flood.active.set()
                elif now > last_due + 2.0:
                    flood.active.clear()
                if proc.poll() is not None:
                    break
                time.sleep(0.01)
            flood.active.clear()
            flood.stop.set()
            tail.stop.set()
            tail.join(timeout=5)
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        flood.join(timeout=5)
        tail.poll()
        drift_ns = (time.time_ns() - time.monotonic_ns()) - offset0
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
        absent_after = owned.present(leases)
        samples = build_samples(leases, tail.completed, tail.outcomes, installed, absent_after, bounds, offset0)
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
    prerequisites.append(prerequisite("load_phase_applied", flood.written > 0, f"{flood.written} synthetic EVE alerts written during the eve_flood phase"))
    early = [s["sample_id"] for s in samples if s.get("observed_before_expiry")]
    prerequisites.append(
        prerequisite(
            "wall_clock_stable_during_run",
            abs(drift_ns) <= CLOCK_STEP_TOLERANCE_NS and not early,
            f"wall-minus-monotonic drift {drift_ns / 1e6:.3f} ms (tolerance {CLOCK_STEP_TOLERANCE_NS / 1e6:.0f} ms); "
            f"completions observed before the declared expiry: {len(early)}",
        )
    )
    return samples, prerequisites


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


__all__ = ["measure", "build_samples", "per_action_summary", "OwnedState", "throttle_iface"]
