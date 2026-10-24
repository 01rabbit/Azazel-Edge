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
* completion -- deliberately not bounded: no action type declares a completion
  bound (OF-05). That half is reported ``not_measurable``, never passing.

What is measured here
---------------------
Edge's enforcement lease is the Rust core's release task
(``rust/azazel-edge-core/src/release.rs``): ``ReleaseTask.due_epoch`` is the
lease's declared expiry, and the core's sweep
(``process_due_releases_with_runner``) attempts rollback once ``due_epoch`` has
passed, then ``process_release_events`` (``src/main.rs``) appends a
``rust_release_engine_v1`` record naming ``release_task_id`` with
``attempted_at_epoch`` to the normalized-event JSONL.

The harness runs the **real, unmodified core binary** as a daemon. It writes
active leases for each declared action type (``throttle``, ``isolate``,
``redirect`` -- the only ones ``build_release_task`` accepts) into the release
ledger before the daemon starts, exactly in the ledger's own schema, then tails
the JSONL from outside and timestamps the first record naming each lease. It
never enables enforcement; the daemon runs with Edge's defaults (enforcement
off, dry-run on), and its rollback commands run against no owned state.

Why the start half is still ``not_measurable``
----------------------------------------------
The observed numbers are reported, but three things the definition needs are
absent, so the part cannot be gate evidence:

* the record naming the lease is **not an audit-chain record** -- the
  normalized-event JSONL is neither hash-chained nor fsynced, and it is written
  after the attempt finishes, carrying the attempt's start time;
* the lease's expiry is declared on the **wall clock** (``SystemTime``), not
  the issuer's monotonic clock that section 4.3 requires;
* **hostile load is undeclared** (OF-06). The harness floods the core's EVE
  input during half the samples, but that is the harness's own choice of load,
  not a declared one.
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
from typing import Any, Dict, List, Optional

from .record import (
    REPO_ROOT,
    RULE_EVERY_SAMPLE_MAX,
    build_part,
    build_record,
    gap,
    prerequisite,
    utc_now,
)

OBJECTIVE_ID = "SO-04"
TITLE = "Lease-expiry rollback starts (within 5 seconds of expiry)"
BOUND_MS = 5000.0
ACTION_TYPES = ("throttle", "isolate", "redirect")
LEASES_PER_TYPE = 50
LEDGER_SCHEMA = "azazel-release-ledger/v1"
DEFAULT_CORE_BIN = REPO_ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
CLOCK_STEP_TOLERANCE_NS = 50_000_000
IFACE = "br0"


def _fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def make_lease(action: str, index: int, created_epoch: float, due_epoch: float) -> Dict[str, Any]:
    """A release task as ``build_release_task`` + ``activate_release_task`` leave it."""

    trace_id = f"so04-{action}-{index:03d}"
    source_ip = f"198.51.100.{(index % 250) + 1}"
    destination_port = 22
    redirect_port = 2222
    resource_key = {
        "throttle": f"tc:root:{IFACE}",
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
        "iface": IFACE,
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
    }


class _Tail(threading.Thread):
    """Timestamps, on the harness monotonic clock, the first release record per lease."""

    def __init__(self, path: Path, wanted: set[str]):
        super().__init__(daemon=True)
        self.path = path
        self.wanted = set(wanted)
        self.first: Dict[str, Dict[str, Any]] = {}
        self.stop = threading.Event()

    def run(self) -> None:
        offset = 0
        pending = b""
        while not self.stop.is_set():
            try:
                with self.path.open("rb") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
            except FileNotFoundError:
                chunk = b""
            now = time.monotonic_ns()
            if chunk:
                offset += len(chunk)
                data = pending + chunk
                lines = data.split(b"\n")
                pending = lines.pop()
                for raw in lines:
                    if b"rust_release_engine_v1" not in raw:
                        continue
                    try:
                        event = json.loads(raw)
                    except Exception:
                        continue
                    release = event.get("release") or {}
                    tid = str(release.get("release_task_id") or "")
                    if tid in self.wanted and tid not in self.first:
                        self.first[tid] = {"observed_monotonic_ns": now, "release": release}
            if self.wanted and len(self.first) == len(self.wanted):
                return
            time.sleep(0.002)


class _EveFlood(threading.Thread):
    def __init__(self, path: Path, rate_per_s: int):
        super().__init__(daemon=True)
        self.path = path
        self.rate = rate_per_s
        self.active = threading.Event()
        self.stop = threading.Event()
        self.written = 0

    def run(self) -> None:
        batch = max(1, self.rate // 100)
        n = 0
        while not self.stop.is_set():
            if not self.active.is_set():
                time.sleep(0.005)
                continue
            lines = []
            for _ in range(batch):
                n += 1
                lines.append(json.dumps({
                    "timestamp": f"2026-01-01T00:00:{n % 60:02d}.{n % 1000000:06d}+0000",
                    "event_type": "alert",
                    "src_ip": f"203.0.113.{(n % 250) + 1}",
                    "dest_ip": "192.0.2.10",
                    "dest_port": 22,
                    "proto": "TCP",
                    "alert": {"signature_id": 2000000 + (n % 50), "signature": "so04 load", "category": "load", "severity": 1 + (n % 3)},
                }))
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            self.written += batch
            time.sleep(0.01)


def _version(core_bin: Path) -> Optional[str]:
    try:
        out = subprocess.run([str(core_bin), "--version"], capture_output=True, text=True, timeout=10, env={"PATH": os.environ.get("PATH", "")})
    except Exception:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def run(
    *,
    core_bin: Optional[Path] = None,
    leases_per_type: int = LEASES_PER_TYPE,
    seed: Optional[int] = None,
    flood_rate_per_s: int = 2000,
) -> Dict[str, Any]:
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    rng = random.Random(seed)
    core = Path(core_bin or os.environ.get("AZAZEL_EDGE_CORE_BIN") or DEFAULT_CORE_BIN)
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
    flood_written = 0
    drift_ns: Optional[int] = None
    per_phase = max(1, leases_per_type // 2)
    if version is not None:
        with tempfile.TemporaryDirectory(prefix="so04-") as tmp:
            work = Path(tmp)
            ledger = work / "release-ledger.json"
            events = work / "normalized-events.jsonl"
            eve = work / "eve.json"
            eve.write_text("", encoding="utf-8")
            offset0 = time.time_ns() - time.monotonic_ns()
            created = time.time()
            leases: List[Dict[str, Any]] = []
            plan: List[tuple[str, int, str]] = []
            for phase_idx, phase in enumerate(("nominal", "eve_flood")):
                count = per_phase if phase_idx == 0 else max(1, leases_per_type - per_phase)
                for k in range(count):
                    for action in ACTION_TYPES:
                        plan.append((action, phase_idx * per_phase + k, phase))
            # Expiries start 3 s after the ledger is written, 0.1 s apart with
            # jitter so that some expire in the same sweep. The flood phase
            # starts 2 s after the nominal phase's last expiry.
            nominal_n = sum(1 for p in plan if p[2] == "nominal")
            base = created + 3.0
            for j, (action, index, phase) in enumerate(plan):
                slot = j if phase == "nominal" else j + 20
                due = base + slot * 0.1 + rng.uniform(0.0, 0.05)
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
            for key in ("AZAZEL_DEFENSE_ENFORCE", "AZAZEL_DEFENSE_DRY_RUN", "AZAZEL_DEFENSE_ENFORCE_LEVEL", "AZAZEL_EVE_POLL_MS"):
                env.pop(key, None)
            tail = _Tail(events, {l["task_id"] for l in leases})
            tail.start()
            flood = _EveFlood(eve, flood_rate_per_s)
            flood.start()
            stderr_path = work / "core.stderr"
            with stderr_path.open("w", encoding="utf-8") as err_fh:
                proc = subprocess.Popen([str(core)], cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=err_fh)
                flood_start = base + (nominal_n + 18) * 0.1
                last_due = max(l["due_epoch"] for l in leases)
                deadline = last_due + 30.0
                while time.time() < deadline and len(tail.first) < len(leases):
                    now = time.time()
                    if now >= flood_start and now <= last_due + 2.0:
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
                exited_early = proc.poll()
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
            flood.join(timeout=5)
            flood_written = flood.written
            drift_ns = (time.time_ns() - time.monotonic_ns()) - offset0
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
            daemon_info = {
                "started": "azazel-edge-core started" in stderr_text,
                "exited_before_harness_stopped_it": exited_early,
                "stderr_tail": stderr_text[-800:],
                "default_poll_ms": 200,
            }
            for lease in leases:
                start_ns = round(lease["due_epoch"] * 1e9) - offset0
                seen = tail.first.get(lease["task_id"])
                row: Dict[str, Any] = {
                    "sample_id": lease["task_id"],
                    "action_type": lease["action"],
                    "condition": {"load": lease["_phase"], "operator_plane": "unavailable (no operator service running)"},
                    "due_epoch": lease["due_epoch"],
                    "start_monotonic_ns": start_ns,
                    "start_event": "lease due_epoch from the release-ledger record, mapped onto the harness monotonic clock",
                    "end_event": "first rust_release_engine_v1 record naming release_task_id observed in the normalized-event JSONL",
                }
                if seen:
                    release = seen["release"]
                    row.update({
                        "end_monotonic_ns": max(seen["observed_monotonic_ns"], start_ns),
                        "elapsed_ms": round((max(seen["observed_monotonic_ns"], start_ns) - start_ns) / 1e6, 3),
                        "attempted_at_epoch": release.get("attempted_at_epoch"),
                        "edge_reported_start_after_expiry_ms": round((float(release.get("attempted_at_epoch", 0)) - lease["due_epoch"]) * 1000, 3),
                        "release_status": release.get("status"),
                        "release_result": release.get("result"),
                        "observed_before_expiry": seen["observed_monotonic_ns"] < start_ns,
                    })
                else:
                    row.update({"end_monotonic_ns": None, "elapsed_ms": None})
                samples.append(row)
            prerequisites.append(
                prerequisite("core_daemon_started", daemon_info["started"], "startup line seen on stderr" if daemon_info["started"] else "no startup line: " + stderr_text[-300:])
            )
            prerequisites.append(
                prerequisite(
                    "wall_clock_stable_during_run",
                    abs(drift_ns) <= CLOCK_STEP_TOLERANCE_NS,
                    f"wall-minus-monotonic drift {drift_ns / 1e6:.3f} ms (tolerance {CLOCK_STEP_TOLERANCE_NS / 1e6:.0f} ms); "
                    "the lease expiry is wall-clock, so a step would move it",
                )
            )
            early = [s["sample_id"] for s in samples if s.get("observed_before_expiry")]
            prerequisites.append(
                prerequisite(
                    "no_release_record_before_expiry",
                    not early,
                    "none" if not early else "observed before the declared expiry (clamped to 0 ms): " + ", ".join(early),
                )
            )
            prerequisites.append(
                prerequisite("load_phase_applied", flood_written > 0, f"{flood_written} synthetic EVE alerts written during the eve_flood phase")
            )
    required = LEASES_PER_TYPE * len(ACTION_TYPES)
    start_gaps = [
        gap(
            "SO04-END-RECORD-NOT-AUDIT-CHAIN",
            "The record naming the lease is the rust_release_engine_v1 line in the normalized-event JSONL: not "
            "hash-chained, not fsynced, and written after the attempt completes (it carries attempted_at_epoch). "
            "Edge writes no audit-chain record stating that rollback has begun.",
            refs=["rust/azazel-edge-core/src/main.rs (process_release_events)", "rust/azazel-edge-core/src/release.rs"],
        ),
        gap(
            "SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
            "ReleaseTask.due_epoch is SystemTime (wall clock); the definition and section 4.3 require the issuer's "
            "monotonic clock. The harness maps due_epoch onto its monotonic clock and checks for steps.",
            refs=["rust/azazel-edge-core/src/main.rs (now_epoch)"],
        ),
        gap(
            "SO04-HOSTILE-LOAD-UNDECLARED",
            "The sample rule requires leases expiring under hostile load; no hostile-load profile or ingress quota is "
            "declared (OF-06). The eve_flood phase is a harness-chosen load, not a declared one.",
            refs=["OF-06"],
        ),
    ]
    start_part = build_part(
        name="rollback_start_after_expiry",
        pass_rule={"kind": RULE_EVERY_SAMPLE_MAX, "bound_ms": BOUND_MS, "description": "every sample starts <= 5 seconds after expiry"},
        required_samples=required,
        samples=samples,
        prerequisites=prerequisites,
        gaps=start_gaps,
    )
    completion_part = build_part(
        name="rollback_completion",
        pass_rule={"kind": RULE_EVERY_SAMPLE_MAX, "bound_ms": 0.0, "description": "action-specific completion bound -- none declared"},
        required_samples=required,
        samples=[],
        prerequisites=[prerequisite("per_action_completion_bound_declared", False, "no action type declares a rollback completion bound (OF-05)")],
        gaps=[gap("OF-05", "Completion is action-specific and no action type declares a bound; section 4.3 ROLLBACK_INCOMPLETE has no time bound.", refs=["OF-05"])],
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
            "daemon": daemon_info,
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "source": "harness time.monotonic_ns() on the node running the core",
            "lease_clock": "wall clock (SystemTime) -- see SO04-LEASE-EXPIRY-ON-WALL-CLOCK",
            "wall_minus_monotonic_drift_ns": drift_ns,
        },
        sample_rule={
            "required_samples": required,
            "per_action_type": LEASES_PER_TYPE,
            "taken": len(samples),
            "conditions": ["nominal", "eve_flood (harness-chosen, not declared hostile load)", "operator plane unavailable (all samples)"],
        },
        parts=[start_part, completion_part],
        method="real azazel-edge-core daemon; leases injected into its release ledger; JSONL tailed from outside",
        notes=[
            "Rollback commands run against no owned state (no tc/nft privileges in the harness), so each first record is "
            "an attempt outcome such as release_attempt_failed/retry_pending or owned_state_already_absent. The row "
            "measures when rollback starts, not whether it succeeds.",
        ],
    )
