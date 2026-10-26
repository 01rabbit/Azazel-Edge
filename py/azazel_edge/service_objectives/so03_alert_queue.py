"""SO-03: P0 visual/voice alert queued after decision (every sample <= 2 s).

Definition (assignment section 3, SO-03):

* start -- the decision record is durable (its audit-chain entry committed);
* end -- the alert is *enqueued* into the visual/voice delivery queue with a
  durable record naming the decision id;
* clock -- the Edge node's monotonic clock;
* samples -- 200 synthetic P0 decisions under nominal load;
* pass -- every sample <= 2 seconds.

The path measured (owner decisions on Edge#414, 2026-10-25, and Edge#412,
2026-10-26: the Rust ``azazel-edge-core`` is the authoritative decision and
enforcement path)
------------------------------------------------------------------------
Every sample goes through the running path, product code unmodified:

1. the harness appends one Suricata EVE alert line to the file the **Rust
   core binary** tails (started with the Environment of
   ``systemd/azazel-edge-core.service``, paths moved into a scratch
   directory, enforcement off and dry run on as the unit sets them);
2. the core decides (``decide_defense``), runs ``maybe_enforce`` (dry run
   here) and forwards the decision event to the AI socket;
3. the **AI agent service** -- the script the
   ``systemd/azazel-edge-ai-agent.service`` ExecStart runs, loaded from the
   repository and started with its own ``_serve`` -- receives it, writes the
   P0 decision as an ``action_decision`` record to its core decision chain
   (fsynced) and the P0 relay its ``_serve`` attached enqueues one entry per
   channel (visual, voice) in the P0 queue (fsynced).

* **start** -- ``CLOCK_MONOTONIC`` read by the harness right before it
  appends the EVE line: an upper bound of the instant the core decides, so
  the core's poll, its decision, the forward to the agent and the agent's
  durable record are all inside the measured interval. The Edge-recorded
  instant of the durable decision record (read after its fsync, carried by
  the queue entries) must lie between the start and the end.
* **end** -- the relay reports the enqueue after the queue fsync; the harness
  reads the end instant there (``P0AlertRelay.on_relayed``, observation
  only). The harness then reads the entries back from the queue file and
  checks that they name the decision, its chain hash, its durable instant and
  what the core did with it (enforcement mode, effective action), and watches
  ``os.fsync`` (observation only) for the inodes synced.
* **P0** -- by what the core does (``enforcement.selected_action``): the
  harness computes the expected effective action of every sample from the
  redirect policy file, and the validator requires the core's to match.

The validator recomputes every record prerequisite, each sample's end, the
P0 class (from the decision's action, by the owner's rule, written
independently) and the closure of the three gaps from the samples. A sample
that did not come from the core's decision event (by source, pipeline, and
the EVE sid the harness wrote) leaves
``SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS`` open.

Diagnostics, not the verdict: per sample, the core's poll and decision
(EVE append to the core's ingest stamp, wall clock), the core to the agent
(wall clock), the agent's receipt to the durable record and the durable
record to the enqueue (monotonic).

Out of scope: rendering and speaking the queued alerts (no output device is
added), the time to collect the alert into Suricata's EVE file, and the
decision under hostile load (SO-11).
"""

from __future__ import annotations

import importlib.util
import itertools
import json
import os
import random
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional

from .record import (
    GAP_CLOSERS,
    RULE_EVERY_SAMPLE_MAX,
    SO03_CORE_DECISION_SOURCE,
    SO03_CORE_PIPELINE,
    build_part,
    build_record,
    gap,
    prerequisite,
    so03_end_observed,
    so03_observed_prerequisites,
    spec_for,
    utc_now,
)

OBJECTIVE_ID = "SO-03"
TITLE = "P0 visual/voice alert queued after decision (within 2 seconds)"
SPEC = spec_for("SO-03", "decision_durable_to_alert_enqueued")
BOUND_MS = SPEC["bound_ms"]
REQUIRED_SAMPLES = SPEC["required_samples"]

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CORE_BIN = REPO_ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
CORE_UNIT = REPO_ROOT / "systemd" / "azazel-edge-core.service"
AGENT_UNIT = REPO_ROOT / "systemd" / "azazel-edge-ai-agent.service"
# Where the installer puts the repository's tree (installer/internal).
INSTALL_ROOT = "/opt/azazel-edge/"

# How long a sample waits for its enqueue before it is recorded as unfinished.
# Far above the bound, so a slow enqueue is measured (and fails), not dropped.
END_WAIT_S = 10.0
# How long the core and the agent get to start.
START_WAIT_S = 15.0

QUEUE_RECORD_KEYS = (
    "channel", "schema", "record_type", "seq", "decision_id", "decision_chain_hash", "p0_class", "p0_basis",
    "p0_rule", "enqueued_monotonic_ns", "decision_durable_monotonic_ns", "decision_record_durable",
    "enforcement_mode", "effective_action",
)

# The core's decisions by EVE severity (decide_defense): 1 isolate,
# 2 redirect, 3 throttle. The core takes no SOC-labelled decision.
P0_KINDS = (("isolate", 1), ("redirect", 2), ("throttle", 3))
REDIRECT_POLICY = REPO_ROOT / "config" / "redirect_policy.yaml"
# Destination ports drawn per sample: prepared redirect mappings and ports
# the redirect policy falls back on (config/redirect_policy.yaml).
DEST_PORTS = (22, 80, 8080, 443, 3389)
SID_BASE = 9_300_000

_LOADS = itertools.count()


@contextmanager
def _watch_fsync():
    """Observe which inodes os.fsync is called on (any thread). Observation
    only: every call goes through to the real fsync, result or error unchanged."""

    real = os.fsync
    synced: List[tuple] = []

    def watching(fd):  # type: ignore[no-untyped-def]
        try:
            st = os.fstat(fd)
            key = (st.st_dev, st.st_ino)
        except OSError:
            key = None
        result = real(fd)
        if key is not None:
            synced.append(key)
        return result

    os.fsync = watching  # type: ignore[assignment]
    try:
        yield synced
    finally:
        os.fsync = real  # type: ignore[assignment]


def _inode(path: Path) -> Optional[tuple]:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


def unit_exec_start(unit: Path) -> List[str]:
    for line in unit.read_text(encoding="utf-8").splitlines():
        if line.startswith("ExecStart="):
            return shlex.split(line[len("ExecStart="):])
    raise ValueError(f"{unit}: no ExecStart")


def unit_environment(unit: Path) -> Dict[str, str]:
    """The unit's ``Environment=`` assignments (EnvironmentFile is not read)."""

    env: Dict[str, str] = {}
    for line in unit.read_text(encoding="utf-8").splitlines():
        if line.startswith("Environment="):
            for item in shlex.split(line[len("Environment="):]):
                key, sep, value = item.partition("=")
                if sep:
                    env[key] = value
    return env


def agent_service_script(unit: Path = AGENT_UNIT) -> Path:
    """The Python script the agent unit's ExecStart runs, in this repository."""

    argv = unit_exec_start(unit)
    scripts = [a for a in argv[1:] if a.endswith(".py")]
    if len(scripts) != 1 or not scripts[0].startswith(INSTALL_ROOT):
        raise ValueError(f"{unit}: ExecStart does not run one script under {INSTALL_ROOT}: {argv}")
    return REPO_ROOT / scripts[0][len(INSTALL_ROOT):]


def agent_environment(work: Path, unit: Path = AGENT_UNIT) -> Dict[str, str]:
    """The agent unit's Environment, with every path it writes moved into ``work``."""

    env = unit_environment(unit)
    env.update({
        "AZAZEL_AI_SOCKET": str(work / "ai" / "ai-bridge.sock"),
        "AZAZEL_AI_ADVISORY": str(work / "ai_advisory.json"),
        "AZAZEL_AI_EVENT_LOG": str(work / "ai-events.jsonl"),
        "AZAZEL_UI_SNAPSHOT": str(work / "ui_snapshot.json"),
        "AZAZEL_AI_DEFERRED_LOG": str(work / "ai-deferred.jsonl"),
        "AZAZEL_AI_LLM_LOG": str(work / "ai-llm.jsonl"),
        "AZAZEL_AI_METRICS": str(work / "ai_metrics.json"),
        "AZAZEL_AI_POLICY": str(work / "ai_runtime_policy.json"),
        "AZAZEL_AI_AUDIT_LOG": str(work / "log" / "ai-audit.jsonl"),
        "AZAZEL_DECISION_LOG_DIR": str(work / "tactics_engine"),
        # The core's normalized log, as the core is started with it below.
        "AZAZEL_NORMALIZED_EVENT_LOG": str(work / "normalized-events.jsonl"),
        "AZAZEL_RUNTIME_SOCKET_GROUP": "",
        # No model server is reached from a measurement: a closed local port.
        "AZAZEL_OLLAMA_ENDPOINT": "http://127.0.0.1:9",
    })
    return env


@contextmanager
def _environ(values: Mapping[str, str]) -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def load_agent_service(script: Path) -> Any:
    """Import the agent script as its own module (fresh globals each time)."""

    name = f"_azazel_edge_ai_agent_service_{next(_LOADS)}"
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def core_environment(work: Path, socket_path: Path, unit: Path = CORE_UNIT) -> Dict[str, str]:
    """The core unit's Environment with its paths moved into ``work``.
    Enforcement stays off and dry run on, as the unit sets them."""

    env = {k: v for k, v in os.environ.items() if not k.startswith("AZAZEL_")}
    env.update(unit_environment(unit))
    env.update({
        "AZAZEL_EVE_PATH": str(work / "eve.json"),
        "AZAZEL_AI_SOCKET": str(socket_path),
        "AZAZEL_NORMALIZED_EVENT_LOG": str(work / "normalized-events.jsonl"),
        "AZAZEL_DEFENSE_RELEASE_LEDGER": str(work / "release-ledger.json"),
        "AZAZEL_REDIRECT_POLICY_PATH": str(REPO_ROOT / "config" / "redirect_policy.yaml"),
        "AZAZEL_EVENT_STDOUT": "off",
        "AZAZEL_DEFENSE_ENFORCE": "false",
        "AZAZEL_DEFENSE_DRY_RUN": "true",
    })
    return env


def _version(core_bin: Path) -> Optional[str]:
    try:
        out = subprocess.run([str(core_bin), "--version"], capture_output=True, text=True, timeout=10, env={"PATH": os.environ.get("PATH", "")})
    except Exception:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def expected_effective_action(decided: str, severity: int, port: int, policy_path: Path = REDIRECT_POLICY) -> str:
    """What the core is expected to do (enforcement.selected_action) for one
    sample, from the redirect policy file, written independently of the core:
    a redirect to a prepared port stays a redirect; any other redirect of an
    EVE severity-2 alert (risk score 81, high risk) takes the policy's
    high-risk fallback."""

    if decided != "redirect":
        return decided
    import yaml

    policy = (yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}).get("redirect_policy") or {}
    if not policy.get("enabled"):
        return "notify"
    if port in {int(k) for k in (policy.get("prepared_ports") or {})}:
        return "redirect"
    risk_score = min(100, (11 - severity) * 9)
    if risk_score >= 80 or severity >= 4:
        return str(policy.get("high_risk_unsupported_port_action") or "isolate")
    return str(policy.get("unsupported_port_action") or "notify")


def _eve_line(i: int, severity: int, port: int, sid: Optional[int] = None) -> str:
    return json.dumps({
        # The current time, as Suricata stamps an alert it has just seen.
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "event_type": "alert",
        "src_ip": f"203.0.113.{(i % 250) + 1}",
        "dest_ip": "192.0.2.10",
        "dest_port": port,
        "proto": "TCP",
        "alert": {"signature_id": SID_BASE + i if sid is None else sid, "signature": "so03 core decision", "category": "so03", "severity": severity},
    })


def _queue_records_for(queue_path: Path, decision_id: str) -> List[Dict[str, Any]]:
    """The queue entries naming ``decision_id``, read back from the file."""

    out: List[Dict[str, Any]] = []
    try:
        lines = queue_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict) and row.get("record_type") == "alert" and row.get("decision_id") == decision_id:
            out.append({k: row.get(k) for k in QUEUE_RECORD_KEYS})
    return out


def _chain_record(chain_path: Path, chain_hash: str) -> Dict[str, Any]:
    try:
        lines = chain_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except Exception:
            continue
        if isinstance(row, dict) and row.get("chain_hash") == chain_hash:
            return row
    return {}


def _full_queue_enqueue_latency() -> Dict[str, Any]:
    """Diagnostic: one enqueue into a queue already at its bound (plain
    append), and one that triggers the 2x-bound compaction."""

    from azazel_edge.notify.p0_alert import DEFAULT_MAX_ENTRIES, P0AlertQueue, build_p0_alerts

    def alerts(i: int) -> List[Dict[str, Any]]:
        rec_ = {"kind": "action_decision", "trace_id": f"fill-{i}", "chain_hash": f"{i:064x}", "action": "throttle"}
        return build_p0_alerts(rec_, "enforcement:throttle", "fsynced", 1)

    with tempfile.TemporaryDirectory(prefix="so03-full-") as tmp:
        q = P0AlertQueue(Path(tmp) / "q.jsonl", max_entries=DEFAULT_MAX_ENTRIES)
        i = 0
        while i * 2 < DEFAULT_MAX_ENTRIES:
            q.enqueue(alerts(i))
            i += 1
        t0 = time.monotonic_ns()
        q.enqueue(alerts(i))
        append_ms = (time.monotonic_ns() - t0) / 1e6
        i += 1
        while (i + 1) * 2 <= q.max_lines:
            q.enqueue(alerts(i))
            i += 1
        before = q.compactions
        t0 = time.monotonic_ns()
        q.enqueue(alerts(i))
        compact_ms = (time.monotonic_ns() - t0) / 1e6
        if q.compactions != before + 1:
            raise RuntimeError("the full-queue enqueue did not compact")
    return {"max_entries": DEFAULT_MAX_ENTRIES, "append_ms": append_ms, "compact_ms": compact_ms}


def _wait(predicate, timeout: float) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def _ms(value: Optional[float]) -> Optional[float]:
    return round(value, 3) if isinstance(value, (int, float)) else None


def _sample(
    i: int, rng: random.Random, eve: Path, chain_path: Path, queue_path: Path, synced: List[tuple],
    relayed: List[tuple], relayed_cv: threading.Condition,
) -> Dict[str, Any]:
    kind, severity = P0_KINDS[i % len(P0_KINDS)]
    port = rng.choice(DEST_PORTS)
    expected = expected_effective_action(kind, severity, port)
    sid = SID_BASE + i
    line = _eve_line(i, severity, port)
    with relayed_cv:
        del relayed[:]
    del synced[:]
    append_epoch = time.time()
    append_ns = time.monotonic_ns()
    with eve.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    deadline = time.monotonic() + END_WAIT_S
    with relayed_cv:
        while not relayed and time.monotonic() < deadline:
            relayed_cv.wait(timeout=max(0.0, deadline - time.monotonic()))
        got = relayed[0] if relayed else None
    decision_id, end_ns, result = got if got is not None else ("", None, {})
    queue_records = _queue_records_for(queue_path, decision_id) if decision_id else []
    first = queue_records[0] if queue_records else {}
    durable_ns = first.get("decision_durable_monotonic_ns")
    durable_ns = durable_ns if isinstance(durable_ns, int) and not isinstance(durable_ns, bool) else None
    chain_hash = str(first.get("decision_chain_hash") or "")
    record = _chain_record(chain_path, chain_hash) if chain_hash else {}
    trace = record.get("decision_trace") if isinstance(record.get("decision_trace"), dict) else {}
    received_ns = record.get("agent_received_monotonic_ns")
    received_ns = received_ns if isinstance(received_ns, int) and not isinstance(received_ns, bool) else None
    ingest_epoch = record.get("core_ingest_epoch")
    received_epoch = record.get("agent_received_epoch")
    row = {
        "sample_id": decision_id or f"so03-sid-{sid}",
        "start_monotonic_ns": append_ns,
        "end_monotonic_ns": end_ns,
        "elapsed_ms": None,
        "start_event": "harness appended the EVE alert line the core decides on (CLOCK_MONOTONIC before the append: an upper bound of the core's decision instant)",
        "end_event": "P0AlertQueue enqueue of the visual and voice entries naming the decision, fsynced (relay reported after the fsync)",
        "action": record.get("action"),
        "reason": record.get("reason"),
        "decision_suspicion_label": trace.get("suspicion_label"),
        "decision_chain_hash": chain_hash,
        "decision_source": record.get("source"),
        "core_pipeline": record.get("core_pipeline"),
        "core_sid": record.get("sid"),
        "harness_sid": sid,
        "harness_expected_action": expected,
        "core_decided_action": record.get("decided_action"),
        "core_enforcement_mode": record.get("enforcement_mode"),
        "core_effective_action": record.get("effective_action"),
        "harness_eve_append_monotonic_ns": append_ns,
        "edge_decision_durable_monotonic_ns": durable_ns,
        # Diagnostics (not the verdict): where the time went.
        "diag_core_poll_and_decision_ms": _ms((ingest_epoch - append_epoch) * 1e3) if isinstance(ingest_epoch, (int, float)) else None,
        "diag_core_to_agent_ms": _ms((received_epoch - ingest_epoch) * 1e3) if isinstance(received_epoch, (int, float)) and isinstance(ingest_epoch, (int, float)) else None,
        "diag_agent_receive_to_durable_ms": _ms((durable_ns - received_ns) / 1e6) if durable_ns is not None and received_ns is not None else None,
        "diag_durable_to_enqueue_ms": _ms((end_ns - durable_ns) / 1e6) if durable_ns is not None and end_ns is not None else None,
        "queue_records": queue_records,
        "enqueue_result_durability": result.get("durability"),
        "decision_record_fsynced": _inode(chain_path) in synced,
        "enqueue_record_fsynced": bool(result.get("p0")) and _inode(queue_path) in synced,
    }
    if result.get("ok") and result.get("p0") and so03_end_observed(row):
        row["elapsed_ms"] = round((row["end_monotonic_ns"] - row["start_monotonic_ns"]) / 1e6, 3)
    else:
        # No durable enqueue record for this decision was observed: the end
        # event never happened; the sample is unfinished.
        row["end_monotonic_ns"] = None
    return row


def _run_core(core: Path, work: Path, socket_path: Path, samples: int, take, info: Dict[str, Any]) -> List[Dict[str, Any]]:  # type: ignore[no-untyped-def]
    rows: List[Dict[str, Any]] = []
    eve = work / "eve.json"
    eve.write_text("", encoding="utf-8")
    stderr_path = work / "core.stderr"
    with stderr_path.open("w", encoding="utf-8") as err_fh:
        proc = subprocess.Popen([str(core)], cwd=str(work), env=core_environment(work, socket_path), stdout=subprocess.DEVNULL, stderr=err_fh)
        try:
            info["core_started"] = _wait(
                lambda: "azazel-edge-core started" in stderr_path.read_text(encoding="utf-8", errors="replace"), START_WAIT_S
            ) and proc.poll() is None
            if info["core_started"]:
                for i in range(int(samples)):
                    rows.append(take(i, eve))
        finally:
            info["core_exited_before_harness_stopped_it"] = proc.poll()
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"defense_enforce=(\w+), defense_dry_run=(\w+)", stderr_text)
    info["core_reported_enforce"] = f"enforce={m.group(1)} dry_run={m.group(2)}" if m else None
    return rows


def _measure(core: Path, samples: int, rng: random.Random, synced: List[tuple], work: Path, info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Start the agent service and the core, take the samples, stop both."""

    from azazel_edge.audit import P0AuditLogger

    rows: List[Dict[str, Any]] = []
    agent_env = agent_environment(work)
    socket_path = Path(agent_env["AZAZEL_AI_SOCKET"])
    script = agent_service_script()
    info["agent_script"] = str(script.relative_to(REPO_ROOT))
    stop = threading.Event()
    with _environ(agent_env):
        agent = load_agent_service(script)
        chain_path = Path(agent.CORE_DECISION_AUDIT_PATH)
        queue_path = Path(agent.P0_ALERT_QUEUE_PATH)
        server = threading.Thread(target=agent._serve, args=(stop,), name="so03-agent-service", daemon=True)
        server.start()
        try:
            started = _wait(lambda: socket_path.exists() and agent.CORE_RECORDER is not None, START_WAIT_S)
            relay = agent.CORE_P0_RELAY
            info["agent_relay_attached"] = bool(
                started and relay is not None and relay.ready.wait(START_WAIT_S) and agent.CORE_RECORDER.ready.wait(START_WAIT_S)
            )
            if not info["agent_relay_attached"]:
                return rows

            relayed: List[tuple] = []
            relayed_cv = threading.Condition()

            def on_relayed(decision_id: str, result: Dict[str, Any]) -> None:
                # The relay thread, once per relayed decision record, after any
                # enqueue (and its fsync) returned.
                now = time.monotonic_ns()
                with relayed_cv:
                    relayed.append((decision_id, now, result))
                    relayed_cv.notify_all()

            relay.on_relayed = on_relayed  # observation only

            def take(i: int, eve: Path) -> Dict[str, Any]:
                return _sample(i, rng, eve, chain_path, queue_path, synced, relayed, relayed_cv)

            rows = _run_core(core, work, socket_path, samples, take, info)
        finally:
            relay = agent.CORE_P0_RELAY
            recorder = agent.CORE_RECORDER
            if recorder is not None:
                recorder.wait_idle(5.0)
                recorder.stop(5.0)
                info["recorder_counters"] = recorder.metrics()
            if relay is not None:
                try:
                    agent.CORE_DECISION_AUDIT.wait_durable_listeners(5.0)
                    relay.wait_idle(5.0)
                    relay.stop(5.0)
                except Exception:
                    pass
                info["relay_counters"] = relay.metrics()
            stop.set()
            server.join(timeout=5)
            info["chain"] = P0AuditLogger.verify_chain(chain_path)
            sys.modules.pop(agent.__name__, None)
    return rows


def run(*, core_bin: Optional[Path] = None, samples: int = REQUIRED_SAMPLES, seed: Optional[int] = None) -> Dict[str, Any]:
    from azazel_edge.notify.p0_alert import P0_RULE, QUEUE_SCHEMA

    spec = spec_for("SO-03", "decision_durable_to_alert_enqueued")
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    rng = random.Random(seed)
    core = Path(core_bin or os.environ.get("AZAZEL_EDGE_CORE_BIN") or DEFAULT_CORE_BIN).resolve()
    version = _version(core) if core.is_file() and os.access(core, os.X_OK) else None
    rows: List[Dict[str, Any]] = []
    info: Dict[str, Any] = {}
    if version is not None:
        with tempfile.TemporaryDirectory(prefix="so03-") as tmp, _watch_fsync() as synced:
            rows = _measure(core, samples, rng, synced, Path(tmp), info)
    try:
        full_queue = _full_queue_enqueue_latency()
    except Exception as exc:  # diagnostic only; never part of the verdict
        full_queue = {"max_entries": 0, "append_ms": float("nan"), "compact_ms": float("nan"), "error": str(exc)}

    chain = info.get("chain") or {}
    counters = info.get("relay_counters") or {}
    observed = so03_observed_prerequisites(rows)
    ended = sum(1 for r in rows if so03_end_observed(r))
    kinds = sorted({str(r.get("action")) for r in rows})
    modes = sorted({str(r.get("core_enforcement_mode")) for r in rows})
    candidates = [
        prerequisite(
            "core_binary_present",
            version is not None,
            f"{core}: version {version}" if version else f"{core}: missing or not runnable (build rust/azazel-edge-core first)",
        ),
        prerequisite(
            "core_daemon_started",
            bool(info.get("core_started")),
            f"core started with the {CORE_UNIT.relative_to(REPO_ROOT)} Environment (paths in a scratch directory); "
            f"reported {info.get('core_reported_enforce')}; exit status before the harness stopped it: {info.get('core_exited_before_harness_stopped_it')}",
        ),
        prerequisite(
            "agent_service_relay_attached",
            bool(info.get("agent_relay_attached")),
            f"{info.get('agent_script', '?')} (the ExecStart of {AGENT_UNIT.relative_to(REPO_ROOT)}) started with its own _serve; "
            f"P0 relay attached to its core decision chain: {bool(info.get('agent_relay_attached'))}",
        ),
        prerequisite(
            "core_enforcement_not_applied",
            observed["core_enforcement_not_applied"],
            f"core enforcement modes seen: {', '.join(modes) or 'none'} (the harness never applies enforcement)",
        ),
        prerequisite(
            "visual_voice_delivery_queue_declared",
            observed["visual_voice_delivery_queue_declared"],
            f"P0AlertQueue ({QUEUE_SCHEMA}), channels visual+voice; samples with one entry per channel: "
            f"{sum(1 for r in rows if len(r.get('queue_records') or []) == 2)}/{len(rows)}",
        ),
        prerequisite(
            "enqueue_record_names_decision_id",
            observed["enqueue_record_names_decision_id"],
            f"samples whose two queue entries name the core decision, its chain hash, its durable instant and its "
            f"enforcement mode, stamped inside the sample window: {ended}/{len(rows)}",
        ),
        prerequisite(
            "enqueue_record_classifies_p0",
            observed["enqueue_record_classifies_p0"],
            f"queue entries classified P0 under {P0_RULE}, recomputed from the core's action; actions sampled: {', '.join(kinds)}",
        ),
        prerequisite(
            "decision_and_enqueue_records_fsynced",
            observed["decision_and_enqueue_records_fsynced"],
            f"samples whose decision record and queue file were fsynced before the event was taken; relay counters {counters}",
        ),
        prerequisite(
            "alert_audit_chain_verifies",
            bool(chain.get("ok")) and int(chain.get("entries") or 0) == len(rows) and bool(rows),
            f"core decision chain verify_chain: ok={chain.get('ok')} entries={chain.get('entries')} (expected {len(rows)}) {chain.get('error') or ''}".strip(),
        ),
    ]
    prerequisites = [p for p in candidates if p["id"] in spec["prerequisites"]]
    all_gaps = [
        gap(
            "SO03-NO-VISUAL-VOICE-QUEUE",
            "Not every sample ended on a durable P0AlertQueue enqueue record on both the visual and voice channel.",
            refs=["py/azazel_edge/notify/p0_alert.py"],
        ),
        gap(
            "SO03-NO-P0-ALERT-PATH",
            "Not every sample's alert was built from its audit-chain decision record and classified P0 by "
            + P0_RULE + ".",
            refs=["py/azazel_edge/notify/p0_alert.py", "py/azazel_edge/audit/logger.py"],
        ),
        gap(
            "SO03-P0-RELAY-NOT-WIRED-FOR-CORE-DECISIONS",
            "Not every sample's alert came from a Rust core decision (the authoritative path, Edge#412) received by the AI "
            "agent service and relayed with what the core did with it.",
            refs=["Edge#412", "py/azazel_edge_ai/agent.py", "rust/azazel-edge-core/src/main.rs"],
        ),
    ]
    # A gap is left out only when the validator's own recomputation closes it.
    gaps = [
        g for g in all_gaps
        if g["id"] in spec["gaps"]
        and not (g["id"] in spec.get("gaps_closed_by_samples", ()) and g["id"] in GAP_CLOSERS and GAP_CLOSERS[g["id"]](rows))
    ]
    part = build_part(
        name="decision_durable_to_alert_enqueued",
        pass_rule={
            "kind": RULE_EVERY_SAMPLE_MAX,
            "bound_ms": spec["bound_ms"],
            "description": "every sample <= 2 seconds; behaviour under hostile load is SO-11's, not a relaxation here",
        },
        required_samples=spec["required_samples"],
        samples=rows,
        prerequisites=prerequisites,
        gaps=gaps,
    )
    def _summary(field: str) -> str:
        vals = sorted(r[field] for r in rows if isinstance(r.get(field), (int, float)))
        return f"{field} median {vals[len(vals) // 2]:.3f} ms max {vals[-1]:.3f} ms" if vals else f"{field} no value"

    diagnostics = "; ".join(_summary(f) for f in (
        "diag_core_poll_and_decision_ms", "diag_core_to_agent_ms", "diag_agent_receive_to_durable_ms", "diag_durable_to_enqueue_ms",
    ))
    return build_record(
        objective_id=OBJECTIVE_ID,
        title=TITLE,
        started_monotonic_ns=started_ns,
        started_at=started_at,
        product_configuration={
            "product": "azazel-edge",
            "decision_path": {
                "core_binary": str(core),
                "core_version": version,
                "core_unit": str(CORE_UNIT.relative_to(REPO_ROOT)),
                "core_decision_source": SO03_CORE_DECISION_SOURCE,
                "core_pipeline": SO03_CORE_PIPELINE,
                "enforcement": "the core unit's values: AZAZEL_DEFENSE_ENFORCE=false, AZAZEL_DEFENSE_DRY_RUN=true; the harness never applies enforcement",
            },
            "alert_path": {
                "receiver": f"{AGENT_UNIT.relative_to(REPO_ROOT)} ExecStart script, started with its _serve",
                "composed_by": "azazel_edge_ai.agent._start_core_p0_path: attach_p0_alert_relay on the core decision P0AuditLogger",
                "queue": QUEUE_SCHEMA,
                "channels": ["visual", "voice"],
                "p0_rule": P0_RULE,
                "output_devices": "none: rendering and speaking are downstream of the queue and out of scope",
            },
            "load": "nominal: one EVE alert at a time, the next after the previous one's enqueue; core poll interval as the unit leaves it (default)",
            "interface_identity": "not_applicable: no interface is involved in this row",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "source": "time.monotonic_ns() on the Edge host: the agent's audit logger stamps the durable decision, the harness reads the end after the queue fsync",
            "note": "one host; the agent runs in the harness process, the core in its own; the Edge durable stamp is checked to lie between the EVE append and the end",
        },
        sample_rule={"required_samples": spec["required_samples"], "taken": len(rows), "load": "nominal"},
        parts=[part],
        method="real Rust azazel-edge-core binary + AI agent service script (P0AuditLogger core decision chain, P0AlertRelay/P0AlertQueue), start stamped by the logger, end after the queue fsync",
        notes=[
            "action_decision records are fsynced (DURABLE_KINDS); the P0 queue append is fsynced before the relay reports it.",
            "diagnostic, not the verdict (the two first are wall clock, the others monotonic): " + diagnostics,
            f"recorder counters {info.get('recorder_counters') or {}}",
            "diagnostic, not a sample: enqueue latency on a full queue (max_entries=%d): append at the bound %.3f ms, "
            "append that compacts at 2x the bound %.3f ms" % (full_queue["max_entries"], full_queue["append_ms"], full_queue["compact_ms"]),
            "the P0 path is observation and notification only: the core decides and acts before it forwards, it forwards without waiting, "
            "and a failure in the agent's record or relay never reaches the core.",
        ],
    )
