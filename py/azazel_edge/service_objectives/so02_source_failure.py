"""SO-02: source/interface failure visible on the operator surface (every sample <= 10 s).

Definition (assignment section 3, SO-02):

* start -- the instant the harness injects the failure (capture-interface link
  down, capture process death, or feed source made unreachable); the harness
  timestamps its own injection;
* end -- the read-only operator status surface reports that source as failed
  or unavailable when polled;
* clock -- the harness host's monotonic clock; the harness both injects and polls;
* samples -- 20 injections covering every declared source type;
* pass -- every sample <= 10 seconds;
* class -- virtual-lab for the logical source types. The physical-NIC variant
  is hardware-only (R7); this record is never evidence for it.

What is measured
----------------
Edge's own stack, unmodified and on its default timings, inside two network
namespaces the harness creates (nothing is changed in the namespace it runs in):

* the control daemon (``py/azazel_edge_control/daemon.py``) -- its snapshot
  refresh and NOC projection;
* the web UI under gunicorn, started as ``systemd/azazel-edge-web.service``
  starts it, polled at ``GET /api/state`` with a viewer-role token -- the
  read-only surface the dashboard reads;
* Suricata capturing on ``br0`` (Edge's default ``SURICATA_IFACE`` and internal
  monitor bridge), with an empty rule file.

Two logical source types are injected, alternately, ten times each:

``capture_process_death``
    SIGKILL to the Suricata process. Edge names it failed when
    ``monitoring.suricata`` reads ``OFF``.
``capture_interface_link_down``
    The far end of ``br0``'s only port is set down (carrier loss, as a cable
    pull). Edge names it failed when ``noc_blast_radius.affected_uplinks``
    lists ``br0``.

Before each injection the surface must show both sources healthy on a poll
begun after the previous recovery. The end is the first poll *begun after the
injection* whose response names the source failed; its instant is read when
that response has been received. A sample with no such poll within
``SAMPLE_TIMEOUT_S`` never ended and counts against the pass rule.

Why the row is still ``not_measurable``
---------------------------------------
* ``SO02-NOT-NEXUS-INTEGRATED`` -- the definition's configuration is Edge
  integrated into a Nexus Core install; none exists. This is standalone Edge.
* ``SO02-SOURCE-TYPES-UNDECLARED`` -- Edge declares no list of source types, so
  "every declared source type" cannot be shown; no feed source type is
  declared or injected.
* ``SO02-NO-COMMISSIONED-INTERFACE-IDENTITY`` -- Edge has no commissioning
  record; the interface is named by its kernel name.

Safety
------
Needs root and ``ip netns``. The harness refuses (``not_measurable``, nothing
started) if a Suricata is already running, its pidfile exists, or a lab
namespace from an earlier run is left over, so it never kills a live node's
capture. It also refuses without PyYAML, and before starting the control
daemon it asks the daemon's own ``load_control_flags()`` (in the lab
environment) and stops unless ``suppress_auto_wifi`` is ``false``. Without
that the daemon would run ``nmcli`` against the host's NetworkManager. The
dev-only healthy-baseline override is removed from every child's environment.

Teardown blocks SIGTERM/SIGINT/SIGHUP, stops every process found inside the
lab namespaces by network-namespace inode (so a daemonized Suricata whose pid
was never read is stopped too), removes ``/run/suricata.pid`` only if it names
a Suricata the harness started, and deletes both namespaces. A harness killed
with SIGKILL cannot clean up; the namespaces remain and the next run refuses.

Process death is detected through the pidfile path (the lab has no systemd);
the production ``systemctl is-active`` path is not measured. Only the total
from injection to the surface is measured; wall-clock stage stamps, and the
NOC collection behind the end response (its trigger, CLOCK_MONOTONIC start and
per-collector timings from ``noc_runtime.collection``), are kept per sample for
diagnosis and never read for the verdict.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .record import (
    REPO_ROOT,
    RULE_EVERY_SAMPLE_MAX,
    SO02_CAPTURE_INTERFACE,
    SO02_CAPTURE_PROCESS,
    SO02_LAB_SOURCE_TYPES,
    SO02_PER_SOURCE_TYPE_SAMPLES,
    SO02_SURFACE,
    build_part,
    build_record,
    gap,
    prerequisite,
    so02_failure_observed,
    so02_observed_prerequisites,
    spec_for,
    utc_now,
)

OBJECTIVE_ID = "SO-02"
TITLE = "Source/interface failure visible (within 10 seconds)"
SPEC = spec_for("SO-02", "source_failure_visible")
BOUND_MS = SPEC["bound_ms"]
REQUIRED_SAMPLES = SPEC["required_samples"]

CAPTURE_IFACE = SO02_SURFACE[SO02_CAPTURE_INTERFACE]["source_id"]
# Edge's internal-scope defaults (daemon._resolve_monitor_scope).
EDGE_ADDR = "172.16.0.1/24"
INTERNAL_TARGET = "172.16.0.254"
# Targets of the NOC path probes (noc_monitor.EXTERNAL_PATH_TARGETS), answered
# inside the lab by the peer namespace so a healthy baseline exists.
PATH_TARGETS = ("1.1.1.1", "8.8.8.8")
SURICATA_PIDFILE = Path("/run/suricata.pid")  # the path the web surface reads
SURICATA_CONFIG = Path("/etc/suricata/suricata.yaml")
WEB_PORT = 8084  # systemd/azazel-edge-web.service; inside the lab namespace
POLL_INTERVAL_S = 0.1
BASELINE_TIMEOUT_S = 300.0
SAMPLE_TIMEOUT_S = 120.0
STACK_START_TIMEOUT_S = 120.0
CMD_TIMEOUT_S = 20.0

_POLLER = r"""
import json, sys, time, urllib.request
port, token = sys.argv[1], sys.argv[2]
req = urllib.request.Request("http://127.0.0.1:%s/api/state" % port, headers={"X-AZAZEL-TOKEN": token})
while True:
    s = time.monotonic_ns()
    row = {"s": s, "w": time.time()}
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        mon = body.get("monitoring") if isinstance(body.get("monitoring"), dict) else {}
        blast = body.get("noc_blast_radius") if isinstance(body.get("noc_blast_radius"), dict) else None
        row.update(ok=True, suricata=mon.get("suricata"),
                   uplinks=blast.get("affected_uplinks") if blast is not None else None,
                   source=body.get("source"), snapshot_epoch=body.get("snapshot_epoch"),
                   noc_updated_epoch=(body.get("noc_runtime") or {}).get("updated_epoch") if isinstance(body.get("noc_runtime"), dict) else None,
                   noc_collection=(body.get("noc_runtime") or {}).get("collection") if isinstance(body.get("noc_runtime"), dict) else None)
    except Exception as exc:
        row.update(ok=False, err=type(exc).__name__ + ": " + str(exc)[:200])
    row["e"] = time.monotonic_ns()
    sys.stdout.write(json.dumps(row) + "\n")
    sys.stdout.flush()
    time.sleep(__INTERVAL__)
""".replace("__INTERVAL__", repr(POLL_INTERVAL_S))


def _run(argv: List[str], timeout: float = CMD_TIMEOUT_S) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "timed out")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


PROC_ROOT = Path("/proc")
NETNS_ROOT = Path("/run/netns")
LAB_NETNS_PREFIXES = ("so02e-", "so02p-")


def _suricata_processes() -> List[int]:
    pids = []
    for entry in PROC_ROOT.glob("[0-9]*"):
        try:
            cmd = (entry / "cmdline").read_bytes().split(b"\0")[0]
        except OSError:
            continue
        if Path(cmd.decode("utf-8", "replace")).name.startswith("suricata"):
            pids.append(int(entry.name))
    return pids


def _leftover_lab_netns() -> List[str]:
    try:
        return sorted(p.name for p in NETNS_ROOT.iterdir() if p.name.startswith(LAB_NETNS_PREFIXES))
    except OSError:
        return []


def _pids_in_netns(ns_path: Path) -> List[int]:
    """Every process whose network namespace is the one at ``ns_path``."""

    try:
        st = os.stat(ns_path)
    except OSError:
        return []
    want = (st.st_dev, st.st_ino)
    pids = []
    for entry in PROC_ROOT.glob("[0-9]*"):
        try:
            nst = os.stat(entry / "ns" / "net")
        except OSError:
            continue
        if (nst.st_dev, nst.st_ino) == want:
            pids.append(int(entry.name))
    return pids


def preflight() -> Dict[str, Any]:
    """What the lab needs, checked before anything is created or started."""

    problems: List[str] = []
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        problems.append("not root: the lab needs network namespaces")
    tools = {name: shutil.which(name) for name in ("ip", "suricata", "ping")}
    problems.extend(f"{name} not found" for name, path in tools.items() if not path)
    if not SURICATA_CONFIG.exists():
        problems.append(f"{SURICATA_CONFIG} missing")
    gunicorn = _run([sys.executable, "-c", "import gunicorn; print(gunicorn.__version__)"])
    if gunicorn.returncode != 0:
        problems.append("gunicorn not importable by this interpreter")
    # Without PyYAML the control daemon ignores the lab's first_minute.yaml and
    # suppresses auto Wi-Fi with nmcli, which reaches the host's NetworkManager.
    if _run([sys.executable, "-c", "import yaml"]).returncode != 0:
        problems.append("PyYAML not importable: the daemon could not read suppress_auto_wifi: false")
    version = ""
    if tools["suricata"]:
        out = _run([tools["suricata"], "-V"])
        version = (out.stdout or out.stderr).strip().splitlines()[0] if (out.stdout or out.stderr).strip() else ""
    live: List[str] = []
    if SURICATA_PIDFILE.exists():
        live.append(f"{SURICATA_PIDFILE} exists")
    running = _suricata_processes()
    if running:
        live.append(f"suricata already running (pid {running})")
    leftover = _leftover_lab_netns()
    if leftover:
        live.append(f"lab namespaces left by an earlier run (killed with SIGKILL?): {leftover}")
    if shutil.which("systemctl"):
        for unit in ("suricata.service", "azazel-edge-suricata.service"):
            if _run(["systemctl", "is-active", unit], timeout=5).stdout.strip() == "active":
                live.append(f"{unit} active")
    return {
        "problems": problems,
        "live_capture": live,
        "suricata_version": version,
        "gunicorn_version": gunicorn.stdout.strip(),
        "tools": tools,
    }


class _Poller:
    """Polls the surface from inside the lab namespace; keeps every response."""

    def __init__(self, proc: subprocess.Popen):
        self.proc = proc
        self.rows: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                with self.lock:
                    self.rows.append(row)

    def since(self, index: int) -> List[Dict[str, Any]]:
        with self.lock:
            return self.rows[index:]

    def count(self) -> int:
        with self.lock:
            return len(self.rows)

    def wait_for(self, predicate: Callable[[Dict[str, Any]], bool], *, begun_after_ns: int, timeout_s: float) -> tuple:
        """First poll begun at or after ``begun_after_ns`` satisfying ``predicate``.

        Returns (row or None, polls seen, poll errors seen)."""

        deadline = time.monotonic() + timeout_s
        cursor, seen, errors = 0, 0, 0
        while True:
            rows = self.since(cursor)
            cursor += len(rows)
            for row in rows:
                if not isinstance(row.get("s"), int) or row["s"] < begun_after_ns:
                    continue
                seen += 1
                if not row.get("ok"):
                    errors += 1
                    continue
                if predicate(row):
                    return row, seen, errors
            if time.monotonic() >= deadline or self.proc.poll() is not None:
                return None, seen, errors
            time.sleep(0.02)


def _healthy(row: Dict[str, Any]) -> bool:
    uplinks = row.get("uplinks")
    return row.get("suricata") == "ON" and isinstance(uplinks, list) and CAPTURE_IFACE not in uplinks


def _failed(source_type: str) -> Callable[[Dict[str, Any]], bool]:
    if source_type == SO02_CAPTURE_PROCESS:
        return lambda row: row.get("suricata") == "OFF"
    return lambda row: isinstance(row.get("uplinks"), list) and CAPTURE_IFACE in row["uplinks"]


def _bounded_collection(value: Any) -> Optional[Dict[str, Any]]:
    """The NOC collection view as the surface returned it, bounded: a dict
    with at most 16 collector rows of scalar fields, or None."""

    if not isinstance(value, dict):
        return None

    def scalar(v: Any) -> Any:
        return v if v is None or isinstance(v, (bool, int, float)) else str(v)[:64]

    collectors = [
        {k: scalar(row.get(k)) for k in ("collector", "started_offset_ms", "duration_ms", "outcome")}
        for row in (value.get("collectors") if isinstance(value.get("collectors"), list) else [])[:16]
        if isinstance(row, dict)
    ]
    return {
        "trigger": scalar(value.get("trigger")),
        "started_monotonic_ns": scalar(value.get("started_monotonic_ns")),
        "duration_ms": scalar(value.get("duration_ms")),
        "collectors": collectors,
    }


def _surface_value(source_type: str, row: Optional[Dict[str, Any]]) -> Any:
    if row is None:
        return None
    return row.get("suricata") if source_type == SO02_CAPTURE_PROCESS else row.get("uplinks")


class _Lab:
    def __init__(self, work: Path, suricata_bin: str):
        tag = secrets.token_hex(3)
        self.edge_ns = f"so02e-{tag}"
        self.peer_ns = f"so02p-{tag}"
        self.work = work
        self.suricata_bin = suricata_bin
        self.token = secrets.token_hex(16)
        self.procs: List[subprocess.Popen] = []
        self.suricata_pid: Optional[int] = None
        self.netns_created: List[str] = []
        self.started_pids: List[int] = []  # every Suricata pid this lab started
        self.env = self._env()

    def _env(self) -> Dict[str, str]:
        w = self.work
        for sub in ("home", "run", "log", "rules", "suricata-log"):
            (w / sub).mkdir(parents=True, exist_ok=True)
        (w / "rules" / "azazel-lite.rules").write_text("", encoding="utf-8")
        (w / "first_minute.yaml").write_text("suppress_auto_wifi: false\n", encoding="utf-8")
        (w / "auth_tokens.json").write_text(
            json.dumps({"tokens": [{"token": self.token, "principal": "so02-harness", "role": "viewer"}]}), encoding="utf-8"
        )
        os.chmod(w / "auth_tokens.json", 0o600)
        # A fresh environment: nothing inherited, so the dev-only
        # AZAZEL_DEV_HEALTHY_BASELINE and AZAZEL_DEMO_FAST cannot leak in and
        # every timing is Edge's default.
        return {
            "PATH": os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
            "HOME": str(w / "home"),
            "LANG": "C.UTF-8",
            "PYTHONPATH": f"{REPO_ROOT}:{REPO_ROOT / 'py'}",
            "AZAZEL_CONTROL_SOCKET": str(w / "run" / "control.sock"),
            "AZAZEL_UI_SNAPSHOT": str(w / "run" / "ui_snapshot.json"),
            "AZAZEL_AUTH_TOKENS_FILE": str(w / "auth_tokens.json"),
            "AZAZEL_FIRST_MINUTE_CONFIG": str(w / "first_minute.yaml"),
            "AZAZEL_AUTHZ_AUDIT_LOG": str(w / "log" / "authz-events.jsonl"),
            "AZAZEL_AI_EVENT_LOG": str(w / "log" / "ai-events.jsonl"),
            "AZAZEL_RUNBOOK_EVENT_LOG": str(w / "log" / "runbook-events.jsonl"),
            "AZAZEL_SOT_AUDIT_LOG": str(w / "log" / "sot-events.jsonl"),
            "AZAZEL_AGGREGATOR_AUDIT_LOG": str(w / "log" / "aggregator-events.jsonl"),
            # ntfy is not part of this row; point its health probe at loopback
            # so a probe to the default management address cannot stall polls.
            "MGMT_IP": "127.0.0.1",
        }

    def _ip(self, *args: str) -> subprocess.CompletedProcess:
        return _run(["ip", *args])

    def _check(self, out: subprocess.CompletedProcess, what: str) -> None:
        if out.returncode != 0:
            raise RuntimeError(f"{what}: {(out.stderr or out.stdout).strip()[:300]}")

    def build(self) -> None:
        e, p = self.edge_ns, self.peer_ns
        for ns in (e, p):
            self._check(self._ip("netns", "add", ns), f"netns add {ns}")
            self.netns_created.append(ns)
        steps = [
            ("-n", e, "link", "set", "lo", "up"),
            ("-n", p, "link", "set", "lo", "up"),
            ("-n", e, "link", "add", CAPTURE_IFACE, "type", "bridge"),
            ("-n", e, "link", "add", "so02cap0", "type", "veth", "peer", "name", "so02peer0", "netns", p),
            ("-n", e, "link", "set", "so02cap0", "master", CAPTURE_IFACE),
            ("-n", e, "addr", "add", EDGE_ADDR, "dev", CAPTURE_IFACE),
            ("-n", e, "link", "set", "so02cap0", "up"),
            ("-n", e, "link", "set", CAPTURE_IFACE, "up"),
            # Edge's default NOC down interface; present so the collector runs.
            ("-n", e, "link", "add", "usb0", "type", "dummy"),
            ("-n", e, "link", "set", "usb0", "up"),
            ("-n", p, "addr", "add", f"{INTERNAL_TARGET}/24", "dev", "so02peer0"),
            *[("-n", p, "addr", "add", f"{t}/32", "dev", "so02peer0") for t in PATH_TARGETS],
            ("-n", p, "link", "set", "so02peer0", "up"),
            ("-n", e, "route", "add", "default", "via", INTERNAL_TARGET, "dev", CAPTURE_IFACE),
        ]
        for step in steps:
            self._check(self._ip(*step), "ip " + " ".join(step))

    def _spawn(self, name: str, argv: List[str], **kw: Any) -> subprocess.Popen:
        log = open(self.work / "log" / f"{name}.log", "ab")
        proc = subprocess.Popen(
            ["ip", "netns", "exec", self.edge_ns, "env", "-i", *[f"{k}={v}" for k, v in self.env.items()], *argv],
            cwd=str(REPO_ROOT),
            stderr=log,
            stdout=kw.pop("stdout", log),
            start_new_session=True,
            **kw,
        )
        self.procs.append(proc)
        return proc

    def verify_daemon_flags(self) -> str:
        """Ask the daemon's own load_control_flags, in the lab environment,
        whether it reads suppress_auto_wifi: false. Raises unless it does."""

        code = (
            "import json, sys; sys.path.insert(0, sys.argv[1]); import yaml, daemon; "
            "print(json.dumps(daemon.load_control_flags()))"
        )
        out = _run(
            ["ip", "netns", "exec", self.edge_ns, "env", "-i", *[f"{k}={v}" for k, v in self.env.items()],
             sys.executable, "-c", code, str(REPO_ROOT / "py" / "azazel_edge_control")],
            timeout=60,
        )
        try:
            flags = json.loads(out.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            flags = None
        if not isinstance(flags, dict) or flags.get("suppress_auto_wifi") is not False:
            raise RuntimeError(f"daemon would suppress auto Wi-Fi (flags={flags!r}, rc={out.returncode}); not started")
        return "load_control_flags() -> suppress_auto_wifi: false"

    def start_stack(self) -> str:
        verified = self.verify_daemon_flags()
        self._spawn("control-daemon", [sys.executable, str(REPO_ROOT / "py" / "azazel_edge_control" / "daemon.py")])
        self._spawn(
            "web",
            [
                sys.executable, "-m", "gunicorn", "--workers", "2", "--threads", "4", "--graceful-timeout", "5",
                "--bind", f"127.0.0.1:{WEB_PORT}", "--chdir", str(REPO_ROOT),
                "--pythonpath", f"{REPO_ROOT}:{REPO_ROOT / 'py'}", "azazel_edge_web.app:app",
            ],
        )
        return verified

    def start_poller(self) -> _Poller:
        proc = self._spawn("poller", [sys.executable, "-I", "-c", _POLLER, str(WEB_PORT), self.token], stdout=subprocess.PIPE, text=True)
        return _Poller(proc)

    def start_suricata(self) -> bool:
        if SURICATA_PIDFILE.exists():
            # Only a pidfile naming a Suricata this lab started, and which is
            # gone, may be replaced; anything else is not ours.
            if not self._pidfile_is_ours(dead_only=True):
                return False
            SURICATA_PIDFILE.unlink()
        out = _run(
            [
                "ip", "netns", "exec", self.edge_ns, "env", "-i", f"PATH={self.env['PATH']}",
                self.suricata_bin, "-c", str(SURICATA_CONFIG), "-i", CAPTURE_IFACE,
                "-S", str(self.work / "rules" / "azazel-lite.rules"), "-l", str(self.work / "suricata-log"),
                "--pidfile", str(SURICATA_PIDFILE), "--set", "unix-command.enabled=no", "-D",
            ],
            timeout=60,
        )
        if out.returncode != 0:
            return False
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                pid = int(SURICATA_PIDFILE.read_text().strip())
                os.kill(pid, 0)
                self.suricata_pid = pid
                self.started_pids.append(pid)
                return True
            except (OSError, ValueError):
                time.sleep(0.1)
        return False

    def _pidfile_is_ours(self, dead_only: bool = False) -> bool:
        try:
            pid = int(SURICATA_PIDFILE.read_text().strip())
        except (OSError, ValueError):
            return False
        if pid not in self.started_pids:
            return False
        if dead_only:
            try:
                return "suricata" not in (PROC_ROOT / str(pid) / "cmdline").read_bytes().decode("utf-8", "replace")
            except OSError:
                return True
        return True

    def inject(self, source_type: str) -> None:
        if source_type == SO02_CAPTURE_PROCESS:
            if self.suricata_pid is None:
                raise RuntimeError("no Suricata to kill")
            os.kill(self.suricata_pid, signal.SIGKILL)
        else:
            self._check(self._ip("-n", self.peer_ns, "link", "set", "so02peer0", "down"), "link down")

    def recover(self, source_type: str) -> bool:
        if source_type == SO02_CAPTURE_PROCESS:
            pid = self.suricata_pid
            self.suricata_pid = None
            if pid is not None:
                _reap(pid)
            return self.start_suricata()
        return self._ip("-n", self.peer_ns, "link", "set", "so02peer0", "up").returncode == 0

    def teardown(self) -> None:
        """Stop everything the lab started. SIGTERM/SIGINT/SIGHUP are blocked
        while it runs so a second signal cannot abort the cleanup. A harness
        killed with SIGKILL cannot clean up: its namespaces (and the processes
        in them) remain, and the next run's preflight refuses until they are
        removed."""

        blocked = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
        try:
            old = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        except (AttributeError, ValueError, OSError):
            old = None
        try:
            self._teardown()
        finally:
            if old is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, old)

    def _teardown(self) -> None:
        for proc in reversed(self.procs):
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except OSError:
                    pass
        for proc in reversed(self.procs):
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        # Whatever still runs inside the lab namespaces -- a daemonized
        # Suricata whose pid was never read, or one started by a failed
        # recovery -- is found by its network namespace, not by a pid we hold.
        for ns in self.netns_created:
            for sig, wait in ((signal.SIGTERM, 10.0), (signal.SIGKILL, 5.0)):
                pids = [p for p in _pids_in_netns(NETNS_ROOT / ns) if p != os.getpid()]
                for pid in pids:
                    try:
                        os.kill(pid, sig)
                    except OSError:
                        pass
                for pid in pids:
                    _reap(pid, timeout=wait)
        self.suricata_pid = None
        if SURICATA_PIDFILE.exists() and self._pidfile_is_ours():
            try:
                SURICATA_PIDFILE.unlink()
            except OSError:
                pass
        for ns in reversed(self.netns_created):
            self._ip("netns", "del", ns)
        self.netns_created = []


def _reap(pid: int, timeout: float = 5.0) -> None:
    """Wait for a daemonized (not our child) process to disappear."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.05)


def _measure(lab: _Lab, poller: _Poller, samples: int, rows: List[Dict[str, Any]]) -> None:
    """Append one row per injection to ``rows`` (kept if a later step raises)."""

    recovered_at = time.monotonic_ns()
    for i in range(int(samples)):
        source_type = SO02_LAB_SOURCE_TYPES[i % len(SO02_LAB_SOURCE_TYPES)]
        entry = SO02_SURFACE[source_type]
        base_row, _, _ = poller.wait_for(_healthy, begun_after_ns=recovered_at, timeout_s=BASELINE_TIMEOUT_S)
        row: Dict[str, Any] = {
            "sample_id": f"so02-{source_type}-{i:02d}",
            "start_monotonic_ns": None,
            "end_monotonic_ns": None,
            "elapsed_ms": None,
            "start_event": "harness injection, stamped on CLOCK_MONOTONIC immediately before it is issued",
            "end_event": f"response received for the first GET /api/state begun after the injection whose {entry['field']} names {entry['source_id']} failed",
            "source_type": source_type,
            "source_id": entry["source_id"],
            "injection": "SIGKILL to the Suricata process" if source_type == SO02_CAPTURE_PROCESS
            else f"far end of {CAPTURE_IFACE}'s only port set down (carrier loss)",
            "surface": f"GET /api/state on the Edge web UI (gunicorn), viewer-role token",
            "surface_field": entry["field"],
            "baseline_healthy": base_row is not None,
            "baseline_poll_started_monotonic_ns": base_row["s"] if base_row else None,
            "baseline_surface_value": _surface_value(source_type, base_row),
            "end_poll_started_monotonic_ns": None,
            "end_surface_value": None,
            "polls_after_injection": 0,
            "poll_errors_after_injection": 0,
            "recovered": False,
            # Diagnostic stage stamps (wall clock, never used for the verdict).
            "injection_wall_epoch": None,
            "end_noc_updated_epoch": None,
            "end_snapshot_epoch": None,
            # The NOC collection behind the end response: its trigger, start
            # (CLOCK_MONOTONIC, same host clock as the injection stamp) and
            # per-collector timings. Diagnostic; never read for the verdict.
            "end_noc_collection": None,
        }
        if base_row is None:
            # No healthy baseline: nothing is injected, the sample never ends,
            # and measuring stops (the shortfall keeps the row not measurable).
            row["start_monotonic_ns"] = time.monotonic_ns()
            rows.append(row)
            return
        row["injection_wall_epoch"] = time.time()
        start_ns = time.monotonic_ns()
        lab.inject(source_type)
        row["start_monotonic_ns"] = start_ns
        end_row, seen, errors = poller.wait_for(_failed(source_type), begun_after_ns=start_ns, timeout_s=SAMPLE_TIMEOUT_S)
        row["polls_after_injection"] = seen
        row["poll_errors_after_injection"] = errors
        if end_row is not None:
            row["end_poll_started_monotonic_ns"] = end_row["s"]
            row["end_surface_value"] = _surface_value(source_type, end_row)
            row["end_monotonic_ns"] = end_row["e"]
            row["end_noc_updated_epoch"] = end_row.get("noc_updated_epoch")
            row["end_snapshot_epoch"] = end_row.get("snapshot_epoch")
            row["end_noc_collection"] = _bounded_collection(end_row.get("noc_collection"))
            if so02_failure_observed(row):
                row["elapsed_ms"] = round((end_row["e"] - start_ns) / 1e6, 3)
            else:
                row["end_monotonic_ns"] = None
        rows.append(row)
        row["recovered"] = lab.recover(source_type)
        recovered_at = time.monotonic_ns()


def run(*, samples: int = REQUIRED_SAMPLES, seed: Optional[int] = None) -> Dict[str, Any]:
    """Run the lab. ``seed`` is accepted for CLI symmetry; injections alternate deterministically."""

    del seed
    started_ns = time.monotonic_ns()
    started_at = utc_now()
    pre = preflight()
    built, stack_ok, stack_detail, build_detail = False, False, "not started", "; ".join(pre["problems"]) or "ok"
    rows: List[Dict[str, Any]] = []
    lab: Optional[_Lab] = None
    notes: List[str] = []
    previous = {}

    def _stop(signum, frame):  # noqa: ARG001
        raise SystemExit(128 + signum)

    if not pre["problems"] and not pre["live_capture"]:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            try:
                previous[sig] = signal.signal(sig, _stop)
            except ValueError:  # not the main thread
                pass
        with tempfile.TemporaryDirectory(prefix="so02-") as tmp:
            lab = _Lab(Path(tmp), pre["tools"]["suricata"])
            try:
                lab.build()
                if not lab.start_suricata():
                    raise RuntimeError("Suricata did not start on the lab capture interface")
                built = True
                build_detail = f"namespaces {lab.edge_ns}/{lab.peer_ns}; {CAPTURE_IFACE} bridge with one veth port; {pre['suricata_version']}"
                notes.append("control daemon flags checked before start: " + lab.start_stack())
                poller = lab.start_poller()
                first, _, _ = poller.wait_for(_healthy, begun_after_ns=started_ns, timeout_s=STACK_START_TIMEOUT_S)
                stack_ok = first is not None
                stack_detail = (
                    f"healthy surface after {round((first['e'] - started_ns) / 1e9, 1)} s (source={first.get('source')})"
                    if first else f"no healthy poll within {STACK_START_TIMEOUT_S} s; last: {poller.since(max(0, poller.count() - 1))}"
                )
                if stack_ok:
                    _measure(lab, poller, samples, rows)
                    notes.append(f"surface polls taken: {poller.count()}")
            except RuntimeError as exc:
                notes.append(f"harness stopped early: {exc}")
                if not built:
                    build_detail = str(exc)
                elif not stack_ok:
                    stack_detail = str(exc)
            finally:
                lab.teardown()
                for sig, handler in previous.items():
                    signal.signal(sig, handler)

    observed = so02_observed_prerequisites(rows)
    per_type = {t: sum(1 for r in rows if r["source_type"] == t) for t in SO02_LAB_SOURCE_TYPES}
    prerequisites = [
        prerequisite("lab_built", built, build_detail),
        prerequisite(
            "no_live_capture_touched",
            not pre["live_capture"],
            "refused: " + "; ".join(pre["live_capture"]) if pre["live_capture"] else "no Suricata, pidfile or active unit before the run",
        ),
        prerequisite("edge_stack_answering", stack_ok, stack_detail),
        prerequisite(
            "every_injection_from_healthy_baseline",
            observed["every_injection_from_healthy_baseline"],
            f"samples injected from a healthy surface: {sum(1 for r in rows if r['baseline_healthy'])}/{len(rows)}",
        ),
        prerequisite(
            "every_lab_source_type_sampled",
            observed["every_lab_source_type_sampled"],
            f"per lab source type (need {SO02_PER_SOURCE_TYPE_SAMPLES} each): {per_type}",
        ),
    ]
    gaps = [
        gap(
            "SO02-NOT-NEXUS-INTEGRATED",
            "The definition measures Edge as integrated into a Nexus Core install, with the operator surface "
            "present. No Nexus install exists (SO-01 is deferred to R7); this is standalone Edge in a lab namespace.",
            refs=["01rabbit/Azazel:docs/roadmaps/service-objective-assignments.md section 5"],
        ),
        gap(
            "SO02-SOURCE-TYPES-UNDECLARED",
            "Edge declares no list of source types, so 'every declared source type' cannot be shown. The lab "
            "covers the two whose failure the surface names by source today. No feed source type is declared; "
            "candidates (SOC visibility stale_sources from the AI agent's second pass, aggregator node freshness "
            "with stale_after 60 s by default) are not injected here. Which types count is the owner's decision.",
            refs=["azazel_edge_web/app.py", "py/azazel_edge/evaluators/soc.py", "py/azazel_edge/aggregator.py"],
        ),
        gap(
            "SO02-NO-COMMISSIONED-INTERFACE-IDENTITY",
            "Edge has no commissioning record, so the capture interface is named by its kernel name "
            f"({CAPTURE_IFACE}), not by a commissioned composite interface identity.",
            refs=["docs/X86_64_INTEGRATION_BOUNDARY.md"],
        ),
    ]
    part = build_part(
        name="source_failure_visible",
        pass_rule={
            "kind": RULE_EVERY_SAMPLE_MAX,
            "bound_ms": SPEC["bound_ms"],
            "description": "every sample <= 10 seconds from injection to the surface naming the source failed",
        },
        required_samples=SPEC["required_samples"],
        samples=rows,
        prerequisites=prerequisites,
        gaps=gaps,
    )
    return build_record(
        objective_id=OBJECTIVE_ID,
        title=TITLE,
        started_monotonic_ns=started_ns,
        started_at=started_at,
        product_configuration={
            "product": "azazel-edge",
            "row_class": SPEC["row_class"],
            "hardware_evidence": False,
            "physical_variant": "hardware-only (R7); not measured by this record and never gated by it",
            "integration": "standalone Edge; not integrated into a Nexus Core install",
            "surface": "GET /api/state, azazel_edge_web.app under gunicorn (2 workers x 4 threads), viewer-role token",
            "components": {
                "control_daemon": "py/azazel_edge_control/daemon.py, default timings (AZAZEL_DEMO_FAST unset)",
                "capture": pre["suricata_version"] or "absent",
                "capture_rules": "empty rule file",
                "gunicorn": pre["gunicorn_version"] or "absent",
                "liveness_probe": "no systemd in the lab: the surface reads Suricata liveness from /run/suricata.pid",
            },
            "lab": {
                "capture_interface": CAPTURE_IFACE,
                "topology": f"{CAPTURE_IFACE} bridge {EDGE_ADDR} with one veth port; peer namespace answers "
                f"{INTERNAL_TARGET} and {', '.join(PATH_TARGETS)}; dummy usb0",
                "source_types": list(SO02_LAB_SOURCE_TYPES),
            },
            "interface_identity": f"not commissioned: kernel name {CAPTURE_IFACE}; Edge has no commissioning record",
        },
        clock={
            "name": "CLOCK_MONOTONIC",
            "source": "time.monotonic_ns() on the harness host: the injection stamp and every poll stamp",
            "note": "the poller runs inside the lab network namespace on the same host; CLOCK_MONOTONIC is not namespaced",
        },
        sample_rule={
            "required_samples": SPEC["required_samples"],
            "taken": len(rows),
            "per_source_type": per_type,
            "order": "alternating source types, each injection from a surface showing both sources healthy",
        },
        parts=[part],
        method="real control daemon + web UI + Suricata in a lab netns; harness injects and polls the surface",
        notes=notes
        + [
            "virtual-lab: a regression signal for the logical source types, never hardware evidence.",
            f"a sample with no failed poll within {SAMPLE_TIMEOUT_S} s never ended and counts as a violation.",
        ],
    )
