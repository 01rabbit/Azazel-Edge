#!/usr/bin/env python3
"""Edge-driven integrated functional test across AZ-06 Deception and Knowledge.

Azazel-Edge is the main driver. This harness exercises, from Edge's own
clients, the two integration seams Edge owns end-to-end on localhost — no
containers, no attacker, no production, zero enforcement:

  SHADOW / REPLAY  (Edge -> AZ-06 Azazel-Deception Host)
    Edge's ``Az06ShadowClient`` runs the full non-executing bootstrap session
    (capabilities -> package identity -> descriptive plan -> local shadow
    evaluation -> activation/termination rehearsal) and then a ``HeartbeatLoop``
    proves steady-state liveness + reconciliation. AZ-06 starts nothing and
    enforces nothing; every response is verified ``descriptive_only`` /
    ``enforcement_applied=False``.

  EFFECTIVENESS  (AZ-06 -> Edge -> Knowledge, advisory-only)
    AZ-06 records fact-only ``InteractionObservation`` records; Edge's
    ``KnowledgeIngestClient`` relays the batch to Knowledge; the Knowledge
    single-writer worker drains it into the immutable observation table; Edge's
    ``EffectivenessAdvisoryReader`` reads back a fail-closed-verified,
    non-executable ``EffectivenessAdvisory``.

Two run modes:

  * one-command (default): the harness starts the AZ-06 shadow server
    in-process (``ShadowReplayHTTPServer``) and the Knowledge API + worker as
    subprocesses, drives everything, and tears them down. Requires the sibling
    ``azazel_deception`` and ``azazel_knowledge`` packages importable plus
    Fabric v0.6.0. Point at the checkouts with ``--deception-root`` /
    ``--knowledge-root`` or the matching env vars.

  * manual: start the other systems yourself (see the printed procedures or
    docs/architecture/edge-integration-functional-test.md) and point the
    harness at them:
        AZ06_SHADOW_URL=http://127.0.0.1:8071 \
        AZ06_SHADOW_KEY=dev-shared-key AZ06_NODE_ID=az06-shadow-dev \
        AZ_KNOWLEDGE_URL=http://127.0.0.1:8072 \
        AZ_KNOWLEDGE_TOKEN=azcti_... \
        python tools/edge_integration_functional_test.py --manual
    In manual mode nothing is started or stopped; the effectiveness worker
    drain is your responsibility unless you also pass --knowledge-root (so the
    harness can run ``worker --once`` against the same AZAZEL_ROOT).

Exit 0 means both seams interlocked from Edge's side.

Run:
    python tools/edge_integration_functional_test.py            # one-command
    python tools/edge_integration_functional_test.py --manual   # external servers
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

REPO_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = REPO_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

# Edge is the driver: everything below is imported from Edge's own clients.
from azazel_edge.deception_shadow_client import (  # noqa: E402
    Az06ShadowClient,
    HeartbeatLoop,
    ShadowTransportError,
)
from azazel_edge.deception_effectiveness_client import (  # noqa: E402
    EffectivenessAdvisoryReader,
    KnowledgeAuthConfig,
    KnowledgeIngestClient,
    fabric_available,
)

ENV_ID = "env-edge-func-test"
EDGE_NODE_ID = "edge-func-test"
SHADOW_KEY = "edge-az06-func-key"
AZ06_NODE_ID = "az06-func-node"
REFERENCE_PACKAGE = "examples/packages/municipal-linux-v1/package.yaml"
REFERENCE_COMPOSE = "runtime/compose/reference-linux.compose.yaml"


def _log(msg: str) -> None:
    print(f"[edge-func] {msg}", flush=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, *, timeout: float = 30.0, any_http: bool = False) -> None:
    """Block until ``url`` answers HTTP. Only connection failures count as down.

    With ``any_http`` set, *any* HTTP status (including 501/405 for a
    POST-only endpoint like AZ-06's ``/shadow``) proves the server is routing;
    otherwise a 5xx is treated as not-yet-ready (Knowledge health path).
    """
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if any_http or r.getcode() < 500:
                    return
        except urllib.error.HTTPError as exc:
            # An HTTP status of any kind proves the server is up and routing.
            if any_http or exc.code < 500:
                return
            last = exc
        except Exception as exc:  # noqa: BLE001 - liveness probe only
            last = exc
        time.sleep(0.3)
    raise RuntimeError(f"server never became ready at {url}: {last}")


# ---------------------------------------------------------------------------
# Deception (AZ-06) side: repo discovery + fact-only observation authoring.
# ---------------------------------------------------------------------------

def _deception_root(args: argparse.Namespace) -> Path:
    candidate = (
        args.deception_root
        or os.environ.get("DECEPTION_ROOT")
        or (REPO_ROOT.parent / "Azazel-Deception")
    )
    root = Path(candidate).resolve()
    if not (root / REFERENCE_PACKAGE).exists():
        raise RuntimeError(
            f"azazel-deception checkout not found at {root} "
            f"(pass --deception-root or set DECEPTION_ROOT)"
        )
    return root


def _knowledge_root(args: argparse.Namespace) -> Path | None:
    candidate = args.knowledge_root or os.environ.get("KNOWLEDGE_ROOT")
    if not candidate:
        default = REPO_ROOT.parent / "Azazel-Knowledge"
        candidate = str(default) if (default / "azctl").exists() else None
    if not candidate:
        return None
    root = Path(candidate).resolve()
    if not (root / "azctl").exists():
        raise RuntimeError(f"azazel-knowledge checkout not found at {root}")
    return root


def _prepare_shadow_package(deception_root: Path, tmp: Path) -> Path:
    """Load the reference package, mark one component verified, reseal digest."""
    from azazel_deception.package import calculate_package_digest, load_package

    package = load_package(deception_root / REFERENCE_PACKAGE)
    for component in package["components"]:
        component["image"]["verified"] = component["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    path = tmp / "package.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    return path


def _build_observations(deception_root: Path, state_root: Path) -> list[dict]:
    """AZ-06 side: record a small attacker episode as fact-only observations."""
    from azazel_deception.package import load_package, parse_package
    from azazel_deception.planner import build_placement_plan
    from azazel_deception.runtime.observation import (
        InteractionObserver,
        build_runtime_context,
    )
    from azazel_deception.runtime.observation_export import export_observations
    from azazel_deception.runtime.state import RuntimeStateStore
    from azazel_fabric.deception_contracts import PlacementPlan

    raw = load_package(deception_root / REFERENCE_PACKAGE)
    package = parse_package(raw)
    host = {
        "node_id": "az06-func", "architecture": "amd64", "cpu_cores": 4,
        "memory_mb": 8192, "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "kvm_available": False, "gpu_available": False,
    }
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, host, requested_tier="lite", edge_decision_id="edge-func-1")
    )
    state = RuntimeStateStore(state_root)
    observer = InteractionObserver(
        state, environment_id=ENV_ID, package_id=package.package_id,
        node_id=plan.node_id, runtime_context=build_runtime_context(package, plan),
    )
    observer.record(observation_class="interaction", surface="port")
    observer.record(
        observation_class="reaction", surface="credential_lure",
        reaction_kind="authenticate", lure_id="lure-municipal-admin",
        first_contact_latency_ms=900, attempt_count=2,
    )
    observer.record(
        observation_class="outcome", surface="file", reaction_kind="exfiltrate",
        dwell_ms=42000, attempt_count=4,
    )
    observer.record(
        observation_class="interaction", surface="port",
        confounder_tags=["scanner_noise"],
    )
    return export_observations(state, ENV_ID)


# ---------------------------------------------------------------------------
# Edge decision builders (normally the Action Arbiter's job).
# ---------------------------------------------------------------------------

def _activation_decision(package: dict, capabilities: dict, plan: dict) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": plan["edge_decision_id"],
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": package["package_id"],
        "package_digest": package["package_digest"],
        "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": {
            "cpu_cores": 2, "memory_mb": 1024, "storage_mb": 2048,
            "max_connections": 100, "max_duration_seconds": 300,
            "bandwidth_kbps": 5000,
        },
        "safety": {
            "outbound_allowed": False, "production_access": False,
            "privileged_containers": False, "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "effective_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [],
        "reason_codes": ["edge-func-shadow"],
    }


def _termination_decision(environment_id: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-termination-decision/v0.1",
        "decision_id": "edge-func-terminate-1",
        "decision_authority": "azazel-edge",
        "environment_id": environment_id,
        "reason": "shadow_rehearsal_complete",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "evidence_refs": [],
    }


# ---------------------------------------------------------------------------
# Fixtures: AZ-06 shadow server (in-process) and Knowledge API+worker.
# ---------------------------------------------------------------------------

class _ShadowServerHandle:
    def __init__(self, base_url: str, node_id: str, key: str, stop=None) -> None:
        self.base_url = base_url
        self.node_id = node_id
        self.key = key
        self._stop = stop

    def stop(self) -> None:
        if self._stop is not None:
            self._stop()


@contextlib.contextmanager
def _shadow_server(args: argparse.Namespace, tmp: Path) -> Iterator[_ShadowServerHandle]:
    """Yield a live AZ-06 shadow endpoint, in-process or already-external."""
    if args.manual:
        base = os.environ.get("AZ06_SHADOW_URL")
        if not base:
            raise RuntimeError("--manual requires AZ06_SHADOW_URL")
        key = os.environ.get("AZ06_SHADOW_KEY", SHADOW_KEY)
        node_id = os.environ.get("AZ06_NODE_ID", AZ06_NODE_ID)
        _wait_http(f"{base.rstrip('/')}/shadow", any_http=True)  # POST-only: 501/405 is fine.
        _log(f"shadow: using external AZ-06 at {base} (node_id={node_id})")
        yield _ShadowServerHandle(base.rstrip("/"), node_id, key)
        return

    from azazel_deception.runtime.shadow_server import (
        ShadowReplayHTTPServer,
        ShadowReplayService,
    )

    deception_root = _deception_root(args)
    package_path = _prepare_shadow_package(deception_root, tmp)
    service = ShadowReplayService(
        node_id=AZ06_NODE_ID,
        transport_key=SHADOW_KEY,
        allowed_edge_ids=[EDGE_NODE_ID],
        package_path=package_path,
        state_root=tmp / "shadow-state",
        compose_file=deception_root / REFERENCE_COMPOSE,
    )
    server = ShadowReplayHTTPServer(service)
    server.start()
    host, port = server.address
    base = f"http://{host}:{port}"
    _log(f"shadow: started in-process AZ-06 at {base} (node_id={AZ06_NODE_ID})")
    try:
        yield _ShadowServerHandle(base, AZ06_NODE_ID, SHADOW_KEY, stop=server.stop)
    finally:
        server.stop()


class _KnowledgeHandle:
    def __init__(self, base_url: str, token: str | None, root: Path | None,
                 config_dir: Path | None, env: dict[str, str] | None) -> None:
        self.base_url = base_url
        self.token = token
        self.root = root
        self.config_dir = config_dir
        self.env = env

    def drain_worker(self) -> None:
        """Run the single-writer worker once, if we own the Knowledge node."""
        if self.root is None or self.config_dir is None or self.env is None:
            _log("effectiveness: manual mode — assuming external worker drains the spool")
            return
        subprocess.run(
            [sys.executable, "-m", "azazel_knowledge.worker",
             "--root", str(self.root), "--config-dir", str(self.config_dir), "--once"],
            cwd=str(self.root), env=self.env, text=True,
            capture_output=True, timeout=120, check=True,
        )
        _log("effectiveness: Knowledge worker drained the ingest spool")


@contextlib.contextmanager
def _knowledge(args: argparse.Namespace) -> Iterator[_KnowledgeHandle]:
    """Yield a live Knowledge endpoint, provisioning+serving it or external."""
    knowledge_root = _knowledge_root(args)

    if args.manual:
        base = os.environ.get("AZ_KNOWLEDGE_URL")
        if not base:
            raise RuntimeError("--manual requires AZ_KNOWLEDGE_URL")
        token = os.environ.get("AZ_KNOWLEDGE_TOKEN") or None
        _wait_http(f"{base.rstrip('/')}/v1/health")
        _log(f"effectiveness: using external Knowledge at {base}")
        # If a checkout + AZAZEL_ROOT are provided we can still drive the worker.
        root_env = os.environ.get("AZAZEL_ROOT")
        config_env = os.environ.get("AZAZEL_CONFIG_DIR")
        if knowledge_root is not None and root_env and config_env:
            worker_env = dict(os.environ)
            yield _KnowledgeHandle(
                base.rstrip("/"), token, Path(root_env), Path(config_env), worker_env
            )
        else:
            yield _KnowledgeHandle(base.rstrip("/"), token, None, None, None)
        return

    if knowledge_root is None:
        raise RuntimeError(
            "one-command mode needs the azazel-knowledge checkout "
            "(pass --knowledge-root or set KNOWLEDGE_ROOT)"
        )

    config_dir = knowledge_root / "config"
    env = dict(os.environ)
    root = Path(tempfile.mkdtemp(prefix="az-edge-func-"))
    env["AZAZEL_ROOT"] = str(root)
    env["AZAZEL_CONFIG_DIR"] = str(config_dir)

    _log(f"effectiveness: provisioning Knowledge node at {root}")
    subprocess.run(
        [sys.executable, "azctl", "provision", "--root", str(root),
         "--config-dir", str(config_dir)],
        cwd=str(knowledge_root), env=env, text=True,
        capture_output=True, timeout=120, check=True,
    )
    added = subprocess.run(
        [sys.executable, "azctl", "client", "add", "--root", str(root),
         "--config-dir", str(config_dir), "--key-id", "edge1",
         "--scopes", "ingest,read"],
        cwd=str(knowledge_root), env=env, text=True,
        capture_output=True, timeout=120, check=True,
    )
    m = re.search(r"token.*?:\s*(azcti_\S+)", added.stdout)
    if not m:
        raise RuntimeError("failed to parse client token:\n" + added.stdout)
    token = m.group(1)
    _log("effectiveness: minted edge client token")

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "azazel_knowledge.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(knowledge_root), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        _wait_http(f"{base}/v1/health")
        _log(f"effectiveness: Knowledge API live at {base}")
        yield _KnowledgeHandle(base, token, root, config_dir, env)
    finally:
        app.terminate()
        try:
            app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill()


# ---------------------------------------------------------------------------
# The two Edge-driven seams.
# ---------------------------------------------------------------------------

def _run_shadow_seam(shadow: _ShadowServerHandle) -> None:
    """Edge drives the bootstrap session + heartbeat loop against AZ-06."""
    if not fabric_available():
        raise RuntimeError("Fabric deception contracts unavailable (need v0.6.0)")

    client = Az06ShadowClient(
        shadow.base_url,
        transport_key=shadow.key,
        edge_node_id=EDGE_NODE_ID,
        az06_node_id=shadow.node_id,
    )

    _log("shadow: running non-executing bootstrap session (Az06ShadowClient)")
    trace = client.run_bootstrap_session(
        edge_decision_id="edge-func-decision-1",
        requested_tier="lite",
        environment_id=ENV_ID,
        build_activation_decision=_activation_decision,
        termination_decision=_termination_decision(ENV_ID),
    )
    steps = [s["step"] for s in trace["steps"]]
    assert trace["outcome"] == "shadow_complete", trace["outcome"]
    assert trace["enforcement_applied"] is False
    assert trace["container_start_count"] == 0
    assert steps == ["capabilities", "package", "plan",
                     "shadow_activate", "shadow_terminate"], steps
    assert trace["capability_snapshot"]["authority"] == "descriptive_only"
    assert trace["local_shadow_evaluation"]["status"] == "would_accept"
    assert trace["simulated_activation"]["live_execution"] is False
    _log(f"shadow: bootstrap OK — steps={steps} enforcement_applied=False "
         f"container_starts=0")

    _log("shadow: proving steady-state heartbeat + reconcile (HeartbeatLoop)")
    active: list[str] = []
    divergences: list[dict] = []
    loop = HeartbeatLoop(
        client,
        interval_seconds=0.2,
        edge_active_environment_ids=lambda: list(active),
        on_divergence=divergences.append,
    )
    loop.start()
    try:
        if not loop.wait_until_healthy(timeout=10.0):
            raise RuntimeError(f"heartbeat never healthy: {loop.last_error}")
        _log("shadow: heartbeat healthy (authenticated, reconciled, consistent)")
    finally:
        loop.stop()
    assert loop.failure_count == 0, loop.last_error


def _run_effectiveness_seam(
    deception_root: Path, knowledge: _KnowledgeHandle
) -> dict:
    """AZ-06 emits facts; Edge relays to Knowledge; Edge reads the advisory."""
    with tempfile.TemporaryDirectory(prefix="az06-obs-") as dstate:
        observations = _build_observations(deception_root, Path(dstate))
    _log(f"effectiveness: AZ-06 exported {len(observations)} fact-only observations")

    auth = KnowledgeAuthConfig(token=knowledge.token)
    ingest = KnowledgeIngestClient(
        knowledge.base_url, edge_node_id=EDGE_NODE_ID, auth=auth
    )
    relay = ingest.submit_observations(observations)
    _log(f"effectiveness: Edge relay status={relay.status} "
         f"submitted={relay.submitted_count}")
    if relay.status not in {"accepted", "backpressure"}:
        raise RuntimeError(f"relay did not succeed: {relay}")

    knowledge.drain_worker()

    reader = EffectivenessAdvisoryReader(knowledge.base_url, auth=auth)
    result = reader.get_advisory(ENV_ID)
    if result.advisory is None:
        raise RuntimeError(f"no advisory available (reason={result.reason})")
    adv = result.advisory

    # Doctrine invariants Edge's fail-closed reader must have upheld.
    assert adv["authority"] == "advisory_only", adv["authority"]
    assert adv["executable"] is False
    assert adv["environment_id"] == ENV_ID
    assert 0.0 <= adv["confidence"] <= 1.0
    assert adv["counter_evidence"], "expected scanner-noise confounder counter-evidence"
    _log("effectiveness: advisory verified — advisory_only, non-executable, "
         "confounder-aware")
    return adv


def _print_manual_procedures() -> None:
    print(__doc__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Edge-driven integrated functional test (shadow + effectiveness)"
    )
    parser.add_argument(
        "--manual", action="store_true",
        help="drive externally-running servers (AZ06_SHADOW_URL / AZ_KNOWLEDGE_URL)",
    )
    parser.add_argument("--deception-root", type=Path, default=None)
    parser.add_argument("--knowledge-root", type=Path, default=None)
    parser.add_argument(
        "--only", choices=["shadow", "effectiveness"], default=None,
        help="run just one seam instead of both",
    )
    parser.add_argument(
        "--print-procedures", action="store_true",
        help="print the manual-mode startup procedures and exit",
    )
    args = parser.parse_args(argv)

    if args.print_procedures:
        _print_manual_procedures()
        return 0

    deception_root = _deception_root(args)
    _log(f"driver = Azazel-Edge  (deception_root={deception_root})")

    tmpdir = Path(tempfile.mkdtemp(prefix="edge-func-"))
    try:
        with contextlib.ExitStack() as stack:
            shadow = None
            knowledge = None
            if args.only != "effectiveness":
                shadow = stack.enter_context(_shadow_server(args, tmpdir))
            if args.only != "shadow":
                knowledge = stack.enter_context(_knowledge(args))

            if shadow is not None:
                _run_shadow_seam(shadow)
            if knowledge is not None:
                adv = _run_effectiveness_seam(deception_root, knowledge)
                print("\n[edge-func] ===== EffectivenessAdvisory (advisory-only) =====")
                print(json.dumps(adv, indent=2, ensure_ascii=False))
                print("[edge-func] ==================================================\n")
    except (AssertionError, RuntimeError, ShadowTransportError) as exc:
        _log(f"FAIL: {exc.__class__.__name__}: {exc}")
        return 1
    finally:
        with contextlib.suppress(Exception):
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    _log("OK — Edge drove AZ-06 shadow/replay + heartbeat and the "
         "Deception->Edge->Knowledge effectiveness loop; both interlocked.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
