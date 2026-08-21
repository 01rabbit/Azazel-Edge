#!/usr/bin/env python3
"""T5 multi-environment isolation drill — per-env advisories + reconcile.

Two decoy environments run at once. This proves Edge keeps them separate on
both seams it owns:

  Effectiveness (AZ-06 -> Edge -> Knowledge)
    I1 advisory isolation  facts recorded under env-A and env-B produce
                           advisories scoped to each environment_id; neither
                           advisory's counts bleed into the other.
    I2 store isolation     the immutable table holds each environment's rows
                           under its own environment_id, no cross-landing.

  Shadow reconcile (Edge -> AZ-06)
    I3 divergence          Edge claims an active set AZ-06 has no local state
                           for; AZ-06 reports it as edge-only divergence
                           (consistent=False), descriptively — it reconciles
                           nothing itself.
    I4 consistent          when Edge's active set matches AZ-06's (both empty
                           in shadow), reconcile reports consistent=True.

One-command: starts the Knowledge API + worker as subprocesses and an in-process
AZ-06 shadow server. Requires the sibling azazel_deception / azazel_knowledge
checkouts importable plus Fabric v0.6.0 and the Knowledge api extra.

Run:  python tools/multi_env_isolation_drill.py
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = REPO_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.deception_shadow_client import Az06ShadowClient  # noqa: E402
from azazel_edge.deception_effectiveness_client import (  # noqa: E402
    EffectivenessAdvisoryReader,
    KnowledgeAuthConfig,
    KnowledgeIngestClient,
)

ENV_A = "env-t5-alpha"
ENV_B = "env-t5-bravo"
EDGE_NODE_ID = "edge-t5"
SHADOW_KEY = "t5-shadow-key"
AZ06_NODE_ID = "az06-t5-node"
REFERENCE_PACKAGE = "examples/packages/municipal-linux-v1/package.yaml"
REFERENCE_COMPOSE = "runtime/compose/reference-linux.compose.yaml"

_SYNTHETIC_CAPS = {
    "node_id": AZ06_NODE_ID, "architecture": "amd64", "cpu_cores": 4,
    "memory_mb": 8192, "storage_free_mb": 65536,
    "runtime_adapters": {"docker_compose": True},
    "kvm_available": False, "gpu_available": False,
}

results: list[tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}", flush=True)


def _log(msg: str) -> None:
    print(f"[t5] {msg}", flush=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.getcode() < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last = exc
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.3)
    raise RuntimeError(f"server never ready at {url}: {last}")


def _root(args, attr, envvar, sibling, marker):
    cand = getattr(args, attr) or os.environ.get(envvar) or (REPO_ROOT.parent / sibling)
    root = Path(cand).resolve()
    if not (root / marker).exists():
        raise SystemExit(f"{sibling} checkout not found at {root}")
    return root


def _observer(deception_root: Path, state, environment_id: str):
    from azazel_deception.package import load_package, parse_package
    from azazel_deception.planner import build_placement_plan
    from azazel_deception.runtime.observation import InteractionObserver, build_runtime_context
    from azazel_fabric.deception_contracts import PlacementPlan

    raw = load_package(deception_root / REFERENCE_PACKAGE)
    package = parse_package(raw)
    host = {"node_id": "az06-t5", "architecture": "amd64", "cpu_cores": 4,
            "memory_mb": 8192, "storage_free_mb": 65536,
            "runtime_adapters": {"docker_compose": True},
            "kvm_available": False, "gpu_available": False}
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, host, requested_tier="lite", edge_decision_id="edge-t5-1"))
    return InteractionObserver(
        state, environment_id=environment_id, package_id=package.package_id,
        node_id=plan.node_id, runtime_context=build_runtime_context(package, plan))


def _db_count(root: Path, environment_id: str) -> int:
    db = root / "data" / "db" / "local.db"
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(
            "SELECT COUNT(*) FROM deception_observation WHERE environment_id=?",
            (environment_id,)).fetchone()[0]
    finally:
        con.close()


def _synthetic_caps():
    from azazel_fabric.deception_contracts import HostCapabilities
    return HostCapabilities.model_validate(_SYNTHETIC_CAPS).model_dump(mode="json")


def _effectiveness_isolation(deception_root: Path, knowledge_root: Path) -> None:
    from azazel_deception.runtime.observation_export import export_observations
    from azazel_deception.runtime.state import RuntimeStateStore

    env = dict(os.environ)
    root = Path(tempfile.mkdtemp(prefix="az-t5-"))
    config_dir = knowledge_root / "config"
    env["AZAZEL_ROOT"] = str(root)
    env["AZAZEL_CONFIG_DIR"] = str(config_dir)

    def _run(cmd):
        return subprocess.run(cmd, cwd=str(knowledge_root), env=env, text=True,
                              capture_output=True, timeout=120, check=True)

    _log(f"provisioning Knowledge node at {root}")
    _run([sys.executable, "azctl", "provision", "--root", str(root), "--config-dir", str(config_dir)])
    added = _run([sys.executable, "azctl", "client", "add", "--root", str(root),
                  "--config-dir", str(config_dir), "--key-id", "edge1", "--scopes", "ingest,read"])
    token = re.search(r"token.*?:\s*(azcti_\S+)", added.stdout).group(1)

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "azazel_knowledge.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(knowledge_root), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    state_dir = Path(tempfile.mkdtemp(prefix="az06-t5-state-"))
    try:
        _wait_http(f"{base}/v1/health")
        auth = KnowledgeAuthConfig(token=token)
        ingest = KnowledgeIngestClient(base, edge_node_id=EDGE_NODE_ID, auth=auth)
        reader = EffectivenessAdvisoryReader(base, auth=auth)
        state = RuntimeStateStore(state_dir)

        # env-A: two facts. env-B: three (different) facts.
        oa = _observer(deception_root, state, ENV_A)
        oa.record(observation_class="interaction", surface="port")
        oa.record(observation_class="reaction", surface="credential_lure",
                  reaction_kind="authenticate", lure_id="a", attempt_count=1)
        ob = _observer(deception_root, state, ENV_B)
        ob.record(observation_class="interaction", surface="port")
        ob.record(observation_class="outcome", surface="file",
                  reaction_kind="exfiltrate", dwell_ms=20000, attempt_count=2)
        ob.record(observation_class="reaction", surface="credential_lure",
                  reaction_kind="enumerate", lure_id="b", attempt_count=1)

        ingest.submit_observations(export_observations(state, ENV_A))
        ingest.submit_observations(export_observations(state, ENV_B))
        subprocess.run([sys.executable, "-m", "azazel_knowledge.worker", "--root", str(root),
                        "--config-dir", str(config_dir), "--once"],
                       cwd=str(knowledge_root), env=env, text=True,
                       capture_output=True, timeout=120, check=True)

        adv_a = reader.get_advisory(ENV_A).advisory or {}
        adv_b = reader.get_advisory(ENV_B).advisory or {}
        ca = adv_a.get("metadata", {}).get("observation_count")
        cb = adv_b.get("metadata", {}).get("observation_count")
        _record("I1 advisory isolation (per-env scoping, no bleed)",
                adv_a.get("environment_id") == ENV_A and adv_b.get("environment_id") == ENV_B
                and ca == 2 and cb == 3,
                f"A(env={adv_a.get('environment_id')} count={ca}) "
                f"B(env={adv_b.get('environment_id')} count={cb})")

        na, nb = _db_count(root, ENV_A), _db_count(root, ENV_B)
        _record("I2 store isolation (rows scoped by environment_id)",
                na == 2 and nb == 3, f"rows env-A={na} env-B={nb}")
    finally:
        app.terminate()
        try:
            app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill()
        import shutil
        shutil.rmtree(state_dir, ignore_errors=True)


def _reconcile_divergence(deception_root: Path) -> None:
    from azazel_deception.runtime.shadow_server import ShadowReplayHTTPServer, ShadowReplayService
    from azazel_deception.package import calculate_package_digest, load_package

    tmp = Path(tempfile.mkdtemp(prefix="az06-t5-shadow-"))
    package = load_package(deception_root / REFERENCE_PACKAGE)
    for c in package["components"]:
        c["image"]["verified"] = c["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    import json
    ppath = tmp / "package.json"
    ppath.write_text(json.dumps(package), encoding="utf-8")

    service = ShadowReplayService(
        node_id=AZ06_NODE_ID, transport_key=SHADOW_KEY, allowed_edge_ids=[EDGE_NODE_ID],
        package_path=ppath, state_root=tmp / "state",
        compose_file=deception_root / REFERENCE_COMPOSE,
        capability_provider=_synthetic_caps)
    server = ShadowReplayHTTPServer(service)
    server.start()
    try:
        host, port = server.address
        client = Az06ShadowClient(f"http://{host}:{port}", transport_key=SHADOW_KEY,
                                  edge_node_id=EDGE_NODE_ID, az06_node_id=AZ06_NODE_ID)
        # Edge asserts a ghost environment is active; AZ-06 (shadow, nothing
        # running) must report it as edge-only divergence.
        resp = client.reconcile(["env-t5-ghost"])
        div = resp.get("result", {}).get("divergence", {})
        _record("I3 reconcile divergence (edge-only ghost env reported)",
                resp.get("status") == "ok" and div.get("consistent") is False
                and "env-t5-ghost" in (div.get("edge_only_active") or []),
                f"consistent={div.get('consistent')} edge_only={div.get('edge_only_active')}")

        # Matching (both empty) must reconcile as consistent.
        resp2 = client.reconcile([])
        div2 = resp2.get("result", {}).get("divergence", {})
        _record("I4 reconcile consistent (matching active sets)",
                resp2.get("status") == "ok" and div2.get("consistent") is True,
                f"consistent={div2.get('consistent')}")
    finally:
        server.stop()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T5 multi-environment isolation drill")
    parser.add_argument("--deception-root", type=Path, default=None)
    parser.add_argument("--knowledge-root", type=Path, default=None)
    args = parser.parse_args(argv)

    deception_root = _root(args, "deception_root", "DECEPTION_ROOT",
                           "Azazel-Deception", REFERENCE_PACKAGE)
    knowledge_root = _root(args, "knowledge_root", "KNOWLEDGE_ROOT",
                           "Azazel-Knowledge", "azctl")
    try:
        _effectiveness_isolation(deception_root, knowledge_root)
        _reconcile_divergence(deception_root)
    finally:
        print("\n==================== T5 MULTI-ENV ISOLATION SUMMARY ====================")
        for name, ok, _ in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        passed = sum(1 for _, ok, _ in results if ok)
        print(f"  ----> {passed}/{len(results)} passed")
        print("=======================================================================")
    return 0 if results and all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
