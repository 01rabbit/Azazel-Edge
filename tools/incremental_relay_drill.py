#!/usr/bin/env python3
"""T3 incremental-relay drill — streaming observations + idempotent landing.

Real deployments don't relay one tidy batch; an engagement is live and AZ-06
keeps emitting facts. This drill drives the effectiveness path the way it
actually runs: AZ-06 records a first burst, Edge relays it and reads advisory①;
AZ-06 records more, Edge relays ONLY the new facts via the incremental cursor
(`observations_since`) and reads advisory②; finally Edge re-relays an already
-sent batch to prove Knowledge's landing is idempotent (no duplicate rows).

Checks:
  R1 cursor       observations_since(last_id) returns only the newly recorded
                  facts, not the whole chain.
  R2 accumulation advisory① sees the first burst; advisory② sees the cumulative
                  set after the incremental relay.
  R3 idempotent   re-relaying an already-landed batch adds no rows
                  (observation_uid UNIQUE); the immutable table holds exactly
                  the distinct observations.

One-command: starts the Azazel-Knowledge API + worker as subprocesses. Requires
the sibling azazel_deception / azazel_knowledge checkouts importable plus Fabric
v0.6.0 and the Knowledge api extra. Point at checkouts with --deception-root /
--knowledge-root or DECEPTION_ROOT / KNOWLEDGE_ROOT.

Run:  python tools/incremental_relay_drill.py
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

from azazel_edge.deception_effectiveness_client import (  # noqa: E402
    EffectivenessAdvisoryReader,
    KnowledgeAuthConfig,
    KnowledgeIngestClient,
)

ENV_ID = "env-t3-incremental"
EDGE_NODE_ID = "edge-t3"
REFERENCE_PACKAGE = "examples/packages/municipal-linux-v1/package.yaml"

results: list[tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}", flush=True)


def _log(msg: str) -> None:
    print(f"[t3] {msg}", flush=True)


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


def _deception_root(args) -> Path:
    cand = (args.deception_root or os.environ.get("DECEPTION_ROOT")
            or (REPO_ROOT.parent / "Azazel-Deception"))
    root = Path(cand).resolve()
    if not (root / REFERENCE_PACKAGE).exists():
        raise SystemExit(f"azazel-deception checkout not found at {root}")
    return root


def _knowledge_root(args) -> Path:
    cand = (args.knowledge_root or os.environ.get("KNOWLEDGE_ROOT")
            or (REPO_ROOT.parent / "Azazel-Knowledge"))
    root = Path(cand).resolve()
    if not (root / "azctl").exists():
        raise SystemExit(f"azazel-knowledge checkout not found at {root}")
    return root


def _make_observer(deception_root: Path, state_root: Path):
    """Build a real AZ-06 InteractionObserver bound to a fresh state store."""
    from azazel_deception.package import load_package, parse_package
    from azazel_deception.planner import build_placement_plan
    from azazel_deception.runtime.observation import InteractionObserver, build_runtime_context
    from azazel_deception.runtime.state import RuntimeStateStore
    from azazel_fabric.deception_contracts import PlacementPlan

    raw = load_package(deception_root / REFERENCE_PACKAGE)
    package = parse_package(raw)
    host = {"node_id": "az06-t3", "architecture": "amd64", "cpu_cores": 4,
            "memory_mb": 8192, "storage_free_mb": 65536,
            "runtime_adapters": {"docker_compose": True},
            "kvm_available": False, "gpu_available": False}
    plan = PlacementPlan.model_validate(
        build_placement_plan(raw, host, requested_tier="lite", edge_decision_id="edge-t3-1"))
    state = RuntimeStateStore(state_root)
    observer = InteractionObserver(
        state, environment_id=ENV_ID, package_id=package.package_id,
        node_id=plan.node_id, runtime_context=build_runtime_context(package, plan))
    return state, observer


def _db_count(root: Path) -> int:
    db = root / "data" / "db" / "local.db"
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return con.execute(
            "SELECT COUNT(*) FROM deception_observation WHERE environment_id=?",
            (ENV_ID,)).fetchone()[0]
    finally:
        con.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T3 incremental-relay drill")
    parser.add_argument("--deception-root", type=Path, default=None)
    parser.add_argument("--knowledge-root", type=Path, default=None)
    args = parser.parse_args(argv)

    deception_root = _deception_root(args)
    knowledge_root = _knowledge_root(args)
    from azazel_deception.runtime.observation_export import export_observations, observations_since

    env = dict(os.environ)
    root = Path(tempfile.mkdtemp(prefix="az-t3-"))
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
    m = re.search(r"token.*?:\s*(azcti_\S+)", added.stdout)
    if not m:
        raise SystemExit("failed to parse client token")
    token = m.group(1)

    def _drain():
        _run([sys.executable, "-m", "azazel_knowledge.worker", "--root", str(root),
              "--config-dir", str(config_dir), "--once"])

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "azazel_knowledge.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(knowledge_root), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    state_dir = Path(tempfile.mkdtemp(prefix="az06-t3-state-"))
    try:
        _wait_http(f"{base}/v1/health")
        _log(f"Knowledge live at {base}")
        auth = KnowledgeAuthConfig(token=token)
        ingest = KnowledgeIngestClient(base, edge_node_id=EDGE_NODE_ID, auth=auth)
        reader = EffectivenessAdvisoryReader(base, auth=auth)

        state, observer = _make_observer(deception_root, state_dir)

        # --- burst 1: contact + reaction ---
        observer.record(observation_class="interaction", surface="port")
        observer.record(observation_class="reaction", surface="credential_lure",
                        reaction_kind="authenticate", lure_id="lure-a", attempt_count=1)
        batch1 = export_observations(state, ENV_ID)
        cursor = batch1[-1]["observation_id"]
        r1 = ingest.submit_observations(batch1)
        _drain()
        adv1 = reader.get_advisory(ENV_ID).advisory
        _log(f"burst1: relayed {len(batch1)} status={r1.status}; advisory1 count="
             f"{(adv1 or {}).get('metadata', {}).get('observation_count')}")

        # --- burst 2: more facts; relay ONLY the new via the cursor ---
        observer.record(observation_class="outcome", surface="file",
                        reaction_kind="exfiltrate", dwell_ms=30000, attempt_count=3)
        observer.record(observation_class="interaction", surface="port",
                        confounder_tags=["scanner_noise"])
        observer.record(observation_class="reaction", surface="credential_lure",
                        reaction_kind="enumerate", lure_id="lure-b", attempt_count=2)
        incremental = observations_since(state, ENV_ID, cursor)
        r2 = ingest.submit_observations(incremental)
        _drain()
        adv2 = reader.get_advisory(ENV_ID).advisory
        _log(f"burst2: incremental={len(incremental)} status={r2.status}; advisory2 count="
             f"{(adv2 or {}).get('metadata', {}).get('observation_count')}")

        # R1 — cursor returned only the 3 new facts, not the full chain of 5.
        _record("R1 incremental cursor returns only new facts",
                len(batch1) == 2 and len(incremental) == 3
                and all(o["observation_id"] > cursor for o in incremental),
                f"burst1={len(batch1)} cursor={cursor} incremental={len(incremental)}")

        # R2 — advisory accumulates (2 -> 5) across the streamed relays.
        c1 = (adv1 or {}).get("metadata", {}).get("observation_count")
        c2 = (adv2 or {}).get("metadata", {}).get("observation_count")
        _record("R2 advisory accumulates across streamed relays",
                c1 == 2 and c2 == 5, f"advisory1={c1} advisory2={c2}")

        # R3 — re-relay an already-landed batch; the immutable table is unchanged.
        before = _db_count(root)
        ingest.submit_observations(batch1)  # duplicate of the first burst
        _drain()
        after = _db_count(root)
        _record("R3 idempotent landing (no duplicate rows)",
                before == 5 and after == 5,
                f"rows_before_replay={before} rows_after_replay={after} (observation_uid UNIQUE)")
        return 0 if all(ok for _, ok, _ in results) else 1
    finally:
        app.terminate()
        try:
            app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill()
        import shutil
        shutil.rmtree(state_dir, ignore_errors=True)
        print("\n==================== T3 INCREMENTAL-RELAY SUMMARY ====================")
        for name, ok, _ in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        passed = sum(1 for _, ok, _ in results if ok)
        print(f"  ----> {passed}/{len(results)} passed")
        print("=====================================================================")


if __name__ == "__main__":
    raise SystemExit(main())
