#!/usr/bin/env python3
"""T4 forward-seam drill — detection -> Knowledge advice -> AZ-06 decoy rehearsal.

The effectiveness loop asks "is the deployed deception working?". This is the
*forward* seam: an attack is detected, Edge asks Knowledge for threat context
and a posture recommendation, and — when the advice is a deploy-a-decoy posture
— Edge rehearses materializing an AZ-06 decoy. Knowledge only advises; Edge
decides; AZ-06 rehearses without executing.

Checks:
  F1 live forward contract   Edge POSTs a real detection to a live Knowledge
                             `/v1/context`; a matching IOC yields a scored,
                             advisory-only ContextResponse (threat_score>0,
                             ioc_match reason, a posture, advisory_notice), and
                             a non-matching detection scores 0 -> observe.
  F2 posture decision        Knowledge's own action bands map a high-threat
                             advisory to a deploy posture (redirect/…) and a
                             low one to observe — deterministically, from the
                             node's real config.
  F3 advice -> decoy         given a deploy posture, Edge runs the AZ-06 shadow
                             bootstrap: the decoy is materialized in rehearsal
                             only (enforcement_applied=False, 0 container
                             starts). The detection->advice->decoy loop closes.
  F4 advisory-only authority the live recommendation carries no executable /
                             runtime-directive key and names Azazel-Edge as the
                             final authority.

One-command: provisions + seeds + serves a Knowledge node and an in-process
AZ-06 shadow server. Requires the sibling azazel_deception / azazel_knowledge
checkouts importable plus Fabric v0.6.0 and the Knowledge api extra.

Run:  python tools/detection_to_decoy_drill.py
"""

from __future__ import annotations

import argparse
import json
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

EDGE_NODE_ID = "edge-t4"
SHADOW_KEY = "t4-shadow-key"
AZ06_NODE_ID = "az06-t4-node"
ENV_ID = "env-t4-decoy"
REFERENCE_PACKAGE = "examples/packages/municipal-linux-v1/package.yaml"
REFERENCE_COMPOSE = "runtime/compose/reference-linux.compose.yaml"
MATCH_IP = "203.0.113.7"

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
    print(f"[t4] {msg}", flush=True)


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


def _seed_intel(data_db_dir: Path) -> None:
    """Seed one matching IOC (+ KEV) into a fresh intel generation and swap it.

    Mirrors azazel-knowledge's own test-support seed so a live node returns a
    real, scored advisory for the matching detection. Intel-tier only; never
    touches local.db.
    """
    from azazel_knowledge.db import generations
    from azazel_knowledge.db.repository import apply_migrations

    intel_path = generations.build_next_generation(data_db_dir)
    # build_next_generation returns .../gen-{N}/intel.db where N = current+1;
    # provision already made gen-1, so seed and swap to the real N, not 1.
    gen_n = int(intel_path.parent.name.split("-")[-1])
    conn = sqlite3.connect(intel_path)
    try:
        apply_migrations(conn, "intel")
        conn.execute(
            "INSERT INTO ioc (ioc_id, type, value, first_seen, last_seen, "
            "agg_raw_confidence, agg_computed_at) VALUES "
            "(1, 'ip', ?, '2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 80.0, "
            "'2026-07-02T00:00:00Z')", (MATCH_IP,))
        conn.execute(
            "INSERT INTO ioc_source (ioc_id, feed_id, source_confidence, first_seen, "
            "last_seen, intel_generation) VALUES (1, 'urlhaus', 85, "
            "'2026-06-01T00:00:00Z', '2026-07-02T00:00:00Z', 1)")
        conn.execute(
            "INSERT INTO kev (cve_id, catalog_version, date_added) VALUES "
            "('CVE-2024-0001', 'v1', '2026-01-01T00:00:00Z')")
        conn.execute("INSERT INTO stats_meta (key, value) VALUES ('intel_generation', ?)",
                     (str(gen_n),))
        conn.execute(
            "INSERT INTO feed_state (feed_id, last_run, last_success, item_count, enabled, "
            "consecutive_polls) VALUES ('urlhaus', '2026-07-06T00:00:00Z', "
            "'2026-07-05T00:00:00Z', 10, 1, 5)")
        conn.commit()
    finally:
        conn.close()
    generations.swap_current(data_db_dir, gen_n)


def _post_context(base: str, token: str, entity_value: str, cves: list[str] | None = None) -> dict:
    event = {"kind": "eve_alert", "event_types": ["eve_alert"]}
    if cves:
        event["cves"] = cves
    body = json.dumps({
        "entities": [{"type": "ip", "value": entity_value}],
        "event": event,
        "edge_id": EDGE_NODE_ID, "actor_key": "actor-t4",
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/v1/context", data=body,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def _synthetic_caps():
    from azazel_fabric.deception_contracts import HostCapabilities
    return HostCapabilities.model_validate(_SYNTHETIC_CAPS).model_dump(mode="json")


def _decoy_rehearsal(deception_root: Path) -> dict:
    """Edge rehearses materializing an AZ-06 decoy (non-executing)."""
    from azazel_deception.package import calculate_package_digest, load_package
    from azazel_deception.runtime.shadow_server import ShadowReplayHTTPServer, ShadowReplayService
    from datetime import datetime, timedelta, timezone

    tmp = Path(tempfile.mkdtemp(prefix="az06-t4-"))
    package = load_package(deception_root / REFERENCE_PACKAGE)
    for c in package["components"]:
        c["image"]["verified"] = c["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    (tmp / "package.json").write_text(json.dumps(package), encoding="utf-8")

    service = ShadowReplayService(
        node_id=AZ06_NODE_ID, transport_key=SHADOW_KEY, allowed_edge_ids=[EDGE_NODE_ID],
        package_path=tmp / "package.json", state_root=tmp / "state",
        compose_file=deception_root / REFERENCE_COMPOSE, capability_provider=_synthetic_caps)
    server = ShadowReplayHTTPServer(service)
    server.start()

    def _activation(package, capabilities, plan):
        now = datetime.now(timezone.utc)
        return {
            "schema_version": "environment-activation-decision/v0.1",
            "decision_id": plan["edge_decision_id"], "decision_authority": "azazel-edge",
            "status": "accepted", "package_id": package["package_id"],
            "package_digest": package["package_digest"], "target_node_id": plan["node_id"],
            "selected_tier": plan["selected_tier"],
            "budget": {"cpu_cores": 2, "memory_mb": 1024, "storage_mb": 2048,
                       "max_connections": 100, "max_duration_seconds": 300, "bandwidth_kbps": 5000},
            "safety": {"outbound_allowed": False, "production_access": False,
                       "privileged_containers": False, "host_network": False,
                       "runtime_socket_exposed_to_decoys": False,
                       "edge_control_access_from_decoys": False},
            "effective_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(),
            "evidence_refs": [], "reason_codes": ["t4-redirect-to-decoy"]}

    try:
        host, port = server.address
        client = Az06ShadowClient(f"http://{host}:{port}", transport_key=SHADOW_KEY,
                                  edge_node_id=EDGE_NODE_ID, az06_node_id=AZ06_NODE_ID)
        return client.run_bootstrap_session(
            edge_decision_id="edge-t4-decoy-1", requested_tier="lite",
            environment_id=ENV_ID, build_activation_decision=_activation)
    finally:
        server.stop()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T4 detection->decoy forward-seam drill")
    parser.add_argument("--deception-root", type=Path, default=None)
    parser.add_argument("--knowledge-root", type=Path, default=None)
    args = parser.parse_args(argv)

    deception_root = _root(args, "deception_root", "DECEPTION_ROOT",
                           "Azazel-Deception", REFERENCE_PACKAGE)
    knowledge_root = _root(args, "knowledge_root", "KNOWLEDGE_ROOT",
                           "Azazel-Knowledge", "azctl")

    env = dict(os.environ)
    root = Path(tempfile.mkdtemp(prefix="az-t4-"))
    config_dir = knowledge_root / "config"
    env["AZAZEL_ROOT"] = str(root)
    env["AZAZEL_CONFIG_DIR"] = str(config_dir)

    def _run(cmd):
        return subprocess.run(cmd, cwd=str(knowledge_root), env=env, text=True,
                              capture_output=True, timeout=120, check=True)

    _log(f"provisioning + seeding Knowledge node at {root}")
    _run([sys.executable, "azctl", "provision", "--root", str(root), "--config-dir", str(config_dir)])
    # Seed a matching IOC so the live node returns a scored advisory.
    sys.path.insert(0, str(knowledge_root / "src"))
    _seed_intel(root / "data" / "db")
    added = _run([sys.executable, "azctl", "client", "add", "--root", str(root),
                  "--config-dir", str(config_dir), "--key-id", "edge1", "--scopes", "query"])
    token = re.search(r"token.*?:\s*(azcti_\S+)", added.stdout).group(1)

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    app = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "azazel_knowledge.api.app:app",
         "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(knowledge_root), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        _wait_http(f"{base}/v1/health")
        _log(f"Knowledge live at {base}")

        # F1 — live forward contract: matching detection scores; non-matching is 0.
        hit = _post_context(base, token, MATCH_IP, cves=["CVE-2024-0001"])
        miss = _post_context(base, token, "198.51.100.200")  # clean: no IOC, no KEV CVE
        reason_components = [r.get("component") for r in hit.get("reason", [])]
        action = hit["recommendation"]["action"]
        _log(f"detection({MATCH_IP}) -> score={hit['threat_score']} conf={hit['confidence']} "
             f"posture={action}")
        _record("F1 live forward contract (scored, advisory-only ContextResponse)",
                hit["threat_score"] > 0 and "ioc_match" in reason_components
                and action in {"isolate", "throttle", "redirect", "observe"}
                and miss["threat_score"] == 0.0 and miss["recommendation"]["action"] == "observe",
                f"hit(score={hit['threat_score']}, posture={action}, ioc_match={'ioc_match' in reason_components}); "
                f"miss(score={miss['threat_score']}, posture={miss['recommendation']['action']})")

        # F2 — posture decision from the node's real action bands.
        import yaml
        from azazel_knowledge.recommend.select import recommend
        bands = yaml.safe_load((config_dir / "scoring.yaml").read_text())["recommendation"]["action_bands"]
        deploy = recommend(50.0, 45.0, bands)   # crosses the redirect threshold
        quiet = recommend(5.0, 5.0, bands)
        _record("F2 threat drives posture (deploy vs observe, deterministic)",
                deploy.get("action") == "redirect" and quiet.get("action") == "observe",
                f"high-threat -> {deploy.get('action')} (deploy-a-decoy); low -> {quiet.get('action')}")

        # F3 — deploy posture triggers a non-executing AZ-06 decoy rehearsal.
        if deploy.get("action") in {"isolate", "throttle", "redirect"}:
            trace = _decoy_rehearsal(deception_root)
            steps = [s["step"] for s in trace.get("steps", [])]
            _record("F3 advice -> AZ-06 decoy rehearsal (loop closed, non-executing)",
                    trace.get("outcome") == "shadow_complete"
                    and trace.get("enforcement_applied") is False
                    and trace.get("container_start_count") == 0
                    and "shadow_activate" in steps,
                    f"posture={deploy.get('action')} outcome={trace.get('outcome')} "
                    f"enforcement={trace.get('enforcement_applied')} container_starts="
                    f"{trace.get('container_start_count')}")
        else:
            _record("F3 advice -> AZ-06 decoy rehearsal", False,
                    f"unexpected non-deploy posture {deploy.get('action')}")

        # F4 — advisory-only authority: no executable directive, Edge is final.
        rec = hit["recommendation"]
        notice = hit.get("advisory_notice", "")
        banned = {"executable", "command", "commands", "runtime_directive", "enforce", "apply"}
        _record("F4 advisory-only authority (no directive; Edge is final)",
                not (banned & set(rec.keys())) and "Azazel-Edge" in notice,
                f"recommendation_keys={sorted(rec.keys())}; notice~='{notice[:48]}...'")

        return 0 if all(ok for _, ok, _ in results) else 1
    finally:
        app.terminate()
        try:
            app.wait(timeout=10)
        except subprocess.TimeoutExpired:
            app.kill()
        print("\n==================== T4 FORWARD-SEAM SUMMARY ====================")
        for name, ok, _ in results:
            print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        passed = sum(1 for _, ok, _ in results if ok)
        print(f"  ----> {passed}/{len(results)} passed")
        print("================================================================")


if __name__ == "__main__":
    raise SystemExit(main())
