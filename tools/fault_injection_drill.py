#!/usr/bin/env python3
"""T1 fault-injection drill — prove the interlock degrades by doctrine (dev).

Runs the five checks from Azazel-Edge#354 against a live, in-process AZ-06
shadow server, from Edge's own clients, and prints a PASS/FAIL table. This is
the "break it while it's running" complement to the pytest e2e suite: it starts
the real ``serve_shadow.py`` server, kills/impersonates/replays against it, and
confirms Edge reacts as the doctrine requires.

  D1  fail-OPEN     Knowledge absent -> ingest 'unreachable' / advisory
                    'unreachable', never an exception. Edge proceeds.
  D2  fail-CLOSED   AZ-06 dies mid-heartbeat -> HeartbeatLoop goes unhealthy
                    (failure_count > 0), the thread survives, and it recovers
                    to healthy when the node comes back.
  D3  auth boundary Wrong transport key -> ShadowTransportError (a spoofed
                    AZ-06 is rejected).
  D4  anti-replay   The same signed envelope sent twice -> the second is
                    rejected with reason 'replayed_request'.
  D5  recovery      The full integrated harness runs green end to end.

Nothing is enforced and no container starts (shadow/replay only). Exit code 0
iff all five pass.

Run (with the shared venv active and PYTHONPATH set, from Azazel-Edge):
    python tools/fault_injection_drill.py
Point at a Deception checkout other than ../Azazel-Deception with
--deception-root or DECEPTION_ROOT.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PY_ROOT = REPO_ROOT / "py"
if str(PY_ROOT) not in sys.path:
    sys.path.insert(0, str(PY_ROOT))

from azazel_edge.deception_shadow_client import (  # noqa: E402
    Az06ShadowClient,
    HeartbeatLoop,
    ShadowTransportError,
    _signature,  # module-owned envelope signer (mirrors the AZ-06 wire format)
)
from azazel_edge.deception_effectiveness_client import (  # noqa: E402
    EffectivenessAdvisoryReader,
    KnowledgeIngestClient,
    fabric_available,
)

REQUEST_SCHEMA = "az06-shadow-request/v0.1"
SIGNATURE_FIELD = "signature"

EDGE_ID = "edge-drill"
NODE_ID = "az06-drill"
KEY = "drill-correct-key"

results: list[tuple[str, bool, str]] = []


def _record(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}", flush=True)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _deception_root(args: argparse.Namespace) -> Path:
    cand = (
        args.deception_root
        or os.environ.get("DECEPTION_ROOT")
        or (REPO_ROOT.parent / "Azazel-Deception")
    )
    root = Path(cand).resolve()
    if not (root / "scripts/dev/serve_shadow.py").exists():
        raise SystemExit(
            f"serve_shadow.py not found under {root} "
            f"(pass --deception-root or set DECEPTION_ROOT)"
        )
    return root


def _wait_shadow(base: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{base}/shadow", timeout=2)
            return
        except urllib.error.HTTPError:
            return  # any HTTP status = server routing (POST-only endpoint)
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"shadow server never came up at {base}: {last}")


def _start_shadow(deception_root: Path, port: int, key: str) -> subprocess.Popen:
    env = dict(os.environ)
    proc = subprocess.Popen(
        [sys.executable, str(deception_root / "scripts/dev/serve_shadow.py"),
         "--host", "127.0.0.1", "--port", str(port),
         "--key", key, "--edge-id", EDGE_ID, "--node-id", NODE_ID],
        cwd=str(deception_root), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


# --- D1 -------------------------------------------------------------------

def drill_d1_fail_open() -> None:
    dead = "http://127.0.0.1:9"  # discard port: connection refused
    ingest = KnowledgeIngestClient(dead, edge_node_id=EDGE_ID, timeout_seconds=2.0)
    try:
        r = ingest.submit_observations([{"environment_id": "env-drill", "observation_id": "d1"}])
    except Exception as exc:  # noqa: BLE001
        _record("D1 fail-open ingest", False, f"raised {exc.__class__.__name__}")
        return
    ingest_ok = r.status == "unreachable"

    reader = EffectivenessAdvisoryReader(dead, timeout_seconds=2.0)
    try:
        adv = reader.get_advisory("env-drill")
    except Exception as exc:  # noqa: BLE001
        _record("D1 fail-open advisory", False, f"raised {exc.__class__.__name__}")
        return
    adv_ok = adv.advisory is None and adv.reason == "unreachable"
    _record(
        "D1 fail-open (Knowledge absent)",
        ingest_ok and adv_ok,
        f"ingest.status={r.status}, advisory.reason={adv.reason} (no exception)",
    )


# --- D2 -------------------------------------------------------------------

def drill_d2_fail_closed(deception_root: Path) -> None:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    proc = _start_shadow(deception_root, port, KEY)
    loop = None
    try:
        _wait_shadow(base)
        client = Az06ShadowClient(base, transport_key=KEY, edge_node_id=EDGE_ID,
                                  az06_node_id=NODE_ID, timeout_seconds=5.0)
        loop = HeartbeatLoop(client, interval_seconds=0.3)
        loop.start()
        if not loop.wait_until_healthy(10.0):
            _record("D2 fail-closed heartbeat", False,
                    f"never became healthy: {loop.last_error}")
            return
        # Kill the node; the loop must go unhealthy but keep running.
        _stop(proc)
        proc = None
        time.sleep(1.5)
        killed_healthy = loop.is_healthy
        killed_failures = loop.failure_count
        went_unhealthy = (not killed_healthy) and killed_failures > 0
        # Bring the node back on the same port; the loop must recover.
        proc = _start_shadow(deception_root, port, KEY)
        _wait_shadow(base)
        recovered = loop.wait_until_healthy(15.0)
        _record(
            "D2 fail-closed heartbeat + recovery",
            went_unhealthy and recovered,
            f"after kill: healthy={killed_healthy} failures={killed_failures}; "
            f"after restart: healthy={recovered}",
        )
    finally:
        if loop is not None:
            loop.stop()
        if proc is not None:
            _stop(proc)


# --- D3 -------------------------------------------------------------------

def drill_d3_impersonation(deception_root: Path) -> None:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    proc = _start_shadow(deception_root, port, KEY)
    try:
        _wait_shadow(base)
        wrong = Az06ShadowClient(base, transport_key="drill-wrong-key",
                                 edge_node_id=EDGE_ID, az06_node_id=NODE_ID,
                                 timeout_seconds=5.0)
        try:
            wrong.discover_capabilities()
        except ShadowTransportError as exc:
            _record("D3 spoofed AZ-06 rejected", True, f"ShadowTransportError: {str(exc)[:80]}")
            return
        _record("D3 spoofed AZ-06 rejected", False, "wrong key was NOT rejected")
    finally:
        _stop(proc)


# --- D4 -------------------------------------------------------------------

def _post(base: str, envelope: dict) -> dict:
    req = urllib.request.Request(
        f"{base}/shadow", data=json.dumps(envelope).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as raw:
        return json.loads(raw.read().decode("utf-8"))


def drill_d4_anti_replay(deception_root: Path) -> None:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    proc = _start_shadow(deception_root, port, KEY)
    try:
        _wait_shadow(base)
        # One fixed, correctly-signed envelope. Sending identical bytes twice
        # must trip the one-shot anti-replay ledger on the second POST.
        envelope: dict = {
            "schema_version": REQUEST_SCHEMA,
            "request_id": f"{EDGE_ID}-{uuid.uuid4().hex}",
            "edge_node_id": EDGE_ID,
            "az06_node_id": NODE_ID,
            "action": "capabilities",
            # Fresh timestamp so the envelope passes the AZ-06 freshness gate;
            # the second identical POST must then trip the anti-replay ledger
            # (not be dismissed as stale first).
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "payload": {},
        }
        envelope[SIGNATURE_FIELD] = _signature(envelope, KEY)
        first = _post(base, envelope)
        second = _post(base, envelope)
        codes = second.get("reason_codes") or []
        ok = first.get("status") == "ok" and "replayed_request" in codes
        _record("D4 anti-replay", ok,
                f"first.status={first.get('status')}, second.reason_codes={codes}")
    finally:
        _stop(proc)


# --- D5 -------------------------------------------------------------------

def drill_d5_recovery() -> None:
    harness = REPO_ROOT / "tools/edge_integration_functional_test.py"
    proc = subprocess.run(
        [sys.executable, str(harness)],
        cwd=str(REPO_ROOT), text=True, capture_output=True, timeout=300,
    )
    ok = proc.returncode == 0 and "OK — " in proc.stdout
    tail = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "(no output)"
    _record("D5 full-loop recovery", ok, f"exit={proc.returncode}; {tail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="T1 fault-injection drill (dev)")
    parser.add_argument("--deception-root", type=Path, default=None)
    parser.add_argument("--skip-d5", action="store_true",
                        help="skip the full-loop recovery run (needs Knowledge checkout)")
    args = parser.parse_args(argv)

    if not fabric_available():
        raise SystemExit("Fabric deception contracts unavailable (need v0.6.0)")
    deception_root = _deception_root(args)
    print(f"[drill] deception_root={deception_root}\n", flush=True)

    drill_d1_fail_open()
    drill_d2_fail_closed(deception_root)
    drill_d3_impersonation(deception_root)
    drill_d4_anti_replay(deception_root)
    if not args.skip_d5:
        drill_d5_recovery()

    print("\n==================== T1 DRILL SUMMARY ====================")
    for name, ok, _ in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  ----> {passed}/{len(results)} passed")
    print("==========================================================")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
