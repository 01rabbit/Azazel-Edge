"""Real-nft test of the core's owned throttle and redirect leases (Edge#464).

The release core is run with enforcement on and dry run off inside a network
namespace this test creates, and given one alert that decides a (strict,
flow-scoped) ``throttle`` and one that decides ``redirect``. Both leases must
reach ``active`` through the core's own apply path (not a pre-written lease),
which now counts an apply only after the owned rule reads back; their rules
must read back from ``nft -j`` with the bare owner token as comment, and the
core's release must delete them and verify their absence. No rule is ever
written to the ``input`` chain: the automatic path never isolates
(docs/architecture/scoped-temporary-actions.md).

Execution needs what the ADR requires: a protected communications set with a
management entry, a fresh alert, and for the redirect this boot's decoy
separation evidence naming the decoy port plus a listener on it.

It needs Linux, root, ``ip``/``nft`` and the release core build, and is skipped
otherwise (the test-python job). CI runs it as root in the service-objectives
job, next to SO-04, where it must pass and never skip. The namespace keeps it
off the host's ruleset. Timings here are container/runner timings, never
hardware evidence.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
TABLE = "azazel_edge"
# The Edge minimum lease (MIN_LEASE_TTL_SEC); a shorter value is raised to it.
TTL_SEC = 30

pytestmark = pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and shutil.which("nft")
        and shutil.which("ip")
        and CORE.is_file()
        and os.access(CORE, os.X_OK)
    ),
    reason="needs Linux, root, ip, nft and the release core build",
)

# Documentation addresses (RFC 5737); the namespace has only loopback.
THROTTLE_SRC = "198.51.100.71"
REDIRECT_SRC = "198.51.100.72"
DEST_IP = "192.0.2.10"
DEST_PORT = 22
DECOY_PORT = 12222
LISTENER = (
    "import socket,time\n"
    "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    f"s.bind(('127.0.0.1', {DECOY_PORT})); s.listen(16)\n"
    "s.settimeout(1)\n"
    "end=time.time()+120\n"
    "while time.time()<end:\n"
    "    try:\n"
    "        c,_=s.accept(); c.close()\n"
    "    except OSError:\n"
    "        pass\n"
)


def _run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _alert(src: str, severity: int, sid: int) -> str:
    return json.dumps(
        {
            "timestamp": _now_ts(),
            "event_type": "alert",
            "src_ip": src,
            "dest_ip": DEST_IP,
            "dest_port": DEST_PORT,
            "proto": "TCP",
            "alert": {"signature_id": sid, "signature": "owned nft lease test", "category": "test", "severity": severity},
        }
    )


def _ledger_tasks(path: Path) -> list:
    try:
        return [t for t in json.loads(path.read_text(encoding="utf-8")).get("tasks", []) if t.get("status") != "merged"]
    except (OSError, ValueError):
        return []


def _owned_rules(ns: str, chain: str) -> list:
    out = _run(["ip", "netns", "exec", ns, "nft", "-a", "-j", "list", "chain", "inet", TABLE, chain])
    assert out.returncode == 0, out.stderr
    return [e["rule"] for e in json.loads(out.stdout)["nftables"] if isinstance(e, dict) and "rule" in e]


def _wait(predicate, timeout_s: float, proc: subprocess.Popen):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        assert proc.poll() is None, "core exited early"
        time.sleep(0.1)
    return predicate()


def _private(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def netns():
    ns = f"aznft-{os.getpid()}"
    out = _run(["ip", "netns", "add", ns])
    assert out.returncode == 0, f"cannot create a network namespace as root: {out.stderr}"
    try:
        _run(["ip", "-n", ns, "link", "set", "lo", "up"])
        script = "\n".join(
            [
                f"add table inet {TABLE}",
                f"add chain inet {TABLE} input {{ type filter hook input priority 0; policy accept; }}",
                f"add chain inet {TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}",
                f"add chain inet {TABLE} throttle {{ type filter hook prerouting priority -150; policy accept; }}",
            ]
        )
        out = _run(["ip", "netns", "exec", ns, "nft", "-f", "-"], input=script + "\n")
        assert out.returncode == 0, out.stderr
        yield ns
    finally:
        _run(["ip", "netns", "del", ns])


def test_core_applies_reads_back_and_releases_owned_throttle_and_redirect(netns):
    with tempfile.TemporaryDirectory(prefix="aznft-") as tmp:
        work = Path(tmp)
        eve, events, ledger = work / "eve.json", work / "normalized-events.jsonl", work / "release-ledger.json"
        eve.write_text("", encoding="utf-8")
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        evidence = _private(
            work / "decoy-separation.json",
            json.dumps({
                "schema": "azazel-edge/decoy-separation/v1", "boot_id": boot_id, "observed_epoch": time.time(),
                "separation": "network_namespace", "decoy_ports": [DECOY_PORT],
            }),
        )
        policy = _private(
            work / "redirect_policy.yaml",
            "redirect_policy:\n  enabled: true\n  prepared_ports:\n"
            f"    {DEST_PORT}: {DECOY_PORT}\n  decoy_separation_evidence_path: {evidence}\n",
        )
        protected = _private(
            work / "protected-flows.yaml",
            "protected_flows:\n  version: 1\n  entries:\n    - {name: mgmt, role: management, network: 203.0.113.0/28}\n",
        )
        listener = subprocess.Popen(["ip", "netns", "exec", netns, sys.executable, "-c", LISTENER])
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AZAZEL_EVE_PATH": str(eve),
            "AZAZEL_EVE_FROM_START": "true",
            "AZAZEL_EVE_POLL_MS": "100",
            "AZAZEL_FORWARD_AI": "false",
            "AZAZEL_FORWARD_LOG": "true",
            "AZAZEL_NORMALIZED_EVENT_LOG": str(events),
            "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(ledger),
            "AZAZEL_DEFENSE_ENFORCE": "true",
            "AZAZEL_DEFENSE_DRY_RUN": "false",
            "AZAZEL_DEFENSE_ENFORCE_LEVEL": "full-auto",
            "AZAZEL_DEFENSE_ACTION_TTL_SEC": str(TTL_SEC),
            "AZAZEL_DEFENSE_IFACE": "lo",
            "AZAZEL_REDIRECT_POLICY_PATH": str(policy),
            "AZAZEL_PROTECTED_FLOWS_PATH": str(protected),
        }
        proc = subprocess.Popen(
            ["ip", "netns", "exec", netns, str(CORE)],
            cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            time.sleep(0.5)
            with eve.open("a", encoding="utf-8") as fh:
                fh.write(_alert(THROTTLE_SRC, 1, 9101) + "\n")
                fh.write(_alert(REDIRECT_SRC, 2, 9102) + "\n")

            def both_settled():
                tasks = _ledger_tasks(ledger)
                return tasks if len(tasks) == 2 and all(t["status"] != "prepared" for t in tasks) else None

            tasks = _wait(both_settled, 10, proc)
            assert tasks, f"leases never left prepared: {_ledger_tasks(ledger)}"
            by_action = {t["action"]: t for t in tasks}
            assert set(by_action) == {"throttle", "redirect"}
            for task in tasks:
                # A bare `comment azazel-edge:...` is an nft syntax error; an
                # apply that does not read back is released, never active.
                assert task["status"] == "active", (task["status"], task["last_error"])

            throttle, redirect = by_action["throttle"], by_action["redirect"]
            assert throttle["mechanism"] == "nft_flow_limit"
            thr_rules = [r for r in _owned_rules(netns, "throttle") if r.get("comment") == throttle["owner_token"]]
            assert len(thr_rules) == 1
            text = json.dumps(thr_rules[0])
            assert text.count(THROTTLE_SRC) == 1 and text.count(DEST_IP) == 1
            limit = [e["limit"] for e in thr_rules[0]["expr"] if "limit" in e]
            assert limit and limit[0]["inv"] is True and limit[0]["rate"] == 16 and limit[0]["rate_unit"] == "kbytes"
            pre_rules = [r for r in _owned_rules(netns, "prerouting") if r.get("comment") == redirect["owner_token"]]
            assert len(pre_rules) == 1
            assert any(expr.get("redirect", {}).get("port") == DECOY_PORT for expr in pre_rules[0]["expr"])
            assert json.dumps(pre_rules[0]).count(REDIRECT_SRC) == 1
            # Nothing source-wide, ever.
            assert _owned_rules(netns, "input") == []

            records = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines() if line.strip()]
            enforced = [r["enforcement"] for r in records if "enforcement" in r]
            assert len(enforced) == 2
            for outcome in enforced:
                assert outcome["mode"] == "enforced" and outcome["result"] == "applied", outcome
                assert outcome["executed_count"] == 1 and outcome["failed_count"] == 0
                token = outcome["metadata"]["release_owner_token"]
                assert f"comment {token}" in outcome["command_plan"][0]
                assert outcome["metadata"]["safety"]["gate"] == "passed"
            assert {o["metadata"]["safety"]["decoy_preconditions"] for o in enforced} == {"met", "not_applicable"}

            def both_released():
                tasks = _ledger_tasks(ledger)
                return tasks if tasks and all(t["status"] == "released" for t in tasks) else None

            released = _wait(both_released, TTL_SEC + 20, proc)
            assert released, f"leases not released: {_ledger_tasks(ledger)}"
            assert not [r for r in _owned_rules(netns, "throttle") if r.get("comment") == throttle["owner_token"]]
            assert not [r for r in _owned_rules(netns, "prerouting") if r.get("comment") == redirect["owner_token"]]
            records = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines() if line.strip()]
            results = sorted(r["release"]["result"] for r in records if "release" in r)
            assert results == ["rollback_applied_and_absence_verified"] * 2, results
        finally:
            listener.terminate()
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            listener.wait(timeout=10)
