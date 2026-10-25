"""Real-nft test of the core's owned isolate and redirect leases (Edge#464).

The release core is run with enforcement on and dry run off inside a network
namespace this test creates, and given one alert that decides ``isolate`` and
one that decides ``redirect``. Both leases must reach ``active`` through the
core's own apply path (not a pre-written lease), their rules must read back
from ``nft -j`` with the bare owner token as comment, and the core's release
must delete them and verify their absence.

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
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "rust" / "azazel-edge-core" / "target" / "release" / "azazel-edge-core"
TABLE = "azazel_edge"
TTL_SEC = 8

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
ISOLATE_SRC = "198.51.100.71"
REDIRECT_SRC = "198.51.100.72"
DEST_PORT = 22
HONEYPOT_PORT = 2222


def _run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, timeout=20, **kwargs)


def _alert(src: str, severity: int, sid: int) -> str:
    return json.dumps(
        {
            "timestamp": "2026-01-01T00:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": src,
            "dest_ip": "192.0.2.10",
            "dest_port": DEST_PORT,
            "proto": "TCP",
            "alert": {"signature_id": sid, "signature": "owned nft lease test", "category": "test", "severity": severity},
        }
    )


def _ledger_tasks(path: Path) -> list:
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("tasks", [])
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
            ]
        )
        out = _run(["ip", "netns", "exec", ns, "nft", "-f", "-"], input=script + "\n")
        assert out.returncode == 0, out.stderr
        yield ns
    finally:
        _run(["ip", "netns", "del", ns])


def test_core_applies_reads_back_and_releases_owned_isolate_and_redirect(netns):
    with tempfile.TemporaryDirectory(prefix="aznft-") as tmp:
        work = Path(tmp)
        eve, events, ledger = work / "eve.json", work / "normalized-events.jsonl", work / "release-ledger.json"
        eve.write_text("", encoding="utf-8")
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
            "AZAZEL_DEFENSE_HONEYPOT_PORT": str(HONEYPOT_PORT),
            "AZAZEL_REDIRECT_POLICY_PATH": str(work / "no-redirect-policy.yaml"),
        }
        proc = subprocess.Popen(
            ["ip", "netns", "exec", netns, str(CORE)],
            cwd=str(work), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        try:
            with eve.open("a", encoding="utf-8") as fh:
                fh.write(_alert(ISOLATE_SRC, 1, 9101) + "\n")
                fh.write(_alert(REDIRECT_SRC, 2, 9102) + "\n")

            def both_settled():
                tasks = _ledger_tasks(ledger)
                return tasks if len(tasks) == 2 and all(t["status"] != "prepared" for t in tasks) else None

            tasks = _wait(both_settled, TTL_SEC / 2, proc)
            assert tasks, f"leases never left prepared: {_ledger_tasks(ledger)}"
            by_action = {t["action"]: t for t in tasks}
            assert set(by_action) == {"isolate", "redirect"}
            for task in tasks:
                # The bug: a bare `comment azazel-edge:...` is an nft syntax
                # error, the apply fails and the lease is cancelled.
                assert task["status"] == "active", (task["status"], task["last_error"])

            # Readback while active: exactly one rule per lease, the comment is
            # the bare owner token (nft -j drops the quotes), semantics match.
            isolate, redirect = by_action["isolate"], by_action["redirect"]
            input_rules = [r for r in _owned_rules(netns, "input") if r.get("comment") == isolate["owner_token"]]
            assert len(input_rules) == 1
            assert any("drop" in expr for expr in input_rules[0]["expr"])
            assert json.dumps(input_rules[0]).count(ISOLATE_SRC) == 1
            pre_rules = [r for r in _owned_rules(netns, "prerouting") if r.get("comment") == redirect["owner_token"]]
            assert len(pre_rules) == 1
            assert any(expr.get("redirect", {}).get("port") == HONEYPOT_PORT for expr in pre_rules[0]["expr"])
            assert json.dumps(pre_rules[0]).count(REDIRECT_SRC) == 1

            records = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines() if line.strip()]
            enforced = [r["enforcement"] for r in records if "enforcement" in r]
            assert len(enforced) == 2
            for outcome in enforced:
                assert outcome["mode"] == "enforced" and outcome["result"] == "applied", outcome
                assert outcome["executed_count"] == 1 and outcome["failed_count"] == 0
                # The recorded plan keeps the bare token after `comment`.
                token = outcome["metadata"]["release_owner_token"]
                assert f"comment {token}" in outcome["command_plan"][0]

            # Rollback by the core at expiry: owned handles resolved by readback,
            # deleted, absence verified.
            def both_released():
                tasks = _ledger_tasks(ledger)
                return tasks if tasks and all(t["status"] == "released" for t in tasks) else None

            released = _wait(both_released, TTL_SEC + 20, proc)
            assert released, f"leases not released: {_ledger_tasks(ledger)}"
            assert not [r for r in _owned_rules(netns, "input") if r.get("comment") == isolate["owner_token"]]
            assert not [r for r in _owned_rules(netns, "prerouting") if r.get("comment") == redirect["owner_token"]]
            records = [json.loads(line) for line in events.read_text(encoding="utf-8").splitlines() if line.strip()]
            results = sorted(r["release"]["result"] for r in records if "release" in r)
            assert results == ["rollback_applied_and_absence_verified"] * 2, results
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
