"""Real-network test of the flow-scoped temporary restriction
(docs/architecture/scoped-temporary-actions.md).

Four network namespaces: an Edge router running the release core with
enforcement on, an attacker, a management host and a server, each joined to
the Edge by a veth pair. Real TCP traffic is measured at the server.

* Only the attack flow is limited: after an alert names the attacker's flow,
  its throughput collapses to the nft limit while the management host's flow
  to the same server port keeps its throughput, and an alert naming the
  management host (in the declared protected set) restricts nothing.
* The interface's own qdisc (``fq_codel`` with handle ``1:``) is the same
  before the restriction, while it is held and after it is released.
* At expiry the core deletes its rule, verifies the absence, and the
  attacker's throughput comes back.
* A wedged apply (nft that never returns, shadowed in a private mount
  namespace for the core only) is killed at its bound and never holds back
  the release of a lease that falls due meanwhile.

It needs Linux, root, ``ip``/``nft``/``tc``/``unshare``/``mount`` and the
release core build, and is skipped otherwise. CI runs it as root in the
service-objectives job, where it must pass and never skip. These are
container/runner timings on virtual links, never hardware evidence.
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
TTL_SEC = 30  # the Edge minimum lease
SERVER_PORT = 5001

pytestmark = pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        and hasattr(os, "geteuid")
        and os.geteuid() == 0
        and all(shutil.which(t) for t in ("nft", "ip", "tc", "unshare", "mount"))
        and CORE.is_file()
        and os.access(CORE, os.X_OK)
    ),
    reason="needs Linux, root, ip, nft, tc, unshare, mount and the release core build",
)

TAG = f"az{os.getpid() % 10000}"
NS = {name: f"{TAG}-{name}" for name in ("edge", "atk", "mgr", "srv")}
ADDR = {"atk": "10.91.1.2", "mgr": "10.91.2.2", "srv": "10.91.3.2"}
EDGE_ADDR = {"atk": "10.91.1.1", "mgr": "10.91.2.1", "srv": "10.91.3.1"}
SRV_IFACE = f"{TAG}es"

SINK = (
    "import socket,sys,threading,time\n"
    "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
    f"s.bind(('0.0.0.0', {SERVER_PORT})); s.listen(64)\n"
    "def serve(c, a):\n"
    "    n=0; t0=time.time()\n"
    "    while True:\n"
    "        b=c.recv(65536)\n"
    "        if not b: break\n"
    "        n+=len(b)\n"
    "    print(a[0], n, round(time.time()-t0, 3), flush=True); c.close()\n"
    "while True:\n"
    "    c,a=s.accept(); threading.Thread(target=serve, args=(c,a), daemon=True).start()\n"
)

SEND = (
    "import socket,sys,time\n"
    "c=socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)\n"
    "c.settimeout(0.5)\n"
    "end=time.time()+float(sys.argv[3]); buf=b'x'*16384\n"
    "while time.time()<end:\n"
    "    try:\n"
    "        c.send(buf)\n"
    "    except socket.timeout:\n"
    "        pass\n"
    "c.shutdown(socket.SHUT_WR); c.settimeout(10)\n"
    "try:\n"
    "    c.recv(1)\n"
    "except OSError:\n"
    "    pass\n"
    "c.close()\n"
)


def _run(argv, check=True, **kwargs):
    out = subprocess.run(argv, capture_output=True, text=True, timeout=60, **kwargs)
    if check:
        assert out.returncode == 0, f"{argv}: {out.stderr}"
    return out


def _ns(name, *argv, check=True, **kwargs):
    return _run(["ip", "netns", "exec", NS[name], *argv], check=check, **kwargs)


def _now_ts(offset: float = 0.0) -> str:
    return datetime.fromtimestamp(time.time() + offset, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _alert(src: str, severity: int, sid: int, port: int = SERVER_PORT) -> str:
    return json.dumps({
        "timestamp": _now_ts(), "event_type": "alert", "src_ip": src, "dest_ip": ADDR["srv"],
        "dest_port": port, "proto": "TCP",
        "alert": {"signature_id": sid, "signature": "scoped action test", "category": "test", "severity": severity},
    })


def _private(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)
    return path


def _root_qdisc() -> dict:
    items = json.loads(_ns("edge", "tc", "-j", "qdisc", "show", "dev", SRV_IFACE).stdout)
    root = [i for i in items if i.get("root")]
    assert len(root) == 1, items
    return {k: root[0].get(k) for k in ("kind", "handle")}


def _owned_rules() -> list:
    out = _ns("edge", "nft", "-a", "-j", "list", "chain", "inet", TABLE, "throttle")
    return [e["rule"] for e in json.loads(out.stdout)["nftables"] if "rule" in e]


@pytest.fixture(scope="module")
def topology():
    for name in NS.values():
        _run(["ip", "netns", "del", name], check=False)
    try:
        for name in NS.values():
            _run(["ip", "netns", "add", name])
            _run(["ip", "-n", name, "link", "set", "lo", "up"])
        for peer in ("atk", "mgr", "srv"):
            edge_if, peer_if = f"{TAG}e{peer[0]}", f"{TAG}{peer[0]}0"
            if peer == "srv":
                edge_if = SRV_IFACE
            _run(["ip", "link", "add", edge_if, "netns", NS["edge"], "type", "veth", "peer", "name", peer_if, "netns", NS[peer]])
            _run(["ip", "-n", NS["edge"], "addr", "add", f"{EDGE_ADDR[peer]}/24", "dev", edge_if])
            _run(["ip", "-n", NS[peer], "addr", "add", f"{ADDR[peer]}/24", "dev", peer_if])
            _run(["ip", "-n", NS["edge"], "link", "set", edge_if, "up"])
            _run(["ip", "-n", NS[peer], "link", "set", peer_if, "up"])
            _run(["ip", "-n", NS[peer], "route", "add", "default", "via", EDGE_ADDR[peer]])
        _ns("edge", "sysctl", "-qw", "net.ipv4.ip_forward=1")
        # The interface's own shaping, which the restriction must not touch.
        _ns("edge", "tc", "qdisc", "replace", "dev", SRV_IFACE, "root", "handle", "1:", "fq_codel")
        script = "\n".join([
            f"add table inet {TABLE}",
            f"add chain inet {TABLE} input {{ type filter hook input priority 0; policy accept; }}",
            f"add chain inet {TABLE} prerouting {{ type nat hook prerouting priority -100; policy accept; }}",
            f"add chain inet {TABLE} throttle {{ type filter hook prerouting priority -150; policy accept; }}",
        ])
        _ns("edge", "nft", "-f", "-", input=script + "\n")
        sink = subprocess.Popen(["ip", "netns", "exec", NS["srv"], sys.executable, "-u", "-c", SINK],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        time.sleep(0.5)
        yield sink
        sink.kill()
        sink.wait(timeout=10)
    finally:
        for name in NS.values():
            _run(["ip", "netns", "del", name], check=False)


def _throughput(sink: subprocess.Popen, client: str, seconds: float = 3.0) -> float:
    """Bytes per second the server received from `client` over one TCP flow."""
    _ns(client, sys.executable, "-c", SEND, ADDR["srv"], str(SERVER_PORT), str(seconds))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        line = sink.stdout.readline()
        if not line:
            break
        source, size, secs = line.split()
        if source == ADDR[client]:
            return int(size) / max(float(secs), 0.001)
    raise AssertionError(f"no measurement for {client}")


class Core:
    def __init__(self, work: Path, wrapper_dir: Path | None = None):
        self.work = work
        self.eve = work / "eve.json"
        self.events = work / "normalized-events.jsonl"
        self.ledger = work / "release-ledger.json"
        self.eve.write_text("", encoding="utf-8")
        protected = _private(work / "protected-flows.yaml", (
            "protected_flows:\n  version: 1\n  entries:\n"
            "    - {name: mgmt, role: management, network: 10.91.2.0/24}\n"
        ))
        env = {
            "PATH": os.environ.get("PATH", ""),
            "AZAZEL_EVE_PATH": str(self.eve), "AZAZEL_EVE_FROM_START": "true", "AZAZEL_EVE_POLL_MS": "100",
            "AZAZEL_FORWARD_AI": "false", "AZAZEL_FORWARD_LOG": "true",
            "AZAZEL_NORMALIZED_EVENT_LOG": str(self.events), "AZAZEL_EVENT_STDOUT": "off",
            "AZAZEL_DEFENSE_RELEASE_LEDGER": str(self.ledger), "AZAZEL_DEFENSE_ENFORCE": "true",
            "AZAZEL_DEFENSE_DRY_RUN": "false", "AZAZEL_DEFENSE_ENFORCE_LEVEL": "full-auto",
            "AZAZEL_DEFENSE_ACTION_TTL_SEC": str(TTL_SEC), "AZAZEL_DEFENSE_IFACE": SRV_IFACE,
            "AZAZEL_REDIRECT_POLICY_PATH": str(work / "no-redirect-policy.yaml"),
            "AZAZEL_PROTECTED_FLOWS_PATH": str(protected),
        }
        argv = ["ip", "netns", "exec", NS["edge"], str(CORE)]
        if wrapper_dir is not None:
            # The core alone sees the wedging nft: bound over /usr/sbin/nft in
            # a private mount namespace (`ip netns exec` keeps the bind).
            argv = ["unshare", "-m", "--propagation", "private", "sh", "-c",
                    f'mount --bind "{wrapper_dir}/nft" "$(command -v nft)" && exec "$@"', "core", *argv]
        self.proc = subprocess.Popen(argv, cwd=str(work), env=env, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        assert self.proc.poll() is None, self.proc.stderr.read()

    def alert(self, src: str, severity: int, sid: int, port: int = SERVER_PORT):
        with self.eve.open("a", encoding="utf-8") as fh:
            fh.write(_alert(src, severity, sid, port) + "\n")

    def records(self) -> list:
        try:
            return [json.loads(l) for l in self.events.read_text(encoding="utf-8").splitlines() if l.strip()]
        except OSError:
            return []

    def wait(self, predicate, timeout_s: float):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            assert self.proc.poll() is None, "core exited early"
            time.sleep(0.1)
        return predicate()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def _outcome_for(core: Core, src: str):
    for record in core.records():
        if record.get("normalized", {}).get("src_ip") == src and "enforcement" in record:
            return record["enforcement"]
    return None


def _release_for(core: Core, task_id: str):
    for record in core.records():
        if record.get("release", {}).get("release_task_id") == task_id and record["release"]["status"] == "released":
            return record["release"]
    return None


def test_only_the_attack_flow_is_limited_and_management_and_shaping_survive(topology):
    sink = topology
    before_qdisc = _root_qdisc()
    assert before_qdisc == {"kind": "fq_codel", "handle": "1:"}
    base_atk = _throughput(sink, "atk")
    base_mgr = _throughput(sink, "mgr")
    assert base_atk > 1_000_000 and base_mgr > 1_000_000, (base_atk, base_mgr)
    with tempfile.TemporaryDirectory(prefix="azscoped-") as tmp:
        core = Core(Path(tmp))
        try:
            # The management host is protected: an alert naming it restricts
            # nothing and says why.
            core.alert(ADDR["mgr"], 3, 9201)
            refused = core.wait(lambda: _outcome_for(core, ADDR["mgr"]), 10)
            assert refused and refused["selected_action"] == "notify", refused
            assert refused["metadata"]["safety"]["gate"] == "refused:protected_flow:management"
            assert _owned_rules() == []

            core.alert(ADDR["atk"], 3, 9202)
            applied = core.wait(lambda: _outcome_for(core, ADDR["atk"]), 10)
            assert applied and applied["result"] == "applied", applied
            assert applied["metadata"]["release_ledger_state"] == "active"
            rules = _owned_rules()
            assert len(rules) == 1 and rules[0]["comment"] == applied["metadata"]["release_owner_token"]
            assert _root_qdisc() == before_qdisc, "the restriction changed the interface qdisc"

            held_atk = _throughput(sink, "atk")
            held_mgr = _throughput(sink, "mgr")
            # 32 kbytes/s limit (plus the burst and TCP's retransmits).
            assert held_atk < 150_000, held_atk
            assert held_mgr > 0.5 * base_mgr and held_mgr > 1_000_000, (held_mgr, base_mgr)

            task_id = applied["metadata"]["release_task_id"]
            released = core.wait(lambda: _release_for(core, task_id), TTL_SEC + 20)
            assert released and released["result"] == "rollback_applied_and_absence_verified", released
            assert released["attempted_at_epoch"] - released["due_epoch"] < 3.0
            assert _owned_rules() == []
            assert _root_qdisc() == before_qdisc, "release changed the interface qdisc"
            after_atk = _throughput(sink, "atk")
            assert after_atk > 1_000_000, after_atk
        finally:
            core.stop()


WEDGE = """#!/bin/sh
# nft for the core under test: an insert for the wedge source never returns.
case "$*" in
  *"saddr 10.91.1.66 "*) exec sleep 600 ;;
esac
exec "{real}" "$@"
"""


def test_a_wedged_apply_is_killed_and_never_holds_back_a_due_release(topology):
    with tempfile.TemporaryDirectory(prefix="azwedge-") as tmp:
        work = Path(tmp)
        wrapper_dir = work / "bin"
        wrapper_dir.mkdir()
        real = wrapper_dir / "nft.real"
        shutil.copy2(shutil.which("nft"), real)
        wrapper = wrapper_dir / "nft"
        wrapper.write_text(WEDGE.format(real=real), encoding="utf-8")
        os.chmod(wrapper, 0o755)
        core = Core(work, wrapper_dir)
        try:
            core.alert(ADDR["atk"], 3, 9301)
            applied = core.wait(lambda: _outcome_for(core, ADDR["atk"]), 10)
            assert applied and applied["result"] == "applied", applied
            task_id = applied["metadata"]["release_task_id"]
            due = applied["metadata"]["release_due_epoch"]
            # The first wedged apply (3 s) starts 1.5 s before the lease falls
            # due, so the decision loop is inside it at the due time. A sweep
            # on the decision loop could only run after it (>= 1.5 s late; the
            # per-poll work bound ends the poll after one wedge); the sweep
            # thread releases on time.
            while time.time() < due - 1.5:
                time.sleep(0.02)
            # Six flows (one port each), so each is admitted and wedges.
            for n in range(6):
                core.alert("10.91.1.66", 3, 9400 + n, 6000 + n)
            released = core.wait(lambda: _release_for(core, task_id), 15)
            assert released, "the due lease was not released while applies were wedged"
            assert released["attempted_at_epoch"] - due < 1.0, released
            # The wedged applies were still running around the release.
            def all_wedged():
                found = [r for r in core.records()
                         if r.get("normalized", {}).get("src_ip") == "10.91.1.66" and "enforcement" in r]
                return found if len(found) == 6 else None

            wedged = core.wait(all_wedged, 40)
            assert wedged, "the wedged alerts were not all decided"
            for record in wedged:
                outcome = record["enforcement"]
                assert outcome["result"] == "failed" and "command timeout" in outcome["errors"][0], outcome
                assert outcome["metadata"]["release_ledger_state"] == "uncertain_release_scheduled"
            # The release happened while the decision loop was inside a
            # wedged apply (each is decided at ingest, then held 3 s).
            starts = sorted(r["normalized"]["ingest_epoch"] for r in wedged)
            at = released["attempted_at_epoch"]
            assert starts[0] < at < starts[0] + 2.8, (starts, at)
            # Each wedged lease was released at once, not after its TTL.
            def wedged_released():
                ids = [r["enforcement"]["metadata"]["release_task_id"] for r in wedged]
                return all(_release_for(core, i) for i in ids) or None

            assert core.wait(wedged_released, 15)
            assert _owned_rules() == []
        finally:
            core.stop()
