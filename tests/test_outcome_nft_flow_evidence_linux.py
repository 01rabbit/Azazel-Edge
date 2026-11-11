"""Opt-in actual kernel mechanism/ownership proof; no traffic or observer claims.

Root stages a combined source containing nft_flow_evidence before the one fresh
VM run. No production observer UID, capability or confinement changes occur.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import stat
import sys
import time

# The same fixed file is a child entry point under isolated Python startup.
if __name__ == "__main__":
    sys.path[:0] = [str(Path(__file__).resolve().parents[1] / "py"), str(Path(__file__).resolve().parent)]

import pytest
import network_measure_driver as network

FLAG = "EDGE_NFT_FLOW_PROOF_TESTS"
MARKER = Path("/etc/edge-nft-flow-proof-vm")
MAGIC = b"azazel-edge-nft-flow-proof-v1\n"
QUERY = ("nft", "-j", "list", "chain", "inet", "azazel_edge", "throttle")
SCOPE = "root_local_kernel_mechanism_only_not_production_observer_or_effect"


def _guard():
    network.require(os.environ.get(FLAG) == "1" and sys.platform.startswith("linux") and os.geteuid() == 0,
                    "explicit root Linux kernel-proof opt-in required")
    fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        network.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                        and not info.st_mode & 0o022 and os.read(fd, 129) == MAGIC,
                        "protected disposable kernel-proof VM marker required")
    finally:
        os.close(fd)
    network.require(network.command("systemd-detect-virt", "--vm").stdout.strip(), "fresh disposable VM required")
    source = os.environ.get("EDGE_NFT_FLOW_PROOF_SOURCE_COMMIT", "")
    expected = os.environ.get("EDGE_NETWORK_MEASURE_CORE_SHA256", "")
    network.require(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[0-9a-f]{64}", expected),
                    "reviewed source/core pins required")
    tools = network.prerequisites(True, expected)
    image = network.CORE.read_bytes()
    machine = {"aarch64": 183, "arm64": 183, "x86_64": 62, "amd64": 62}.get(platform.machine().lower())
    network.require(machine is not None and len(image) >= 20 and image[:6] == b"\x7fELF\x02\x01"
                    and int.from_bytes(image[18:20], "little") == machine,
                    "reviewed core must be native ELF64 for this VM")
    return dict(reviewed_source_commit=source, core_sha256=expected, tool_sha256=tools,
                native_machine=platform.machine(), kernel=platform.release())


def _probe_child():
    from azazel_edge.outcome import nft_flow_evidence as flow
    from azazel_edge.outcome.postcondition import SubprocessReadOnlyRunner
    network.require(sys.argv[1:] == ["--root-readonly-nft"] and os.geteuid() == 0 and tuple(flow.QUERY) == QUERY,
                    "fixed root read-only nft child only")
    binary = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    network.require(binary is not None, "trusted nft binary unavailable")
    started = datetime.now(timezone.utc).isoformat()
    result = SubprocessReadOnlyRunner().run(QUERY, timeout_seconds=2)
    ended = datetime.now(timezone.utc).isoformat()
    print(json.dumps(dict(argv=list(result.argv), returncode=result.returncode,
                          stdout=result.stdout, stderr=result.stderr,
                          query_started_at=started, query_ended_at=ended,
                          root_pid=os.getpid(), root_uid=os.geteuid(),
                          netns_inode=os.stat("/proc/self/ns/net").st_ino,
                          nft_binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                          capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns")), flush=True)


def _query(assets, label):
    child = assets.spawn("edge", [sys.executable, "-I", str(Path(__file__).resolve()), "--root-readonly-nft"])
    network.write_new(assets.work / (label + "-probe-launch.json"), dict(
        actual_child_argv=list(map(str, child.args)), child_pid=child.pid,
        expected_namespace_inode=assets.created[assets.names["edge"]][2]))
    # Allow bounded interpreter/import overhead in addition to the runner's 2s
    # query deadline. Retain the exact envelope even on timeout/invalid output.
    raw = bytearray()
    until = time.monotonic() + 8
    with (assets.work / (label + "-raw-probe-envelope.jsonl")).open("xb") as retained:
        try:
            while not raw.endswith(b"\n"):
                remaining = until - time.monotonic()
                network.require(remaining > 0, "root query envelope absolute deadline")
                readable, _, _ = select.select([child.stdout], [], [], remaining)
                network.require(readable, "root query envelope absolute deadline")
                chunk = os.read(child.stdout.fileno(), 65536)
                network.require(chunk, "root query supplied no complete envelope")
                retained.write(chunk)
                raw.extend(chunk)
                network.require(len(raw) <= 8 * 1024 * 1024, "root query envelope exceeds bound")
        finally:
            retained.flush()
            os.fsync(retained.fileno())
    receipt = json.loads(raw)
    receipt["actual_child_argv"] = list(map(str, child.args))
    receipt["source"] = "live_root_query_recorded_once_for_pure_projection"
    # Persist refusals too; no bad return code/identity/time is dropped as noise.
    network.write_new(assets.work / (label + "-raw-readonly-receipt.json"), receipt)
    child.wait(timeout=5)
    network.require(child.returncode == 0 and receipt.get("argv") == list(QUERY)
                    and receipt.get("returncode") == 0 and receipt.get("root_uid") == 0
                    and receipt.get("root_pid") == child.pid
                    and receipt.get("netns_inode") == assets.created[assets.names["edge"]][2],
                    "independent root query identity/result mismatch")
    start, end = (datetime.fromisoformat(receipt[key]) for key in ("query_started_at", "query_ended_at"))
    network.require(start.utcoffset() is not None and end.utcoffset() is not None and start <= end,
                    "actual query timestamps invalid")
    return receipt


def _event_line(assets, predicate, timeout):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        network.require(assets.core.poll() is None, "core exited before required execution/release fact")
        if assets.events.exists():
            for line in assets.events.read_bytes().splitlines(keepends=True):
                if not line.endswith(b"\n"):
                    continue  # incomplete in-flight append is never reconstructed
                event = json.loads(line)
                if predicate(event):
                    return event, line.decode("utf-8")
        time.sleep(.05)
    raise AssertionError("bounded wait ended without required original core fact")


def _foreign(payload, token):
    rules = [entry["rule"] for entry in payload["nftables"] if "rule" in entry and entry["rule"].get("comment") == token]
    network.require(len(rules) == 1, "foreign operator canary missing/duplicated")
    return rules[0]


@pytest.mark.skipif(os.environ.get(FLAG) != "1", reason="requires one reviewed fresh marked offline root VM kernel proof")
def test_actual_native_nft_flow_mechanism_and_owned_release(tmp_path):
    pins = _guard()
    from azazel_edge.outcome import from_rust_event, verify_mechanism_postcondition, nft_flow_evidence as flow
    from azazel_edge.outcome.golden_replay import RecordedProbeRunner
    from azazel_edge.outcome.ownership import expected_ownership
    network.require(tuple(flow.QUERY) == QUERY and flow.SCOPE_KIND == "nft_flow_limit", "reviewed flow API required")
    work = tmp_path / "kernel-proof"
    work.mkdir(mode=0o700)  # existing output refuses; no replay/backfill/overwrite
    api_hashes = {}
    for name in ("nft_flow_evidence.py", "adapter.py", "ownership.py", "postcondition.py"):
        api_hashes[name] = hashlib.sha256((Path(flow.__file__).parent / name).read_bytes()).hexdigest()
    network.write_new(work / "intent.json", dict(scope=SCOPE, pins=pins, api_sha256=api_hashes,
                      traffic_started=False, production_observer_used=False, production_origin_admitted=False))
    before = network.root_snapshot()
    network.write_new(work / "root-before.json", before)
    assets = network.Assets(work)
    try:
        assets.setup()
        baseline = _query(assets, "before-apply")
        foreign = _foreign(flow.parse_readback(baseline["stdout"]), assets.foreign)
        assets.start_core(True)
        with assets.eve.open("a") as stream:
            stream.write(network._alert(network.ATK, 1, 393101, port=network.PORT, dst=network.SERVER) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        event, original_line = _event_line(assets, lambda row: row.get("normalized", {}).get("sid") == 393101
                                          and row.get("enforcement", {}).get("result") == "applied", 10)
        network.write_new(work / "original-apply-event.json", dict(original_core_event_line=original_line,
                          original_source_file="events.jsonl", parsed_event=event))
        applied = _query(assets, "applied")
        payload = flow.parse_readback(applied["stdout"])
        bundle = from_rust_event(event)
        execution_before = asdict(bundle.execution)
        network.require(bundle.mechanism.status.value == "unverified" and bundle.mechanism.scope.get("scope_kind") == flow.SCOPE_KIND
                        and "interface" not in bundle.mechanism.scope, "native flow must not masquerade as interface TBF")
        scope = bundle.mechanism.scope
        network.require(scope["source_ip"] == network.ATK and scope["destination_ip"] == network.SERVER
                        and scope["protocol"] == "tcp" and scope["destination_port"] == network.PORT
                        and scope["rate_bytes_per_second"] == scope["burst_bytes"] == 16 * 1024,
                        "actual core requested unexpected flow tuple/rate")
        network.require(expected_ownership(bundle.execution) == {"kind": "nft_comment", "value": scope["owner_token"]}
                        and flow.readback_matches(payload, scope) is True
                        and _foreign(payload, assets.foreign) == foreign,
                        "full actual chain does not prove the exact owned flow")
        recorded = RecordedProbeRunner([applied])  # explicitly recorded live receipt, never synthetic readback
        observed = verify_mechanism_postcondition(execution=bundle.execution, mechanism=bundle.mechanism,
                    runner=recorded, observed_at=applied["query_ended_at"], timeout_seconds=2)
        network.require(observed.status.value == "observed" and recorded.calls == [QUERY]
                        and asdict(bundle.execution) == execution_before,
                        "public mechanism/ownership projection did not verify actual readback")
        network.write_new(work / "observed-mechanism.json", dict(mechanism=observed.to_dict(),
                          execution=bundle.execution.to_dict(), raw_receipt="applied-raw-readonly-receipt.json"))
        task = event["enforcement"]["metadata"]["release_task_id"]
        released, released_line = _event_line(assets, lambda row: row.get("release", {}).get("release_task_id") == task
                                             and row["release"].get("status") == "released", 45)
        release = released["release"]
        network.require(release.get("result") == "rollback_applied_and_absence_verified"
                        and release.get("postcondition", {}).get("verified") is True,
                        "core did not report verified owned release")
        network.write_new(work / "original-release-event.json", dict(original_core_event_line=released_line,
                          original_source_file="events.jsonl", parsed_event=released))
        after = _query(assets, "released")
        remaining = flow.parse_readback(after["stdout"])
        network.require(flow.readback_matches(remaining, scope) is False and _foreign(remaining, assets.foreign) == foreign,
                        "independent release readback failed or changed foreign canary")
    finally:
        try:
            assets.close()
        finally:
            after_root = network.root_snapshot()
            network.write_new(work / "root-after.json", after_root)
            network.require(after_root == before, "root routes/rules changed; retain failed proof")
    network.write_new(work / "result.json", dict(scope=SCOPE, actual_kernel_mechanism_verified=True,
                      owned_release_absence_verified=True, foreign_preserved=True, cleanup_verified=True,
                      root_routes_rules_unchanged=True, traffic_started=False, service_effect_measured=False,
                      production_observer_used=False, production_origin_admitted=False, sealed_origin_verified=False,
                      efficacy_claim=False, source_pins=pins))


if __name__ == "__main__":
    _probe_child()
