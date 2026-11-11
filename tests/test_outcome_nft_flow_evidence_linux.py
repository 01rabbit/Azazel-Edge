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


def _source_identity():
    expected = os.environ.get("EDGE_NFT_FLOW_PROOF_SOURCE_COMMIT", "")
    network.require(re.fullmatch(r"[0-9a-f]{40}", expected), "reviewed source revision required")
    source_root = Path(__file__).resolve().parents[1]
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory = os.open("/", flags | os.O_DIRECTORY)
    try:
        for name in source_root.parts[1:]:
            info = os.fstat(directory)
            network.require(info.st_uid == 0 and not info.st_mode & 0o022,
                            "source revision requires protected root-owned ancestors")
            child = os.open(name, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        network.require(info.st_uid == 0 and not info.st_mode & 0o022, "source root is not protected")
        fd = os.open("SOURCE_REVISION", flags | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            network.require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_nlink == 1
                            and not before.st_mode & 0o022 and before.st_size <= 41,
                            "protected plain SOURCE_REVISION required")
            raw = os.read(fd, 42)
            after = os.fstat(fd)
            named = os.stat("SOURCE_REVISION", dir_fd=directory, follow_symlinks=False)
            fingerprint = lambda value: (value.st_dev, value.st_ino, value.st_uid, value.st_mode,
                                          value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            network.require(fingerprint(before) == fingerprint(after) == fingerprint(named)
                            and raw in (expected.encode(), (expected + "\n").encode()),
                            "SOURCE_REVISION mismatch or identity changed")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    return dict(source_revision=expected,
                helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                network_driver_sha256=hashlib.sha256(Path(network.__file__).read_bytes()).hexdigest())


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
    identity = _source_identity()
    tools = network.prerequisites(True, expected)
    image = network.CORE.read_bytes()
    machine = {"aarch64": 183, "arm64": 183, "x86_64": 62, "amd64": 62}.get(platform.machine().lower())
    network.require(machine is not None and len(image) >= 20 and image[:6] == b"\x7fELF\x02\x01"
                    and int.from_bytes(image[18:20], "little") == machine,
                    "reviewed core must be native ELF64 for this VM")
    return dict(reviewed_source_commit=source, core_sha256=expected, tool_sha256=tools,
                native_machine=platform.machine(), kernel=platform.release(),
                kernel_boot_id=network.read_boot_id(), **identity)


def _probe_child():
    from azazel_edge.outcome import nft_flow_evidence as flow
    from azazel_edge.outcome.postcondition import SubprocessReadOnlyRunner
    network.require(sys.argv[1:] == ["--root-readonly-nft"] and os.geteuid() == 0 and tuple(flow.QUERY) == QUERY,
                    "fixed root read-only nft child only")
    # Direct child invocation must not bypass the explicit root/VM/source/core
    # gates. Route checks now apply inside the owned namespace as well.
    pins = _guard()
    identity = {key: pins[key] for key in ("source_revision", "helper_sha256", "network_driver_sha256")}
    kernel_boot = pins["kernel_boot_id"]
    binary = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
    network.require(binary is not None, "trusted nft binary unavailable")
    started = datetime.now(timezone.utc).isoformat()
    result = SubprocessReadOnlyRunner().run(QUERY, timeout_seconds=2)
    ended = datetime.now(timezone.utc).isoformat()
    print(json.dumps(dict(argv=list(result.argv), returncode=result.returncode,
                          stdout=result.stdout, stderr=result.stderr,
                          query_started_at=started, query_ended_at=ended,
                          root_pid=os.getpid(), root_uid=os.geteuid(), kernel_boot_id=kernel_boot,
                          source_identity=identity,
                          netns_inode=os.stat("/proc/self/ns/net").st_ino,
                          nft_binary_sha256=hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                          capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns")), flush=True)


def _query(assets, label, pins):
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
                    and receipt.get("netns_inode") == assets.created[assets.names["edge"]][2]
                    and receipt.get("kernel_boot_id") == pins["kernel_boot_id"] == network.read_boot_id()
                    and receipt.get("source_identity") == {key: pins[key] for key in
                         ("source_revision", "helper_sha256", "network_driver_sha256")},
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


def _require_zero_owner_rules(payload, owner_token):
    # Full-chain schema validation is performed first by readback_matches.
    # A tuple/rate mismatch is not absence when the owner's rule still exists.
    remaining = [entry["rule"] for entry in payload["nftables"]
                 if "rule" in entry and entry["rule"].get("comment") == owner_token]
    network.require(not remaining, "owned rule still present; semantic mismatch is not verified absence")


def test_release_absence_refuses_semantically_changed_owned_rule():
    owner = "azazel-edge:release-owned-unit-test"
    payload = {"nftables": [
        {"chain": {"family": "inet", "table": "azazel_edge", "name": "throttle", "handle": 1,
                   "type": "filter", "hook": "prerouting", "prio": -150, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "azazel_edge", "chain": "throttle", "handle": 2,
                  "comment": owner, "expr": [
                      {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                                 "right": "10.91.3.99"}},
                      {"limit": {"rate": 1, "rate_unit": "kbytes", "burst": 1, "burst_unit": "kbytes",
                                 "per": "second", "inv": True}}, {"drop": None}]}},
    ]}
    # This owned rule no longer matches the original tuple/rate, but its owner
    # is still present. The added independent absence check must refuse it.
    with pytest.raises(ValueError, match="owned rule still present"):
        _require_zero_owner_rules(payload, owner)
    payload["nftables"].pop()
    _require_zero_owner_rules(payload, owner)


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
                      kernel_boot_id=pins["kernel_boot_id"],
                      traffic_started=False, production_observer_used=False, production_origin_admitted=False))
    before = network.root_snapshot()
    network.write_new(work / "root-before.json", before)
    assets = network.Assets(work)
    try:
        assets.setup()
        baseline = _query(assets, "before-apply", pins)
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
        applied = _query(assets, "applied", pins)
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
        after = _query(assets, "released", pins)
        remaining = flow.parse_readback(after["stdout"])
        no_semantic_match = flow.readback_matches(remaining, scope) is False  # validates the full chain first
        _require_zero_owner_rules(remaining, scope["owner_token"])
        network.require(no_semantic_match and _foreign(remaining, assets.foreign) == foreign,
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
