"""REAL kernel protocol-copy tests; target responses are control_only, not proof.

The observer never receives from a target socket or reads userspace buffers.
A successful protocol payload copy is deliberately NOT syscall/application success.
"""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

from udp_payload_copy_data import make_inputs, PAYLOAD
from udp_payload_copy_lab import COPY_TARGET_WORKER
import test_udp_queue_linux as queue_lab

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root and preprovisioned BPF toolchain required",
)
lab = queue_lab.lab
line, command, wire, digest = (
    queue_lab.line,
    queue_lab.command,
    queue_lab.wire,
    queue_lab.digest,
)
TARGET_UID, PRODUCER = queue_lab.TARGET_UID, queue_lab.PRODUCER
ROOT = Path(__file__).resolve().parents[1]
SENSOR_WORKER = (
    queue_lab.SENSOR_WORKER.replace(
        "azazel_edge.benchmark.udp_queue", "azazel_edge.benchmark.udp_payload_copy"
    )
    .replace("capture_udp_queue", "capture_udp_payload_copy")
    .replace("UDPQueueError", "UDPPayloadCopyError")
    .replace("from udp_queue_data import KEY", "from udp_payload_copy_data import KEY")
)
JOIN_WORKER = (
    queue_lab.JOIN_WORKER.replace(
        "azazel_edge.benchmark.udp_queue",
        "azazel_edge.benchmark.udp_payload_copy_collection",
    )
    .replace("collect_udp_queue", "collect_udp_payload_copy")
    .replace("UDPQueueError", "UDPPayloadCopyError")
)


@pytest.fixture(scope="session")
def copy_object():
    directory = Path(tempfile.mkdtemp(prefix="edge-udp-copy-object-", dir="/run"))
    directory.chmod(0o755)
    try:
        with (directory / "vmlinux.h").open("wb") as output:
            subprocess.run(
                [
                    "bpftool",
                    "btf",
                    "dump",
                    "file",
                    "/sys/kernel/btf/vmlinux",
                    "format",
                    "c",
                ],
                stdout=output,
                check=True,
                timeout=30,
            )
        arch = {"aarch64": "arm64", "x86_64": "x86"}[platform.machine()]
        obj = directory / "copy.bpf.o"
        subprocess.run(
            [
                "clang",
                "-g",
                "-O2",
                "-target",
                "bpf",
                "-D__TARGET_ARCH_" + arch,
                "-I" + str(directory),
                "-c",
                str(ROOT / "native/udp_payload_copy_observer.bpf.c"),
                "-o",
                str(obj),
            ],
            check=True,
            timeout=60,
        )
        obj.chmod(0o444)
        yield obj
    finally:
        shutil.rmtree(directory)


def ready(process):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                "copy observer stopped before three links: "
                + process.stdout.read()
                + process.stderr.read()
            )
        try:
            names = [os.readlink(p) for p in Path(f"/proc/{process.pid}/fd").iterdir()]
            if sum("bpf-link" in name or "bpf_link" in name for name in names) == 3:
                return
        except (FileNotFoundError, ProcessLookupError):
            pass
        time.sleep(0.005)
    raise AssertionError("three kernel copy links not ready")


def setup_capture(lab, copy_object, *, filter_drop=False, without_caps=False):
    target = lab(
        COPY_TARGET_WORKER, ["filter-drop" if filter_drop else "allow"], uid=TARGET_UID
    )
    metadata = line(target)
    sender = lab(queue_lab.SENDER_WORKER, uid=PRODUCER)
    source_port = line(sender)["port"]
    net, pid, tim = [
        os.stat("/proc/self/ns/" + name) for name in ("net", "pid", "time")
    ]
    offsets = {
        parts[0]: int(parts[1]) * 1_000_000_000 + int(parts[2])
        for parts in (
            row.split()
            for row in Path("/proc/self/timens_offsets").read_text().splitlines()
        )
    }
    assert offsets == dict(monotonic=0, boottime=0)
    now = time.monotonic_ns()
    contract, plan, _ = make_inputs(
        net.st_dev,
        net.st_ino,
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        source_port,
        metadata["port"],
        now - 1_000_000,
        now + 4_000_000_000,
        PAYLOAD,
        metadata["target"],
        platform.release(),
        digest(Path("/sys/kernel/btf/vmlinux").read_bytes()),
        digest(copy_object.read_bytes()),
        pidns=dict(device=pid.st_dev, inode=pid.st_ino),
        timens=dict(
            device=tim.st_dev,
            inode=tim.st_ino,
            monotonic_offset_ns=0,
            boottime_offset_ns=0,
        ),
    )
    c, p = json.loads(contract), json.loads(plan)
    c["scope"]["run_id"] = "real-linux-protocol-copy-run"
    c["scope"]["scope_ref"] = "real-linux-protocol-copy-scope"
    for category, channel in c["channels"].items():
        channel["capture_id"] = "real-linux-copy-capture-" + category
        channel["channel_id"] = "real-linux-copy-channel-" + category
    c["opportunities"]["protected_escape"][0]["id"] = "real-linux-copy-opportunity"
    contract = wire(c)
    p.update(
        contract_sha256=digest(contract),
        opportunity_id="real-linux-copy-opportunity",
        max_duration_ns=1_000_000_000,
    )
    plan = wire(p)
    pins = dict(
        expected_contract_sha256=digest(contract), expected_plan_sha256=digest(plan)
    )
    sensor = lab(SENSOR_WORKER)
    sensor.stdin.write(
        json.dumps(
            dict(
                contract=contract.decode(),
                plan=plan.decode(),
                object_path=str(copy_object),
                without_caps=without_caps,
                **pins,
            )
        )
    )
    sensor.stdin.close()
    return target, sender, metadata, sensor, contract, plan, pins


def _assert_unqualified(result):
    assert result["successful_syscall_count"] is None
    assert result["application_delivery_count"] is None
    assert result["qualified_safety_count"] is None
    assert result["independently_measured"] is False
    assert all(
        v["observed_violation_count"] is None
        for v in result["safety_evaluation"]["categories"].values()
    )
    assert not any(result["safety_evaluation"]["authority_flags"].values())


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("iovec", 1),
        ("ubuf", 1),
        ("namefault", 1),
        ("peek", None),
        ("short", None),
        ("trunc", None),
        ("copyfault", None),
        ("no-read", None),
        ("filter-drop", None),
        ("wrong-challenge", None),
        ("replace", None),
        ("inherited", 1),
    ],
)
def test_actual_protocol_copy_controls(lab, copy_object, mode, expected):
    from azazel_edge.benchmark.udp_payload_copy import evaluate_udp_payload_copy

    target, sender, metadata, sensor, contract, plan, pins = setup_capture(
        lab, copy_object, filter_drop=mode == "filter-drop"
    )
    ready(sensor)
    if mode == "replace":
        replacement = command(target, dict(op="replace"))
        assert (
            replacement["target"]["socket_cookie"]
            != metadata["target"]["socket_cookie"]
        )
    payload = b"x" * 64 if mode == "wrong-challenge" else PAYLOAD
    assert command(sender, dict(port=metadata["port"], payload_hex=payload.hex()))[
        "sent"
    ]
    control = None
    if mode != "no-read":
        control = command(
            target,
            dict(
                op="inherit_receive" if mode == "inherited" else "copy",
                mode=mode
                if mode
                in {"iovec", "ubuf", "namefault", "peek", "short", "trunc", "copyfault"}
                else "iovec",
            ),
        )
        assert control["control_only"] is True
    outcome = line(sensor)
    sensor.wait(timeout=5)
    assert "report" in outcome, outcome
    raw = outcome["report"].encode()
    report = json.loads(raw)
    result = evaluate_udp_payload_copy(contract, plan, raw, **pins)
    assert result["protocol_payload_copy_observed_count"] == expected
    _assert_unqualified(result)
    if expected:
        assert len(report["events"]) == 1
        event = report["events"][0]
        facts = control["result"] if mode == "inherited" else control
        assert facts["control_only"] is True
        assert event["receiver_tgid"] == facts["receiver"]["pid"]
        assert event["receiver_tid"] == facts["receiver"]["tid"]
        assert (
            event["receiver_real_uid"] == event["receiver_effective_uid"] == TARGET_UID
        )
        assert event["receiver_start_boottime_ns"] > 0
        assert event["payload_hex"] == facts["payload_hex"] == PAYLOAD.hex()
        if mode == "namefault":
            assert facts["ret"] == -1 and facts["errno"] == 14
        else:
            assert facts["ret"] == 64 and facts["errno"] == 0
        if mode == "inherited":
            assert control["receiver_child_reaped"] is True
            assert (
                event["receiver_tgid"]
                == control["receiver_child_pid"]
                != control["locator_pid"]
            )
    else:
        assert report["events"] == []
        if mode == "copyfault":
            assert control["ret"] == -1 and control["errno"] == 14
        if mode == "filter-drop":
            assert control["ret"] == -1 and control["errno"] == 11
        if mode == "no-read":
            # Separate AFTER-detach target-only control: bytes remained queued.
            received = command(target, dict(op="copy", mode="iovec"))
            assert received["control_only"] and received["payload_hex"] == PAYLOAD.hex()


def test_actual_copy_capability_refusal(lab, copy_object):
    *_, sensor, contract, plan, pins = setup_capture(
        lab, copy_object, without_caps=True
    )
    assert line(sensor)["rejected"] is True
    sensor.wait(timeout=5)


def test_actual_signed_copy_sealed_collection(lab, copy_object):
    target, sender, metadata, sensor, contract, plan, pins = setup_capture(
        lab, copy_object
    )
    ready(sensor)
    assert command(sender, dict(port=metadata["port"], payload_hex=PAYLOAD.hex()))[
        "sent"
    ]
    assert command(target, dict(op="copy", mode="iovec"))["ret"] == 64
    outcome = line(sensor)
    sensor.wait(timeout=5)
    assert "report" in outcome, outcome
    report = outcome["report"].encode()
    c, sha = json.loads(contract), digest(contract)
    directory = Path(tempfile.mkdtemp(prefix="edge-copy-sealed-", dir="/run"))
    directory.chmod(0o755)
    try:
        paths = {
            name: directory / (name + ".json")
            for name in (
                "enrollment",
                "contract",
                "observations",
                "checkpoint",
                "plan",
                "report",
            )
        }
        enrollment = dict(
            schema_version="edge-safety-enrollment/v1",
            contract_sha256=sha,
            scope=c["scope"],
            observer_uid=TARGET_UID,
            paths={
                k: str(paths[k]) for k in ("contract", "observations", "checkpoint")
            },
        )
        checkpoint = dict(
            schema_version="edge-safety-checkpoint/v1",
            contract_sha256=sha,
            scope=c["scope"],
            capture_ids={k: v["capture_id"] for k, v in c["channels"].items()},
            stream_heads=dict.fromkeys(c["channels"]),
        )
        files = dict(
            enrollment=wire(enrollment),
            contract=contract,
            observations=wire(
                dict(
                    schema_version="edge-finite-safety-observations/v1",
                    contract_sha256=sha,
                    scope=c["scope"],
                    channels={},
                )
            ),
            checkpoint=wire(checkpoint),
            plan=plan,
            report=report,
        )
        for name, raw in files.items():
            paths[name].write_bytes(raw)
            paths[name].chmod(0o444)
        args = {
            name + "_path": str(paths[name])
            for name in ("enrollment", "plan", "report")
        }
        args.update(
            {
                "expected_" + name + "_sha256": digest(files[name])
                for name in ("enrollment", "checkpoint", "plan", "report")
            }
        )
        process = lab(JOIN_WORKER, uid=TARGET_UID)
        process.stdin.write(json.dumps(args))
        process.stdin.close()
        answer = line(process)
        assert "result" in answer, answer
        result = answer["result"]
        copied = result["payload_copy"]
        assert copied["protocol_payload_copy_observed_count"] == 1
        _assert_unqualified(copied)
        args["expected_report_sha256"] = "f" * 64
        process = lab(JOIN_WORKER, uid=TARGET_UID)
        process.stdin.write(json.dumps(args))
        process.stdin.close()
        assert line(process)["rejected"] is True
        assert all(path.read_bytes() == files[name] for name, path in paths.items())
    finally:
        shutil.rmtree(directory)
