"""REAL AF_PACKET/loopback observations in isolated Linux, never sensor fixtures.

Only the harness sends UDP or creates a disposable target. The product sensor has
NET_RAW alone and NNP; the enrolled reader is a different nonroot UID. Observed
application receipt below is a harness control, never a sensor delivery claim.
"""

import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import time

import pytest
from azazel_edge.outcome.journal import _json
from protected_ingress_data import make_inputs

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root required for actual NET_RAW capture and child UIDs",
)
PRODUCER, READER = 61001, 61002
PAYLOAD = b"edge-real-ingress-challenge-v1-unique"
UDP_WORKER = r"""
import json,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',0))
print(json.dumps({'port':s.getsockname()[1]}),flush=True)
if sys.argv[1]=='target':
 s.settimeout(5)
 raw,peer=s.recvfrom(2048)
 print(json.dumps({'received_hex':raw.hex()}),flush=True)
else:
 args=json.loads(sys.stdin.readline())
 s.sendto(bytes.fromhex(args['payload_hex']),('127.0.0.1',args['port']))
 print(json.dumps({'sent':True}),flush=True)
s.close()
"""
SENSOR_WORKER = r"""
import ctypes,json,sys
from azazel_edge.benchmark.protected_ingress import capture_protected_ingress,SafetyIngressError
from protected_ingress_data import KEY
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
a=json.loads(sys.stdin.read());libc=ctypes.CDLL(None,use_errno=True)
for capability in range(64):
 if capability==13:continue
 if libc.prctl(24,capability,0,0,0)!=0 and ctypes.get_errno()!=22:
  raise OSError(ctypes.get_errno(),'bounding set drop')
h=Header(0x20080522,0);data=(Data*2)();mask=0 if a.get('without_net_raw') else 1<<13
data[0].effective=data[0].permitted=mask
if libc.capset(ctypes.byref(h),ctypes.byref(data))!=0:raise OSError(ctypes.get_errno(),'capset')
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'NoNewPrivs')
try:
 raw=capture_protected_ingress(a['contract'].encode(),a['plan'].encode(),
  expected_contract_sha256=a['expected_contract_sha256'],expected_plan_sha256=a['expected_plan_sha256'],observer_private_key=KEY)
 print(json.dumps({'report':raw.decode()}),flush=True)
except SafetyIngressError as exc:print(json.dumps({'rejected':True,'reason':str(exc)}),flush=True)
"""
JOIN_WORKER = r"""
import json,sys
from pathlib import Path
from azazel_edge.benchmark.protected_ingress import collect_protected_ingress,SafetyIngressError
a=json.loads(sys.stdin.read())
try:
 r=collect_protected_ingress(Path(a.pop('enrollment_path')),Path(a.pop('plan_path')),Path(a.pop('report_path')),**a)
 print(json.dumps({'result':r}))
except SafetyIngressError:print(json.dumps({'rejected':True}))
"""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return _json(value) + b"\n"


def identity(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    return drop


def line(process):
    assert select.select([process.stdout], [], [], 8)[0], "lab child readiness timeout"
    raw = process.stdout.readline()
    assert raw, process.stderr.read()
    return json.loads(raw)


@pytest.fixture
def lab():
    processes = []

    def launch(code, args=(), uid=None):
        p = subprocess.Popen(
            [sys.executable, "-u", "-c", code, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=identity(uid) if uid is not None else None,
        )
        processes.append(p)
        return p

    try:
        yield launch
    finally:
        for p in processes:
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)
            for stream in (p.stdin, p.stdout, p.stderr):
                if stream is not None:
                    stream.close()


def inputs(source_port, target_port, *, expired=False, wrong_namespace=False):
    ns = os.stat("/proc/self/ns/net")
    now = time.monotonic_ns()
    contract_raw, plan_raw, _ = make_inputs(
        ns.st_dev,
        ns.st_ino + int(wrong_namespace),
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        source_port,
        target_port,
        now - 2_000_000_000 if expired else now - 1_000_000,
        now - 1_000_000_000 if expired else now + 2_000_000_000,
        PAYLOAD,
    )
    # Freeze real lab identities before capture; parser fixtures retain their
    # separate synthetic names. These public test keys prove no key custody.
    contract, plan = json.loads(contract_raw), json.loads(plan_raw)
    contract["scope"]["run_id"] = "real-linux-ingress-run"
    contract["scope"]["scope_ref"] = "real-linux-ingress-scope"
    for category, channel in contract["channels"].items():
        channel["capture_id"] = "real-linux-capture-" + category
        channel["channel_id"] = "real-linux-channel-" + category
    opportunity = contract["opportunities"]["protected_escape"][0]
    opportunity["id"] = "real-linux-ingress-opportunity"
    contract_raw = wire(contract)
    plan["contract_sha256"] = digest(contract_raw)
    plan["opportunity_id"] = opportunity["id"]
    plan_raw = wire(plan)
    return (
        contract_raw,
        plan_raw,
        dict(
            expected_contract_sha256=digest(contract_raw),
            expected_plan_sha256=digest(plan_raw),
        ),
    )


def sensor(lab, contract, plan, pins, *, without_net_raw=False):
    p = lab(SENSOR_WORKER)
    p.stdin.write(
        json.dumps(
            dict(
                contract=contract.decode(),
                plan=plan.decode(),
                without_net_raw=without_net_raw,
                **pins,
            )
        )
    )
    p.stdin.close()
    return p


def wait_bound_packet_socket(process):
    """Independent kernel readiness, never a product callback or fabricated sample."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                "sensor stopped before packet bind: "
                + process.stdout.read()
                + process.stderr.read()
            )
        try:
            held = {os.readlink(p) for p in Path(f"/proc/{process.pid}/fd").iterdir()}
            rows = Path(f"/proc/{process.pid}/net/packet").read_text().splitlines()[1:]
            for row in rows:
                fields = row.split()
                if (
                    fields[3] == "0800"
                    and int(fields[4]) == 1
                    and f"socket:[{fields[-1]}]" in held
                ):
                    return
        except (FileNotFoundError, ProcessLookupError):
            pass
        time.sleep(0.005)
    raise AssertionError("no bound passive packet socket")


def actual_capture(lab, *, traffic="matching"):
    target = lab(UDP_WORKER, ["target"], READER)
    target_port = line(target)["port"]
    sender = lab(UDP_WORKER, ["sender"], PRODUCER)
    source_port = line(sender)["port"]
    contract, plan, pins = inputs(source_port, target_port)
    capture = sensor(lab, contract, plan, pins)
    wait_bound_packet_socket(capture)
    if traffic != "none":
        payload = (
            PAYLOAD
            if traffic == "matching"
            else b"different-unrelated-loopback-payload"
        )
        sender.stdin.write(
            json.dumps(dict(port=target_port, payload_hex=payload.hex())) + "\n"
        )
        sender.stdin.flush()
        assert line(sender)["sent"] is True
        # Actual application control stays separate from the AF_PACKET report.
        assert line(target)["received_hex"] == payload.hex()
    outcome = line(capture)
    capture.wait(timeout=5)
    assert capture.returncode == 0, capture.stderr.read()
    assert "report" in outcome, outcome
    return contract, plan, pins, outcome["report"].encode()


@pytest.mark.parametrize(
    "traffic,expected", [("matching", 1), ("unrelated", None), ("none", None)]
)
def test_real_kernel_capture_never_becomes_delivery_or_zero(lab, traffic, expected):
    from azazel_edge.benchmark.protected_ingress import evaluate_ingress_capture

    contract, plan, pins, report = actual_capture(lab, traffic=traffic)
    result = evaluate_ingress_capture(contract, plan, report, **pins)
    assert result["observation_layer"] == "interface_ingress"
    assert result["interface_ingress_observed_count"] == expected
    assert result["qualified_safety_count"] is None
    assert result["independently_measured"] is False
    for category in result["safety_evaluation"]["categories"].values():
        assert category["observed_violation_count"] is None
    assert not any(result["safety_evaluation"]["authority_flags"].values())


@pytest.mark.parametrize("fault", ["without_net_raw", "expired", "wrong_namespace"])
def test_real_kernel_prerequisite_refusal(lab, fault):
    contract, plan, pins = inputs(
        40001,
        18080,
        expired=fault == "expired",
        wrong_namespace=fault == "wrong_namespace",
    )
    p = sensor(lab, contract, plan, pins, without_net_raw=fault == "without_net_raw")
    assert line(p)["rejected"] is True
    p.wait(timeout=5)
    assert p.returncode == 0


def test_real_capture_sealed_readonly_registered_join(lab):
    contract_raw, plan_raw, _, report_raw = actual_capture(lab)
    contract = json.loads(contract_raw)
    directory = Path(tempfile.mkdtemp(prefix="edge-real-ingress-", dir="/run"))
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
        contract_sha = digest(contract_raw)
        enrollment = dict(
            schema_version="edge-safety-enrollment/v1",
            contract_sha256=contract_sha,
            scope=contract["scope"],
            observer_uid=READER,
            paths={
                name: str(paths[name])
                for name in ("contract", "observations", "checkpoint")
            },
        )
        checkpoint = dict(
            schema_version="edge-safety-checkpoint/v1",
            contract_sha256=contract_sha,
            scope=contract["scope"],
            capture_ids={k: v["capture_id"] for k, v in contract["channels"].items()},
            stream_heads={k: None for k in contract["channels"]},
        )
        files = dict(
            enrollment=wire(enrollment),
            contract=contract_raw,
            plan=plan_raw,
            report=report_raw,
            checkpoint=wire(checkpoint),
            observations=wire(
                dict(
                    schema_version="edge-finite-safety-observations/v1",
                    contract_sha256=contract_sha,
                    scope=contract["scope"],
                    channels={},
                )
            ),
        )
        for name, raw in files.items():
            paths[name].write_bytes(raw)
            paths[name].chmod(0o444)
        # External pins retained after actual capture, before the reader sees paths.
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
        before = {name: path.read_bytes() for name, path in paths.items()}
        p = lab(JOIN_WORKER, uid=READER)
        p.stdin.write(json.dumps(args))
        p.stdin.close()
        joined = line(p)["result"]
        assert joined["ingress"]["interface_ingress_observed_count"] == 1
        assert all(
            v["observed_violation_count"] is None
            for v in joined["collection"]["evaluation"]["categories"].values()
        )
        assert {name: path.read_bytes() for name, path in paths.items()} == before
        args["expected_report_sha256"] = "f" * 64
        bad = lab(JOIN_WORKER, uid=READER)
        bad.stdin.write(json.dumps(args))
        bad.stdin.close()
        assert line(bad)["rejected"] is True
    finally:
        shutil.rmtree(directory)
