"""REAL read-only fentry/fexit queue observations, not synthetic event fixtures."""

import hashlib
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
from azazel_edge.outcome.journal import _json
import test_protected_ingress_linux as ingress_lab
from udp_queue_data import make_inputs, PAYLOAD

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root and preprovisioned BPF toolchain required",
)
ROOT = Path(__file__).resolve().parents[1]
PRODUCER, TARGET_UID = 61001, 61002
lab = ingress_lab.lab
line = ingress_lab.line
TARGET_WORKER = r"""
import ctypes,json,os,socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
if sys.argv[1]=='filter-drop':
 class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class Program(ctypes.Structure):_fields_=[('length',ctypes.c_ushort),('filter',ctypes.POINTER(Filter))]
 ins=(Filter*1)(Filter(6,0,0,0));prog=Program(1,ins);libc=ctypes.CDLL(None,use_errno=True)
 if libc.setsockopt(s.fileno(),socket.SOL_SOCKET,26,ctypes.byref(prog),ctypes.sizeof(prog))!=0:raise OSError(ctypes.get_errno(),'owned socket filter')
def metadata():
 stat=open('/proc/self/stat').read();start=int(stat[stat.rfind(')')+2:].split()[19])
 return dict(port=s.getsockname()[1],target=dict(pid=os.getpid(),start_ticks=start,uid=os.geteuid(),fd=s.fileno(),socket_inode=os.fstat(s.fileno()).st_ino,socket_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,57,8))[0],netns_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,71,8))[0]))
print(json.dumps(metadata()),flush=True)
for raw in sys.stdin:
 a=json.loads(raw)
 if a['op']=='receive':
  try:
   data,anc,flags,peer=s.recvmsg(2048,0,socket.MSG_DONTWAIT)
   print(json.dumps({'payload_hex':data.hex(),'peer':list(peer),'flags':flags}),flush=True)
  except BlockingIOError:print(json.dumps({'queue_empty':True}),flush=True)
 elif a['op']=='replace':
  port=s.getsockname()[1];s.close();s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port))
  print(json.dumps(metadata()),flush=True)
s.close()
"""
SENDER_WORKER = r"""
import json,socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
print(json.dumps({'port':s.getsockname()[1]}),flush=True)
for raw in sys.stdin:
 a=json.loads(raw);s.sendto(bytes.fromhex(a['payload_hex']),('127.0.0.1',a['port']))
 print(json.dumps({'sent':True}),flush=True)
s.close()
"""
SENSOR_WORKER = r"""
import ctypes,json,sys
from azazel_edge.benchmark.udp_queue import capture_udp_queue,UDPQueueError
from udp_queue_data import KEY
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
a=json.loads(sys.stdin.read());libc=ctypes.CDLL(None,use_errno=True)
for cap in range(64):
 if cap in (38,39):continue
 if libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'bounding set')
h=Header(0x20080522,0);data=(Data*2)();mask=0 if a.pop('without_caps',False) else (1<<38|1<<39)
data[0].effective=data[0].permitted=mask&0xffffffff;data[1].effective=data[1].permitted=mask>>32
if libc.capset(ctypes.byref(h),ctypes.byref(data))!=0:raise OSError(ctypes.get_errno(),'capset')
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'NNP')
try:
 report=capture_udp_queue(a.pop('contract').encode(),a.pop('plan').encode(),observer_private_key=KEY,**a)
 print(json.dumps({'report':report.decode()}),flush=True)
except UDPQueueError as exc:print(json.dumps({'rejected':True,'reason':str(exc)}),flush=True)
"""
JOIN_WORKER = r"""
import json,sys
from pathlib import Path
from azazel_edge.benchmark.udp_queue import collect_udp_queue,UDPQueueError
a=json.loads(sys.stdin.read())
try:
 r=collect_udp_queue(Path(a.pop('enrollment_path')),Path(a.pop('plan_path')),Path(a.pop('report_path')),**a)
 print(json.dumps({'result':r}),flush=True)
except UDPQueueError:print(json.dumps({'rejected':True}),flush=True)
"""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return _json(value) + b"\n"


@pytest.fixture(scope="session")
def approved_object():
    directory = Path(tempfile.mkdtemp(prefix="edge-udp-bpf-object-", dir="/run"))
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
        architecture = {"aarch64": "arm64", "x86_64": "x86"}[platform.machine()]
        obj = directory / "observer.bpf.o"
        subprocess.run(
            [
                "clang",
                "-O2",
                "-g",
                "-target",
                "bpf",
                "-D__TARGET_ARCH_" + architecture,
                "-I" + str(directory),
                "-c",
                str(ROOT / "native/udp_queue_observer.bpf.c"),
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


def command(process, value):
    process.stdin.write(json.dumps(value) + "\n")
    process.stdin.flush()
    return line(process)


def ready(process):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                "observer stopped before both hooks: "
                + process.stdout.read()
                + process.stderr.read()
            )
        try:
            names = [os.readlink(p) for p in Path(f"/proc/{process.pid}/fd").iterdir()]
            if sum("bpf-link" in name or "bpf_link" in name for name in names) >= 2:
                return
        except (FileNotFoundError, ProcessLookupError):
            pass
        time.sleep(0.005)
    raise AssertionError("both kernel BPF links not ready")


def setup_capture(lab, approved_object, *, mode="allow", without_caps=False):
    target = lab(TARGET_WORKER, [mode], uid=TARGET_UID)
    meta = line(target)
    sender = lab(SENDER_WORKER, uid=PRODUCER)
    source_port = line(sender)["port"]
    ns = os.stat("/proc/self/ns/net")
    now = time.monotonic_ns()
    contract, plan, _ = make_inputs(
        ns.st_dev,
        ns.st_ino,
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        source_port,
        meta["port"],
        now - 1_000_000,
        now + 4_000_000_000,
        PAYLOAD,
        meta["target"],
        platform.release(),
        digest(Path("/sys/kernel/btf/vmlinux").read_bytes()),
        digest(approved_object.read_bytes()),
    )
    # Freeze actual lab identifiers and pins before any hook or test traffic.
    c, p = json.loads(contract), json.loads(plan)
    c["scope"]["run_id"] = "real-linux-udp-queue-run"
    c["scope"]["scope_ref"] = "real-linux-udp-queue-scope"
    for category, channel in c["channels"].items():
        channel["capture_id"] = "real-linux-queue-capture-" + category
        channel["channel_id"] = "real-linux-queue-channel-" + category
    c["opportunities"]["protected_escape"][0]["id"] = "real-linux-queue-opportunity"
    contract = wire(c)
    p["contract_sha256"] = digest(contract)
    p["opportunity_id"] = "real-linux-queue-opportunity"
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
                object_path=str(approved_object),
                without_caps=without_caps,
                **pins,
            )
        )
    )
    sensor.stdin.close()
    return target, sender, meta, sensor, contract, plan, pins


@pytest.mark.parametrize(
    "mode,traffic,expected",
    [
        ("allow", "matching", 1),
        ("filter-drop", "matching", None),
        ("allow", "unrelated", None),
        ("allow", "none", None),
        ("replace", "matching", None),
    ],
)
def test_actual_kernel_queue_controls(lab, approved_object, mode, traffic, expected):
    from azazel_edge.benchmark.udp_queue import evaluate_udp_queue

    target, sender, meta, sensor, contract, plan, pins = setup_capture(
        lab, approved_object, mode="allow" if mode == "replace" else mode
    )
    ready(sensor)
    if mode == "replace":
        replaced = command(target, dict(op="replace"))
        assert replaced["target"]["socket_cookie"] != meta["target"]["socket_cookie"]
    payload = PAYLOAD if traffic == "matching" else b"x" * 64
    if traffic != "none":
        assert command(sender, dict(port=meta["port"], payload_hex=payload.hex()))[
            "sent"
        ]
    outcome = line(sensor)
    sensor.wait(timeout=5)
    assert "report" in outcome, outcome
    raw = outcome["report"].encode()
    result = evaluate_udp_queue(contract, plan, raw, **pins)
    assert result["queue_admission_observed_count"] == expected
    assert (
        result["application_delivery_count"] is None
        and result["qualified_safety_count"] is None
    )
    assert all(
        v["observed_violation_count"] is None
        for v in result["safety_evaluation"]["categories"].values()
    )
    assert not any(result["safety_evaluation"]["authority_flags"].values())
    # Separate AFTER-detach control: the observer never receives on the target.
    received = command(target, dict(op="receive"))
    if traffic == "none" or mode == "filter-drop":
        assert received["queue_empty"] is True
    else:
        assert received["payload_hex"] == payload.hex()
        assert received["peer"] == [
            "127.0.0.1",
            json.loads(contract)["opportunities"]["protected_escape"][0]["predicate"][
                "protected_tuple"
            ]["src_port"],
        ]


def test_actual_capability_denial(lab, approved_object):
    *_, sensor, contract, plan, pins = setup_capture(
        lab, approved_object, without_caps=True
    )
    assert line(sensor)["rejected"] is True
    sensor.wait(timeout=5)


def test_actual_signed_queue_join(lab, approved_object):
    target, sender, meta, sensor, contract_raw, plan_raw, pins = setup_capture(
        lab, approved_object
    )
    ready(sensor)
    assert command(sender, dict(port=meta["port"], payload_hex=PAYLOAD.hex()))["sent"]
    outcome = line(sensor)
    sensor.wait(timeout=5)
    assert "report" in outcome, outcome
    report_raw = outcome["report"].encode()
    assert command(target, dict(op="receive"))["payload_hex"] == PAYLOAD.hex()
    c = json.loads(contract_raw)
    directory = Path(tempfile.mkdtemp(prefix="edge-udp-queue-sealed-", dir="/run"))
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
        sha = digest(contract_raw)
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
            contract=contract_raw,
            observations=wire(
                dict(
                    schema_version="edge-finite-safety-observations/v1",
                    contract_sha256=sha,
                    scope=c["scope"],
                    channels={},
                )
            ),
            checkpoint=wire(checkpoint),
            plan=plan_raw,
            report=report_raw,
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
        p = lab(JOIN_WORKER, uid=TARGET_UID)
        p.stdin.write(json.dumps(args))
        p.stdin.close()
        result = line(p)["result"]
        assert result["queue"]["queue_admission_observed_count"] == 1
        assert result["queue"]["application_delivery_count"] is None
        args["expected_report_sha256"] = "f" * 64
        p = lab(JOIN_WORKER, uid=TARGET_UID)
        p.stdin.write(json.dumps(args))
        p.stdin.close()
        assert line(p)["rejected"] is True
        assert all(path.read_bytes() == files[name] for name, path in paths.items())
    finally:
        shutil.rmtree(directory)
