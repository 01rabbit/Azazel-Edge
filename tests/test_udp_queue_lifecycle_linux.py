"""REAL lifecycle faults on owned BPF resources; no recovery/continuity fiction."""

from contextlib import contextmanager
import ctypes as C
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

import pytest
import test_udp_queue_linux as base
from azazel_edge.benchmark import udp_queue as q
from azazel_edge.benchmark.udp_queue_bpf import Counters
from udp_queue_data import make_inputs

pytestmark = base.pytestmark
approved_object = base.approved_object
lab = base.lab
line, command, ready = base.line, base.command, base.ready
PRODUCER, TARGET_UID = base.PRODUCER, base.TARGET_UID
TARGET_WORKER = r"""
import json,os,socket,struct,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',int(sys.argv[1])))
def meta():
 raw=open('/proc/self/stat').read();start=int(raw[raw.rfind(')')+2:].split()[19])
 return dict(port=s.getsockname()[1],target=dict(pid=os.getpid(),start_ticks=start,uid=os.geteuid(),fd=s.fileno(),socket_inode=os.fstat(s.fileno()).st_ino,socket_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,57,8))[0],netns_cookie=struct.unpack('=Q',s.getsockopt(socket.SOL_SOCKET,71,8))[0]))
print(json.dumps(meta()),flush=True)
for raw in sys.stdin:
 a=json.loads(raw)
 if a['op']=='receive':
  try:data,anc,flags,peer=s.recvmsg(2048,0,socket.MSG_DONTWAIT);print(json.dumps({'payload_hex':data.hex(),'peer':list(peer)}),flush=True)
  except BlockingIOError:print(json.dumps({'queue_empty':True}),flush=True)
 elif a['op']=='replace':
  port=s.getsockname()[1];s.close();s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port));print(json.dumps(meta()),flush=True)
"""
WORKER = r"""
import ctypes,json,os,sys,time
from types import SimpleNamespace
from azazel_edge.benchmark.udp_queue import capture_udp_queue,UDPQueueError
from azazel_edge.benchmark import udp_queue_bpf as p
from udp_queue_data import KEY
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
a=json.loads(sys.stdin.read());fault=a.pop('fault',None);libc=ctypes.CDLL(None,use_errno=True)
for cap in range(64):
 if cap in (38,39):continue
 if libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'bounding set')
h=Header(0x20080522,0);data=(Data*2)();data[1].effective=data[1].permitted=(1<<6|1<<7)
if libc.capset(ctypes.byref(h),ctypes.byref(data))!=0:raise OSError(ctypes.get_errno(),'capset')
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'NNP')
state={'applied':False,'attach_calls':0,'replacement_alive':None,'fd_reused':False}
cache={};replacement=None;backend=None;original_factory=p._Libbpf
class Library:
 def __init__(self,original):self.original=original
 def __getattr__(self,name):return getattr(self.original,name)
 def bpf_map__fd(self,value):
  fd=self.original.bpf_map__fd(value);name=self.original.bpf_map__name(value).decode();cache[name]=fd;return fd
 def bpf_program__attach(self,program):
  pointer=self.original.bpf_program__attach(program)
  if self.original.libbpf_get_error(pointer)==0:
   name=self.original.bpf_program__name(program).decode();cache[name]=self.original.bpf_link__fd(pointer);state['attach_calls']+=1
  return pointer
def factory():
 global backend
 backend=original_factory();backend.lib=Library(backend.lib);return backend
if fault:p._Libbpf=factory
original_sleep=time.sleep
def fault_sleep(seconds):
 global replacement
 if not state['applied'] and 'stats' in cache and 'queue_entry' in cache:
  value=p.Counters();zero=ctypes.c_uint32(0)
  rc=backend.lib.bpf_map_lookup_elem(cache['stats'],ctypes.byref(zero),ctypes.byref(value))
  if rc==0 and value.accepted>=1:
   name='queue_exit' if fault=='exit' else 'queue_entry';fd=cache[name]
   # Close ONLY the owned real kernel FD. The libbpf pointer remains alive.
   os.close(fd);state['applied']=True
   if fault=='reuse':
    replacement=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
    if replacement!=fd:os.dup2(replacement,fd,inheritable=False);os.close(replacement);replacement=fd
    state['fd_reused']=True
 original_sleep(seconds)
if fault:p.time=SimpleNamespace(monotonic_ns=time.monotonic_ns,sleep=fault_sleep)
try:
 report=capture_udp_queue(a.pop('contract').encode(),a.pop('plan').encode(),observer_private_key=KEY,**a)
 if replacement is not None:
  try:os.fstat(replacement);state['replacement_alive']=True
  except OSError:state['replacement_alive']=False
 print(json.dumps({'report':report.decode(),'fault_state':state}),flush=True)
except UDPQueueError as exc:print(json.dumps({'rejected':True,'reason':str(exc),'fault_state':state}),flush=True)
finally:
 if replacement is not None:
  try:os.close(replacement)
  except OSError:pass
"""


@contextmanager
def group():
    processes = []

    def launch(code, args=(), uid=None):
        def drop():
            os.setgroups([])
            os.setgid(uid)
            os.setuid(uid)

        env = dict(
            os.environ,
            PYTHONPATH=str(Path(__file__).parent)
            + os.pathsep
            + os.environ.get("PYTHONPATH", ""),
        )
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", code, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=drop if uid else None,
            env=env,
        )
        processes.append(process)
        return process

    try:
        yield launch
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def start(
    lab,
    obj,
    *,
    fault=None,
    max_events=16,
    expired=False,
    target=None,
    sender=None,
    meta=None,
):
    if target is None:
        target = lab(TARGET_WORKER, ["0"], uid=TARGET_UID)
        meta = line(target)
    if sender is None:
        sender = lab(base.SENDER_WORKER, uid=PRODUCER)
        source = line(sender)["port"]
    else:
        source = sender.source_port
    sender.source_port = source
    now = time.monotonic_ns()
    ns = os.stat("/proc/self/ns/net")
    payload = os.urandom(64)
    beginning = now - 3_000_000_000 if expired else now - 1_000_000
    ending = now - 1_000_000_000 if expired else now + 4_000_000_000
    contract, plan, _ = make_inputs(
        ns.st_dev,
        ns.st_ino,
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        source,
        meta["port"],
        beginning,
        ending,
        payload,
        meta["target"],
        base.platform.release(),
        base.digest(Path("/sys/kernel/btf/vmlinux").read_bytes()),
        base.digest(obj.read_bytes()),
    )
    c, p = json.loads(contract), json.loads(plan)
    ref = uuid.uuid4().hex
    c["scope"]["run_id"] = "real-life-run-" + ref
    c["scope"]["scope_ref"] = "real-life-scope-" + ref
    c["scope"]["session_ref"] = ref
    for category, channel in c["channels"].items():
        channel["capture_id"] = "life-cap-" + ref + "-" + category
        channel["channel_id"] = "life-channel-" + ref + "-" + category
    opportunity = c["opportunities"]["protected_escape"][0]
    opportunity["id"] = "life-op-" + ref
    contract = base.wire(c)
    p["contract_sha256"] = base.digest(contract)
    p["opportunity_id"] = opportunity["id"]
    p["max_events"] = max_events
    plan = base.wire(p)
    pins = dict(
        expected_contract_sha256=base.digest(contract),
        expected_plan_sha256=base.digest(plan),
    )
    sensor = lab(WORKER)
    sensor.stdin.write(
        json.dumps(
            dict(
                contract=contract.decode(),
                plan=plan.decode(),
                object_path=str(obj),
                fault=fault,
                **pins,
            )
        )
    )
    sensor.stdin.close()
    return dict(
        target=target,
        sender=sender,
        meta=meta,
        sensor=sensor,
        contract=contract,
        plan=plan,
        pins=pins,
        payload=payload,
        deadline=ending,
    )


def send(run, number=1):
    for _ in range(number):
        assert command(
            run["sender"],
            dict(port=run["meta"]["port"], payload_hex=run["payload"].hex()),
        )["sent"]


def sample_accepted(process):
    """Read only an owned map temporarily; close all duplicates BEFORE any kill."""
    libc = C.CDLL(None, use_errno=True)
    lib = C.CDLL("libbpf.so.1", use_errno=True)
    lib.bpf_map_lookup_elem.argtypes = [C.c_int, C.c_void_p, C.c_void_p]
    lib.bpf_map_lookup_elem.restype = C.c_int
    for path in Path(f"/proc/{process.pid}/fdinfo").iterdir():
        try:
            fields = dict(
                line.split(":", 1)
                for line in path.read_text().splitlines()
                if ":" in line
            )
        except FileNotFoundError:
            continue
        if (
            fields.get("value_size", "").strip() != "40"
            or fields.get("max_entries", "").strip() != "1"
        ):
            continue
        pidfd = os.pidfd_open(process.pid)
        fd = -1
        try:
            fd = libc.syscall(438, pidfd, int(path.name), 0)
            assert fd >= 0, ("owned map duplicate denied", C.get_errno())
            zero = C.c_uint32()
            value = Counters()
            assert lib.bpf_map_lookup_elem(fd, C.byref(zero), C.byref(value)) == 0
            return value.accepted
        finally:
            if fd >= 0:
                os.close(fd)
            os.close(pidfd)
    return 0


def wait_positive(run, minimum=1):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        assert run["sensor"].poll() is None, "observer stopped before volatile event"
        if sample_accepted(run["sensor"]) >= minimum:
            return
        time.sleep(0.005)
    raise AssertionError("no real owned-map positive before fault")


def completed(run):
    outcome = line(run["sensor"])
    run["sensor"].wait(timeout=5)
    assert "report" in outcome, outcome
    raw = outcome["report"].encode()
    result = q.evaluate_udp_queue(run["contract"], run["plan"], raw, **run["pins"])
    assert (
        result["application_delivery_count"] is None
        and result["qualified_safety_count"] is None
    )
    assert all(
        v["observed_violation_count"] is None
        for v in result["safety_evaluation"]["categories"].values()
    )
    assert not any(result["safety_evaluation"]["authority_flags"].values())
    return raw, result, outcome


@pytest.fixture(scope="module")
def historical(approved_object):
    with group() as launch:
        run = start(launch, approved_object)
        ready(run["sensor"])
        send(run)
        raw, result, _ = completed(run)
        assert result["queue_admission_observed_count"] == 1
        directory = Path(tempfile.mkdtemp(prefix="edge-life-history-", dir="/run"))
        directory.chmod(0o755)
        path = directory / "published-report.json"
        path.write_bytes(raw)
        path.chmod(0o444)
        try:
            yield dict(
                path=path,
                raw=raw,
                sha=base.digest(raw),
                contract=run["contract"],
                plan=run["plan"],
                pins=run["pins"],
            )
        finally:
            path.unlink()
            directory.rmdir()


@pytest.fixture(autouse=True)
def preserve_history(historical):
    yield
    assert historical["path"].read_bytes() == historical["raw"]
    assert base.digest(historical["path"].read_bytes()) == historical["sha"]
    assert (
        q.evaluate_udp_queue(
            historical["contract"],
            historical["plan"],
            historical["raw"],
            **historical["pins"],
        )["queue_admission_observed_count"]
        == 1
    )


def test_unsealed_sigkill_has_no_report_and_does_not_replace_history(
    lab, approved_object, historical
):
    run = start(lab, approved_object)
    ready(run["sensor"])
    send(run)
    wait_positive(run)
    run["sensor"].kill()
    run["sensor"].wait(timeout=5)
    assert run["sensor"].returncode == -signal.SIGKILL
    assert run["sensor"].stdout.read() == ""
    assert (
        command(run["target"], dict(op="receive"))["payload_hex"]
        == run["payload"].hex()
    )


def test_sigstop_past_deadline_never_adopts_late_packet(lab, approved_object):
    run = start(lab, approved_object)
    ready(run["sensor"])
    send(run)
    wait_positive(run)
    os.kill(run["sensor"].pid, signal.SIGSTOP)
    time.sleep(max(0, (run["deadline"] - time.monotonic_ns()) / 1e9) + 0.03)
    send(run)
    os.kill(run["sensor"].pid, signal.SIGCONT)
    raw, result, _ = completed(run)
    report = json.loads(raw)
    assert result["queue_admission_observed_count"] == 1 and len(report["events"]) == 1
    assert report["counters"]["accepted"] == 1
    assert all(event["exited_ns"] <= run["deadline"] for event in report["events"])
    assert report["finished_ns"] > run["deadline"]


@pytest.mark.parametrize("fault", ["entry", "exit", "reuse"])
def test_real_owned_link_loss_retains_earlier_event_no_reattach(
    lab, approved_object, fault
):
    run = start(lab, approved_object, fault=fault)
    ready(run["sensor"])
    send(run)
    raw, result, outcome = completed(run)
    report = json.loads(raw)
    assert result["queue_admission_observed_count"] == 1
    assert "observer_link_lost" in report["partial_reasons"]
    assert (
        outcome["fault_state"]["applied"]
        and outcome["fault_state"]["attach_calls"] == 2
    )
    if fault == "reuse":
        assert (
            outcome["fault_state"]["fd_reused"]
            and outcome["fault_state"]["replacement_alive"]
        )
    assert (
        command(run["target"], dict(op="receive"))["payload_hex"]
        == run["payload"].hex()
    )


def test_real_event_overflow_preserves_first_event(lab, approved_object):
    run = start(lab, approved_object, max_events=1)
    ready(run["sensor"])
    send(run, 20)
    wait_positive(run, 2)
    raw, result, _ = completed(run)
    report = json.loads(raw)
    assert result["queue_admission_observed_count"] == 1 and len(report["events"]) == 1
    assert report["counters"]["accepted"] >= 2 and report["counters"]["overflow"] >= 1
    assert "event_overflow" in report["partial_reasons"]


def test_real_target_pid_restart_same_port_never_replaces_old_identity(
    lab, approved_object
):
    run = start(lab, approved_object)
    ready(run["sensor"])
    send(run)
    wait_positive(run)
    run["target"].kill()
    run["target"].wait(timeout=5)
    replacement = lab(TARGET_WORKER, [str(run["meta"]["port"])], uid=TARGET_UID)
    new = line(replacement)
    assert new["target"]["pid"] != run["meta"]["target"]["pid"]
    assert new["target"]["socket_cookie"] != run["meta"]["target"]["socket_cookie"]
    send(run)
    raw, result, _ = completed(run)
    report = json.loads(raw)
    assert result["queue_admission_observed_count"] == 1 and len(report["events"]) == 1
    assert (
        report["counters"]["accepted"] == 1
        and "target_lifecycle_changed" in report["partial_reasons"]
    )


def test_real_target_fd_reuse_same_process_never_adopts_new_cookie(
    lab, approved_object
):
    run = start(lab, approved_object)
    ready(run["sensor"])
    send(run)
    wait_positive(run)
    new = command(run["target"], dict(op="replace"))
    assert new["target"]["fd"] == run["meta"]["target"]["fd"]
    assert new["target"]["socket_cookie"] != run["meta"]["target"]["socket_cookie"]
    send(run)
    raw, result, _ = completed(run)
    report = json.loads(raw)
    assert result["queue_admission_observed_count"] == 1 and len(report["events"]) == 1
    assert report["counters"]["accepted"] == 1


def test_expired_old_plan_rejected_then_explicit_new_capture(lab, approved_object):
    old = start(lab, approved_object, expired=True)
    assert line(old["sensor"])["rejected"] is True
    old["sensor"].wait(timeout=5)
    fresh = start(
        lab,
        approved_object,
        target=old["target"],
        sender=old["sender"],
        meta=old["meta"],
    )
    oldc, newc = json.loads(old["contract"]), json.loads(fresh["contract"])
    for key in ("run_id", "scope_ref", "session_ref"):
        assert oldc["scope"][key] != newc["scope"][key]
    assert (
        oldc["channels"]["protected_escape"]["capture_id"]
        != newc["channels"]["protected_escape"]["capture_id"]
    )
    assert old["pins"] != fresh["pins"]
    ready(fresh["sensor"])
    send(fresh)
    _, result, _ = completed(fresh)
    assert result["queue_admission_observed_count"] == 1


def test_same_sealed_report_replay_is_only_historical(historical):
    first = q.evaluate_udp_queue(
        historical["contract"],
        historical["plan"],
        historical["raw"],
        **historical["pins"],
    )
    second = q.evaluate_udp_queue(
        historical["contract"],
        historical["plan"],
        historical["path"].read_bytes(),
        **historical["pins"],
    )
    assert first == second and first["queue_admission_observed_count"] == 1
    assert first["qualified_safety_count"] is None
