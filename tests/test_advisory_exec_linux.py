"""Actual ARM-only syscall ENTRY layer; TEST invoker and control facts are explicit."""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import select
import shutil
import subprocess
import sys
import tempfile
import time

import pytest
from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.advisory_exec import verify_advisory_exec_observation

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    "ordinary_advice",
    "command_prose",
    "extra_keys",
    "forbidden_intent",
    "execve_success",
    "execve_failed",
    "execveat_failed",
    "creation_attempt",
    "link_loss",
)
PUBLIC = (
    "plan.json",
    "probe.json",
    "governance.raw",
    "audit.raw",
    "actor-control.json",
    "diagnostic.json",
)
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="explicit isolated Linux Root ARM acquisition job required",
)

ACTOR = r"""
import ctypes,hashlib,json,os,sys,tempfile,time
from pathlib import Path
from azazel_edge.ai_governance import AIGovernance
from azazel_edge.audit import P0AuditLogger
from azazel_edge.outcome.journal import _json
libc=ctypes.CDLL(None,use_errno=True);libc.syscall.restype=ctypes.c_long
case=json.loads(sys.argv[1]);name=case['case_id'];pid=os.getpid()
fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid()==os.geteuid()==1000 and all(int(fields[k],16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and fields['NoNewPrivs'].strip()=='1'
print(json.dumps({'control_only':True,'pid':pid,'uid':os.getuid(),'caps':fields}),flush=True)
assert sys.stdin.readline()=='calibrate\n';assert libc.syscall(172)==pid
print(json.dumps({'control_only':True,'calibration_call_returned':True}),flush=True)
assert sys.stdin.readline()=='go\n'
reply={'control_only':True,'case_id':name}
if name in ('ordinary_advice','command_prose','extra_keys','forbidden_intent'):
 directory=Path(tempfile.mkdtemp(prefix='edge-advisory-actor-'));directory.chmod(0o755);audit=directory/'audit.raw';calls=[]
 def invoke(data):calls.append(data);return case['invoker_output']
 started=time.monotonic_ns();result=AIGovernance(P0AuditLogger(audit)).invoke(case['context'],case['raw_payload'],invoke);finished=time.monotonic_ns()
 record={**case,'result':result,'invoker_calls':len(calls),'call_started_ns':started,'call_finished_ns':finished}
 out=directory/'governance.raw';out.write_bytes(_json(record)+b'\n');out.chmod(0o444);audit.chmod(0o444)
 reply.update(governance_path=str(out),audit_path=str(audit));print(json.dumps(reply),flush=True)
 assert sys.stdin.readline()=='close\n';out.unlink();audit.unlink();directory.rmdir()
elif name=='execve_success':os.execve('/usr/bin/true',['edge-benign-control'],{})
elif name in ('execve_failed','link_loss'):
 try:os.execve('/nonexistent/edge-fixed-exec-absent',['edge-absent-control'],{})
 except FileNotFoundError as error:reply['errno']=error.errno
 print(json.dumps(reply),flush=True);assert sys.stdin.readline()=='close\n'
elif name=='execveat_failed':
 result=libc.syscall(281,ctypes.c_int(-100),ctypes.c_char_p(b'/nonexistent/edge-fixed-execat-absent'),ctypes.c_void_p(),ctypes.c_void_p(),ctypes.c_int(0));reply.update(syscall_result=result,errno=ctypes.get_errno())
 print(json.dumps(reply),flush=True);assert sys.stdin.readline()=='close\n'
elif name=='creation_attempt':
 child=os.fork()
 if child==0:os._exit(0)
 reply['child_reaped']=os.waitpid(child,0)==(child,0)
 print(json.dumps(reply),flush=True);assert sys.stdin.readline()=='close\n'
else:raise ValueError('fixed case required')
"""

SENSOR = r"""
import ctypes,json,os,sys
from pathlib import Path
from azazel_edge.benchmark import advisory_exec_bpf as backend
from azazel_edge.outcome.journal import _json
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
args=json.load(sys.stdin);libc=ctypes.CDLL(None,use_errno=True)
for cap in range(64):
 if cap not in (38,39) and libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'bounding drop')
h=Header(0x20080522,0);data=(Data*2)();data[1].effective=data[1].permitted=192
assert libc.capset(ctypes.byref(h),ctypes.byref(data))==0 and libc.prctl(38,1,0,0,0)==0
fault={'control_only':True,'closed_own_link':False}
if args.pop('fault'):
 class Fault(backend._Libbpf):
  def inspect(self,obj):
   maps,program=super().inspect(obj);self.stats_map=maps['stats'];return maps,program
  def check_link(self,identity):
   stats=self.lookup(self.lib.bpf_map__fd(self.stats_map),ctypes.c_uint32(),backend.Counters())
   if stats.emitted>=2 and not fault['closed_own_link']:
    os.close(identity['fd']);fault['closed_own_link']=True
   return super().check_link(identity)
 backend._Libbpf=Fault
raw=Path(args.pop('object_path')).read_bytes()
result=backend._capture_events(args.pop('configuration'),raw,**args)
print(json.dumps({'probe_raw':(_json(result)+b'\n').decode(),'control':fault}),flush=True)
"""


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def line(process):
    assert select.select([process.stdout], [], [], 12)[0], (
        "bounded actor response timeout"
    )
    raw = process.stdout.readline()
    assert raw, process.stderr.read()
    return json.loads(raw)


def identity():
    libc = ctypes.CDLL(None, use_errno=True)
    for cap in range(64):
        if libc.prctl(24, cap, 0, 0, 0) != 0 and ctypes.get_errno() != 22:
            raise OSError(ctypes.get_errno(), "actor bounding drop")
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)
    assert libc.prctl(38, 1, 0, 0, 0) == 0


def _popen(code, *args, actor=False):
    return subprocess.Popen(
        [sys.executable, "-c", code, *args],
        cwd="/",
        env=dict(os.environ, PYTHONPATH=str(ROOT / "py")),
        preexec_fn=identity if actor else None,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


@pytest.fixture(scope="module")
def approved_object():
    assert platform.machine() == "aarch64", (
        "other architectures unsupported, not a skipped acquisition"
    )
    assert os.sysconf("SC_CLK_TCK") == 100
    for path in (Path(sys.executable), Path("/usr/bin/true")):
        raw = path.read_bytes()[:20]
        assert raw[:5] == b"\x7fELF\x02" and raw[18:20] == b"\xb7\x00"
    directory = Path(tempfile.mkdtemp(prefix="edge-advisory-object-", dir="/run"))
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
        native = b"#include <asm/unistd.h>\n__NR_getpid __NR_execve __NR_execveat __NR_clone __NR_clone3\n"
        actual = subprocess.check_output(
            ["clang", "-E", "-P", "-x", "c", "-"], input=native, timeout=10
        ).split()
        assert actual == [b"172", b"221", b"281", b"220", b"435"]
        source = ROOT / "native/advisory_exec_observer.bpf.c"
        subprocess.run(
            [
                "clang",
                "-O2",
                "-g",
                "-target",
                "bpf",
                "-mcpu=v3",
                "-D__TARGET_ARCH_arm64",
                "-I" + str(directory),
                "-I/usr/include/aarch64-linux-gnu",
                "-c",
                str(source),
                "-o",
                str(directory / "observer.o"),
            ],
            check=True,
            timeout=60,
        )
        (directory / "observer.o").chmod(0o444)
        yield directory / "observer.o", sha(source.read_bytes())
    finally:
        shutil.rmtree(directory)


def ready(process):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        assert process.poll() is None, process.stdout.read() + process.stderr.read()
        for path in Path(f"/proc/{process.pid}/fdinfo").iterdir():
            try:
                raw = path.read_text()
                if "link_type:\traw_tracepoint" in raw and "tp_name:\tsys_enter" in raw:
                    return
            except FileNotFoundError:
                pass
        time.sleep(0.005)
    pytest.fail("actual owned raw syscall link did not become ready")


@pytest.mark.parametrize("case_id", CASES)
def test_actual_governance_and_exec_layer(approved_object, public_export, case_id):
    path, source_sha = approved_object
    corpus = json.loads(
        (ROOT / "tests/fixtures/advisory-exec/v1/governance.json").read_bytes()
    )
    payload = corpus.get(case_id, dict(case_id=case_id))
    worker_started = time.monotonic_ns()
    actor = _popen(ACTOR, json.dumps(payload), actor=True)
    sensor = None
    try:
        actor_ready = line(actor)
        assert actor_ready["control_only"] is True and actor_ready["uid"] == 1000
        text = Path(f"/proc/{actor.pid}/stat").read_text()
        ticks = int(text[text.rfind(")") + 2 :].split()[19])
        ns = os.stat("/proc/self/ns/pid")
        started = time.monotonic_ns()
        config = dict(
            pidns_device=ns.st_dev,
            pidns_inode=ns.st_ino,
            actor_start_ticks=ticks,
            started_ns=started,
            deadline_ns=started + 4_000_000_000,
            actor_tgid=actor.pid,
            actor_uid=1000,
            user_hz=100,
            max_events=64,
        )
        sensor = _popen(SENSOR)
        sensor.stdin.write(
            json.dumps(
                dict(
                    configuration=config,
                    object_path=str(path),
                    expected_object_sha256=sha(path.read_bytes()),
                    expected_source_sha256=source_sha,
                    fault=case_id == "link_loss",
                )
            )
        )
        sensor.stdin.close()
        sensor.stdin = None
        ready(sensor)
        actor.stdin.write("calibrate\n")
        actor.stdin.flush()
        assert line(actor)["calibration_call_returned"] is True
        before = time.monotonic_ns()
        actor.stdin.write("go\n")
        actor.stdin.flush()
        after = time.monotonic_ns()
        governance = audit = None
        control = dict(control_only=True, actor_ready=actor_ready)
        if case_id != "execve_success":
            control["reply"] = line(actor)
            if case_id in corpus:
                governance = Path(control["reply"]["governance_path"]).read_bytes()
                audit = Path(control["reply"]["audit_path"]).read_bytes()
            actor.stdin.write("close\n")
            actor.stdin.flush()
        stdout, stderr = actor.communicate(timeout=8)
        exited = time.monotonic_ns()
        assert actor.returncode == 0, stderr
        observed, observer_stderr = sensor.communicate(timeout=8)
        assert sensor.returncode == 0, observer_stderr
        observed = json.loads(observed)
        probe_raw = observed["probe_raw"].encode()
        probe = json.loads(probe_raw)
        control.update(
            actor_stdout=stdout, actor_stderr=stderr, observer=observed["control"]
        )
        plan = dict(
            schema_version="edge-advisory-exec-plan/v1",
            capture_id="actual-" + case_id,
            case_id=case_id,
            kernel_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            architecture="aarch64",
            actor=dict(
                tgid=actor.pid,
                uid=1000,
                start_ticks=ticks,
                pidns_device=ns.st_dev,
                pidns_inode=ns.st_ino,
                user_hz=100,
                code_sha256=sha(ACTOR.encode()),
                input_sha256=sha(_json(payload) + b"\n"),
            ),
            configuration=config,
            go=dict(release_before_ns=before, release_after_ns=after),
            worker=dict(
                started_ns=worker_started,
                exited_ns=exited,
                returncode=actor.returncode,
                forced=False,
                error=None,
            ),
            observer_source_sha256=source_sha,
            observer_object_sha256=sha(path.read_bytes()),
            probe_sha256=sha(probe_raw),
            governance_sha256=sha(governance) if governance is not None else None,
            audit_sha256=sha(audit) if audit is not None else None,
        )
        plan_raw = _json(plan) + b"\n"
        result = verify_advisory_exec_observation(
            plan_raw,
            expected_plan_sha256=sha(plan_raw),
            probe_raw=probe_raw,
            governance_raw=governance,
            audit_raw=audit,
        )
        _export(
            public_export,
            case_id,
            plan_raw,
            probe_raw,
            governance,
            audit,
            _json(control) + b"\n",
            _json(result) + b"\n",
        )
        expected = (
            1
            if case_id
            in ("execve_success", "execve_failed", "execveat_failed", "link_loss")
            else None
        )
        assert result["kernel_exec_attempt_count"] == expected, (result, probe)
        assert result["qualified_safety_count"] is None
        if case_id in corpus:
            assert result["governance_boundary_consistent"] is True, result
        if case_id in ("creation_attempt", "link_loss"):
            assert result["coverage_disposition"] == "unknown"
            assert (
                "creation_attempt"
                if case_id == "creation_attempt"
                else "observer_link_lost"
            ) in probe["partial_reasons"]
        else:
            assert result["coverage_disposition"] == "single_task_window_consistent", (
                result,
                probe,
            )
        _sealed(result, plan_raw, probe_raw, governance, audit)
    finally:
        for process in (actor, sensor):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=8)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()


READ = r"""
import json,sys
from azazel_edge.benchmark.advisory_exec_collection import collect_advisory_exec_observation
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
try:print(json.dumps({'result':collect_advisory_exec_observation(**json.load(sys.stdin))}))
except SafetyCollectionError:print(json.dumps({'rejected':True}))
"""


def _sealed(result, plan, probe, governance, audit):
    directory = Path(tempfile.mkdtemp(prefix="edge-advisory-sealed-", dir="/run"))
    directory.chmod(0o755)
    try:
        values = dict(plan=plan, probe=probe, governance=governance, audit=audit)
        paths = {
            k: str(directory / k) if raw is not None else None
            for k, raw in values.items()
        }
        for key, raw in values.items():
            if raw is not None:
                _save(Path(paths[key]), raw)
        enrollment = (
            _json(
                dict(
                    schema_version="edge-advisory-exec-enrollment/v1",
                    plan_sha256=sha(plan),
                    reader_uid=65533,
                    kernel_boot_id=json.loads(plan)["kernel_boot_id"],
                    paths=paths,
                )
            )
            + b"\n"
        )
        _save(directory / "enrollment", enrollment)
        args = dict(
            enrollment_path=str(directory / "enrollment"),
            expected_enrollment_sha256=sha(enrollment),
            expected_plan_sha256=sha(plan),
        )
        p = subprocess.run(
            [sys.executable, "-c", READ],
            input=json.dumps(args),
            capture_output=True,
            text=True,
            user=65533,
            group=65533,
            extra_groups=[],
            timeout=10,
            env=dict(os.environ, PYTHONPATH=str(ROOT / "py")),
        )
        assert p.returncode == 0, p.stderr
        assert json.loads(p.stdout)["result"]["evaluation"] == result
        assert {
            key: Path(path).read_bytes()
            for key, path in paths.items()
            if path is not None
        } == {key: raw for key, raw in values.items() if raw is not None}
    finally:
        shutil.rmtree(directory)


def _save(path, raw):
    with path.open("xb") as out:
        out.write(raw)
    path.chmod(0o444)


@pytest.fixture(scope="module")
def public_export():
    path = os.environ.get("EDGE_ADVISORY_EXEC_PUBLIC_DIR")
    inventory = {name: dict(state="missing", manifest_sha256=None) for name in CASES}
    if not path:
        yield None, inventory
        return
    root = Path(path)
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    try:
        yield root, inventory
    finally:
        index_raw = _json(inventory) + b"\n"
        _save(root / "case-index.json", index_raw)
        checked = subprocess.run(
            [sys.executable, "-c", PUBLIC_READER, str(root), sha(index_raw)],
            cwd="/",
            user=1000,
            group=1000,
            extra_groups=[],
            capture_output=True,
            text=True,
            timeout=12,
        )
        assert checked.returncode == 0, checked.stderr


def _export(public_export, case_id, plan, probe, governance, audit, control, result):
    root, inventory = public_export
    if root is None:
        return
    child = root / case_id
    child.mkdir(mode=0o755)
    child.chmod(0o755)
    values = dict(zip(PUBLIC, (plan, probe, governance, audit, control, result)))
    manifest = {}
    for name, raw in values.items():
        if raw is None:
            manifest[name] = None
        else:
            _save(child / name, raw)
            manifest[name] = dict(sha256=sha(raw), bytes=len(raw))
    raw = _json(manifest) + b"\n"
    _save(child / "manifest.json", raw)
    inventory[case_id] = dict(state="complete", manifest_sha256=sha(raw))


PUBLIC_READER = r"""
import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);assert os.geteuid()==1000
cases={'ordinary_advice','command_prose','extra_keys','forbidden_intent','execve_success','execve_failed','execveat_failed','creation_attempt','link_loss'}
slots={'plan.json','probe.json','governance.raw','audit.raw','actor-control.json','diagnostic.json'}
assert stat.S_IMODE(root.stat().st_mode)==0o755 and set(os.listdir(root))<=cases|{'case-index.json'}
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  i=os.fstat(fd);assert stat.S_ISREG(i.st_mode) and stat.S_IMODE(i.st_mode)==0o444 and i.st_nlink==1 and i.st_size<=1048576
  raw=b''
  while len(raw)<=i.st_size:
   chunk=os.read(fd,min(65536,i.st_size+1-len(raw)))
   if not chunk:break
   raw+=chunk
  assert len(raw)==i.st_size;return raw
 finally:os.close(fd)
raw=read(root/'case-index.json');assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
index=json.loads(raw);assert set(index)==cases
for name,item in index.items():
 assert set(item)=={'state','manifest_sha256'}
 child=root/name
 if not child.exists():assert item=={'state':'missing','manifest_sha256':None};continue
 assert stat.S_IMODE(child.stat().st_mode)==0o755
 names=set(os.listdir(child));assert names<=slots|{'manifest.json'}
 originals={name:read(child/name) for name in names}
 if item['state']=='missing':assert item['manifest_sha256'] is None;continue
 assert item['state']=='complete'
 raw=originals.pop('manifest.json');assert hashlib.sha256(raw).hexdigest()==item['manifest_sha256']
 manifest=json.loads(raw);assert set(manifest)==slots
 for filename,entry in manifest.items():
  if entry is None:assert filename in ('governance.raw','audit.raw') and filename not in originals
  else:
   data=originals[filename];assert entry=={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
 assert set(originals)=={key for key,entry in manifest.items() if entry is not None}
print(json.dumps({'control_only':True,'uid':os.geteuid(),'cases':len(index)}))
"""
