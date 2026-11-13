"""Actual finite authority-ingress fixture; no advisory-to-Rust bridge is invented."""

import ctypes
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
from azazel_edge.benchmark.authority_ingress import verify_authority_ingress_observation
from test_forged_input_refusal_linux import snapshot, digest

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    "root_patch",
    "advisory_dac_denied",
    "spoofed_root_dac_denied",
    "unrelated_path",
    "observer_loss",
    "missing_readback",
)
SLOTS = (
    "plan.json",
    "probe.json",
    "sot_before.raw",
    "sot_after.raw",
    "audit_before.raw",
    "audit_after.raw",
    "control.json",
    "diagnostic.json",
)
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="explicit isolated ARM Linux Root acquisition job required",
)

SERVER = r"""
import json,os,select,socket,sys,tempfile,time
from pathlib import Path
args=json.loads(sys.argv[1]);directory=Path(tempfile.mkdtemp(prefix='edge-authority-'));directory.chmod(0o750)
path=directory/'control.sock';sot=directory/'sot.json';audit=directory/'audit.raw'
sot.write_text(args['before_sot_utf8']);audit.write_bytes(b'');sot.chmod(0o644);audit.chmod(0o644)
os.environ['AZAZEL_CONTROL_SOCKET']=str(path);os.environ['AZAZEL_SOT_PATH']=str(sot);os.environ['AZAZEL_SOT_AUDIT_LOG']=str(audit)
from azazel_edge_control import daemon
fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert os.getuid()==os.geteuid()==0 and all(int(fields[k],16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and fields['NoNewPrivs'].strip()=='1'
srv=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);srv.bind(str(path));path.chmod(0o660);srv.listen(2)
assert daemon.SOCKET_PATH==path and daemon.SOT_AUDIT_LOG==audit
print(json.dumps({'control_only':True,'pid':os.getpid(),'directory':str(directory),'path':str(path),'sot':str(sot),'audit':str(audit),'status':fields,'web_uid':daemon._web_ui_uid()}),flush=True)
handled=0
while True:
 ready,_,_=select.select([srv,sys.stdin],[],[],15)
 if sys.stdin in ready:
  assert sys.stdin.readline()=='stop\n';break
 if srv in ready:
  conn,addr=srv.accept();daemon.handle_client(conn,addr);handled+=1
 if not ready:raise TimeoutError('bounded owned server lifecycle')
# The inline handler has returned; this timestamp proves the later joined fence,
# not a fabricated exact handler-return instant. No background daemon main runs.
joined=time.monotonic_ns();srv.close()
print(json.dumps({'control_only':True,'handlers':handled,'handlers_joined_ns':joined}),flush=True)
"""

ACTOR = r"""
import json,os,socket,sys
from pathlib import Path
args=json.loads(sys.argv[1]);fields=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert all(int(fields[k],16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and fields['NoNewPrivs'].strip()=='1'
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
print(json.dumps({'control_only':True,'uid':os.getuid(),'gid':os.getgid(),'groups':os.getgroups(),'client_inode':os.fstat(s.fileno()).st_ino,'status':fields}),flush=True)
assert sys.stdin.readline()=='go\n'
try:
 s.settimeout(3);s.connect(args['path']);s.sendall(args['request_utf8'].encode());raw=b''
 while b'\n' not in raw:
  part=s.recv(4096)
  if not part:break
  raw+=part
 print(json.dumps({'control_only':True,'response_utf8':raw.decode()}),flush=True)
except OSError as exc:print(json.dumps({'control_only':True,'errno':exc.errno}),flush=True)
s.close()
"""

SENSOR = r"""
import ctypes,json,os,sys
from pathlib import Path
from azazel_edge.benchmark import authority_ingress_bpf as b
from azazel_edge.outcome.journal import _json
class H(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure):_fields_=[('eff',ctypes.c_uint32),('prm',ctypes.c_uint32),('inh',ctypes.c_uint32)]
a=json.load(sys.stdin);libc=ctypes.CDLL(None,use_errno=True)
for cap in range(64):
 if cap not in (38,39) and libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'bounding drop')
h=H(0x20080522,0);d=(D*2)();d[1].eff=d[1].prm=192
assert libc.capset(ctypes.byref(h),ctypes.byref(d))==0 and libc.prctl(38,1,0,0,0)==0
control={'control_only':True,'closed_own_link':False}
if a.pop('fault'):
 class Fault(b._Libbpf):
  def inspect(self,obj):
   maps,program=super().inspect(obj);self.stats_map=maps['stats'];return maps,program
  def check_link(self,identity):
   stats=self.lookup(self.lib.bpf_map__fd(self.stats_map),ctypes.c_uint32(),b.Counters())
   if stats.emitted>=1 and not control['closed_own_link']:
    os.close(identity['fd']);control['closed_own_link']=True
   return super().check_link(identity)
 b._Libbpf=Fault
raw=Path(a.pop('object_path')).read_bytes();probe=b._capture_events(a.pop('configuration'),raw,**a)
print(json.dumps({'probe_raw':(_json(probe)+b'\n').decode(),'control':control}),flush=True)
"""


def role(uid, gid):
    def apply():
        libc = ctypes.CDLL(None, use_errno=True)
        for cap in range(64):
            if libc.prctl(24, cap, 0, 0, 0) != 0 and ctypes.get_errno() != 22:
                raise OSError(ctypes.get_errno(), "bounding drop")
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

        class Header(ctypes.Structure):
            _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

        class Data(ctypes.Structure):
            _fields_ = [(k, ctypes.c_uint32) for k in ("eff", "prm", "inh")]

        assert (
            libc.capset(ctypes.byref(Header(0x20080522, 0)), ctypes.byref((Data * 2)()))
            == 0
        )
        assert libc.prctl(38, 1, 0, 0, 0) == 0

    return apply


def popen(code, value, uid=None, gid=None):
    return subprocess.Popen(
        [sys.executable, "-c", code, json.dumps(value)],
        cwd="/",
        env=dict(os.environ, PYTHONPATH=str(ROOT / "py")),
        preexec_fn=role(uid, gid) if uid is not None else None,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def line(p):
    assert select.select([p.stdout], [], [], 12)[0], "bounded worker response"
    raw = p.stdout.readline()
    assert raw, p.stderr.read()
    return json.loads(raw)


def ticks(p):
    raw = Path(f"/proc/{p.pid}/stat").read_text()
    return int(raw[raw.rfind(")") + 2 :].split()[19])


def ready(p):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        assert p.poll() is None, p.stdout.read() + p.stderr.read()
        for path in Path(f"/proc/{p.pid}/fdinfo").iterdir():
            try:
                raw = path.read_text()
                if "link_type:\ttracing" in raw and "attach_type:\t25" in raw:
                    return
            except FileNotFoundError:
                pass
        time.sleep(0.005)
    pytest.fail("fixed tracing link unavailable")


def endpoint(path):
    def meta(p):
        info = p.lstat()
        return dict(
            device=info.st_dev,
            inode=info.st_ino,
            uid=info.st_uid,
            gid=info.st_gid,
            mode=info.st_mode & 0o7777,
            nlink=info.st_nlink,
        )

    before = (meta(path.parent), meta(path))
    assert before == (meta(path.parent), meta(path))
    return before, time.monotonic_ns()


@pytest.fixture(scope="module")
def approved_object():
    assert platform.machine() == "aarch64" and os.sysconf("SC_CLK_TCK") == 100
    directory = Path(tempfile.mkdtemp(prefix="edge-authority-object-", dir="/run"))
    directory.chmod(0o755)
    try:
        with (directory / "vmlinux.h").open("wb") as out:
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
                stdout=out,
                check=True,
                timeout=30,
            )
        from azazel_edge.benchmark.authority_ingress_bpf import (
            validate_kernel_prototype,
        )

        raw_btf = subprocess.check_output(
            [
                "bpftool",
                "-j",
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "raw",
            ],
            timeout=30,
        )
        build_prototype = validate_kernel_prototype(raw_btf)
        source = ROOT / "native/authority_ingress_observer.bpf.c"
        obj = directory / "observer.o"
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
                str(obj),
            ],
            check=True,
            timeout=60,
        )
        obj.chmod(0o444)
        yield obj, digest(source.read_bytes()), build_prototype
    finally:
        shutil.rmtree(directory)


@pytest.mark.parametrize("case_id", CASES)
def test_actual_authority_ingress(approved_object, public_export, case_id):
    corpus = json.loads(
        (ROOT / "tests/fixtures/authority-ingress/v1/cases.json").read_bytes()
    )
    recipe = next(row for row in corpus["cases"] if row["case_id"] == case_id)
    server_started = time.monotonic_ns()
    server = popen(SERVER, dict(before_sot_utf8=corpus["before_sot_utf8"]), 0, 2000)
    actor = sensor = None
    directory = None
    try:
        setup = line(server)
        assert setup["control_only"] is True and setup["web_uid"] != 1000
        directory = Path(setup["directory"])
        path = Path(setup["path"])
        sot = Path(setup["sot"])
        audit = Path(setup["audit"])
        server_ticks = ticks(server)
        (parent_before, socket_before), endpoint_before = endpoint(path)
        originals, before_meta = snapshot(dict(sot=sot, audit=audit))
        assert (
            originals["audit"] == b""
            and originals["sot"] == corpus["before_sot_utf8"].encode()
        )
        negative = recipe["actor_role"] != "root"
        uid = 1000 if negative else 0
        gid = 1000 if negative else 2000
        requested = (
            str(directory / "unrelated.sock")
            if case_id == "unrelated_path"
            else str(path)
        )
        actor_started = time.monotonic_ns()
        actor = popen(
            ACTOR, dict(path=requested, request_utf8=recipe["request_utf8"]), uid, gid
        )
        actor_ready = line(actor)
        assert actor_ready["uid"] == uid and actor_ready["groups"] == []
        actor_ticks = ticks(actor)
        pidns = os.stat("/proc/self/ns/pid")
        netns = os.stat("/proc/self/ns/net")
        start = time.monotonic_ns()
        config = dict(
            pidns_device=pidns.st_dev,
            pidns_inode=pidns.st_ino,
            actor_start_ticks=actor_ticks,
            started_ns=start,
            deadline_ns=start + 4_000_000_000,
            actor_tgid=actor.pid,
            actor_uid=uid,
            user_hz=100,
            max_events=16,
        )
        obj, source_sha, build_prototype = approved_object
        sensor = popen(SENSOR, {})
        sensor.stdin.write(
            json.dumps(
                dict(
                    configuration=config,
                    object_path=str(obj),
                    expected_object_sha256=digest(obj.read_bytes()),
                    expected_source_sha256=source_sha,
                    fault=case_id == "observer_loss",
                )
            )
        )
        sensor.stdin.close()
        sensor.stdin = None
        ready(sensor)
        go_before = time.monotonic_ns()
        actor.stdin.write("go\n")
        actor.stdin.flush()
        go_after = time.monotonic_ns()
        actor_reply = line(actor)
        actor_out, actor_err = actor.communicate(timeout=8)
        actor_exited = time.monotonic_ns()
        assert actor.returncode == 0, actor_err
        server.stdin.write("stop\n")
        server.stdin.flush()
        server_out, server_err = server.communicate(timeout=8)
        server_exited = time.monotonic_ns()
        assert server.returncode == 0, server_err
        joined = json.loads(server_out)["handlers_joined_ns"]
        after_raw, after_meta = snapshot(dict(sot=sot, audit=audit))
        (parent_after, socket_after), endpoint_after = endpoint(path)
        sensor_out, sensor_err = sensor.communicate(timeout=8)
        assert sensor.returncode == 0, sensor_err
        sensor_result = json.loads(sensor_out)
        probe = sensor_result["probe_raw"].encode()
        if case_id == "missing_readback":
            after_raw["sot"] = None
            after_meta["sot"] = None
        plan = dict(
            schema_version="edge-authority-ingress-plan/v1",
            capture_id="actual-" + case_id,
            case_id=case_id,
            kernel_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            request_utf8=recipe["request_utf8"],
            request_sha256=digest(recipe["request_utf8"].encode()),
            requested_path=requested,
            target_paths=dict(sot=str(sot), audit=str(audit)),
            control_endpoint=dict(
                path=str(path),
                parent_before=parent_before,
                parent_after=parent_after,
                socket_before=socket_before,
                socket_after=socket_after,
                before_sample_ns=endpoint_before,
                after_sample_ns=endpoint_after,
                control_gid=2000,
            ),
            actor=dict(
                pid=actor.pid,
                uid=uid,
                gid=gid,
                groups=[],
                start_ticks=actor_ticks,
                pidns_device=pidns.st_dev,
                pidns_inode=pidns.st_ino,
                netns_inode=netns.st_ino,
                code_sha256=digest(ACTOR.encode()),
                started_ns=actor_started,
                exited_ns=actor_exited,
                returncode=actor.returncode,
                forced=False,
                error=None,
            ),
            server=dict(
                pid=server.pid,
                uid=0,
                start_ticks=server_ticks,
                code_sha256=digest(SERVER.encode()),
                started_ns=server_started,
                handlers_joined_ns=joined,
                exited_ns=server_exited,
                returncode=server.returncode,
                forced=False,
                error=None,
            ),
            go=dict(release_before_ns=go_before, release_after_ns=go_after),
            configuration=config,
            samples=dict(before=before_meta, after=after_meta),
            probe_sha256=digest(probe),
            observer_source_sha256=source_sha,
            observer_object_sha256=digest(obj.read_bytes()),
        )
        plan_raw = _json(plan) + b"\n"
        result = verify_authority_ingress_observation(
            plan_raw,
            expected_plan_sha256=digest(plan_raw),
            probe_raw=probe,
            sot_before_raw=originals["sot"],
            sot_after_raw=after_raw["sot"],
            audit_before_raw=originals["audit"],
            audit_after_raw=after_raw["audit"],
        )
        control = (
            _json(
                dict(
                    control_only=True,
                    server=setup,
                    actor=actor_ready,
                    actor_reply=actor_reply,
                    actor_stdout=actor_out,
                    actor_stderr=actor_err,
                    server_stdout=server_out,
                    server_stderr=server_err,
                    observer=sensor_result["control"],
                    kernel_build_prototype=build_prototype,
                )
            )
            + b"\n"
        )
        _export(
            public_export,
            case_id,
            plan_raw,
            probe,
            originals,
            after_raw,
            control,
            result,
        )
        expected = recipe["expected"]
        mapped = (
            "unrelated_path_observed"
            if case_id == "unrelated_path"
            else expected["connection_observation"]
        )
        assert result["connection_disposition"] == mapped, result
        assert result["object_changes"] == expected["object_changes"], result
        assert (
            result["sampled_originals_unchanged"]
            is expected["sampled_originals_unchanged"]
        ), result
        assert (
            result["permitted_hostname_patch_consistent"]
            is expected["permitted_hostname_patch_consistent"]
        ), result
        assert (
            result["qualified_safety_count"] is None
            and result["application_peer_refusal_verified"] is False
        )
        assert result["coverage_disposition"] == (
            "unknown"
            if case_id in ("observer_loss", "missing_readback")
            else "finite_case_consistent"
        ), result
        _sealed(plan_raw, probe, originals, after_raw, result)
    finally:
        for p in (actor, server, sensor):
            if p is not None:
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=8)
                for stream in (p.stdin, p.stdout, p.stderr):
                    if stream is not None:
                        stream.close()
        if directory is not None:
            shutil.rmtree(directory)


READ = r"""
import json,sys
from azazel_edge.benchmark.authority_ingress_collection import collect_authority_ingress_observation
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
try:print(json.dumps({'result':collect_authority_ingress_observation(**json.load(sys.stdin))}))
except SafetyCollectionError:print(json.dumps({'rejected':True}))
"""


def _save(path, raw):
    with path.open("xb") as out:
        out.write(raw)
    path.chmod(0o444)


def _sealed(plan, probe, before, after, result):
    directory = Path(tempfile.mkdtemp(prefix="edge-authority-sealed-", dir="/run"))
    directory.chmod(0o755)
    try:
        values = dict(
            plan=plan,
            probe=probe,
            sot_before=before["sot"],
            sot_after=after["sot"],
            audit_before=before["audit"],
            audit_after=after["audit"],
        )
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
                    schema_version="edge-authority-ingress-enrollment/v1",
                    plan_sha256=digest(plan),
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
            expected_enrollment_sha256=digest(enrollment),
            expected_plan_sha256=digest(plan),
        )
        p = subprocess.run(
            [sys.executable, "-c", READ],
            input=json.dumps(args),
            capture_output=True,
            text=True,
            cwd="/",
            preexec_fn=role(65533, 65533),
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


@pytest.fixture(scope="module")
def public_export():
    value = os.environ.get("EDGE_AUTHORITY_INGRESS_PUBLIC_DIR")
    index = {case: dict(state="missing", manifest_sha256=None) for case in CASES}
    if not value:
        yield None, index
        return
    root = Path(value)
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    try:
        yield root, index
    finally:
        raw = _json(index) + b"\n"
        _save(root / "case-index.json", raw)
        p = subprocess.run(
            [sys.executable, "-c", PUBLIC_READ, str(root), digest(raw)],
            cwd="/",
            preexec_fn=role(1000, 1000),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert p.returncode == 0, p.stderr


def _export(public_export, case, plan, probe, before, after, control, result):
    root, index = public_export
    if root is None:
        return
    child = root / case
    child.mkdir(mode=0o755)
    child.chmod(0o755)
    values = dict(
        zip(
            SLOTS,
            (
                plan,
                probe,
                before["sot"],
                after["sot"],
                before["audit"],
                after["audit"],
                control,
                _json(result) + b"\n",
            ),
        )
    )
    manifest = {}
    for name, raw in values.items():
        if raw is None:
            manifest[name] = None
        else:
            _save(child / name, raw)
            manifest[name] = dict(sha256=digest(raw), bytes=len(raw))
    raw = _json(manifest) + b"\n"
    _save(child / "manifest.json", raw)
    index[case] = dict(state="complete", manifest_sha256=digest(raw))


PUBLIC_READ = r"""
import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);assert os.geteuid()==1000
cases={'root_patch','advisory_dac_denied','spoofed_root_dac_denied','unrelated_path','observer_loss','missing_readback'}
slots={'plan.json','probe.json','sot_before.raw','sot_after.raw','audit_before.raw','audit_after.raw','control.json','diagnostic.json'}
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
for case,item in index.items():
 assert set(item)=={'state','manifest_sha256'};child=root/case
 if not child.exists():assert item=={'state':'missing','manifest_sha256':None};continue
 assert stat.S_IMODE(child.stat().st_mode)==0o755
 names=set(os.listdir(child));assert names<=slots|{'manifest.json'};originals={name:read(child/name) for name in names}
 if item['state']=='missing':assert item['manifest_sha256'] is None;continue
 assert item['state']=='complete';raw=originals.pop('manifest.json');assert hashlib.sha256(raw).hexdigest()==item['manifest_sha256']
 manifest=json.loads(raw);assert set(manifest)==slots
 for name,entry in manifest.items():
  if entry is None:assert name in ('probe.json','sot_before.raw','sot_after.raw','audit_before.raw','audit_after.raw') and name not in originals
  else:assert entry=={'bytes':len(originals[name]),'sha256':hashlib.sha256(originals[name]).hexdigest()}
 assert set(originals)=={key for key,value in manifest.items() if value is not None}
print(json.dumps({'control_only':True,'uid':os.geteuid(),'cases':len(index)}))
"""
