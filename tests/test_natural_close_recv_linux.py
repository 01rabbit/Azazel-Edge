"""Actual DEV own-UID authorization refusal responses, not branch attestation."""

import json
import os
from pathlib import Path
import platform
import pwd
import grp
import shutil
import subprocess
import sys
import tempfile
import time

import pytest
from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.natural_close_recv import (
    verify_natural_close_recv_observation,
)
from test_forged_input_refusal_linux import snapshot, digest
from test_authority_ingress_linux import (
    SERVER as BASE_SERVER,
    ACTOR,
    role,
    popen,
    line,
    ticks,
    endpoint,
    _save,
    _export,
    PUBLIC_READ as BASE_PUBLIC_READ,
)

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    "own_uid_patch",
    "root_only_refused",
    "spoofed_root_refused",
    "partial_read_close",
    "actor_death",
    "observer_stop_after_copy",
    "missing_after_sot",
)
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="explicit isolated ARM Linux Root acquisition job required",
)
# No duplicate or accepted socket hold. Delay only ACCEPT for death scheduling.
SERVER = (
    BASE_SERVER.replace(
        "assert os.getuid()==os.geteuid()==0",
        "assert os.getuid()==os.geteuid()==65534 and os.getgid()==65534 and os.getgroups()==[]",
    )
    .replace("handled=0", "assert sys.stdin.readline()=='accept\\n';handled=0")
    .replace(
        "daemon.handle_client(conn,addr);handled+=1",
        "daemon.handle_client(conn,addr);handled+=1;print(json.dumps({'control_only':True,'handler_returned':True}),flush=True)",
    )
)
PARTIAL_ACTOR = ACTOR.replace("s.recv(4096)", "s.recv(16)").replace(
    "raw+=part", "raw+=part;break"
)
DEATH_ACTOR = ACTOR.replace("s.settimeout(3)", "s.settimeout(None)")
SENSOR = r"""
import ctypes,json,os,sys
from pathlib import Path
from azazel_edge.benchmark import natural_close_recv_bpf as b
from azazel_edge.outcome.journal import _json
libc=ctypes.CDLL(None,use_errno=True)
class H(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
for cap in range(64):
 if cap not in (38,39) and libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'boundingdrop')
h=H(0x20080522,0);d=(D*2)();d[1].effective=d[1].permitted=(1<<6)|(1<<7)
assert libc.capset(ctypes.byref(h),ctypes.byref(d))==0 and libc.prctl(38,1,0,0,0)==0
b._role();a=json.loads(sys.stdin.readline());fault=a.pop('fault');control={'control_only':True,'closed_own_link':False,'entry_notified':False,'caps':Path('/proc/self/status').read_text(),'fixture_fd_hold':False}
class Observed(b._Libbpf):
 def inspect(self,obj):
  maps,programs=super().inspect(obj);self.event_map=maps['events'];self.recv_exit_prog=programs['recv_exit'];return maps,programs
 def link_identity(self,link,program,attach_type):
  identity=super().link_identity(link,program,attach_type)
  if program==self.recv_exit_prog:self.recv_exit_identity=identity.copy()
  return identity
 def check_link(self,identity):
  fd=self.lib.bpf_map__fd(self.event_map)
  if fd>=0:
   rows=[self.lookup_optional(fd,ctypes.c_uint32(i),b.Event()) for i in range(32)]
   rows=[r for r in rows if r is not None]
   if fault=='actor_death' and not control['entry_notified'] and any(r.kind==0 and r.role==1 for r in rows):
    control['entry_notified']=True;print(json.dumps({'control_only':True,'actor_recv_entered':True}),flush=True)
   if fault=='observer_stop_after_copy' and not control['closed_own_link'] and hasattr(self,'recv_exit_identity') and identity['prog_id']==self.recv_exit_identity['prog_id']:
    for r in rows:
     if r.kind!=1 or r.role!=1 or not(r.token and r.entered_ns and r.exited_ns and r.ret==r.chunk and r.skip==r.consumed==r.data_len==0 and r.skb_len==r.chunk and 1<=r.chunk<=256):continue
     payload=bytes(r.data[:r.chunk])
     try:parsed=json.loads(payload)
     except (ValueError,UnicodeError):parsed=None
     if payload.endswith(b'\n') and isinstance(parsed,dict) and parsed.get('ok') is False and parsed.get('error')=='forbidden' and parsed.get('reason')=='root_only' and parsed.get('action')=='migrate_path_schema':
      os.close(identity['fd']);control['closed_own_link']=True;break
  return super().check_link(identity)
b._Libbpf=Observed
raw=Path(a.pop('object_path')).read_bytes();probe=b._capture_events(a.pop('configuration'),raw,**a)
print(json.dumps({'probe_raw':(_json(probe)+b'\n').decode(),'control':control}),flush=True)
"""


def ready(proc):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        assert proc.poll() is None, proc.stdout.read() + proc.stderr.read()
        found = []
        for path in Path(f"/proc/{proc.pid}/fdinfo").iterdir():
            try:
                raw = path.read_text()
                if "link_type:\\ttracing".replace("\\t", "\t") in raw:
                    for attach in (24, 25):
                        if ("attach_type:\\t" + str(attach)).replace(
                            "\\t", "\t"
                        ) in raw:
                            found.append(attach)
            except FileNotFoundError:
                pass
        if sorted(found) == [24, 24, 25, 25]:
            return
        time.sleep(0.005)
    pytest.fail("all four fixed copy/recv links unavailable")


@pytest.fixture(scope="module", autouse=True)
def existing_development_profile():
    assert pwd.getpwnam("nobody").pw_uid == 65534
    assert pwd.getpwnam("nobody").pw_gid == 65534
    assert grp.getgrnam("nogroup").gr_gid == 65534
    original_gid = os.getgid()
    os.setgid(65534)
    try:
        yield
    finally:
        os.setgid(original_gid)


def _identity_profile(server_pid, actor_pid):
    own = os.stat("/proc/self/ns/user")
    result = dict(
        profile="development-own-uid65534",
        userns_device=own.st_dev,
        userns_inode=own.st_ino,
    )
    for name in ("uid_map", "gid_map"):
        value = " ".join(Path("/proc/self/" + name).read_text().split())
        assert value == "0 0 4294967295", (
            "identity maps required; no namespace fallback"
        )
        result[name] = value
    # Same-UID, cap0 read-only sampler: no SYS_PTRACE/DAC permission added.
    code = r"""
import json,os,sys
from pathlib import Path
rows={}
for name,pid in json.loads(sys.argv[1]).items():
 ns=os.stat(f'/proc/{pid}/ns/user')
 status=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
 assert status['Uid'].split()==['65534']*4 and status['Gid'].split()==['65534']*4
 assert status['Groups'].split()==[] and status['NoNewPrivs'].strip()=='1'
 assert all(int(status[k],16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb'))
 rows[name]={'device':ns.st_dev,'inode':ns.st_ino,**{field:' '.join(Path(f'/proc/{pid}/{field}').read_text().split()) for field in ('uid_map','gid_map')}}
print(json.dumps(rows))
"""
    sampled = subprocess.run(
        [
            sys.executable,
            "-c",
            code,
            json.dumps(dict(server=server_pid, actor=actor_pid)),
        ],
        preexec_fn=role(65534, 65534),
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert sampled.returncode == 0, sampled.stderr
    for name, row in json.loads(sampled.stdout).items():
        assert (row["device"], row["inode"]) == (own.st_dev, own.st_ino)
        assert all(row[field] == result[field] for field in ("uid_map", "gid_map"))
        result[name + "_userns_device"] = row["device"]
        result[name + "_userns_inode"] = row["inode"]
    return result


@pytest.fixture(scope="module")
def approved_object():
    assert platform.machine() == "aarch64" and os.sysconf("SC_CLK_TCK") == 100
    directory = Path(tempfile.mkdtemp(prefix="edge-postconnect-object-", dir="/run"))
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
        from azazel_edge.benchmark.natural_close_recv_bpf import (
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
        source = ROOT / "native/natural_close_recv_observer.bpf.c"
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


def _assert_observations(case_id, result, probe, control):
    assert result["qualified_safety_count"] is None
    assert result["authorization_refusal_verified"] is None
    assert result["internal_branch_verified"] is None
    assert result["reciprocal_pair_verified"] is None
    assert result["root_only_refusal_response_consistent"] is None
    assert control["fixture_fd_hold"] is False
    if case_id == "actor_death":
        assert control["entry_notified"] is True
        assert result["client_response_completion_verified"] is None
        assert result["clean_lifecycle_verified"] is None
        assert any(e["kind"] == 0 and e["role"] == 1 for e in result["verified_events"])
    else:
        assert result["clean_lifecycle_verified"] is True
        if case_id != "observer_stop_after_copy":
            assert result["server_request_completion_verified"] is True, result
            assert result["client_response_completion_verified"] is True, result
        if case_id == "partial_read_close":
            assert result["client_response_frame_verified"] is None
            assert any(
                r["role"] == 1 and r["bytes"] == 16
                for r in result["receiver_completions"]
            )
        elif case_id != "observer_stop_after_copy":
            assert result["client_response_frame_verified"] is True, result
    if case_id == "observer_stop_after_copy":
        assert control["closed_own_link"] is True
        assert "observer_link_lost" in probe["partial_reasons"]
        retained = [
            e
            for e in result["raw_protocol_copy_events"]
            if e["role"] == 1
            and e["skip"] == e["consumed"] == e["data_len"] == 0
            and e["skb_len"] == e["chunk"]
            and bytes.fromhex(e["data_hex"]).endswith(b"\n")
        ]
        assert retained, result
        assert any(
            json.loads(bytes.fromhex(e["data_hex"])).get("reason") == "root_only"
            for e in retained
        ), result
    else:
        allowed = {"pending_not_empty"} if case_id == "actor_death" else set()
        assert set(probe["partial_reasons"]).issubset(allowed), probe
    positive = case_id in ("own_uid_patch", "missing_after_sot")
    expected_changes = {
        "sot": None if case_id == "missing_after_sot" else positive,
        "audit": positive,
    }
    assert result["object_changes"] == expected_changes, result
    assert result["sampled_originals_unchanged"] is (not positive), result
    if case_id in (
        "partial_read_close",
        "actor_death",
        "observer_stop_after_copy",
        "missing_after_sot",
    ):
        assert result["coverage_disposition"] == "unknown", result
    else:
        assert result["coverage_disposition"] == "bounded_individual_observation", (
            result
        )
    for event in result["raw_protocol_copy_events"]:
        if event["peer_status"] != 1:
            assert event["peer_inode"] is None
            assert result["reciprocal_pair_verified"] is None
            assert result["root_only_refusal_response_consistent"] is None


@pytest.mark.parametrize("case_id", CASES)
def test_actual_natural_close_recv(approved_object, public_export, case_id):
    corpus = json.loads(
        (ROOT / "tests/fixtures/natural-close/v1/cases.json").read_bytes()
    )
    recipe = next(row for row in corpus["cases"] if row["case_id"] == case_id)
    server_started = time.monotonic_ns()
    server = popen(
        SERVER, dict(before_sot_utf8=corpus["before_sot_utf8"]), 65534, 65534
    )
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
        uid, gid = 65534, 65534
        requested = str(path)
        actor_started = time.monotonic_ns()
        actor_code = (
            PARTIAL_ACTOR
            if case_id == "partial_read_close"
            else DEATH_ACTOR
            if case_id == "actor_death"
            else ACTOR
        )
        actor = popen(
            actor_code,
            dict(path=requested, request_utf8=recipe["request_utf8"]),
            uid,
            gid,
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
            server_start_ticks=server_ticks,
            actor_start_ticks=actor_ticks,
            started_ns=start,
            deadline_ns=start + 4_000_000_000,
            server_tgid=server.pid,
            actor_tgid=actor.pid,
            user_hz=100,
            max_events=32,
            server_uid=65534,
            actor_uid=65534,
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
                    fault=case_id,
                )
            )
        )
        sensor.stdin.close()
        sensor.stdin = None
        ready(sensor)
        identity_profile = _identity_profile(server.pid, actor.pid)
        if case_id != "actor_death":
            server.stdin.write("accept\n")
            server.stdin.flush()
        go_before = time.monotonic_ns()
        actor.stdin.write("go\n")
        actor.stdin.flush()
        go_after = time.monotonic_ns()
        if case_id == "actor_death":
            assert line(sensor) == {"control_only": True, "actor_recv_entered": True}
            actor.kill()
            actor_reply = {
                "control_only": True,
                "owned_actor_killed_after_observed_recv_entry": True,
            }
        else:
            actor_reply = line(actor)
        actor_out, actor_err = actor.communicate(timeout=8)
        actor_exited = time.monotonic_ns()
        if case_id == "actor_death":
            server.stdin.write("accept\n")
            server.stdin.flush()
        assert line(server) == {"control_only": True, "handler_returned": True}
        server.stdin.write("stop\n")
        server.stdin.flush()
        server_out, server_err = server.communicate(timeout=8)
        server_exited = time.monotonic_ns()
        joined = json.loads(server_out)["handlers_joined_ns"]
        after_raw, after_meta = snapshot(dict(sot=sot, audit=audit))
        (parent_after, socket_after), endpoint_after = endpoint(path)
        sensor_out, sensor_err = sensor.communicate(timeout=8)
        assert sensor.returncode == 0, sensor_err
        sensor_result = json.loads(sensor_out)
        probe = sensor_result["probe_raw"].encode()
        if case_id == "missing_after_sot":
            after_raw["sot"] = None
            after_meta["sot"] = None
        plan = dict(
            schema_version="edge-natural-close-plan/v1",
            capture_id="actual-" + case_id,
            case_id=case_id,
            identity_profile=identity_profile,
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
                control_gid=65534,
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
                code_sha256=digest(actor_code.encode()),
                started_ns=actor_started,
                exited_ns=actor_exited,
                returncode=actor.returncode,
                forced=case_id == "actor_death",
                error="intentional_actor_death" if case_id == "actor_death" else None,
            ),
            server=dict(
                pid=server.pid,
                uid=65534,
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
        result = verify_natural_close_recv_observation(
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
        assert server.returncode == 0, server_err
        assert actor.returncode == (-9 if case_id == "actor_death" else 0), actor_err
        _assert_observations(
            case_id, result, json.loads(probe), sensor_result["control"]
        )
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
            # Owner-only removal after independently sampling/exporting originals.
            done = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import shutil,sys;shutil.rmtree(sys.argv[1])",
                    str(directory),
                ],
                preexec_fn=role(65534, 65534),
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert done.returncode == 0, done.stderr


READ = r"""
import json,sys
from azazel_edge.benchmark.natural_close_recv_collection import collect_natural_close_recv_observation
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
try:print(json.dumps({'result':collect_natural_close_recv_observation(**json.load(sys.stdin))}))
except SafetyCollectionError:print(json.dumps({'rejected':True}))
"""


def _sealed(plan, probe, before, after, result):
    directory = Path(tempfile.mkdtemp(prefix="edge-postconnect-sealed-", dir="/run"))
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
                    schema_version="edge-natural-close-enrollment/v1",
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
    value = os.environ.get("EDGE_NATURAL_CLOSE_RECV_PUBLIC_DIR")
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


PUBLIC_READ = BASE_PUBLIC_READ.replace(
    "{'root_patch','advisory_dac_denied','spoofed_root_dac_denied','unrelated_path','observer_loss','missing_readback'}",
    repr(set(CASES)),
)
