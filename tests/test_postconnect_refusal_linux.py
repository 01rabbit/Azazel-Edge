"""Actual finite post-connect protocol copies; no internal branch proof."""

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
from azazel_edge.benchmark.postconnect_refusal import (
    verify_postconnect_refusal_observation,
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
    "root_patch",
    "devices_not_list",
    "invalid_allowed_networks",
    "observer_loss_after_refusal",
    "missing_after_sot",
)
pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="explicit isolated ARM Linux Root acquisition job required",
)
# Fixture-only lifetime hold. The real handler still closes its original fd.
assert (
    "conn,addr=srv.accept();daemon.handle_client(conn,addr);handled+=1" in BASE_SERVER
)
SERVER = (
    BASE_SERVER.replace("handled=0", "handled=0;holds=[]")
    .replace(
        "conn,addr=srv.accept();daemon.handle_client(conn,addr);handled+=1",
        "conn,addr=srv.accept();holds.append(os.dup(conn.fileno()));daemon.handle_client(conn,addr);handled+=1",
    )
    .replace(
        "joined=time.monotonic_ns();srv.close()",
        "joined=time.monotonic_ns();[os.close(fd) for fd in holds];srv.close()",
    )
)
SENSOR = r"""
import ctypes,json,os,sys
from pathlib import Path
from azazel_edge.benchmark import postconnect_copy_bpf as b
from azazel_edge.outcome.journal import _json
libc=ctypes.CDLL(None,use_errno=True)
class H(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class D(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
for cap in range(64):
 if cap not in (38,39) and libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'boundingdrop')
h=H(0x20080522,0);d=(D*2)();d[1].effective=d[1].permitted=(1<<6)|(1<<7)
assert libc.capset(ctypes.byref(h),ctypes.byref(d))==0 and libc.prctl(38,1,0,0,0)==0
b._role();a=json.loads(sys.stdin.readline());fault=a.pop('fault');fault_request=a.pop('fault_request_utf8');fault_configuration=a['configuration'].copy();control={'control_only':True,'closed_own_link':False,'caps':Path('/proc/self/status').read_text(),'fixture_fd_hold':True}
if fault:
 class Fault(b._Libbpf):
  def inspect(self,obj):
   maps,programs=super().inspect(obj);self.event_map=maps['events'];return maps,programs
  def check_link(self,identity):
   if not control['closed_own_link'] and identity['attach_type']==25:
    event_fd=self.lib.bpf_map__fd(self.event_map)
    rows=[self.lookup_optional(event_fd,ctypes.c_uint32(i),b.Event()) for i in range(2)]
    if all(r is not None for r in rows) and {r.role for r in rows}=={0,1} and all(r.entered_ns and r.exited_ns and r.ret==r.chunk and r.skip==r.consumed==r.data_len==0 and r.skb_len==r.chunk and 1<=r.chunk<=256 and bytes(r.data[:r.chunk]).endswith(b'\n') for r in rows):
     by_role={r.role:r for r in rows};request=bytes(by_role[0].data[:by_role[0].chunk]);response=bytes(by_role[1].data[:by_role[1].chunk])
     try:parsed=json.loads(response)
     except (ValueError,UnicodeError):parsed=None
     if request==fault_request.encode() and isinstance(parsed,dict) and parsed.get('ok') is False and parsed.get('error')=='devices_must_be_list' and by_role[0].tgid==fault_configuration['server_tgid'] and by_role[1].tgid==fault_configuration['actor_tgid'] and by_role[0].exited_ns<=by_role[1].entered_ns and by_role[0].receiver_inode==by_role[1].peer_inode and by_role[1].receiver_inode==by_role[0].peer_inode:
      os.close(identity['fd']);control['closed_own_link']=True
   return super().check_link(identity)
 b._Libbpf=Fault
raw=Path(a.pop('object_path')).read_bytes();probe=b._capture_events(a.pop('configuration'),raw,**a)
print(json.dumps({'probe_raw':(_json(probe)+b'\n').decode(),'control':control}),flush=True)
"""


def ready(proc):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        assert proc.poll() is None, proc.stdout.read() + proc.stderr.read()
        found = set()
        for path in Path(f"/proc/{proc.pid}/fdinfo").iterdir():
            try:
                raw = path.read_text()
                if "link_type:\\ttracing".replace("\\t", "\t") in raw:
                    for attach in (24, 25):
                        if ("attach_type:\\t" + str(attach)).replace(
                            "\\t", "\t"
                        ) in raw:
                            found.add(attach)
            except FileNotFoundError:
                pass
        if found == {24, 25}:
            return
        time.sleep(0.005)
    pytest.fail("both fixed copy links unavailable")


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
        from azazel_edge.benchmark.postconnect_copy_bpf import (
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
        source = ROOT / "native/postconnect_copy_observer.bpf.c"
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


def _assert_probe_reasons(case_id, probe_raw):
    # Controlled readback omission never permits unrelated acquisition failures.
    reasons = json.loads(probe_raw)["partial_reasons"]
    assert reasons == (
        ["observer_link_lost"] if case_id == "observer_loss_after_refusal" else []
    ), reasons


@pytest.mark.parametrize("case_id", CASES)
def test_actual_postconnect_refusal(approved_object, public_export, case_id):
    corpus = json.loads(
        (ROOT / "tests/fixtures/postconnect-refusal/v1/cases.json").read_bytes()
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
        uid, gid = 0, 2000
        requested = str(path)
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
            server_start_ticks=server_ticks,
            actor_start_ticks=actor_ticks,
            started_ns=start,
            deadline_ns=start + 4_000_000_000,
            server_tgid=server.pid,
            actor_tgid=actor.pid,
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
                    fault=case_id == "observer_loss_after_refusal",
                    fault_request_utf8=recipe["request_utf8"],
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
            schema_version="edge-postconnect-refusal-plan/v1",
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
        result = verify_postconnect_refusal_observation(
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
        assert actor.returncode == server.returncode == 0, (actor_err, server_err)
        expected = recipe["expected"]
        _assert_probe_reasons(case_id, probe)
        assert result["response_disposition"] == expected["response_consistency"], (
            result
        )
        assert result["server_request_copy_verified"] is True, result
        assert result["client_response_copy_verified"] is True, result
        assert result["reciprocal_pair_verified"] is True, result
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
            and result["authorization_refusal_verified"] is None
            and result["internal_branch_verified"] is None
        )
        assert result["coverage_disposition"] == (
            "unknown"
            if case_id in ("observer_loss_after_refusal", "missing_after_sot")
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
from azazel_edge.benchmark.postconnect_refusal_collection import collect_postconnect_refusal_observation
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
try:print(json.dumps({'result':collect_postconnect_refusal_observation(**json.load(sys.stdin))}))
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
                    schema_version="edge-postconnect-refusal-enrollment/v1",
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
    value = os.environ.get("EDGE_POSTCONNECT_REFUSAL_PUBLIC_DIR")
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
