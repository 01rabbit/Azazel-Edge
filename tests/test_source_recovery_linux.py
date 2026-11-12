"""REAL syscall denial and separate-UID sealed intake, NOT actual recovery success.

Source/report payloads use PUBLIC TEST keys and synthetic event recipes. Only OS
permissions, actual BPF ID syscalls and sealed-file intake are real observations.
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
from source_recovery_data import make_proof_bundle
from recovery_evidence_data import make_recovery

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root/child UIDs required",
)
BOOT = Path("/proc/sys/kernel/random/boot_id")
READER, PRODUCER = 61002, 61001
QUERY_WORKER = r"""
import ctypes,json,sys
from azazel_edge.benchmark.recovery_evidence import capture_recovery_evidence,evaluate_recovery_evidence
from safety_observation_data import KEYS,digest,wire
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
a=json.loads(sys.stdin.read());mask=(1<<38|1<<39) if a['bpf'] else 0
libc=ctypes.CDLL(None,use_errno=True)
for cap in range(64):
 if mask & (1<<cap):continue
 if libc.prctl(24,cap,0,0,0)!=0 and ctypes.get_errno()!=22:raise OSError(ctypes.get_errno(),'drop bounding')
h=Header(0x20080522,0);d=(Data*2)();d[0].effective=d[0].permitted=mask&0xffffffff;d[1].effective=d[1].permitted=mask>>32
if libc.capset(ctypes.byref(h),ctypes.byref(d))!=0:raise OSError(ctypes.get_errno(),'capset')
if libc.prctl(38,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'NNP')
p=wire(a['plan']);raw=capture_recovery_evidence(p,expected_plan_sha256=digest(p),observer_private_key=KEYS[0])
r=evaluate_recovery_evidence(p,raw,expected_plan_sha256=digest(p),expected_report_sha256=digest(raw))
print(json.dumps({'report':json.loads(raw),'evaluation':r}))
"""
INTAKE_WORKER = r"""
import json,os,sys
from azazel_edge.benchmark.safety_proofs import collect_safety_proofs
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
a=json.loads(sys.stdin.read())
# Imported before guards; intake must never access a socket/process/private key.
import socket,subprocess
real_open=os.open
writing=os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND
def ro(path,flags,*args,**kw):
 if flags&writing:raise AssertionError('write requested')
 return real_open(path,flags,*args,**kw)
def no(*args,**kw):raise AssertionError('mutation/action requested')
os.open=ro
for name in ('chmod','chown','mkdir','unlink','remove','rename','replace','system'):setattr(os,name,no)
socket.socket=no;subprocess.Popen=no
try:print(json.dumps({'result':collect_safety_proofs(**a)}))
except SafetyCollectionError:print(json.dumps({'rejected':True}))
"""


def run_worker(code, payload, uid=None):
    def identity():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    done = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=12,
        preexec_fn=identity if uid is not None else None,
        env=dict(
            os.environ,
            PYTHONPATH=os.pathsep.join(
                [str(Path(__file__).resolve().parent), os.environ.get("PYTHONPATH", "")]
            ),
        ),
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.parametrize(
    "bpf", [True, False], ids=["actual_bpf_perfmon_denied", "actual_no_caps_denied"]
)
def test_actual_id_queries_remain_unknown_without_inventory_privilege(bpf):
    now = time.monotonic_ns()
    plan, _ = make_recovery(
        kernel_boot_id=BOOT.read_text().strip(),
        kernel_release=platform.release(),
        not_before_ns=now - 1_000_000,
        deadline_ns=now + 10_000_000_000,
    )
    out = run_worker(QUERY_WORKER, dict(plan=plan, bpf=bpf))
    r = out["evaluation"]
    assert r["status"] == "unknown"
    assert r["observer_objects_absent"] is None
    assert r["matching_residue_count"] is None
    assert r["network_mechanism_restored"] is None
    assert len(r["resources"]) == 8
    assert all(
        x["state"] == "unknown" and x["reason"] == "query_denied_or_failed"
        for x in r["resources"]
    )
    assert out["report"]["context_stable"] is True
    assert not any(r["authority_flags"].values())


@pytest.fixture
def enrolled():
    directory = Path(tempfile.mkdtemp(prefix="edge-source-recovery-", dir="/run"))
    directory.chmod(0o755)
    try:
        yield directory
    finally:
        directory.chmod(0o755)
        shutil.rmtree(directory)


def enroll(directory, case):
    # Real filesystem/UID boundary; all event semantics are synthetic.
    bundle = make_proof_bundle(directory, case, kernel_boot_id=BOOT.read_text().strip())
    for name, raw in bundle["files"].items():
        bundle["paths"][name].write_bytes(raw)
        bundle["paths"][name].chmod(0o444)
    payload = dict(
        enrollment_path=str(bundle["paths"]["enrollment"]),
        supplement_path=str(bundle["paths"]["supplement"]),
        **{
            k: bundle[k]
            for k in (
                "expected_enrollment_sha256",
                "expected_checkpoint_sha256",
                "expected_supplement_sha256",
            )
        },
    )
    return payload, list(directory.iterdir())


@pytest.mark.parametrize("case", ["source_closed", "source_bad_suffix"])
def test_actual_sealed_intake_preserves_independent_positive(enrolled, case):
    payload, paths = enroll(enrolled, case)
    before = {
        p: (
            p.read_bytes(),
            p.stat().st_ino,
            p.stat().st_mode,
            p.stat().st_mtime_ns,
            p.stat().st_ctime_ns,
        )
        for p in paths
    }
    out = run_worker(INTAKE_WORKER, payload, READER)
    assert "result" in out, out
    r = out["result"]["evaluation"]
    assert r["source_authentication"]["authenticated_prefix"] is True
    assert r["source_authentication"]["authenticated_full_source"] is (
        case == "source_closed"
    )
    assert (
        r["safety_evaluation"]["categories"]["forged_evidence_accepted"][
            "observed_violation_count"
        ]
        == 1
    )
    assert r["recovery"]["observer_objects_absent"] is None
    assert r["qualified_safety_count"] is None
    assert not any(r["authority_flags"].values())
    after = {
        p: (
            p.read_bytes(),
            p.stat().st_ino,
            p.stat().st_mode,
            p.stat().st_mtime_ns,
            p.stat().st_ctime_ns,
        )
        for p in paths
    }
    assert before == after


@pytest.mark.parametrize(
    "fault",
    ["producer_reader", "writable", "symlink", "hardlink", "changed", "wrong_pin"],
)
def test_actual_unsafe_artifact_refuses_without_repair(enrolled, fault):
    payload, paths = enroll(enrolled, "source_closed")
    supplement = json.loads(Path(payload["supplement_path"]).read_bytes())
    trust = Path(supplement["paths"]["trust"])
    if fault == "writable":
        trust.chmod(0o644)
    elif fault == "symlink":
        old = enrolled / "original"
        trust.rename(old)
        trust.symlink_to(old)
    elif fault == "hardlink":
        os.link(trust, enrolled / "alias")
    elif fault == "changed":
        trust.chmod(0o644)
        trust.write_bytes(b"{}\n")
        trust.chmod(0o444)
    elif fault == "wrong_pin":
        payload["expected_supplement_sha256"] = "f" * 64
    before = {p: p.read_bytes() for p in enrolled.iterdir()}
    out = run_worker(
        INTAKE_WORKER, payload, PRODUCER if fault == "producer_reader" else READER
    )
    assert out["rejected"] is True
    assert before == {p: p.read_bytes() for p in enrolled.iterdir()}
