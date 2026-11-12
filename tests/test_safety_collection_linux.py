"""Actual root enrollment and separate-UID read-only intake; no live sensor claim.

Run explicitly as root in isolated offline Linux. Uses disposable /run artifacts,
public test-only signing recipes and child UIDs; no services or defense actions.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest

from safety_collection_data import build_bundle

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux root required for actual enrollment and child UIDs",
)
PRODUCER, READER = 61001, 61002
BOOT = Path("/proc/sys/kernel/random/boot_id")
WORKER = r"""
import json,os,sys
from pathlib import Path
from azazel_edge.benchmark.safety_collection import collect_registered_safety,SafetyCollectionError
args=json.loads(sys.stdin.read())
if args['op']=='write-probe':
 denied=[]
 for name in args['paths']:
  try:
   with open(name,'ab') as stream:stream.write(b'forbidden')
  except PermissionError:denied.append(True)
  else:denied.append(False)
 try:Path(args['directory'],'forbidden-new-file').write_bytes(b'forbidden')
 except PermissionError:denied.append(True)
 else:denied.append(False)
 print(json.dumps({'denied':denied}));sys.exit(0)
# Guard collection's action surface after imports. Reads and stdout are allowed.
real_open=os.open
writing=os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND
def readonly_open(path,flags,*a,**kw):
 if flags & writing:raise AssertionError('collector requested write access')
 return real_open(path,flags,*a,**kw)
os.open=readonly_open
def forbidden(*a,**kw):raise AssertionError('collector requested a mutation or action')
for name in ('chmod','chown','mkdir','unlink','remove','rename','replace','system'):
 setattr(os,name,forbidden)
import socket,subprocess
socket.socket=forbidden
subprocess.Popen=forbidden
try:
 result=collect_registered_safety(Path(args['enrollment']),
  expected_enrollment_sha256=args['expected_enrollment_sha256'],
  expected_checkpoint_sha256=args['expected_checkpoint_sha256'])
 print(json.dumps({'result':result}))
except SafetyCollectionError as exc:
 print(json.dumps({'rejected':True,'error_type':type(exc).__name__}))
"""


@pytest.fixture
def sealed_directory():
    path = Path(tempfile.mkdtemp(prefix="edge-safety-collection-", dir="/run"))
    path.chmod(0o755)
    try:
        yield path
    finally:
        path.chmod(0o755)
        shutil.rmtree(path)


def enroll(directory, case="complete"):
    bundle = build_bundle(
        directory,
        case,
        boot_id=BOOT.read_text().strip(),
        observer_uid=READER,
        producer_uid=PRODUCER,
    )
    for name, raw in bundle["files"].items():
        bundle["paths"][name].write_bytes(raw)
        bundle["paths"][name].chmod(0o444)
    return bundle


def child(bundle, uid=READER, op="collect"):
    def drop_identity():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)

    payload = dict(
        op=op,
        enrollment=str(bundle["paths"]["enrollment"]),
        expected_enrollment_sha256=bundle["expected_enrollment_sha256"],
        expected_checkpoint_sha256=bundle["expected_checkpoint_sha256"],
        paths=[str(p) for p in bundle["paths"].values()],
        directory=str(bundle["paths"]["enrollment"].parent),
    )
    completed = subprocess.run(
        [sys.executable, "-c", WORKER],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=15,
        preexec_fn=drop_identity,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def snapshot(bundle):
    return {
        name: (
            hashlib.sha256(path.read_bytes()).hexdigest(),
            path.stat().st_ino,
            path.stat().st_mode,
            path.stat().st_size,
            path.stat().st_mtime_ns,
            path.stat().st_ctime_ns,
        )
        for name, path in bundle["paths"].items()
    }


@pytest.mark.parametrize(
    "case,count",
    [
        ("complete", 0),
        ("violation", 1),
        ("null-head", None),
        ("null-head-violation", 1),
        ("gap", None),
        ("gap-violation", 1),
        ("missing-channel", None),
        ("bad-signature", None),
        ("wrong-head", None),
    ],
)
def test_actual_enrollment_readonly_evaluator_composition(
    sealed_directory, case, count
):
    bundle = enroll(sealed_directory, case)
    before = snapshot(bundle)
    result = child(bundle)["result"]
    assert snapshot(bundle) == before
    assert result["status"] == "unqualified_collection"
    assert result["independently_measured"] is False
    assert result["qualified_safety_count"] is None
    assert result["provenance"]["observer_uid"] == READER
    evaluation = result["evaluation"]
    assert (
        evaluation["categories"]["protected_escape"]["observed_violation_count"]
        == count
    )
    assert evaluation["qualified_safety_count"] is None
    assert not any(evaluation["authority_flags"].values())
    assert evaluation["source_authentication_performed"] is False
    assert evaluation["cleanup_status"] == "unknown"


@pytest.mark.parametrize(
    "uid", [PRODUCER, READER], ids=["producer-write-denied", "observer-write-denied"]
)
def test_actual_roles_cannot_modify_registration_or_artifacts(sealed_directory, uid):
    bundle = enroll(sealed_directory)
    before = snapshot(bundle)
    assert child(bundle, uid, "write-probe")["denied"] == [True] * 5
    assert snapshot(bundle) == before
    assert not (sealed_directory / "forbidden-new-file").exists()


def test_actual_producer_cannot_act_as_reader(sealed_directory):
    bundle = enroll(sealed_directory)
    assert child(bundle, PRODUCER)["rejected"] is True


@pytest.mark.parametrize(
    "fault",
    [
        "unsafe-owner",
        "unsafe-mode",
        "unsafe-ancestor",
        "symlink",
        "hardlink",
        "special-file",
        "missing-artifact",
    ],
)
def test_actual_unsafe_paths_are_rejected(sealed_directory, fault):
    bundle = enroll(sealed_directory)
    path = bundle["paths"]["observations"]
    if fault == "unsafe-owner":
        os.chown(path, PRODUCER, PRODUCER)
    elif fault == "unsafe-mode":
        path.chmod(0o644)
    elif fault == "unsafe-ancestor":
        sealed_directory.chmod(0o777)
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(bundle["paths"]["contract"])
    elif fault == "hardlink":
        os.link(path, sealed_directory / "extra-link")
    elif fault == "special-file":
        path.unlink()
        os.mkfifo(path, 0o444)
    elif fault == "missing-artifact":
        path.unlink()
    assert child(bundle)["rejected"] is True
