"""REAL separate-UID refusal and sampled state; lifecycle payloads are lab data."""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import pytest
from azazel_edge.outcome.input_auth import SourceVerifier
from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.forged_input_refusal import verify_forged_input_refusal
from test_outcome_input_auth_linux import ROOT
from test_source_witness_linux import actual_prefix  # noqa: F401
from test_outcome_live_origin import frame

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root and actual separate child UIDs required",
)

WORKER = r"""
import json,sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_witness import InputAuthentication
from azazel_edge.outcome.input_cursor import BoundedInput
from azazel_edge.outcome.journal import ObservationJournal
from azazel_edge.outcome.input_resume import recover_input
from azazel_edge.outcome.telemetry import persistence_context
from test_outcome_input_resume import line_for
from test_outcome_telemetry_g3 import policy
p=TrustPolicy.from_file(Path(sys.argv[1]),role='observer');d=p.data
with BoundedInput(Path(d['source_path']),max_bytes=d['input_max_bytes'],max_records=d['input_max_records'],authentication=InputAuthentication(p)) as source:
 with ObservationJournal(Path(d['journal_directory']),scope_ref=d['scope_ref'],policy_ref=persistence_context(policy(),'br0'),boot_id='observer-boot',create=False,max_bytes=d['journal_max_bytes'],input_source=source) as j:
  recover_input(j,policy())
  line=line_for(source,j)
  j.advance_input(line.position,missed=True)
  print(json.dumps({'control_only':True,'pid':__import__('os').getpid(),'uid':__import__('os').geteuid(),'status':j.status()}),flush=True)
"""

# Reopening consumes the existing restart backlog through recover_input as
# explicit missed input. The control must not attempt a second read at EOF.
CONTROL = WORKER.replace(
    "  line=line_for(source,j)\n  j.advance_input(line.position,missed=True)\n", ""
)

PRODUCER = r"""
import json,os,sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,SignedCaptureWriter,_json
p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer');a=json.load(sys.stdin)
with SignedCaptureWriter(p,Path(sys.argv[2]),boot_ref=a['boot_ref']) as w:w.append(a['event'])
path=Path(p.data['source_path']);raw=path.read_bytes();valid=raw.splitlines(keepends=True)[-1]
if a['invalid']:
 row=json.loads(valid);s=row['signature'];row['signature']=('0' if s[0]!='0' else '1')+s[1:]
 bad=_json(row)+b'\n';assert len(bad)==len(valid)
 fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  os.lseek(fd,len(raw)-len(valid),os.SEEK_SET)
  assert os.write(fd,bad)==len(bad);os.fsync(fd)
 finally:os.close(fd)
print(json.dumps({'valid_frame':valid.decode(),'uid':os.geteuid()}))
"""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(info):
    return {
        "device": info.st_dev,
        "inode": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": stat.S_IMODE(info.st_mode),
        "nlink": info.st_nlink,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
        "ctime_ns": info.st_ctime_ns,
    }


def snapshot(paths):
    """Controller-only bounded stable reads, with no target write or witness call."""
    raw, descriptors = {}, {}
    for name, path in paths.items():
        started = time.monotonic_ns()
        named = path.lstat()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            opened = os.fstat(fd)
            assert stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1
            assert _identity(named) == _identity(opened)
            assert 0 <= opened.st_size <= 1024 * 1024
            chunks = []
            remaining = opened.st_size + 1
            while remaining:
                chunk = os.read(fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            assert len(data) == opened.st_size
            assert _identity(os.fstat(fd)) == _identity(opened)
            assert _identity(path.lstat()) == _identity(opened)
        finally:
            os.close(fd)
        raw[name] = data
        descriptors[name] = dict(
            sha256=digest(data),
            read_started_ns=started,
            read_finished_ns=time.monotonic_ns(),
            identity=_identity(opened),
        )
    return raw, descriptors


def _run(f, script, *, uid, input_raw=None):
    started = time.monotonic_ns()
    process = subprocess.Popen(
        [sys.executable, "-c", script, str(f.policy_file), str(f.pk)],
        cwd="/",
        env=dict(
            os.environ,
            PYTHONPATH=os.pathsep.join([str(ROOT / "py"), str(ROOT / "tests")]),
        ),
        user=uid,
        group=uid,
        extra_groups=[],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = process.communicate(input_raw, timeout=20)
    except BaseException:
        process.kill()
        process.wait(timeout=10)
        raise
    return (
        stdout,
        stderr,
        dict(
            pid=process.pid,
            uid=uid,
            code_sha256=digest(script.encode()),
            started_ns=started,
            exited_ns=time.monotonic_ns(),
            returncode=process.returncode,
            forced=False,
            error=None,
            stdout_sha256=digest(stdout),
            stderr_sha256=digest(stderr),
        ),
    )


@pytest.mark.parametrize(
    "invalid", [False, True], ids=["valid-next-control", "invalid-signature"]
)
def test_actual_registered_next_frame_refusal_and_independent_state(
    actual_prefix,  # noqa: F811 -- imported real fixture
    invalid,
):
    f, trust, prefix, anchors, arguments = actual_prefix
    # The reused fixture accepted a nonempty registered prepare prefix and
    # closed the observer session. Witness restart is setup, before challenge.
    assert arguments["expected_source_checkpoint"]["size"] == len(prefix) > 0
    f.start()
    context = arguments["expected_context"]
    event = frame("session_start", 1, context["session_ref"])["event"]
    event["capture_origin"] = dict(
        schema_version="outcome-registered-origin/v2",
        registration_sha256=context["registration_sha256"],
        mode="live-core",
        session_ref=context["session_ref"],
        seq=1,
        kind="session_start",
    )
    output, errors, producer = _run(
        f,
        PRODUCER,
        uid=f.p.data["producer_uid"],
        input_raw=json.dumps(
            dict(boot_ref=context["boot_ref"], event=event, invalid=invalid)
        ).encode(),
    )
    assert producer["returncode"] == 0 and errors == b""
    control = json.loads(output)
    assert control["uid"] == f.p.data["producer_uid"]
    valid = control["valid_frame"].encode()
    assert SourceVerifier(f.p).verify(prefix + valid)["seq"] == 2
    challenged = f.source.read_bytes()
    assert challenged.startswith(prefix)
    if invalid:
        old, new = json.loads(valid), json.loads(challenged[len(prefix) :])
        assert old.pop("signature") != new.pop("signature")
        assert _json(old) == _json(new)
    else:
        assert challenged == prefix + valid
    paths = dict(source=f.source, journal=f.journal, anchors=f.anchors)
    before, before_descriptors = snapshot(paths)
    stdout, stderr, worker = _run(
        f, WORKER if invalid else CONTROL, uid=f.p.data["observer_uid"]
    )
    after, after_descriptors = snapshot(paths)
    if invalid:
        assert worker["returncode"] != 0 and stdout == b""
        assert stderr.endswith(
            b"azazel_edge.outcome.journal.OutcomeJournalError: authentication signature invalid\n"
        )
        assert before == after
        assert {k: v["identity"] for k, v in before_descriptors.items()} == {
            k: v["identity"] for k, v in after_descriptors.items()
        }
        plan = dict(
            schema_version="edge-forged-input-refusal-plan/v1",
            capture_id="actual-invalid-signature",
            kernel_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            expected_trust_sha256=digest(trust),
            expected_context=context,
            expected_source_checkpoint=arguments["expected_source_checkpoint"],
            expected_anchor_checkpoint=arguments["expected_anchor_checkpoint"],
            samples=dict(before=before_descriptors, after=after_descriptors),
            worker=worker,
        )
        raw = _json(plan) + b"\n"
        result = verify_forged_input_refusal(
            raw,
            expected_plan_sha256=digest(raw),
            trust_raw=trust,
            before=before,
            after=after,
            stdout_raw=stdout,
            stderr_raw=stderr,
        )
        assert result["status"] == "recorded_refusal_consistent", result
        assert result["sampled_state_unchanged"] is True
        assert result["observed_persistent_change"] is False
        assert result["invalid_signature_verified"] is True
        assert result["baseline_witness_verified"] is True
        assert result["journal_cursor_structurally_verified"] is True
        assert result["full_journal_semantics_verified"] is False
        assert result["qualified_safety_count"] is None
        _sealed_and_exported(raw, trust, before, after, stdout, stderr, result)
    else:
        assert worker["returncode"] == 0, stderr.decode()
        actual = json.loads(stdout)
        assert (
            actual["control_only"] is True and actual["uid"] == f.p.data["observer_uid"]
        )
        assert actual["status"]["input_position"] == dict(
            offset=len(challenged), sha256=digest(challenged)
        )
        assert before["source"] == after["source"]
        assert (
            before["journal"] != after["journal"]
            and before["anchors"] != after["anchors"]
        )


INTAKE = r"""
import json,sys
from azazel_edge.benchmark.forged_refusal_collection import collect_forged_input_refusal
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
args=json.load(sys.stdin)
try:print(json.dumps({'result':collect_forged_input_refusal(**args)}))
except SafetyCollectionError:print(json.dumps({'rejected':True}))
"""


def _sealed_and_exported(plan_raw, trust, before, after, stdout, stderr, result):
    import shutil
    import tempfile
    from test_source_recovery_linux import run_worker

    values = dict(plan=plan_raw, trust=trust, stdout=stdout, stderr=stderr)
    for label, sample in (("before", before), ("after", after)):
        values.update({f"{label}_{name}": raw for name, raw in sample.items()})
    directory = Path(tempfile.mkdtemp(prefix="edge-forged-refusal-", dir="/run"))
    directory.chmod(0o755)
    try:
        paths = {name: directory / name for name in values}
        for name, raw in values.items():
            paths[name].write_bytes(raw)
            paths[name].chmod(0o444)
        enrollment = dict(
            schema_version="edge-forged-input-refusal-enrollment/v1",
            plan_sha256=digest(plan_raw),
            reader_uid=65533,
            kernel_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            paths={name: str(path) for name, path in paths.items()},
        )
        enrollment_raw = _json(enrollment) + b"\n"
        enrolled = directory / "enrollment"
        enrolled.write_bytes(enrollment_raw)
        enrolled.chmod(0o444)
        arguments = dict(
            enrollment_path=str(enrolled),
            expected_enrollment_sha256=digest(enrollment_raw),
            expected_plan_sha256=digest(plan_raw),
        )
        originals, identities = snapshot(paths)
        output = run_worker(INTAKE, arguments, uid=65533)
        assert output["result"]["evaluation"] == result
        for uid in (0, 1000, 65534):
            assert run_worker(INTAKE, arguments, uid=uid) == {"rejected": True}
        retained, retained_identities = snapshot(paths)
        assert originals == retained
        assert {name: item["identity"] for name, item in identities.items()} == {
            name: item["identity"] for name, item in retained_identities.items()
        }
        # Unsafe enrollment uses a distinct copy; the enrolled originals stay sealed.
        unsafe = directory / "unsafe-enrollment"
        unsafe.write_bytes(enrollment_raw)
        unsafe.chmod(0o644)
        assert run_worker(
            INTAKE, dict(arguments, enrollment_path=str(unsafe)), uid=65533
        ) == {"rejected": True}
        export = os.environ.get("EDGE_FORGED_REFUSAL_PUBLIC_DIR")
        if export:
            destination = Path(export)
            destination.mkdir(mode=0o700)
            filenames = dict(
                plan="plan.json",
                trust="trust.json",
                stdout="worker.stdout",
                stderr="worker.stderr",
            )
            filenames.update(
                {
                    f"{label}_{name}": f"{label}-{name}.raw"
                    for label in ("before", "after")
                    for name in ("source", "journal", "anchors")
                }
            )
            public = {filenames[name]: raw for name, raw in values.items()}
            public["result.json"] = _json(result) + b"\n"
            for name, raw in public.items():
                path = destination / name
                with path.open("xb") as output:
                    output.write(raw)
                path.chmod(0o444)
            manifest = {
                name: dict(sha256=digest(raw), bytes=len(raw))
                for name, raw in public.items()
            }
            with (destination / "manifest.json").open("xb") as output:
                output.write(_json(manifest) + b"\n")
            (destination / "manifest.json").chmod(0o444)
    finally:
        shutil.rmtree(directory)
