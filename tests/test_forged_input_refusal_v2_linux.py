"""Ten REAL UID scopes; registration/lifecycle payloads and wrong key are lab data."""

import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest
from azazel_edge.outcome.input_auth import (
    TrustPolicy,
    SourceVerifier,
    crypto,
    public_hex,
)
from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.forged_input_refusal import verify_forged_input_refusal_v2
import test_outcome_input_auth_linux as auth_lab
from test_source_witness_linux import actual_prefix
from test_outcome_live_origin import frame
from test_source_recovery_linux import run_worker
from test_forged_input_refusal_linux import WORKER, CONTROL, _run, snapshot, digest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root and actual separate child UIDs required",
)
CASES = ("wrong_key", "scope_mismatch", "replay", "chain_corruption", "partial_frame")
FILES = (
    "plan.json",
    "trust.json",
    "before-source.raw",
    "before-journal.raw",
    "before-anchors.raw",
    "after-source.raw",
    "after-journal.raw",
    "after-anchors.raw",
    "worker.stdout",
    "worker.stderr",
    "result.json",
    "reference-frame.raw",
    "manifest.json",
)
REASONS = {
    "wrong_key": "authentication signature invalid",
    "scope_mismatch": "signed input identity/sequence mismatch",
    "replay": "signed input identity/sequence mismatch",
    "chain_corruption": "signed input identity/sequence mismatch",
    "partial_frame": "incomplete input tail; automatic resume refused",
}

PRODUCER = r"""
import json,os,sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,SignedCaptureWriter,_json,private_key,sign,SOURCE_DOMAIN,crypto,public_hex
p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer');a=json.load(sys.stdin)
path=Path(p.data['source_path']);prefix=path.read_bytes()
with SignedCaptureWriter(p,Path(sys.argv[2]),boot_ref=a['boot_ref']) as w:w.append(a['event'])
valid=path.read_bytes()[len(prefix):];row=json.loads(valid);core={k:v for k,v in row.items() if k!='signature'}
wrong=crypto()[0].from_private_bytes(bytes.fromhex('42'*32));wrong_public=public_hex(wrong)
assert wrong_public not in (p.data['producer_public_key'],p.data['witness_public_key'])
tail=valid
if a['negative']:
 kind=a['kind']
 if kind=='wrong_key':row['signature']=sign(wrong,SOURCE_DOMAIN,core);tail=_json(row)+b'\n'
 elif kind in ('scope_mismatch','chain_corruption'):
  if kind=='scope_mismatch':core['scope_ref']='foreign-scope'
  else:core['prev']='1'*64 if core['prev']!='1'*64 else '2'*64
  row={**core,'signature':sign(private_key(Path(sys.argv[2]),p.data['producer_public_key']),SOURCE_DOMAIN,core)};tail=_json(row)+b'\n'
 elif kind=='replay':tail=prefix.splitlines(keepends=True)[-1]
 elif kind=='partial_frame':tail=valid[:-17];assert tail and b'\n' not in tail
 else:raise ValueError('fixed case required')
 fd=os.open(path,os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  os.lseek(fd,len(prefix),os.SEEK_SET);remaining=memoryview(tail)
  while remaining:
   n=os.write(fd,remaining);assert n>0;remaining=remaining[n:]
  os.ftruncate(fd,len(prefix)+len(tail));os.fsync(fd)
 finally:os.close(fd)
assert path.read_bytes()==prefix+tail
print(json.dumps({'valid_frame':valid.decode(),'uid':os.geteuid(),'wrong_public_key':wrong_public}))
"""


@pytest.fixture
def fresh_prefix(monkeypatch):
    # Only the synthetic enrollment constructor changes: verifiers, processes,
    # filesystem reads and authentication remain actual existing implementations.
    original = auth_lab.make_policy

    def unique_scope(*args, **kwargs):
        policy, *material = original(*args, **kwargs)
        return (
            TrustPolicy(dict(policy.data, scope_ref="scope-" + uuid.uuid4().hex)),
            *material,
        )

    monkeypatch.setattr(auth_lab, "make_policy", unique_scope)
    yield from actual_prefix.__wrapped__(monkeypatch)


@pytest.fixture(scope="module")
def public_export():
    root = os.environ.get("EDGE_FORGED_REFUSAL_V2_PUBLIC_DIR")
    inventory = {kind: dict(state="missing", manifest_sha256=None) for kind in CASES}
    if not root:
        yield None, inventory
        return
    root = Path(root)
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    try:
        yield root, inventory
    finally:
        raw = _json(inventory) + b"\n"
        _save(root / "case-index.json", raw)
        done = subprocess.run(
            [sys.executable, "-c", PUBLIC_READER, str(root), digest(raw)],
            cwd="/",
            user=1000,
            group=1000,
            extra_groups=[],
            capture_output=True,
            text=True,
            timeout=12,
        )
        assert done.returncode == 0, done.stderr
        assert json.loads(done.stdout)["uid"] == 1000


def _save(path, raw):
    with path.open("xb") as output:
        output.write(raw)
    path.chmod(0o444)


@pytest.mark.parametrize("kind", CASES)
@pytest.mark.parametrize("negative", [False, True], ids=["matched-valid", "refusal"])
def test_actual_five_refusal_recipes(fresh_prefix, public_export, kind, negative):
    f, trust, prefix, anchors, arguments = fresh_prefix
    f.start()  # witness startup is setup, before the challenge/sampling interval
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
            dict(
                boot_ref=context["boot_ref"], event=event, negative=negative, kind=kind
            )
        ).encode(),
    )
    assert producer["returncode"] == 0 and errors == b"", errors.decode()
    generated = json.loads(output)
    assert generated["uid"] == 1000
    reference = generated["valid_frame"].encode()
    assert SourceVerifier(f.p).verify(prefix + reference)["seq"] == 2
    assert reference.endswith(b"\n") and reference.count(b"\n") == 1
    paths = dict(source=f.source, journal=f.journal, anchors=f.anchors)
    before, before_meta = snapshot(paths)
    assert before["source"].startswith(prefix)
    stdout, stderr, worker = _run(f, WORKER if negative else CONTROL, uid=65534)
    after, after_meta = snapshot(paths)
    if not negative:
        assert worker["returncode"] == 0, stderr.decode()
        state = json.loads(stdout)
        assert state["control_only"] is True and state["uid"] == 65534
        assert state["status"]["input_position"] == dict(
            offset=len(prefix + reference), sha256=digest(prefix + reference)
        )
        assert before["source"] == after["source"] == prefix + reference
        assert (
            before["journal"] != after["journal"]
            and before["anchors"] != after["anchors"]
        )
        return
    assert worker["returncode"] > 0 and stdout == b""
    assert stderr.endswith(
        (
            "azazel_edge.outcome.journal.OutcomeJournalError: " + REASONS[kind] + "\n"
        ).encode()
    )
    assert before == after
    assert {k: v["identity"] for k, v in before_meta.items()} == {
        k: v["identity"] for k, v in after_meta.items()
    }
    private = crypto()[0].from_private_bytes(bytes.fromhex("42" * 32))
    wrong_public = public_hex(private)
    assert generated["wrong_public_key"] == wrong_public
    plan = dict(
        schema_version="edge-forged-input-refusal-plan/v2",
        capture_id="actual-" + kind + "-" + context["scope_ref"],
        kernel_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        expected_trust_sha256=digest(trust),
        expected_context=context,
        expected_source_checkpoint=arguments["expected_source_checkpoint"],
        expected_anchor_checkpoint=arguments["expected_anchor_checkpoint"],
        samples=dict(before=before_meta, after=after_meta),
        worker=worker,
        challenge=dict(
            kind=kind,
            reference_frame_sha256=digest(reference),
            challenge_public_key=wrong_public if kind == "wrong_key" else None,
            partial_bytes=len(reference) - 17 if kind == "partial_frame" else None,
        ),
    )
    raw = _json(plan) + b"\n"
    result = verify_forged_input_refusal_v2(
        raw,
        expected_plan_sha256=digest(raw),
        trust_raw=trust,
        before=before,
        after=after,
        stdout_raw=stdout,
        stderr_raw=stderr,
        reference_frame_raw=reference,
    )
    assert result["status"] == "recorded_refusal_consistent", result
    assert (
        result["challenge_verified"] is True
        and result["reference_frame_authenticated"] is True
    )
    assert (
        result["challenge_kind"] == kind
        and result["expected_refusal_reason"] == REASONS[kind]
    )
    assert (
        result["sampled_state_unchanged"] is True
        and result["observed_persistent_change"] is False
    )
    assert (
        result["baseline_witness_verified"] is True
        and result["journal_cursor_structurally_verified"] is True
    )
    assert (
        result["full_journal_semantics_verified"] is False
        and result["qualified_safety_count"] is None
    )
    _sealed_and_exported(
        public_export,
        kind,
        raw,
        trust,
        before,
        after,
        stdout,
        stderr,
        reference,
        result,
    )


INTAKE = r"""
import json,sys
from azazel_edge.benchmark.forged_refusal_collection import collect_forged_input_refusal_v2
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
try:print(json.dumps({'result':collect_forged_input_refusal_v2(**json.load(sys.stdin))}))
except SafetyCollectionError:print(json.dumps({'rejected':True}))
"""


def _sealed_and_exported(
    public_export, kind, plan, trust, before, after, stdout, stderr, reference, result
):
    import shutil
    import tempfile

    directory = Path(tempfile.mkdtemp(prefix="edge-refusal-v2-", dir="/run"))
    directory.chmod(0o755)
    values = dict(
        plan=plan, trust=trust, stdout=stdout, stderr=stderr, reference_frame=reference
    )
    values.update(
        {
            f"{phase}_{name}": raw
            for phase, sample in (("before", before), ("after", after))
            for name, raw in sample.items()
        }
    )
    try:
        paths = {name: directory / name for name in values}
        for name, raw in values.items():
            _save(paths[name], raw)
        enrollment = dict(
            schema_version="edge-forged-input-refusal-enrollment/v2",
            plan_sha256=digest(plan),
            reader_uid=65533,
            kernel_boot_id=json.loads(plan)["kernel_boot_id"],
            paths={name: str(path) for name, path in paths.items()},
        )
        enrolled = _json(enrollment) + b"\n"
        _save(directory / "enrollment", enrolled)
        kwargs = dict(
            enrollment_path=str(directory / "enrollment"),
            expected_enrollment_sha256=digest(enrolled),
            expected_plan_sha256=digest(plan),
        )
        original, metadata = snapshot(paths)
        output = run_worker(INTAKE, kwargs, uid=65533)
        assert output["result"]["evaluation"] == result
        for uid in (0, 1000, 65534):
            assert run_worker(INTAKE, kwargs, uid=uid) == {"rejected": True}
        unsafe = directory / "unsafe-enrollment"
        _save(unsafe, enrolled)
        unsafe.chmod(0o644)
        assert run_worker(
            INTAKE, dict(kwargs, enrollment_path=str(unsafe)), uid=65533
        ) == {"rejected": True}
        retained, retained_meta = snapshot(paths)
        assert original == retained
        assert {k: v["identity"] for k, v in metadata.items()} == {
            k: v["identity"] for k, v in retained_meta.items()
        }
        root, inventory = public_export
        if root is not None:
            child = root / kind
            child.mkdir(mode=0o755)
            child.chmod(0o755)
            public = {
                name.replace("_", "-") + ".raw": raw
                for name, raw in values.items()
                if name.startswith(("before_", "after_"))
            }
            public.update(
                {
                    "plan.json": plan,
                    "trust.json": trust,
                    "worker.stdout": stdout,
                    "worker.stderr": stderr,
                    "reference-frame.raw": reference,
                    "result.json": _json(result) + b"\n",
                }
            )
            assert set(public) == set(FILES) - {"manifest.json"}
            for name, raw in public.items():
                _save(child / name, raw)
            manifest = (
                _json(
                    {
                        name: dict(bytes=len(raw), sha256=digest(raw))
                        for name, raw in public.items()
                    }
                )
                + b"\n"
            )
            _save(child / "manifest.json", manifest)
            inventory[kind] = dict(state="complete", manifest_sha256=digest(manifest))
    finally:
        shutil.rmtree(directory)


PUBLIC_READER = r"""
import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);assert os.geteuid()==1000
cases={'wrong_key','scope_mismatch','replay','chain_corruption','partial_frame'}
files={'plan.json','trust.json','before-source.raw','before-journal.raw','before-anchors.raw','after-source.raw','after-journal.raw','after-anchors.raw','worker.stdout','worker.stderr','result.json','reference-frame.raw','manifest.json'}
assert stat.S_IMODE(root.stat().st_mode)==0o755
assert set(os.listdir(root))<=cases|{'case-index.json'}
def read(path):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==0o444 and info.st_nlink==1 and 0<=info.st_size<=1048576
  data=b''
  while len(data)<=info.st_size:
   part=os.read(fd,min(65536,info.st_size+1-len(data)))
   if not part:break
   data+=part
  assert len(data)==info.st_size
  return data
 finally:os.close(fd)
raw=read(root/'case-index.json');assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
index=json.loads(raw);assert set(index)==cases
for kind,record in index.items():
 assert set(record)=={'state','manifest_sha256'}
 directory=root/kind
 if not directory.exists():assert record=={'state':'missing','manifest_sha256':None};continue
 assert stat.S_ISDIR(directory.stat().st_mode) and stat.S_IMODE(directory.stat().st_mode)==0o755
 names=set(os.listdir(directory));assert names<=files
 originals={name:read(directory/name) for name in names}
 if record['state']=='missing':assert record['manifest_sha256'] is None;continue
 assert record['state']=='complete' and names==files
 manifest=originals.pop('manifest.json');assert hashlib.sha256(manifest).hexdigest()==record['manifest_sha256']
 entries=json.loads(manifest);assert set(entries)==files-{'manifest.json'}
 for name,data in originals.items():assert entries[name]=={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
print(json.dumps({'uid':os.geteuid(),'cases':len(index)}))
"""
