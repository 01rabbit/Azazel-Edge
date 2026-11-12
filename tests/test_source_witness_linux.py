"""REAL existing witness/producer/observer UIDs; payload lifecycle is SYNTHETIC.

No installed service, production key, defense event or recovery acceptance.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from test_outcome_input_auth_linux import Fixture, Child, ROOT
import test_outcome_input_auth_linux as auth_lab
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from azazel_edge.outcome.journal import _json
from azazel_edge.benchmark.source_witness import verify_witnessed_source_prefix
from safety_observation_data import digest
from source_witness_data import anchor_checkpoint
from test_outcome_live_origin import frame

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root and actual child UIDs required",
)
PRODUCER_WORKER = r"""
import json,sys
from pathlib import Path
from azazel_edge.outcome.input_auth import TrustPolicy,SignedCaptureWriter
p=TrustPolicy.from_file(Path(sys.argv[1]),role='producer')
a=json.loads(sys.stdin.read())
with SignedCaptureWriter(p,Path(sys.argv[2]),boot_ref=a['boot_ref']) as w:print(json.dumps(w.append(a['event'])))
"""

# Reuse the existing lab worker with one explicit CONTROL-only cursor operation.
# Marking missed preserves the input without submitting it to Outcome collection.
OBSERVER_WORKER = auth_lab.WORKER.replace(
    "     elif cmd['op']=='begin':",
    "     elif cmd['op']=='cursoronly':\n      line=line_for(source,j);j.advance_input(line.position,missed=True)\n     elif cmd['op']=='begin':",
)


@pytest.fixture
def actual_prefix(monkeypatch):
    f = Fixture()
    child = None
    try:
        f.p = TrustPolicy(
            dict(
                f.p.data,
                schema_version="outcome-input-trust/v3",
                origin_registration_sha256="f" * 64,
            )
        )
        f.policy_file.write_bytes(_json(dict(f.p.data)))
        f.start(initialize=True)
        monkeypatch.setattr(auth_lab, "WORKER", OBSERVER_WORKER)
        child = Child(f, True)
        assert child.initial.get("ready"), child.initial
        boot = (
            Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
        )
        session = "a" * 32
        native = frame("session_prepare", 0, session)
        event = native["event"]
        event["capture_origin"] = dict(
            schema_version="outcome-registered-origin/v2",
            registration_sha256="f" * 64,
            mode="live-core",
            session_ref=session,
            seq=0,
            kind="session_prepare",
        )
        done = subprocess.run(
            [sys.executable, "-c", PRODUCER_WORKER, str(f.policy_file), str(f.pk)],
            input=json.dumps(dict(boot_ref=boot, event=event)),
            text=True,
            capture_output=True,
            timeout=15,
            user=1000,
            group=1000,
            extra_groups=[],
            env=dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    [str(ROOT), str(ROOT / "py"), str(ROOT / "tests")]
                ),
            ),
        )
        assert done.returncode == 0, done.stderr
        observed = child.command("cursoronly")
        assert observed["outcomes"] == 0 and observed["status"]["pending"] == 0
        captured = f.source.read_bytes()
        assert observed["status"]["input_position"] == dict(
            offset=len(captured), sha256=digest(captured)
        )
        # Existing observer cursor lifecycle creates actual durable signed anchors;
        # no source event is submitted to its Outcome collector.
        denied = child.command("probe", paths=[str(f.pk), str(f.wk), str(f.anchors)])
        assert denied["denied"] == [True, True, True]
        child.close()
        child = None
        f.halt()
        source, anchors = f.source.read_bytes(), f.anchors.read_bytes()
        assert len(anchors.splitlines()) > 1
        tip = SourceVerifier(f.p).verify(source)
        context = {
            k: f.p.data[k]
            for k in (
                "scope_ref",
                "producer_ref",
                "stream_ref",
                "producer_public_key",
                "witness_public_key",
                "producer_uid",
                "observer_uid",
            )
        }
        context.update(registration_sha256="f" * 64, session_ref=session, boot_ref=boot)
        trust = _json(dict(f.p.data)) + b"\n"
        args = dict(
            expected_trust_sha256=digest(trust),
            expected_context=context,
            expected_source_checkpoint=tip,
            expected_anchor_checkpoint=anchor_checkpoint(anchors),
        )
        yield f, trust, source, anchors, args
    finally:
        if child is not None:
            child.kill()
        f.clean()


@pytest.mark.parametrize("suffix", ["none", "source", "anchor", "both"])
def test_actual_witness_anchor_prefix_survives_unverified_suffix(actual_prefix, suffix):
    f, trust, source, anchors, args = actual_prefix
    before = {p: p.read_bytes() for p in (f.source, f.anchors, f.journal, f.pk, f.wk)}
    result = verify_witnessed_source_prefix(
        trust,
        source + (b'{"partial":' if suffix in ("source", "both") else b""),
        anchors + (b'{"partial":' if suffix in ("anchor", "both") else b""),
        **args,
    )
    assert result["source_prefix_authenticated"] is True
    assert result["witness_prefix_authenticated"] is True
    assert result["journal_verified"] is False
    assert result["qualified_safety_count"] is None
    assert before == {p: p.read_bytes() for p in before}


def test_actual_old_anchor_cannot_satisfy_retained_later_checkpoint(actual_prefix):
    _, trust, source, anchors, args = actual_prefix
    earlier = b"".join(anchors.splitlines(keepends=True)[:-1])
    result = verify_witnessed_source_prefix(trust, source, earlier, **args)
    assert result["source_prefix_authenticated"] is True
    assert result["witness_prefix_authenticated"] is False


@pytest.mark.parametrize("case", ["valid", "bad-anchor", "missing-plan"])
def test_actual_sealed_witness_export_and_separate_reader(actual_prefix, case):
    import shutil
    import tempfile
    from witnessed_proofs_data import make_witness_bundle
    from test_source_recovery_linux import INTAKE_WORKER, run_worker

    f, trust, source, anchors, args = actual_prefix
    directory = Path(tempfile.mkdtemp(prefix="edge-witness-export-", dir="/run"))
    directory.chmod(0o755)
    try:
        override = dict(
            trust_raw=trust,
            source_raw=source,
            arguments=dict(
                expected_trust_sha256=args["expected_trust_sha256"],
                expected_context=args["expected_context"],
                expected_prefix_checkpoint=args["expected_source_checkpoint"],
                expected_final_checkpoint=args["expected_source_checkpoint"],
            ),
        )
        bundle = make_witness_bundle(
            directory,
            source_override=override,
            anchors_raw=anchors,
            anchor_checkpoint=args["expected_anchor_checkpoint"],
        )
        if case == "bad-anchor":
            # Re-pin the deliberately bad submission, retain original signed-prefix
            # checkpoint: a root manifest alone cannot authenticate its bytes.
            raw = bundle["files"]["anchors"].replace(
                b'"signature":"', b'"signature":"0', 1
            )
            bundle["files"]["anchors"] = raw
            en = json.loads(bundle["files"]["witness_supplement"])
            en["anchors_sha256"] = digest(raw)
            bundle["files"]["witness_supplement"] = _json(en) + b"\n"
            bundle["pins"]["expected_witness_supplement_sha256"] = digest(
                bundle["files"]["witness_supplement"]
            )
        elif case == "missing-plan":
            en = json.loads(bundle["files"]["witness_supplement"])
            en["plan_path"] = en["plan_sha256"] = None
            bundle["files"]["witness_supplement"] = _json(en) + b"\n"
            bundle["pins"]["expected_witness_supplement_sha256"] = digest(
                bundle["files"]["witness_supplement"]
            )
        for name, raw in bundle["files"].items():
            bundle["paths"][name].write_bytes(raw)
            bundle["paths"][name].chmod(0o444)
        before = {
            p: (
                p.read_bytes(),
                p.stat().st_ino,
                p.stat().st_mode,
                p.stat().st_mtime_ns,
                p.stat().st_ctime_ns,
            )
            for p in directory.iterdir()
        }
        worker = INTAKE_WORKER.replace(
            "from azazel_edge.benchmark.safety_proofs import collect_safety_proofs",
            "from azazel_edge.benchmark.witnessed_proofs import collect_witnessed_safety_proofs",
        ).replace("collect_safety_proofs(**a)", "collect_witnessed_safety_proofs(**a)")
        payload = dict(
            enrollment_path=str(bundle["paths"]["enrollment"]),
            supplement_path=str(bundle["paths"]["supplement"]),
            witness_supplement_path=str(bundle["paths"]["witness_supplement"]),
            **bundle["pins"],
        )
        output = run_worker(worker, payload, uid=f.p.data["observer_uid"])
        assert "result" in output, output
        r = output["result"]
        assert r["source_witness"]["witness_prefix_authenticated"] is (case == "valid")
        assert r["source_witness"]["journal_verified"] is False
        base = r["base_collection"]["evaluation"]
        assert base["source_authentication"]["authenticated_full_source"] is True
        assert base["source_authentication"]["normal_terminal_verified"] is False
        assert (
            base["safety_evaluation"]["categories"]["forged_evidence_accepted"][
                "observed_violation_count"
            ]
            == 1
        )
        assert before == {
            p: (
                p.read_bytes(),
                p.stat().st_ino,
                p.stat().st_mode,
                p.stat().st_mtime_ns,
                p.stat().st_ctime_ns,
            )
            for p in before
        }
        # Producer cannot become the root-enrolled offline observer.
        assert (
            run_worker(worker, payload, uid=f.p.data["producer_uid"])["rejected"]
            is True
        )
    finally:
        shutil.rmtree(directory)
