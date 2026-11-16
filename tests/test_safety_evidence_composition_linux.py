"""Actual isolated file/UID boundary; synthetic signatures/metadata, no sensor claim."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import pytest

from safety_collection_data import build_bundle
from safety_observation_data import digest, wire
from test_natural_close_recv import build, evaluate
from test_authority_ingress_linux import role

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="explicit isolated offline Root/separate-UID file-intake job required",
)
ROOT = Path(__file__).resolve().parents[1]
READER = 61002
CASES = (
    "complete",
    "missing_report",
    "changed_report",
    "missing_sot",
    "wrong_reader",
    "writable_leaf",
    "wrong_boot",
)
WORKER = r"""
import json,os,sys,socket,subprocess
from pathlib import Path
from azazel_edge.benchmark.safety_evidence_composition_collection import collect_safety_evidence_composition
from azazel_edge.benchmark.safety_collection import SafetyCollectionError
args=json.load(sys.stdin)
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
assert all(int(status[k],16)==0 for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and status['NoNewPrivs'].strip()=='1'
real_open=os.open
writing=os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND
def readonly_open(path,flags,*a,**kw):
 if flags & writing:raise AssertionError('collector requested write access')
 return real_open(path,flags,*a,**kw)
def forbidden(*a,**kw):raise AssertionError('collector requested mutation or execution')
os.open=readonly_open
for name in ('chmod','chown','mkdir','unlink','remove','rename','replace','system'):setattr(os,name,forbidden)
socket.socket=forbidden;subprocess.Popen=forbidden
try:
 result=collect_safety_evidence_composition(**args)
 print(json.dumps({'result':result}))
except SafetyCollectionError:
 print(json.dumps({'rejected':True}))
"""


@pytest.mark.parametrize("case_id", CASES)
def test_actual_readonly_safety_composition(case_id):
    directory = Path(tempfile.mkdtemp(prefix="edge-safety-composition-", dir="/run"))
    directory.chmod(0o755)
    try:
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        main_dir = directory / "main"
        main_dir.mkdir(mode=0o755)
        main = build_bundle(main_dir, "violation", boot_id=boot, observer_uid=READER)
        originals = {}

        def save(path, raw):
            path.write_bytes(raw)
            path.chmod(0o444)
            originals[path] = raw

        for name, raw in main["files"].items():
            save(main["paths"][name], raw)
        synthetic = build(
            "missing_after_sot" if case_id == "missing_sot" else "root_only_refused"
        )
        synthetic["plan"]["kernel_boot_id"] = boot
        expected = evaluate(synthetic)
        artifacts = dict(
            plan=wire(synthetic["plan"]),
            probe=wire(synthetic["probe"]),
            evaluation=wire(expected),
            **{
                name: synthetic[name + "_raw"]
                for name in ("sot_before", "sot_after", "audit_before", "audit_after")
            },
        )
        if case_id == "changed_report":
            artifacts["evaluation"] = wire(
                {"pretend_qualified": True, "observed_violation_count": 0}
            )
        pins = {
            name: None if raw is None else digest(raw)
            for name, raw in artifacts.items()
        }
        if case_id == "missing_report":
            artifacts["evaluation"] = None
        child_dir = directory / "supplement"
        child_dir.mkdir(mode=0o755)
        paths = {
            name: None if raw is None else str(child_dir / name)
            for name, raw in artifacts.items()
        }
        for name, raw in artifacts.items():
            if raw is not None:
                save(Path(paths[name]), raw)
        plan = wire(
            dict(
                schema_version="edge-safety-evidence-composition-plan/v1",
                main_contract_sha256=digest(main["files"]["contract"]),
                entries=[dict(id="natural-1", kind="natural_close_recv", sha256=pins)],
            )
        )
        save(directory / "plan", plan)
        enrollment = wire(
            dict(
                schema_version="edge-safety-evidence-composition-enrollment/v1",
                reader_uid=READER,
                kernel_boot_id="00000000-0000-4000-8000-000000000001"
                if case_id == "wrong_boot"
                else boot,
                safety=dict(
                    enrollment_path=str(main["paths"]["enrollment"]),
                    enrollment_sha256=main["expected_enrollment_sha256"],
                    checkpoint_sha256=main["expected_checkpoint_sha256"],
                ),
                composition_plan_path=str(directory / "plan"),
                supplements={"natural-1": paths},
            )
        )
        save(directory / "enrollment", enrollment)
        if case_id == "writable_leaf":
            Path(paths["probe"]).chmod(0o644)
        before = {str(path): digest(path.read_bytes()) for path in originals}
        args = dict(
            composition_enrollment_path=str(directory / "enrollment"),
            expected_composition_enrollment_sha256=digest(enrollment),
            expected_composition_plan_sha256=digest(plan),
        )
        p = subprocess.run(
            [sys.executable, "-c", WORKER],
            input=json.dumps(args),
            capture_output=True,
            text=True,
            timeout=20,
            preexec_fn=role(
                READER + 1 if case_id == "wrong_reader" else READER, READER
            ),
            cwd="/",
            env=dict(os.environ, PYTHONPATH=str(ROOT / "py")),
        )
        assert p.returncode == 0, p.stderr
        answer = json.loads(p.stdout)
        assert before == {str(path): digest(path.read_bytes()) for path in originals}
        assert all(path.read_bytes() == raw for path, raw in originals.items())
        if case_id in ("wrong_reader", "writable_leaf", "wrong_boot"):
            assert answer == {"rejected": True}
        else:
            report = answer["result"]
            combined = report["composition"]
            assert (
                combined["main_evaluation"] == report["base_collection"]["evaluation"]
            )
            assert (
                combined["main_evaluation"]["categories"]["protected_escape"][
                    "observed_violation_count"
                ]
                == 1
            )
            assert (
                combined["comparison_status"] == "WITHHELD"
                and combined["comparison_eligibility"] is False
                and combined["qualified_safety_count"] is None
            )
            assert all(
                combined[key] is False
                for key in (
                    "authorizes_transition",
                    "experiment",
                    "measurement_completed",
                    "production_admission",
                    "resume_authorized",
                )
            )
            item = combined["supplemental_items"][0]
            assert item["replayed_evaluation"] == expected
            assert item["evidence_relation"] == "historical_reference_only"
            assert item["published_evaluation_matches"] is (
                False
                if case_id == "changed_report"
                else None
                if case_id == "missing_report"
                else True
            )
            if case_id == "missing_sot":
                assert item["replayed_evaluation"]["object_changes"] == {
                    "sot": None,
                    "audit": True,
                }
                assert (
                    item["replayed_evaluation"]["sampled_originals_unchanged"] is False
                )
    finally:
        shutil.rmtree(directory)
