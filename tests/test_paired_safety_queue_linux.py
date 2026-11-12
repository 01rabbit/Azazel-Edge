"""REAL queue admission + file/UID intake; main-channel facts are SYNTHETIC.

No new sensor privilege, application-delivery/safety or production-custody claim.
"""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import pytest
from azazel_edge.benchmark.paired_safety_queue import evaluate_paired_safety_queue
from azazel_edge.benchmark.safety_observations import FLAGS
from paired_safety_queue_data import pair_from_queue, make_pair_case, make_pair_bundle
import test_udp_queue_linux as queue_lab
from test_udp_queue_linux import (
    setup_capture,
    ready,
    command,
    line,
    PAYLOAD,
)
from test_source_recovery_linux import INTAKE_WORKER, run_worker
from safety_observation_data import digest, wire

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root/BPF and child UIDs required",
)
WORKER = INTAKE_WORKER.replace(
    "from azazel_edge.benchmark.safety_proofs import collect_safety_proofs",
    "from azazel_edge.benchmark.paired_queue_collection import collect_paired_safety_queue",
).replace("collect_safety_proofs(**a)", "collect_paired_safety_queue(**a)")
BOOT = Path("/proc/sys/kernel/random/boot_id")
lab = queue_lab.lab
approved_object = queue_lab.approved_object


@pytest.fixture
def directory():
    d = Path(tempfile.mkdtemp(prefix="edge-paired-queue-", dir="/run"))
    d.chmod(0o755)
    try:
        yield d
    finally:
        shutil.rmtree(d)


def stage(bundle):
    for name, raw in bundle["files"].items():
        if raw is not None:
            bundle["paths"][name].write_bytes(raw)
            bundle["paths"][name].chmod(0o444)
    return dict(
        main_enrollment_path=str(bundle["paths"]["main_enrollment"]),
        pairing_enrollment_path=str(bundle["paths"]["pairing_enrollment"]),
        **{
            k: bundle[k]
            for k in (
                "expected_main_enrollment_sha256",
                "expected_main_checkpoint_sha256",
                "expected_pairing_enrollment_sha256",
            )
        },
    )


def assert_separate(r, expected):
    assert r["queue_pairing"]["status"] == "context_bound_pair"
    assert r["queue_pairing"]["queue_admission_observed_count"] == expected
    assert r["queue_pairing"]["application_delivery_count"] is None
    assert (
        r["main_evaluation"]["categories"]["protected_escape"][
            "observed_violation_count"
        ]
        is None
    )
    assert (
        r["main_evaluation"]["categories"]["forged_evidence_accepted"][
            "observed_violation_count"
        ]
        == 1
    )
    assert r["qualified_safety_count"] is None
    assert all(r[k] is False for k in FLAGS)


@pytest.mark.parametrize("mode,expected", [("allow", 1), ("filter-drop", None)])
def test_actual_queue_pairs_with_synthetic_four_category_main(
    lab, approved_object, directory, mode, expected
):
    target, sender, meta, sensor, c, p, pins = setup_capture(
        lab, approved_object, mode=mode
    )
    ready(sensor)
    assert command(sender, dict(port=meta["port"], payload_hex=PAYLOAD.hex()))["sent"]
    out = line(sensor)
    sensor.wait(timeout=5)
    assert "report" in out, out
    report = out["report"].encode()
    original = (c, p, report)
    inputs = pair_from_queue(c, p, report)
    result = evaluate_paired_safety_queue(
        inputs["main_contract_raw"],
        inputs["main_observations_raw"],
        **inputs["arguments"],
    )
    assert_separate(result, expected)
    bundle = make_pair_bundle(directory, inputs=inputs)
    payload = stage(bundle)
    before = {
        x: (
            x.read_bytes(),
            x.stat().st_ino,
            x.stat().st_mode,
            x.stat().st_mtime_ns,
            x.stat().st_ctime_ns,
        )
        for x in directory.iterdir()
    }
    collected = run_worker(WORKER, payload, uid=61002)
    assert "result" in collected, collected
    assert_separate(collected["result"]["evaluation"], expected)
    assert (
        collected["result"]["base_collection"]["evaluation"]
        == result["main_evaluation"]
    )
    assert before == {
        x: (
            x.read_bytes(),
            x.stat().st_ino,
            x.stat().st_mode,
            x.stat().st_mtime_ns,
            x.stat().st_ctime_ns,
        )
        for x in before
    }
    assert original == (c, p, report)
    assert run_worker(WORKER, payload, uid=61001)["rejected"] is True


@pytest.mark.parametrize(
    "fault",
    ["writable", "hardlink", "symlink", "mutation", "pin", "alias", "missing-pair"],
)
def test_actual_pair_file_boundaries_over_synthetic_payloads(directory, fault):
    # Live boot is only intake identity; every queue/main observation here is synthetic.
    inputs = make_pair_case(
        kernel_boot_id=BOOT.read_text().strip(), omit_main_protected=True
    )
    bundle = make_pair_bundle(directory, inputs=inputs)
    if fault == "missing-pair":
        en = json.loads(bundle["files"]["pairing_enrollment"])
        en["paths"]["pair_plan"] = en["sha256"]["pair_plan"] = None
        bundle["files"]["pairing_enrollment"] = wire(en)
        bundle["expected_pairing_enrollment_sha256"] = digest(
            bundle["files"]["pairing_enrollment"]
        )
    payload = stage(bundle)
    artifact = bundle["paths"]["queue_report"]
    if fault == "writable":
        artifact.chmod(0o644)
    elif fault == "hardlink":
        os.link(artifact, directory / "alias")
    elif fault == "symlink":
        old = directory / "original"
        artifact.rename(old)
        artifact.symlink_to(old)
    elif fault == "mutation":
        artifact.chmod(0o644)
        artifact.write_bytes(b"{}\n")
        artifact.chmod(0o444)
    elif fault == "pin":
        payload["expected_pairing_enrollment_sha256"] = "f" * 64
    elif fault == "alias":
        en = json.loads(bundle["paths"]["pairing_enrollment"].read_bytes())
        en["paths"]["queue_report"] = str(bundle["paths"]["queue_plan"])
        path = bundle["paths"]["pairing_enrollment"]
        path.chmod(0o644)
        path.write_bytes(wire(en))
        path.chmod(0o444)
        payload["expected_pairing_enrollment_sha256"] = digest(path.read_bytes())
    before = {x: x.read_bytes() for x in directory.iterdir()}
    out = run_worker(WORKER, payload, uid=61002)
    if fault == "missing-pair":
        assert "result" in out, out
        r = out["result"]["evaluation"]
        assert r["queue_pairing"]["status"] == "unknown"
        assert r["queue_pairing"]["queue_admission_observed_count"] is None
        assert (
            r["main_evaluation"]["categories"]["forged_evidence_accepted"][
                "observed_violation_count"
            ]
            == 1
        )
    else:
        assert out["rejected"] is True
    assert before == {x: x.read_bytes() for x in before}
