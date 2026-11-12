"""REAL protocol payload-copy + file/UID intake; main-channel facts are SYNTHETIC.

No new sensor privilege, application-delivery/safety or production-custody claim.
"""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

import pytest
from udp_payload_copy_data import PAYLOAD
from test_udp_copy_link_lifecycle_linux import TARGET_WORKER
from test_udp_copy_credentials_linux import SENDER_WORKER
import test_udp_queue_linux as old_queue
from azazel_edge.benchmark.paired_safety_payload_copy import (
    evaluate_paired_safety_payload_copy,
)
from azazel_edge.benchmark.safety_observations import (
    FLAGS,
    evaluate_safety_observations,
)
from paired_safety_payload_copy_data import (
    pair_from_copy,
    make_pair_case,
    make_pair_bundle,
)
import test_udp_payload_copy_linux as copy_lab
from test_udp_payload_copy_linux import (
    command,
    line,
)
from test_source_recovery_linux import INTAKE_WORKER, run_worker
from safety_observation_data import digest, wire

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root/BPF and child UIDs required",
)
WORKER = INTAKE_WORKER.replace(
    "from azazel_edge.benchmark.safety_proofs import collect_safety_proofs",
    "from azazel_edge.benchmark.paired_copy_collection import collect_paired_safety_payload_copy",
).replace("collect_safety_proofs(**a)", "collect_paired_safety_payload_copy(**a)")
MAIN_WORKER = INTAKE_WORKER.replace(
    "from azazel_edge.benchmark.safety_proofs import collect_safety_proofs",
    "from azazel_edge.benchmark.safety_collection import collect_registered_safety",
).replace("collect_safety_proofs(**a)", "collect_registered_safety(**a)")
BOOT = Path("/proc/sys/kernel/random/boot_id")
lab = copy_lab.lab
copy_object = copy_lab.copy_object


@pytest.fixture
def directory():
    d = Path(tempfile.mkdtemp(prefix="edge-paired-copy-", dir="/run"))
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
    assert r["payload_copy_pairing"]["status"] == "context_bound_pair"
    assert r["payload_copy_pairing"]["protocol_payload_copy_observed_count"] == expected
    assert r["payload_copy_pairing"]["application_delivery_count"] is None
    assert r["payload_copy_pairing"]["successful_syscall_count"] is None
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


def test_actual_copy_pairs_with_synthetic_four_category_main(
    lab, copy_object, directory
):
    # Only disposable target/sender code is guarded; the observer is unchanged.
    def guarded_actor(code, *args, **kwargs):
        if code == copy_lab.COPY_TARGET_WORKER:
            code = TARGET_WORKER
        elif code == old_queue.SENDER_WORKER:
            code = SENDER_WORKER
        return lab(code, *args, **kwargs)

    target, sender, meta, sensor, c, p, pins = copy_lab.setup_capture(
        guarded_actor, copy_object
    )
    expected = 1
    copy_lab.ready(sensor)
    assert command(sender, dict(port=meta["port"], payload_hex=PAYLOAD.hex()))["sent"]
    before_copy = time.monotonic_ns()
    control = command(target, dict(op="copy", mode="iovec"))
    after_copy = time.monotonic_ns()
    assert control["control_only"] is True
    assert control["ret"] == 64 and control["payload_hex"] == PAYLOAD.hex()
    out = line(sensor)
    sensor.wait(timeout=5)
    assert "report" in out, out
    report = out["report"].encode()
    event = json.loads(report)["events"][0]
    assert (
        before_copy
        <= event["entered_ns"]
        <= event["consumed_ns"]
        <= event["exited_ns"]
        <= after_copy
    )
    assert event["receiver_tgid"] == control["receiver"]["pid"]
    assert event["receiver_tid"] == control["receiver"]["tid"]
    original = (c, p, report)
    inputs = pair_from_copy(c, p, report)
    result = evaluate_paired_safety_payload_copy(
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
    assert run_worker(WORKER, payload, uid=0)["rejected"] is True


@pytest.mark.parametrize(
    "fault",
    ["writable", "hardlink", "symlink", "mutation", "pin", "alias", "missing-pair"],
)
def test_actual_pair_file_boundaries_over_synthetic_payloads(directory, fault):
    # Live boot is only intake identity; every copy/main observation here is synthetic.
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
    artifact = bundle["paths"]["copy_report"]
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
        en["paths"]["copy_report"] = str(bundle["paths"]["copy_plan"])
        path = bundle["paths"]["pairing_enrollment"]
        path.chmod(0o644)
        path.write_bytes(wire(en))
        path.chmod(0o444)
        payload["expected_pairing_enrollment_sha256"] = digest(path.read_bytes())
    before = {x: x.read_bytes() for x in directory.iterdir()}
    expected_main = evaluate_safety_observations(
        inputs["main_contract_raw"],
        inputs["main_observations_raw"],
        **inputs["arguments"]["main_arguments"],
    )
    out = run_worker(WORKER, payload, uid=61002)
    if fault == "missing-pair":
        assert "result" in out, out
        r = out["result"]["evaluation"]
        assert r["payload_copy_pairing"]["status"] == "unknown"
        assert r["payload_copy_pairing"]["protocol_payload_copy_observed_count"] is None
        assert (
            r["main_evaluation"]["categories"]["forged_evidence_accepted"][
                "observed_violation_count"
            ]
            == 1
        )
    else:
        assert out["rejected"] is True
    standalone = run_worker(
        MAIN_WORKER,
        dict(
            enrollment_path=str(bundle["paths"]["main_enrollment"]),
            expected_enrollment_sha256=bundle["expected_main_enrollment_sha256"],
            expected_checkpoint_sha256=bundle["expected_main_checkpoint_sha256"],
        ),
        uid=61002,
    )
    assert standalone["result"]["evaluation"] == expected_main
    assert before == {x: x.read_bytes() for x in before}
