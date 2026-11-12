"""REAL sealed-file/UID intake of SYNTHETIC NFT snapshots, not kernel restoration."""

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import pytest
from recorded_nft_restoration_data import make_restoration_bundle
from test_source_recovery_linux import INTAKE_WORKER, run_worker
from safety_observation_data import digest, wire

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="isolated Linux Root/reader/producer UIDs required",
)
BOOT = Path("/proc/sys/kernel/random/boot_id")
WORKER = INTAKE_WORKER.replace(
    "from azazel_edge.benchmark.safety_proofs import collect_safety_proofs",
    "from azazel_edge.benchmark.recorded_nft_collection import collect_recorded_nft_restoration",
).replace("collect_safety_proofs(**a)", "collect_recorded_nft_restoration(**a)")


@pytest.fixture
def staged():
    directory = Path(tempfile.mkdtemp(prefix="edge-recorded-nft-", dir="/run"))
    directory.chmod(0o755)
    try:
        bundle = make_restoration_bundle(
            directory, kernel_boot_id=BOOT.read_text().strip()
        )
        yield directory, bundle
    finally:
        shutil.rmtree(directory)


def stage(bundle):
    for name, raw in bundle["files"].items():
        bundle["paths"][name].write_bytes(raw)
        bundle["paths"][name].chmod(0o444)
    return dict(
        enrollment_path=str(bundle["paths"]["enrollment"]),
        expected_enrollment_sha256=bundle["expected_enrollment_sha256"],
    )


@pytest.mark.parametrize("missing", [False, True])
def test_actual_nonroot_sealed_intake_of_synthetic_triplets(staged, missing):
    directory, bundle = staged
    if missing:
        en = json.loads(bundle["files"]["enrollment"])
        en["paths"]["released"] = en["sha256"]["released"] = None
        bundle["files"]["enrollment"] = wire(en)
        bundle["expected_enrollment_sha256"] = digest(bundle["files"]["enrollment"])
    payload = stage(bundle)
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
    out = run_worker(WORKER, payload, uid=61002)
    assert "result" in out, out
    r = out["result"]
    assert r["evaluation"]["status"] == (
        "unknown" if missing else "sampled_fixed_chain_returned_to_baseline"
    )
    assert r["qualified_safety_count"] is None and r["independently_measured"] is False
    assert not any(r["authority_flags"].values())
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
    assert run_worker(WORKER, payload, uid=61001)["rejected"] is True


@pytest.mark.parametrize(
    "fault",
    ["writable", "hardlink", "symlink", "mutation", "pin", "wrong-boot", "same-path"],
)
def test_actual_unsafe_recorded_intake_refuses_without_repair(staged, fault):
    directory, bundle = staged
    payload = stage(bundle)
    artifact = bundle["paths"]["released"]
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
        payload["expected_enrollment_sha256"] = "f" * 64
    else:
        en = json.loads(bundle["paths"]["enrollment"].read_bytes())
        if fault == "wrong-boot":
            en["kernel_boot_id"] = "00000000-0000-4000-8000-000000000099"
        else:
            en["paths"]["released"] = str(bundle["paths"]["baseline"])
        path = bundle["paths"]["enrollment"]
        path.chmod(0o644)
        path.write_bytes(wire(en))
        path.chmod(0o444)
        payload["expected_enrollment_sha256"] = digest(path.read_bytes())
    before = {p: p.read_bytes() for p in directory.iterdir()}
    assert run_worker(WORKER, payload, uid=61002)["rejected"] is True
    assert before == {p: p.read_bytes() for p in before}
