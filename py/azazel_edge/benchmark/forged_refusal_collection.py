"""Root-enrolled read-only copies, with a separate nonroot artifact reader."""

import os

from . import safety_collection as collection
from . import safety_observations as safety
from .forged_input_refusal import (
    MAX_ARTIFACT,
    _object,
    _sha,
    _integer,
    verify_forged_input_refusal,
)
from azazel_edge.outcome.input_auth import TrustPolicy

SLOTS = (
    "plan",
    "trust",
    "before_source",
    "before_journal",
    "before_anchors",
    "after_source",
    "after_journal",
    "after_anchors",
    "stdout",
    "stderr",
)


def collect_forged_input_refusal(
    enrollment_path, *, expected_enrollment_sha256, expected_plan_sha256
):
    """Verify sealed finite samples; never query a live journal or witness."""
    held = collection._HeldFiles()
    failure = result = None
    try:
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        safety._hex(expected_enrollment_sha256)
        safety._hex(expected_plan_sha256)
        seen = set()

        def read(path, maximum):
            path = collection._physical_path(path)[0]
            collection._require(path not in seen, "artifact paths overlap")
            seen.add(path)
            return held.read(path, maximum)

        raw = read(enrollment_path, 32768)
        enrollment = _object(raw, 32768)
        safety._fields(
            enrollment, "schema_version plan_sha256 reader_uid kernel_boot_id paths"
        )
        _integer(enrollment["reader_uid"], 1, 2**32 - 1)
        collection._require(
            _sha(raw) == expected_enrollment_sha256
            and enrollment["schema_version"]
            == "edge-forged-input-refusal-enrollment/v1"
            and enrollment["plan_sha256"] == expected_plan_sha256
            and uid == enrollment["reader_uid"]
            and boot == enrollment["kernel_boot_id"],
            "external enrollment/reader/boot differs",
        )
        paths = enrollment["paths"]
        safety._fields(paths, " ".join(SLOTS))
        plan_raw, trust_raw = read(paths["plan"], 32768), read(paths["trust"], 32768)
        plan = _object(plan_raw, 32768)
        trust = TrustPolicy(_object(trust_raw, 32768))
        collection._require(
            uid not in (0, trust.data["producer_uid"], trust.data["observer_uid"])
            and plan["kernel_boot_id"] == boot,
            "independent reader differs",
        )
        samples = {"before": {}, "after": {}}
        for phase in samples:
            for kind in ("source", "journal", "anchors"):
                path = paths[phase + "_" + kind]
                descriptor = plan["samples"][phase][kind]
                collection._require(
                    (path is None) == (descriptor is None),
                    "missing path/descriptor differs",
                )
                samples[phase][kind] = (
                    None if path is None else read(path, MAX_ARTIFACT)
                )
        stdout, stderr = read(paths["stdout"], 65536), read(paths["stderr"], 65536)
        held.verify()
        evaluation = verify_forged_input_refusal(
            plan_raw,
            expected_plan_sha256=expected_plan_sha256,
            trust_raw=trust_raw,
            before=samples["before"],
            after=samples["after"],
            stdout_raw=stdout,
            stderr_raw=stderr,
        )
        held.verify()
        collection._require(
            os.geteuid() == uid and collection._kernel_boot_id() == boot,
            "reader/boot changed",
        )
        result = dict(
            schema_version="edge-forged-input-refusal-collection/v1",
            evaluation=evaluation,
            provenance=dict(
                enrollment_sha256=expected_enrollment_sha256,
                plan_sha256=expected_plan_sha256,
                reader_uid=uid,
                kernel_boot_id=boot,
            ),
            qualified_safety_count=None,
            **safety.FLAGS,
        )
    except Exception as exc:
        failure = exc
    finally:
        errors = held.close()
        if errors:
            failure = collection.SafetyCollectionError(
                "artifact close failed: " + ",".join(errors)
            )
    if failure is not None:
        raise collection.SafetyCollectionError(str(failure)) from failure
    return result
