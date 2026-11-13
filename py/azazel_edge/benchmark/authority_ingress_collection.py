"""Read-only intake of independently pinned authority-ingress originals."""

import os

from . import safety_collection as collection
from . import safety_observations as safety
from .advisory_exec import _object, _sha, _uint
from .authority_ingress import verify_authority_ingress_observation


def collect_authority_ingress_observation(
    enrollment_path, *, expected_enrollment_sha256, expected_plan_sha256
):
    """Hold enrolled originals through final fences and close every owned FD."""
    held = collection._HeldFiles()
    failure = result = None
    try:
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        collection._require(uid > 0, "nonroot artifact reader required")
        safety._hex(expected_enrollment_sha256)
        safety._hex(expected_plan_sha256)
        seen = set()

        def read(path, maximum):
            path = collection._physical_path(path)[0]
            collection._require(path not in seen, "enrolled paths overlap")
            seen.add(path)
            return held.read(path, maximum)

        raw = read(enrollment_path, 32768)
        enrollment = _object(raw, 32768)
        safety._fields(
            enrollment, "schema_version plan_sha256 reader_uid kernel_boot_id paths"
        )
        _uint(enrollment["reader_uid"], 2**32 - 1, 1)
        collection._require(
            _sha(raw) == expected_enrollment_sha256
            and enrollment["schema_version"] == "edge-authority-ingress-enrollment/v1"
            and enrollment["plan_sha256"] == expected_plan_sha256
            and enrollment["reader_uid"] == uid
            and enrollment["kernel_boot_id"] == boot,
            "external enrollment/reader/boot differs",
        )
        paths = enrollment["paths"]
        safety._fields(paths, "plan probe sot_before sot_after audit_before audit_after")
        plan_raw = read(paths["plan"], 32768)
        plan = _object(plan_raw, 32768)
        collection._require(
            plan["kernel_boot_id"] == boot and uid != plan["actor"]["uid"],
            "independent reader/boot differs",
        )
        artifacts = {}
        path = paths["probe"]
        collection._require(
            (path is None) == (plan["probe_sha256"] is None),
            "missing probe path/hash differs",
        )
        artifacts["probe_raw"] = None if path is None else read(path, 65536)
        for phase in ("before", "after"):
            for kind in ("sot", "audit"):
                name = kind + "_" + phase
                path = paths[name]
                descriptor = plan["samples"][phase][kind]
                collection._require(
                    (path is None) == (descriptor is None),
                    "missing sample path/descriptor differs",
                )
                artifacts[name + "_raw"] = (
                    None if path is None else read(path, 1024 * 1024)
                )
        held.verify()
        evaluation = verify_authority_ingress_observation(
            plan_raw, expected_plan_sha256=expected_plan_sha256, **artifacts
        )
        held.verify()
        collection._require(
            os.geteuid() == uid and collection._kernel_boot_id() == boot,
            "reader/boot changed",
        )
        result = dict(
            schema_version="edge-authority-ingress-collection/v1",
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
