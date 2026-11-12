"""Sealed read-only socket payload-copy intake, no acquisition or process reads."""

import os
from . import safety_collection as collection
from . import safety_observations as safety
from .udp_payload_copy import (
    UDPPayloadCopyError,
    _need,
    _digest,
    evaluate_udp_payload_copy,
)


def collect_udp_payload_copy(
    enrollment_path,
    plan_path,
    report_path,
    *,
    expected_enrollment_sha256,
    expected_checkpoint_sha256,
    expected_plan_sha256,
    expected_report_sha256,
):
    held = collection._HeldFiles()
    failure = None
    result = None
    try:
        for value in (
            expected_enrollment_sha256,
            expected_checkpoint_sha256,
            expected_plan_sha256,
            expected_report_sha256,
        ):
            safety._hex(value)
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        _need(type(uid) is int and uid > 0, "nonroot reader required")
        enrollment_path = collection._physical_path(enrollment_path)[0]
        raw = held.read(enrollment_path, 32 * 1024)
        _need(_digest(raw) == expected_enrollment_sha256, "enrollment pin differs")
        enrollment = safety._wire(raw, 32 * 1024)
        safety._fields(
            enrollment, "schema_version contract_sha256 scope observer_uid paths"
        )
        safety._fields(enrollment["paths"], "contract observations checkpoint")
        paths = {
            k: collection._physical_path(v)[0] for k, v in enrollment["paths"].items()
        }
        plan_path = collection._physical_path(plan_path)[0]
        report_path = collection._physical_path(report_path)[0]
        _need(
            len(set([enrollment_path, *paths.values(), plan_path, report_path])) == 6,
            "six distinct paths required",
        )
        contract = held.read(paths["contract"], 128 * 1024)
        observations = held.read(paths["observations"], 2 * 1024 * 1024)
        checkpoint = held.read(paths["checkpoint"], 32 * 1024)
        plan = held.read(plan_path, 32 * 1024)
        report = held.read(report_path, 64 * 1024)
        _need(
            _digest(plan) == expected_plan_sha256
            and _digest(report) == expected_report_sha256
            and _digest(checkpoint) == expected_checkpoint_sha256,
            "artifact pin differs",
        )
        obs = safety._wire(observations, 2 * 1024 * 1024)
        check = safety._wire(checkpoint, 32 * 1024)
        _need(
            obs.get("channels") == {}
            and type(check.get("stream_heads")) is dict
            and set(check["stream_heads"]) == set(safety.CATEGORIES)
            and all(v is None for v in check["stream_heads"].values()),
            "delivery sensor must be absent",
        )
        collected = collection.collect_registered_safety(
            enrollment_path,
            expected_enrollment_sha256=expected_enrollment_sha256,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
        )
        _need(
            collected["provenance"]["observer_uid"] == uid
            and collected["provenance"]["kernel_boot_id"] == boot
            and collected["provenance"]["contract_sha256"]
            == enrollment["contract_sha256"],
            "reader context differs",
        )
        held.verify()
        payload_copy = evaluate_udp_payload_copy(
            contract,
            plan,
            report,
            expected_contract_sha256=enrollment["contract_sha256"],
            expected_plan_sha256=expected_plan_sha256,
        )
        _need(
            os.geteuid() == uid and collection._kernel_boot_id() == boot,
            "reader UID/boot changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-udp-payload-copy-collection/v1",
            status="unqualified_udp_payload_copy_collection",
            collection=collected,
            payload_copy=payload_copy,
        )
    except BaseException as exc:
        failure = exc
    finally:
        errors = held.close()
    if failure is not None or errors:
        raise UDPPayloadCopyError(
            "sealed payload-copy join failed"
            + (f": {failure}" if failure else "")
            + ("; FD close failure" if errors else "")
        ) from failure
    return result
