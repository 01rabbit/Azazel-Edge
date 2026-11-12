"""Root-enrolled sealed RECORDED NFT diagnostics, never live acquisition."""

import hashlib
import os

from . import safety_collection as collection
from . import safety_observations as safety
from .recorded_nft_restoration import evaluate_recorded_nft_restoration

LIMITS = dict(
    plan=32768,
    contract=128 * 1024,
    source_plan=32768,
    trust=32768,
    source=64 * 1024 * 1024,
    baseline=8 * 1024 * 1024,
    applied=8 * 1024 * 1024,
    released=8 * 1024 * 1024,
)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def collect_recorded_nft_restoration(enrollment_path, *, expected_enrollment_sha256):
    """Fixed read-only intake. Explicit missing slots remain unmeasured."""
    held = collection._HeldFiles()
    result, failure = None, None
    try:
        safety._hex(expected_enrollment_sha256)
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        safety._need(type(uid) is int and uid > 0, "nonroot registered reader required")
        enrollment_path = collection._physical_path(enrollment_path)[0]
        raw = held.read(enrollment_path, 32768)
        safety._need(
            _sha(raw) == expected_enrollment_sha256,
            "recorded NFT enrollment pin differs",
        )
        en = safety._wire(raw, 32768)
        safety._fields(en, "schema_version observer_uid kernel_boot_id paths sha256")
        safety._need(
            en["schema_version"] == "edge-recorded-nft-enrollment/v1",
            "recorded NFT enrollment schema",
        )
        safety._need(
            type(en["observer_uid"]) is int
            and en["observer_uid"] == uid
            and en["kernel_boot_id"] == boot,
            "recorded reader/boot differs",
        )
        safety._fields(en["paths"], " ".join(LIMITS))
        safety._fields(en["sha256"], " ".join(LIMITS))
        seen, data = {enrollment_path}, {}
        for name, limit in LIMITS.items():
            path, digest = en["paths"][name], en["sha256"][name]
            if path is None:
                safety._need(
                    digest is None and name not in ("plan", "contract"),
                    "required registration artifact missing",
                )
                data[name] = None
                continue
            safety._hex(digest)
            path = collection._physical_path(path)[0]
            safety._need(path not in seen, "recorded artifact paths must be distinct")
            seen.add(path)
            data[name] = held.read(path, limit)
            safety._need(_sha(data[name]) == digest, "recorded artifact pin differs")
        contract = safety._wire(data["contract"], 128 * 1024)
        safety._contract(contract, contract["keypins"])
        safety._need(
            contract["scope"]["kernel_boot_id"] == boot
            and contract["scope"]["owner"]["observer_uid"] == uid,
            "Source contract registration differs",
        )
        plan = safety._wire(data["plan"], 32768)
        safety._need(
            plan["contract_sha256"] == en["sha256"]["contract"]
            and plan["kernel_boot_id"] == boot,
            "recorded plan registration differs",
        )
        held.verify()
        evaluation = evaluate_recorded_nft_restoration(
            data["plan"],
            expected_plan_sha256=en["sha256"]["plan"],
            source_inputs=dict(
                contract_raw=data["contract"],
                source_plan_raw=data["source_plan"],
                trust_raw=data["trust"],
                source_raw=data["source"],
            ),
            receipts={k: data[k] for k in ("baseline", "applied", "released")},
        )
        safety._need(
            uid == os.geteuid() and boot == collection._kernel_boot_id(),
            "recorded reader/boot changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-recorded-nft-collection/v1",
            evaluation=evaluation,
            provenance=dict(
                enrollment_sha256=expected_enrollment_sha256,
                artifact_sha256=dict(en["sha256"]),
                observer_uid=uid,
                kernel_boot_id=boot,
            ),
            qualified_safety_count=None,
            independently_measured=False,
            authority_flags=dict(safety.FLAGS),
            **safety.FLAGS,
        )
    except BaseException as exc:
        failure = exc
    finally:
        close_errors = held.close()
    if failure is not None or close_errors:
        raise collection.SafetyCollectionError(
            "recorded NFT intake failed"
            + (f": {failure}" if failure else "")
            + ("; independent FD close failed" if close_errors else "")
        ) from failure
    return result
