"""Root-sealed intake of explicit main/queue pairing; no acquisition or authority."""

import hashlib
import os

from . import safety_collection as collection
from . import safety_observations as safety
from . import paired_safety_queue as pairing

LIMITS = dict(
    pair_plan=32768, queue_contract=128 * 1024, queue_plan=32768, queue_report=65536
)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def collect_paired_safety_queue(
    main_enrollment_path,
    pairing_enrollment_path,
    *,
    expected_main_enrollment_sha256,
    expected_main_checkpoint_sha256,
    expected_pairing_enrollment_sha256,
):
    """No write, signing, query, target, key-path or witness-client operation."""
    held = collection._HeldFiles()
    result, failure = None, None
    try:
        base = collection.collect_registered_safety(
            main_enrollment_path,
            expected_enrollment_sha256=expected_main_enrollment_sha256,
            expected_checkpoint_sha256=expected_main_checkpoint_sha256,
        )
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        safety._need(
            uid == base["provenance"]["observer_uid"]
            and boot == base["provenance"]["kernel_boot_id"],
            "base pairing reader changed",
        )
        seen = set()

        def read(path, limit):
            path = collection._physical_path(path)[0]
            safety._need(path not in seen, "paired artifact paths must be distinct")
            seen.add(path)
            return held.read(path, limit)

        en_raw = read(main_enrollment_path, 32768)
        safety._need(
            _sha(en_raw) == expected_main_enrollment_sha256, "main enrollment changed"
        )
        en = safety._wire(en_raw, 32768)
        raws = {}
        for name, limit in dict(
            contract=128 * 1024, observations=2 * 1024 * 1024, checkpoint=32768
        ).items():
            raws[name] = read(en["paths"][name], limit)
            safety._need(
                _sha(raws[name]) == base["provenance"][name + "_sha256"],
                "main artifacts changed",
            )
        contract = safety._wire(raws["contract"], 128 * 1024)
        keys = collection._registration(en, contract, uid)
        heads = collection._checkpoint(
            safety._wire(raws["checkpoint"], 32768), en, contract
        )
        raw = read(pairing_enrollment_path, 32768)
        safety._hex(expected_pairing_enrollment_sha256)
        safety._need(
            _sha(raw) == expected_pairing_enrollment_sha256,
            "pairing enrollment pin differs",
        )
        pe = safety._wire(raw, 32768)
        safety._fields(
            pe,
            "schema_version main_enrollment_sha256 main_checkpoint_sha256 paths sha256",
        )
        safety._need(
            pe["schema_version"] == "edge-paired-safety-queue-enrollment/v1"
            and pe["main_enrollment_sha256"] == expected_main_enrollment_sha256
            and pe["main_checkpoint_sha256"] == expected_main_checkpoint_sha256,
            "paired main enrollment differs",
        )
        safety._fields(pe["paths"], " ".join(LIMITS))
        safety._fields(pe["sha256"], " ".join(LIMITS))
        data = {}
        for name, limit in LIMITS.items():
            path, digest = pe["paths"][name], pe["sha256"][name]
            if path is None:
                safety._need(digest is None, "missing pair artifact with supplied hash")
                data[name] = None
            else:
                safety._hex(digest)
                data[name] = read(path, limit)
                safety._need(_sha(data[name]) == digest, "paired artifact hash differs")
        held.verify()
        diagnostic = pairing._pair(
            raws["contract"],
            dict(
                expected_contract_sha256=en["contract_sha256"],
                expected_stream_heads=heads,
                **keys,
            ),
            data["pair_plan"],
            pe["sha256"]["pair_plan"],
            data["queue_contract"],
            data["queue_plan"],
            data["queue_report"],
        )
        safety._need(
            uid == os.geteuid() and boot == collection._kernel_boot_id(),
            "pairing reader changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-paired-safety-queue-collection/v1",
            base_collection=base,
            evaluation=pairing._result(base["evaluation"], diagnostic),
            pairing_enrollment_sha256=expected_pairing_enrollment_sha256,
            qualified_safety_count=None,
            authority_flags=dict(safety.FLAGS),
            **safety.FLAGS,
        )
    except BaseException as exc:
        failure = exc
    finally:
        close_errors = held.close()
    if failure is not None or close_errors:
        raise collection.SafetyCollectionError(
            "paired safety/queue intake failed"
            + (f": {failure}" if failure else "")
            + ("; independent FD close failed" if close_errors else "")
        ) from failure
    return result
