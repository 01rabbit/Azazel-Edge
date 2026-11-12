"""Additive Source/recovery diagnostics; preserve independent safety evidence."""

import hashlib
import os
import uuid

from . import safety_observations as safety
from . import safety_collection as collection
from . import recovery_evidence as recovery
from .source_authentication import verify_source_bytes
from .udp_queue import evaluate_udp_queue

FILES = dict(
    source_plan=32768,
    trust=32768,
    source=64 * 1024 * 1024,
    recovery_plan=32768,
    recovery_report=32768,
    queue_plan=32768,
    queue_report=65536,
)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _source(contract, raw, expected, trust, source):
    safety._hex(expected)
    safety._need(_digest(raw) == expected, "Source plan pin differs")
    p = safety._wire(raw, 32768)
    safety._fields(
        p,
        "schema_version contract_sha256 trust_sha256 context prefix_checkpoint final_checkpoint",
    )
    safety._need(
        p["schema_version"] == "edge-source-proof-plan/v1"
        and p["contract_sha256"] == _digest(contract),
        "Source plan binding",
    )
    c = safety._wire(contract, 128 * 1024)
    scope, keys, ctx = c["scope"], c["keypins"], p["context"]
    safety._need(type(ctx) is dict, "Source context")
    expected_context = dict(
        scope_ref=scope["scope_ref"],
        registration_sha256=scope["registration_sha256"],
        session_ref=scope["session_ref"],
        boot_ref=uuid.UUID(scope["kernel_boot_id"]).hex,
        producer_public_key=keys["source_producer_public_key"],
        witness_public_key=keys["source_witness_public_key"],
        producer_uid=scope["owner"]["producer_uid"],
        observer_uid=scope["owner"]["observer_uid"],
    )
    safety._need(
        all(ctx.get(k) == v for k, v in expected_context.items()),
        "Source scope context differs",
    )
    safety._need(
        p["trust_sha256"] == scope["policy_sha256"], "Source trust scope differs"
    )
    if p["prefix_checkpoint"] is not None:
        safety._need(
            p["prefix_checkpoint"]["sha256"] == scope["source_sha256"],
            "Source prefix scope differs",
        )
    return verify_source_bytes(
        trust,
        source,
        expected_trust_sha256=p["trust_sha256"],
        expected_context=ctx,
        expected_prefix_checkpoint=p["prefix_checkpoint"],
        expected_final_checkpoint=p["final_checkpoint"],
    )


def evaluate_safety_proofs(
    contract_raw,
    observations_raw,
    *,
    safety_pins,
    source_plan_raw=None,
    expected_source_plan_sha256=None,
    trust_raw=None,
    source_raw=None,
    recovery_plan_raw=None,
    expected_recovery_plan_sha256=None,
    recovery_report_raw=None,
    expected_recovery_report_sha256=None,
    queue_plan_raw=None,
    queue_report_raw=None,
):
    """No I/O. Supplemental failures never discard an old admissible positive."""
    base = safety.evaluate_safety_observations(
        contract_raw, observations_raw, **safety_pins
    )
    src = dict(
        schema_version="edge-source-byte-diagnostic/v1",
        status="unknown",
        authenticated_prefix=False,
        authenticated_full_source=False,
        normal_terminal_verified=False,
        reasons=["not_measured"],
        qualified_safety_count=None,
        authority_flags=dict(safety.FLAGS),
        **safety.FLAGS,
    )
    if source_plan_raw is not None:
        try:
            src = _source(
                contract_raw,
                source_plan_raw,
                expected_source_plan_sha256,
                trust_raw,
                source_raw,
            )
        except (
            ValueError,
            OSError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            src["reasons"] = ["invalid_source_proof"]
    rec = recovery.unknown_recovery()
    if recovery_plan_raw is not None:
        try:
            p = recovery._plan(recovery_plan_raw, expected_recovery_plan_sha256)
            contract = safety._wire(contract_raw, 128 * 1024)
            safety._need(
                p["contract_sha256"] == _digest(contract_raw)
                and p["kernel_boot_id"] == contract["scope"]["kernel_boot_id"]
                and p["observer_public_key"]
                == contract["keypins"]["observer_public_key"],
                "recovery scope differs",
            )
            # Validate the actual historical queue bytes, not a loader success flag.
            safety._need(
                _digest(queue_plan_raw) == p["queue_plan_sha256"]
                and _digest(queue_report_raw) == p["queue_report_sha256"],
                "queue evidence pin differs",
            )
            evaluate_udp_queue(
                contract_raw,
                queue_plan_raw,
                queue_report_raw,
                expected_contract_sha256=p["contract_sha256"],
                expected_plan_sha256=p["queue_plan_sha256"],
            )
            q = safety._wire(queue_report_raw, 65536)
            safety._need(
                p["kernel_release"] == q["kernel_release"]
                and p["not_before_ns"] >= q["finished_ns"],
                "recovery precedes observed capture finish",
            )
            rec = recovery.evaluate_recovery_evidence(
                recovery_plan_raw,
                recovery_report_raw,
                expected_plan_sha256=expected_recovery_plan_sha256,
                expected_report_sha256=expected_recovery_report_sha256,
            )
        except (
            ValueError,
            OSError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            rec = recovery.unknown_recovery("invalid_recovery_proof")
    return dict(
        schema_version="edge-safety-proof-diagnostic/v1",
        status="unqualified_diagnostic",
        safety_evaluation=base,
        source_authentication=src,
        recovery=rec,
        qualified_safety_count=None,
        authority_flags=dict(safety.FLAGS),
        **safety.FLAGS,
    )


def collect_safety_proofs(
    enrollment_path,
    supplement_path,
    *,
    expected_enrollment_sha256,
    expected_checkpoint_sha256,
    expected_supplement_sha256,
):
    """Root-sealed additive intake under the registered NONROOT reader UID."""
    held = collection._HeldFiles()
    result, failure = None, None
    try:
        base = collection.collect_registered_safety(
            enrollment_path,
            expected_enrollment_sha256=expected_enrollment_sha256,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
        )
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        safety._need(
            uid == base["provenance"]["observer_uid"]
            and boot == base["provenance"]["kernel_boot_id"],
            "base collection reader UID/boot differs",
        )
        paths = {
            "enrollment": collection._physical_path(enrollment_path)[0],
            "supplement": collection._physical_path(supplement_path)[0],
        }
        en_raw = held.read(paths["enrollment"], 32768)
        safety._need(
            _digest(en_raw) == expected_enrollment_sha256, "enrollment changed"
        )
        en = safety._wire(en_raw, 32768)
        paths.update(en["paths"])
        contract = held.read(paths["contract"], 128 * 1024)
        observations = held.read(paths["observations"], 2 * 1024 * 1024)
        checkpoint = held.read(paths["checkpoint"], 32768)
        safety._need(
            _digest(contract) == base["provenance"]["contract_sha256"]
            and _digest(observations) == base["provenance"]["observations_sha256"]
            and _digest(checkpoint) == expected_checkpoint_sha256,
            "base artifacts changed",
        )
        raw = held.read(paths["supplement"], 32768)
        safety._hex(expected_supplement_sha256)
        safety._need(
            _digest(raw) == expected_supplement_sha256, "supplement pin differs"
        )
        supplement = safety._wire(raw, 32768)
        safety._fields(
            supplement,
            "schema_version enrollment_sha256 checkpoint_sha256 paths sha256",
        )
        safety._need(
            supplement["schema_version"] == "edge-safety-proof-enrollment/v1"
            and supplement["enrollment_sha256"] == expected_enrollment_sha256
            and supplement["checkpoint_sha256"] == expected_checkpoint_sha256,
            "supplement base enrollment differs",
        )
        safety._fields(supplement["paths"], " ".join(FILES))
        safety._fields(supplement["sha256"], " ".join(FILES))
        values = {}
        for name, limit in FILES.items():
            path, digest = supplement["paths"][name], supplement["sha256"][name]
            if path is None:
                safety._need(digest is None, "missing path with supplied hash")
                values[name] = None
                continue
            safety._hex(digest)
            path, _ = collection._physical_path(path)
            safety._need(path not in paths.values(), "proof paths must be distinct")
            paths[name] = path
            values[name] = held.read(path, limit)
            safety._need(
                _digest(values[name]) == digest, "supplement artifact pin differs"
            )
        safety._need(
            len(set(paths.values())) == len(paths), "base paths must be distinct"
        )
        c = safety._wire(contract, 128 * 1024)
        keys = collection._registration(en, c, uid)
        heads = collection._checkpoint(safety._wire(checkpoint, 32768), en, c)
        held.verify()
        evaluation = evaluate_safety_proofs(
            contract,
            observations,
            safety_pins=dict(
                expected_contract_sha256=_digest(contract),
                expected_stream_heads=heads,
                **keys,
            ),
            source_plan_raw=values["source_plan"],
            expected_source_plan_sha256=supplement["sha256"]["source_plan"],
            trust_raw=values["trust"],
            source_raw=values["source"],
            recovery_plan_raw=values["recovery_plan"],
            expected_recovery_plan_sha256=supplement["sha256"]["recovery_plan"],
            recovery_report_raw=values["recovery_report"],
            expected_recovery_report_sha256=supplement["sha256"]["recovery_report"],
            queue_plan_raw=values["queue_plan"],
            queue_report_raw=values["queue_report"],
        )
        safety._need(
            uid == os.geteuid() and boot == collection._kernel_boot_id(),
            "proof reader identity changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-safety-proof-collection/v1",
            provenance=dict(
                **base["provenance"], supplement_sha256=expected_supplement_sha256
            ),
            evaluation=evaluation,
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
            "sealed proof intake failed"
            + (f": {failure}" if failure else "")
            + ("; independent FD close failed" if close_errors else "")
        ) from failure
    return result
