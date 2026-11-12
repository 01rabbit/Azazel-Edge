"""Additive independently pinned witness-prefix provenance; no new authority."""

import hashlib
import os

from . import safety_observations as safety
from . import safety_collection as collection
from . import safety_proofs as proofs
from .source_witness import verify_witnessed_source_prefix


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _unknown(reason="not_measured"):
    return dict(
        schema_version="edge-source-witness-prefix-diagnostic/v1",
        source_prefix_authenticated=False,
        witness_prefix_authenticated=False,
        source_checkpoint=None,
        anchor_checkpoint=None,
        raw_sha256={},
        reasons=[reason],
        journal_verified=False,
        qualified_safety_count=None,
        **safety.FLAGS,
    )


def _witness(
    contract_raw, arguments, base, plan_raw, expected_plan_sha256, anchors_raw
):
    if plan_raw is None:
        return _unknown()
    try:
        safety._hex(expected_plan_sha256)
        safety._need(_sha(plan_raw) == expected_plan_sha256, "witness plan pin differs")
        plan = safety._wire(plan_raw, 32768)
        safety._fields(
            plan, "schema_version contract_sha256 source_plan_sha256 anchor_checkpoint"
        )
        safety._need(
            plan["schema_version"] == "edge-source-witness-plan/v1"
            and plan["contract_sha256"] == _sha(contract_raw),
            "witness contract binding",
        )
        sp_raw = arguments["source_plan_raw"]
        safety._need(
            plan["source_plan_sha256"]
            == arguments["expected_source_plan_sha256"]
            == _sha(sp_raw),
            "witness Source plan binding",
        )
        # The base was computed internally from raw inputs, never caller flags.
        safety._need(
            base["source_authentication"]["authenticated_prefix"] is True,
            "Source prefix not authenticated/bound to contract",
        )
        sp = safety._wire(sp_raw, 32768)
        result = verify_witnessed_source_prefix(
            arguments["trust_raw"],
            arguments["source_raw"],
            anchors_raw,
            expected_trust_sha256=sp["trust_sha256"],
            expected_context=sp["context"],
            expected_source_checkpoint=sp["prefix_checkpoint"],
            expected_anchor_checkpoint=plan["anchor_checkpoint"],
        )
        result["raw_sha256"]["witness_plan"] = expected_plan_sha256
        return result
    except (ValueError, OSError, TypeError, KeyError, OverflowError, RecursionError):
        return _unknown("invalid_witness_proof")


def evaluate_witnessed_safety_proofs(
    contract_raw,
    observations_raw,
    *,
    proof_arguments,
    witness_plan_raw=None,
    expected_witness_plan_sha256=None,
    anchors_raw=None,
):
    """Pure nested result: existing diagnostics/positive facts remain byte-equivalent."""
    base = proofs.evaluate_safety_proofs(
        contract_raw, observations_raw, **proof_arguments
    )
    return dict(
        schema_version="edge-witnessed-safety-proof-diagnostic/v1",
        base_evaluation=base,
        source_witness=_witness(
            contract_raw,
            proof_arguments,
            base,
            witness_plan_raw,
            expected_witness_plan_sha256,
            anchors_raw,
        ),
        qualified_safety_count=None,
        authority_flags=dict(safety.FLAGS),
        **safety.FLAGS,
    )


def collect_witnessed_safety_proofs(
    enrollment_path,
    supplement_path,
    witness_supplement_path,
    *,
    expected_enrollment_sha256,
    expected_checkpoint_sha256,
    expected_supplement_sha256,
    expected_witness_supplement_sha256,
):
    """Separate registered nonroot reader; no witness requests or private-key reads."""
    held = collection._HeldFiles()
    result, failure = None, None
    try:
        base = proofs.collect_safety_proofs(
            enrollment_path,
            supplement_path,
            expected_enrollment_sha256=expected_enrollment_sha256,
            expected_checkpoint_sha256=expected_checkpoint_sha256,
            expected_supplement_sha256=expected_supplement_sha256,
        )
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        safety._need(
            uid == base["provenance"]["observer_uid"]
            and boot == base["provenance"]["kernel_boot_id"],
            "base reader changed",
        )
        seen = set()

        def read(path, limit):
            path = collection._physical_path(path)[0]
            safety._need(path not in seen, "witness intake paths must be distinct")
            seen.add(path)
            return held.read(path, limit)

        en_raw = read(enrollment_path, 32768)
        safety._need(
            _sha(en_raw) == expected_enrollment_sha256, "base enrollment changed"
        )
        en = safety._wire(en_raw, 32768)
        raw = read(supplement_path, 32768)
        safety._need(
            _sha(raw) == expected_supplement_sha256, "Source supplement changed"
        )
        old = safety._wire(raw, 32768)
        # Keep all old artifacts pinned through the witness leg's final fences.
        old_raw = {}
        for name, limit in dict(
            contract=128 * 1024, observations=2 * 1024 * 1024, checkpoint=32768
        ).items():
            old_raw[name] = read(en["paths"][name], limit)
            expected = (
                base["provenance"][name + "_sha256"]
                if name != "observations"
                else base["provenance"]["observations_sha256"]
            )
            safety._need(_sha(old_raw[name]) == expected, "base bytes changed")
        extra = {}
        for name, limit in proofs.FILES.items():
            path, digest = old["paths"][name], old["sha256"][name]
            if path is None:
                safety._need(digest is None, "old missing artifact binding")
                extra[name] = None
            else:
                extra[name] = read(path, limit)
                safety._need(_sha(extra[name]) == digest, "Source artifact changed")
        ws_raw = read(witness_supplement_path, 32768)
        safety._hex(expected_witness_supplement_sha256)
        safety._need(
            _sha(ws_raw) == expected_witness_supplement_sha256,
            "witness supplement pin differs",
        )
        ws = safety._wire(ws_raw, 32768)
        safety._fields(
            ws,
            "schema_version enrollment_sha256 supplement_sha256 plan_path plan_sha256 anchors_path anchors_sha256",
        )
        safety._need(
            ws["schema_version"] == "edge-source-witness-enrollment/v1"
            and ws["enrollment_sha256"] == expected_enrollment_sha256
            and ws["supplement_sha256"] == expected_supplement_sha256,
            "witness enrollment binding",
        )
        incoming = {}
        for name, limit in (("plan", 32768), ("anchors", 8 * 1024 * 1024)):
            path, digest = ws[name + "_path"], ws[name + "_sha256"]
            if path is None:
                safety._need(digest is None, "missing witness bytes with hash")
                incoming[name] = None
            else:
                safety._hex(digest)
                incoming[name] = read(path, limit)
                safety._need(_sha(incoming[name]) == digest, "witness bytes differ")
        held.verify()
        args = dict(
            source_plan_raw=extra["source_plan"],
            expected_source_plan_sha256=old["sha256"]["source_plan"],
            trust_raw=extra["trust"],
            source_raw=extra["source"],
        )
        witness = _witness(
            old_raw["contract"],
            args,
            base["evaluation"],
            incoming["plan"],
            ws["plan_sha256"],
            incoming["anchors"],
        )
        safety._need(
            uid == os.geteuid() and boot == collection._kernel_boot_id(),
            "witness reader changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-witnessed-safety-proof-collection/v1",
            base_collection=base,
            source_witness=witness,
            witness_supplement_sha256=expected_witness_supplement_sha256,
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
            "sealed witness intake failed"
            + (f": {failure}" if failure else "")
            + ("; independent FD close failed" if close_errors else "")
        ) from failure
    return result
