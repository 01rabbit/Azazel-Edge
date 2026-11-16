"""Current-boot Root-sealed composition intake; archived replay remains pure."""

import hashlib
import os

from . import safety_collection as collection
from . import safety_evidence_composition as composition
from . import safety_observations as safety
from .advisory_exec import _object as observation_object
from .forged_input_refusal import _object as forged_object
from azazel_edge.outcome.input_auth import TrustPolicy


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _reader_roles(kind, artifacts, uid, boot):
    """Apply the original collectors' reader separation, without inferring roles."""
    forged = kind in ("forged_refusal_v1", "forged_refusal_v2")
    parse = forged_object if forged else observation_object
    plan = parse(artifacts["plan"], composition.BOUNDS["plan"])
    collection._require(plan["kernel_boot_id"] == boot, "supplement boot differs")
    if forged:
        trust = TrustPolicy(
            forged_object(artifacts["trust"], composition.BOUNDS["trust"])
        )
        actors = (trust.data["producer_uid"], trust.data["observer_uid"])
    else:
        actors = (plan["actor"]["uid"],)
        if kind in (
            "postconnect_refusal",
            "postconnect_authorization",
            "natural_close_recv",
        ):
            actors += (plan["server"]["uid"],)
    collection._require(uid not in actors, "supplement reader role overlaps")


def collect_safety_evidence_composition(
    composition_enrollment_path,
    *,
    expected_composition_enrollment_sha256,
    expected_composition_plan_sha256,
):
    """Hold every original through unchanged main collection and pure composition.

    Unsafe or changed enrollment refuses this new collection. No failure is
    replaced by an absent measurement, and no prior result or file is modified.
    """
    held = collection._HeldFiles()
    result = failure = None
    try:
        safety._hex(expected_composition_enrollment_sha256)
        safety._hex(expected_composition_plan_sha256)
        uid, boot = os.geteuid(), collection._kernel_boot_id()
        collection._require(type(uid) is int and uid > 0, "nonroot reader required")
        seen = set()

        def read(path, maximum):
            path = collection._physical_path(path)[0]
            collection._require(path not in seen, "enrolled paths overlap")
            seen.add(path)
            return held.read(path, maximum)

        enrollment_raw = read(composition_enrollment_path, 128 * 1024)
        collection._require(
            _digest(enrollment_raw) == expected_composition_enrollment_sha256,
            "composition enrollment pin differs",
        )
        enrollment = safety._wire(enrollment_raw, 128 * 1024)
        safety._fields(
            enrollment,
            "schema_version reader_uid kernel_boot_id safety composition_plan_path supplements",
        )
        collection._require(
            enrollment["schema_version"]
            == "edge-safety-evidence-composition-enrollment/v1"
            and type(enrollment["reader_uid"]) is int
            and enrollment["reader_uid"] == uid
            and enrollment["kernel_boot_id"] == boot,
            "composition enrollment reader/boot/schema differs",
        )
        registered = enrollment["safety"]
        safety._fields(
            registered, "enrollment_path enrollment_sha256 checkpoint_sha256"
        )
        for name in ("enrollment_sha256", "checkpoint_sha256"):
            safety._hex(registered[name])
        main_enrollment_raw = read(registered["enrollment_path"], 32 * 1024)
        main_enrollment = safety._wire(main_enrollment_raw, 32 * 1024)
        safety._fields(
            main_enrollment, "schema_version contract_sha256 scope observer_uid paths"
        )
        safety._fields(main_enrollment["paths"], "contract observations checkpoint")
        main_raw = {
            name: read(main_enrollment["paths"][name], bound)
            for name, bound in (
                ("contract", 128 * 1024),
                ("observations", 2 * 1024 * 1024),
                ("checkpoint", 32 * 1024),
            )
        }
        # The original intake decides main admissibility before any supplement.
        base = collection.collect_registered_safety(
            registered["enrollment_path"],
            expected_enrollment_sha256=registered["enrollment_sha256"],
            expected_checkpoint_sha256=registered["checkpoint_sha256"],
        )
        held.verify()
        collection._require(
            _digest(main_enrollment_raw) == registered["enrollment_sha256"]
            and _digest(main_raw["checkpoint"]) == registered["checkpoint_sha256"]
            and _digest(main_raw["contract"]) == main_enrollment["contract_sha256"],
            "held main registration differs",
        )
        contract = safety._wire(main_raw["contract"], 128 * 1024)
        keys = collection._registration(main_enrollment, contract, uid)
        heads = collection._checkpoint(
            safety._wire(main_raw["checkpoint"], 32 * 1024),
            main_enrollment,
            contract,
        )
        plan_raw = read(enrollment["composition_plan_path"], 128 * 1024)
        plan = composition._plan(
            plan_raw,
            expected_composition_plan_sha256,
            main_enrollment["contract_sha256"],
        )
        paths = enrollment["supplements"]
        safety._fields(paths, " ".join(entry["id"] for entry in plan["entries"]))
        supplements = {}
        total = 0
        for entry in plan["entries"]:
            identifier, kind = entry["id"], entry["kind"]
            slots = paths[identifier]
            safety._fields(slots, " ".join(composition.SLOTS[kind]))
            artifacts = {}
            for slot in composition.SLOTS[kind]:
                path, pin = slots[slot], entry["sha256"][slot]
                collection._require(
                    (slot == "evaluation" and path is None)
                    or (path is None) == (pin is None),
                    "missing artifact path/pin differs",
                )
                raw = None if path is None else read(path, composition.BOUNDS[slot])
                if raw is not None:
                    total += len(raw)
                    collection._require(
                        total <= composition.MAX_TOTAL_BYTES,
                        "supplement total byte bound",
                    )
                    collection._require(_digest(raw) == pin, "supplement pin differs")
                artifacts[slot] = raw
            _reader_roles(kind, artifacts, uid, boot)
            supplements[identifier] = artifacts
        held.verify()
        evaluation = composition.evaluate_safety_evidence_composition(
            main_raw["contract"],
            main_raw["observations"],
            safety_pins=dict(
                expected_contract_sha256=main_enrollment["contract_sha256"],
                expected_stream_heads=heads,
                **keys,
            ),
            composition_plan_raw=plan_raw,
            expected_composition_plan_sha256=expected_composition_plan_sha256,
            supplements=supplements,
        )
        collection._require(
            safety._same(evaluation["main_evaluation"], base["evaluation"]),
            "composed main differs from original collection",
        )
        collection._require(
            os.geteuid() == uid and collection._kernel_boot_id() == boot,
            "reader UID or boot changed",
        )
        held.verify()
        result = dict(
            schema_version="edge-safety-evidence-composition-collection/v1",
            base_collection=base,
            composition=evaluation,
            provenance=dict(
                composition_enrollment_sha256=expected_composition_enrollment_sha256,
                composition_plan_sha256=expected_composition_plan_sha256,
                reader_uid=uid,
                kernel_boot_id=boot,
            ),
            independently_measured=False,
            qualified_safety_count=None,
            **safety.FLAGS,
        )
    except BaseException as exc:
        failure = exc
    finally:
        errors = held.close()
    if failure is not None or errors:
        raise collection.SafetyCollectionError(
            "sealed composition collection failed"
            + (f": {type(failure).__name__}: {failure}" if failure else "")
            + ("; independent FD close failure: " + ",".join(errors) if errors else "")
        ) from failure
    return result
