"""Local structural gate for unchanged actual reader outputs, not authentication.

The caller must retain the original read_assignment_artifacts outputs and supply
Root's independently frozen/verified core SHA. Caller-authored JSON/flags cannot
become authenticated evidence through this function. No calculation/score, new
measurement qualification, execution, admission or resume authority is emitted.
"""

import re
import uuid

import signed_network_plan as plan
from signed_network_service import native_session_reference
from signed_network_recording import canonical
from azazel_edge.benchmark.benefit import (
    BenefitInputError,
    manifest_digest,
    validate_manifest,
)
from azazel_edge.benchmark.measurement import _bounded, _ref
from azazel_edge.outcome.journal import _ref as journal_ref

ORIGIN_FIELDS = {
    "assignment_id",
    "kernel_boot_id",
    "session_ref",
    "scope_ref",
    "registration_sha256",
    "producer_public_key",
    "witness_public_key",
}


def _hex(value, size):
    plan.need(
        type(value) is str
        and re.fullmatch("[0-9a-f]{" + str(size) + "}", value) is not None,
        "exact lowercase hex identity required",
    )
    return value


def _validate_fresh_records(manifest, read_results, *, core_sha256, telemetry=False):
    """Return the SAME measurement records in frozen execution order, or refuse.

    This checks local completeness, consistency and freshness only. It neither
    authenticates imported JSON nor calls measure_experiment. Its existing gates
    remain mandatory after this function, including baseline full signed chain.
    """
    try:
        _bounded([manifest, read_results])
        _hex(core_sha256, 64)
        assignments = validate_manifest(manifest)
        if telemetry:
            plan.validate_telemetry_manifest(manifest, core_sha256)
            pins = manifest["measurement_binding"]["telemetry_lab"]
            expected, _ = plan.planned_telemetry(
                manifest["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"],
                core_sha256,
                abi_sha256=pins["abi_sha256"],
                interpreter_sha256=pins["interpreter_sha256"],
                source_archive_sha256=pins["source_archive_sha256"],
            )
        else:
            plan.validate_manifest(manifest, core_sha256)
            expected, _ = plan.planned(
                manifest["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"],
                core_sha256,
            )
        plan.need(
            canonical(manifest) == canonical(expected), "canonical frozen plan differs"
        )
        plan.need(
            type(read_results) is list and len(read_results) == len(assignments) == 4,
            "exact four complete reader results required",
        )
        records, unique = (
            {},
            {
                key: set()
                for key in (
                    "kernel_boot_id",
                    "scope_ref",
                    "session_ref",
                    "registration_sha256",
                    "run_id",
                    "keys",
                )
            },
        )
        for result in read_results:
            plan.need(
                type(result) is dict
                and result["status"] == "calculation_available"
                and result["reasons"] == []
                and result["measurement_record"] is not None,
                "reader result is unavailable",
            )
            origin, record = (
                result["authenticated_origin"],
                result["measurement_record"],
            )
            plan.need(
                type(origin) is dict
                and set(origin) == ORIGIN_FIELDS
                and type(record) is dict
                and set(record)
                == {"assignment_id", "capture", "edge_recording", "linkage"},
                "closed origin/measurement shape required",
            )
            identity = origin["assignment_id"]
            capture, linkage = record["capture"], record["linkage"]
            plan.need(
                type(identity) is str
                and identity in assignments
                and identity not in records
                and type(record["assignment_id"]) is str
                and type(capture["assignment_id"]) is str
                and identity == record["assignment_id"] == capture["assignment_id"],
                "assignment conflict/duplicate",
            )
            boot = origin["kernel_boot_id"]
            plan.need(
                type(boot) is str and str(uuid.UUID(boot)) == boot,
                "canonical raw boot UUID required",
            )
            journal_ref(origin["scope_ref"])
            _hex(origin["session_ref"], 32)
            _hex(origin["registration_sha256"], 64)
            run = _ref(capture["run_id"])
            plan.need(
                capture["boot_id"] == plan.n.boot_reference(boot)
                and capture["manifest_sha256"] == manifest_digest(manifest)
                and linkage["session_ref"]
                == native_session_reference(origin["session_ref"])
                and linkage["capture_sha256"] == manifest_digest(capture)
                and (
                    "edge_boot_id" not in linkage
                    or linkage["edge_boot_id"] == plan.n.boot_reference(boot)
                )
                and canonical([capture["scenario"], capture["seed"]])
                == canonical(
                    [assignments[identity]["scenario"], assignments[identity]["seed"]]
                ),
                "capture/origin cross-binding conflict",
            )
            for key in (
                "kernel_boot_id",
                "scope_ref",
                "session_ref",
                "registration_sha256",
                "run_id",
            ):
                value = run if key == "run_id" else origin[key]
                plan.need(value not in unique[key], "fresh identity reused: " + key)
                unique[key].add(value)
            for key in ("producer_public_key", "witness_public_key"):
                value = _hex(origin[key], 64)
                plan.need(
                    value not in unique["keys"], "producer/witness public key reused"
                )
                unique["keys"].add(value)
            records[identity] = record
        plan.need(set(records) == set(assignments), "four-assignment coverage gap")
        return [records[assignment["id"]] for assignment in plan.order(manifest)]
    except (KeyError, TypeError, ValueError, AttributeError, OSError) as exc:
        raise BenefitInputError("invalid/partial four-run structural input") from exc


def validate_fresh_records(manifest, read_results, *, core_sha256):
    """Closed legacy v1 completeness/freshness gate, never runtime authority."""
    return _validate_fresh_records(manifest, read_results, core_sha256=core_sha256)
