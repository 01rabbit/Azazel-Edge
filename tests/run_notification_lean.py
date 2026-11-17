"""Three preregistered fresh-child diagnostic arms; never performance admission."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from azazel_edge.benchmark.notification_timing import analyze_notification_timing
from azazel_edge.notify.core_decisions import CORE_DECISION_SOURCE
from p0_handoff_attribution_lab import (
    ROOT, SUPPLEMENT, SUPPLEMENT_SHA256, collect_case, read_original, save, sha,
)
from p0_handoff_attribution_recording import canonical
from run_notification_timing import FLAGS, SOURCE_FILES, SUFFIXES, _artifact
from run_notification_timing_supplement import (
    bind_child_header, drain_child, legacy_timer_summary, parse_child_rows, require_authority,
)

PROTOCOL = ROOT / "tests/fixtures/notification-timing/lean-v1/protocol.json"
PROTOCOL_SHA256 = "5617214899eed681c435330cd456b149f214d01bc9b067be30724f6e23dfdcb8"
ARM_IDS = ("original", "v1", "deferred")
CHILD_SUFFIXES = ("child-stdout.raw", "child-stderr.raw", "child-process.json")
EXTRA_SOURCES = (
    "tests/run_notification_timing_supplement.py", "tests/run_notification_lean.py",
    "tests/p0_handoff_lean_recording.py", "tests/test_notification_lean_linux.py",
    "py/azazel_edge/benchmark/notification_lean.py",
)


def load_protocol():
    raw = read_original(PROTOCOL)
    if sha(raw) != PROTOCOL_SHA256 or sha(read_original(SUPPLEMENT)) != SUPPLEMENT_SHA256:
        raise ValueError("prospective study or underlying fixture protocol changed")
    result = json.loads(raw)
    if tuple(arm["id"] for arm in result["arms"]) != ARM_IDS:
        raise ValueError("frozen assignment order changed")
    return raw, result


def source_inventory():
    return dict(schema_version="edge-notification-lean-source-inventory/v1", files={
        name: dict(sha256=sha(read_original(ROOT / name)), bytes=(ROOT / name).stat().st_size)
        for name in (*SOURCE_FILES, *EXTRA_SOURCES)})


def _launch(output, arm, metadata):
    identifier = arm["fixture_case"]
    command = [sys.executable, str(Path(__file__).resolve()), "--child", arm["id"],
        "--output", str(output), "--metadata", json.dumps(metadata, sort_keys=True, separators=(",", ":"))]
    environment = dict(os.environ, EDGE_NOTIFICATION_SUPPLEMENT_CHILD=identifier)
    begin = time.monotonic_ns()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    retained, streams, timed_out, capture_error = drain_child(process)
    end = time.monotonic_ns()
    for name, raw in retained.items():
        save(output / (identifier + ".child-" + name + ".raw"), raw)
    rows, decode_error = [], None
    try:
        rows = parse_child_rows(retained["stdout"])
    except (ValueError, UnicodeError, RecursionError) as exc:
        decode_error = type(exc).__name__
        rows = getattr(exc, "valid_prefix_rows", [])
    bootstrap = next((row for row in rows if row.get("kind") == "bootstrap"), None)
    completion = next((row for row in rows if row.get("kind") == "completion"), None)
    try:
        header, errors = bind_child_header(process.pid, identifier, metadata, bootstrap, completion)
    except Exception as exc:
        header, errors = None, ["malformed_child_binding:" + type(exc).__name__]
    for name, reply in (("bootstrap", bootstrap), ("completion", completion)):
        if (type(reply) is not dict or reply.get("arm") != arm["id"]
                or reply.get("profile") != arm["profile"] or reply.get("study_protocol_sha256") != PROTOCOL_SHA256):
            errors.append(name + "_study_arm_profile_binding_unavailable_or_mismatch")
    result = dict(schema_version="edge-notification-lean-child/v1", arm=arm, pid=process.pid,
        started_ns=begin, exit_observed_ns=end, returncode=process.returncode,
        timed_out=timed_out, capture_error=capture_error, streams=streams,
        stdout_decode_error=decode_error, expected_header=header, binding_errors=errors,
        bootstrap=bootstrap, completion=completion, command=command,
        authority="inherited_same_UID_caps0_NNP_offline_no_additions")
    save(output / (identifier + ".child-process.json"), canonical(result))
    return result


def _evaluate(output, arm, expected):
    identifier = arm["fixture_case"]
    raw = {}
    for suffix in SUFFIXES[:-1]:
        try:
            raw[suffix] = read_original(output / (identifier + "." + suffix))
        except (OSError, ValueError):
            raw[suffix] = None
    if expected is not None:
        expected = dict(header=expected,
            event_index_sha256=sha(raw["event-index.json"]) if raw["event-index.json"] is not None else None,
            original_result_sha256=sha(raw["original-result.json"]) if raw["original-result.json"] is not None else None)
    if arm["profile"] == "edge-notification-lean/v1":
        from azazel_edge.benchmark.notification_lean import analyze_notification_lean
        analysis = analyze_notification_lean(raw["trace.jsonl"], expected=expected,
            event_index_raw=raw["event-index.json"], original_result_raw=raw["original-result.json"],
            study_protocol_sha256=PROTOCOL_SHA256)
    else:
        analysis = analyze_notification_timing(raw["trace.jsonl"], expected=expected,
            event_index_raw=raw["event-index.json"], original_result_raw=raw["original-result.json"])
    save(output / (identifier + ".analysis.json"), canonical(analysis))
    original = analysis.get("original_result")
    reasons = []
    for name in ("audit", "queue"):
        embedded = original.get(name + "_raw") if type(original) is dict else None
        if type(embedded) is not str or raw[name + ".raw"] != embedded.encode():
            reasons.append(name + "_export_missing_or_differs_from_embedded_original")
    exported = dict(match=not reasons, reasons=reasons)
    return analysis, expected, exported, _original_acceptance(analysis, arm, raw["event-index.json"])


def _original_acceptance(analysis, arm, index_raw):
    """A footer cannot substitute for validated original opportunity/accounting."""
    reasons = []
    original = analysis.get("original_result")
    if type(original) is not dict or analysis.get("event_index_valid") is not True:
        return dict(valid=False, reasons=["original_or_index_unverified"])
    try:
        events = json.loads(index_raw)["events"]
        if len(events) != 120 or {row["index"] for row in events} != set(range(120)):
            reasons.append("original_event_opportunities_incomplete")
        if original["case_id"] != arm["fixture_case"] or any(
            type(original.get(key)) is not int or original[key] != 120
            for key in ("assigned_events", "completed_submissions")
        ):
            reasons.append("original_assignments_incomplete")
        metrics = original["metrics"]
        names = ("core_recorded_total", "core_record_handoff_dropped_total", "core_record_failed_total")
        if (type(metrics) is not dict or any(type(metrics.get(key)) is not int or metrics[key] < 0 for key in names)
                or metrics[names[0]] + metrics[names[1]] != 120 or metrics[names[2]] != 0):
            reasons.append("original_accounting_invalid")
        structural = analysis["original_structural_counts"]
        if structural["audit_raw"]["chain"].get("ok") is not True:
            reasons.append("original_audit_chain_invalid")
        rows = [row for row in structural["audit_raw"]["original_rows"] if row.get("source") == CORE_DECISION_SOURCE]
        keys = {row["core_event_key"]: row["trace_id"] for row in events}
        if (len(rows) != metrics[names[0]] or len({row.get("core_event_key") for row in rows}) != len(rows)
                or any(keys.get(row.get("core_event_key")) != row.get("trace_id") for row in rows)):
            reasons.append("original_audit_event_identity_or_count_invalid")
        if metrics[names[1]] and not any(row.get("event") == "core_record_loss"
                and type(row.get("core_record_handoff_dropped_total")) is int
                and row["core_record_handoff_dropped_total"] == metrics[names[1]]
                for row in structural["queue_raw"]["original_rows"]):
            reasons.append("original_drop_evidence_missing")
        if original["collection_errors"]:
            reasons.append("original_collection_errors")
        control = original["control"]
        if not all(control.get(key) is True for key in ("producers_joined", "recorder_joined", "relay_joined", "callbacks_quiescent")):
            reasons.append("original_quiescence_unconfirmed")
        if legacy_timer_summary(original)["original_timer_observations_complete"] is not True:
            reasons.append("original_timer_opportunities_incomplete")
        if arm["profile"] != "none" and (
            analysis.get("status") != "complete_descriptive_trace"
            or analysis.get("normal_return_confirmed") is not True or analysis.get("reasons")
        ):
            reasons.append("profile_trace_not_complete_descriptive")
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError):
        reasons.append("original_validation_fields_unavailable_or_invalid")
    return dict(valid=not reasons, reasons=reasons)


def _safe_artifact(output, name, errors):
    try:
        return _artifact(output, name)
    except (OSError, ValueError) as exc:
        errors.append(name + ":artifact_unreadable_or_unsafe:" + type(exc).__name__)
        return None


def run(output_dir):
    output = Path(output_dir)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    boundary = require_authority()
    protocol_raw, protocol = load_protocol()
    source = {name: os.environ.get("EDGE_NOTIFICATION_SOURCE_" + name.upper()) for name in ("head", "tree")}
    if not all(type(value) is str and re.fullmatch("[0-9a-f]{40}", value) for value in source.values()):
        raise ValueError("independently enrolled source commit/tree required")
    inventory_raw = canonical(source_inventory())
    base = dict(run_id="notification-lean-" + uuid.uuid4().hex, protocol_sha256=SUPPLEMENT_SHA256,
        source_inventory_sha256=sha(inventory_raw),
        fixture_sha256=sha(read_original(ROOT / "tests/fixtures/rust_core_event_v1.json")),
        interpreter_sha256=sha(Path(sys.executable).resolve().read_bytes()))
    save(output / "protocol.json", protocol_raw)
    save(output / "source-inventory.json", inventory_raw)
    save(output / "process-boundary.json", canonical(boundary))
    arms, blockers, names = [], [], {"protocol.json", "source-inventory.json", "process-boundary.json", "report.json"}
    halted = False
    for arm in protocol["arms"]:
        identifier = arm["fixture_case"]
        directory = output / arm["id"]
        directory.mkdir(mode=0o700)
        save(directory / "source-inventory.json", inventory_raw)
        names.add(arm["id"] + "/source-inventory.json")
        entry = dict(arm=arm, child=None, expected=None, summary=None, artifacts={})
        try:
            if halted:
                raise RuntimeError("not_run_prior_unfinished_child_work")
            child = _launch(directory, arm, dict(base, case_id=identifier))
            entry["child"] = child
            if child["returncode"] != 0 or child["timed_out"] or child["capture_error"] or child["stdout_decode_error"] or child["binding_errors"]:
                blockers.append(arm["id"] + ":child_incomplete_or_unverified")
            # A missing completion does not justify later workloads or a normal END.
            halted = child["completion"] is None or child["completion"].get("safe_to_continue") is not True
            analysis, expected, exported, validation = _evaluate(directory, arm, child["expected_header"])
            entry["expected"] = expected
            entry["exported_original_files"] = exported
            entry["original_validation"] = validation
            blockers.extend(arm["id"] + ":" + reason for reason in exported["reasons"])
            blockers.extend(arm["id"] + ":" + reason for reason in validation["reasons"])
            completion = child["completion"]
            if completion is not None and canonical(completion.get("expected")) != canonical(expected):
                blockers.append(arm["id"] + ":completion_pins_differ_from_closed_originals")
            if completion is not None and completion.get("collection_errors"):
                blockers.append(arm["id"] + ":original_collection_errors")
            entry["summary"] = dict(**legacy_timer_summary(analysis.get("original_result")),
                normal_return_confirmed=analysis.get("normal_return_confirmed", False) and exported["match"] and validation["valid"],
                event_index_valid=analysis.get("event_index_valid", False), reasons=analysis.get("reasons", []),
                completed_spans=len(analysis.get("completed_spans", [])), performance_acceptance=False, **FLAGS)
            if arm["profile"] != "none" and not analysis.get("normal_return_confirmed"):
                blockers.append(arm["id"] + ":trace_not_normally_complete")
        except Exception as exc:
            entry["error"] = type(exc).__name__
            blockers.append(arm["id"] + ":" + type(exc).__name__)
            halted = True
        for suffix in (*SUFFIXES, *CHILD_SUFFIXES):
            name = identifier + "." + suffix
            errors = []
            entry["artifacts"][suffix] = _safe_artifact(directory, name, errors)
            blockers.extend(arm["id"] + ":" + error for error in errors)
            names.add(arm["id"] + "/" + name)
        arms.append(entry)
    files, inventory_errors = {}, []
    for name in sorted(names - {"report.json"}):
        files[name] = _safe_artifact(output, name, inventory_errors)
    for entry in arms:
        for suffix, descriptor in entry["artifacts"].items():
            name = entry["arm"]["id"] + "/" + entry["arm"]["fixture_case"] + "." + suffix
            if canonical(files[name]) != canonical(descriptor):
                inventory_errors.append(name + ":artifact_changed_between_closed_reads")
    blockers.extend(inventory_errors)
    report = dict(schema_version="edge-notification-lean-study-result/v1", arms=arms, blockers=blockers,
        study_protocol_sha256=PROTOCOL_SHA256, original_source_load_gates="unchanged_separate_not_notification_denominator",
        historical_cause="UNKNOWN", performance_acceptance=False, data_kind="PROSPECTIVE_DESCRIPTIVE_NO_CAUSAL_PROFILER_COST", **FLAGS)
    save(output / "report.json", canonical(report))
    files["report.json"] = _safe_artifact(output, "report.json", inventory_errors)
    save(output / "manifest.json", canonical(dict(schema_version="edge-notification-lean-public-inventory/v1",
        source=source, study_protocol_sha256=PROTOCOL_SHA256, metadata=base,
        files=files, inventory_errors=inventory_errors, **FLAGS)))
    return report


def child(output, arm_id, metadata):
    boundary = require_authority()
    _, protocol = load_protocol()
    arm = next(value for value in protocol["arms"] if value["id"] == arm_id)
    recipe = next(value for value in json.loads(read_original(SUPPLEMENT))["cases"] if value["id"] == arm["fixture_case"])
    if metadata.get("case_id") != recipe["id"] or metadata.get("protocol_sha256") != SUPPLEMENT_SHA256:
        raise ValueError("child fixture metadata mismatch")
    if sha(read_original(output / "source-inventory.json")) != metadata.get("source_inventory_sha256"):
        raise ValueError("child inventory differs from external parent pin")
    envelope = dict(arm=arm_id, profile=arm["profile"], study_protocol_sha256=PROTOCOL_SHA256)
    print(canonical(dict(kind="bootstrap", boundary=boundary, **envelope)).decode(), end="", flush=True)
    if arm["profile"] == "edge-notification-lean/v1":
        from p0_handoff_lean_recording import LeanRecording
        result = collect_case(output, recipe, metadata, recording_factory=LeanRecording)
    else:
        result = collect_case(output, recipe, metadata)
    print(canonical(dict(kind="completion", expected=result["expected"], safe_to_continue=result["safe_to_continue"],
        collection_errors=result["original"]["collection_errors"], **envelope)).decode(), end="", flush=True)
    return int(bool(result["original"]["collection_errors"]) or result["safe_to_continue"] is not True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--child", choices=ARM_IDS)
    parser.add_argument("--metadata")
    args = parser.parse_args()
    if args.child:
        return child(args.output, args.child, json.loads(args.metadata))
    run(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
