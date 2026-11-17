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
    return analysis, expected


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
            analysis, expected = _evaluate(directory, arm, child["expected_header"])
            entry["expected"] = expected
            completion = child["completion"]
            if completion is not None and canonical(completion.get("expected")) != canonical(expected):
                blockers.append(arm["id"] + ":completion_pins_differ_from_closed_originals")
            if completion is not None and completion.get("collection_errors"):
                blockers.append(arm["id"] + ":original_collection_errors")
            entry["summary"] = dict(**legacy_timer_summary(analysis.get("original_result")),
                normal_return_confirmed=analysis.get("normal_return_confirmed", False),
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
            entry["artifacts"][suffix] = _artifact(directory, name)
            names.add(arm["id"] + "/" + name)
        arms.append(entry)
    report = dict(schema_version="edge-notification-lean-study-result/v1", arms=arms, blockers=blockers,
        study_protocol_sha256=PROTOCOL_SHA256, original_source_load_gates="unchanged_separate_not_notification_denominator",
        historical_cause="UNKNOWN", performance_acceptance=False, data_kind="PROSPECTIVE_DESCRIPTIVE_NO_CAUSAL_PROFILER_COST", **FLAGS)
    save(output / "report.json", canonical(report))
    save(output / "manifest.json", canonical(dict(schema_version="edge-notification-lean-public-inventory/v1",
        source=source, study_protocol_sha256=PROTOCOL_SHA256, metadata=base,
        files={name: _artifact(output, name) for name in sorted(names)}, **FLAGS)))
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
