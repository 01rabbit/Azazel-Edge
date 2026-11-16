"""Bounded notification software diagnostics; historical cause always UNKNOWN."""

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
    PROTOCOL, ROOT, collect_case, has_retained_unfinished_resources, read_original, save, sha,
)
from p0_handoff_attribution_recording import canonical, process_identity

FLAGS = dict(comparison_qualified=False, whole_measurement_qualified=False,
             production_admission=False, resume_authorized=False, qualified_safety_count=None)
SOURCE_FILES = (
    "tests/p0_handoff_attribution_lab.py", "tests/p0_handoff_attribution_recording.py",
    "tests/run_notification_timing.py", "tests/test_notification_timing_linux.py",
    "tests/test_agent_core_p0_path_v1.py", "py/azazel_edge/notify/core_decisions.py",
    "py/azazel_edge/notify/p0_alert.py", "py/azazel_edge/audit/logger.py",
    "py/azazel_edge/benchmark/notification_timing.py",
)
SUFFIXES = ("original-result.json", "event-index.json", "trace.jsonl", "audit.raw", "queue.raw", "analysis.json")


def process_boundary():
    values = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    return dict(uid=os.geteuid(), gid=os.getegid(), groups=os.getgroups(),
                capabilities={name: values[name].strip() for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
                no_new_privileges=int(values["NoNewPrivs"].strip()), identity=process_identity(),
                evidence_kind="ACTUAL_LINUX_PROCESS_BOUNDARY_NOT_NOTIFICATION_PERFORMANCE")


def source_inventory():
    return dict(schema_version="edge-notification-source-inventory/v1",
                files={name: dict(sha256=sha(read_original(ROOT / name)), bytes=(ROOT / name).stat().st_size)
                       for name in SOURCE_FILES})


def _artifact(output, name):
    path = output / name
    if not path.exists():
        return None
    raw = read_original(path)
    return dict(path=name, sha256=sha(raw), bytes=len(raw))


def scheduler_control_summary(analysis):
    """Derive only from qualified read-only replay, never mutate originals."""
    values = [span.get("scheduler", {}).get("qualified_runqueue_wait_ns")
              for span in analysis.get("completed_spans", []) if span.get("phase") == "scheduler_control"]
    qualified = [value for value in values if type(value) is int and value >= 0]
    if any(value > 0 for value in qualified):
        status = "observed_positive_identity_bound_counter"
    elif qualified and len(qualified) == len(values):
        status = "unexercised_zero_counter"
    else:
        status = "unmeasured_counter_unavailable"
    return dict(status=status, qualified_runqueue_wait_ns=qualified[0] if len(qualified) == 1 else None,
                scope="enclosing_counter_brackets_not_exclusive_operation_or_historical_cause")


def run(output_dir):
    output = Path(output_dir)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    protocol_raw = read_original(PROTOCOL)
    protocol = json.loads(protocol_raw)
    inventory = source_inventory()
    inventory_raw = canonical(inventory)
    run_id = "notification-" + uuid.uuid4().hex
    base_metadata = dict(run_id=run_id, protocol_sha256=sha(protocol_raw), source_inventory_sha256=sha(inventory_raw),
                         fixture_sha256=sha(read_original(ROOT / "tests/fixtures/rust_core_event_v1.json")),
                         interpreter_sha256=sha(Path(sys.executable).resolve().read_bytes()))
    save(output / "protocol.json", protocol_raw)
    save(output / "source-inventory.json", inventory_raw)
    save(output / "process-boundary.json", canonical(process_boundary()))
    # Git calls precede every measured scope; no source/default change.
    enrolled = {"head": os.environ.get("EDGE_NOTIFICATION_SOURCE_HEAD"), "tree": os.environ.get("EDGE_NOTIFICATION_SOURCE_TREE")}
    provenance = dict(source="externally_enrolled_environment" if any(enrolled.values()) else "readonly_git_checkout")
    for name, args in (("head", ["rev-parse", "HEAD"]), ("tree", ["rev-parse", "HEAD^{tree}"])):
        if any(enrolled.values()):
            provenance[name] = enrolled[name] if type(enrolled[name]) is str and re.fullmatch("[0-9a-f]{40}", enrolled[name]) else None
        else:
            try:
                provenance[name] = subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.DEVNULL, text=True).strip()
            except (OSError, subprocess.SubprocessError):
                provenance[name] = None
    cases, blockers = [], []
    if not all(type(provenance[name]) is str and re.fullmatch("[0-9a-f]{40}", provenance[name]) for name in ("head", "tree")):
        blockers.append("source_commit_or_tree_unavailable_or_invalid")
    halted = False
    for recipe in protocol["cases"]:
        identifier = recipe["id"]
        entry = dict(case_id=identifier, recipe=recipe, expected=None, collection_error=None, artifacts={})
        try:
            if halted:
                raise RuntimeError("not_run_prior_unfinished_workers")
            collected = collect_case(output, recipe, dict(base_metadata, case_id=identifier))
            halted = collected.get("safe_to_continue") is False
            entry["expected"] = collected["expected"]
            blockers.extend(identifier + ":" + name + ":" + reason
                            for name, reason in collected["original"]["collection_errors"].items())
        except Exception as exc:
            entry["collection_error"] = "not_run_prior_unfinished_workers" if halted else type(exc).__name__
            blockers.append(identifier + ":collection_failed:" + type(exc).__name__)
        finally:
            # A late EXCL write failure can prevent the case returning its state.
            halted = halted or has_retained_unfinished_resources()
        # Retain already closed originals/descriptors BEFORE entering pure analysis.
        raw = {}
        for suffix in SUFFIXES[:-1]:
            name = identifier + "." + suffix
            try:
                descriptor = _artifact(output, name)
                entry["artifacts"][suffix] = descriptor
                raw[suffix] = read_original(output / name) if descriptor is not None else None
            except (OSError, ValueError) as exc:
                entry["artifacts"][suffix] = None
                raw[suffix] = None
                blockers.append(name + ":original_read_failed:" + type(exc).__name__)
        try:
            analysis = analyze_notification_timing(raw["trace.jsonl"], expected=entry["expected"],
                        event_index_raw=raw["event-index.json"], original_result_raw=raw["original-result.json"])
        except Exception as exc:
            analysis = dict(schema_version="edge-notification-analysis-unavailable/v1", historical_cause="UNKNOWN",
                            status="unavailable", reasons=[type(exc).__name__], **FLAGS)
            blockers.append(identifier + ":analysis_failed:" + type(exc).__name__)
        save(output / (identifier + ".analysis.json"), canonical(analysis))
        entry["artifacts"]["analysis.json"] = _artifact(output, identifier + ".analysis.json")
        entry["analysis"] = dict(schema_version="edge-notification-case-summary/v1",
            historical_cause=analysis.get("historical_cause", "UNKNOWN"),
            status=analysis.get("status"), reasons=analysis.get("reasons", []),
            normal_return_confirmed=analysis.get("normal_return_confirmed", False),
            valid_prefix_rows=analysis.get("valid_prefix_rows", 0),
            completed_span_count=len(analysis.get("completed_spans", [])),
            event_index_valid=analysis.get("event_index_valid", False), **FLAGS)
        if identifier == "scheduler_contention":
            entry["analysis"]["scheduler_control"] = scheduler_control_summary(analysis)
        cases.append(entry)
    report = dict(schema_version="edge-notification-timing-lab/v1", run_id=run_id,
        evidence_kind="DIRECT_SUBMIT_SOFTWARE_DIAGNOSTIC_NOT_SOCKET_OR_CORE_INGRESS",
        historical_cause="UNKNOWN", historical_wall_failure=protocol["historical_wall_failure"],
        cases=cases, blockers=blockers, original_source_load_gates="separate_unchanged_not_concurrent_not_P0_denominator",
        unknown_scopes=["network_input_and_socket_receive", "Rust_core_ingress", "application_delivery",
            "unmeasured_handler_internal_locks", "inclusive_save_remainder", "recording_and_probe_overhead",
            "scheduler_cause_from_wall_minus_CPU", "shared_process_CPU_and_surviving_idle_original_dispatchers",
            "statistics_lock_held_remainder_after_prefix", "trace_footer_not_descriptor_close_or_durability_proof"], **FLAGS)
    save(output / "report.json", canonical(report))
    allowed = {"report.json", "manifest.json", "protocol.json", "source-inventory.json", "process-boundary.json"}
    allowed.update(recipe["id"] + "." + suffix for recipe in protocol["cases"] for suffix in SUFFIXES)
    # No traversal: every read is one flat, frozen public basename.
    manifest = dict(schema_version="edge-notification-public-inventory/v1", run_id=run_id,
        source=provenance, pins=base_metadata, created_monotonic_ns=time.monotonic_ns(),
        cases=[{key: entry[key] for key in ("case_id", "expected", "collection_error", "artifacts")} for entry in cases],
        files={name: _artifact(output, name) for name in sorted(allowed - {"manifest.json"})}, **FLAGS)
    save(output / "manifest.json", canonical(manifest))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps(dict(report=str(args.output / "report.json"), historical_cause=result["historical_cause"])))


if __name__ == "__main__":
    main()
