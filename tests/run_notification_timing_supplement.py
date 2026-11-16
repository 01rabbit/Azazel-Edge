"""Two separately frozen global-fsync cases in fresh ordinary-UID children."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time
import uuid

from azazel_edge.benchmark.notification_timing import analyze_notification_timing
from p0_handoff_attribution_lab import (
    ROOT, SUPPLEMENT, SUPPLEMENT_CASES, SUPPLEMENT_SHA256, collect_case, read_original, save, sha,
)
from p0_handoff_attribution_recording import canonical
from run_notification_timing import FLAGS, SOURCE_FILES, SUFFIXES, _artifact, process_boundary

EXTRA_SOURCES = ("tests/run_notification_timing_supplement.py", "tests/test_notification_timing_supplement_linux.py")
CHILD_SUFFIXES = ("child-stdout.raw", "child-stderr.raw", "child-process.json")
PARENT_PINS = {"run_id", "case_id", "protocol_sha256", "source_inventory_sha256", "fixture_sha256", "interpreter_sha256"}


def drain_child(process, *, maximum=16 * 1024 * 1024, timeout=30):
    """Drain both streams concurrently, retaining bounded prefixes only."""
    retained = {name: bytearray() for name in ("stdout", "stderr")}
    observed = dict(stdout=0, stderr=0)
    errors = dict(stdout=None, stderr=None)
    timed_out, capture_error = False, None
    deadline = time.monotonic() + timeout
    killed_at = None
    with selectors.DefaultSelector() as selector:
        try:
            for name in retained:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                now = time.monotonic()
                if now >= deadline and killed_at is None:
                    timed_out = True
                    if process.poll() is None:
                        process.kill()
                    killed_at = now
                if killed_at is not None and now - killed_at >= 5:
                    capture_error = "pipe_EOF_watchdog_after_termination"
                    break
                for key, _ in selector.select(timeout=0.1):
                    name = key.data
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        errors[name] = type(exc).__name__
                        chunk = b""
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    observed[name] += len(chunk)
                    room = maximum - len(retained[name])
                    if room > 0:
                        retained[name].extend(chunk[:room])
        except Exception as exc:
            capture_error = type(exc).__name__
        finally:
            for key in list(selector.get_map().values()):
                selector.unregister(key.fileobj)
                key.fileobj.close()
    if capture_error is not None and process.poll() is None:
        process.kill()
        killed_at = time.monotonic()
    try:
        process.wait(timeout=max(0.01, deadline - time.monotonic()) if killed_at is None else 5)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait(timeout=5)
    streams = {name: dict(bytes_observed=observed[name], bytes_retained=len(retained[name]),
        truncated=observed[name] > len(retained[name]), capture_error=errors[name], retained_sha256=sha(retained[name]))
        for name in retained}
    return {name: bytes(value) for name, value in retained.items()}, streams, timed_out, capture_error


def parse_child_rows(raw):
    """Parse at most four small records from the already bounded prefix."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate child reply field")
            result[key] = value
        return result

    rows, start = [], 0
    try:
        while start < len(raw):
            end = raw.find(b"\n", start)
            if end < 0 or end - start > 65536 or len(rows) >= 4:
                raise ValueError("child reply row/line capacity or partial line")
            row = json.loads(raw[start:end], object_pairs_hook=pairs)
            if type(row) is not dict or row.get("kind") not in ("bootstrap", "completion"):
                raise ValueError("unknown child reply record")
            if any(previous["kind"] == row["kind"] for previous in rows):
                rows = [previous for previous in rows if previous["kind"] != row["kind"]]
                raise ValueError("ambiguous child reply records")
            rows.append(row)
            start = end + 1
    except (ValueError, UnicodeError, RecursionError) as exc:
        exc.valid_prefix_rows = rows
        raise
    return rows


def legacy_timer_summary(original):
    intervals = original.get("control", {}).get("legacy_intervals") if type(original) is dict else None
    valid, counts = [], {}
    if type(intervals) is list:
        for row in intervals:
            if type(row) is not dict or type(row.get("index")) is not int or not 0 <= row["index"] < 120:
                continue
            index = row["index"]
            counts[index] = counts.get(index, 0) + 1
            values = [row.get(name) for name in ("start_monotonic_seconds", "end_monotonic_seconds", "elapsed_seconds")]
            if all(type(value) in (int, float) and math.isfinite(value) and value >= 0 for value in values):
                begin, end, elapsed = values
                if end >= begin and elapsed == end - begin:
                    valid.append((index, elapsed))
    values = [elapsed for index, elapsed in valid if counts[index] == 1]
    complete = (type(intervals) is list and len(intervals) == len(values) == 120
        and type(original.get("assigned_events")) is int and original["assigned_events"] == 120
        and type(original.get("completed_submissions")) is int and original["completed_submissions"] == 120)
    positive = sum(value > 0.050 for value in values) if values else None
    return dict(max_original_elapsed_seconds=max(values) if values else None,
        original_intervals_over_50ms=positive if complete else None,
        original_intervals_observed_count=len(values) if type(intervals) is list else None,
        original_intervals_positive_observed_lower_bound=positive,
        original_timer_observations_complete=complete)


def bind_child_header(pid, identifier, metadata, bootstrap, completion):
    errors = []
    boundary = bootstrap.get("boundary") if type(bootstrap) is dict else None
    identity = boundary.get("identity") if type(boundary) is dict else None
    if type(metadata) is not dict or set(metadata) != PARENT_PINS or metadata.get("case_id") != identifier:
        errors.append("parent_metadata_fields_or_case_mismatch")
    if (type(identity) is not dict or set(identity) != {"pid", "process_start_ticks", "boot_id", "clock_domain"}
            or type(pid) is not int or type(identity.get("pid")) is not int or identity["pid"] != pid):
        errors.append("bootstrap_identity_not_bound_to_external_Popen_pid")
    header = dict(metadata, **identity) if not errors else None
    if type(completion) is not dict:
        errors.append("completion_unavailable")
    elif (header is None or type(completion.get("expected")) is not dict
            or canonical(completion["expected"].get("header")) != canonical(header)):
        errors.append("completion_header_differs_from_parent_pins_and_bootstrap")
    return header, errors


def require_authority():
    boundary = process_boundary()
    if boundary["uid"] == 0 or boundary["no_new_privileges"] != 1 or any(int(value, 16) for value in boundary["capabilities"].values()):
        raise ValueError("ordinary UID, zero capabilities and NNP required")
    return boundary


def launch_child(output, recipe, metadata):
    identifier = recipe["id"]
    command = [sys.executable, str(Path(__file__).resolve()), "--child", identifier,
               "--output", str(output), "--metadata", json.dumps(metadata, sort_keys=True, separators=(",", ":"))]
    started = time.monotonic_ns()
    environment = dict(os.environ, EDGE_NOTIFICATION_SUPPLEMENT_CHILD=identifier)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment)
    retained, streams, timed_out, capture_error = drain_child(process)
    stdout, stderr = retained["stdout"], retained["stderr"]
    exited = time.monotonic_ns()
    for name, raw in (("stdout", stdout), ("stderr", stderr)):
        save(output / (identifier + ".child-" + name + ".raw"), raw)
    rows, decode_error = [], None
    try:
        rows = parse_child_rows(stdout)
    except (ValueError, UnicodeError, RecursionError) as exc:
        decode_error = type(exc).__name__
        rows = getattr(exc, "valid_prefix_rows", [])
    bootstrap = next((row for row in rows if type(row) is dict and row.get("kind") == "bootstrap"), None)
    completion = next((row for row in rows if type(row) is dict and row.get("kind") == "completion"), None)
    try:
        header, binding_errors = bind_child_header(process.pid, identifier, metadata, bootstrap, completion)
    except Exception as exc:
        header, binding_errors = None, ["malformed_child_binding:" + type(exc).__name__]
    result = dict(schema_version="edge-notification-supplement-child/v1", case_id=identifier,
        pid=process.pid, started_ns=started, exit_observed_ns=exited, returncode=process.returncode,
        timed_out=timed_out, streams=streams, capture_error=capture_error, stdout_decode_error=decode_error,
        expected_header=header, binding_errors=binding_errors,
        bootstrap=bootstrap, completion=completion, capture_profile="concurrent_bounded_prefix_pipe_drain_then_discard",
        command=command, authority="inherited_same_UID_capabilities_NNP_network_namespace_no_additions")
    save(output / (identifier + ".child-process.json"), canonical(result))
    return result


def _source_inventory():
    return dict(schema_version="edge-notification-supplement-source-inventory/v1", files={
        name: dict(sha256=sha(read_original(ROOT / name)), bytes=(ROOT / name).stat().st_size)
        for name in (*SOURCE_FILES, *EXTRA_SOURCES)})


def run(output_dir):
    output = Path(output_dir)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    boundary = require_authority()
    protocol_raw = read_original(SUPPLEMENT)
    if sha(protocol_raw) != SUPPLEMENT_SHA256:
        raise ValueError("supplement frozen protocol changed")
    protocol = json.loads(protocol_raw)
    if tuple(row["id"] for row in protocol["cases"]) != SUPPLEMENT_CASES:
        raise ValueError("supplement case order changed")
    source = dict(head=os.environ.get("EDGE_NOTIFICATION_SOURCE_HEAD"), tree=os.environ.get("EDGE_NOTIFICATION_SOURCE_TREE"),
                  origin="externally_enrolled_environment")
    if not all(type(source[name]) is str and re.fullmatch("[0-9a-f]{40}", source[name]) for name in ("head", "tree")):
        raise ValueError("independently enrolled source commit/tree required")
    inventory_raw = canonical(_source_inventory())
    run_id = "notification-supplement-" + uuid.uuid4().hex
    base = dict(run_id=run_id, protocol_sha256=SUPPLEMENT_SHA256, source_inventory_sha256=sha(inventory_raw),
                fixture_sha256=sha(read_original(ROOT / "tests/fixtures/rust_core_event_v1.json")),
                interpreter_sha256=sha(Path(sys.executable).resolve().read_bytes()))
    save(output / "protocol.json", protocol_raw)
    save(output / "source-inventory.json", inventory_raw)
    save(output / "process-boundary.json", canonical(boundary))
    cases, blockers = [], []
    for recipe in protocol["cases"]:
        identifier = recipe["id"]
        entry = dict(case_id=identifier, recipe=recipe, artifacts={}, expected=None, collection_error=None)
        try:
            child = launch_child(output, recipe, dict(base, case_id=identifier))
            entry["child"] = child
            complete = child.get("completion")
            if child["returncode"] != 0 or child["timed_out"] or complete is None:
                blockers.append(identifier + ":child_incomplete_or_failed")
            if any(value["truncated"] for value in child["streams"].values()):
                blockers.append(identifier + ":child_output_truncated")
            if child.get("capture_error") or any(value.get("capture_error") for value in child["streams"].values()):
                blockers.append(identifier + ":child_capture_failed")
            if child.get("stdout_decode_error") is not None:
                blockers.append(identifier + ":child_stdout_decode_failed")
            blockers.extend(identifier + ":" + error for error in child.get("binding_errors", []))
        except Exception as exc:
            entry["collection_error"] = type(exc).__name__
            blockers.append(identifier + ":child_collection_failed:" + type(exc).__name__)
        raw = {}
        for suffix in (*SUFFIXES[:-1], *CHILD_SUFFIXES):
            try:
                descriptor = _artifact(output, identifier + "." + suffix)
                entry["artifacts"][suffix] = descriptor
                raw[suffix] = read_original(output / (identifier + "." + suffix)) if descriptor is not None else None
            except (OSError, ValueError) as exc:
                entry["artifacts"][suffix] = None
                raw[suffix] = None
                blockers.append(identifier + ":original_read_failed:" + suffix + ":" + type(exc).__name__)
        child_header = entry.get("child", {}).get("expected_header")
        if child_header is not None:
            entry["expected"] = dict(header=child_header,
                event_index_sha256=sha(raw["event-index.json"]) if raw["event-index.json"] is not None else None,
                original_result_sha256=sha(raw["original-result.json"]) if raw["original-result.json"] is not None else None)
            complete = entry["child"].get("completion")
            if complete is not None and canonical(complete.get("expected")) != canonical(entry["expected"]):
                blockers.append(identifier + ":completion_pins_differ_from_closed_originals")
        try:
            analysis = analyze_notification_timing(raw["trace.jsonl"], expected=entry["expected"],
                event_index_raw=raw["event-index.json"], original_result_raw=raw["original-result.json"])
        except Exception as exc:
            analysis = dict(schema_version="edge-notification-analysis-unavailable/v1", status="unavailable",
                            historical_cause="UNKNOWN", reasons=[type(exc).__name__], **FLAGS)
            blockers.append(identifier + ":analysis_failed:" + type(exc).__name__)
        save(output / (identifier + ".analysis.json"), canonical(analysis))
        entry["artifacts"]["analysis.json"] = _artifact(output, identifier + ".analysis.json")
        original = analysis.get("original_result")
        entry["summary"] = dict(historical_cause="UNKNOWN", normal_return_confirmed=analysis.get("normal_return_confirmed", False),
            event_index_valid=analysis.get("event_index_valid", False), reasons=analysis.get("reasons", []),
            **legacy_timer_summary(original), performance_acceptance=False, **FLAGS)
        cases.append(entry)
    report = dict(schema_version="edge-notification-slow-fsync-lab/v1", run_id=run_id, cases=cases, blockers=blockers,
        historical_cause="UNKNOWN", base_protocol_sha256=protocol["base_protocol_sha256"],
        profile="separately_frozen_two_fresh_child_global_requested50ms_fsync_mock",
        logging_equivalence_to_historical_caplog="UNKNOWN_actual_child_profile_retained",
        base_pilot_reruns=0, performance_acceptance=False,
        original_source_load_gates="separate_unchanged_not_P0_denominator", **FLAGS)
    save(output / "report.json", canonical(report))
    names = {"report.json", "protocol.json", "source-inventory.json", "process-boundary.json"}
    names.update(identifier + "." + suffix for identifier in SUPPLEMENT_CASES for suffix in (*SUFFIXES, *CHILD_SUFFIXES))
    save(output / "manifest.json", canonical(dict(schema_version="edge-notification-supplement-public-inventory/v1",
        source=source, metadata=base, cases=[dict(case_id=entry["case_id"], expected=entry["expected"], artifacts=entry["artifacts"]) for entry in cases],
        files={name: _artifact(output, name) for name in sorted(names)}, **FLAGS)))
    return report


def child(output, identifier, metadata):
    boundary = require_authority()
    protocol = json.loads(read_original(SUPPLEMENT))
    recipe = next(row for row in protocol["cases"] if row["id"] == identifier)
    if metadata.get("case_id") != identifier or metadata.get("protocol_sha256") != SUPPLEMENT_SHA256:
        raise ValueError("child metadata not pinned to supplement")
    if sha(read_original(output / "source-inventory.json")) != metadata["source_inventory_sha256"]:
        raise ValueError("child source inventory changed")
    print(canonical(dict(kind="bootstrap", boundary=boundary)).decode(), end="", flush=True)
    result = collect_case(output, recipe, metadata)
    print(canonical(dict(kind="completion", expected=result["expected"], safe_to_continue=result["safe_to_continue"],
                         collection_errors=result["original"]["collection_errors"])).decode(), end="", flush=True)
    if result["original"]["collection_errors"] or not result["safe_to_continue"]:
        return 1
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--child", choices=SUPPLEMENT_CASES)
    parser.add_argument("--metadata")
    args = parser.parse_args()
    if args.child:
        return child(args.output, args.child, json.loads(args.metadata))
    run(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
