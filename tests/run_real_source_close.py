"""Fixed three-case original signed Source annex; no old assessment changes."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from capture_close_lab import read_closed, sha, wire
from real_source_close_lab import ARG_FILES, CASES, EXTRAS, PROTOCOL, PROTOCOL_SHA256, RAW_FILES, role_boundary
from run_capture_close import _drain, _reply

ROOT = Path(__file__).resolve().parents[1]
OUTER = ("child-stdout.raw", "child-stderr.raw", "child-process.json")
CASE_FILES = tuple(RAW_FILES.values()) + tuple(ARG_FILES.values()) + EXTRAS + OUTER + ("analysis.json", "source-inventory.json")
SOURCES = (
    "py/azazel_edge/benchmark/real_source_close.py", "py/azazel_edge/benchmark/real_source_close_collection.py",
    "py/azazel_edge/benchmark/source_authentication.py", "py/azazel_edge/benchmark/source_witness.py",
    "py/azazel_edge/outcome/input_auth.py", "py/azazel_edge/outcome/live_protocol.py",
    "py/azazel_edge/outcome/input_witness.py", "py/azazel_edge/outcome/input_cursor.py",
    "py/azazel_edge/outcome/input_resume.py", "py/azazel_edge/outcome/journal.py",
    "tests/real_source_close_lab.py", "tests/run_real_source_close.py", "tests/test_real_source_close_linux.py",
    "tests/fixtures/real-source-close/v1/protocol.json", "tests/test_outcome_input_auth_linux.py",
    "tests/test_source_witness_linux.py", "tests/source_witness_data.py", "tests/auth_input_helpers.py",
    "tests/capture_close_lab.py", "tests/run_capture_close.py", "tests/test_outcome_input_resume.py",
    "tests/test_outcome_telemetry_g3.py", "py/azazel_edge/outcome/telemetry.py",
    "py/azazel_edge/outcome/contracts.py", "py/azazel_edge/outcome/adapter.py",
)


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    try:
        os.fchmod(fd, 0o644)  # This freshly created PUBLIC copy only.
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def new_directory(path):
    """Fresh public directory, rooted traversal never follows a symlink."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute non-traversing output required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
        os.mkdir(path.name, mode=0o755, dir_fd=fd)
        child = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            os.fchmod(child, 0o755)
        finally:
            os.close(child)
    finally:
        os.close(fd)


def launch(directory, case, run_id, inventory_hash):
    argv = [sys.executable, str(Path(__file__).resolve()), "--case", case, "--output", str(directory),
        "--run-id", run_id, "--source-inventory-sha256", inventory_hash]
    began = time.monotonic_ns()
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=os.pathsep.join([str(ROOT / "py"), str(ROOT / "tests")])))
    raw, streams, timed_out, errors = _drain(process, timeout=30)
    finished = time.monotonic_ns()
    for name, value in raw.items():
        save(directory / ("child-" + name + ".raw"), value)
    rows, decode_error = _reply(raw["stdout"])
    bootstrap = next((x for x in rows if x["kind"] == "bootstrap"), None)
    completion = next((x for x in rows if x["kind"] == "completion"), None)
    binding_errors = []
    for row in (bootstrap, completion):
        if type(row) is not dict or any(row.get(k) != v for k, v in (
                ("case_id", case), ("run_id", run_id), ("protocol_sha256", PROTOCOL_SHA256),
                ("source_inventory_sha256", inventory_hash))):
            binding_errors.append("child_envelope_missing_or_mismatched")
    identity = bootstrap.get("boundary", {}).get("identity") if bootstrap else None
    if type(identity) is not dict or type(identity.get("pid")) is not int or identity["pid"] != process.pid or identity.get("uid") != 0 or (bootstrap or {}).get("boundary", {}).get("no_new_privileges") != 1:
        binding_errors.append("bootstrap_not_bound_to_actual_Root_supervisor")
    result = dict(pid=process.pid, started_ns=began, finished_ns=finished, returncode=process.returncode,
        streams=streams, timed_out=timed_out, capture_errors=errors, stdout_decode_error=decode_error,
        bootstrap=bootstrap, completion=completion, binding_errors=binding_errors)
    save(directory / "child-process.json", wire(result))
    return result


def read_case(directory):
    raw, errors, descriptors = {}, {}, {}
    for name in tuple(RAW_FILES.values()) + tuple(ARG_FILES.values()) + EXTRAS + OUTER + ("source-inventory.json",):
        try:
            value = read_closed(directory / name)
            raw[name] = value
            descriptors[name] = dict(path=name, bytes=len(value), sha256=sha(value))
        except Exception as exc:
            raw[name], descriptors[name] = None, None
            errors[name] = dict(type=type(exc).__name__, errno=getattr(exc, "errno", None))
    return raw, descriptors, errors


def evaluate_saved(raw):
    from azazel_edge.benchmark.real_source_close import evaluate_real_source_close
    expected = {key + "_sha256": sha(raw[name]) if raw.get(name) is not None else None
        for key, name in {**RAW_FILES, **ARG_FILES}.items()}
    args = {key: json.loads(raw[name]) if raw.get(name) is not None else {} for key, name in ARG_FILES.items()}
    result = evaluate_real_source_close(raw["trust.json"], raw["source.raw"], raw["anchors.raw"],
        source_arguments=args["source_arguments"], witness_arguments=args["witness_arguments"],
        plan_raw=raw["plan.json"], controller_raw=raw["controller.json"], read_raw=raw["collection.json"], expected=expected)
    return expected, result


def state_problems(case, raw, child):
    problems = []
    try:
        state = json.loads(raw["case-state.json"])
        controller, plan = json.loads(raw["controller.json"]), json.loads(raw["plan.json"])
    except (KeyError, TypeError, ValueError):
        return ["original_controller_or_state_unavailable"]
    allowed = {"producer_closed_ack": dict(type="EOFError", errno=None)} if case == "abrupt_writer" else {}
    if state.get("errors") != allowed or state.get("safe_to_continue") is not True:
        problems.append("unexpected_stage_errors_or_unfinished_actors")
    completion = (child.get("completion") or {})
    for key, other in (("errors", "errors"), ("actorfacts", "actors"), ("safe_to_continue", "safe_to_continue")):
        if wire(completion.get(key)) != wire(state.get(other)):
            problems.append("child_completion_state_mismatch")
    if (child.get("bootstrap") or {}).get("boundary", {}).get("identity") != plan.get("controller_identity"):
        problems.append("plan_controller_not_supervised_actor")
    if state.get("stage_facts", {}).get("collector_private_probes_denied") != [True] * 4:
        problems.append("collector_private_DAC_refusal_unverified")
    actors = state.get("actors", {})
    if set(actors) != {"producer", "observer", "collector"}:
        problems.append("actor_set_incomplete")
    for role in ("producer", "observer", "collector"):
        actor = actors.get(role, {})
        expected_rc = 7 if role == "producer" and case == "abrupt_writer" else 0
        if actor.get("cleanup_errors") != {} or type(actor.get("returncode")) is not int or actor.get("returncode") != expected_rc:
            problems.append(role + ":exit_or_cleanup_unverified")
        for stream in ("stdout", "stderr"):
            value = raw.get(role + "-" + stream + ".raw")
            observed = actor.get("observed_bytes", {}).get(stream)
            retained = actor.get("retained_bytes", {}).get(stream)
            if (type(value) is not bytes or type(observed) is not int or type(retained) is not int
                    or observed != retained or retained != len(value) or actor.get("stream_truncated", {}).get(stream) is not False):
                problems.append(role + ":truncated_or_unavailable_" + stream)
        boundary = state.get("actor_boundaries", {}).get(role, {})
        clock_binding = state.get("clock_provenance", {}).get(role, {})
        if (clock_binding.get("clock_provenance", {}).get("matched") is not True
                or wire(clock_binding.get("identity")) != wire(boundary.get("identity"))
                or clock_binding.get("clock_provenance", {}).get("cross_uid_namespace_lookup") != "NOT_ATTEMPTED"):
            problems.append(role + ":independent_incarnation_or_self_domain_binding_unavailable")
        expected_uid = {"producer": 1000, "observer": 65534, "collector": 61002}[role]
        if (boundary.get("identity", {}).get("uid") != expected_uid or boundary.get("identity", {}).get("pid") != actor.get("pid")
                or boundary.get("groups") != [] or boundary.get("no_new_privileges") != 1
                or set(boundary.get("capabilities", {})) != {"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"}
                or any(int(v, 16) != 0 for v in boundary.get("capabilities", {}).values())):
            problems.append(role + ":role_boundary_unverified")
    for role, field in (("producer", "producer_identity"), ("collector", "collector_identity")):
        if state.get("actor_boundaries", {}).get(role, {}).get("identity") != plan.get(field):
            problems.append(role + ":planned_identity_mismatch")
    if case == "abrupt_writer" and (controller.get("W", {}).get("returncode") != 7 or controller.get("writer_close") is not None):
        problems.append("actual_abrupt_exit_not_supported")
    return problems


def disposition(case, analysis):
    ids = [f"a{i:02}" for i in range(8)]
    if analysis.get("schema_version") != "edge-real-source-close-analysis/v1" or analysis.get("independent_read_verified") is not True:
        return False
    if any(analysis.get(k) is not v for k, v in {
        "actual_native_execution": False, "actual_native_terminal_verified": None, "source_immutability": False,
        "whole_window_coverage": False, "old_evaluation_modified": False, "performance_acceptance": False}.items()):
        return False
    if analysis.get("original_witness_evaluation", {}).get("witness_prefix_authenticated") is not True:
        return False
    if case == "abrupt_writer":
        return (analysis.get("known_signed_ids") == ids[:4] and analysis.get("test_gate_missing_count") is None
            and analysis.get("finite_test_gate_accounting_complete") is False and analysis.get("complete_assigned_test_capture") is False)
    lost = case == "explicit_loss"
    return (analysis.get("known_signed_ids") == [i for i in ids if not (lost and i == "a04")]
        and analysis.get("finite_test_gate_accounting_complete") is True
        and analysis.get("complete_assigned_test_capture") is (not lost)
        and type(analysis.get("test_gate_missing_count")) is int and analysis["test_gate_missing_count"] == int(lost)
        and analysis.get("test_gate_missing_ids") == (["a04"] if lost else [])
        and analysis.get("original_source_evaluation", {}).get("normal_terminal_verified") is True)


def final_fences(output, cases, sources):
    """Retain initial and final hashes; a changed original never becomes a new pin."""
    problems, observed = [], {}
    for case in cases:
        for name, initial in case["artifacts"].items():
            relative = case["case_id"] + "/" + name
            try:
                raw = read_closed(output / relative)
                current = dict(path=name, bytes=len(raw), sha256=sha(raw))
            except Exception as exc:
                current = dict(error=type(exc).__name__)
            observed[relative] = current
            if current != initial:
                problems.append(relative + ":original_changed_or_missing_after_analysis")
    for name, initial in sources.items():
        try:
            raw = read_closed(ROOT / name)
            current = dict(bytes=len(raw), sha256=sha(raw))
        except Exception as exc:
            current = dict(error=type(exc).__name__)
        observed["source:" + name] = current
        if current != initial:
            problems.append(name + ":source_inventory_changed_after_analysis")
    return problems, observed


def run(output_dir):
    output = Path(output_dir)
    new_directory(output)
    boundary = role_boundary()
    save(output / "process-boundary.json", wire(boundary))
    blockers, cases, inventory_errors = [], [], []
    raw_protocol = read_closed(PROTOCOL)
    if sha(raw_protocol) != PROTOCOL_SHA256:
        raise ValueError("frozen protocol mismatch")
    save(output / "protocol.json", raw_protocol)
    pins = {k: os.environ.get("EDGE_REAL_SOURCE_CLOSE_SOURCE_" + k.upper()) for k in ("head", "tree")}
    if not all(type(v) is str and re.fullmatch(r"[0-9a-f]{40}", v) for v in pins.values()):
        blockers.append("external_source_commit_tree_missing")
    sources = {}
    for name in SOURCES:
        try:
            value = read_closed(ROOT / name)
            sources[name] = dict(sha256=sha(value), bytes=len(value))
        except Exception as exc:
            inventory_errors.append(name + ":" + type(exc).__name__)
    inventory = dict(schema_version="edge-real-source-close-source-inventory/v1", **pins,
        protocol_sha256=PROTOCOL_SHA256, files=sources, inventory_errors=inventory_errors,
        scope="SELECTED_DIRECT_IMPLEMENTATION_AND_HELPERS_PLUS_EXTERNAL_CLEAN_CHECKOUT_TREE")
    inventory_raw = wire(inventory)
    save(output / "source-inventory.json", inventory_raw)
    if boundary["identity"]["uid"] != 0:
        blockers.append("existing_Root_fixture_authority_required")
    if inventory_errors:
        blockers.append("source_inventory_incomplete")
    run_id = "real-source-" + uuid.uuid4().hex
    unsafe = bool(blockers)
    for case in CASES:
        directory = output / case
        new_directory(directory)
        save(directory / "source-inventory.json", inventory_raw)
        row = dict(case_id=case, child=None, expected=None, analysis=None, artifacts={}, errors={}, expected_disposition=False)
        if unsafe:
            row["errors"]["not_run"] = "prior_unsafe_or_source_enrollment_failure"
            blockers.append(case + ":not_run_after_unsafe_or_source_enrollment_failure")
            cases.append(row)
            continue
        try:
            row["child"] = launch(directory, case, run_id, sha(inventory_raw))
        except Exception as exc:
            row["errors"]["launch"] = type(exc).__name__
            blockers.append(case + ":supervisor_launch_or_collection_failed")
            unsafe = True
        # Read and retain all available original siblings BEFORE any analysis/assertion.
        raw, row["artifacts"], row["errors"]["reads"] = read_case(directory)
        try:
            row["expected"], row["analysis"] = evaluate_saved(raw)
            analysis_raw = wire(row["analysis"])
            save(directory / "analysis.json", analysis_raw)
            row["artifacts"]["analysis.json"] = dict(path="analysis.json", bytes=len(analysis_raw), sha256=sha(analysis_raw))
            row["expected_disposition"] = disposition(case, row["analysis"])
        except Exception as exc:
            row["errors"]["analysis"] = type(exc).__name__
        child = row["child"]
        if child is not None:
            try:
                failures = state_problems(case, raw, child)
            except Exception as exc:
                failures = ["controller_validation:" + type(exc).__name__]
            row["errors"]["state"] = failures
            completion = child.get("completion") or {}
            if completion.get("safe_to_continue") is not True:
                unsafe = True
            if (child["returncode"] != 0 or child["timed_out"] or child["capture_errors"] or child["stdout_decode_error"]
                    or child["binding_errors"] or any(v["truncated"] for v in child["streams"].values()) or failures):
                blockers.append(case + ":supervision_or_controller_evidence_failed")
                unsafe = True
            if completion.get("expected") != row["expected"]:
                blockers.append(case + ":child_original_pins_differ")
        if not row["expected_disposition"]:
            blockers.append(case + ":assigned_disposition_unavailable")
        if row["errors"]["reads"]:
            blockers.append(case + ":required_originals_unavailable")
        cases.append(row)
    fence_problems, fence_observed = final_fences(output, cases, sources)
    blockers.extend(fence_problems)
    report = dict(schema_version="edge-real-source-close-run/v1", final_fence=fence_observed, run_id=run_id, protocol_sha256=PROTOCOL_SHA256,
        cases=cases, blockers=blockers, source=inventory, actual_native_execution=False, source_immutability=False,
        old_evaluation_modified=False, performance_acceptance=False, qualified_safety_count=None)
    report_raw = wire(report)
    save(output / "report.json", report_raw)
    original_refs = {case["case_id"] + "/" + name: desc for case in cases for name, desc in case["artifacts"].items()}
    original_refs.update({name: dict(bytes=len(raw), sha256=sha(raw)) for name, raw in (
        ("report.json", report_raw), ("protocol.json", raw_protocol), ("source-inventory.json", inventory_raw),
        ("process-boundary.json", wire(boundary)))})
    descriptors, export_errors, final_disagreements = {}, {}, {}
    for relative in ("report.json", "protocol.json", "source-inventory.json", "process-boundary.json") + tuple(case + "/" + name for case in CASES for name in CASE_FILES):
        try:
            value = read_closed(output / relative)
            descriptors[relative] = dict(bytes=len(value), sha256=sha(value))
            initial = original_refs.get(relative)
            expected_ref = {key: initial[key] for key in ("bytes", "sha256")} if type(initial) is dict else None
            if descriptors[relative] != expected_ref:
                export_errors[relative] = "final_manifest_read_differs_from_original_pin"
                final_disagreements[relative] = dict(original=expected_ref, observed=descriptors[relative])
        except Exception as exc:
            descriptors[relative] = None
            export_errors[relative] = type(exc).__name__
    save(output / "manifest.json", wire(dict(schema_version="edge-real-source-close-manifest/v1", files=descriptors,
        missing_or_errors=export_errors, final_read_disagreements=final_disagreements, inventory_errors=inventory_errors)))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--run-id")
    parser.add_argument("--source-inventory-sha256")
    args = parser.parse_args()
    if args.case:
        envelope = dict(case_id=args.case, run_id=args.run_id, protocol_sha256=PROTOCOL_SHA256,
            source_inventory_sha256=args.source_inventory_sha256)
        print(wire(dict(kind="bootstrap", boundary=role_boundary(), **envelope)).decode(), end="", flush=True)
        from real_source_close_lab import collect_case
        result = collect_case(args.output, args.case, run_id=args.run_id, source_inventory_sha256=args.source_inventory_sha256)
        print(wire(dict(kind="completion", **envelope, **result)).decode(), end="", flush=True)
    else:
        run(args.output)


if __name__ == "__main__":
    main()
