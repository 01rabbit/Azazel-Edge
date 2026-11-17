"""Frozen finite capture trials, separate from all original safety assessments."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

from azazel_edge.benchmark.capture_close import evaluate_capture_close
from azazel_edge.benchmark.capture_close_collection import process_identity

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "tests/fixtures/capture-close/v1/protocol.json"
PROTOCOL_SHA256 = "d89e6e78266cbe6af7cc0f24a8b78ce7560d98da3eeadc6ab3c1acdd7931620b"
CASES = ("clean", "explicit_loss", "abrupt_writer", "missing_loss_counter", "late_bypass", "seal_busy")
ORIGINALS = ("plan.json", "enrollment.json", "admission.json", "terminal.json", "collector.json", "capture.raw")
EXTRAS = ("case-state.json", "source-stdout.raw", "source-stderr.raw", "collector-stdout.raw", "collector-stderr.raw")
OUTER = ("child-stdout.raw", "child-stderr.raw", "child-process.json")
PINS = dict(zip(ORIGINALS, ("plan_sha256", "enrollment_sha256", "admission_sha256", "terminal_sha256", "collector_sha256", "capture_sha256")))
SOURCES = (
    "py/azazel_edge/benchmark/capture_close.py", "py/azazel_edge/benchmark/capture_close_collection.py",
    "tests/capture_close_lab.py", "tests/run_capture_close.py", "tests/test_capture_close_linux.py",
    "tests/fixtures/capture-close/v1/protocol.json",
)
MAXIMUM = 1048576
FLAGS = dict(whole_window_coverage=False, qualified_safety_count=None, comparison_qualified=False,
    production_admission=False, resume_authorized=False, performance_acceptance=False, old_evaluation_modified=False)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def descriptor(relative, raw):
    return None if raw is None else dict(path=relative, bytes=len(raw), sha256=sha(raw))


def save(path, raw):
    with Path(path).open("xb") as stream:
        stream.write(raw)


def read(path):
    path = Path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        def meta(obj):
            return tuple(getattr(obj, name) for name in fields)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or not 0 <= opened.st_size <= MAXIMUM
                or meta(before) != meta(opened)):
            raise ValueError("unsafe_or_oversized_original")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAXIMUM + 1)
        if len(raw) != opened.st_size or meta(os.fstat(fd)) != meta(opened) or meta(path.lstat()) != meta(opened):
            raise ValueError("changed_original")
        return raw
    finally:
        os.close(fd)


def boundary():
    values = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    result = dict(identity=process_identity(), uid=os.geteuid(), gid=os.getegid(), groups=os.getgroups(),
        capabilities={key: values[key].strip() for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        no_new_privileges=int(values["NoNewPrivs"].strip()))
    if result["uid"] == 0 or result["no_new_privileges"] != 1 or any(int(v, 16) for v in result["capabilities"].values()):
        raise ValueError("ordinary_UID_caps0_NNP_required")
    return result


def protocol():
    raw = read(PROTOCOL)
    if sha(raw) != PROTOCOL_SHA256 or tuple(json.loads(raw)["cases"]) != CASES:
        raise ValueError("frozen_protocol_changed")
    return raw


def _drain(process, timeout=30):
    retained = {name: bytearray() for name in ("stdout", "stderr")}
    observed = {name: 0 for name in retained}
    errors, timed_out, killed = [], False, None
    deadline = time.monotonic() + timeout
    def stop_owned_session():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            errors.append("owned_session_stop:" + type(exc).__name__)
    with selectors.DefaultSelector() as selector:
        try:
            for name in retained:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                now = time.monotonic()
                if now >= deadline and killed is None:
                    timed_out, killed = True, now
                    stop_owned_session()
                if killed is not None and now - killed > 5:
                    errors.append("owned_session_pipe_EOF_unavailable")
                    break
                for key, _ in selector.select(timeout=0.1):
                    try:
                        block = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    except OSError as exc:
                        errors.append(key.data + ":" + type(exc).__name__)
                        block = b""
                    if not block:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    observed[key.data] += len(block)
                    room = MAXIMUM - len(retained[key.data])
                    if room > 0:
                        retained[key.data].extend(block[:room])
        except Exception as exc:
            errors.append("stream_capture:" + type(exc).__name__)
            stop_owned_session()
        finally:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                except OSError as exc:
                    errors.append("stream_close:" + type(exc).__name__)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        timed_out = True
        stop_owned_session()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            errors.append("owned_supervisor_termination_unverified")
    streams = {name: dict(bytes_observed=observed[name], bytes_retained=len(raw), truncated=observed[name] > len(raw),
        retained_sha256=sha(raw)) for name, raw in retained.items()}
    return {name: bytes(raw) for name, raw in retained.items()}, streams, timed_out, errors


def _reply(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_reply_field")
            result[key] = value
        return result
    rows = []
    try:
        for line in raw.splitlines(keepends=True):
            if not line.endswith(b"\n") or len(line) > 65536 or len(rows) >= 4:
                raise ValueError("reply_capacity_or_partial_row")
            row = json.loads(line, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
            if type(row) is not dict or row.get("kind") not in ("bootstrap", "completion") or any(x["kind"] == row["kind"] for x in rows):
                raise ValueError("reply_kind_or_duplicate")
            rows.append(row)
    except (ValueError, UnicodeError, RecursionError) as exc:
        return rows, type(exc).__name__
    return rows, None


def launch(output, case, run_id, inventory_hash):
    command = [sys.executable, str(Path(__file__).resolve()), "--case", case, "--output", str(output),
        "--run-id", run_id, "--source-inventory-sha256", inventory_hash]
    started = time.monotonic_ns()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    raw, streams, timeout, errors = _drain(process)
    finished = time.monotonic_ns()
    for name, value in raw.items():
        save(output / ("child-" + name + ".raw"), value)
    rows, decode_error = _reply(raw["stdout"])
    bootstrap = next((row for row in rows if row["kind"] == "bootstrap"), None)
    completion = next((row for row in rows if row["kind"] == "completion"), None)
    binding = []
    for row in (bootstrap, completion):
        if type(row) is not dict or any(row.get(key) != value for key, value in (
            ("case_id", case), ("run_id", run_id), ("protocol_sha256", PROTOCOL_SHA256), ("source_inventory_sha256", inventory_hash))):
            binding.append("missing_or_mismatched_child_envelope")
    identity = bootstrap.get("boundary", {}).get("identity") if type(bootstrap) is dict else None
    if type(identity) is not dict or identity.get("pid") != process.pid:
        binding.append("bootstrap_not_bound_to_Popen_pid")
    result = dict(schema_version="edge-capture-close-child/v1", pid=process.pid, command=command,
        started_ns=started, finished_ns=finished, returncode=process.returncode, timed_out=timeout,
        capture_errors=errors, streams=streams, stdout_decode_error=decode_error,
        bootstrap=bootstrap, completion=completion, binding_errors=binding)
    save(output / "child-process.json", canonical(result))
    return result


def disposition(case, analysis, raw):
    if analysis.get("schema_version") != "edge-capture-close-analysis/v1":
        return False
    try:
        terminal = json.loads(raw["terminal.json"])
        collected = json.loads(raw["collector.json"])
        frames = [json.loads(line) for line in raw["capture.raw"].splitlines()]
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return False
    matching = analysis.get("known_matching_ids")
    if type(matching) is not list:
        return False
    if (any(analysis.get(name) is not None for name in ("upstream_produced", "upstream_dropped", "runtime_inflight", "qualified_safety_count"))
            or any(analysis.get(name) is not False for name in FLAGS if name != "qualified_safety_count")):
        return False
    complete = analysis.get("complete_finite_capture") is True
    accounted = analysis.get("finite_accounting_complete") is True
    lost = analysis.get("terminal_missing_count")
    read_complete = collected.get("complete") is True
    waited = terminal.get("W")
    sealed = terminal.get("S")
    if type(waited) is not dict or type(sealed) is not dict:
        return False
    if case == "clean":
        return (complete and accounted and type(lost) is int and lost == 0 and len(matching) == 16
            and read_complete and waited.get("returncode") == 0 and sealed.get("result") == "sealed")
    if case == "explicit_loss":
        return (not complete and accounted and type(lost) is int and lost == 1 and len(matching) == 15
            and read_complete and analysis.get("terminal_missing_ids") == ["a07"])
    if case == "late_bypass":
        return (not complete and "late0" in analysis.get("unexpected_ids", []) and read_complete
            and any(frame.get("kind") == "data" and frame.get("attempt_id") == "late0" for frame in frames))
    if complete or accounted or lost is not None:
        return False
    if case == "abrupt_writer":
        return len(matching) == 8 and waited.get("returncode") == 7 and terminal.get("D") is None and read_complete
    if case == "missing_loss_counter":
        return (len(matching) == 16 and read_complete and frames and frames[-1].get("kind") == "terminal"
            and "declared_lost" not in frames[-1])
    if case == "seal_busy":
        return (not matching and not read_complete and raw["capture.raw"] == b""
            and sealed.get("result") == "failed" and sealed.get("errno") == 16 and collected.get("errors"))
    return False


def state_errors(case, state, completion, logs, terminal, plan):
    """Only the frozen, evidenced negative error is expected; never blanket-ignore."""
    problems = []
    if (type(state) is not dict or state.get("schema_version") != "edge-capture-close-lab-state/v1"
            or state.get("case_id") != case or state.get("safe_to_continue") is not True
            or state.get("old_evaluations_modified") is not False):
        return ["case_state_missing_or_unsafe"]
    expected_errors = {"terminal_ack": dict(type="EOFError", errno=None)} if case == "abrupt_writer" else {}
    if state.get("errors") != expected_errors:
        problems.append("unexpected_or_missing_controller_stage_error")
    if type(completion) is not dict or any(
        canonical(completion.get(key)) != canonical(state.get(value))
        for key, value in (("errors", "errors"), ("actorfacts", "actors"), ("safe_to_continue", "safe_to_continue"))
    ):
        problems.append("case_state_differs_from_supervised_completion")
    if case == "abrupt_writer":
        ack = state.get("stage_facts", {}).get("footer_ack_read", {})
        if (type(terminal) is not dict or terminal.get("D") is not None
                or terminal.get("W", {}).get("returncode") != 7
                or ack.get("acknowledgment_received") is not False or ack.get("error") != expected_errors["terminal_ack"]
                or any(type(ack.get(key)) is not int or ack[key] < 0 for key in ("started_ns", "finished_ns"))
                or not ack["started_ns"] <= ack["finished_ns"] <= terminal.get("W", {}).get("started_ns", -1)):
            problems.append("expected_abrupt_EOF_not_independently_supported")
    actors = state.get("actors")
    if type(actors) is not dict or set(actors) != {"source", "collector"}:
        return problems + ["owned_actor_set_incomplete"]
    for role, identity_name in (("source", "writer_identity"), ("collector", "collector_identity")):
        actor = actors[role]
        if (type(actor) is not dict or actor.get("cleanup_errors") != {}
                or type(actor.get("returncode")) is not int
                or actor["returncode"] != (7 if role == "source" and case == "abrupt_writer" else 0)
                or type(plan) is not dict or actor.get("pid") != plan.get(identity_name, {}).get("pid")):
            problems.append(role + ":unexpected_exit_identity_or_cleanup")
            continue
        for stream in ("stdout", "stderr"):
            observed = actor.get("observed_bytes", {}).get(stream)
            retained = actor.get("retained_bytes", {}).get(stream)
            raw = logs.get(role + "-" + stream + ".raw")
            if (type(observed) is not int or type(retained) is not int or observed < 0 or observed != retained
                    or actor.get("stream_truncated", {}).get(stream) is not False
                    or type(raw) is not bytes or len(raw) != retained):
                problems.append(role + ":unverified_or_truncated_" + stream)
    return problems


def run(output_dir):
    output = Path(output_dir)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    process_boundary = boundary()
    raw_protocol = protocol()
    source = {key: os.environ.get("EDGE_CAPTURE_CLOSE_SOURCE_" + key.upper()) for key in ("head", "tree")}
    if not all(type(value) is str and re.fullmatch("[0-9a-f]{40}", value) for value in source.values()):
        raise ValueError("external_source_commit_tree_required")
    source_files = {}
    for name in SOURCES:
        data = read(ROOT / name)
        source_files[name] = dict(sha256=sha(data), bytes=len(data))
    inventory = canonical(dict(schema_version="edge-capture-close-source-inventory/v1", files=source_files))
    for name, raw in (("protocol.json", raw_protocol), ("source-inventory.json", inventory),
                      ("process-boundary.json", canonical(process_boundary))):
        save(output / name, raw)
    run_id = "capture-close-" + uuid.uuid4().hex
    entries, blockers, artifacts = [], [], {}
    halted = False
    for case in CASES:
        directory = output / case
        directory.mkdir(mode=0o700)
        save(directory / "source-inventory.json", inventory)
        evaluated = {case + "/source-inventory.json": descriptor(case + "/source-inventory.json", inventory)}
        entry = dict(case_id=case, child=None, expected=None, analysis=None, expected_disposition=False)
        try:
            if halted:
                raise RuntimeError("not_run_prior_unfinished_work")
            child = entry["child"] = launch(directory, case, run_id, sha(inventory))
            completion = child["completion"]
            halted = type(completion) is not dict or completion.get("safe_to_continue") is not True
            if (child["returncode"] != 0 or child["timed_out"] or child["capture_errors"] or child["binding_errors"]
                    or child["stdout_decode_error"] or any(x["truncated"] for x in child["streams"].values())):
                blockers.append(case + ":child_unverified_or_incomplete")
                halted = True
            raw, expected = {}, {}
            for name in ORIGINALS:
                try:
                    raw[name] = read(directory / name)
                except (OSError, ValueError) as exc:
                    raw[name] = None
                    entry.setdefault("original_read_errors", {})[name] = type(exc).__name__
                    blockers.append(case + "/" + name + ":original_unavailable_or_unverified")
                expected[PINS[name]] = sha(raw[name]) if raw[name] is not None else None
                evaluated[case + "/" + name] = descriptor(case + "/" + name, raw[name])
            entry["expected"] = expected
            if type(completion) is dict and canonical(completion.get("expected")) != canonical(expected):
                blockers.append(case + ":completion_differs_from_closed_originals")
            analysis = evaluate_capture_close(raw["plan.json"], raw["admission.json"], raw["terminal.json"],
                raw["collector.json"], raw["capture.raw"], expected=expected, enrollment_raw=raw["enrollment.json"])
            analysis_raw = canonical(analysis)
            save(directory / "analysis.json", analysis_raw)
            evaluated[case + "/analysis.json"] = descriptor(case + "/analysis.json", analysis_raw)
            entry["analysis"] = analysis
            entry["expected_disposition"] = disposition(case, analysis, raw)
            if not entry["expected_disposition"]:
                blockers.append(case + ":unexpected_verifier_disposition")
            plan = json.loads(raw["plan.json"]) if raw["plan.json"] is not None else None
            if (type(plan) is not dict or plan.get("controller_identity") != child["bootstrap"].get("boundary", {}).get("identity")
                    or plan.get("case_id") != case or plan.get("run_id") != run_id or plan.get("source_inventory_sha256") != sha(inventory)):
                blockers.append(case + ":plan_not_bound_to_external_controller_source_enrollment")
            extra_raw = {}
            for name in EXTRAS:
                try:
                    extra_raw[name] = read(directory / name)
                except (OSError, ValueError):
                    extra_raw[name] = None
                evaluated[case + "/" + name] = descriptor(case + "/" + name, extra_raw[name])
            state = json.loads(extra_raw["case-state.json"]) if extra_raw["case-state.json"] is not None else None
            terminal = json.loads(raw["terminal.json"]) if raw["terminal.json"] is not None else None
            entry["state_errors"] = state_errors(case, state, completion, extra_raw, terminal, plan)
            blockers.extend(case + ":" + error for error in entry["state_errors"])
        except Exception as exc:
            entry["error"] = type(exc).__name__
            blockers.append(case + ":" + type(exc).__name__)
            halted = True
        entries.append(entry)
        for name in (*ORIGINALS, *EXTRAS, *OUTER, "analysis.json", "source-inventory.json"):
            relative = case + "/" + name
            try:
                data = read(output / relative)
                artifacts[relative] = descriptor(relative, data)
            except FileNotFoundError:
                artifacts[relative] = None
            except (OSError, ValueError) as exc:
                artifacts[relative] = None
                blockers.append(relative + ":artifact_unverified:" + type(exc).__name__)
            if relative in evaluated and canonical(artifacts[relative]) != canonical(evaluated[relative]):
                blockers.append(relative + ":changed_between_evaluation_and_inventory")
    report = dict(schema_version="edge-capture-close-study/v1", run_id=run_id, cases=entries, blockers=blockers,
        scope="FINITE_CONTROLLER_OWNED_TEST_CAPTURE_ONLY", **FLAGS)
    save(output / "report.json", canonical(report))
    for name in ("protocol.json", "source-inventory.json", "process-boundary.json", "report.json"):
        data = read(output / name)
        artifacts[name] = dict(path=name, bytes=len(data), sha256=sha(data))
    save(output / "manifest.json", canonical(dict(schema_version="edge-capture-close-public-inventory/v1",
        source=source, run_id=run_id, protocol_sha256=PROTOCOL_SHA256, files=artifacts, **FLAGS)))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    parser.add_argument("--run-id")
    parser.add_argument("--source-inventory-sha256")
    args = parser.parse_args()
    if args.case:
        from capture_close_lab import collect_case
        protocol()
        if sha(read(args.output / "source-inventory.json")) != args.source_inventory_sha256:
            raise ValueError("source_inventory_mismatch_before_controller")
        envelope = dict(case_id=args.case, run_id=args.run_id, protocol_sha256=PROTOCOL_SHA256,
            source_inventory_sha256=args.source_inventory_sha256)
        print(canonical(dict(kind="bootstrap", boundary=boundary(), **envelope)).decode(), end="", flush=True)
        result = collect_case(args.output, args.case, run_id=args.run_id, source_inventory_sha256=args.source_inventory_sha256)
        print(canonical(dict(kind="completion", **envelope, **result)).decode(), end="", flush=True)
        return int(result.get("safe_to_continue") is not True)
    run(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
