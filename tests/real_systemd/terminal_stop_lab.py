"""Explicit disposable-VM terminal CONTROL proof; no traffic or effect claim."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests"), str(Path(__file__).parent)]
import armor as a  # noqa: E402
import terminal_cgroup as cg  # noqa: E402

g = a.g
POLICY = SRC / "tests/fixtures/terminal_stop_policy.json"
INTERFACE = "lo"
INTERVAL = 1.0
OBSERVER = "edge400-terminal-observer.service"
INIT = "edge400-terminal-initialize.service"
FLAG = "EDGE_TERMINAL_VM_TESTS"


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def boot_reference(raw):
    need(str(uuid.UUID(raw)) == raw, "actual canonical kernel boot UUID required")
    return "kernel-boot-" + raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def save_json(path, value):
    save(path, json.dumps(value, sort_keys=True, allow_nan=False).encode() + b"\n")


def journal_frames(raw):
    """Independent read-only chain validation, never an ObservationJournal reopen."""
    from azazel_edge.outcome.journal import _parse, _json
    need(raw.endswith(b"\n") and len(raw) <= 16 * 1024 * 1024, "incomplete/big journal")
    frames, head = [], "0" * 64
    for number, line in enumerate(raw.splitlines(), 1):
        frame = _parse(line)
        need(set(frame) == {"seq", "prev", "kind", "data", "sha256"}, "journal fields")
        body = {k: v for k, v in frame.items() if k != "sha256"}
        need(frame["seq"] == number and frame["prev"] == head and sha(_json(body)) == frame["sha256"], "journal chain")
        frames.append(frame)
        head = frame["sha256"]
    return frames


def ready_for(raw, position):
    frames = journal_frames(raw)
    return frames[-1]["kind"] == "input_ready" and frames[-1]["data"] == position



def isolated_api_preflight():
    """Read-only staging check before any unit/profile/account/key mutation."""
    from azazel_edge.outcome.input_auth import read_regular

    probe = (
        "import inspect,json; "
        "import azazel_edge.outcome.input_resume as resume; "
        "import azazel_edge.outcome.input_terminal as terminal; "
        "print(json.dumps(dict(resume=resume.__file__,terminal=terminal.__file__,"
        "optional_api='terminal_stop_registration' in inspect.signature(resume.run_live_resumable).parameters)))"
    )
    result = subprocess.run(
        [str(g.PYTHON), "-I", "-B", "-c", probe], capture_output=True, text=True, timeout=5
    )
    need(result.returncode == 0, "isolated Edge API import unavailable; stage protected site-packages path before new VM assignment")
    need(len(result.stdout) <= 4096 and len(result.stderr) <= 8192, "isolated API probe output oversized")
    value = json.loads(result.stdout)
    need(type(value) is dict and set(value) == {"resume", "terminal", "optional_api"}
         and value["optional_api"] is True, "isolated optional Edge API unavailable")
    pins = {}
    for name, filename in (("resume", "input_resume.py"), ("terminal", "input_terminal.py")):
        expected = SRC / "py/azazel_edge/outcome" / filename
        need(value[name] == str(expected), "isolated import came from wrong package source")
        raw, _ = read_regular(expected, owner=0, max_bytes=1024 * 1024)
        pins[name] = dict(path=str(expected), sha256=sha(raw))
    return pins


def guard():
    from azazel_edge.outcome.input_auth import read_regular
    need(os.environ.get(FLAG) == "1", "explicit terminal VM opt-in required")
    marker, _ = read_regular(Path("/etc/edge400-disposable-vm"), owner=0, max_bytes=256)
    need(marker == g.MAGIC.encode(), "protected VM marker required")
    g.guard()
    source = os.environ.get("EDGE_TERMINAL_SOURCE_COMMIT", "")
    core = os.environ.get("EDGE_TERMINAL_CORE_SHA256", "")
    need(re.fullmatch("[0-9a-f]{40}", source) and re.fullmatch("[0-9a-f]{64}", core), "source/core pins required")
    revision, _ = read_regular(SRC / "SOURCE_REVISION", owner=0, max_bytes=41)
    need(revision in (source.encode(), (source + "\n").encode()), "protected source pin mismatch")
    binary, _ = read_regular(g.CORE, owner=0, max_bytes=128 * 1024 * 1024)
    need(sha(binary) == core, "actual core pin mismatch")
    for path in (g.BASE, g.UNITS / g.UNIT, g.UNITS / g.WITNESS, g.UNITS / (g.UNIT + ".d")):
        need(not path.exists(), "used scope refused; new VM required")
    for unit in (OBSERVER, INIT):
        need(g.systemctl("show", unit, "-p", "LoadState", "--value", check=False).stdout.strip() == "not-found", "existing worker unit refused")
    files = {}
    for name, path in dict(helper=Path(__file__), policy=POLICY, armor=Path(a.__file__),
                           guest=Path(g.__file__), cgroup=Path(cg.__file__), apparmor=SRC / "tests/real_systemd/edge400.apparmor").items():
        raw, _ = read_regular(path, owner=0, max_bytes=1024 * 1024)
        files[name + "_sha256"] = sha(raw)
    boot = g.boot()
    boot_reference(boot)
    return dict(source_commit=source, core_sha256=core, kernel_boot_id=boot,
                isolated_api=isolated_api_preflight(), **files)


def role_argv(mode, case):
    # Same observer properties as armor.execute_role; no added authority.
    return ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + (INIT if mode == "initialize" else OBSERVER),
            "-p", "User=edge400-observer", "-p", "Group=edge400-observer", "-p", "NoNewPrivileges=yes",
            "-p", "CapabilityBoundingSet=", "-p", "AppArmorProfile=edge400-observer",
            "-p", "RestrictAddressFamilies=AF_UNIX", "-p", "Restart=no", "-p", "DefaultDependencies=no", "-p", "RuntimeMaxSec=25", "-p", "TimeoutStopSec=5",
            str(g.PYTHON.with_name("edge-observe")), "-I", str(Path(__file__)), "--worker", mode, "--case", case]


def worker(mode, case):
    from role_probe import status
    from azazel_edge.outcome.confinement import enforce_capture
    from azazel_edge.outcome.input_auth import TrustPolicy
    from azazel_edge.outcome.input_cursor import BoundedInput
    from azazel_edge.outcome.input_resume import recover_input, run_live_resumable
    from azazel_edge.outcome.input_witness import InputAuthentication, WitnessClient
    from azazel_edge.outcome.journal import ObservationJournal, NAME
    from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy, persistence_context
    enforce_capture("edge400-observer")
    identity = status()
    need(identity["uid"] == 61002 and set(identity["groups"]) <= {61002}
         and identity["cap_eff"] == identity["cap_prm"] == identity["cap_amb"] == 0, "observer identity")
    trust = TrustPolicy.from_file(g.BUNDLE / "trust.json", role="observer")
    p = trust.data
    policy = OutcomeTelemetryPolicy.from_file(POLICY)
    if mode == "initialize":
        with BoundedInput(p["source_path"], max_bytes=p["input_max_bytes"], max_records=p["input_max_records"], authentication=InputAuthentication(trust)) as source:
            with ObservationJournal(Path(p["journal_directory"]), scope_ref=p["scope_ref"], policy_ref=persistence_context(policy, INTERFACE, INTERVAL), boot_id=boot_reference(g.boot()), create=True, max_bytes=p["journal_max_bytes"], input_source=source) as journal:
                recover_input(journal, policy)
                need(journal.input_position()["offset"] == 0 and not journal.retained_outcomes(), "nonempty initialization")
        print(json.dumps(dict(initialized_empty=True, identity=identity)), flush=True)
        return
    receipt = run_live_resumable(input_path=Path(p["source_path"]), output_path=Path(p["journal_directory"]) / "outcomes.jsonl",
        policy_path=POLICY, interface=INTERFACE, poll_seconds=.05, sample_interval_seconds=INTERVAL,
        max_output_bytes=65536, journal_directory=Path(p["journal_directory"]), journal_scope=p["scope_ref"],
        journal_boot_id=boot_reference(g.boot()), initialize_journal=False, journal_max_bytes=p["journal_max_bytes"], journal_max_identities=4096,
        input_max_bytes=p["input_max_bytes"], input_max_records=p["input_max_records"], authentication_policy=g.BUNDLE / "trust.json",
        **({"terminal_stop_registration": g.BUNDLE / "origin.json"} if case == "positive" else {}))
    need(case == "positive" and receipt is not None, "default driver unexpectedly returned")
    raw = (Path(p["journal_directory"]) / NAME).read_bytes()
    frames = journal_frames(raw)
    need(frames[-1]["kind"] == "session_close", "journal not closed")
    client = WitnessClient(trust)
    client.preflight(frames[-1]["seq"], frames[-1]["sha256"], len(raw))
    # Original terminal bytes are retained in private observer-owned artifacts.
    save(Path(p["journal_directory"]) / "terminal.wire", receipt.signed_wire)
    save(Path(p["journal_directory"]) / "terminal.decoded", receipt.decoded_record)
    print(json.dumps(dict(receipt=receipt.to_dict(), witness_state=client.state, identity=identity)), flush=True)


def pid_identity(raw):
    # Field 22 is stable across CPU/runtime changes and avoids PID-reuse claims.
    return (raw.split(" ", 1)[0], raw.rsplit(")", 1)[1].split()[19])


def unit_snapshot(unit):
    raw = g.systemctl("show", unit, "-p", "LoadState", "-p", "ActiveState", "-p", "MainPID", "-p", "ControlPID", "-p", "ControlGroup", check=False).stdout
    value = dict(line.split("=", 1) for line in raw.splitlines())
    pid = int(value.get("MainPID", "0"))
    value["pid_stat"] = Path(f"/proc/{pid}/stat").read_text() if pid else None
    return value


EFFECTIVE_PROPERTIES = (
    "ExecStart", "User", "Group", "AppArmorProfile", "CapabilityBoundingSet",
    "AmbientCapabilities", "RestrictAddressFamilies", "NoNewPrivileges", "Restart",
    "RuntimeMaxUSec", "TimeoutStopUSec", "DefaultDependencies", "Slice",
    "Wants", "Requires", "Requisite", "BindsTo", "PartOf", "Upholds",
    "OnFailure", "OnSuccess", "Triggers", "TriggeredBy", "After", "Before", "Conflicts",
)


def validate_effective(value, case):
    need(set(value) == set(EFFECTIVE_PROPERTIES), "effective worker properties incomplete")
    expected = dict(User="edge400-observer", Group="edge400-observer", AppArmorProfile="edge400-observer",
        CapabilityBoundingSet="", AmbientCapabilities="", RestrictAddressFamilies="AF_UNIX", NoNewPrivileges="yes",
        Restart="no", RuntimeMaxUSec="25s", TimeoutStopUSec="5s", DefaultDependencies="no", Slice="system.slice")
    need(all(value[key] == wanted for key, wanted in expected.items()), "effective worker authority/restart/bounds differ")
    for key in ("Wants", "Requisite", "BindsTo", "PartOf", "Upholds", "OnFailure", "OnSuccess", "Triggers", "TriggeredBy", "Before", "Conflicts"):
        need(value[key] == "", "unexpected worker activation/dependency")
    need(set(value["Requires"].split()) <= {"system.slice"}
         and set(value["After"].split()) <= {"system.slice", "systemd-journald.socket"}, "unexpected worker dependency")
    executable = str(g.PYTHON.with_name("edge-observe"))
    argv = " ".join([executable, "-I", str(Path(__file__)), "--worker", "live", "--case", case])
    command = value["ExecStart"]
    need(command.count("{") == command.count("}") == 1 and command.startswith("{ ") and command.endswith(" }"), "ambiguous worker commands")
    fields = {}
    for part in command[2:-2].split(" ; "):
        key, sep, item = part.partition("=")
        need(sep and key not in fields, "ambiguous effective command")
        fields[key] = item
    need(fields.get("path") == executable and fields.get("argv[]") == argv
         and fields.get("ignore_errors") == "no", "effective worker command differs")


def effective_worker(case):
    result = subprocess.run(["systemctl", "show", OBSERVER, "--property=" + ",".join(EFFECTIVE_PROPERTIES)],
                            capture_output=True, text=True, check=True, timeout=2)
    need(len(result.stdout) <= 32768, "effective worker state oversized")
    rows = result.stdout.splitlines()
    need(all("=" in row for row in rows), "effective worker state malformed")
    value = dict(row.split("=", 1) for row in rows)
    need(len(rows) == len(value), "duplicate effective worker property")
    validate_effective(value, case)
    state = unit_snapshot(OBSERVER)
    need(state["ActiveState"] == "active" and int(state["MainPID"]) > 0, "worker not active")
    pid = state["MainPID"]
    status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
    label = Path(f"/proc/{pid}/attr/apparmor/current").read_text().strip()
    need(status["Uid"].split() == ["61002"] * 4 and status["Gid"].split() == ["61002"] * 4
         and set(status["Groups"].split()) <= {"61002"} and status["NoNewPrivs"].strip() == "1"
         and all(int(status[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd"))
         and label == "edge400-observer (enforce)", "actual worker kernel confinement differs")
    need(cg._kernel_text(f"/proc/{pid}/cgroup", 4096) == "0::/system.slice/" + OBSERVER + "\n", "actual worker cgroup differs")
    return dict(properties=value, state=state, kernel_status=status, kernel_apparmor=label)


def cleanup(units, tracked):
    errors, records = [], []
    before = {}
    for unit in units:
        try:
            before[unit] = unit_snapshot(unit)
        except BaseException as exc:
            errors.append((unit, "before", type(exc).__name__))
        # Always try stop, even when status/PID reads failed. A collected unit
        # can return nonzero on stop; only an independently proven absent unit
        # may excuse that error. Snapshot failures remain sticky either way.
        try:
            stopped = subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=5)
            if stopped.returncode:
                need(before.get(unit, {}).get("LoadState") == "not-found", "actor stop failed")
        except BaseException as exc:
            errors.append((unit, "stop", type(exc).__name__))
    for unit in units:
        try:
            state = unit_snapshot(unit)
            need(state.get("ActiveState") in ("inactive", "failed")
                 and state.get("MainPID") == state.get("ControlPID") == "0", "unit still active")
            saved_states = [*tracked.get(unit, []), before.get(unit, {}), state]
            groups = {"/system.slice/" + unit}
            for saved in saved_states:
                group = saved.get("ControlGroup", "")
                need(group in ("", "/system.slice/" + unit), "unexpected actor cgroup")
                groups.add(group)
                if saved.get("pid_stat"):
                    current = Path("/proc") / saved["MainPID"] / "stat"
                    need(not current.exists() or pid_identity(current.read_text()) != pid_identity(saved["pid_stat"]), "original actor remains")
            for group in sorted(groups):
                need(cg.group_empty(group, units), "actor cgroup or descendants populated/unknown")
            records.append(dict(unit=unit, state=state, verified_groups=sorted(groups)))
        except BaseException as exc:
            errors.append((unit, "verify", type(exc).__name__))
    try:
        need(not g.Systemd().cores(), "core actor remains")
    except BaseException as exc:
        errors.append(("core-process-scan", "verify", type(exc).__name__))
    return dict(errors=errors, units=records)


def run_case(case, output):
    need(case in ("positive", "default-refusal"), "unknown fixed case")
    pins = guard()
    output.mkdir(mode=0o700)  # Never reuse/overwrite an assignment.
    save_json(output / "intent.json", dict(case=case, pins=pins, production_admission=False))
    units = [OBSERVER, INIT, g.UNIT, g.WITNESS]
    tracked = {unit: [] for unit in units}
    process = None
    failure = None
    try:
        a.NATIVE = True
        a.configure()
        a.prepare_accounts()
        a.install_policy()

        def initialize(create=False):
            need(create, "only genuine empty initialization authorized")
            # Restore the existing lab's intended traversal mode despite umask077.
            g.BASE.chmod(0o755)
            completed = subprocess.run(role_argv("initialize", case), capture_output=True, timeout=30)
            save(output / "initialization.stdout", completed.stdout)
            save(output / "initialization.stderr", completed.stderr)
            need(completed.returncode == 0, "confined empty initialization failed")
            return json.loads(completed.stdout)

        g.observer = initialize
        g.prepare_lab()  # Existing provisioning + witness-first + authentic empty init.
        tracked[g.WITNESS].append(unit_snapshot(g.WITNESS))
        switch = g.Switch(g.BUNDLE)
        plan = switch.plan()
        save_json(output / "switch-plan.json", plan)
        need(switch.apply(plan, g.digest(plan))["status"] == "started", "sealed normal-core start failed")
        g.live()
        tracked[g.UNIT].append(unit_snapshot(g.UNIT))
        p = g.fixture().p
        prefix = g.source()
        events = g.events()
        need([v["capture_origin"]["kind"] for v in events] == ["session_prepare", "session_start"], "unexpected initial source")
        before = dict(offset=len(prefix), sha256=sha(prefix))
        save(output / "source-prefix.raw", prefix)
        with (output / "observer.stdout").open("xb") as stdout, (output / "observer.stderr").open("xb") as stderr:
            process = subprocess.Popen(role_argv("live", case), stdout=stdout, stderr=stderr)
            deadline = time.monotonic() + 12
            journal_path = Path(p.data["journal_directory"]) / "observations.journal"
            while True:
                need(process.poll() is None, "observer exited before ready fence")
                raw = journal_path.read_bytes()
                if raw.endswith(b"\n") and ready_for(raw, before):
                    break
                need(time.monotonic() < deadline, "missing exact input_ready fence")
                time.sleep(.05)
            effective = effective_worker(case)
            tracked[OBSERVER].append(effective["state"])
            save_json(output / "effective-worker.json", effective)
            save(output / "ready-journal.raw", raw)
            g.stop()  # Clean real actor shutdown; signed end is not actor-cleanup proof.
            process.wait(timeout=15)
        source = g.source()
        save(output / "source-final.raw", source)
        raw = journal_path.read_bytes()
        save(output / "journal-final.raw", raw)
        frames = journal_frames(raw)
        source_events = g.events()
        need([v["capture_origin"]["kind"] for v in source_events] == ["session_prepare", "session_start", "session_end"], "unexpected final source")
        need(not any(f["kind"] in ("commit", "begin") for f in frames), "unexpected measurement")
        cursors = [f["data"] for f in frames if f["kind"] == "cursor"]
        need(frames[-1]["kind"] == "session_close", "missing closed journal")
        if case == "default-refusal":
            need(process.returncode != 0 and (output / "observer.stdout").read_bytes() == b"", "default did not refuse without receipt")
            need(cursors[-1]["position"] == before and not (Path(p.data["journal_directory"]) / "terminal.wire").exists(), "default consumed terminal")
            need(b"live core boundary requires verified observer recovery" in (output / "observer.stderr").read_bytes(), "original default failure absent")
        else:
            need(process.returncode == 0, "positive observer failed")
            result = json.loads((output / "observer.stdout").read_bytes())
            receipt = result["receipt"]
            need(receipt["registration_sha256"] == p.data["origin_registration_sha256"]
                 and receipt["session_ref"] == source_events[-1]["capture_origin"]["session_ref"]
                 and receipt["native_seq"] == source_events[-1]["capture_origin"]["seq"], "registered terminal origin differs")
            wire = source[len(prefix):]
            decoded = g.SourceVerifier.unwrap(wire)
            need(receipt["disposition"] == "verified_terminal_control_stop" and receipt["source_position_before"] == before
                 and receipt["source_position_after"] == dict(offset=len(source), sha256=sha(source))
                 and receipt["signed_wire_sha256"] == sha(wire) and receipt["decoded_record_sha256"] == sha(decoded)
                 and receipt["signed_wire_bytes"] == len(wire) and receipt["decoded_record_bytes"] == len(decoded)
                 and receipt["cursor_missed"] is True and receipt["measurement_completed"] is False and receipt["resume_authorized"] is False, "terminal receipt binding")
            need(cursors[-1] == dict(position=receipt["source_position_after"], missed=True), "terminal CONTROL cursor differs")
            need(result["witness_state"]["journal_head"] == frames[-1]["sha256"] and result["witness_state"]["source_sha256"] == sha(source)
                 and result["witness_state"]["journal_seq"] == frames[-1]["seq"]
                 and result["witness_state"]["journal_size"] == len(raw), "protected state differs")
            for name, expected in (("terminal.wire", wire), ("terminal.decoded", decoded)):
                need((Path(p.data["journal_directory"]) / name).read_bytes() == expected, "original terminal artifact differs")
                save(output / name, expected)
            save_json(output / "receipt.json", result)
    except BaseException as exc:
        failure = exc
    finally:
        cleaned = cleanup(units, tracked)
        if process is not None:
            try:
                process.wait(timeout=6)
            except BaseException as exc:
                cleaned["errors"].append(("systemd-run-client", type(exc).__name__))
        save_json(output / "cleanup.json", cleaned)
    if failure is not None:
        raise failure
    need(not cleaned["errors"], "actor cleanup unverified; see cleanup.json")
    save_json(output / "result.json", dict(case=case, terminal_control_only=True, actor_cleanup_verified=True,
        measurement_completed=False, efficacy=False, production_admission=False, pins=pins))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=("initialize", "live"))
    parser.add_argument("--case", required=True, choices=("positive", "default-refusal"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.case)
    else:
        need(args.output is not None, "private new output path required")
        run_case(args.case, args.output)
