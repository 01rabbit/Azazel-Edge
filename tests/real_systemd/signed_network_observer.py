"""Single real confined observer role; no workload, query or VM orchestration."""

# ruff: noqa: E402
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(SRC / "py"),
    str(SRC / "tests"),
    str(Path(__file__).resolve().parent),
]
from signed_network_plan import g, n, p, POLICY_PATH, INTERVAL, need, strict
from signed_network_scope import OBSERVER_UNIT, INITIALIZER_UNIT, _kernel_text
from signed_network_recording import record_collector
from signed_network_service import record_clock_anchor
import terminal_stop_lab as lab
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, read_regular, open_parent
from azazel_edge.outcome.input_cursor import BoundedInput
from azazel_edge.outcome.input_resume import recover_input, run_live_resumable
from azazel_edge.outcome.input_terminal import TerminalControlStop
from azazel_edge.outcome.input_witness import InputAuthentication, WitnessClient
from azazel_edge.outcome.journal import ObservationJournal, NAME
from azazel_edge.outcome.telemetry import (
    OutcomeTelemetryPolicy,
    LinuxProcTelemetrySource,
    persistence_context,
)

RUNTIME_SECONDS = 40
STOP_SECONDS = 5


def role_argv(mode):
    need(mode in ("initialize", "live"), "unknown fixed observer mode")
    return [
        "systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=" + (INITIALIZER_UNIT if mode == "initialize" else OBSERVER_UNIT),
        "-p",
        "User=edge400-observer",
        "-p",
        "Group=edge400-observer",
        "-p",
        "NoNewPrivileges=yes",
        "-p",
        "CapabilityBoundingSet=",
        "-p",
        "AppArmorProfile=edge400-observer",
        "-p",
        "RestrictAddressFamilies=AF_UNIX",
        "-p",
        "Restart=no",
        "-p",
        "DefaultDependencies=no",
        "-p",
        f"RuntimeMaxSec={RUNTIME_SECONDS}",
        "-p",
        f"TimeoutStopSec={STOP_SECONDS}",
        "-p",
        "NetworkNamespacePath=/run/netns/" + p.EDGE,
        str(g.PYTHON.with_name("edge-observe")),
        "-I",
        str(Path(__file__).resolve()),
        "--worker",
        mode,
    ]


def policy_material():
    raw, _ = read_regular(POLICY_PATH, owner=0, max_bytes=8192)
    payload = strict(raw)
    return (
        payload,
        OutcomeTelemetryPolicy.from_mapping(payload, source_ref=str(POLICY_PATH)),
        hashlib.sha256(raw).hexdigest(),
    )


def worker(mode):
    from role_probe import status
    from azazel_edge.outcome.confinement import enforce_capture

    need(mode in ("initialize", "live"), "unknown fixed observer mode")
    enforce_capture("edge400-observer")
    identity = status()
    need(
        identity["uid"] == 61002
        and set(identity["groups"]) <= {61002}
        and identity["apparmor"] == "edge400-observer (enforce)"
        and all(identity[k] == 0 for k in ("cap_eff", "cap_prm", "cap_amb")),
        "observer identity mismatch",
    )
    trust = TrustPolicy.from_file(g.BUNDLE / "trust.json", role="observer")
    d = trust.data
    need(
        d["observer_uid"] == 61002
        and d["producer_uid"] == 61001
        and d["witness_uid"] == 0,
        "registered observer role mismatch",
    )
    payload, policy, policy_file_sha = policy_material()
    kernel = g.boot()
    boot = n.boot_reference(kernel)
    sample = LinuxProcTelemetrySource().sample(interface="es", epoch=time.time())
    need(
        sample.coverage and all(sample.coverage.values()),
        "commissioning gap: unchanged observer label cannot sample required procfs",
    )
    if mode == "initialize":
        with BoundedInput(
            d["source_path"],
            max_bytes=d["input_max_bytes"],
            max_records=d["input_max_records"],
            authentication=InputAuthentication(trust),
        ) as source:
            with ObservationJournal(
                Path(d["journal_directory"]),
                scope_ref=d["scope_ref"],
                policy_ref=persistence_context(policy, "es", INTERVAL),
                boot_id=boot,
                create=True,
                max_bytes=d["journal_max_bytes"],
                input_source=source,
            ) as journal:
                recover_input(journal, policy)
                need(
                    journal.input_position()["offset"] == 0
                    and journal.status()["pending"] == 0
                    and not journal.retained_outcomes(),
                    "genuine new empty initialization required",
                )
        result = dict(
            initialized_empty=True,
            identity=identity,
            kernel_boot_id=kernel,
            boot_ref=boot,
            policy_sha256=n.manifest_digest(payload),
            policy_file_sha256=policy_file_sha,
        )
        print(json.dumps(result, sort_keys=True), flush=True)
        return result
    source_raw, _ = read_regular(
        Path(d["source_path"]), owner=d["producer_uid"], max_bytes=d["input_max_bytes"]
    )
    verifier = SourceVerifier(trust)
    verifier.verify(source_raw)
    wires = [strict(line) for line in source_raw.splitlines()]
    signed_boot = kernel.replace("-", "")  # systemd service profile uses %b.
    need(
        all(wire["boot_ref"] == signed_boot for wire in wires),
        "signed source boot differs from actual kernel/systemd boot mapping",
    )
    events = [wire["event"] for wire in wires]
    need(
        [event["capture_origin"]["kind"] for event in events]
        == ["session_prepare", "session_start"]
        and not verifier.live_state.closed,
        "fresh actual signed start prefix required",
    )
    directory = Path(d["journal_directory"])
    context = dict(
        identity=identity,
        kernel_boot_id=kernel,
        boot_ref=boot,
        signed_boot_ref=signed_boot,
        scope_ref=d["scope_ref"],
        registration_sha256=d["origin_registration_sha256"],
        policy_sha256=n.manifest_digest(payload),
        policy_file_sha256=policy_file_sha,
        source_start_position=dict(
            offset=len(source_raw), sha256=hashlib.sha256(source_raw).hexdigest()
        ),
        clock_anchor=record_clock_anchor(),
    )
    n.write_new(directory / "observer-start-context.json", context)
    # This is NOT input_ready. Controller must independently wait for the actual
    # durable input_ready position before starting baseline/workload.
    with record_collector(
        directory / "actual-collector-calls.jsonl",
        policy=payload,
        policy_source_ref=str(POLICY_PATH),
    ):
        receipt = run_live_resumable(
            input_path=Path(d["source_path"]),
            output_path=directory / "outcomes.jsonl",
            policy_path=POLICY_PATH,
            interface="es",
            poll_seconds=0.05,
            sample_interval_seconds=INTERVAL,
            max_output_bytes=1024 * 1024,
            journal_directory=directory,
            journal_scope=d["scope_ref"],
            journal_boot_id=boot,
            initialize_journal=False,
            journal_max_bytes=d["journal_max_bytes"],
            journal_max_identities=4096,
            input_max_bytes=d["input_max_bytes"],
            input_max_records=d["input_max_records"],
            authentication_policy=g.BUNDLE / "trust.json",
            terminal_stop_registration=g.BUNDLE / "origin.json",
        )
        need(
            type(receipt) is TerminalControlStop,
            "actual verified terminal CONTROL result required",
        )
    end_clock_anchor = (
        record_clock_anchor()
    )  # Actual post-recorder endpoint, never reconstructed.
    final_raw, _ = read_regular(
        Path(d["source_path"]), owner=d["producer_uid"], max_bytes=d["input_max_bytes"]
    )
    final = SourceVerifier(trust)
    final.verify(final_raw)
    need(
        all(strict(line)["boot_ref"] == signed_boot for line in final_raw.splitlines()),
        "final source boot differs from actual kernel",
    )
    need(
        receipt.registration_sha256 == d["origin_registration_sha256"],
        "terminal registration differs",
    )
    need(
        final.live_state.closed
        and receipt.session_ref == final.live_state.session
        and receipt.native_seq == final.live_state.seq
        and receipt.source_position_after
        == dict(offset=len(final_raw), sha256=hashlib.sha256(final_raw).hexdigest()),
        "final source tip differs from terminal receipt",
    )
    need(
        final_raw[receipt.source_position_before["offset"] :] == receipt.signed_wire
        and SourceVerifier.unwrap(receipt.signed_wire) == receipt.decoded_record,
        "original terminal wire/decoded bytes differ",
    )
    journal_raw, _ = read_regular(
        directory / NAME, owner=d["observer_uid"], max_bytes=d["journal_max_bytes"]
    )
    frames = lab.journal_frames(journal_raw)
    need(frames[-1]["kind"] == "session_close", "observer journal not closed")
    client = WitnessClient(trust)
    client.preflight(frames[-1]["seq"], frames[-1]["sha256"], len(journal_raw))
    need(
        client.state["source_sha256"] == hashlib.sha256(final_raw).hexdigest(),
        "final protected source differs",
    )
    lab.save(directory / "terminal.wire", receipt.signed_wire)
    lab.save(directory / "terminal.decoded", receipt.decoded_record)
    result = dict(
        context=context,
        end_clock_anchor=end_clock_anchor,
        terminal=receipt.to_dict(),
        witness_state=client.state,
        scope="real_observer_calls_and_terminal_control_not_measurement_success",
    )
    n.write_new(directory / "observer-terminal-result.json", result)
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


EFFECTIVE_PROPERTIES = (
    *lab.EFFECTIVE_PROPERTIES,
    "NetworkNamespacePath",
    "ExecCondition",
    "ExecStartPre",
    "ExecStartPost",
    "ExecStop",
    "ExecStopPost",
)


def validate_effective(value):
    need(
        set(value) == set(EFFECTIVE_PROPERTIES),
        "effective observer properties incomplete",
    )
    expected = dict(
        User="edge400-observer",
        Group="edge400-observer",
        AppArmorProfile="edge400-observer",
        CapabilityBoundingSet="",
        AmbientCapabilities="",
        RestrictAddressFamilies="AF_UNIX",
        NoNewPrivileges="yes",
        Restart="no",
        RuntimeMaxUSec=f"{RUNTIME_SECONDS}s",
        TimeoutStopUSec=f"{STOP_SECONDS}s",
        DefaultDependencies="no",
        Slice="system.slice",
        NetworkNamespacePath="/run/netns/" + p.EDGE,
    )
    need(
        all(value[key] == wanted for key, wanted in expected.items()),
        "effective observer authority/restart/namespace/bounds differ",
    )
    for key in (
        "Wants",
        "Requisite",
        "BindsTo",
        "PartOf",
        "Upholds",
        "OnFailure",
        "OnSuccess",
        "Triggers",
        "TriggeredBy",
        "Before",
        "Conflicts",
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
    ):
        need(value[key] == "", "unexpected observer activation/hook/dependency")
    need(
        set(value["Requires"].split()) <= {"system.slice"}
        and set(value["After"].split()) <= {"system.slice", "systemd-journald.socket"},
        "unexpected observer dependency",
    )
    command = value["ExecStart"]
    need(
        command.count("{") == command.count("}") == 1
        and command.startswith("{ ")
        and command.endswith(" }"),
        "ambiguous observer commands",
    )
    fields = {}
    for part in command[2:-2].split(" ; "):
        key, sep, item = part.partition("=")
        need(sep and key not in fields, "ambiguous effective observer command")
        fields[key] = item
    argv = " ".join(
        [
            str(g.PYTHON.with_name("edge-observe")),
            "-I",
            str(Path(__file__).resolve()),
            "--worker",
            "live",
        ]
    )
    need(
        fields.get("path") == str(g.PYTHON.with_name("edge-observe"))
        and fields.get("argv[]") == argv
        and fields.get("ignore_errors") == "no",
        "effective observer command differs",
    )


HOOKS = ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecCondition")
BUS_PATH = "/org/freedesktop/systemd1/unit/edge400_2dsigned_2dnetwork_2dobserver_2eservice"


def _retained_query(argv, prefix, directory):
    n.write_new(directory / (prefix + ".argv.json"), argv)
    code, error, stdout, stderr = None, None, b"", b""
    try:
        result = subprocess.run(argv, capture_output=True, timeout=2)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as exc:
        error, stdout, stderr = "TimeoutExpired", exc.stdout or b"", exc.stderr or b""
    except OSError as exc:
        error = type(exc).__name__
    lab.save(directory / (prefix + ".stdout"), stdout)
    lab.save(directory / (prefix + ".stderr"), stderr)
    n.write_new(directory / (prefix + ".result.json"), dict(returncode=code, error=error))
    return code, stdout


def merged_effective(text, bus):
    need(len(text) <= 32768 and len(bus) <= 65536, "effective observer evidence oversized")
    rows = text.decode("utf-8").splitlines()
    need(all("=" in row for row in rows), "effective observer state malformed")
    value = dict(row.split("=", 1) for row in rows)
    need(len(value) == len(rows) and set(value) - set(HOOKS) == set(EFFECTIVE_PROPERTIES) - set(HOOKS), "effective observer properties missing/duplicate")
    lines = bus.splitlines()
    need(len(lines) == len(HOOKS), "typed observer hooks unavailable")
    for key, line in zip(HOOKS, lines):
        typed = strict(line)
        need(type(typed) is dict and set(typed) == {"type", "data"} and typed["type"] == "a(sasbttttuii)"
             and type(typed["data"]) is list and typed["data"] == [], "typed observer hook not proven empty")
        need(value.get(key, "") == "", "text/typed observer hook mismatch")
        value[key] = ""
    return value


def effective_observer(namespace_identity, *, evidence_directory):
    directory = Path(evidence_directory)
    parent, _ = open_parent(directory / "unused", trusted_owner=os.geteuid())
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and info.st_mode & 0o7777 == 0o700, "private observer evidence directory required")
        text_code, text = _retained_query(["systemctl", "show", OBSERVER_UNIT, "--property=" + ",".join(EFFECTIVE_PROPERTIES)], "effective-systemctl", directory)
        bus_code, bus = _retained_query(["/usr/bin/busctl", "--system", "--json=short", "get-property", "org.freedesktop.systemd1", BUS_PATH,
                                       "org.freedesktop.systemd1.Service", *HOOKS], "effective-busctl", directory)
    finally:
        os.close(parent)
    need(text_code == bus_code == 0, "effective observer backend unavailable")
    value = merged_effective(text, bus)
    validate_effective(value)
    state = lab.unit_snapshot(OBSERVER_UNIT)
    pid = state["MainPID"]
    need(
        state["LoadState"] == "loaded"
        and state["ActiveState"] == "active"
        and state["ControlPID"] == "0"
        and int(pid) > 0,
        "observer not active",
    )
    status = dict(
        line.split(":", 1)
        for line in _kernel_text(f"/proc/{pid}/status", 65536).splitlines()
        if ":" in line
    )
    need(
        status["Uid"].split() == ["61002"] * 4
        and status["Gid"].split() == ["61002"] * 4
        and set(status["Groups"].split()) <= {"61002"}
        and status["NoNewPrivs"].strip() == "1"
        and all(
            int(status[key], 16) == 0
            for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd")
        )
        and _kernel_text(f"/proc/{pid}/attr/apparmor/current", 4096).strip()
        == "edge400-observer (enforce)",
        "actual observer kernel confinement differs",
    )
    network = os.stat(f"/proc/{pid}/ns/net")
    need(
        dict(device=network.st_dev, inode=network.st_ino) == namespace_identity,
        "actual observer namespace differs",
    )
    need(
        _kernel_text(f"/proc/{pid}/cgroup", 4096)
        == "0::/system.slice/" + OBSERVER_UNIT + "\n",
        "actual observer cgroup differs",
    )
    after = lab.unit_snapshot(OBSERVER_UNIT)
    need(
        after["MainPID"] == pid
        and lab.pid_identity(after["pid_stat"]) == lab.pid_identity(state["pid_stat"])
        and after["ActiveState"] == "active",
        "observer PID identity changed during verification",
    )
    return dict(
        properties=value,
        state=state,
        kernel_status=status,
        namespace_identity=namespace_identity,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", required=True, choices=("initialize", "live"))
    worker(parser.parse_args().worker)
