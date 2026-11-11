"""Standalone read-only observer commissioning; no experiment or capture keys."""
# ruff: noqa: E402
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import time

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests"), str(Path(__file__).parent)]
import armor as a
import terminal_stop_lab as lab
import terminal_cgroup as cg
import network_measure_driver as network
from azazel_edge.outcome.input_auth import read_regular

g = a.g
UNIT = "edge400-telemetry-preflight.service"
FLAG = "EDGE_TELEMETRY_PREFLIGHT"
PATHS = {"proc_net_dev": "/proc/net/dev", "proc_loadavg": "/proc/loadavg",
         "proc_meminfo": "/proc/meminfo", "proc_uptime": "/proc/uptime"}


def guard():
    lab.need(os.environ.get(FLAG) == "1", "explicit commissioning opt-in required")
    marker, _ = read_regular(Path("/etc/edge400-disposable-vm"), owner=0, max_bytes=256)
    lab.need(marker == g.MAGIC.encode(), "protected disposable VM marker required")
    g.guard()
    source = os.environ.get("EDGE_TELEMETRY_SOURCE_COMMIT", "")
    core = os.environ.get("EDGE_TELEMETRY_CORE_SHA256", "")
    archive = os.environ.get("EDGE_TELEMETRY_ARCHIVE_SHA256", "")
    lab.need(re.fullmatch("[0-9a-f]{40}", source) and all(re.fullmatch("[0-9a-f]{64}", v) for v in (core, archive)), "reviewed source/core/archive pins required")
    revision, _ = read_regular(SRC / "SOURCE_REVISION", owner=0, max_bytes=41)
    binary, _ = read_regular(g.CORE, owner=0, max_bytes=128 * 1024 * 1024)
    lab.need(revision in (source.encode(), (source + "\n").encode()) and lab.sha(binary) == core, "actual source/core pin mismatch")
    lab.need(not g.BASE.exists(), "used capture scope refused")
    for unit in (UNIT, g.UNIT, g.WITNESS):
        lab.need(g.systemctl("show", unit, "-p", "LoadState", "--value", check=False).stdout.strip() == "not-found", "existing actor unit refused")
    pins = dict(source_commit=source, core_sha256=core, kernel_boot_id=g.boot(),
                source_archive_sha256_operator_boundary=archive, isolated_api=lab.isolated_api_preflight())
    for name, path in dict(helper=Path(__file__), armor=Path(a.__file__), guest=Path(g.__file__),
                           terminal_lab=Path(lab.__file__), cgroup=Path(cg.__file__), assets=Path(network.__file__),
                           profile=SRC / "tests/real_systemd/edge400.apparmor").items():
        raw, _ = read_regular(path, owner=0, max_bytes=1024 * 1024)
        pins[name + "_sha256"] = lab.sha(raw)
    network.boot_reference(pins["kernel_boot_id"])
    return pins


def role_argv(namespace):
    return ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=" + UNIT,
            "-p", "User=edge400-observer", "-p", "Group=edge400-observer", "-p", "NoNewPrivileges=yes",
            "-p", "CapabilityBoundingSet=", "-p", "AppArmorProfile=edge400-observer",
            "-p", "RestrictAddressFamilies=AF_UNIX", "-p", "Restart=no", "-p", "DefaultDependencies=no",
            "-p", "RuntimeMaxSec=10", "-p", "TimeoutStopSec=3",
            "-p", "NetworkNamespacePath=/run/netns/" + namespace,
            str(g.PYTHON.with_name("edge-observe")), "-I", "-B", str(Path(__file__).resolve()), "--worker"]


def worker():
    from role_probe import status
    from azazel_edge.outcome.confinement import enforce_capture
    from azazel_edge.outcome.telemetry import LinuxProcTelemetrySource
    enforce_capture("edge400-observer")
    identity = status()
    fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    identity.update(pid=os.getpid(), cap_bnd=int(fields["CapBnd"], 16))
    lab.need(identity["uid"] == 61002 and set(identity["groups"]) <= {61002}
             and all(identity[k] == 0 for k in ("cap_eff", "cap_prm", "cap_amb", "cap_bnd")), "observer authority differs")
    print(json.dumps(dict(kind="ready", pid=os.getpid())), flush=True)
    lab.need(sys.stdin.buffer.readline(16) == b"sample\n", "fixed root-controller sample fence required")
    sample = LinuxProcTelemetrySource().sample(interface="es", epoch=time.time())
    reads = {}
    for name, path in PATHS.items():
        try:
            raw = Path(path).read_bytes()
            reads[name] = dict(path=path, errno=None, bytes=len(raw), sha256=lab.sha(raw))
        except OSError as exc:
            reads[name] = dict(path=path, errno=exc.errno, error=type(exc).__name__)
    print(json.dumps(dict(identity=identity, kernel_boot_id=g.boot(), sample=asdict(sample), reads=reads)), flush=True)


def classify(value, *, boot, namespace, expected_namespace):
    identity, sample = value["identity"], value["sample"]
    lab.need(identity["uid"] == 61002 and identity["apparmor"] == "edge400-observer (enforce)"
             and identity["no_new_privs"] is True and set(identity["groups"]) <= {61002}
             and all(identity[k] == 0 for k in ("cap_eff", "cap_prm", "cap_amb", "cap_bnd")), "actual observer identity differs")
    lab.need(value["kernel_boot_id"] == boot and namespace == expected_namespace, "actual boot/namespace differs")
    lab.need(sample["interface"] == "es" and set(sample["coverage"]) == set(PATHS)
             and all(type(v) is bool for v in sample["coverage"].values()) and set(value["reads"]) == set(PATHS), "actual coverage/read shape differs")
    readable = all(row.get("errno") is None and row.get("path") == PATHS[name] and type(row.get("bytes")) is int and row["bytes"] > 0 for name, row in value["reads"].items())
    return "commissioning_ready" if readable and all(sample["coverage"].values()) else "commissioning_blocked"


def receive_ready(process, path):
    raw, deadline = bytearray(), time.monotonic() + 2
    try:
        while not raw.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            lab.need(remaining > 0 and select.select([process.stdout], [], [], remaining)[0], "ready absolute deadline")
            chunk = os.read(process.stdout.fileno(), 16385 - len(raw))
            lab.need(chunk and len(raw) + len(chunk) <= 16384, "missing/oversized ready receipt")
            raw.extend(chunk)
        return json.loads(raw)
    finally:
        lab.save(path, bytes(raw))


def close_namespace_after_actors(assets, cleanup, before):
    lab.need(not cleanup["errors"], "actor quiescence unknown; retain owned namespace")
    assets.close()
    lab.need(network.root_snapshot() == before, "root rules/routes changed")


def run(output):
    pins = guard()
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    lab.save_json(output / "intent.json", dict(pins=pins, experiment=False, keys=False))
    before = network.root_snapshot()
    assets = network.Assets(output)
    assets.names = {"edge": assets.names["edge"]}
    tracked, failure, cleanup, process = {UNIT: []}, None, None, None
    try:
        a.prepare_accounts()  # Existing fixed locked accounts, no keys/material.
        a.install_policy()  # Exact unchanged profile/aliases only.
        profile = Path("/etc/apparmor.d/edge400-lab")
        raw, _ = read_regular(profile, owner=0, max_bytes=32768)
        lab.need(lab.sha(raw) == pins["profile_sha256"], "installed profile differs")
        expanded = subprocess.run(["apparmor_parser", "-p", str(profile)], capture_output=True, timeout=5)
        lab.save(output / "expanded-profile.raw", expanded.stdout)
        lab.save(output / "expanded-profile.stderr", expanded.stderr)
        lab.need(expanded.returncode == 0 and 0 < len(expanded.stdout) <= 1024 * 1024, "expanded include evidence unavailable")
        lab.save_json(output / "profile.json", dict(source_sha256=lab.sha(raw), expanded_sha256=lab.sha(expanded.stdout)))
        assets.create_namespace(assets.names["edge"])
        assets.ns("edge", "ip", "link", "add", "es", "type", "dummy")
        assets.ns("edge", "ip", "link", "set", "es", "up")
        for family in ("-4", "-6"):
            lab.need(not assets.ns("edge", "ip", family, "route", "show", "default").stdout.strip(), "external namespace route")
        argv = role_argv(assets.names["edge"])
        lab.save_json(output / "launch.json", argv)
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ready = receive_ready(process, output / "worker-ready.raw")
        lab.save_json(output / "worker-ready.json", ready)
        state = lab.unit_snapshot(UNIT)
        lab.need(ready.get("kind") == "ready" and ready.get("pid") == int(state["MainPID"]), "actual worker PID differs")
        actual_ns = os.stat("/proc/" + state["MainPID"] + "/ns/net")
        namespace = dict(device=actual_ns.st_dev, inode=actual_ns.st_ino)
        tracked[UNIT].append(state)
        lab.save_json(output / "root-observed-worker.json", dict(state=state, namespace=namespace))
        stdout, stderr = process.communicate(input=b"sample\n", timeout=12)
        lab.save(output / "worker.stdout", stdout)
        lab.save(output / "worker.stderr", stderr)
        lab.need(process.returncode == 0 and len(stdout) <= 65536, "actual confined worker failed")
        value = json.loads(stdout)
        _, device, inode = assets.created[assets.names["edge"]]
        outcome = classify(value, boot=pins["kernel_boot_id"], namespace=namespace, expected_namespace=dict(device=device, inode=inode))
        lab.save_json(output / "sample.json", value)
    except BaseException as exc:
        failure = exc
    finally:
        cleanup = lab.cleanup([UNIT], tracked)
        if process is not None:
            try:
                tail_out, tail_err = process.communicate(timeout=4)
                if failure is not None:
                    lab.save(output / "worker-failure-tail.stdout", tail_out)
                    lab.save(output / "worker-failure.stderr", tail_err)
            except BaseException as exc:
                cleanup["errors"].append(("systemd-run-client", type(exc).__name__))
        lab.save_json(output / "actor-cleanup.json", cleanup)
        if not cleanup["errors"]:
            try:
                close_namespace_after_actors(assets, cleanup, before)
            except BaseException as exc:
                cleanup["errors"].append(("namespace/root-cleanup", type(exc).__name__))
        lab.save_json(output / "cleanup-result.json", cleanup)
    if failure is not None:
        raise failure
    lab.need(not cleanup["errors"], "actor/namespace cleanup unverified; retain VM")
    result = dict(status=outcome, coverage=value["sample"]["coverage"], experiment=False,
                  production_admission=False, observer_authority_widened=False, cleanup_verified=True, pins=pins)
    lab.save_json(output / "result.json", result)
    return result


if __name__ == "__main__":
    if sys.argv[1:] == ["--worker"]:
        worker()
    else:
        lab.need(len(sys.argv) == 2, "one new private output directory required")
        print(json.dumps(run(Path(sys.argv[1]))))
