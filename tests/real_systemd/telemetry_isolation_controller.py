"""Manual one-case Root controller. No CLI, VM orchestration or trial admission.

Invoke only after independent complete-source review/freeze on a NEW unused VM.
All policy/asset staging is explicit through the separately guarded stage helper.
"""

import errno
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import time

import telemetry_isolation_preflight as p
import telemetry_isolation_setup as setup
import telemetry_isolation_result as frames
import network_measure_driver as network

C, LAB, G = p.contract, p.lab, p.old.g
UNITS = [C.role_spec(mode)["unit"] for mode in ("probe", "peer")]


def _fenced(assets, mode):
    name = assets.names[mode]
    fd, device, inode = assets.created[name]
    actual, named = (
        os.fstat(fd),
        os.stat(Path("/run/netns") / name, follow_symlinks=False),
    )
    LAB.need(
        (actual.st_dev, actual.st_ino)
        == (named.st_dev, named.st_ino)
        == (device, inode),
        "owned namespace identity changed",
    )
    return [device, inode]


def _workspace(output, baseline):
    work = output / "namespace-evidence"
    key = str(work)
    baseline["intended_assets"][key] = dict(kind="directory", mode=0o700)
    LAB.save_json(
        output / "namespace-workspace-intent.json",
        dict(path=key, spec=baseline["intended_assets"][key]),
    )
    p.old.private_output(work)
    fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = setup._metadata(os.fstat(fd))
        baseline["asset_confirmations"][key] = dict(created=info, complete=info)
        LAB.save_json(
            output / "namespace-workspace-created.json", dict(path=key, metadata=info)
        )
    finally:
        os.close(fd)
    return work


def _launch(mode, output):
    spec = C.role_spec(mode)
    LAB.need(
        G.systemctl(
            "show", spec["unit"], "-p", "LoadState", "--value", check=False
        ).stdout.strip()
        == "not-found",
        "unexpected existing role unit",
    )
    argv = [
        "systemd-run",
        "--quiet",
        "--wait",
        "--pipe",
        "--collect",
        "--unit=" + spec["unit"],
    ]
    for key, value in spec["properties"].items():
        argv.extend(["-p", key + "=" + value])
    argv.extend(p.worker_argv(mode))
    LAB.save_json(output / (mode + "-launch-intent.json"), argv)
    return subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )


def _exchange(process, payload, prefix, output):
    """Bounded original stream drain with independent best-effort persistence."""
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    error = None
    written = None if payload is None else 0
    try:
        deadline = time.monotonic() + 2
        if payload is not None:
            LAB.need(
                type(payload) is bytes and len(payload) <= 1024,
                "fixed Root frame bound",
            )
            written = os.write(process.stdin.fileno(), payload)
            LAB.need(written == len(payload), "short Root frame write")
        if not process.stdin.closed:
            process.stdin.close()
        streams = {process.stdout.fileno(): "stdout", process.stderr.fileno(): "stderr"}
        while streams:
            remaining = deadline - time.monotonic()
            LAB.need(remaining > 0, "worker reply absolute deadline")
            ready = select.select(list(streams), [], [], remaining)[0]
            LAB.need(ready, "worker reply missing")
            for fd in ready:
                target = buffers[streams[fd]]
                chunk = os.read(fd, min(16384, 65537 - len(target)))
                if not chunk:
                    del streams[fd]
                    continue
                target.extend(chunk)
                LAB.need(len(target) <= 65536, "worker reply retention bound")
        LAB.need(deadline > time.monotonic(), "worker wait budget exhausted")
        process.wait(timeout=deadline - time.monotonic())
    except BaseException as exc:
        error = exc
    finally:
        for name, raw in buffers.items():
            try:
                LAB.save(output / (prefix + "." + name), bytes(raw))
            except BaseException as exc:
                if error is None:
                    error = exc
                else:
                    error.add_note(
                        "Stream persistence failure: " + name + ":" + type(exc).__name__
                    )
        try:
            LAB.save_json(
                output / (prefix + ".result.json"),
                dict(
                    returncode=process.returncode,
                    error=type(error).__name__ if error else None,
                    requested_input_bytes=None if payload is None else len(payload),
                    written_input_bytes=written,
                ),
            )
        except BaseException as exc:
            if error is None:
                error = exc
            else:
                error.add_note(
                    "Reply receipt persistence failure: " + type(exc).__name__
                )
    if error is not None:
        raise error
    return bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _receive_ready(process, path):
    """Retain EVERY consumed byte, including the first offending bound byte."""
    raw = bytearray()
    deadline = time.monotonic() + 2
    try:
        while not raw.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            LAB.need(
                remaining > 0 and select.select([process.stdout], [], [], remaining)[0],
                "ready absolute deadline",
            )
            chunk = os.read(process.stdout.fileno(), 16385 - len(raw))
            raw.extend(chunk)
            LAB.need(chunk and len(raw) <= 16384, "missing/oversized ready receipt")
    finally:
        LAB.save(path, bytes(raw))


def _ready(process, mode, assets, baseline, output, tracked):
    counterparts = p.stdio_identity(process)
    _receive_ready(process, output / (mode + "-ready.raw"))
    raw = setup._read(output / (mode + "-ready.raw"), 16384)[0]
    source = setup._read(Path(p.worker_argv(mode)[3]))[0]
    ready = frames.parse_ready(
        raw,
        mode,
        boot=baseline["kernel_boot_id"],
        worker_sha256=hashlib.sha256(source).hexdigest(),
    )
    unit = C.role_spec(mode)["unit"]
    tracked[unit].append(LAB.unit_snapshot(unit))
    LAB.save_json(
        output / (mode + "-effective.json"), p.collect_effective(mode, output)
    )
    proof = p.collect_actor(
        mode,
        ready_identity={k: ready["identity"][k] for k in ("pid", "dumpable")},
        expected_namespace=_fenced(assets, mode),
        expected_stdio=counterparts,
        output=output,
    )
    LAB.need(
        json.dumps(proof["identity"], sort_keys=True)
        == json.dumps(ready["identity"], sort_keys=True),
        "actual kernel/ready identity differs",
    )
    LAB.need(process.poll() is None, "role exited before Root fence")
    return ready, proof


def _live_targets(proof, boot, output, label):
    evidence = {}
    try:
        evidence["state"] = LAB.unit_snapshot(C.role_spec("peer")["unit"])
        evidence["pid1_stat"] = p.cg._kernel_text("/proc/1/stat", 8192)
        evidence["boot"] = G.boot()
        pid = proof["identity"]["pid"]
        evidence["binfmt"] = {}
        p.binfmt_metadata(pid, evidence["binfmt"])
        for name in ("net", "mnt"):
            info = os.stat(f"/proc/{pid}/ns/" + name)
            evidence[name] = [info.st_dev, info.st_ino]
    finally:
        LAB.save_json(output / (label + "-live-targets.json"), evidence)
    old, new = proof["evidence"]["before"], evidence["state"]
    LAB.need(
        all(
            old[k] == new[k]
            for k in (
                "LoadState",
                "ActiveState",
                "MainPID",
                "ControlPID",
                "ControlGroup",
            )
        )
        and new["ActiveState"] == "active"
        and LAB.pid_identity(old["pid_stat"]) == LAB.pid_identity(new["pid_stat"])
        and all(
            evidence[k] == proof["evidence"]["namespaces"][k] for k in ("net", "mnt")
        )
        and evidence["boot"] == boot
        and evidence["binfmt"] == proof["evidence"]["binfmt_before"],
        "actual known-live peer/boot drift",
    )
    return evidence


def _namespace_empty(assets, output):
    residents = {}
    try:
        for mode, name in assets.names.items():
            _fenced(assets, mode)
            residents[name] = network.command(
                "ip", "netns", "pids", name, timeout=2
            ).stdout
    finally:
        LAB.save_json(output / "namespace-residents-before-close.json", residents)
    LAB.need(
        all(not value.strip() for value in residents.values()),
        "unknown namespace resident; retain names",
    )


def _close_namespace_fd(fd, device, inode):
    try:
        info = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return
        raise
    LAB.need(
        (info.st_dev, info.st_ino) == (device, inode),
        "namespace FD number reused; do not close foreign descriptor",
    )
    os.close(fd)


def _reap_client(process):
    """Bounded stop/reap of our Popen client only, never a unit/foreign PID."""
    proof = dict(
        pid=process.pid,
        scope="owned_Root_Popen_client_only",
        steps=[],
        errors=[],
        forced=False,
        reaped=False,
    )

    def step(name, call):
        try:
            value = call()
            proof["steps"].append(dict(operation=name, result=value))
            return True, value
        except BaseException as exc:
            proof["steps"].append(dict(operation=name, error=type(exc).__name__))
            proof["errors"].append(name + ":" + type(exc).__name__)
            return False, None

    ok, status = step("poll", process.poll)
    if not ok or status is None:
        proof["forced"] = True
        proof["errors"].append("client_still_running_or_unknown_after_drain")
        step("terminate", process.terminate)
    ok, status = step("wait", lambda: process.wait(timeout=1))
    if not ok:
        proof["forced"] = True
        step("kill", process.kill)
        ok, status = step("kill_wait", lambda: process.wait(timeout=1))
    proof["reaped"] = ok and type(status) is int
    proof["returncode"] = status
    return proof


def run(output):
    baseline = setup.stage(output)  # Stage handles its own pre-actor failures.
    assets = None
    processes = {}
    tracked = {unit: [] for unit in UNITS}
    error = None
    result = None
    try:
        work = _workspace(output, baseline)
        assets = network.Assets(work)
        assets.names = {mode: C.role_spec(mode)["namespace"] for mode in C.ROLES}
        for mode, name in assets.names.items():
            assets.create_namespace(name)
            _fenced(assets, mode)
            assets.ns(mode, "ip", "link", "set", "lo", "up")
        _fenced(assets, "probe")
        assets.ns("probe", "ip", "link", "add", "es", "type", "dummy")
        _fenced(assets, "probe")
        assets.ns("probe", "ip", "link", "set", "es", "up")
        for mode in C.ROLES:
            for family in ("-4", "-6"):
                _fenced(assets, mode)
                LAB.need(
                    not assets.ns(
                        mode, "ip", family, "route", "show", "default"
                    ).stdout.strip(),
                    "external namespace route",
                )
        ready = {}
        proofs = {}
        for mode in ("peer", "probe"):
            _fenced(assets, mode)
            processes[mode] = _launch(mode, output)
            ready[mode], proofs[mode] = _ready(
                processes[mode], mode, assets, baseline, output, tracked
            )
        C.validate_role_identity(
            proofs["probe"]["identity"], proofs["peer"]["identity"]
        )
        LAB.need(
            proofs["probe"]["evidence"]["namespaces"]["net"]
            != proofs["peer"]["evidence"]["namespaces"]["net"],
            "peer namespace not foreign",
        )
        LAB.need(
            proofs["probe"]["evidence"]["binfmt_before"]
            == proofs["peer"]["evidence"]["binfmt_before"],
            "roles see different binfmt endpoint identities",
        )
        before = _live_targets(
            proofs["peer"], baseline["kernel_boot_id"], output, "before"
        )
        peer = ready["peer"]
        payload = (
            json.dumps(
                dict(
                    pid=peer["identity"]["pid"],
                    tgid=peer["identity"]["tgid"],
                    address=peer["public_address"],
                    size=peer["public_size"],
                    kernel_boot_id=peer["kernel_boot_id"],
                ),
                sort_keys=True,
            ).encode()
            + b"\n"
        )
        LAB.save(output / "probe-input.raw", payload)
        stdout, stderr = _exchange(processes["probe"], payload, "probe-final", output)
        LAB.need(
            processes["probe"].returncode == 0 and stderr == b"",
            "actual probe did not finish cleanly",
        )
        observation = frames.validate_result(
            stdout, ready["probe"], peer_pid=peer["identity"]["pid"]
        )
        after = _live_targets(
            proofs["peer"], baseline["kernel_boot_id"], output, "after"
        )
        LAB.need(
            processes["peer"].poll() is None
            and LAB.pid_identity(before["pid1_stat"])
            == LAB.pid_identity(after["pid1_stat"]),
            "peer/PID1 no longer original live targets",
        )
        stdout, stderr = _exchange(processes["peer"], b"stop\n", "peer-final", output)
        LAB.need(
            processes["peer"].returncode == 0 and stderr == b"",
            "actual peer stop did not finish cleanly",
        )
        frames.validate_result(stdout, ready["peer"])
        result = dict(
            status="new_role_precheck_complete",
            scope="this_boot_self_process_threadgroup_observations",
            observations=observation,
            kernel_boot_id=baseline["kernel_boot_id"],
            authorizes_transition=False,
            experiment=False,
            production_admission=False,
            old_profile="previous_commissioning_blocked_result_not_retested",
        )
    except BaseException as exc:
        error = exc
    finally:
        cleanup_ok = True

        def attempt(name, call, *, critical=False):
            nonlocal error, cleanup_ok
            try:
                return call()
            except BaseException as exc:
                if critical:
                    cleanup_ok = False
                if error is None:
                    error = exc
                else:
                    error.add_note(name + ":" + type(exc).__name__)
                return None

        cleanup = attempt(
            "all fixed actor stops", lambda: LAB.cleanup(UNITS, tracked), critical=True
        )
        attempt(
            "all-actor proof",
            lambda: LAB.need(
                type(cleanup) is dict
                and cleanup.get("errors") == []
                and len(cleanup.get("units", [])) == 2
                and {row["unit"] for row in cleanup["units"]} == set(UNITS),
                "incomplete/unknown all-actor quiescence",
            ),
            critical=True,
        )
        attempt(
            "actor cleanup receipt",
            lambda: LAB.save_json(output / "actor-cleanup.json", cleanup),
            critical=True,
        )
        # Reap Root systemd-run clients and close every owned stream before namespace deletion.
        for mode, process in processes.items():
            attempt(
                mode + " client drain",
                lambda process=process, mode=mode: _exchange(
                    process, None, mode + "-cleanup", output
                ),
                critical=True,
            )
            reaped = attempt(
                mode + " owned client reap",
                lambda process=process: _reap_client(process),
                critical=True,
            )
            attempt(
                mode + " client reap receipt",
                lambda mode=mode, reaped=reaped: LAB.save_json(
                    output / (mode + "-client-reap.json"), reaped
                ),
                critical=True,
            )
            attempt(
                mode + " client clean reap proof",
                lambda reaped=reaped: LAB.need(
                    type(reaped) is dict
                    and reaped["reaped"]
                    and not reaped["forced"]
                    and reaped["errors"] == [],
                    "Root client needed forced or unknown reap; retain namespaces",
                ),
                critical=True,
            )
            for stream in (process.stdin, process.stdout, process.stderr):
                attempt("Root pipe close", stream.close, critical=True)
        if cleanup_ok and assets is not None:
            attempt(
                "owned namespace empty proof",
                lambda: _namespace_empty(assets, output),
                critical=True,
            )
        if cleanup_ok and assets is not None:
            attempt("owned namespace close", assets.close, critical=True)
        if assets is not None:
            for fd, device, inode in assets.created.values():
                attempt(
                    "owned namespace FD close",
                    lambda fd=fd, device=device, inode=inode: _close_namespace_fd(
                        fd, device, inode
                    ),
                    critical=True,
                )
        attempt(
            "Root invariant checks",
            lambda: setup.invariants(output, baseline, require_new=True),
        )
        if error is None:
            attempt(
                "final namespace absence",
                lambda: LAB.need(
                    all(
                        not os.path.lexists(
                            Path("/run/netns") / C.role_spec(mode)["namespace"]
                        )
                        for mode in C.ROLES
                    ),
                    "owned namespace remains",
                ),
            )
        if error is not None:
            attempt(
                "failed case receipt",
                lambda: LAB.save_json(
                    output / "failure.json",
                    dict(
                        status="blocked",
                        error=type(error).__name__,
                        notes=getattr(error, "__notes__", []),
                    ),
                ),
            )
    if error is not None:
        raise error
    LAB.save_json(output / "final-result.json", result)
    return result
