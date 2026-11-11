"""Fixed manual Root initializer caller, independent of a four-run manifest.

Outer fresh-scope provisioning owns witness/core and namespaces. This helper owns
only its fixed initializer unit/client; no installation, key creation or trial.
Root must authenticate the complete source archive and supply independent pins.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time

import signed_network_plan as plan
import signed_network_observer as observer
import signed_network_telemetry_contract as role
import signed_network_telemetry_material as material
from signed_network_telemetry_binding import public_auth_binding
import signed_network_telemetry_proof as proof
import signed_network_scope as scope
from telemetry_isolation_controller import _reap_client

lab, g = proof.lab, plan.g


def _namespace(fd, expected):
    expected = tuple(proof.legacy._pair(expected))
    lab.need(type(fd) is int and fd >= 0, "owned EDGE descriptor required")
    lab.need(
        not os.get_inheritable(fd), "parent-only CLOEXEC namespace descriptor required"
    )
    opened = os.fstat(fd)
    named = os.stat(role.NSFS_TARGETS[0], follow_symlinks=False)
    lab.need(
        (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino) == expected
        and stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(named.st_mode)
        and opened.st_uid == named.st_uid == 0,
        "owned EDGE identity differs",
    )
    return list(expected)


def _drain(process, output, deadline, prefix="initialization"):
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    error = None
    try:
        streams = {process.stdout.fileno(): "stdout", process.stderr.fileno(): "stderr"}
        while streams:
            remaining = deadline - time.monotonic()
            lab.need(remaining > 0, "initializer 20-second client deadline")
            ready = select.select(list(streams), [], [], remaining)[0]
            lab.need(ready, "initializer reply deadline")
            for fd in ready:
                target = buffers[streams[fd]]
                chunk = os.read(fd, min(16384, 65537 - len(target)))
                target.extend(chunk)
                lab.need(len(target) <= 65536, "initializer reply bound")
                if not chunk:
                    del streams[fd]
        lab.need(deadline > time.monotonic(), "initializer wait budget exhausted")
        process.wait(timeout=deadline - time.monotonic())
    except BaseException as exc:
        error = exc
    finally:
        for name, raw in buffers.items():
            try:
                lab.save(output / (prefix + "." + name), bytes(raw))
            except BaseException as exc:
                if error is None:
                    error = exc
                else:
                    error.add_note(
                        "stream persistence: " + name + ":" + type(exc).__name__
                    )
        try:
            lab.save_json(
                output / (prefix + "-client.json"),
                dict(
                    returncode=process.returncode,
                    error=type(error).__name__ if error else None,
                ),
            )
        except BaseException as exc:
            if error is None:
                error = exc
            else:
                error.add_note("client receipt persistence: " + type(exc).__name__)
    if error is not None:
        raise error
    return {name: bytes(raw) for name, raw in buffers.items()}


def prelaunch_unit_material(mode, output):
    """Reject every applicable on-disk override BEFORE a fixed role can start.

    Closed initializer/live specs only; this helper launches no actor or GO.
    Actual lookup output and errors are retained before strict path validation.
    """
    unit = role.observer_spec(mode)["unit"]
    output = Path(output)
    proof.p._output(output)
    code, raw = proof.p.old._retained_query(
        ["systemd-analyze", "unit-paths"], mode + "-launch-unit-paths", output
    )
    stderr = material._read(output / (mode + "-launch-unit-paths.stderr"), 4096)
    lab.need(
        code == 0
        and 0 < len(raw) <= 16384
        and raw.endswith(b"\n")
        and b"\r" not in raw
        and stderr == b"",
        "actual bounded unit paths unavailable",
    )
    rows = raw.decode("ascii").splitlines()
    lab.need(
        0 < len(rows) <= 128 and len(set(rows)) == len(rows),
        "duplicate/malformed unit paths",
    )
    names = {
        "service.d",
        *(unit + suffix for suffix in ("", ".d", ".wants", ".requires", ".upholds")),
    }
    parts = unit.removesuffix(".service").split("-")
    names.update("-".join(parts[:i]) + "-.service.d" for i in range(1, len(parts)))
    for row in rows:
        parent = Path(row)
        lab.need(
            re.fullmatch(r"/[A-Za-z0-9_.@/-]+", row)
            and str(parent) == row
            and "//" not in row
            and all(p not in (".", "..") for p in parent.parts),
            "malformed actual unit search path",
        )
        for name in sorted(names):
            lab.need(
                not os.path.lexists(parent / name),
                "preexisting inherited fixed-role unit material refused",
            )
    return rows


def _current_binding(*, current, namespace, source_sha256, kernel):
    """Fixed shared lab metadata only; callers independently verify inputs.

    No dynamic role/path selectors or cryptographic scope/label claim. Return
    policy bytes too so callers can refuse a change before their literal GO.
    """
    policy_raw = material._read(plan.POLICY_PATH, 8192)
    payload = plan.strict(policy_raw)
    binding = dict(
        role=role.ROLE,
        kernel_boot_id=kernel,
        namespace=namespace,
        observer_source_sha256=source_sha256,
        material=current,
        public_auth=public_auth_binding(),
        roles={mode: role.observer_spec(mode) for mode in ("initialize", "live")},
        policy_file_sha256=hashlib.sha256(policy_raw).hexdigest(),
        policy_sha256=plan.manifest_digest(payload),
    )
    return binding, policy_raw


def initialize(
    output,
    *,
    abi_sha256,
    interpreter_sha256,
    source_sha256,
    expected_sources,
    namespace_fd,
    namespace_identity,
):
    """Run one unused-scope initializer; all inputs are Root-pinned lab context.

    No manifest is required. No receipt/file existence substitutes for successful
    current checks. Caller must already own a fresh scope and live witness, and
    must stop/prove all outer actors before namespace cleanup on ANY failure.
    Outer fresh provisioning must already make BASE traversable (intended0755)
    with creation provenance. This helper never repairs a used directory/mode.
    """
    g.guard()
    material.pin(source_sha256)
    current = material.verify_current(
        abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
    )
    lab.need(
        type(expected_sources) is dict
        and expected_sources == current["source_sha256"]
        and current["source_sha256"][str(Path(role.SOURCE).relative_to(material.SRC))]
        == source_sha256,
        "independently frozen current source pins differ",
    )
    output = Path(output)
    proof.p._output(output)
    namespace = _namespace(namespace_fd, namespace_identity)
    unit = role.INITIALIZER_UNIT
    prelaunch_unit_material("initialize", output)
    lab.need(
        scope._known_collected(scope._state(unit))
        and lab.cg.group_empty("/system.slice/" + unit, (unit,)),
        "existing initializer refused",
    )
    kernel = g.boot()
    lab.boot_reference(kernel)
    binding, policy_raw = _current_binding(
        current=current, namespace=namespace, source_sha256=source_sha256, kernel=kernel
    )
    argv = observer.role_argv("initialize", telemetry_lab_v2=True)
    lab.save_json(output / "initializer-intent.json", dict(argv=argv, binding=binding))
    process, error, result, verified = None, None, None, None
    tracked = {unit: []}
    try:
        deadline = time.monotonic() + 20
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        verified = proof.collect_pre_api(
            "initialize",
            process,
            expected_namespace=namespace,
            kernel_boot_id=kernel,
            source_sha256=source_sha256,
            output=output,
        )
        lab.need(
            type(verified) is dict
            and set(verified) == {"ready", "effective", "actor", "metadata"}
            and all(type(v) is dict and v for v in verified.values()),
            "complete verified Root bundle required",
        )
        tracked[unit].append(verified["actor"]["evidence"]["before"])
        _namespace(namespace_fd, namespace_identity)
        lab.need(
            material.verify_current(
                abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
            )
            == current,
            "material changed before GO",
        )
        lab.need(
            g.boot() == kernel and material._read(plan.POLICY_PATH, 8192) == policy_raw,
            "boot/policy changed before GO",
        )
        auth_before_go = public_auth_binding()
        lab.save_json(output / "initializer-public-auth-before-go.json", auth_before_go)
        lab.need(
            auth_before_go == binding["public_auth"],
            "public auth context changed before GO",
        )
        lab.save_json(
            output / "initializer-verified-bundle.json",
            dict(
                proof=verified,
                binding=binding,
                binding_sha256=plan.manifest_digest(binding),
            ),
        )
        lab.need(
            select.select([], [process.stdin], [], 2)[1],
            "initializer GO write deadline",
        )
        count = os.write(process.stdin.fileno(), role.GO)
        lab.need(count == len(role.GO), "initializer short GO write")
        process.stdin.close()
        raw = _drain(process, output, deadline)
        lab.need(
            process.returncode == 0 and raw["stderr"] == b"",
            "actual initializer failed",
        )
        value = plan.strict(raw["stdout"])
        lab.need(
            type(value) is dict
            and set(value)
            == {
                "initialized_empty",
                "identity",
                "kernel_boot_id",
                "boot_ref",
                "policy_sha256",
                "policy_file_sha256",
            }
            and value["initialized_empty"] is True
            and json.dumps(value["identity"], sort_keys=True)
            == json.dumps(verified["ready"]["identity"], sort_keys=True)
            and value["kernel_boot_id"] == kernel
            and value["boot_ref"] == plan.n.boot_reference(kernel)
            and value["policy_sha256"] == binding["policy_sha256"]
            and value["policy_file_sha256"] == binding["policy_file_sha256"],
            "genuine unchanged empty initialization result required",
        )
        auth_after_init = public_auth_binding()
        lab.save_json(
            output / "initializer-public-auth-after-init.json", auth_after_init
        )
        lab.need(
            auth_after_init == binding["public_auth"],
            "public auth context changed after initialization",
        )
        result = dict(
            initialization=value,
            binding=binding,
            proof=verified,
            authorizes_transition=False,
            experiment=False,
            production_admission=False,
        )
    except BaseException as exc:
        error = exc
    finally:

        def attempt(name, operation):
            nonlocal error
            try:
                return operation()
            except BaseException as exc:
                if error is None:
                    error = exc
                else:
                    error.add_note(name + ":" + type(exc).__name__)

        cleanup = attempt(
            "fixed initializer stop/proof", lambda: lab.cleanup((unit,), tracked)
        )
        attempt(
            "cleanup receipt",
            lambda: lab.save_json(output / "initializer-cleanup.json", cleanup),
        )
        attempt(
            "cleanup proof",
            lambda: lab.need(
                type(cleanup) is dict and cleanup.get("errors") == [],
                "initializer cleanup incomplete",
            ),
        )
        if process is not None:
            attempt(
                "owned client residual streams",
                lambda: _drain(
                    process,
                    output,
                    time.monotonic() + 2,
                    prefix="initializer-cleanup-streams",
                ),
            )
            reaped = attempt("owned client reap", lambda: _reap_client(process))
            attempt(
                "reap receipt",
                lambda: lab.save_json(output / "initializer-client-reap.json", reaped),
            )
            attempt(
                "reap proof",
                lambda: lab.need(
                    type(reaped) is dict
                    and reaped.get("reaped") is True
                    and reaped.get("forced") is False
                    and reaped.get("errors") == [],
                    "initializer client not cleanly reaped",
                ),
            )
            for stream in (process.stdin, process.stdout, process.stderr):
                attempt("owned pipe close", stream.close)
    if error is not None:
        raise error
    lab.save_json(output / "initializer-result.json", result)
    return result
