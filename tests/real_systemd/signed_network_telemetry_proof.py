"""Fixed Root pre-API metadata collector ONLY; no launch, GO or admission API.

The compared worker argv is reserved until a separately reviewed worker exists.
READY is an untrusted claim; actual Root metadata supplies the independent binding.
"""

# ruff: noqa: E402
import hashlib
import json
import os
from pathlib import Path
import re
import select
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
import signed_network_telemetry_contract as contract
import telemetry_isolation_contract as legacy
import telemetry_isolation_preflight as p

lab = p.lab


def reserved_argv(mode):
    contract.observer_spec(mode)
    return [
        contract.ALIAS,
        "-I",
        "-B",
        contract.SOURCE,
        "--worker",
        mode,
        contract.CLI_FLAG,
    ]


def _pairs(rows):
    value = {}
    for key, item in rows:
        lab.need(key not in value, "duplicate READY key")
        value[key] = item
    return value


def parse_ready(raw, mode, *, kernel_boot_id, source_sha256):
    contract.observer_spec(mode)
    lab.boot_reference(kernel_boot_id)
    lab.need(
        type(source_sha256) is str and re.fullmatch("[0-9a-f]{64}", source_sha256),
        "external source digest required",
    )
    lab.need(
        type(raw) is bytes
        and len(raw) <= 16384
        and raw.endswith(b"\n")
        and raw.count(b"\n") == 1,
        "single bounded READY required",
    )
    value = json.loads(
        raw,
        object_pairs_hook=_pairs,
        parse_constant=lambda _: lab.need(False, "nonfinite READY"),
    )
    lab.need(
        type(value) is dict
        and set(value)
        == {
            "kind",
            "role",
            "mode",
            "identity",
            "kernel_boot_id",
            "source",
            "source_sha256",
        },
        "exact READY schema required",
    )
    lab.need(
        value["kind"] == contract.READY_KIND
        and value["role"] == contract.ROLE
        and value["mode"] == mode
        and value["kernel_boot_id"] == kernel_boot_id
        and value["source"] == contract.SOURCE
        and value["source_sha256"] == source_sha256,
        "READY context differs",
    )
    legacy.validate_role_identity(value["identity"])
    return value


def _receive_ready(process, path):
    """Persist consumed bounded prefix even on failure; keep original stdin open."""
    raw = bytearray()
    try:
        deadline = time.monotonic() + 2
        while not raw.endswith(b"\n"):
            remaining = deadline - time.monotonic()
            lab.need(remaining > 0, "PREAPI READY deadline")
            lab.need(
                select.select([process.stdout], [], [], remaining)[0], "missing READY"
            )
            chunk = os.read(process.stdout.fileno(), 16385 - len(raw))
            raw.extend(chunk)
            lab.need(len(raw) <= 16384 and chunk, "READY overflow/EOF")
        return bytes(raw)
    finally:
        lab.save(path, bytes(raw))


def _proc_view(raw, **kwargs):
    return legacy._validate_proc_view(
        raw, nsfs_targets=set(contract.NSFS_TARGETS), **kwargs
    )


def _namespaces():
    result = {}
    for path in contract.NSFS_TARGETS:
        info = os.stat(path, follow_symlinks=False)
        lab.need(p.stat.S_ISREG(info.st_mode), "regular namespace object required")
        result[path] = [info.st_dev, info.st_ino]
    return result


def _bind_nsfs(raw, handles):
    """Require every literal named handle in the actor's actual nsfs mount rows.

    A regular file by itself is not a namespace proof. The already structurally
    validated actor mountinfo must independently supply matching device/inode.
    Duplicate systemd bind rows are allowed only when every row still matches.
    """
    lab.need(
        set(handles) == set(contract.NSFS_TARGETS), "exact namespace handles required"
    )
    seen = set()
    for row in raw.splitlines():
        fields = row.split()
        if " - nsfs " in row:
            lab.need(len(fields) >= 10 and fields[4] in handles, "unknown nsfs target")
            device, inode = handles[fields[4]]
            lab.need(
                fields[2] == str(os.major(device)) + ":" + str(os.minor(device))
                and fields[3] == "net:[" + str(inode) + "]",
                "actual nsfs handle differs",
            )
            seen.add(fields[4])
    lab.need(
        seen == set(contract.NSFS_TARGETS), "all three actual nsfs targets required"
    )


def collect_pre_api(
    mode, process, *, expected_namespace, kernel_boot_id, source_sha256, output
):
    """Read only at original three-FIFO fence; never writes GO or opens an API.

    Caller supplies the independently owned EDGE namespace and frozen source pin.
    This proves sampled Root metadata, not worker negative probes/API operation,
    cryptographic observer-label binding, isolation qualification or admission.
    """
    spec = contract.observer_spec(mode)
    p.old.g.guard()
    p._output(output)
    lab.need(
        os.environ.get("EDGE_SIGNED_NETWORK_TELEMETRY") == "1",
        "explicit v2 opt-in required",
    )
    lab.boot_reference(kernel_boot_id)
    lab.need(
        type(source_sha256) is str and re.fullmatch("[0-9a-f]{64}", source_sha256),
        "external source digest required",
    )
    expected_namespace = list(legacy._pair(expected_namespace))
    evidence = dict(
        scope="root_pre_api_metadata_only",
        mode=mode,
        kernel_boot_id=kernel_boot_id,
        source_sha256=source_sha256,
        reserved_argv=reserved_argv(mode),
    )
    try:
        source, _ = p.read_regular(
            Path(contract.SOURCE), owner=0, max_bytes=1024 * 1024
        )
        evidence["observed_source_sha256"] = hashlib.sha256(source).hexdigest()
        evidence["observed_kernel_boot_id"] = p.old.g.boot()
        lab.need(
            evidence["observed_source_sha256"] == source_sha256
            and evidence["observed_kernel_boot_id"] == kernel_boot_id,
            "actual source/boot differs",
        )
        stdio = p.stdio_identity(process)
        evidence["namespaces_before"] = _namespaces()
        lab.need(
            evidence["namespaces_before"][contract.NSFS_TARGETS[0]]
            == expected_namespace,
            "owned EDGE handle differs",
        )
        raw = _receive_ready(process, output / (mode + "-pre-api-ready.raw"))
        ready = parse_ready(
            raw, mode, kernel_boot_id=kernel_boot_id, source_sha256=source_sha256
        )
        effective = p._collect_effective(spec["unit"], mode, output)
        p._validate_effective(effective, spec, reserved_argv(mode))
        actor = p._collect_actor(
            spec["unit"],
            mode,
            ready_identity={k: ready["identity"][k] for k in ("pid", "dumpable")},
            expected_namespace=expected_namespace,
            expected_stdio=stdio,
            output=output,
            proc_validator=_proc_view,
        )
        lab.need(
            actor["identity"] == ready["identity"], "actual READY identity differs"
        )
        evidence["namespaces_after"] = _namespaces()
        _bind_nsfs(actor["evidence"]["raw"]["mountinfo"], evidence["namespaces_before"])
        source_after, _ = p.read_regular(
            Path(contract.SOURCE), owner=0, max_bytes=1024 * 1024
        )
        lab.need(
            source_after == source
            and p.old.g.boot() == kernel_boot_id
            and evidence["namespaces_before"] == evidence["namespaces_after"]
            and process.poll() is None
            and not process.stdin.closed
            and p.stdio_identity(process) == stdio,
            "PREAPI fence/source/namespace drift",
        )
        return dict(ready=ready, effective=effective, actor=actor, metadata=evidence)
    finally:
        lab.save_json(output / (mode + "-pre-api-root-proof.json"), evidence)
