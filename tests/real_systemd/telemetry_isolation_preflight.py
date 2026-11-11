"""Root proof collectors ONLY; no worker/controller/installation/policy loading.

Callable only by later reviewed Root orchestration. Fixed paths/roles, no sampling
IPC, commands supplied by callers, secrets or transition/qualification receipts.
"""

# ruff: noqa: E402
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SRC / "py"), str(SRC / "tests"), str(Path(__file__).parent)]
import telemetry_isolation_contract as contract
import telemetry_preflight as old
import terminal_stop_lab as lab
import terminal_cgroup as cg
from azazel_edge.outcome.input_auth import open_parent, read_regular

EXTRA = {"ProtectProc", "ProcSubset", "MountAPIVFS"}
EFFECTIVE = (*old.EFFECTIVE, *sorted(EXTRA))
FEATURES = {
    "namespaces": "/sys/kernel/security/apparmor/features/namespaces/mask",
    "ptrace": "/sys/kernel/security/apparmor/features/ptrace/mask",
}
ABI = Path("/etc/apparmor.d/abi/4.0")


def canary_spec():
    """PUBLIC NONKEY bytes only; no creation/truncation, real key or bundle."""
    return [
        dict(path=str(path), mode=mode, data="PUBLIC-NONKEY-DENIAL-CANARY\n")
        for path, mode in (
            (old.g.BASE / "aa-denied", 0o644),
            (old.g.BASE / "root-key-canary", 0o644),
            (old.g.BUNDLE / "producer/key.raw", 0o644),
            (old.g.BUNDLE / "witness/key.raw", 0o644),
            (old.g.BUNDLE / "input", 0o666),
        )
    ]


def _output(output):
    lab.need(os.geteuid() == 0, "explicit Root collector required")
    parent, _ = open_parent(output / "proof", trusted_owner=0)
    try:
        info = os.fstat(parent)
        lab.need(
            info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            "protected Root output required",
        )
    finally:
        os.close(parent)


def collect_features(output, *, expected_abi_sha256):
    """Masks/ABI availability only; not compilation or effective deny proof."""
    _output(output)
    lab.need(
        type(expected_abi_sha256) is str
        and re.fullmatch("[0-9a-f]{64}", expected_abi_sha256),
        "external ABI pin required",
    )
    data = {}
    try:
        abi = read_regular(ABI, owner=0, max_bytes=65536)[0]
        lab.save(output / "abi4.raw", abi)
        data["abi_sha256"] = hashlib.sha256(abi).hexdigest()
        for name, path in FEATURES.items():
            data[name] = cg._kernel_text(path, 4096)
            lab.save(output / (name + "-mask.raw"), data[name].encode())
    finally:
        lab.save_json(output / "feature-metadata.json", data)
    lab.need(
        data["abi_sha256"] == expected_abi_sha256
        and "userns_create" in data["namespaces"].split()
        and {"read", "trace"} <= set(data["ptrace"].split()),
        "required ABI/mask metadata unavailable",
    )
    return data


def worker_argv(mode):
    contract.role_spec(mode)
    return [
        contract.ALIAS,
        "-I",
        "-B",
        str(Path(__file__).with_name("telemetry_isolation_worker.py").resolve()),
        "--worker",
        mode,
    ]


def validate_effective(value, mode):
    spec = contract.role_spec(mode)
    return _validate_effective(value, spec, worker_argv(mode))


def _validate_effective(value, spec, argv):
    """Private common check; callers expose only fixed role wrappers."""
    lab.need(set(value) == set(EFFECTIVE), "complete actual effective unit required")
    expected = dict(spec["properties"])
    runtime = expected.pop("RuntimeMaxSec")
    stop = expected.pop("TimeoutStopSec")
    expected.update(
        RuntimeMaxUSec=runtime + "s",
        TimeoutStopUSec=stop + "s",
        Slice="system.slice",
        DropInPaths="",
        FragmentPath="/run/systemd/transient/" + spec["unit"],
    )
    lab.need(
        all(value[k] == v for k, v in expected.items()), "actual role properties differ"
    )
    empty = (
        *old.HOOKS,
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
    )
    lab.need(
        all(value[k] == "" for k in empty)
        and set(value["Requires"].split()) <= {"system.slice"}
        and set(value["After"].split()) <= {"system.slice", "systemd-journald.socket"},
        "unexpected activation/hooks",
    )
    command = value["ExecStart"]
    lab.need(
        command.startswith("{ ")
        and command.endswith(" }")
        and command.count("{") == command.count("}") == 1,
        "ambiguous actual command",
    )
    rows = [part.partition("=") for part in command[2:-2].split(" ; ")]
    lab.need(
        all(sep for _, sep, _ in rows) and len({k for k, _, _ in rows}) == len(rows),
        "duplicate command field",
    )
    fields = {k: v for k, _, v in rows}
    lab.need(
        fields.get("path") == spec["alias"]
        and fields.get("argv[]") == " ".join(argv)
        and fields.get("ignore_errors") == "no",
        "actual worker command differs",
    )


def collect_effective(mode, output):
    _output(output)
    unit = contract.role_spec(mode)["unit"]
    value = _collect_effective(unit, mode, output)
    validate_effective(value, mode)
    return value


def _collect_effective(unit, prefix, output):
    """Private raw collection; public wrappers supply literal unit/prefix."""
    bus = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(
        ".", "_2e"
    )
    code, text = old._retained_query(
        ["systemctl", "show", unit, "--property=" + ",".join(EFFECTIVE)],
        prefix + "-effective-systemctl",
        output,
    )
    buscode, typed = old._retained_query(
        [
            "/usr/bin/busctl",
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            bus,
            "org.freedesktop.systemd1.Service",
            *old.HOOKS,
        ],
        prefix + "-effective-busctl",
        output,
    )
    lab.need(code == buscode == 0, "actual effective backend failed")
    rows = text.decode().splitlines()
    lab.need(all("=" in row for row in rows), "malformed effective property")
    pairs = [row.split("=", 1) for row in rows]
    extra = {k: v for k, v in pairs if k in EXTRA}
    lab.need(
        len(pairs) == len({k for k, _ in pairs}) and set(extra) == EXTRA,
        "duplicate/missing proc properties",
    )
    base = "\n".join(row for row in rows if row.split("=", 1)[0] not in EXTRA).encode()
    value = {**old.merged_effective(base, typed), **extra}
    return value


def stdio_identity(process):
    result = {}
    for fd, stream in enumerate((process.stdin, process.stdout, process.stderr)):
        info = os.fstat(stream.fileno())
        lab.need(stat.S_ISFIFO(info.st_mode), "Root stdio counterpart is not FIFO")
        result[fd] = dict(device=info.st_dev, inode=info.st_ino)
    return result


def binfmt_metadata(pid, evidence):
    """Fixed Root stat-only endpoints through actual actor root; never controls."""
    lab.need(type(pid) is int and 1 < pid < 2**31, "actual endpoint PID required")
    for name in ("status", "register"):
        info = os.stat(
            f"/proc/{pid}/root" + contract.BINFMT + "/" + name, follow_symlinks=False
        )
        evidence[name] = dict(
            device=info.st_dev,
            inode=info.st_ino,
            mode=info.st_mode,
            uid=info.st_uid,
            gid=info.st_gid,
        )
        lab.need(
            stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0,
            "actual root-owned regular binfmt endpoint required",
        )
    return evidence


def collect_actor(mode, *, ready_identity, expected_namespace, expected_stdio, output):
    """Original Root kernel metadata at ready fence; no probe or sample IPC."""
    _output(output)
    unit = contract.role_spec(mode)["unit"]
    return _collect_actor(
        unit,
        mode,
        ready_identity=ready_identity,
        expected_namespace=expected_namespace,
        expected_stdio=expected_stdio,
        output=output,
        proc_validator=contract.validate_proc_view,
    )


def _collect_actor(
    unit,
    prefix,
    *,
    ready_identity,
    expected_namespace,
    expected_stdio,
    output,
    proc_validator,
):
    """Private common metadata collection; no public arbitrary role/spec selector."""
    evidence = dict(
        scope="root_metadata_not_isolation_qualification",
        ready_identity=ready_identity,
        expected_namespace=expected_namespace,
        expected_stdio=expected_stdio,
    )
    try:
        before = lab.unit_snapshot(unit)
        evidence["before"] = before
        pid = before.get("MainPID")
        lab.need(
            type(pid) is str
            and re.fullmatch("[1-9][0-9]{0,9}", pid)
            and 1 < int(pid) < 2**31,
            "canonical actual MainPID required",
        )
        root = "/proc/" + pid
        raw = {}
        for name, path, limit in (
            ("status", root + "/status", 65536),
            ("label", root + "/attr/apparmor/current", 4096),
            ("cgroup", root + "/cgroup", 4096),
            ("mountinfo", root + "/mountinfo", 1024 * 1024),
        ):
            raw[name] = cg._kernel_text(path, limit)
            lab.save(output / (prefix + "-" + name + ".raw"), raw[name].encode())
        evidence["raw"] = raw
        evidence["binfmt_before"] = {}
        binfmt_metadata(int(pid), evidence["binfmt_before"])
        namespaces = {}
        for name, path in (
            ("net", root + "/ns/net"),
            ("mnt", root + "/ns/mnt"),
            ("pid1_mnt", "/proc/1/ns/mnt"),
        ):
            info = os.stat(path)
            namespaces[name] = [info.st_dev, info.st_ino]
        evidence["namespaces"] = namespaces
        info = os.stat(root + "/root/proc")
        evidence["proc_device"] = [os.major(info.st_dev), os.minor(info.st_dev)]
        info = os.stat(root)
        evidence["proc_owner"] = [info.st_uid, info.st_gid]
        names = []
        with os.scandir(root + "/fd") as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > 64:
                    break
        evidence["fd_names"] = names
        lab.need(
            len(names) <= 64 and all(re.fullmatch("[0-9]+", v) for v in names),
            "unknown/big descriptor inventory",
        )
        evidence["fds"] = []
        for name in sorted(names, key=int):
            path = root + "/fd/" + name
            info = os.stat(path)
            evidence["fds"].append(
                dict(
                    fd=int(name),
                    device=info.st_dev,
                    inode=info.st_ino,
                    mode=info.st_mode,
                    target=os.readlink(path),
                )
            )
        evidence["binfmt_after"] = {}
        binfmt_metadata(int(pid), evidence["binfmt_after"])
        evidence["after"] = lab.unit_snapshot(unit)
        evidence["namespace_after"] = {}
        for name, path in (
            ("net", root + "/ns/net"),
            ("mnt", root + "/ns/mnt"),
            ("pid1_mnt", "/proc/1/ns/mnt"),
        ):
            info = os.stat(path)
            evidence["namespace_after"][name] = [info.st_dev, info.st_ino]
    finally:
        lab.save_json(output / (prefix + "-actor-proof.json"), evidence)
    after = evidence["after"]
    lab.need(
        evidence["binfmt_before"] == evidence["binfmt_after"], "binfmt endpoint drift"
    )
    lab.need(
        all(
            before[k] == after[k]
            for k in (
                "LoadState",
                "ActiveState",
                "MainPID",
                "ControlPID",
                "ControlGroup",
            )
        )
        and before["LoadState"] == "loaded"
        and before["ActiveState"] == "active"
        and before["ControlPID"] == "0"
        and before["ControlGroup"] == "/system.slice/" + unit
        and lab.pid_identity(before["pid_stat"]) == lab.pid_identity(after["pid_stat"])
        and lab.pid_identity(before["pid_stat"])[0] == pid,
        "actual unit/PID identity drift",
    )
    rows = [line.split(":", 1) for line in raw["status"].splitlines()]
    lab.need(
        all(len(row) == 2 for row in rows)
        and len({row[0] for row in rows}) == len(rows),
        "ambiguous kernel status",
    )
    status = dict(rows)
    lab.need(
        status["Uid"].split() == status["Gid"].split() == ["61002"] * 4
        and set(ready_identity) == {"pid", "dumpable"}
        and type(ready_identity["pid"]) is int
        and ready_identity["pid"] == int(pid)
        and evidence["proc_owner"] == [61002, 61002],
        "actual credentials/ready/dumpability owner differs",
    )
    actual = dict(
        pid=int(status["Pid"]),
        tgid=int(status["Tgid"]),
        uid=61002,
        gid=61002,
        groups=[int(v) for v in status["Groups"].split()],
        apparmor=raw["label"].strip(),
        no_new_privs=status["NoNewPrivs"].strip() == "1",
        dumpable=ready_identity["dumpable"],
        **{
            key: int(status[field], 16)
            for key, field in (
                ("cap_eff", "CapEff"),
                ("cap_prm", "CapPrm"),
                ("cap_amb", "CapAmb"),
                ("cap_bnd", "CapBnd"),
            )
        },
    )
    contract.validate_role_identity(actual)
    lab.need(
        actual["pid"] == int(pid)
        and raw["cgroup"] == "0::/system.slice/" + unit + "\n"
        and namespaces["net"] == list(contract._pair(expected_namespace))
        and all(
            evidence["namespace_after"][k] == namespaces[k]
            for k in ("net", "mnt", "pid1_mnt")
        ),
        "actual namespace/cgroup drift",
    )
    proc_validator(
        raw["mountinfo"],
        own_mount_ns=namespaces["mnt"],
        pid1_mount_ns=namespaces["pid1_mnt"],
        proc_device=evidence["proc_device"],
    )
    contract.validate_pipe_fds(evidence["fds"], expected_stdio)
    return dict(identity=actual, evidence=evidence)
