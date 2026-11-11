"""Mocked Root collectors + pure fixtures only; no actual role/LSM qualification."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import os
import stat
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_preflight as p


def effective(mode="probe"):
    value = dict.fromkeys(p.EFFECTIVE, "")
    spec = p.contract.role_spec(mode)
    value.update(spec["properties"])
    value.pop("RuntimeMaxSec")
    value.pop("TimeoutStopSec")
    value.update(
        RuntimeMaxUSec="15s",
        TimeoutStopUSec="3s",
        Slice="system.slice",
        FragmentPath="/run/systemd/transient/" + spec["unit"],
        ExecStart="{ path="
        + p.contract.ALIAS
        + " ; argv[]="
        + " ".join(p.worker_argv(mode))
        + " ; ignore_errors=no }",
    )
    return value


def test_future_command_and_actual_properties_fixed_to_each_literal_role():
    assert not hasattr(p, "run") and not hasattr(p, "worker")
    for role in ("probe", "peer"):
        p.validate_effective(effective(role), role)
        assert p.worker_argv(role)[-2:] == ["--worker", role]
    with pytest.raises(ValueError):
        p.worker_argv("../../other")


@pytest.mark.parametrize(
    "field,value",
    [
        ("ProtectProc", "default"),
        ("ProcSubset", "pid"),
        ("MountAPIVFS", "no"),
        ("AppArmorProfile", "edge400-observer"),
        ("CapabilityBoundingSet", "cap_sys_ptrace"),
        ("ExecStartPre", "ignored"),
        ("Wants", "other.service"),
        ("Restart", "always"),
        ("DropInPaths", "/foreign"),
        ("ExecStart", "/usr/bin/true"),
    ],
)
def test_effective_setting_drift_blocks(field, value):
    actual = effective()
    actual[field] = value
    with pytest.raises((AssertionError, ValueError)):
        p.validate_effective(actual, "probe")


def test_collected_typed_backends_retained_before_missing_hook_refusal(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(p, "_output", lambda output: None)
    value = effective()
    text = "\n".join(
        k + "=" + v for k, v in value.items() if k not in p.old.HOOKS
    ).encode()
    typed = (
        b"\n".join(
            json.dumps(dict(type="a(sasbttttuii)", data=[])).encode()
            for _ in p.old.HOOKS
        )
        + b"\n"
    )
    results = iter(
        [
            SimpleNamespace(returncode=0, stdout=text, stderr=b""),
            SimpleNamespace(returncode=0, stdout=typed, stderr=b""),
        ]
    )
    monkeypatch.setattr(p.old.subprocess, "run", lambda *a, **k: next(results))
    assert p.collect_effective("probe", tmp_path)["ProtectProc"] == "ptraceable"
    assert (tmp_path / "probe-effective-systemctl.stdout").read_bytes() == text
    assert (tmp_path / "probe-effective-busctl.stdout").read_bytes() == typed
    bad = tmp_path / "bad"
    bad.mkdir()
    results = iter(
        [
            SimpleNamespace(returncode=0, stdout=text, stderr=b""),
            SimpleNamespace(returncode=0, stdout=b"", stderr=b"original error"),
        ]
    )
    with pytest.raises(AssertionError):
        p.collect_effective("peer", bad)
    assert (bad / "peer-effective-busctl.stderr").read_bytes() == b"original error"


def state(start="10"):
    return dict(
        LoadState="loaded",
        ActiveState="active",
        MainPID="123",
        ControlPID="0",
        ControlGroup="/system.slice/" + p.contract.ROLES["probe"][0],
        pid_stat="123 (worker) " + " ".join(["S"] + ["0"] * 18 + [start]),
    )


def actor_fixture(tmp_path, monkeypatch, fault=None):
    monkeypatch.setattr(p, "_output", lambda output: None)
    before, after = state(), state()
    if fault == "pidreuse":
        after = state("11")
    if fault == "unitdrift":
        after["MainPID"] = "124"
    snapshots = iter([before, after])
    monkeypatch.setattr(p.lab, "unit_snapshot", lambda unit: deepcopy(next(snapshots)))
    unit = p.contract.ROLES["probe"][0]
    status = (
        "\n".join(
            [
                "Pid:\t123",
                "Tgid:\t123",
                "Uid:\t61002 61002 61002 61002",
                "Gid:\t61002 61002 61002 61002",
                "Groups:\t61002",
                "NoNewPrivs:\t1",
                "CapEff:\t0",
                "CapPrm:\t0",
                "CapAmb:\t0",
                "CapBnd:\t0",
            ]
        )
        + "\n"
    )
    texts = {
        "/proc/123/status": status,
        "/proc/123/attr/apparmor/current": p.contract.PROFILE + " (enforce)\n",
        "/proc/123/cgroup": "0::/system.slice/" + unit + "\n",
        "/proc/123/mountinfo": "30 1 0:4 / /proc rw - proc proc rw,hidepid=ptraceable\n",
    }
    if fault == "oldlabel":
        texts["/proc/123/attr/apparmor/current"] = "edge400-observer (enforce)\n"
    if fault == "permissiveproc":
        texts["/proc/123/mountinfo"] = texts["/proc/123/mountinfo"].replace(
            "ptraceable", "2"
        )
    if fault == "cgroup":
        texts["/proc/123/cgroup"] = "0::/other\n"
    monkeypatch.setattr(p.cg, "_kernel_text", lambda path, limit: texts[path])
    ns_reads = {}

    def metadata(path):
        ns_reads[path] = ns_reads.get(path, 0) + 1
        if path.endswith("/ns/net"):
            return SimpleNamespace(
                st_dev=5, st_ino=21 if fault == "nsdrift" and ns_reads[path] > 1 else 20
            )
        if path.endswith("/ns/mnt"):
            return SimpleNamespace(st_dev=5, st_ino=10 if "123" in path else 11)
        if path.endswith("/root/proc"):
            return SimpleNamespace(st_dev=os.makedev(0, 4))
        if path == "/proc/123":
            return SimpleNamespace(
                st_uid=0 if fault == "nondumpable" else 61002, st_gid=61002
            )
        fd = int(path.rsplit("/", 1)[1])
        if fault == "fdmissing":
            raise FileNotFoundError("original FD gone")
        return SimpleNamespace(
            st_dev=16,
            st_ino=100 + fd,
            st_mode=stat.S_IFREG if fault == "foreignfd" else stat.S_IFIFO,
        )

    class Entries:
        def __enter__(self):
            return iter(
                SimpleNamespace(name=str(n))
                for n in range(4 if fault == "extrafd" else 3)
            )

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        p,
        "os",
        SimpleNamespace(
            stat=metadata,
            major=os.major,
            minor=os.minor,
            readlink=lambda path: "pipe:["
            + str(100 + int(path.rsplit("/", 1)[1]))
            + "]",
            scandir=lambda path: Entries(),
        ),
    )
    expected = {fd: dict(device=16, inode=100 + fd) for fd in range(3)}
    return dict(
        mode="probe",
        ready_identity=dict(pid=123, dumpable=1),
        expected_namespace=(5, 20),
        expected_stdio=expected,
        output=tmp_path,
    ), texts


def test_actual_root_metadata_fixture_preserves_originals_without_qualification(
    tmp_path, monkeypatch
):
    args, texts = actor_fixture(tmp_path, monkeypatch)
    result = p.collect_actor(**args)
    assert result["identity"]["uid"] == 61002 and result["identity"]["dumpable"] == 1
    assert result["evidence"]["scope"] == "root_metadata_not_isolation_qualification"
    assert (
        json.loads((tmp_path / "probe-actor-proof.json").read_bytes())["before"]
        == state()
    )
    assert (tmp_path / "probe-mountinfo.raw").read_text() == texts[
        "/proc/123/mountinfo"
    ]


@pytest.mark.parametrize(
    "fault",
    [
        "pidreuse",
        "unitdrift",
        "oldlabel",
        "permissiveproc",
        "cgroup",
        "nsdrift",
        "nondumpable",
        "foreignfd",
        "extrafd",
        "fdmissing",
    ],
)
def test_actor_collection_gap_retains_raw_before_refusal(tmp_path, monkeypatch, fault):
    args, texts = actor_fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, ValueError, FileNotFoundError)):
        p.collect_actor(**args)
    retained = json.loads((tmp_path / "probe-actor-proof.json").read_bytes())
    assert retained["before"] == state() and "qualification" in retained["scope"]
    assert (tmp_path / "probe-status.raw").read_text() == texts["/proc/123/status"]


def test_actual_ready_dumpable_report_is_not_replaced_by_root_metadata(
    tmp_path, monkeypatch
):
    args, _ = actor_fixture(tmp_path, monkeypatch)
    args["ready_identity"]["dumpable"] = 0
    with pytest.raises(ValueError):
        p.collect_actor(**args)
    assert (tmp_path / "probe-actor-proof.json").exists()


@pytest.mark.parametrize("fault", [None, "missingclass", "wrongabi"])
def test_current_feature_masks_and_abi_retained_not_deny_enforcement(
    tmp_path, monkeypatch, fault
):
    monkeypatch.setattr(p, "_output", lambda output: None)
    raw = b"public ABI4 fixture\n"
    monkeypatch.setattr(p, "read_regular", lambda *a, **k: (raw, None))
    masks = {
        p.FEATURES["namespaces"]: "userns_create\n",
        p.FEATURES["ptrace"]: "read trace\n",
    }
    if fault == "missingclass":
        masks[p.FEATURES["ptrace"]] = "read\n"
    monkeypatch.setattr(p.cg, "_kernel_text", lambda path, limit: masks[path])
    pin = "0" * 64 if fault == "wrongabi" else hashlib.sha256(raw).hexdigest()
    if fault:
        with pytest.raises(AssertionError):
            p.collect_features(tmp_path, expected_abi_sha256=pin)
    else:
        assert p.collect_features(tmp_path, expected_abi_sha256=pin) == dict(
            abi_sha256=pin, namespaces="userns_create\n", ptrace="read trace\n"
        )
    assert (tmp_path / "abi4.raw").read_bytes() == raw
    assert (
        json.loads((tmp_path / "feature-metadata.json").read_bytes())["ptrace"]
        == masks[p.FEATURES["ptrace"]]
    )


def test_canary_spec_is_public_and_pure_without_any_creation():
    spec = p.canary_spec()
    assert len(spec) == 5 and len({row["path"] for row in spec}) == 5
    assert all(row["data"] == "PUBLIC-NONKEY-DENIAL-CANARY\n" for row in spec)
    assert [row["mode"] for row in spec] == [0o644] * 4 + [0o666]


def test_root_popen_pipe_metadata_matches_unchanged_open_descriptors():
    pipes = [os.pipe() for _ in range(3)]
    streams = []
    try:
        streams = [os.fdopen(pair[0], "rb", closefd=False) for pair in pipes]
        result = p.stdio_identity(
            SimpleNamespace(stdin=streams[0], stdout=streams[1], stderr=streams[2])
        )
        assert len({(row["device"], row["inode"]) for row in result.values()}) == 3
    finally:
        for stream in streams:
            stream.close()
        for pair in pipes:
            for fd in pair:
                os.close(fd)
