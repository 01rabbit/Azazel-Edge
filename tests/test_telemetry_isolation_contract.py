"""Pure structural fixtures only; no AppArmor compile/load or actual isolation."""

from copy import deepcopy
from pathlib import Path
import stat
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_isolation_contract as c

PROC = "30 1 0:4 / /proc rw,nosuid,nodev,noexec - proc proc rw,hidepid=ptraceable\n"
ROOT = "1 0 8:1 / / rw - ext4 /dev/root rw\n"


def view(raw=ROOT + PROC, **kw):
    args = dict(own_mount_ns=(5, 10), pid1_mount_ns=(5, 11), proc_device=(0, 4))
    args.update(kw)
    return c.validate_proc_view(raw, **args)


def identity(pid):
    return dict(
        pid=pid,
        tgid=pid,
        uid=61002,
        gid=61002,
        groups=[61002],
        apparmor=c.PROFILE + " (enforce)",
        no_new_privs=True,
        cap_eff=0,
        cap_prm=0,
        cap_amb=0,
        cap_bnd=0,
        dumpable=1,
    )


def pipes():
    records = [
        dict(
            fd=fd,
            device=16,
            inode=100 + fd,
            mode=stat.S_IFIFO | 0o600,
            target=f"pipe:[{100 + fd}]",
        )
        for fd in range(3)
    ]
    expected = {row["fd"]: {k: row[k] for k in ("device", "inode")} for row in records}
    return records, expected


def test_fixed_roles_have_no_executable_entrypoint_and_keep_required_unit_properties():
    probe, peer = c.role_spec("probe"), c.role_spec("peer")
    assert probe["unit"] != peer["unit"] and probe["namespace"] != peer["namespace"]
    assert probe["alias"] == peer["alias"] == c.ALIAS
    for spec in (probe, peer):
        assert "argv" not in spec and "ExecStart" not in spec["properties"]
        assert spec["properties"]["AppArmorProfile"] == c.PROFILE
        assert spec["properties"]["ProtectProc"] == "ptraceable"
        assert spec["properties"]["ProcSubset"] == "all"
        assert (
            spec["properties"]["MountAPIVFS"]
            == spec["properties"]["NoNewPrivileges"]
            == "yes"
        )
        assert (
            spec["properties"]["CapabilityBoundingSet"]
            == spec["properties"]["AmbientCapabilities"]
            == ""
        )
        assert spec["properties"]["RestrictAddressFamilies"] == "AF_UNIX"
        assert spec["properties"]["Restart"] == "no"
    probe["properties"]["AppArmorProfile"] = "unconfined"
    assert c.role_spec("probe")["properties"]["AppArmorProfile"] == c.PROFILE


@pytest.mark.parametrize("mode", [True, None, "observer", "../../probe", "probe "])
def test_unknown_role_has_no_fallback(mode):
    with pytest.raises(ValueError):
        c.role_spec(mode)


@pytest.mark.parametrize("hidepid", ["ptraceable", "4"])
def test_actual_private_proc_shape_is_necessary_not_runtime_proof(hidepid):
    raw = ROOT + PROC.replace("ptraceable", hidepid)
    before = raw
    assert view(raw) is None and raw == before


# Unchanged selected rows from Root's failed v2 peer-mountinfo.raw. These prove
# parser compatibility only, not successful proc isolation or probe coverage.
V2_NSFS = """415 414 0:4 net:[4026532228] /run/netns/edge400-telemetry-isolation-edge rw shared:343 master:295 - nsfs nsfs rw
416 414 0:4 net:[4026532285] /run/netns/edge400-telemetry-isolation-foreign rw shared:344 master:311 - nsfs nsfs rw
417 411 0:4 net:[4026532228] /run/netns/edge400-telemetry-isolation-edge rw shared:345 master:295 - nsfs nsfs rw
418 411 0:4 net:[4026532285] /run/netns/edge400-telemetry-isolation-foreign rw shared:346 master:311 - nsfs nsfs rw
"""
V2_PROC = "434 405 0:47 / /proc rw,nosuid,nodev,noexec,relatime shared:351 - proc proc rw,hidepid=ptraceable\n"


def test_actual_v2_namespace_mount_rows_parse_without_rewriting_originals():
    raw = ROOT + V2_NSFS + V2_PROC
    before = raw
    assert view(raw, proc_device=(0, 47)) is None and raw == before


@pytest.mark.parametrize(
    "root",
    [
        "/",
        "net:[]",
        "net:[0]",
        "net:[01]",
        "net:[+1]",
        "net:[-1]",
        "net:[18446744073709551616]",
        "net:[999999999999999999999]",
        "net:[1]suffix",
        "net:[1",
        "pid:[1]",
        "mnt:[1]",
        "user:[1]",
    ],
)
def test_namespace_root_is_only_canonical_positive_bounded_net_inode(root):
    row = V2_NSFS.splitlines(keepends=True)[0].replace("net:[4026532228]", root)
    with pytest.raises(ValueError):
        view(ROOT + PROC + row)


@pytest.mark.parametrize("filesystem", ["nsfs2", "tmpfs", "proc", "unknown"])
def test_typed_namespace_root_never_accepted_for_another_filesystem(filesystem):
    row = V2_NSFS.splitlines(keepends=True)[0].replace(
        " - nsfs ", " - " + filesystem + " "
    )
    with pytest.raises(ValueError):
        view(ROOT + PROC + row)


@pytest.mark.parametrize(
    "target",
    [
        "/run/netns/other",
        "/run/netns/edge400-telemetry-isolation-edge/child",
        "/run//netns/edge400-telemetry-isolation-edge",
        "/run/netns/../edge400-telemetry-isolation-edge",
        r"/run/netns/edge400-telemetry-isolation-edge\040alias",
        "/proc",
        "/proc/net",
        "/run/alt-proc",
    ],
)
def test_namespace_mount_target_remains_exact_fixed_owned_role_path(target):
    row = V2_NSFS.splitlines(keepends=True)[0].replace(
        "/run/netns/" + c.ROLES["probe"][1], target
    )
    with pytest.raises(ValueError):
        view(ROOT + PROC + row)


@pytest.mark.parametrize(
    "proc",
    [
        V2_PROC.replace("hidepid=ptraceable", "hidepid=2"),
        V2_PROC.replace("hidepid=ptraceable", "hidepid=ptraceable,gid=61002"),
        V2_PROC.replace(" /proc ", " /run/alt-proc "),
        V2_PROC.replace(" - proc ", " - tmpfs "),
        V2_PROC.replace("0:47 / /proc", "0:48 / /proc"),
        V2_PROC + "435 434 0:48 / /proc/net rw - tmpfs tmpfs rw\n",
    ],
)
def test_valid_namespace_rows_do_not_relax_proc_visibility_device_or_overlay_gates(
    proc,
):
    with pytest.raises(ValueError):
        view(ROOT + V2_NSFS + proc, proc_device=(0, 47))


@pytest.mark.parametrize(
    "raw",
    [
        ROOT,
        ROOT + PROC.rstrip(),
        ROOT + PROC.replace("hidepid=ptraceable", "hidepid=2"),
        ROOT + PROC.replace("hidepid=ptraceable", "hidepid=0"),
        ROOT + PROC.replace(",hidepid=ptraceable", ""),
        ROOT + PROC.replace("hidepid=ptraceable", "hidepid=ptraceable,gid=61002"),
        ROOT + PROC.replace("hidepid=ptraceable", "hidepid=ptraceable,gid=0"),
        ROOT + PROC.replace("hidepid=ptraceable", "hidepid=ptraceable,subset=pid"),
        ROOT + PROC.replace("hidepid=ptraceable", "hidepid=ptraceable,hidepid=4"),
        ROOT + PROC + PROC.replace("/proc ", "/run/alt-proc "),
        ROOT + PROC + "31 30 0:5 / /proc/net rw - tmpfs tmpfs rw\n",
        ROOT + PROC + "31 30 0:5 / /proc rw - tmpfs tmpfs rw\n",
        ROOT + PROC.replace("0:4 / /proc", "0:4 /123 /proc"),
        ROOT + PROC.replace(" /proc ", " /proc\\040alias "),
        ROOT + PROC.replace(" /proc ", " /proc/../proc "),
        ROOT + PROC.replace(" - proc ", " - nonsense "),
    ],
)
def test_unknown_or_permissive_proc_layout_refuses(raw):
    with pytest.raises(ValueError):
        view(raw)


@pytest.mark.parametrize(
    "kw",
    [
        dict(own_mount_ns=(5, 11)),
        dict(proc_device=(0, 5)),
        dict(own_mount_ns=(True, 10)),
        dict(pid1_mount_ns=None),
    ],
)
def test_namespace_or_device_identity_must_match_actual_private_view(kw):
    with pytest.raises(ValueError):
        view(**kw)


def test_same_profile_same_uid_peer_must_be_distinct_dumpable_threadgroup():
    actual, peer = identity(100), identity(101)
    before = deepcopy((actual, peer))
    assert c.validate_role_identity(actual, peer) is None
    assert (actual, peer) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", True),
        ("tgid", 101),
        ("uid", 0),
        ("gid", 0),
        ("cap_eff", 1),
        ("cap_bnd", False),
        ("dumpable", 0),
        ("no_new_privs", 1),
        ("apparmor", "edge400-observer (enforce)"),
        ("groups", [True]),
    ],
)
def test_actor_identity_or_authority_drift_refuses(field, value):
    actual = identity(100)
    actual[field] = value
    with pytest.raises(ValueError):
        c.validate_role_identity(actual, identity(101))


def test_same_threadgroup_peer_is_not_foreign_process_proof():
    with pytest.raises(ValueError):
        c.validate_role_identity(identity(100), identity(100))


def test_only_exact_three_root_pipe_counterparts_qualify_structurally():
    records, expected = pipes()
    before = deepcopy((records, expected))
    assert c.validate_pipe_fds(list(reversed(records)), expected) is None
    assert (records, expected) == before


@pytest.mark.parametrize(
    "fault",
    [
        "extra",
        "missing",
        "duplicate",
        "procfd",
        "nsfd",
        "socket",
        "regular",
        "wrongino",
        "wrongdev",
        "target",
        "boolfd",
        "boolino",
        "aliased",
        "unknownfield",
    ],
)
def test_foreign_unknown_or_wrong_stdio_descriptor_refuses(fault):
    records, expected = pipes()
    if fault == "extra":
        records.append(
            dict(fd=3, device=1, inode=4, mode=stat.S_IFREG, target="/proc/1/net/dev")
        )
    elif fault == "missing":
        records.pop()
    elif fault == "duplicate":
        records[1] = deepcopy(records[0])
    elif fault == "procfd":
        records[0].update(mode=stat.S_IFREG, target="/proc/1/net/dev")
    elif fault == "nsfd":
        records[0].update(mode=stat.S_IFREG, target="net:[123]")
    elif fault == "socket":
        records[0].update(mode=stat.S_IFSOCK, target="socket:[100]")
    elif fault == "regular":
        records[0]["mode"] = stat.S_IFREG | 0o600
    elif fault == "wrongino":
        records[0]["inode"] += 1
    elif fault == "wrongdev":
        records[0]["device"] += 1
    elif fault == "target":
        records[0]["target"] = "pipe:[999]"
    elif fault == "boolfd":
        records[0]["fd"] = False
    elif fault == "boolino":
        records[0]["inode"] = True
    elif fault == "aliased":
        records[1].update(device=16, inode=100, target="pipe:[100]")
        expected[1] = deepcopy(expected[0])
    elif fault == "unknownfield":
        records[0]["verified"] = True
    with pytest.raises(ValueError):
        c.validate_pipe_fds(records, expected)


def test_new_profile_only_declares_separate_candidate_and_explicit_mediation_requirements():
    directory = Path(__file__).parent / "real_systemd"
    raw = (directory / "edge400-observer-telemetry-lab.apparmor").read_text()
    assert "abi <abi/4.0>," in raw and "audit deny userns," in raw
    assert "audit deny ptrace (read,trace)," in raw
    assert "audit deny signal (send)," in raw
    assert "ptrace (readby) peer=unconfined," in raw
    assert "profile " + c.PROFILE + " " + c.ALIAS + " {" in raw
    for path in ("/proc/", "/proc/loadavg", "/proc/uptime", "/proc/@{pid}/net/dev"):
        assert path + " r," in raw
    assert "/opt/edge400-runtime/bin/edge-observe ix," not in raw
    old = (directory / "edge400.apparmor").read_text()
    assert c.PROFILE not in old and c.ALIAS not in old


def test_source_root_permission_is_only_literal_read_directory_metadata():
    directory = Path(__file__).parent / "real_systemd"
    profile = (directory / "edge400-observer-telemetry-lab.apparmor").read_text()
    source_rules = [
        line.strip()
        for line in profile.splitlines()
        if line.strip().startswith("/opt/edge400-src/")
    ]
    assert source_rules.count("/opt/edge400-src/ r,") == 1
    assert set(source_rules) == {
        "/opt/edge400-src/ r,",
        "/opt/edge400-src/py/ r,",
        "/opt/edge400-src/py/** r,",
        "/opt/edge400-src/tests/ r,",
        "/opt/edge400-src/tests/** r,",
    }
    assert "/opt/edge400-src/ r," not in (directory / "edge400.apparmor").read_text()
