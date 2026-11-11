"""Pure static candidate checks, not observed isolation or import authentication.

No controller/worker, policy loading, process execution or environment selection.
Later Root code must collect original runtime evidence independently; caller JSON
and these local structural checks cannot create proof of effective isolation.
"""

import re
import stat

PROFILE = "edge400-observer-telemetry-lab"
ALIAS = "/opt/edge400-runtime/bin/edge-observe-telemetry-lab"
ROLES = {
    "probe": (
        "edge400-telemetry-isolation-probe.service",
        "edge400-telemetry-isolation-edge",
    ),
    "peer": (
        "edge400-telemetry-isolation-peer.service",
        "edge400-telemetry-isolation-foreign",
    ),
}
BINFMT = "/proc/sys/fs/binfmt_misc"
IDENTITY_FIELDS = {
    "pid",
    "tgid",
    "uid",
    "gid",
    "groups",
    "apparmor",
    "no_new_privs",
    "cap_eff",
    "cap_prm",
    "cap_amb",
    "cap_bnd",
    "dumpable",
}


def _need(value, reason):
    if not value:
        raise ValueError(reason)


def _pair(value):
    _need(
        type(value) in (tuple, list)
        and len(value) == 2
        and all(type(x) is int and x >= 0 for x in value)
        and value[1] > 0,
        "actual namespace/device identity required",
    )
    return tuple(value)


def role_spec(mode):
    """Fixed properties only. Deliberately no executable missing worker CLI."""
    _need(type(mode) is str and mode in ROLES, "unknown fixed role")
    unit, namespace = ROLES[mode]
    return dict(
        unit=unit,
        namespace=namespace,
        alias=ALIAS,
        properties=dict(
            User="edge400-observer",
            Group="edge400-observer",
            AppArmorProfile=PROFILE,
            CapabilityBoundingSet="",
            AmbientCapabilities="",
            NoNewPrivileges="yes",
            RestrictAddressFamilies="AF_UNIX",
            Restart="no",
            DefaultDependencies="no",
            RuntimeMaxSec="15",
            TimeoutStopSec="3",
            ProtectProc="ptraceable",
            ProcSubset="all",
            MountAPIVFS="yes",
            NetworkNamespacePath="/run/netns/" + namespace,
        ),
    )


def validate_role_identity(actual, peer=None):
    for item in [actual] if peer is None else [actual, peer]:
        _need(
            type(item) is dict and set(item) == IDENTITY_FIELDS,
            "closed actual identity required",
        )
        _need(
            all(
                type(item[k]) is int
                for k in (
                    "pid",
                    "tgid",
                    "uid",
                    "gid",
                    "dumpable",
                    "cap_eff",
                    "cap_prm",
                    "cap_amb",
                    "cap_bnd",
                )
            )
            and 1 < item["pid"] == item["tgid"] < 2**31
            and item["uid"] == item["gid"] == 61002
            and item["dumpable"] == 1
            and all(item[k] == 0 for k in ("cap_eff", "cap_prm", "cap_amb", "cap_bnd")),
            "actual authority/dumpability differs",
        )
        _need(
            type(item["groups"]) is list
            and all(type(v) is int and v == 61002 for v in item["groups"])
            and item["apparmor"] == PROFILE + " (enforce)"
            and item["no_new_privs"] is True,
            "actual label/groups/NNP differs",
        )
    _need(
        peer is None or actual["tgid"] != peer["tgid"],
        "peer must be an independent thread group",
    )


def validate_proc_view(raw, *, own_mount_ns, pid1_mount_ns, proc_device):
    """Require one hidden root proc view, no aliases/submounts or exemptions.

    Raw is Root-collected /proc/PID/mountinfo, not the Root reader's own view.
    This structural proof still requires actual same-profile read negatives.
    """
    return _validate_proc_view(
        raw,
        own_mount_ns=own_mount_ns,
        pid1_mount_ns=pid1_mount_ns,
        proc_device=proc_device,
        nsfs_targets={"/run/netns/" + ns for _, ns in ROLES.values()},
    )


def _validate_proc_view(raw, *, own_mount_ns, pid1_mount_ns, proc_device, nsfs_targets):
    """Private common parser; public wrappers select only fixed contexts."""
    _need(
        _pair(own_mount_ns) != _pair(pid1_mount_ns),
        "actor mount namespace must differ from PID1",
    )
    device = _pair(proc_device)
    _need(
        type(raw) is str and 0 < len(raw.encode()) <= 1024 * 1024,
        "bounded complete mountinfo required",
    )
    lines, mounts, binfmt = raw.splitlines(), [], []
    _need(raw.endswith("\n") and 0 < len(lines) <= 4096, "complete mountinfo required")
    for line in lines:
        fields = line.split()
        _need(fields.count("-") == 1, "malformed mountinfo")
        sep = fields.index("-")
        _need(sep >= 6 and len(fields) == sep + 4, "malformed mount fields")
        root, target, filesystem = fields[3], fields[4], fields[sep + 1]
        if filesystem == "nsfs":
            # Linux nsfs_show_path emits a namespace type and inode, not a path.
            match = re.fullmatch(r"net:\[([1-9][0-9]{0,19})\]", root)
            _need(
                match is not None and int(match[1]) < 2**64 and target in nsfs_targets,
                "unknown namespace mount root/target",
            )
        _need(
            all(
                p.startswith("/")
                and "\\" not in p
                and "//" not in p
                and all(part not in (".", "..") for part in p.split("/"))
                for p in ((target,) if filesystem == "nsfs" else (root, target))
            ),
            "unknown/escaped mount path",
        )
        is_binfmt = filesystem == "binfmt_misc"
        if is_binfmt:
            _need(
                root == "/"
                and target == BINFMT
                and fields[sep + 2] == "binfmt_misc"
                and all(re.fullmatch("[1-9][0-9]*", v) for v in fields[:2]),
                "unknown binfmt mount",
            )
            binfmt.append(fields[:2])
        _need(
            (not target.startswith("/proc/") or is_binfmt)
            and (target != "/proc" or filesystem == "proc"),
            "proc submount/overlay is unsupported",
        )
        if filesystem == "proc":
            _need(
                root == "/" and target == "/proc",
                "alternate proc view is unsupported",
            )
            _need(root == "/", "subtree proc root is unsupported")
            _need(
                fields[2] == str(device[0]) + ":" + str(device[1]),
                "actual proc device differs",
            )
            options = fields[5].split(",") + fields[sep + 3].split(",")
            hidden = [v for v in options if v.startswith("hidepid=")]
            _need(
                hidden in (["hidepid=4"], ["hidepid=ptraceable"])
                and not any(
                    v.startswith("gid=")
                    or v.startswith("subset=")
                    and v != "subset=all"
                    for v in options
                ),
                "permissive/unknown proc visibility",
            )
            mounts.append(fields[0])
    _need(len(mounts) == 1, "exact one private proc view required")
    _need(
        not binfmt
        or len(binfmt) == 1
        and binfmt[0][1] == mounts[0]
        and binfmt[0][0] != mounts[0],
        "binfmt must be one child of actual private proc mount",
    )


def validate_pipe_fds(records, expected_stdio):
    """Only original Root-Popen stdio pipe identities; no inherited foreign FD."""
    _need(
        type(records) is list
        and len(records) == 3
        and type(expected_stdio) is dict
        and all(type(k) is int for k in expected_stdio)
        and set(expected_stdio) == {0, 1, 2},
        "exact stdio evidence required",
    )
    seen = set()
    for row in records:
        _need(
            type(row) is dict
            and set(row) == {"fd", "device", "inode", "mode", "target"},
            "closed FD metadata required",
        )
        fd = row["fd"]
        _need(
            type(fd) is int and fd in expected_stdio and fd not in seen,
            "unknown/duplicate inherited descriptor",
        )
        expected = expected_stdio[fd]
        _need(
            type(expected) is dict and set(expected) == {"device", "inode"},
            "Root pipe counterpart required",
        )
        pair = _pair([row["device"], row["inode"]])
        _need(
            pair == _pair([expected["device"], expected["inode"]])
            and type(row["mode"]) is int
            and stat.S_ISFIFO(row["mode"])
            and row["target"] == "pipe:[" + str(row["inode"]) + "]",
            "stdio is not the exact original pipe",
        )
        seen.add(fd)
    _need(
        len({(r["device"], r["inode"]) for r in records}) == 3,
        "aliased stdio pipes unsupported",
    )
