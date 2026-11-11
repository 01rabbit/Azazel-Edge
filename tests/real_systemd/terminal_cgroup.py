"""Narrow read-only PID1 cgroup checks extracted from reviewed 8d4f3f8 lab scope.

No actors, namespace join, unit mutations or observer permissions. Keep the
canonical full-view and descendant-populated semantics of the reviewed helper.
"""
import os
import re


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def _kernel_text(path, maximum=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        raw = bytearray()
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
            need(len(raw) <= maximum, "kernel hierarchy evidence exceeds bound")
        return raw.decode("ascii")
    finally:
        os.close(fd)


def _unified_mount(raw):
    rows = []
    lines = raw.splitlines()
    need(0 < len(lines) <= 4096, "mount hierarchy evidence unavailable")
    for line in lines:
        fields = line.split()
        need(fields.count("-") == 1, "mount hierarchy malformed")
        separator = fields.index("-")
        need(
            separator >= 6 and len(fields) == separator + 4, "mount hierarchy malformed"
        )
        rows.append(
            dict(
                device=fields[2],
                root=fields[3],
                target=fields[4],
                filesystem=fields[separator + 1],
            )
        )
    need(
        not any(row["filesystem"] == "cgroup" for row in rows),
        "cgroup v1/hybrid hierarchy unsupported",
    )
    mounts = [row for row in rows if row["filesystem"] == "cgroup2"]
    need(
        len(mounts) == 1
        and mounts[0]["target"] == "/sys/fs/cgroup"
        and mounts[0]["root"] == "/",
        "full canonical unified cgroup2 mount required",
    )
    need(
        not any(row["target"].startswith("/sys/fs/cgroup/") for row in rows),
        "cgroup subtree overlay unsupported",
    )
    need(
        re.fullmatch(r"[0-9]+:[0-9]+", mounts[0]["device"]) is not None,
        "cgroup mount device malformed",
    )
    return mounts[0]


def _physical_cgroup_root():
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in (None, "sys", "fs", "cgroup"):
            if part is not None:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            need(
                info.st_uid == 0 and not info.st_mode & 0o022,
                "cgroup canonical ancestor unprotected",
            )
        return fd
    except BaseException:
        os.close(fd)
        raise


def _cgroup_view():
    """Return an open complete PID1 cgroup2 root, or refuse every absence claim.

    /proc namespace/root links are deliberately kernel-provided identity views;
    the canonical /sys path is instead walked physically with no symlinks.
    """
    own_ns = os.stat("/proc/self/ns/cgroup")
    manager_ns = os.stat("/proc/1/ns/cgroup")
    need(
        (own_ns.st_dev, own_ns.st_ino) == (manager_ns.st_dev, manager_ns.st_ino),
        "manager cgroup namespace differs",
    )
    mount = _unified_mount(_kernel_text("/proc/self/mountinfo"))
    manager_mount = _unified_mount(_kernel_text("/proc/1/mountinfo"))
    need(mount == manager_mount, "manager canonical cgroup mount view differs")
    fd = _physical_cgroup_root()
    try:
        info = os.fstat(fd)
        major, minor = map(int, mount["device"].split(":"))
        need(
            (os.major(info.st_dev), os.minor(info.st_dev)) == (major, minor),
            "cgroup mount device differs",
        )
        manager_root = os.stat("/proc/1/root/sys/fs/cgroup")
        need(
            (info.st_dev, info.st_ino) == (manager_root.st_dev, manager_root.st_ino),
            "manager cgroup root differs",
        )
        return fd
    except BaseException:
        os.close(fd)
        raise



def group_empty(group, actor_units):
    root = _cgroup_view()  # Even an empty/missing group requires a verified hierarchy.
    fd = None
    try:
        if not group:
            return True
        need(
            group in {"/system.slice/" + unit for unit in actor_units},
            "unexpected actor cgroup path",
        )
        fd = os.dup(root)
        for part in group.strip("/").split("/"):
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                )
            except FileNotFoundError:
                return True  # Absent only in verified complete canonical PID1 view.
            os.close(fd)
            fd = child
        values = {}
        for name in ("cgroup.procs", "cgroup.events"):
            child = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd
            )
            try:
                raw = os.read(child, 65536)
                need(len(raw) < 65536, "actor cgroup exceeds read bound")
                values[name] = raw.decode("ascii")
            finally:
                os.close(child)
        events = [line.split() for line in values["cgroup.events"].splitlines()]
        need(
            all(len(row) == 2 for row in events)
            and len({row[0] for row in events}) == len(events),
            "cgroup events malformed",
        )
        populated = dict(events).get("populated")
        need(populated in ("0", "1"), "cgroup descendant state unavailable")
        return not values["cgroup.procs"].strip() and populated == "0"
    finally:
        if fd is not None:
            os.close(fd)
        os.close(root)

