"""Fixed marked-VM scope reopen and actor stop fencing; no VM orchestration."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat

from azazel_edge.outcome.input_auth import read_regular
from signed_network_plan import g, n, p, names, need, strict

OBSERVER_UNIT = "edge400-signed-network-observer.service"
ACTOR_UNITS = (OBSERVER_UNIT, g.UNIT, g.WITNESS, p.NET_UNIT)
PROPERTIES = ("LoadState", "ActiveState", "MainPID", "ControlPID", "ControlGroup")


def load(path):
    raw, _ = read_regular(path, owner=os.geteuid(), max_bytes=8192)
    return strict(raw)


def _open_namespace(name):
    return os.open(Path("/run/netns") / name, os.O_RDONLY | os.O_NOFOLLOW)


def _named_identity(name):
    value = os.stat(Path("/run/netns") / name, follow_symlinks=False)
    return value.st_dev, value.st_ino


class FencedAssets(n.Assets):
    def _check(self, kind):
        name = self.names.get(kind)
        need(name in self.created, "namespace operation lacks confirmed identity")
        fd, device, inode = self.created[name]
        info = os.fstat(fd)
        need(
            (info.st_dev, info.st_ino) == (device, inode) == _named_identity(name),
            "namespace operation identity drift",
        )

    def ns(self, kind, *argv, **kwargs):
        self._check(kind)
        return super().ns(kind, *argv, **kwargs)

    def spawn(self, kind, argv, **kwargs):
        self._check(kind)
        return super().spawn(kind, argv, **kwargs)


def reopen_assets(work):
    """Validate EVERY saved creation identity before returning usable Assets.

    Refusal closes our opened descriptors only: it never deletes/signals unknown,
    substituted or partly confirmed namespaces. Existing Assets.close repeats its
    own named-handle identity check at each cleanup operation.
    """
    work = Path(work)
    directory = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    opened = []
    try:
        info = os.fstat(directory)
        need(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and not info.st_mode & 0o077,
            "protected assignment directory required",
        )
        entries = os.listdir(directory)
        expected = {
            f"namespace-{kind}-{i}.json"
            for kind in ("intent", "confirmed")
            for i in (1, 2, 3)
        }
        need(
            {
                name
                for name in entries
                if name.startswith(("namespace-intent-", "namespace-confirmed-"))
            }
            == expected,
            "exact complete namespace evidence required",
        )
        proof = load(work / "namespace-boot.json")
        need(
            type(proof) is dict
            and set(proof) == {"kernel_boot_id", "names", "root_before", "foreign"}
            and proof["kernel_boot_id"] == g.boot()
            and proof["names"] == names(),
            "namespace boot/name conflict",
        )
        need(
            type(proof["foreign"]) is str
            and re.fullmatch("foreign-[0-9a-f]{8}", proof["foreign"]) is not None,
            "foreign canary identity missing",
        )
        records, seen = [], set()
        for i in (1, 2, 3):
            intent = load(work / f"namespace-intent-{i}.json")
            record = load(work / f"namespace-confirmed-{i}.json")
            need(
                type(record) is dict
                and set(record) == {"name", "state", "identity"}
                and record["state"] == "confirmed_created",
                "unconfirmed namespace",
            )
            name, identity = record["name"], record["identity"]
            need(
                type(name) is str
                and name in names().values()
                and name not in seen
                and intent == dict(name=name, state="creation_intent"),
                "creation intent/name conflict",
            )
            need(
                type(identity) is dict
                and set(identity) == {"device", "inode"}
                and type(identity["device"]) is int
                and identity["device"] >= 0
                and type(identity["inode"]) is int
                and identity["inode"] > 0,
                "namespace identity malformed",
            )
            records.append(record)
            seen.add(name)
        need(seen == set(names().values()), "missing namespace identity")
        need(
            n.root_snapshot() == proof["root_before"],
            "parent state changed before reopen",
        )
        assets = FencedAssets(work)
        assets.names = names()
        assets.foreign = proof["foreign"]
        for record in records:
            name, identity = record["name"], record["identity"]
            fd = _open_namespace(name)
            opened.append(fd)
            info = os.fstat(fd)
            expected_identity = identity["device"], identity["inode"]
            need(
                (info.st_dev, info.st_ino)
                == expected_identity
                == _named_identity(name),
                "namespace handle replaced",
            )
            assets.created[name] = (fd, info.st_dev, info.st_ino)
            assets.creation_intents[name] = record
        for kind in names():
            assets._check(kind)
        return assets, proof
    except BaseException:
        for fd in opened:
            os.close(fd)
        raise
    finally:
        os.close(directory)


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


def _membership(pid, group):
    need(re.fullmatch(r"0|[1-9][0-9]{0,9}", pid) is not None, "unit PID malformed")
    if pid != "0":
        need(
            group != ""
            and _kernel_text("/proc/" + pid + "/cgroup", 4096) == "0::" + group + "\n",
            "unit PID cgroup view inconsistent",
        )


def _state(unit):
    result = n.command(
        "systemctl", "show", unit, "--property=" + ",".join(PROPERTIES), timeout=2
    )
    need(len(result.stdout.encode()) <= 4096, "unit state oversized")
    rows = result.stdout.splitlines()
    need(all("=" in row for row in rows), "unit state malformed")
    state = dict(row.split("=", 1) for row in rows)
    need(
        len(rows) == len(PROPERTIES) and set(state) == set(PROPERTIES),
        "unit state missing/duplicate",
    )
    need(state["LoadState"] in ("loaded", "not-found"), "unknown unit load state")
    group = state["ControlGroup"]
    need(group in ("", "/system.slice/" + unit), "unexpected actor cgroup")
    _membership(state["MainPID"], group)
    _membership(state["ControlPID"], group)
    return state


def _group_empty(group):
    root = _cgroup_view()  # Even an empty/missing group requires a verified hierarchy.
    fd = None
    try:
        if not group:
            return True
        need(
            group in {"/system.slice/" + unit for unit in ACTOR_UNITS},
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


def stop_systemd_actors():
    """Attempt every fixed actor; any gap prohibits later namespace cleanup.

    Systemd actors are not Assets.processes. The original cgroup AND the final
    cgroup must be empty, with no main/control PID, before a clean stop receipt.
    Every child command has an explicit 2/3-second limit; failures remain recorded
    even when best-effort force kill/reap succeeds. Never clear/reset failed units.
    """
    g.guard()
    receipt = dict(status="failed", actors=[], failures=[])
    for unit in ACTOR_UNITS:
        row = dict(unit=unit)
        receipt["actors"].append(row)
        try:
            row["before"] = _state(unit)
        except BaseException as exc:
            receipt["failures"].append(
                dict(unit=unit, step="before", error=type(exc).__name__)
            )
        try:
            n.command("systemctl", "stop", unit, timeout=3)
        except BaseException as exc:
            receipt["failures"].append(
                dict(unit=unit, step="stop", error=type(exc).__name__)
            )
            for argv in (
                ("kill", "--kill-whom=all", "--signal=KILL", unit),
                ("stop", unit),
            ):
                try:
                    n.command("systemctl", *argv, timeout=2)
                except BaseException as cleanup:
                    receipt["failures"].append(
                        dict(unit=unit, step="force_stop", error=type(cleanup).__name__)
                    )
        try:
            row["after"] = after = _state(unit)
            need(
                after["ActiveState"] in ("inactive", "failed")
                and after["MainPID"] == after["ControlPID"] == "0",
                "actor remains live",
            )
            need(
                "before" in row
                and _group_empty(row["before"]["ControlGroup"])
                and _group_empty(after["ControlGroup"]),
                "actor cgroup has live descendants or unknown identity",
            )
        except BaseException as exc:
            receipt["failures"].append(
                dict(unit=unit, step="verify", error=type(exc).__name__)
            )
    if not receipt["failures"]:
        receipt["status"] = "verified_stopped"
    return receipt


def close_namespaces_after_actors(assets, proof):
    receipt = stop_systemd_actors()
    n.write_new(assets.work / "systemd-stop-receipt.json", receipt)
    need(
        receipt["status"] == "verified_stopped",
        "systemd actor gap; retain namespace handles and all evidence",
    )
    try:
        assets.close()  # Existing best-effort peer reap + identity-fenced deletion.
    finally:
        need(
            n.root_snapshot() == proof["root_before"],
            "parent state changed during cleanup",
        )
    need(
        all(not (Path("/run/netns") / name).exists() for name in names().values()),
        "owned namespace handle remains",
    )
    return receipt
