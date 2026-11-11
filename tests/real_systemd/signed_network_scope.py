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
    return state


def _group_empty(group):
    if not group:
        return True
    directory = Path("/sys/fs/cgroup") / group.lstrip("/")
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return True  # Removed kernel cgroup cannot retain descendants.
    try:
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
        os.close(fd)


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
