"""Fixed Root staging code only; no actor/controller loop or automatic entrypoint.

Old accounts/profile/aliases are an EXTERNAL Root baseline, never repaired here.
Every callable transition requires the explicit new opt-in and fresh marked VM.
"""

import collections
import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

import telemetry_isolation_preflight as p
import network_measure_driver as network
from azazel_edge.outcome.input_auth import open_parent, read_regular

G, LAB, C = p.old.g, p.lab, p.contract
NEW_POLICY = Path("/etc/apparmor.d/edge400-observer-telemetry-lab")
OLD_POLICY = Path("/etc/apparmor.d/edge400-lab")
SOURCE_POLICY = p.SRC / "tests/real_systemd/edge400-observer-telemetry-lab.apparmor"
FLAG = "EDGE_TELEMETRY_ISOLATION_PREFLIGHT"
PROFILES = "/sys/kernel/security/apparmor/profiles"


def _read(path, limit=1024 * 1024, mode=None):
    raw, info = read_regular(path, owner=0, mode=mode, max_bytes=limit)
    return raw, dict(
        sha256=hashlib.sha256(raw).hexdigest(),
        device=info.st_dev,
        inode=info.st_ino,
        mode=info.st_mode,
    )


def old_assets():
    original, _ = _read(p.SRC / "tests/real_systemd/edge400.apparmor")
    installed, entry = _read(OLD_POLICY)
    LAB.need(original == installed, "external old profile baseline differs; no repair")
    python, base = _read(G.PYTHON.resolve(strict=True), 64 * 1024 * 1024, 0o755)
    values = {"profile": entry, "interpreter": base}
    for alias in ("edge-capture", "edge-observe"):
        raw, entry = _read(G.PYTHON.with_name(alias), 64 * 1024 * 1024, 0o755)
        LAB.need(raw == python, "external old alias baseline differs; no repair")
        values[alias] = entry
    return values


def reject_unit_material(paths):
    units = [C.role_spec(mode)["unit"] for mode in C.ROLES]
    for parent in map(Path, paths):
        LAB.need(
            parent.is_absolute() and ".." not in parent.parts,
            "physical absolute unit path required",
        )
        LAB.need(
            not os.path.lexists(parent / "edge400-telemetry-isolation-.service.d"),
            "preexisting deep candidate prefix material",
        )
        for unit in units:
            LAB.need(
                all(
                    not os.path.lexists(parent / name)
                    for name in (
                        unit,
                        unit + ".d",
                        unit + ".wants",
                        unit + ".requires",
                        unit + ".upholds",
                    )
                ),
                "preexisting candidate unit material",
            )


def guard(output):
    G.guard()
    LAB.need(os.environ.get(FLAG) == "1", "explicit NEW candidate opt-in required")
    marker, _ = _read(Path("/etc/edge400-disposable-vm"), 256)
    LAB.need(marker == G.MAGIC.encode(), "protected disposable marker differs")
    pins = {}
    for name, length in (
        ("SOURCE_COMMIT", 40),
        ("ARCHIVE_SHA256", 64),
        ("CORE_SHA256", 64),
        ("ABI_SHA256", 64),
    ):
        value = os.environ.get("EDGE_TELEMETRY_ISOLATION_" + name, "")
        LAB.need(
            re.fullmatch("[0-9a-f]{" + str(length) + "}", value),
            "external frozen pin required",
        )
        pins[name] = value
    revision, _ = _read(p.SRC / "SOURCE_REVISION", 41)
    core, _ = _read(G.CORE, 128 * 1024 * 1024)
    LAB.need(
        revision
        in (pins["SOURCE_COMMIT"].encode(), (pins["SOURCE_COMMIT"] + "\n").encode())
        and core[:6] == b"\x7fELF\x02\x01"
        and hashlib.sha256(core).hexdigest() == pins["CORE_SHA256"],
        "protected source/core differs",
    )
    LAB.boot_reference(G.boot())
    user, group = pwd.getpwnam("edge400-observer"), grp.getgrnam("edge400-observer")
    LAB.need(
        user.pw_uid == user.pw_gid == group.gr_gid == 61002
        and user.pw_shell == "/usr/sbin/nologin"
        and set(os.getgrouplist("edge400-observer", 61002)) == {61002},
        "external account baseline differs",
    )
    locked = subprocess.run(
        ["passwd", "--status", "edge400-observer"], capture_output=True, timeout=2
    )
    LAB.need(
        locked.returncode == 0
        and len(locked.stdout) <= 4096
        and locked.stdout.split()[:2] == [b"edge400-observer", b"L"],
        "external account not proven locked",
    )
    paths = p.old.pre_mutation_checks()["unit_search_paths"]
    units = [C.role_spec(mode)["unit"] for mode in C.ROLES]
    reject_unit_material(paths)
    for unit in (*units, G.UNIT, G.WITNESS):
        LAB.need(
            G.systemctl(
                "show", unit, "-p", "LoadState", "--value", check=False
            ).stdout.strip()
            == "not-found",
            "existing actor refused",
        )
    names = [C.role_spec(mode)["namespace"] for mode in C.ROLES]
    LAB.need(
        not G.Systemd().cores()
        and all(
            not os.path.lexists(path)
            for path in (
                output,
                G.BASE,
                Path(C.ALIAS),
                NEW_POLICY,
                *(Path("/run/netns") / name for name in names),
            )
        ),
        "used material/name refused",
    )
    old = old_assets()
    loaded = p.cg._kernel_text(PROFILES, 256 * 1024)
    LAB.need(
        not any(
            line.split(" (", 1)[0] == C.PROFILE or line.startswith(C.PROFILE + "//")
            for line in loaded.splitlines()
        )
        and all(
            name + " (enforce)" in loaded.splitlines()
            for name in (
                "edge400-capture",
                "edge400-witness",
                "edge400-observer",
                "edge400-native",
            )
        ),
        "external loaded old baseline/new absence differs",
    )
    return dict(
        pins=pins,
        old_assets=old,
        loaded_before=loaded,
        kernel_boot_id=G.boot(),
        account_status=locked.stdout.decode(),
        unit_search_paths=paths,
        isolated_api_preflight=LAB.isolated_api_preflight(),
        source_archive_boundary="externally verified host and guest archive SHA; revision is not archive proof",
    )


def _mkdir(path, *, on_create=None):
    parent, name = open_parent(path, trusted_owner=0)
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent)
        created = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            actual = os.fstat(fd)
            LAB.need(
                (created.st_dev, created.st_ino) == (actual.st_dev, actual.st_ino)
                and actual.st_uid == 0
                and stat.S_ISDIR(actual.st_mode),
                "new directory identity changed",
            )
            if on_create:
                on_create("created", actual)
            os.fchmod(fd, 0o755)
            os.fsync(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            LAB.need(
                (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino)
                and named.st_uid == 0
                and stat.S_ISDIR(named.st_mode)
                and stat.S_IMODE(named.st_mode) == 0o755,
                "new directory replaced during normalization",
            )
            os.fsync(parent)
            if on_create:
                on_create("complete", os.fstat(fd))
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def _new_file(path, raw, mode, *, on_create=None):
    parent, name = open_parent(path, trusted_owner=0)
    try:
        fd = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        try:
            identity = os.fstat(fd)
            if on_create:
                on_create("created", identity)
            LAB.need(os.write(fd, raw) == len(raw), "short exclusive write")
            os.fchmod(fd, mode)
            os.fsync(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            LAB.need(
                (identity.st_dev, identity.st_ino) == (named.st_dev, named.st_ino)
                and named.st_uid == 0
                and stat.S_ISREG(named.st_mode)
                and named.st_nlink == 1
                and stat.S_IMODE(named.st_mode) == mode,
                "new owned file changed",
            )
            os.fsync(parent)
            if on_create:
                on_create("complete", os.fstat(fd))
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _metadata(info):
    return dict(
        device=info.st_dev,
        inode=info.st_ino,
        uid=info.st_uid,
        mode=info.st_mode,
        nlink=info.st_nlink,
        size=info.st_size,
    )


def intended_assets(output, image, policy):
    planned = {str(output): dict(kind="directory", mode=0o700)}
    for path in (G.BASE, G.BUNDLE, G.BUNDLE / "producer", G.BUNDLE / "witness"):
        planned[str(path)] = dict(kind="directory", mode=0o755)
    for path, data, mode in (
        (Path(C.ALIAS), image, 0o755),
        (NEW_POLICY, policy, 0o644),
        *(
            (Path(row["path"]), row["data"].encode(), row["mode"])
            for row in p.canary_spec()
        ),
    ):
        planned[str(path)] = dict(
            kind="file",
            mode=mode,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
    return planned


def inventory_assets(baseline):
    """Every intended path, including absent/unknown and confirmed partial files.

    Unconfirmed/replaced nodes never supply contents; only our recorded FD's same
    regular inode is read with a finite expected-size bound. No repair/delete.
    """
    inventory = {}
    for path, spec in baseline["intended_assets"].items():
        record = inventory[path] = dict(state="unknown")
        parent = fd = None
        try:
            parent, name = open_parent(Path(path), trusted_owner=0)
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            record.update(state="present", metadata=_metadata(info))
            created = baseline["asset_confirmations"].get(path, {})
            record["confirmation"] = created
            original = created.get("created", {})
            same = (info.st_dev, info.st_ino) == (
                original.get("device"),
                original.get("inode"),
            )
            if (
                spec["kind"] == "file"
                and same
                and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
            ):
                LAB.need(
                    info.st_size <= spec["size"],
                    "created file exceeds expected finite bound",
                )
                fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
                )
                pinned = os.fstat(fd)
                LAB.need(
                    (pinned.st_dev, pinned.st_ino) == (info.st_dev, info.st_ino),
                    "inventory file replaced",
                )
                raw = bytearray()
                while len(raw) <= spec["size"]:
                    part = os.read(fd, min(65536, spec["size"] + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
                after = os.stat(name, dir_fd=parent, follow_symlinks=False)
                LAB.need(
                    len(raw) == info.st_size
                    and (after.st_dev, after.st_ino) == (info.st_dev, info.st_ino),
                    "inventory content/identity changed",
                )
                record["sha256"] = hashlib.sha256(raw).hexdigest()
        except FileNotFoundError:
            record["state"] = "absent"
        except BaseException as exc:
            record.update(state="unknown", error=type(exc).__name__)
        finally:
            for descriptor in (fd, parent):
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except BaseException as exc:
                        record.update(state="unknown", close_error=type(exc).__name__)
    return inventory


def validate_inventory(inventory, baseline):
    LAB.need(
        bool(baseline.get("intended_assets"))
        and set(inventory) == set(baseline["intended_assets"]),
        "incomplete intended inventory",
    )
    for path, spec in baseline["intended_assets"].items():
        row = inventory[path]
        facts = row.get("metadata", {})
        confirmation = row.get("confirmation", {}).get("complete", {})
        LAB.need(
            row["state"] == "present"
            and facts.get("uid") == 0
            and (facts.get("device"), facts.get("inode"))
            == (confirmation.get("device"), confirmation.get("inode"))
            and stat.S_IMODE(facts.get("mode", 0)) == spec["mode"],
            "missing/partial/unknown intended asset: " + path,
        )
        LAB.need(
            stat.S_ISDIR(facts["mode"])
            if spec["kind"] == "directory"
            else stat.S_ISREG(facts["mode"])
            and facts["nlink"] == 1
            and facts["size"] == spec["size"]
            and row.get("sha256") == spec["sha256"],
            "intended asset type/content differs: " + path,
        )


def invariants(output, baseline, *, require_new=False):
    """Independent best-effort checks; one error never skips remaining evidence."""
    errors = []
    for name, operation in (
        ("parent", lambda: network.root_snapshot()),
        ("old_assets", old_assets),
        ("new_assets", lambda: inventory_assets(baseline)),
        ("loaded_profiles", lambda: p.cg._kernel_text(PROFILES, 256 * 1024)),
    ):
        try:
            value = operation()
            LAB.save_json(output / (name + "-after.json"), value)
            if name == "parent":
                LAB.need(
                    value == baseline["root_before"], "parent network state changed"
                )
            elif name == "old_assets":
                LAB.need(value == baseline["old_assets"], "old assets changed")
            elif name == "new_assets":
                validate_inventory(value, baseline)
            else:
                actual, expected = (
                    collections.Counter(value.splitlines()),
                    collections.Counter(baseline["loaded_before"].splitlines()),
                )
                allowed = expected + collections.Counter({C.PROFILE + " (enforce)": 1})
                LAB.need(
                    actual == allowed or not require_new and actual == expected,
                    "unexpected old/new loaded profile change",
                )
        except BaseException as exc:
            errors.append((name, type(exc).__name__))
    LAB.need(not errors, "Root invariants failed: " + str(errors))


def stage(output):
    baseline = guard(output)
    image, _ = _read(G.PYTHON.resolve(strict=True), 64 * 1024 * 1024, 0o755)
    policy, _ = _read(SOURCE_POLICY)
    baseline["intended_assets"] = intended_assets(output, image, policy)
    baseline["asset_confirmations"] = {}

    def confirm(path, phase, info):
        key = str(path)
        baseline["asset_confirmations"].setdefault(key, {})[phase] = _metadata(info)
        number = list(baseline["intended_assets"]).index(key)
        LAB.save_json(
            output / f"asset-{number}-{phase}.json",
            dict(path=key, phase=phase, metadata=_metadata(info)),
        )

    p.old.private_output(output)
    try:
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            confirm(output, "created", os.fstat(fd))
            confirm(output, "complete", os.fstat(fd))
        finally:
            os.close(fd)
        baseline["root_before"] = network.root_snapshot()
        LAB.save_json(output / "root-before.json", baseline["root_before"])
        LAB.save_json(output / "baseline.json", baseline)
        p.collect_features(output, expected_abi_sha256=baseline["pins"]["ABI_SHA256"])
        for name, path in (
            ("yama", "/proc/sys/kernel/yama/ptrace_scope"),
            ("candidate", str(SOURCE_POLICY)),
        ):
            raw = (
                p.cg._kernel_text(path, 65536)
                if name == "yama"
                else _read(Path(path))[0].decode()
            )
            LAB.save(output / (name + ".raw"), raw.encode())
        code, binary = p.old._retained_query(
            [
                "apparmor_parser",
                "--skip-kernel-load",
                "--skip-cache",
                "--stdout",
                "--Werror",
                str(SOURCE_POLICY),
            ],
            "candidate-compile",
            output,
        )
        LAB.need(
            code == 0
            and 0 < len(binary) <= 1024 * 1024
            and _read(output / "candidate-compile.stderr")[0] == b"",
            "current candidate compilation failed/warned",
        )
        LAB.save_json(
            output / "install-intent.json",
            dict(
                alias=C.ALIAS,
                alias_sha256=hashlib.sha256(image).hexdigest(),
                profile=str(NEW_POLICY),
                profile_sha256=hashlib.sha256(policy).hexdigest(),
                public_nonkey_canaries=p.canary_spec(),
                intended_assets=baseline["intended_assets"],
            ),
        )
        _new_file(
            Path(C.ALIAS),
            image,
            0o755,
            on_create=lambda phase, info: confirm(Path(C.ALIAS), phase, info),
        )
        _new_file(
            NEW_POLICY,
            policy,
            0o644,
            on_create=lambda phase, info: confirm(NEW_POLICY, phase, info),
        )
        for path in (G.BASE, G.BUNDLE, G.BUNDLE / "producer", G.BUNDLE / "witness"):
            _mkdir(
                path,
                on_create=lambda phase, info, path=path: confirm(path, phase, info),
            )
        for row in p.canary_spec():
            _new_file(
                Path(row["path"]),
                row["data"].encode(),
                row["mode"],
                on_create=lambda phase, info, path=Path(row["path"]): confirm(
                    path, phase, info
                ),
            )
        code, _ = p.old._retained_query(
            [
                "apparmor_parser",
                "--replace",
                "--skip-cache",
                "--Werror",
                str(NEW_POLICY),
            ],
            "candidate-load",
            output,
        )
        LAB.need(
            code == 0 and _read(output / "candidate-load.stderr")[0] == b"",
            "current candidate load failed/warned",
        )
        loaded = p.cg._kernel_text(PROFILES, 256 * 1024)
        LAB.save(output / "loaded-after.raw", loaded.encode())
        LAB.need(
            collections.Counter(loaded.splitlines())
            == collections.Counter(baseline["loaded_before"].splitlines())
            + collections.Counter({C.PROFILE + " (enforce)": 1}),
            "expected new loaded label only",
        )
        baseline["new_assets"] = inventory_assets(baseline)
        validate_inventory(baseline["new_assets"], baseline)
        LAB.save_json(output / "staged.json", baseline)
        return baseline
    except BaseException as exc:
        try:
            invariants(output, baseline)
        except BaseException as failed:
            exc.add_note("Independent Root invariant failure: " + type(failed).__name__)
        raise
