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
    for parent in map(Path, paths):
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
        isolated_api_preflight=LAB.isolated_api_preflight(),
        source_archive_boundary="externally verified host and guest archive SHA; revision is not archive proof",
    )


def _mkdir(path):
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
        finally:
            os.close(fd)
        os.fsync(parent)
    finally:
        os.close(parent)


def _new_file(path, raw, mode):
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
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def invariants(output, baseline, *, require_new=False):
    """Independent best-effort checks; one error never skips remaining evidence."""
    errors = []
    for name, operation in (
        ("parent", lambda: network.root_snapshot()),
        ("old_assets", old_assets),
        (
            "new_assets",
            lambda: {
                path: _read(Path(path), 64 * 1024 * 1024)[1]
                for path in baseline.get("new_assets", {})
            },
        ),
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
                LAB.need(
                    value == baseline.get("new_assets", {}), "new staged assets changed"
                )
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
    p.old.private_output(output)
    baseline["root_before"] = network.root_snapshot()
    LAB.save_json(output / "root-before.json", baseline["root_before"])
    LAB.save_json(output / "baseline.json", baseline)
    try:
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
        image, _ = _read(G.PYTHON.resolve(strict=True), 64 * 1024 * 1024, 0o755)
        policy, _ = _read(SOURCE_POLICY)
        LAB.save_json(
            output / "install-intent.json",
            dict(
                alias=C.ALIAS,
                alias_sha256=hashlib.sha256(image).hexdigest(),
                profile=str(NEW_POLICY),
                profile_sha256=hashlib.sha256(policy).hexdigest(),
                public_nonkey_canaries=p.canary_spec(),
            ),
        )
        _new_file(Path(C.ALIAS), image, 0o755)
        _new_file(NEW_POLICY, policy, 0o644)
        for path in (G.BASE, G.BUNDLE, G.BUNDLE / "producer", G.BUNDLE / "witness"):
            _mkdir(path)
        for row in p.canary_spec():
            _new_file(Path(row["path"]), row["data"].encode(), row["mode"])
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
        baseline["new_assets"] = {
            str(path): _read(path, 64 * 1024 * 1024)[1]
            for path in (Path(C.ALIAS), NEW_POLICY)
        }
        LAB.save_json(output / "staged.json", baseline)
        return baseline
    except BaseException as exc:
        try:
            invariants(output, baseline)
        except BaseException as failed:
            exc.add_note("Independent Root invariant failure: " + type(failed).__name__)
        raise
