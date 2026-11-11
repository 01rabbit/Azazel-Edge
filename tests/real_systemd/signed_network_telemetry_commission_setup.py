"""Fixed single-case commissioning prerequisites only; no scope or actor creation.

Root externally stages profiles/accounts/aliases and authenticates the complete
source archive. No four-run manifest, imported admission receipt or repair exists.
This first component creates only private evidence and performs compile-only work.
"""

import grp
import hashlib
import os
from pathlib import Path
import pwd
import re
import subprocess

import signed_network_plan as plan
import signed_network_scope as scope
import signed_network_telemetry_contract as role
import signed_network_telemetry_material as material
import telemetry_isolation_setup as old

lab, g, n, p = old.LAB, plan.g, plan.n, plan.p
UNITS = (
    scope.INITIALIZER_UNIT,
    scope.OBSERVER_UNIT,
    role.INITIALIZER_UNIT,
    role.OBSERVER_UNIT,
    g.UNIT,
    g.WITNESS,
    p.NET_UNIT,
)


def _accounts():
    result = {}
    for kind, uid in (("capture", 61001), ("observer", 61002), ("ai", 61003)):
        name = "edge400-" + kind
        user, group = pwd.getpwnam(name), grp.getgrnam(name)
        lab.need(
            user.pw_uid == user.pw_gid == group.gr_gid == uid
            and user.pw_shell == "/usr/sbin/nologin"
            and user.pw_dir == "/nonexistent"
            and set(os.getgrouplist(name, uid)) == {uid},
            "external account baseline differs",
        )
        status = subprocess.run(
            ["passwd", "--status", name], capture_output=True, timeout=2
        )
        lab.need(
            status.returncode == 0
            and len(status.stdout) <= 4096
            and status.stdout.split()[:2] == [name.encode(), b"L"],
            "external account not locked",
        )
        result[name] = dict(uid=uid, gid=uid, shell=user.pw_shell, locked=True)
    return result


def _assets():
    baseline = old.old_assets()  # Root-protected old aliases/profile, no installation.
    source = material._read(
        material.SRC / "tests/real_systemd/edge400-provider.apparmor", 32768
    )
    installed = material._read(p.POLICY, 32768)
    lab.need(source == installed, "external provider profile differs; no repair")
    baseline["provider_profile_sha256"] = hashlib.sha256(source).hexdigest()
    return baseline


def _fresh(output):
    lab.need(
        all(
            not os.path.lexists(path)
            for path in (
                output,
                g.BASE,
                *(Path("/run/netns") / name for name in role.NAMESPACE_NAMES),
            )
        ),
        "used output/scope/namespace refused",
    )
    for unit in UNITS:
        lab.need(
            scope._known_collected(scope._state(unit))
            and lab.cg.group_empty("/system.slice/" + unit, UNITS),
            "existing fixed actor or unknown PID1 cgroup view",
        )
    lab.need(not g.Systemd().cores(), "existing unmanaged native actor")


def _unit_material(output):
    code, raw = material.preflight.old._retained_query(
        ["systemd-analyze", "unit-paths"], "commission-unit-paths", output
    )
    error = material._read(output / "commission-unit-paths.stderr", 4096)
    lab.need(
        code == 0
        and 0 < len(raw) <= 16384
        and raw.endswith(b"\n")
        and b"\r" not in raw
        and error == b"",
        "actual bounded unit paths unavailable",
    )
    paths = raw.decode("ascii").splitlines()
    lab.need(
        0 < len(paths) <= 128 and len(set(paths)) == len(paths),
        "duplicate/unknown unit paths",
    )
    names = {"service.d"}
    for unit in UNITS:
        names.update(
            unit + suffix for suffix in ("", ".d", ".wants", ".requires", ".upholds")
        )
        parts = unit.removesuffix(".service").split("-")
        names.update("-".join(parts[:i]) + "-.service.d" for i in range(1, len(parts)))
    for row in paths:
        parent = Path(row)
        lab.need(
            re.fullmatch(r"/[A-Za-z0-9_.@/-]+", row)
            and str(parent) == row
            and "//" not in row
            and all(part not in (".", "..") for part in parent.parts),
            "malformed actual unit path",
        )
        lab.need(
            all(not os.path.lexists(parent / name) for name in names),
            "preexisting fixed-family unit material",
        )
    return paths


def _invariants(output, baseline):
    errors = []
    for name, operation, expected in (
        ("assets", _assets, baseline["assets"]),
        ("parent", n.root_snapshot, baseline["root_before"]),
        (
            "material",
            lambda: material.verify_current(
                abi_sha256=baseline["pins"]["abi_sha256"],
                interpreter_sha256=baseline["pins"]["interpreter_sha256"],
            ),
            baseline["material"],
        ),
    ):
        try:
            value = operation()
            lab.save_json(output / ("preflight-" + name + "-after.json"), value)
            lab.need(value == expected, "preflight invariant changed")
        except BaseException as exc:
            errors.append((name, type(exc).__name__))
    lab.need(not errors, "preflight invariants incomplete: " + str(errors))


def preflight(
    output,
    *,
    source_commit,
    archive_sha256,
    core_sha256,
    abi_sha256,
    interpreter_sha256,
):
    """Prove current prerequisites, then create private evidence; never a scope.

    archive_sha256 records the mandatory EXTERNAL host/guest archive verification
    boundary. This function does not authenticate the archive from revision text.
    No namespace/unit/key/BASE mutation occurs; later setup needs another review.
    """
    g.guard()
    lab.need(
        type(source_commit) is str and re.fullmatch("[0-9a-f]{40}", source_commit),
        "external exact source commit required",
    )
    for value in (archive_sha256, core_sha256, abi_sha256, interpreter_sha256):
        material.pin(value)
    output = Path(output)
    marker = material._read(Path("/etc/edge400-disposable-vm"), 256)
    revision = material._read(material.SRC / "SOURCE_REVISION", 41)
    image = material._read(g.CORE, 128 * 1024 * 1024, 0o755)
    lab.need(
        marker == g.MAGIC.encode()
        and revision in (source_commit.encode(), (source_commit + "\n").encode())
        and image[:6] == b"\x7fELF\x02\x01"
        and hashlib.sha256(image).hexdigest() == core_sha256,
        "protected marker/source/core differs",
    )
    current = material.verify_current(
        abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
    )
    required = (
        "edge400-capture",
        "edge400-observer",
        "edge400-witness",
        "edge400-native",
        "edge400-provider",
        role.PROFILE,
    )
    lab.need(
        all(
            current["loaded_profiles"].splitlines().count(name + " (enforce)") == 1
            for name in required
        ),
        "external required enforcing baseline missing",
    )
    _fresh(output)
    baseline = dict(
        pins=dict(
            source_commit=source_commit,
            archive_sha256=archive_sha256,
            core_sha256=core_sha256,
            abi_sha256=abi_sha256,
            interpreter_sha256=interpreter_sha256,
        ),
        kernel_boot_id=g.boot(),
        material=current,
        accounts=_accounts(),
        assets=_assets(),
        root_before=n.root_snapshot(),
        isolated_api=lab.isolated_api_preflight(),
        authorizes_transition=False,
        experiment=False,
        production_admission=False,
    )
    lab.boot_reference(baseline["kernel_boot_id"])
    material.preflight.old.private_output(output)
    try:
        lab.save_json(output / "root-before.json", baseline["root_before"])
        lab.save_json(output / "commission-baseline.json", baseline)
        baseline["unit_search_paths"] = _unit_material(output)
        material.compile_current(
            output, abi_sha256=abi_sha256, interpreter_sha256=interpreter_sha256
        )
    except BaseException as error:
        try:
            _invariants(output, baseline)
        except BaseException as failure:
            error.add_note("independent invariants: " + type(failure).__name__)
        raise
    _invariants(output, baseline)
    lab.save_json(output / "commission-preflight.json", baseline)
    return baseline
