"""Manual fresh assignment preparation only; no workload or VM orchestration."""

# ruff: noqa: E402
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

SRC = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(SRC / "py"),
    str(SRC / "tests"),
    str(Path(__file__).resolve().parent),
]
import signed_network_plan as plan
import signed_network_scope as scope
import signed_network_observer as observer
import terminal_stop_lab as lab
from azazel_edge.outcome.input_auth import read_regular
from azazel_edge.outcome.input_service import verify

p, g, n = plan.p, plan.g, plan.n
WORK = Path("/var/lib/edge400-signed-network-lab")
MANIFEST = Path("/var/lib/edge400-signed-network-manifest.json")
TICKET = Path("/var/lib/edge400-signed-network-ticket.json")


def _read(path, maximum=8 * 1024 * 1024):
    return read_regular(path, owner=0, max_bytes=maximum)[0]


def validated_inputs(expected_manifest_sha256, expected_start_head):
    for value in (expected_manifest_sha256, expected_start_head):
        plan.need(
            type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None,
            "exact external manifest/head pins required",
        )
    manifest_raw, ticket_raw = _read(MANIFEST), _read(TICKET, 4096)
    manifest, ticket = plan.strict(manifest_raw), plan.strict(ticket_raw)
    plan.need(
        type(manifest) is dict
        and n.manifest_digest(manifest) == expected_manifest_sha256,
        "external frozen manifest differs",
    )
    plan.need(
        type(ticket) is dict
        and set(ticket) == {"manifest_sha256", "assignment_id", "run_id", "start_head"}
        and ticket["manifest_sha256"] == expected_manifest_sha256
        and ticket["start_head"] == expected_start_head,
        "external started assignment ticket differs",
    )
    plan.need(
        type(ticket["run_id"]) is str
        and re.fullmatch("[A-Za-z][A-Za-z0-9_-]{0,127}", ticket["run_id"]) is not None,
        "bounded run identity required",
    )
    image = _read(g.CORE, 128 * 1024 * 1024)
    core_sha = hashlib.sha256(image).hexdigest()
    plan.need(image[:6] == b"\x7fELF\x02\x01", "reviewed ELF64 core required")
    safety = plan.validate_manifest(manifest, core_sha)
    assignment = next(
        (a for a in manifest["assignments"] if a["id"] == ticket["assignment_id"]), None
    )
    plan.need(assignment is not None, "ticket assignment not frozen")
    revision = manifest["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"]
    plan.need(
        _read(SRC / "SOURCE_REVISION", 41)
        in (revision.encode(), (revision + "\n").encode()),
        "protected source revision differs",
    )
    # Full source authenticity is the mandatory external Root git-archive SHA
    # staging boundary. These protected direct-file reads are not a new tree proof.
    paths = (
        Path(__file__),
        Path(plan.__file__),
        Path(scope.__file__),
        Path(observer.__file__),
        Path(n.__file__),
        n.PEER,
        plan.POLICY_PATH,
        SRC / "tests/real_systemd/edge400.apparmor",
        SRC / "tests/real_systemd/edge400-provider.apparmor",
    )
    direct = {
        str(path.relative_to(SRC)): hashlib.sha256(_read(path, 1024 * 1024)).hexdigest()
        for path in paths
    }
    plan.need(
        direct[str(plan.POLICY_PATH.relative_to(SRC))]
        == manifest["observer_policy_sha256"],
        "protected observer policy differs from frozen manifest",
    )
    return dict(
        manifest=manifest,
        ticket=ticket,
        assignment=assignment,
        safety=safety[ticket["assignment_id"]],
        core_sha256=core_sha,
        source_commit=revision,
        direct_files_sha256=direct,
        manifest_file_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        ticket_file_sha256=hashlib.sha256(ticket_raw).hexdigest(),
    )


def reject_observer_material(paths):
    units = (scope.INITIALIZER_UNIT, scope.OBSERVER_UNIT)
    names = {"service.d"}
    for unit in units:
        names.update(unit + suffix for suffix in ("", ".d", ".wants", ".requires", ".upholds"))
        parts = unit.removesuffix(".service").split("-")
        names.update("-".join(parts[:i]) + "-.service.d" for i in range(1, len(parts)))
    for parent in paths:
        plan.need(parent.is_absolute() and ".." not in parent.parts, "invalid actual unit search path")
        for name in names:
            plan.need(not os.path.lexists(parent / name), "preexisting observer/initializer unit material refused")


def fresh_preflight(inputs):
    g.guard()
    unit_paths = subprocess.run(["systemd-analyze", "unit-paths"], capture_output=True, text=True, check=True, timeout=2)
    plan.need(0 < len(unit_paths.stdout) <= 16384, "actual unit search paths unavailable")
    reject_observer_material([Path(row) for row in unit_paths.stdout.splitlines()])
    for path in (
        WORK,
        g.BASE,
        g.UNITS / g.UNIT,
        g.UNITS / g.WITNESS,
        g.UNITS / p.NET_UNIT,
        p.POLICY,
        g.UNITS / (g.UNIT + ".d"),
    ):
        plan.need(
            not os.path.lexists(path), "used assignment material refused; never retry"
        )
    for name in plan.names().values():
        plan.need(
            not os.path.lexists(Path("/run/netns") / name),
            "preexisting namespace refused; no predelete",
        )
    root = scope._cgroup_view()
    os.close(root)
    for unit in scope.ACTOR_UNITS:
        plan.need(
            scope._known_collected(scope._state(unit))
            and scope._group_empty("/system.slice/" + unit),
            "unexpected fixed actor/unit state before preparation",
        )
    plan.need(not g.Systemd().cores(), "unexpected native actor before preparation")
    return lab.isolated_api_preflight()


def namespace_prepare(expected_manifest_sha256, expected_start_head):
    # Runs only in the existing fixed root preparation unit. Do not require new
    # ptrace/DAC capabilities to inspect PID1 here: the controller proved the
    # full cgroup view before launching this unchanged two-capability unit.
    g.guard()
    inputs = validated_inputs(expected_manifest_sha256, expected_start_head)
    plan.need(
        not os.path.lexists(g.BASE) and not os.path.lexists(WORK),
        "namespace preparation requires unused assignment",
    )
    WORK.mkdir(mode=0o700)
    n.write_new(WORK / "inputs.json", inputs)
    assets = n.Assets(WORK)
    assets.names = plan.names()
    before = n.root_snapshot()
    cleanup_attempted = False
    try:
        assets.setup()
        n.write_new(
            WORK / "namespace-boot.json",
            dict(
                kernel_boot_id=g.boot(),
                names=plan.names(),
                root_before=before,
                foreign=assets.foreign,
            ),
        )
    except BaseException:
        cleanup_attempted = True
        assets.close()
        raise
    finally:
        plan.need(
            n.root_snapshot() == before,
            "parent state changed during namespace preparation",
        )
        if not cleanup_attempted:
            for fd, _, _ in assets.created.values():
                os.close(fd)


def _initialize_new_observer(create):
    plan.need(create is True, "only genuine new-scope initialization permitted")
    # Existing guest fixture just created BASE under the operator umask. Only
    # this newly owned fixture root needs the same traversal mode as the proven
    # terminal lab; never use this callback as a used-directory repair API.
    fd = os.open(g.BASE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        identity = os.fstat(fd)
        named = os.stat(g.BASE, follow_symlinks=False)
        plan.need(
            identity.st_uid == 0
            and (identity.st_dev, identity.st_ino) == (named.st_dev, named.st_ino),
            "new fixture base identity differs",
        )
        os.fchmod(fd, 0o755)
        os.fsync(fd)
        named = os.stat(g.BASE, follow_symlinks=False)
        plan.need(
            (named.st_dev, named.st_ino) == (identity.st_dev, identity.st_ino)
            and named.st_uid == 0
            and named.st_mode & 0o7777 == 0o755,
            "new fixture base changed during traversal setup",
        )
    finally:
        os.close(fd)
    try:
        result = subprocess.run(
            observer.role_argv("initialize"), capture_output=True, timeout=20
        )
    except subprocess.TimeoutExpired as exc:
        lab.save(WORK / "initialization.stdout", exc.stdout or b"")
        lab.save(WORK / "initialization.stderr", exc.stderr or b"")
        raise
    lab.save(WORK / "initialization.stdout", result.stdout)
    lab.save(WORK / "initialization.stderr", result.stderr)
    plan.need(
        result.returncode == 0,
        "genuine confined initialization failed; retain assignment",
    )
    value = plan.strict(result.stdout)
    plan.need(
        type(value) is dict and value.get("initialized_empty") is True,
        "genuine initialization result missing",
    )
    return value


def _failure_cleanup(error):
    try:
        stopped = scope.stop_systemd_actors()  # Always before any reopen/delete.
        if WORK.exists():
            n.write_new(WORK / "preparation-stop-receipt.json", stopped)
        plan.need(
            stopped["status"] == "verified_stopped",
            "preparation actors not verified stopped",
        )
        if (WORK / "namespace-boot.json").exists():
            assets, proof = scope.reopen_assets(WORK)
            try:
                assets.close()  # Existing identity-fenced cleanup, all handles tried.
            finally:
                plan.need(
                    n.root_snapshot() == proof["root_before"],
                    "parent state changed during preparation cleanup",
                )
    except BaseException as cleanup:
        error.add_note(
            "Lab cleanup unverified; retain all evidence: " + type(cleanup).__name__
        )


def prepare_assignment(expected_manifest_sha256, expected_start_head):
    inputs = validated_inputs(expected_manifest_sha256, expected_start_head)
    preflight = fresh_preflight(inputs)  # BEFORE output/accounts/profiles/keys/actors.
    try:
        plan.configure_assignment(inputs, observer_initializer=_initialize_new_observer)
        p.a.prepare_accounts()
        p.a.install_policy()
        plan.need(not os.path.lexists(p.POLICY), "existing provider profile refused")
        g.write(
            p.POLICY, _read(SRC / "tests/real_systemd/edge400-provider.apparmor", 32768)
        )
        g.command("apparmor_parser", "-r", str(p.POLICY))
        g.write(
            g.UNITS / p.NET_UNIT,
            f"[Unit]\nDescription=Fresh signed network namespaces; operator lab only\n[Service]\nType=oneshot\nRemainAfterExit=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN\nExecStart={g.PYTHON} -I {Path(__file__).resolve()} --namespace {expected_manifest_sha256} {expected_start_head}\n",
        )
        g.systemctl("daemon-reload")
        g.systemctl("start", p.NET_UNIT)
        g.prepare_lab()  # Existing witness-first provisioning invokes genuine init.
        trust, registered = verify(g.BUNDLE)
        plan.need(
            registered["schema_version"] == "outcome-live-origin-registration/v4"
            and registered["environment"]
            == plan.native_environment(inputs["assignment"]["arm"]),
            "materialized v4 registered environment differs",
        )
        plan.need(
            hashlib.sha256(_read(g.BASE / "native/protected.yaml", 8192)).hexdigest()
            == inputs["manifest"]["protected_policy_sha256"],
            "materialized protected policy differs",
        )
        # Candidate enforcement is never newly enabled by an inactive Switch:
        # reuse the existing empty-EVE ordinary core -> reviewed Switch sequence.
        g.systemctl("start", g.UNIT)
        g.wait_for(lambda: len(g.Systemd().cores()) == 1)
        switch = g.Switch(g.BUNDLE)
        switch_plan = switch.plan()
        plan.need(
            switch.apply(switch_plan, g.digest(switch_plan))["status"] == "started",
            "reviewed signed core did not start",
        )
        pid = p.identity()
        result = dict(
            inputs=inputs,
            isolated_api_preflight=preflight,
            kernel_boot_id=g.boot(),
            trust_policy=dict(trust.data),
            registration=registered,
            native_pid=pid,
            scope="prepared_fresh_signed_lab_not_measurement_or_production_admission",
        )
        n.write_new(WORK / "prepared.json", result)
        return result
    except BaseException as error:
        _failure_cleanup(error)
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--namespace", nargs=2, metavar=("MANIFEST_SHA256", "START_HEAD"), required=True
    )
    namespace_prepare(*parser.parse_args().namespace)
