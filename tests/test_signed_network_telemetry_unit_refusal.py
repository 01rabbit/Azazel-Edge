"""Synthetic actor/Root facts; real fixed guard and private artifact IO. No VM."""

import hashlib
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_unit_refusal as c


def fixture(tmp_path, monkeypatch, fault=None):
    output = tmp_path / "output"
    units = tmp_path / "units"
    units.mkdir()
    dropin = units / (c.role.INITIALIZER_UNIT + ".d")
    monkeypatch.setattr(c, "DROPIN", dropin)
    monkeypatch.setattr(c, "HOOK", dropin / "90-fixed-refusal-marker.conf")
    monkeypatch.setattr(c, "MARKER", tmp_path / "marker")
    monkeypatch.setattr(c.g, "guard", lambda: None)
    monkeypatch.setattr(c.os, "geteuid", lambda: 0)
    monkeypatch.setenv(c.FLAG, "1")
    monkeypatch.setenv(c.material.FLAG, "1")
    monkeypatch.setattr(c.g, "boot", lambda: "synthetic-boot")
    monkeypatch.setattr(
        c.main.initializer, "namespace_observation", lambda _: {"synthetic": True}
    )
    monkeypatch.setattr(c.lab, "unit_snapshot", lambda _: dict(MainPID="123"))
    monkeypatch.setattr(
        c.material, "_read", lambda path, maximum=1024 * 1024: Path(path).read_bytes()
    )
    monkeypatch.setattr(c.main.initializer.proof.p, "_output", lambda path: None)
    events = []
    monkeypatch.setattr(
        c.material.preflight.old, "private_output", lambda path: path.mkdir(mode=0o700)
    )
    monkeypatch.setattr(c.main.initializer, "_namespace", lambda fd, pair: [4, 5])
    monkeypatch.setattr(
        c.main.initializer, "public_auth_binding", lambda: {"synthetic_public": True}
    )

    def witness(auth, namespace, directory, phase, observed):
        events.append("actual-passive-barrier-interface")
        assert namespace == [4, 5] and phase == "initialize-initial"
        assert directory == output / "pre-injection-witness"
        if fault == "witness":
            raise AssertionError("listener not ready")
        return {"synthetic_root_witness_proof": True}

    monkeypatch.setattr(c.main.initializer, "witness_binding", witness)
    original_guard = c.main.initializer.prelaunch_unit_material

    def query(argv, prefix, directory):
        c.lab.save_json(directory / (prefix + ".argv.json"), argv)
        raw = (str(units) + "\n").encode()
        c.lab.save(directory / (prefix + ".stdout"), raw)
        c.lab.save(directory / (prefix + ".stderr"), b"")
        c.lab.save_json(
            directory / (prefix + ".result.json"), dict(returncode=0, error=None)
        )
        return 0, raw

    monkeypatch.setattr(c.main.initializer.proof.p.old, "_retained_query", query)

    def initialize(path, **kwargs):
        events.append("unchanged-material-guard")
        if fault == "generic":
            raise RuntimeError("generic failure")
        if fault == "launch-artifact":
            c.lab.save_json(path / "initializer-intent.json", {})
        if fault == "marker":
            c.MARKER.touch()
        if fault == "query-missing":
            raise AssertionError(c.REFUSAL)
        if fault == "false-success":
            return {}
        original_guard("initialize", path)
        pytest.fail("guard failed to stop launch")

    monkeypatch.setattr(c.main.initializer, "initialize", initialize)

    def commission(path, **pins):
        path.mkdir(mode=0o700)
        (path / "initialize").mkdir(mode=0o700)
        (path / "live").mkdir(mode=0o700)
        events.append("owned-resources-ready")
        try:
            c.main.initializer.initialize(
                path / "initialize",
                transport_context=object(),
                namespace_fd=123,
                namespace_identity=[4, 5],
            )
        finally:
            events.extend(("owned-actors-witness-last", "owned-namespace-close"))
            if fault == "cleanup-note":
                error = sys.exc_info()[1]
                error.add_note("commission cleanup failed")

    monkeypatch.setattr(c.main, "commission_telemetry", commission)

    def foreign(path, *, create=False):
        if create:
            c.DROPIN.mkdir()
            c.HOOK.write_bytes(c.WIRE)
            c.lab.save_json(path / "foreign-create-intent.json", {})
        elif fault == "foreign-change":
            c.HOOK.write_bytes(b"changed")
        return dict(hash=hashlib.sha256(c.HOOK.read_bytes()).hexdigest())

    monkeypatch.setattr(c, "_foreign", foreign)

    def snapshot(path, phase):
        c.lab.save(
            path / (phase + "-source.raw"),
            b"source" if fault == "source-change" and phase == "after-refusal" else b"",
        )
        return {
            "synthetic": "changed"
            if fault == "source-change" and phase == "after-refusal"
            else "unchanged"
        }

    monkeypatch.setattr(c, "_snapshot", snapshot)

    def after(path):
        events.append("independent-checks")
        if fault == "cleanup":
            raise AssertionError("unknown cleanup")
        return dict(synthetic_cleanup=True)

    monkeypatch.setattr(c, "_after", after)
    return output, events, initialize


def invoke(output):
    return c.refuse_inherited_initializer_material(
        output,
        **{
            name: "a" * 64
            for name in (
                "source_commit",
                "archive_sha256",
                "core_sha256",
                "abi_sha256",
                "interpreter_sha256",
            )
        },
    )


def test_exact_guard_refusal_after_ready_then_cleanup_and_foreign_retention(
    tmp_path, monkeypatch
):
    output, events, original = fixture(tmp_path, monkeypatch)
    result = invoke(output)
    assert result["status"] == "inherited_initializer_material_refusal_complete"
    assert result["intentional_foreign_material_retained"] is True
    assert all(
        result[key] is False
        for key in (
            "authorizes_transition",
            "experiment",
            "measurement_completed",
            "production_admission",
        )
    )
    assert events == [
        "owned-resources-ready",
        "actual-passive-barrier-interface",
        "unchanged-material-guard",
        "owned-actors-witness-last",
        "owned-namespace-close",
        "independent-checks",
    ]
    assert c.main.initializer.initialize is original and c.HOOK.read_bytes() == c.WIRE
    assert (output / "initialize/initialize-launch-unit-paths.stdout").exists()
    assert not (output / "initialize/initializer-intent.json").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "generic",
        "launch-artifact",
        "marker",
        "query-missing",
        "false-success",
        "cleanup-note",
        "source-change",
        "foreign-change",
        "cleanup",
    ],
)
def test_generic_or_missing_or_changed_evidence_never_completes(
    tmp_path, monkeypatch, fault
):
    output, events, original = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, RuntimeError, FileNotFoundError)):
        invoke(output)
    assert c.main.initializer.initialize is original
    assert events[-1] == "independent-checks"
    assert not (output / "unit-refusal-result.json").exists()
    assert (output / "unit-refusal-failure.json").exists()
    assert c.HOOK.exists()  # Never remove/repair the foreign fixture.


@pytest.mark.parametrize(
    "fault", ["flag", "telemetry-flag", "existing", "dangling", "marker"]
)
def test_outer_guard_refuses_before_any_owner_activity(tmp_path, monkeypatch, fault):
    output, events, _ = fixture(tmp_path, monkeypatch)
    if fault == "flag":
        monkeypatch.delenv(c.FLAG)
    elif fault == "telemetry-flag":
        monkeypatch.delenv(c.material.FLAG)
    elif fault == "existing":
        c.DROPIN.mkdir()
    elif fault == "dangling":
        c.DROPIN.symlink_to(tmp_path / "absent")
    else:
        c.MARKER.touch()
    with pytest.raises(AssertionError):
        invoke(output)
    assert events == [] and not output.exists()


@pytest.mark.skipif(
    os.geteuid() != 0,
    reason="actual Root physical-file guard requires offline Linux Root check",
)
def test_real_exclusive_foreign_fixture_permissions_identity_and_no_retry(
    tmp_path, monkeypatch
):
    output = tmp_path / "output"
    output.mkdir(mode=0o700)
    monkeypatch.setattr(c, "DROPIN", tmp_path / "fixed.d")
    monkeypatch.setattr(c, "HOOK", c.DROPIN / "90-fixed-refusal-marker.conf")
    previous = os.umask(0o077)
    try:
        first = c._foreign(output, create=True)
    finally:
        os.umask(previous)
    assert first == c._foreign(output)
    assert c.DROPIN.stat().st_mode & 0o777 == 0o755
    assert c.HOOK.stat().st_mode & 0o777 == 0o644
    assert c.HOOK.read_bytes() == c.WIRE
    with pytest.raises(FileExistsError):
        c._foreign(output, create=True)
    assert c.HOOK.read_bytes() == c.WIRE


@pytest.mark.parametrize(
    "fault", [None, "receipt", "first-actor", "namespace-permission", "truthy-group"]
)
def test_independent_cleanup_attempts_all_fixed_actors_despite_failed_proof(
    tmp_path, monkeypatch, fault
):
    import json

    output = tmp_path
    (output / "namespace-evidence").mkdir()
    (output / "actor-cleanup.json").write_text(
        json.dumps(dict(errors=["unknown"] if fault == "receipt" else []))
    )
    (output / "namespace-evidence/cleanup.json").write_text(
        json.dumps(dict(errors=[], cleanup_verified=True))
    )
    (output / "commission-baseline.json").write_text(
        json.dumps(dict(root_before={}, kernel_boot_id="synthetic"))
    )
    monkeypatch.setattr(c.material, "_read", lambda path: Path(path).read_bytes())
    calls = []

    def state(unit):
        calls.append(unit)
        if fault == "first-actor" and unit == c.main.setup.UNITS[0]:
            raise OSError("unknown PID")
        return dict(
            ActiveState="inactive", MainPID="0", ControlPID="0", ControlGroup=""
        )

    monkeypatch.setattr(c.main.setup.scope, "_state", state)
    monkeypatch.setattr(
        c.lab.cg, "group_empty", lambda *a: 1 if fault == "truthy-group" else True
    )
    monkeypatch.setattr(
        c.g, "Systemd", lambda: type("System", (), {"cores": lambda self: []})()
    )
    monkeypatch.setattr(c.g, "boot", lambda: "synthetic")
    monkeypatch.setattr(c.main.setup.n, "root_snapshot", lambda: {})
    namespace_calls = []
    actual_lstat = os.lstat

    def namespace_lstat(path, *args, **kwargs):
        path = Path(path)
        if path.parent == Path("/run/netns"):
            namespace_calls.append(path.name)
            if (
                fault == "namespace-permission"
                and path.name == c.role.NAMESPACE_NAMES[0]
            ):
                raise PermissionError("unknown namespace access")
            raise FileNotFoundError(str(path))
        return actual_lstat(path, *args, **kwargs)

    monkeypatch.setattr(c.os, "lstat", namespace_lstat)
    if fault:
        with pytest.raises(AssertionError, match="independent cleanup incomplete"):
            c._after(output)
    else:
        assert c._after(output)["all_fixed_groups_empty"] is True
    assert calls == list(c.main.setup.UNITS)
    assert namespace_calls == list(c.role.NAMESPACE_NAMES)
    observed = json.loads(
        (output / "independent-namespace-observations.json").read_bytes()
    )["observations"]
    assert len(observed) == 3
    assert observed[0]["state"] == (
        "unknown" if fault == "namespace-permission" else "absent"
    )
    if fault == "namespace-permission":
        assert observed[0]["error"] == "PermissionError"
        assert [row["state"] for row in observed[1:]] == ["absent", "absent"]
    assert (output / "independent-parent-after.json").exists()
    assert bool(
        json.loads((output / "independent-cleanup-checks.json").read_bytes())["errors"]
    ) == bool(fault)


def test_unknown_fresh_fixture_stat_never_invokes_owner(tmp_path, monkeypatch):
    output, events, _ = fixture(tmp_path, monkeypatch)
    real = os.lstat

    def lstat(path, *a, **kw):
        if Path(path) == c.DROPIN:
            raise PermissionError("unknown preflight")
        return real(path, *a, **kw)

    monkeypatch.setattr(c.os, "lstat", lstat)
    with pytest.raises(PermissionError):
        invoke(output)
    assert events == [] and not output.exists()


def test_unknown_post_refusal_marker_stat_never_completes(tmp_path, monkeypatch):
    output, events, _ = fixture(tmp_path, monkeypatch)
    real = os.lstat

    def lstat(path, *a, **kw):
        if Path(path) == c.MARKER and "independent-checks" in events:
            raise PermissionError("unknown marker state")
        return real(path, *a, **kw)

    monkeypatch.setattr(c.os, "lstat", lstat)
    with pytest.raises(PermissionError):
        invoke(output)
    assert (output / "unit-refusal-failure.json").exists()
    assert not (output / "unit-refusal-result.json").exists()
    assert c.HOOK.exists()


def test_witness_barrier_failure_prevents_injection_and_still_attempts_cleanup(
    tmp_path, monkeypatch
):
    output, events, _ = fixture(tmp_path, monkeypatch, "witness")
    with pytest.raises(AssertionError, match="listener not ready"):
        invoke(output)
    assert "independent-checks" in events and not c.HOOK.exists()
    assert not (output / "unit-refusal-entered.json").exists()
    assert not (output / "unit-refusal-result.json").exists()
