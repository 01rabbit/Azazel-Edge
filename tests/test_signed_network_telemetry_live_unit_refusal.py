"""Synthetic actor/Root orchestration; real fixed guard, file IO and signed source."""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_live_unit_refusal as c


def fixture(tmp_path, monkeypatch, fault=None):
    output, units = tmp_path / "output", tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(c, "DROPIN", units / (c.role.OBSERVER_UNIT + ".d"))
    monkeypatch.setattr(c, "HOOK", c.DROPIN / "90-fixed-refusal-marker.conf")
    monkeypatch.setattr(c, "MARKER", tmp_path / "marker")
    monkeypatch.setattr(c.g, "guard", lambda: None)
    monkeypatch.setattr(c.os, "geteuid", lambda: 0)
    monkeypatch.setenv(c.FLAG, "1")
    monkeypatch.setenv(c.material.FLAG, "1")
    monkeypatch.setattr(
        c.material,
        "_read",
        lambda path, maximum=1024 * 1024: Path(path).read_bytes()
        if Path(path).exists()
        else b"{}",
    )
    monkeypatch.setattr(c, "TrustPolicy", lambda value: {"synthetic": True})
    monkeypatch.setattr(c.g, "boot", lambda: "synthetic-boot")
    monkeypatch.setattr(c.material, "SRC", Path("/opt/edge400-src"))
    events = []
    initialized = {"direct": True}
    monkeypatch.setattr(c.main.initializer, "initialize", lambda *a, **k: initialized)
    monkeypatch.setattr(
        c.lab,
        "journal_frames",
        lambda raw: [
            dict(kind=kind)
            for kind in ("header", "session_open", "input_ready", "session_close")
        ],
    )
    monkeypatch.setattr(c.g, "stop", lambda: events.append("native-stop"))
    monkeypatch.setattr(
        c, "_closed", lambda *a: events.append("closed-source-verified")
    )
    monkeypatch.setattr(
        c.material.preflight.old, "private_output", lambda path: path.mkdir(mode=0o700)
    )
    monkeypatch.setattr(
        c.material,
        "verify_current",
        lambda **k: dict(
            source_sha256={
                str(Path(c.role.SOURCE).relative_to(c.material.SRC)): "source"
            }
        ),
    )
    monkeypatch.setattr(c.main.initializer, "_namespace", lambda *a: [4, 5])

    def binding(**kwargs):
        events.append("current-binding-passive-witness")
        if fault == "witness":
            raise AssertionError("unknown witness")
        return {}, b"policy"

    monkeypatch.setattr(c.main.initializer, "_current_binding", binding)

    def check_init(value, binding):
        assert value is initialized
        if fault == "init-binding":
            raise AssertionError("wrong current binding")

    monkeypatch.setattr(c.live, "_initialized", check_init)

    def snapshot(path, phase):
        events.append(phase)
        raw = b"" if phase == "genuine-initialized" else b"closed-source"
        if fault == "source-change" and phase == "immediate-live-refusal":
            raw += b"changed"
        journal = (
            b"changed"
            if fault == "journal-change" and phase == "before-live-injection"
            else b"journal"
        )
        value = dict(
            public_auth={
                "hash": "changed"
                if fault == "public-auth-drift" and phase == "immediate-live-refusal"
                else "initial"
            },
            source=dict(raw=raw, identity={"inode": 4}),
            journal=dict(raw=journal),
            **{"observations.journal": dict(raw=journal)},
        )
        if fault == "after-cleanup-change" and phase == "after-owner-cleanup":
            value["journal"] = {"raw": b"changed"}
        c.lab.save(path / (phase + ".raw"), raw)
        return value

    monkeypatch.setattr(c, "_snapshot", snapshot)

    def foreign(path, create=False, phase="immediate"):
        if create:
            events.append("foreign-injected")
            c.DROPIN.mkdir()
            c.HOOK.write_bytes(c.WIRE)
        return {"hash": hashlib.sha256(c.HOOK.read_bytes()).hexdigest()}

    monkeypatch.setattr(c, "_foreign", foreign)
    monkeypatch.setattr(c.main.initializer.proof.p, "_output", lambda path: None)

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

    @contextmanager
    def original_live(path, **kwargs):
        events.append("original-live-entry")
        if fault == "unexpected-yield":
            yield SimpleNamespace()
            return
        if fault == "generic":
            raise RuntimeError("generic live failure")
        if fault == "artifact":
            c.lab.save_json(path / "live-intent.json", {})
        c.main.initializer.prelaunch_unit_material("live", path)
        pytest.fail("guard failed to refuse")
        yield

    monkeypatch.setattr(c.main, "live", original_live)

    def commission(path, **kwargs):
        path.mkdir(mode=0o700)
        for name in ("initialize", "live"):
            (path / name).mkdir()
        try:
            value = c.main.initializer.initialize(path / "initialize")
            events.append("ordinary-sealed-native-lifecycle")
            with c.main.live(
                path / "live",
                initialization={} if fault == "wrong-direct-init" else value,
                expected_sources={
                    str(Path(c.role.SOURCE).relative_to(c.material.SRC)): "source"
                },
                source_sha256="source",
                namespace_fd=3,
                namespace_identity=[4, 5],
                transport_context=object(),
            ):
                pytest.fail("outer body must not execute")
        finally:
            events.extend(("owner-witness-last", "owner-namespaces-close"))
            if fault == "cleanup-note":
                sys.exc_info()[1].add_note("uncertain cleanup")

    monkeypatch.setattr(c.main, "commission_telemetry", commission)

    def after(path):
        events.append("independent-cleanup")
        if fault == "cleanup":
            raise AssertionError("cleanup unknown")
        return {"synthetic": True}

    monkeypatch.setattr(c, "_after", after)
    return output, events, original_live


def invoke(output):
    return c.refuse_inherited_live_material(
        output,
        **{
            key: "a" * 64
            for key in (
                "source_commit",
                "archive_sha256",
                "core_sha256",
                "abi_sha256",
                "interpreter_sha256",
            )
        },
    )


def test_complete_flow_inner_snapshot_precedes_owner_cleanup(tmp_path, monkeypatch):
    output, events, original = fixture(tmp_path, monkeypatch)
    result = invoke(output)
    assert result["status"] == "inherited_live_material_refusal_complete"
    assert (
        events.index("native-stop")
        < events.index("closed-source-verified")
        < events.index("before-live-injection")
        < events.index("foreign-injected")
    )
    assert (
        events.index("immediate-live-refusal")
        < events.index("owner-witness-last")
        < events.index("independent-cleanup")
        < events.index("after-owner-cleanup")
    )
    assert c.main.live is original and c.HOOK.read_bytes() == c.WIRE
    assert all(
        result[key] is False
        for key in (
            "authorizes_transition",
            "experiment",
            "measurement_completed",
            "production_admission",
        )
    )


@pytest.mark.parametrize(
    "fault",
    [
        "witness",
        "init-binding",
        "wrong-direct-init",
        "journal-change",
        "source-change",
        "public-auth-drift",
        "after-cleanup-change",
        "unexpected-yield",
        "generic",
        "artifact",
        "cleanup",
        "cleanup-note",
    ],
)
def test_missing_changed_generic_or_yielded_state_never_passes(
    tmp_path, monkeypatch, fault
):
    output, events, original = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, RuntimeError)):
        invoke(output)
    assert c.main.live is original
    assert "independent-cleanup" in events
    assert not (output / "live-unit-refusal-result.json").exists()
    assert (output / "live-unit-refusal-failure.json").exists()


@pytest.mark.parametrize("fault", ["flag", "existing", "unknown"])
def test_fresh_preflight_refuses_without_owner(tmp_path, monkeypatch, fault):
    output, events, _ = fixture(tmp_path, monkeypatch)
    if fault == "flag":
        monkeypatch.delenv(c.FLAG)
    elif fault == "existing":
        c.DROPIN.mkdir()
    else:
        real = os.lstat

        def lstat(path, *a, **kw):
            if Path(path) == c.DROPIN:
                raise PermissionError("unknown fixture")
            return real(path, *a, **kw)

        monkeypatch.setattr(c.os, "lstat", lstat)
    with pytest.raises((AssertionError, PermissionError)):
        invoke(output)
    assert events == [] and not output.exists()


@pytest.mark.parametrize(
    "fault", [None, "signature", "unclosed", "extra-decision", "core", "truthy-cgroup"]
)
def test_closed_native_boundary_uses_real_signature_and_lifecycle_verifier(
    tmp_path, monkeypatch, fault
):
    from test_signed_network_run import signed_source_fixture, KERNEL, decision

    reader, state, append = signed_source_fixture(tmp_path, monkeypatch)
    if fault == "extra-decision":
        append("decision_execution", 2, decision())
        append("session_end", 3)
    elif fault != "unclosed":
        append("session_end", 2)
    if fault == "signature":
        state["raw"] = state["raw"].replace(b'"signature":"', b'"signature":"0', 1)
    monkeypatch.setattr(c, "read_regular", lambda *a, **kw: (state["raw"], None))
    monkeypatch.setattr(
        c.lab,
        "unit_snapshot",
        lambda _: dict(
            MainPID="0", ControlPID="0", ActiveState="inactive", ControlGroup=""
        ),
    )
    monkeypatch.setattr(
        c.lab.cg, "group_empty", lambda *a: 1 if fault == "truthy-cgroup" else True
    )
    monkeypatch.setattr(
        c.g,
        "Systemd",
        lambda: SimpleNamespace(cores=lambda: [123] if fault == "core" else []),
    )
    monkeypatch.setattr(c.g, "boot", lambda: KERNEL)
    if fault:
        with pytest.raises(Exception):
            c._closed(tmp_path, reader.verifier.policy)
    else:
        c._closed(tmp_path, reader.verifier.policy)
        assert (tmp_path / "native-closed-source.raw").read_bytes() == state["raw"]


def test_snapshot_preserves_real_file_bytes_fixed_absence_and_public_continuity(
    tmp_path, monkeypatch
):
    """Actual private IO with explicit synthetic role-owner metadata adapter only."""
    from azazel_edge.outcome.input_auth import read_regular

    bundle, output = tmp_path / "bundle", tmp_path / "out"
    output.mkdir(mode=0o700)
    observer = bundle / "observer"
    observer.mkdir(parents=True, mode=0o700)
    (bundle / "witness/anchors").mkdir(parents=True, mode=0o700)
    for path, raw, mode in (
        (bundle / "input", b"source", 0o644),
        (observer / "observations.journal", b"journal", 0o600),
        (bundle / "witness/anchors/anchors.journal", b"anchors", 0o600),
    ):
        path.write_bytes(raw)
        path.chmod(mode)
    monkeypatch.setattr(c.g, "BUNDLE", bundle)
    physical_owner = os.geteuid()
    monkeypatch.setattr(
        c,
        "read_regular",
        lambda path, *, owner, **kwargs: read_regular(
            path, owner=physical_owner, **kwargs
        ),
    )
    actual = os.lstat

    def lstat(path, *args, **kwargs):
        info = actual(path, *args, **kwargs)
        if Path(path) == observer:
            fields = list(info)
            fields[4] = 61002
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(c.os, "lstat", lstat)
    public = dict(trust_sha256="a" * 64, origin_file_sha256="b" * 64)
    monkeypatch.setattr(c.main.initializer, "public_auth_binding", lambda: dict(public))
    before = c._snapshot(output, "before")
    assert before["source"]["raw"] == b"source"
    assert before["actual-collector-calls.jsonl"] == dict(absent=True)
    public["origin_file_sha256"] = "c" * 64
    after = c._snapshot(output, "after")
    assert before["public_auth"] != after["public_auth"]
    assert before["observations.journal"] == after["observations.journal"]
    assert (output / "before-source.raw").read_bytes() == b"source"


@pytest.mark.skipif(
    os.geteuid() != 0, reason="physical Root creation check requires offline Linux Root"
)
def test_live_foreign_exact_file_has_distinct_phase_receipts_and_retained_identity(
    tmp_path, monkeypatch
):
    output = tmp_path / "out"
    output.mkdir(mode=0o700)
    monkeypatch.setattr(c, "DROPIN", tmp_path / "fixed-live.d")
    monkeypatch.setattr(c, "HOOK", c.DROPIN / "90-fixed-refusal-marker.conf")
    previous = os.umask(0o077)
    try:
        original = c._foreign(output, create=True)
    finally:
        os.umask(previous)
    assert c._foreign(output) == original == c._foreign(output, phase="owner")
    assert c.HOOK.read_bytes() == c.WIRE
    assert c.DROPIN.stat().st_mode & 0o777 == 0o755
    for name in ("created", "immediate", "owner"):
        assert (output / ("live-foreign-" + name + ".raw")).read_bytes() == c.WIRE
