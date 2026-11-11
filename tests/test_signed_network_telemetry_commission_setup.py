"""Synthetic Root/kernel/tool observations only; no setup, policy load or VM."""

from pathlib import Path
import hashlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_commission_setup as setup

BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"
IMAGE = b"\x7fELF\x02\x01PUBLIC SYNTHETIC CORE"


def fixture(tmp_path, monkeypatch, fault=None):
    output = tmp_path / "private-output"
    lookup = tmp_path / "unit-lookup"
    lookup.mkdir()
    events, reads = [], []
    pins = dict(
        source_commit="a" * 40,
        archive_sha256="b" * 64,
        core_sha256=hashlib.sha256(IMAGE).hexdigest(),
        abi_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )

    def read(path, limit=1024 * 1024, mode=None):
        path = Path(path)
        reads.append(path)
        if path == Path("/etc/edge400-disposable-vm"):
            return b"wrong" if fault == "marker" else setup.g.MAGIC.encode()
        if path.name == "SOURCE_REVISION":
            return b"e" * 40 if fault == "source" else b"a" * 40 + b"\n"
        if path == setup.g.CORE:
            assert mode == 0o755 and limit == 128 * 1024 * 1024
            return IMAGE + (b"changed" if fault == "core" else b"")
        return path.read_bytes()

    monkeypatch.setattr(setup.material, "_read", read)
    monkeypatch.setattr(setup.g, "guard", lambda: events.append("guard"))
    monkeypatch.setattr(setup.g, "boot", lambda: BOOT)
    monkeypatch.setattr(setup.g, "BASE", tmp_path / "scope")
    states = []

    def state(unit):
        states.append(unit)
        return {"expected": "absent", "unit": unit}

    monkeypatch.setattr(setup.scope, "_state", state)
    monkeypatch.setattr(setup.scope, "_known_collected", lambda value: fault != "actor")
    monkeypatch.setattr(
        setup.lab.cg,
        "group_empty",
        lambda path, units: fault != "cgroup" and units == setup.UNITS,
    )
    monkeypatch.setattr(
        setup.g,
        "Systemd",
        lambda: SimpleNamespace(cores=lambda: [123] if fault == "coreactor" else []),
    )
    namespaces = {Path("/run/netns") / name for name in setup.role.NAMESPACE_NAMES}
    lexists = setup.os.path.lexists

    def exists(path):
        return fault == "namespace" and Path(path) in namespaces or lexists(path)

    monkeypatch.setattr(setup.os.path, "lexists", exists)
    current = dict(
        loaded_profiles="\n".join(
            name + " (enforce)"
            for name in (
                "edge400-capture",
                "edge400-observer",
                "edge400-witness",
                "edge400-native",
                "edge400-provider",
                setup.role.PROFILE,
            )
        ),
        source_sha256={"public-module": "f" * 64},
    )
    material_calls = []

    def material(**actual):
        assert actual == dict(
            abi_sha256=pins["abi_sha256"], interpreter_sha256=pins["interpreter_sha256"]
        )
        material_calls.append(1)
        events.append("material")
        if fault == "material":
            raise AssertionError("synthetic current material failure")
        if fault == "loaded":
            return dict(current, loaded_profiles="")
        return current

    monkeypatch.setattr(setup.material, "verify_current", material)

    def assets():
        events.append("assets")
        if fault == "assetsread" and events.count("assets") > 1:
            raise PermissionError("synthetic asset read failure")
        return {
            "old-and-provider": "changed"
            if fault == "assetsdrift" and events.count("assets") > 1
            else "original"
        }

    monkeypatch.setattr(setup, "_assets", assets)
    monkeypatch.setattr(setup, "_accounts", lambda: {"roles": "public-locked"})

    def snapshot():
        events.append("parent")
        return {
            "network": "changed"
            if fault == "parentdrift" and events.count("parent") > 1
            else "original"
        }

    monkeypatch.setattr(setup.n, "root_snapshot", snapshot)
    monkeypatch.setattr(
        setup.lab, "isolated_api_preflight", lambda: {"actual_import": "synthetic"}
    )

    def private(path):
        events.append("output")
        path.mkdir(mode=0o700)

    monkeypatch.setattr(setup.material.preflight.old, "private_output", private)

    def query(argv, prefix, path):
        assert (
            argv == ["systemd-analyze", "unit-paths"]
            and prefix == "commission-unit-paths"
        )
        events.append("query")
        raw = (str(lookup) + "\n").encode()
        if fault == "duplicate":
            raw += raw
        if fault == "badpath":
            raw = b"/etc/systemd/../system\n"
        setup.lab.save(path / (prefix + ".stdout"), raw)
        setup.lab.save(path / (prefix + ".stderr"), b"")
        setup.lab.save_json(
            path / (prefix + ".result.json"),
            dict(returncode=None if fault == "query" else 0),
        )
        return None if fault == "query" else 0, raw

    monkeypatch.setattr(setup.material.preflight.old, "_retained_query", query)

    def compile(path, **actual):
        assert (path / "root-before.json").exists() and (
            path / "commission-baseline.json"
        ).exists()
        events.append("compile-only")
        if fault == "compile":
            raise AssertionError("synthetic compile warning/failure")
        return current

    monkeypatch.setattr(setup.material, "compile_current", compile)
    return output, lookup, pins, events, reads, states


def test_prerequisite_component_saves_baselines_before_compile_and_never_creates_scope(
    tmp_path, monkeypatch
):
    output, _, pins, events, reads, states = fixture(tmp_path, monkeypatch)
    result = setup.preflight(output, **pins)
    assert result["pins"] == pins and set(states) == set(setup.UNITS)
    assert (
        events.index("parent")
        < events.index("output")
        < events.index("query")
        < events.index("compile-only")
    )
    assert (output / "commission-preflight.json").exists()
    assert not setup.g.BASE.exists()
    assert not any("key.raw" in str(path) or "journal" in str(path) for path in reads)
    assert (
        result["authorizes_transition"]
        is result["experiment"]
        is result["production_admission"]
        is False
    )


@pytest.mark.parametrize(
    "fault",
    [
        "marker",
        "source",
        "core",
        "material",
        "loaded",
        "actor",
        "cgroup",
        "coreactor",
        "namespace",
        "usedbase",
        "usedoutput",
    ],
)
def test_bad_source_or_used_unknown_resources_refuse_before_output_or_compiler(
    tmp_path, monkeypatch, fault
):
    output, _, pins, events, _, _ = fixture(tmp_path, monkeypatch, fault)
    if fault == "usedbase":
        setup.g.BASE.mkdir()
    if fault == "usedoutput":
        output.mkdir()
    with pytest.raises(AssertionError):
        setup.preflight(output, **pins)
    assert (
        "output" not in events
        and "query" not in events
        and "compile-only" not in events
    )


@pytest.mark.parametrize(
    "fault",
    [
        "query",
        "duplicate",
        "badpath",
        "compile",
        "assetsdrift",
        "assetsread",
        "parentdrift",
    ],
)
def test_failure_retains_baselines_and_attempts_parent_assets_material_independently(
    tmp_path, monkeypatch, fault
):
    output, _, pins, events, _, _ = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises(AssertionError):
        setup.preflight(output, **pins)
    assert (output / "root-before.json").exists() and (
        output / "commission-baseline.json"
    ).exists()
    assert (
        events.count("parent") == 2
        and events.count("assets") == 2
        and events.count("material") == 2
    )
    assert not (output / "commission-preflight.json").exists()


@pytest.mark.parametrize(
    "name",
    [
        setup.scope.INITIALIZER_UNIT + ".d",
        setup.scope.OBSERVER_UNIT + ".wants",
        setup.role.INITIALIZER_UNIT + ".requires",
        setup.role.OBSERVER_UNIT + ".upholds",
        setup.g.UNIT,
        setup.g.WITNESS + ".d",
        setup.p.NET_UNIT + ".d",
        "edge400-signed-network-telemetry-.service.d",
        "edge400-signed-network-.service.d",
        "edge400-lab-provider-.service.d",
        "service.d",
    ],
)
def test_every_fixed_family_and_inherited_prefix_is_refused_even_dangling(
    tmp_path, monkeypatch, name
):
    output, lookup, pins, events, _, _ = fixture(tmp_path, monkeypatch)
    (lookup / name).symlink_to(lookup / "does-not-exist")
    with pytest.raises(AssertionError, match="unit material"):
        setup.preflight(output, **pins)
    assert "compile-only" not in events and not setup.g.BASE.exists()
    assert (output / "commission-unit-paths.stdout").exists()


@pytest.mark.parametrize(
    "name",
    [
        "source_commit",
        "archive_sha256",
        "core_sha256",
        "abi_sha256",
        "interpreter_sha256",
    ],
)
def test_all_external_pins_are_mandatory_and_strict_before_reads(
    tmp_path, monkeypatch, name
):
    output, _, pins, events, reads, _ = fixture(tmp_path, monkeypatch)
    pins[name] = True
    with pytest.raises((AssertionError, ValueError)):
        setup.preflight(output, **pins)
    assert reads == [] and "output" not in events


@pytest.mark.parametrize("fault", [None, "uid", "shell", "groups", "unlocked"])
def test_external_accounts_are_checked_without_shadow_or_secret_reads(
    monkeypatch, fault
):
    requests = []
    monkeypatch.setattr(
        setup.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(
            pw_uid={"capture": 61001, "observer": 61002, "ai": 61003}[
                name.removeprefix("edge400-")
            ],
            pw_gid={"capture": 61001, "observer": 61002, "ai": 61003}[
                name.removeprefix("edge400-")
            ],
            pw_shell="/usr/sbin/nologin",
            pw_dir="/nonexistent",
        ),
    )
    monkeypatch.setattr(
        setup.grp,
        "getgrnam",
        lambda name: SimpleNamespace(gr_gid=setup.pwd.getpwnam(name).pw_gid),
    )
    monkeypatch.setattr(setup.os, "getgrouplist", lambda name, uid: [uid])

    def status(argv, **kw):
        requests.append(argv)
        assert argv[:2] == ["passwd", "--status"] and kw == dict(
            capture_output=True, timeout=2
        )
        return SimpleNamespace(
            returncode=0, stdout=(argv[-1] + " L public status\n").encode()
        )

    monkeypatch.setattr(setup.subprocess, "run", status)
    if fault == "uid":
        original = setup.pwd.getpwnam
        monkeypatch.setattr(
            setup.pwd,
            "getpwnam",
            lambda name: SimpleNamespace(**{**vars(original(name)), "pw_uid": 0}),
        )
    elif fault == "shell":
        original = setup.pwd.getpwnam
        monkeypatch.setattr(
            setup.pwd,
            "getpwnam",
            lambda name: SimpleNamespace(
                **{**vars(original(name)), "pw_shell": "/bin/sh"}
            ),
        )
    elif fault == "groups":
        monkeypatch.setattr(setup.os, "getgrouplist", lambda name, uid: [uid, 0])
    elif fault == "unlocked":
        monkeypatch.setattr(
            setup.subprocess,
            "run",
            lambda argv, **kw: SimpleNamespace(
                returncode=0, stdout=(argv[-1] + " P public status\n").encode()
            ),
        )
    if fault is not None:
        with pytest.raises(AssertionError):
            setup._accounts()
        return
    result = setup._accounts()
    assert len(requests) == 3 and all(
        value["locked"] is True for value in result.values()
    )


@pytest.mark.parametrize("changed", [False, True])
def test_external_provider_text_must_match_protected_source_no_install_or_repair(
    monkeypatch, changed
):
    monkeypatch.setattr(setup.old, "old_assets", lambda: {"old": "original"})
    reads = []

    def read(path, limit):
        reads.append(path)
        assert limit == 32768
        return (
            b"changed"
            if changed and path == setup.p.POLICY
            else b"PUBLIC provider profile"
        )

    monkeypatch.setattr(setup.material, "_read", read)
    if changed:
        with pytest.raises(AssertionError, match="provider profile"):
            setup._assets()
    else:
        assert setup._assets()["old"] == "original"
    assert reads == [
        setup.material.SRC / "tests/real_systemd/edge400-provider.apparmor",
        setup.p.POLICY,
    ]
