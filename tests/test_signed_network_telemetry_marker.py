"""Synthetic Root/unit observations plus real private FD writes; no systemd load."""

import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_marker as marker


def effective():
    value = dict.fromkeys(marker.material.preflight.EFFECTIVE, "")
    value.update(
        User="root",
        Group="root",
        NoNewPrivileges="yes",
        RestrictAddressFamilies="AF_UNIX",
        Restart="no",
        DefaultDependencies="no",
        FragmentPath=str(marker.g.UNITS / marker.p.NET_UNIT),
        TimeoutStopUSec="3s",
        Requires="system.slice",
        After="system.slice systemd-journald.socket",
        ExecStart="{ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no }",
    )
    return value


def fixture(tmp_path, monkeypatch, fault=None):
    units, output = tmp_path / "units", tmp_path / "evidence"
    units.mkdir()
    output.mkdir()
    events = []
    monkeypatch.setattr(marker.g, "UNITS", units)
    monkeypatch.setattr(marker.g, "guard", lambda: events.append("guard"))
    monkeypatch.setattr(marker.g, "boot", lambda: "actual-boot-fixture")
    baseline = dict(
        pins=dict(abi_sha256="a" * 64, interpreter_sha256="b" * 64),
        kernel_boot_id="actual-boot-fixture",
        material={"exact": "current"},
    )
    monkeypatch.setattr(
        marker.material, "verify_current", lambda **pins: baseline["material"]
    )
    monkeypatch.setattr(marker.material.preflight, "_output", lambda path: None)

    def inherited(path):
        events.append("unit-material")
        if fault == "inherited":
            raise AssertionError("synthetic inherited material")

    monkeypatch.setattr(marker.setup, "_unit_material", inherited)
    monkeypatch.setattr(
        marker.setup.scope, "_state", lambda unit: {"expected": "absent"}
    )
    monkeypatch.setattr(
        marker.setup.scope, "_known_collected", lambda value: fault != "existing"
    )
    monkeypatch.setattr(
        marker.lab.cg, "group_empty", lambda group, allowed: fault != "cgroup"
    )

    def parent(path, **kw):
        assert path == units / marker.p.NET_UNIT and kw == dict(trusted_owner=0)
        return os.open(units, os.O_RDONLY | os.O_DIRECTORY), marker.p.NET_UNIT

    monkeypatch.setattr(marker.material.preflight, "open_parent", parent)
    real_stat = os.stat

    def metadata(name, **kw):
        info = real_stat(name, **kw)
        return SimpleNamespace(
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
            st_uid=61002 if fault == "owner" else 0,
        )

    real_write = os.write

    def writing(fd, raw):
        return real_write(fd, raw[:5] if fault == "shortwrite" else raw)

    monkeypatch.setattr(
        marker,
        "os",
        SimpleNamespace(
            **{
                key: getattr(os, key)
                for key in (
                    "open",
                    "close",
                    "fstat",
                    "fchmod",
                    "fsync",
                    "O_WRONLY",
                    "O_CREAT",
                    "O_EXCL",
                    "O_NOFOLLOW",
                )
            },
            stat=metadata,
            write=writing,
        ),
    )
    monkeypatch.setattr(
        marker.material, "_read", lambda path, *a: Path(path).read_bytes()
    )

    def collect(unit, prefix, path):
        assert unit == marker.p.NET_UNIT and prefix == "marker"
        value = effective()
        if fault == "hook":
            value["ExecStartPre"] = "unexpected"
        if fault == "cap":
            value["CapabilityBoundingSet"] = "cap_net_admin"
        if fault == "exec":
            value["ExecStart"] = value["ExecStart"].replace(
                "/usr/bin/true", "/usr/bin/false"
            )
        if fault == "duplicateexec":
            value["ExecStart"] = value["ExecStart"].replace(
                " ; argv[]", " ; path=/usr/bin/true ; argv[]"
            )
        return value

    monkeypatch.setattr(marker.material.preflight, "_collect_effective", collect)

    def query(argv, prefix, path):
        events.append(prefix)
        state = dict(
            Type="oneshot",
            RemainAfterExit="yes",
            ActiveState="active",
            SubState="exited",
            LoadState="loaded",
            MainPID="0",
            ControlPID="0",
        )
        if fault == "state":
            state["MainPID"] = "123"
        raw = (
            "\n".join(k + "=" + v for k, v in state.items()).encode() + b"\n"
            if prefix == "marker-state"
            else b""
        )
        code = None if fault == "starttimeout" and prefix == "marker-start" else 0
        marker.lab.save(path / (prefix + ".stdout"), raw)
        marker.lab.save(path / (prefix + ".stderr"), b"")
        marker.lab.save_json(path / (prefix + ".result.json"), dict(returncode=code))
        assert argv in (
            ["systemctl", "daemon-reload"],
            ["systemctl", "start", marker.p.NET_UNIT],
            [
                "systemctl",
                "show",
                marker.p.NET_UNIT,
                "--property=Type,RemainAfterExit,ActiveState,SubState,LoadState,MainPID,ControlPID",
            ],
        )
        return code, raw

    monkeypatch.setattr(marker.material.preflight.old, "_retained_query", query)

    def cleanup(units_arg, tracked):
        assert units_arg == (marker.p.NET_UNIT,) and tracked == {marker.p.NET_UNIT: []}
        events.append("owned-stop")
        return dict(errors=["synthetic unknown CG"] if fault == "stop" else [])

    monkeypatch.setattr(marker.lab, "cleanup", cleanup)
    if fault == "createdsave":
        save = marker.lab.save_json

        def saving(path, value):
            if path.name == "marker-file-created.json":
                raise OSError("synthetic evidence failure")
            return save(path, value)

        monkeypatch.setattr(marker.lab, "save_json", saving)
    return marker.Marker(output, baseline), units, output, events


def test_owned_marker_is_fixed_cap0_dependency_only_and_keeps_original_file(
    tmp_path, monkeypatch
):
    state, units, output, events = fixture(tmp_path, monkeypatch)
    assert state.start() is state
    path = units / marker.p.NET_UNIT
    assert path.read_bytes() == marker.UNIT_TEXT.encode()
    assert path.stat().st_mode & 0o7777 == 0o644
    assert state.stop()["errors"] == [] and events[-1] == "owned-stop"
    assert path.exists()  # Used unit file is retained, never repaired/deleted.
    receipt = json.loads((output / "marker-verified.json").read_bytes())
    assert receipt["scope"] == "dependency_marker_only"
    assert (
        receipt["authorizes_transition"]
        is receipt["experiment"]
        is receipt["production_admission"]
        is False
    )


@pytest.mark.parametrize(
    "fault",
    [
        "inherited",
        "existing",
        "owner",
        "shortwrite",
        "createdsave",
        "hook",
        "cap",
        "exec",
        "duplicateexec",
        "state",
        "starttimeout",
        "cgroup",
    ],
)
def test_any_setup_gap_retains_state_and_never_publishes_verified_marker(
    tmp_path, monkeypatch, fault
):
    state, units, output, events = fixture(tmp_path, monkeypatch, fault)
    with pytest.raises((AssertionError, OSError)):
        state.start()
    assert not (output / "marker-verified.json").exists()
    if state.identity is not None:
        assert (units / marker.p.NET_UNIT).exists()
        if fault != "owner":
            state.stop()
    else:
        assert "marker-start" not in events


@pytest.mark.parametrize("kind", ["file", "dangling"])
def test_preexisting_foreign_file_or_alias_never_overwritten_or_stopped(
    tmp_path, monkeypatch, kind
):
    state, units, _, events = fixture(tmp_path, monkeypatch)
    path = units / marker.p.NET_UNIT
    if kind == "file":
        path.write_bytes(b"FOREIGN ORIGINAL")
    else:
        path.symlink_to(units / "absent")
    with pytest.raises(FileExistsError):
        state.start()
    assert state.identity is None and state.stop()["scope"] == "marker_not_created"
    assert "owned-stop" not in events and "marker-start" not in events
    assert (
        path.is_symlink()
        if kind == "dangling"
        else path.read_bytes() == b"FOREIGN ORIGINAL"
    )


def test_replaced_marker_does_not_authorize_stopping_foreign_unit(
    tmp_path, monkeypatch
):
    state, units, _, events = fixture(tmp_path, monkeypatch)
    state.start()
    path = units / marker.p.NET_UNIT
    path.rename(units / "retained-original")
    path.write_bytes(b"FOREIGN REPLACEMENT")
    with pytest.raises(AssertionError, match="identity"):
        state.stop()
    assert "owned-stop" not in events and path.read_bytes() == b"FOREIGN REPLACEMENT"


def test_failed_stop_proof_is_retained_and_remains_failure(tmp_path, monkeypatch):
    state, _, output, _ = fixture(tmp_path, monkeypatch, "stop")
    state.start()
    with pytest.raises(AssertionError, match="stop/cgroup"):
        state.stop()
    assert json.loads((output / "marker-stop.json").read_bytes())["errors"]


@pytest.mark.parametrize(
    "name",
    [
        "signed_network_telemetry_commission_setup.py",
        "signed_network_telemetry_marker.py",
    ],
)
@pytest.mark.parametrize("fault", ["missing", "changed"])
def test_actual_setup_and_marker_are_mandatory_new_plan_source_pins(name, fault):
    import signed_network_plan as plan

    path = marker.material.SRC / "tests/real_systemd" / name
    key = str(path.relative_to(marker.material.SRC))
    value, _ = plan.planned_telemetry(
        "a" * 40, "b" * 64, abi_sha256="c" * 64, interpreter_sha256="d" * 64
    )
    pins = value["measurement_binding"]["telemetry_lab"]["source_sha256"]
    assert pins[key] == hashlib.sha256(path.read_bytes()).hexdigest()
    if fault == "missing":
        del pins[key]
    else:
        pins[key] = "0" * 64
    with pytest.raises(plan.BenefitInputError):
        plan.validate_telemetry_manifest(value, "b" * 64)
