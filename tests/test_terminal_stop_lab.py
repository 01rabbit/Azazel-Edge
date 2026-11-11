"""Pure proof guards; one explicit VM case per fresh VM, default skipped."""
import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import terminal_stop_lab as lab


def chain(records):
    frames = []
    head = "0" * 64
    for number, (kind, data) in enumerate(records, 1):
        body = dict(seq=number, prev=head, kind=kind, data=data)
        head = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        frames.append(json.dumps(dict(body, sha256=head)).encode() + b"\n")
    return b"".join(frames)


def test_ready_requires_exact_durable_recovery_fence():
    position = dict(offset=200, sha256="a" * 64)
    assert lab.ready_for(chain([("input_ready", position)]), position)
    assert not lab.ready_for(chain([("cursor", dict(position=position, missed=True))]), position)
    assert not lab.ready_for(chain([("input_ready", dict(position, sha256="b" * 64))]), position)
    with pytest.raises(AssertionError):
        lab.ready_for(chain([("input_ready", position)])[:-1], position)
    with pytest.raises(AssertionError):
        lab.ready_for(chain([("input_ready", position)]).replace(b'"offset": 200', b'"offset": 201'), position)


def test_explicit_guard_precedes_any_host_query(monkeypatch):
    monkeypatch.delenv(lab.FLAG, raising=False)
    monkeypatch.setattr(lab.g, "guard", lambda: pytest.fail("ambient host queried"))
    with pytest.raises(AssertionError, match="opt-in"):
        lab.guard()


def test_worker_retains_existing_observer_authority():
    argv = lab.role_argv("live", "positive")
    assert "User=edge400-observer" in argv and "Group=edge400-observer" in argv
    assert "CapabilityBoundingSet=" in argv
    assert "AppArmorProfile=edge400-observer" in argv
    assert "RestrictAddressFamilies=AF_UNIX" in argv
    assert "NoNewPrivileges=yes" in argv
    assert not any("NET_ADMIN" in item or "AF_INET" in item for item in argv)


def test_cleanup_continues_after_stop_failure_and_records_residual(monkeypatch):
    called = []

    def stop(argv, **kwargs):
        called.append(argv[-1])
        if argv[-1] == "bad.service":
            raise OSError("original stop failed")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(lab.subprocess, "run", stop)
    monkeypatch.setattr(lab, "unit_snapshot", lambda unit: dict(ActiveState="inactive", MainPID="0", ControlPID="0", ControlGroup="", pid_stat=None))
    monkeypatch.setattr(lab.cg, "group_empty", lambda *args: True)
    monkeypatch.setattr(lab.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [dict(pid=99)]))
    result = lab.cleanup(["bad.service", "good.service"], {})
    assert called == ["bad.service", "good.service"]
    assert {row[0] for row in result["errors"]} == {"bad.service", "core-process-scan"}
    assert len(result["units"]) == 2


def test_artifacts_never_overwrite(tmp_path):
    path = tmp_path / "retained"
    lab.save(path, b"first")
    with pytest.raises(FileExistsError):
        lab.save(path, b"second")
    assert path.read_bytes() == b"first"


@pytest.mark.skipif(os.environ.get(lab.FLAG) != "1", reason="explicit fresh marked VM only")
def test_actual_confined_terminal_stop_one_fresh_scope(tmp_path):
    case = os.environ.get("EDGE_TERMINAL_VM_CASE")
    assert case in ("positive", "default-refusal"), "choose ONE case per fresh VM"
    lab.run_case(case, tmp_path / "proof")


def test_actual_boot_uuid_is_injectively_encoded_without_fabrication():
    raw = "7be45004-1731-4b7c-8e62-59a5ddf129a4"
    assert lab.boot_reference(raw) == "kernel-boot-" + raw
    with pytest.raises(ValueError):
        lab.boot_reference("fake-boot")


def test_pid_identity_ignores_changing_runtime_fields_but_not_starttime():
    # proc fields 3..21 vary; field22 starttime identifies the original actor.
    raw = "99 (worker with spaces) " + " ".join(["S"] + ["0"] * 18 + ["123"] + ["0"] * 5)
    changed = raw.replace(" S 0", " R 1", 1)
    assert lab.pid_identity(raw) == lab.pid_identity(changed) == ("99", "123")
    assert lab.pid_identity(raw.replace(" 123 ", " 124 ")) != lab.pid_identity(raw)


def test_cleanup_accepts_collected_unit_only_after_stop_attempt_and_verified_hierarchy(monkeypatch):
    called = []
    monkeypatch.setattr(lab.subprocess, "run", lambda argv, **kw: (called.append(argv[-1]) or SimpleNamespace(returncode=5)))
    monkeypatch.setattr(lab, "unit_snapshot", lambda unit: dict(LoadState="not-found", ActiveState="inactive", MainPID="0", ControlPID="0", ControlGroup="", pid_stat=None))
    monkeypatch.setattr(lab.g, "Systemd", lambda: SimpleNamespace(cores=lambda: []))
    groups = []
    monkeypatch.setattr(lab.cg, "group_empty", lambda group, units: groups.append(group) or True)
    assert lab.cleanup(["collected.service"], {})["errors"] == []
    assert called == ["collected.service"]
    assert groups == ["", "/system.slice/collected.service"]


def test_preread_failure_never_skips_any_unit_stop(monkeypatch):
    calls, reads = [], {}

    def state(unit):
        reads[unit] = reads.get(unit, 0) + 1
        if unit == "bad.service" and reads[unit] == 1:
            raise PermissionError("PID stat unavailable")
        return dict(LoadState="loaded", ActiveState="inactive", MainPID="0", ControlPID="0", ControlGroup="", pid_stat=None)

    monkeypatch.setattr(lab, "unit_snapshot", state)
    monkeypatch.setattr(lab.subprocess, "run", lambda argv, **kw: calls.append(argv[-1]) or SimpleNamespace(returncode=0))
    monkeypatch.setattr(lab.cg, "group_empty", lambda *args: True)
    monkeypatch.setattr(lab.g, "Systemd", lambda: SimpleNamespace(cores=lambda: []))
    result = lab.cleanup(["bad.service", "good.service"], {})
    assert calls == ["bad.service", "good.service"]
    assert ("bad.service", "before", "PermissionError") in result["errors"]


def test_cgroup_wrong_or_partial_mount_refuses_absence():
    full = "25 1 0:20 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
    assert lab.cg._unified_mount(full)["root"] == "/"
    for raw in (full.replace(" / /sys", " /hidden /sys"), full + "26 25 0:21 / /sys/fs/cgroup/hidden rw - tmpfs tmpfs rw\n", full.replace("cgroup2", "cgroup")):
        with pytest.raises(AssertionError):
            lab.cg._unified_mount(raw)


def test_nested_child_populated_refuses_even_when_parent_has_no_pids(tmp_path, monkeypatch):
    unit = "actor.service"
    group = tmp_path / "system.slice" / unit
    group.mkdir(parents=True)
    (group / "cgroup.procs").write_text("")
    (group / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    monkeypatch.setattr(lab.cg, "_cgroup_view", lambda: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
    assert not lab.cg.group_empty("/system.slice/" + unit, [unit])
    (group / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert lab.cg.group_empty("/system.slice/" + unit, [unit])
    (group / "cgroup.events").unlink()
    with pytest.raises(FileNotFoundError):
        lab.cg.group_empty("/system.slice/" + unit, [unit])


def test_missing_group_still_requires_verified_full_view(monkeypatch):
    def wrong_view():
        raise AssertionError("manager cgroup namespace differs")
    monkeypatch.setattr(lab.cg, "_cgroup_view", wrong_view)
    for group in ("", "/system.slice/missing.service"):
        with pytest.raises(AssertionError, match="namespace differs"):
            lab.cg.group_empty(group, ["missing.service"])


def effective_fixture():
    value = dict.fromkeys(lab.EFFECTIVE_PROPERTIES, "")
    value.update(User="edge400-observer", Group="edge400-observer", AppArmorProfile="edge400-observer",
        RestrictAddressFamilies="AF_UNIX", NoNewPrivileges="yes", Restart="no", RuntimeMaxUSec="25s",
        TimeoutStopUSec="5s", DefaultDependencies="no", Slice="system.slice", Requires="system.slice", After="system.slice")
    executable = str(lab.g.PYTHON.with_name("edge-observe"))
    argv = " ".join([executable, "-I", str(Path(lab.__file__)), "--worker", "live", "--case", "positive"])
    value["ExecStart"] = "{ path=" + executable + " ; argv[]=" + argv + " ; ignore_errors=no ; pid=123 ; code=(null) ; status=0/0 }"
    return value


@pytest.mark.parametrize("field,replacement", [("Restart", "always"), ("ExecStart", "{ path=/bin/other }"), ("User", "root"), ("CapabilityBoundingSet", "cap_net_admin"), ("RestrictAddressFamilies", "AF_UNIX AF_INET"), ("Wants", lab.g.UNIT), ("TriggeredBy", "unexpected.timer"), ("DefaultDependencies", "yes")])
def test_effective_unit_rejects_reopen_authority_or_unregistered_command(field, replacement):
    value = effective_fixture()
    lab.validate_effective(value, "positive")
    value[field] = replacement
    with pytest.raises(AssertionError):
        lab.validate_effective(value, "positive")
    assert "Restart=no" in lab.role_argv("live", "positive")
