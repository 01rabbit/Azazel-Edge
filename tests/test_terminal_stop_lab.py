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

    def stop(*args):
        called.append(args)
        if args == ("stop", "bad.service"):
            raise OSError("original stop failed")

    monkeypatch.setattr(lab.g, "systemctl", stop)
    monkeypatch.setattr(lab, "unit_snapshot", lambda unit: dict(ActiveState="inactive", MainPID="0", ControlGroup="", pid_stat=None))
    monkeypatch.setattr(lab.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [dict(pid=99)]))
    result = lab.cleanup(["bad.service", "good.service"], {})
    assert called == [("stop", "bad.service"), ("stop", "good.service")]
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


def test_cleanup_accepts_collected_transient_unit_only_with_empty_readback(monkeypatch):
    monkeypatch.setattr(lab.g, "systemctl", lambda *args: pytest.fail("collected unit must not be stopped"))
    monkeypatch.setattr(lab, "unit_snapshot", lambda unit: dict(LoadState="not-found", ActiveState="inactive", MainPID="0", ControlGroup="", pid_stat=None))
    monkeypatch.setattr(lab.g, "Systemd", lambda: SimpleNamespace(cores=lambda: []))
    assert lab.cleanup(["collected.service"], {})["errors"] == []
    monkeypatch.setattr(lab, "unit_snapshot", lambda unit: dict(LoadState="not-found", ActiveState="active", MainPID="7", ControlGroup="", pid_stat=None))
    assert lab.cleanup(["collected.service"], {})["errors"]
