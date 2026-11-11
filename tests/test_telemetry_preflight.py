"""Pure commissioning guards plus default-skipped explicit one-VM precheck."""
from pathlib import Path
import os
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import telemetry_preflight as t


def sample():
    return dict(identity=dict(uid=61002, pid=123, groups=[61002], apparmor="edge400-observer (enforce)", no_new_privs=True,
                              cap_eff=0, cap_prm=0, cap_amb=0, cap_bnd=0), kernel_boot_id="actual-boot",
                sample=dict(interface="es", coverage=dict.fromkeys(t.PATHS, True)),
                reads={name: dict(path=path, errno=None, bytes=100, sha256="a"*64) for name,path in t.PATHS.items()})


def classify(value):
    return t.classify(value, boot="actual-boot", namespace=dict(device=1, inode=2), expected_namespace=dict(device=1, inode=2))


def test_actual_denial_is_explicit_commissioning_blocked_not_efficacy_success():
    value = sample()
    assert classify(value) == "commissioning_ready"
    value["sample"]["coverage"]["proc_net_dev"] = False
    value["reads"]["proc_net_dev"] = dict(path="/proc/net/dev", errno=13, error="PermissionError")
    assert classify(value) == "commissioning_blocked"
    assert value["reads"]["proc_net_dev"]["errno"] == 13


@pytest.mark.parametrize("field,bad", [("uid",0),("cap_eff",4096),("cap_bnd",4096),("apparmor","unconfined"),("no_new_privs",False)])
def test_wrong_actual_observer_identity_refuses_receipt(field,bad):
    value = sample()
    value["identity"][field] = bad
    with pytest.raises(AssertionError):
        classify(value)


def test_missing_coverage_or_namespace_binding_refuses():
    value = sample()
    del value["sample"]["coverage"]["proc_uptime"]
    with pytest.raises(AssertionError):
        classify(value)
    with pytest.raises(AssertionError):
        t.classify(sample(), boot="actual-boot", namespace=dict(device=1,inode=9), expected_namespace=dict(device=1,inode=2))


def test_optin_precedes_host_read_or_mutation(monkeypatch):
    monkeypatch.delenv(t.FLAG, raising=False)
    monkeypatch.setattr(t, "read_regular", lambda *a, **k: pytest.fail("unapproved host read"))
    with pytest.raises(AssertionError, match="opt-in"):
        t.guard()


def test_worker_authority_and_no_restart_are_fixed():
    argv = t.role_argv("fresh-owned-ns")
    for expected in ("User=edge400-observer", "Group=edge400-observer", "CapabilityBoundingSet=", "NoNewPrivileges=yes",
                     "AppArmorProfile=edge400-observer", "RestrictAddressFamilies=AF_UNIX", "Restart=no", "DefaultDependencies=no"):
        assert expected in argv
    assert not any("NET_ADMIN" in item or "AF_INET" in item for item in argv)


@pytest.mark.skipif(os.environ.get(t.FLAG) != "1", reason="explicit unused marked commissioning VM only")
def test_actual_readonly_telemetry_commissioning(tmp_path):
    result = t.run(tmp_path / "telemetry-preflight")
    assert result["status"] in ("commissioning_ready", "commissioning_blocked")
    assert result["experiment"] is False and result["cleanup_verified"] is True


def test_failure_ready_bytes_are_retained_without_reconstruction(tmp_path):
    import subprocess
    process = subprocess.Popen([sys.executable, "-c", "print('not-json', flush=True)"], stdout=subprocess.PIPE)
    retained = tmp_path / "ready.raw"
    try:
        with pytest.raises(ValueError):
            t.receive_ready(process, retained)
        assert retained.read_bytes() == b"not-json\n"
    finally:
        process.wait(timeout=2)


def test_unknown_actor_quiescence_cannot_delete_owned_namespace(monkeypatch):
    from types import SimpleNamespace
    assets = SimpleNamespace(close=lambda: pytest.fail("namespace deleted before actor proof"))
    monkeypatch.setattr(t.network, "root_snapshot", lambda: pytest.fail("must refuse first"))
    with pytest.raises(AssertionError, match="retain owned namespace"):
        t.close_namespace_after_actors(assets, dict(errors=[("unit", "unknown")]), {})
