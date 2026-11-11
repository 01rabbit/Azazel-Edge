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


@pytest.mark.parametrize("name", [t.UNIT, t.UNIT+".d", "service.d", "edge400-.service.d", "edge400-telemetry-.service.d"])
def test_preexisting_exact_and_global_unit_material_refuses(tmp_path,name):
    (tmp_path/name).symlink_to(tmp_path/"missing")
    with pytest.raises(AssertionError, match="unit material"):
        t.reject_unit_material([tmp_path])


def effective():
    value = dict.fromkeys(t.EFFECTIVE, "")
    value.update(User="edge400-observer", Group="edge400-observer", AppArmorProfile="edge400-observer",
                 RestrictAddressFamilies="AF_UNIX", NoNewPrivileges="yes", Restart="no", RuntimeMaxUSec="10s", TimeoutStopUSec="3s",
                 DefaultDependencies="no", Slice="system.slice", NetworkNamespacePath="/run/netns/fresh",
                 FragmentPath="/run/systemd/transient/"+t.UNIT, Requires="system.slice", After="system.slice")
    executable = str(t.g.PYTHON.with_name("edge-observe"))
    value["ExecStart"] = "{ path="+executable+" ; argv[]="+" ".join([executable,"-I","-B",str(Path(t.__file__).resolve()),"--worker"])+" ; ignore_errors=no ; pid=123 }"
    return value


@pytest.mark.parametrize("field,bad", [("ExecStartPre","/bin/hook"),("ExecStartPost","/bin/hook"),("ExecStop","/bin/hook"),("ExecStopPost","/bin/hook"),
                                     ("Wants","unexpected.service"),("Requires","unexpected.service"),("Restart","always"),("DropInPaths","/etc/global.conf"),
                                     ("NetworkNamespacePath","/run/netns/foreign"),("ExecStart","{ path=/bin/other }"),("RuntimeMaxUSec","infinity"),
                                     ("NoNewPrivileges","no"),("CapabilityBoundingSet","cap_net_admin"),("AppArmorProfile","unconfined"),("RestrictAddressFamilies","AF_UNIX AF_INET")])
def test_effective_hooks_authority_command_and_bounds_must_match(field,bad):
    value=effective()
    t.validate_effective(value,"fresh")
    value[field]=bad
    with pytest.raises(AssertionError):
        t.validate_effective(value,"fresh")


def test_bad_pid1_cgroup_view_refuses_before_first_mutation(monkeypatch,tmp_path):
    from types import SimpleNamespace
    monkeypatch.setattr(t.subprocess,"run",lambda *a,**k: SimpleNamespace(stdout=str(tmp_path)+"\n"))
    def bad_view():
        raise AssertionError("wrong PID1 view")
    monkeypatch.setattr(t.cg,"_cgroup_view",bad_view)
    monkeypatch.setattr(t,"guard",t.pre_mutation_checks)
    monkeypatch.setattr(t.a,"prepare_accounts",lambda:pytest.fail("account mutation before full view"))
    output=tmp_path/"never-created"
    with pytest.raises(AssertionError,match="PID1 view"):
        t.run(output)
    assert not output.exists()


def test_dangling_used_base_alias_is_refused(monkeypatch,tmp_path):
    path=tmp_path/"used"
    path.symlink_to(tmp_path/"absent")
    monkeypatch.setattr(t.g,"BASE",path)
    with pytest.raises(AssertionError,match="scope/alias"):
        t.reject_used_base()


def test_writable_output_ancestor_refuses_creation(tmp_path):
    parent=tmp_path/"writable"
    parent.mkdir(mode=0o777)
    parent.chmod(0o777)
    with pytest.raises(OSError,match="ancestor"):
        t.private_output(parent/"private")
    assert not (parent/"private").exists()
