"""Hardware-free manual preparation refusal/order tests; no actor execution."""

import hashlib
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_phase as phase


def input_fixture(monkeypatch):
    image = b"\x7fELF\x02\x01" + b"reviewed synthetic core bytes"
    manifest, _ = phase.plan.planned("a" * 40, hashlib.sha256(image).hexdigest())
    digest = phase.n.manifest_digest(manifest)
    head = "b" * 64
    ticket = dict(
        manifest_sha256=digest,
        assignment_id=manifest["assignments"][0]["id"],
        run_id="run-fresh-assignment",
        start_head=head,
    )
    material = {
        phase.MANIFEST: json.dumps(manifest).encode(),
        phase.TICKET: json.dumps(ticket).encode(),
        phase.g.CORE: image,
        phase.SRC / "SOURCE_REVISION": b"a" * 40 + b"\n",
    }

    def read(path, maximum=8 * 1024 * 1024):
        path = Path(path)
        raw = material[path] if path in material else path.read_bytes()
        assert len(raw) <= maximum
        return raw

    monkeypatch.setattr(phase, "_read", read)
    return manifest, ticket, material, digest, head


def test_strict_frozen_assignment_and_actual_source_core_material(monkeypatch):
    manifest, ticket, _, digest, head = input_fixture(monkeypatch)
    result = phase.validated_inputs(digest, head)
    assert result["manifest"] == manifest and result["ticket"] == ticket
    assert result["assignment"] == manifest["assignments"][0]
    assert result["source_commit"] == "a" * 40 and result["direct_files_sha256"]
    assert "keys" not in result


@pytest.mark.parametrize(
    "fault",
    [
        "external_pin",
        "head",
        "extra_ticket",
        "assignment",
        "run",
        "source",
        "core",
        "policy",
        "protected_read",
    ],
)
def test_changed_or_unavailable_frozen_inputs_refuse_before_mutation(
    monkeypatch, fault
):
    _, ticket, material, digest, head = input_fixture(monkeypatch)
    if fault == "external_pin":
        digest = "c" * 64
    elif fault == "head":
        head = "c" * 64
    elif fault == "extra_ticket":
        ticket["other"] = "unregistered"
    elif fault == "assignment":
        ticket["assignment_id"] = "unregistered"
    elif fault == "run":
        ticket["run_id"] = "bad run"
    elif fault == "source":
        material[phase.SRC / "SOURCE_REVISION"] = b"c" * 40
    elif fault == "core":
        material[phase.g.CORE] += b"wrong"
    elif fault == "policy":
        material[phase.plan.POLICY_PATH] = b"wrong"
    else:
        monkeypatch.setattr(
            phase, "_read", lambda *a, **k: (_ for _ in ()).throw(PermissionError())
        )
    material[phase.TICKET] = json.dumps(ticket).encode()
    monkeypatch.setattr(
        phase, "fresh_preflight", lambda *a: pytest.fail("must not reach preparation")
    )
    with pytest.raises((BenefitInputError, PermissionError)):
        phase.prepare_assignment(digest, head)


def preflight_fixture(tmp_path, monkeypatch, fault=None):
    monkeypatch.setattr(phase.g, "guard", lambda: None)
    monkeypatch.setattr(phase.os.path, "lexists", lambda path: False)
    monkeypatch.setattr(
        phase.scope,
        "_cgroup_view",
        lambda: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY),
    )
    absent = dict(
        LoadState="not-found",
        ActiveState="inactive",
        MainPID="0",
        ControlPID="0",
        ControlGroup="",
    )
    monkeypatch.setattr(phase.scope, "_state", lambda unit: dict(absent))
    monkeypatch.setattr(phase.scope, "_group_empty", lambda group: True)
    monkeypatch.setattr(phase.g, "Systemd", lambda: SimpleNamespace(cores=lambda: []))
    monkeypatch.setattr(
        phase.lab, "isolated_api_preflight", lambda: {"isolated": "staged"}
    )
    if fault == "used":
        monkeypatch.setattr(
            phase.os.path, "lexists", lambda path: Path(path) == phase.WORK
        )
    elif fault == "namespace":
        monkeypatch.setattr(
            phase.os.path, "lexists", lambda path: str(path).startswith("/run/netns/")
        )
    elif fault == "unit":
        monkeypatch.setattr(
            phase.scope, "_state", lambda unit: dict(absent, LoadState="loaded")
        )
    elif fault == "cgroup":
        monkeypatch.setattr(phase.scope, "_group_empty", lambda group: False)
    elif fault == "core":
        monkeypatch.setattr(
            phase.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [dict(pid=123)])
        )
    elif fault == "runtime":
        monkeypatch.setattr(
            phase.lab,
            "isolated_api_preflight",
            lambda: (_ for _ in ()).throw(
                BenefitInputError("missing staged isolated API")
            ),
        )


@pytest.mark.parametrize(
    "fault", ["used", "namespace", "unit", "cgroup", "core", "runtime"]
)
def test_precondition_gap_precedes_accounts_profiles_keys_and_actor_mutation(
    tmp_path, monkeypatch, fault
):
    preflight_fixture(tmp_path, monkeypatch, fault)
    monkeypatch.setattr(phase, "validated_inputs", lambda *a: {})
    monkeypatch.setattr(
        phase.plan,
        "configure_assignment",
        lambda *a, **k: pytest.fail("must not configure"),
    )
    monkeypatch.setattr(
        phase.p.a, "prepare_accounts", lambda: pytest.fail("must not create accounts")
    )
    with pytest.raises(BenefitInputError):
        phase.prepare_assignment("a" * 64, "b" * 64)


def test_supported_fresh_preflight_reads_without_provisioning(tmp_path, monkeypatch):
    preflight_fixture(tmp_path, monkeypatch)
    assert phase.fresh_preflight({}) == {"isolated": "staged"}


def preparation_fixture(tmp_path, monkeypatch, *, bad_registration=False):
    inputs = dict(
        manifest=dict(
            protected_policy_sha256=hashlib.sha256(
                phase.plan.PROTECTED.encode()
            ).hexdigest()
        ),
        assignment=dict(arm="c0"),
        ticket=dict(run_id="run-case"),
    )
    work = tmp_path / "work"
    monkeypatch.setattr(phase, "WORK", work)
    monkeypatch.setattr(phase, "validated_inputs", lambda *a: inputs)
    monkeypatch.setattr(phase, "fresh_preflight", lambda *a: {"staged": True})
    monkeypatch.setattr(phase.os.path, "lexists", lambda path: False)
    log = []
    callback = {}
    monkeypatch.setattr(
        phase.plan,
        "configure_assignment",
        lambda value, observer_initializer: (
            callback.update(initialize=observer_initializer),
            log.append("configure"),
        ),
    )
    monkeypatch.setattr(phase.p.a, "prepare_accounts", lambda: log.append("accounts"))
    monkeypatch.setattr(phase.p.a, "install_policy", lambda: log.append("profiles"))
    monkeypatch.setattr(
        phase.g, "write", lambda path, data, *a: log.append(("write", path, data))
    )
    monkeypatch.setattr(phase.g, "command", lambda *a: log.append(tuple(a)))

    def systemctl(*args):
        log.append(args)
        if args == ("start", phase.p.NET_UNIT):
            work.mkdir(mode=0o700)

    monkeypatch.setattr(phase.g, "systemctl", systemctl)
    monkeypatch.setattr(
        phase,
        "_initialize_new_observer",
        lambda create: log.append(("genuine-init", create)),
    )

    def prepare():
        log.append("witness-first")
        callback["initialize"](True)

    monkeypatch.setattr(phase.g, "prepare_lab", prepare)
    registration = dict(
        schema_version="outcome-live-origin-registration/v4",
        environment=phase.plan.native_environment("c0"),
    )
    if bad_registration:
        registration["environment"] = {}
    monkeypatch.setattr(
        phase,
        "verify",
        lambda bundle: (
            SimpleNamespace(data={"scope_ref": "fresh-scope"}),
            registration,
        ),
    )
    monkeypatch.setattr(
        phase,
        "_read",
        lambda path, *a: phase.plan.PROTECTED.encode()
        if Path(path).name == "protected.yaml"
        else b"reviewed provider profile",
    )
    monkeypatch.setattr(
        phase.g, "Systemd", lambda: SimpleNamespace(cores=lambda: [{"pid": 123}])
    )
    monkeypatch.setattr(phase.g, "wait_for", lambda predicate: predicate())

    class Switch:
        def __init__(self, *args):
            pass

        def plan(self):
            log.append("switch-plan")
            return {"reviewed": "plan"}

        def apply(self, *args):
            log.append("switch-apply")
            return dict(status="started")

    monkeypatch.setattr(phase.g, "Switch", Switch)
    monkeypatch.setattr(
        phase.p, "identity", lambda: (log.append("actual-native-identity") or 123)
    )
    monkeypatch.setattr(phase.g, "boot", lambda: "actual-boot")
    return work, log


def test_preparation_reuses_witness_init_switch_sequence_and_fixed_namespace_unit(
    tmp_path, monkeypatch
):
    work, log = preparation_fixture(tmp_path, monkeypatch)
    result = phase.prepare_assignment("a" * 64, "b" * 64)
    assert (
        log.index("witness-first")
        < log.index(("genuine-init", True))
        < log.index(("start", phase.g.UNIT))
        < log.index("switch-plan")
        < log.index("switch-apply")
        < log.index("actual-native-identity")
    )
    unit = next(
        data
        for kind, path, data in (
            row
            for row in log
            if type(row) is tuple and len(row) == 3 and row[0] == "write"
        )
        if path == phase.g.UNITS / phase.p.NET_UNIT
    )
    assert "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_ADMIN\n" in unit
    assert (
        "NoNewPrivileges=yes" in unit
        and "--namespace " + "a" * 64 + " " + "b" * 64 in unit
    )
    assert "ExecStop" not in unit
    assert (work / "prepared.json").exists() and result["native_pid"] == 123
    assert "not_measurement_or_production_admission" in result["scope"]


def test_materialized_registration_mismatch_never_activates_core(tmp_path, monkeypatch):
    _, log = preparation_fixture(tmp_path, monkeypatch, bad_registration=True)
    cleanup = []
    monkeypatch.setattr(
        phase, "_failure_cleanup", lambda error: cleanup.append(type(error).__name__)
    )
    with pytest.raises(BenefitInputError, match="materialized v4"):
        phase.prepare_assignment("a" * 64, "b" * 64)
    assert ("start", phase.g.UNIT) not in log and cleanup == ["BenefitInputError"]


def test_cleanup_stops_all_before_reopen_and_retains_failure_note(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(phase, "WORK", tmp_path)
    (tmp_path / "namespace-boot.json").write_text("{}")
    log = []
    monkeypatch.setattr(
        phase.scope,
        "stop_systemd_actors",
        lambda: (log.append("stop-all") or dict(status="failed")),
    )
    monkeypatch.setattr(
        phase.scope,
        "reopen_assets",
        lambda *a: pytest.fail("unknown actor state must not reopen/delete namespaces"),
    )
    error = RuntimeError("original setup failed")
    phase._failure_cleanup(error)
    assert log == ["stop-all"] and "cleanup unverified" in error.__notes__[0]
    assert (
        json.loads((tmp_path / "preparation-stop-receipt.json").read_text())["status"]
        == "failed"
    )


@pytest.mark.parametrize("failure", [False, True])
def test_namespace_setup_uses_fixed_assets_and_retains_intents_without_double_close(
    tmp_path, monkeypatch, failure
):
    work = tmp_path / "work"
    base = tmp_path / "absent-base"
    monkeypatch.setattr(phase, "WORK", work)
    monkeypatch.setattr(phase.g, "BASE", base)
    monkeypatch.setattr(phase.g, "guard", lambda: None)
    monkeypatch.setattr(phase.g, "boot", lambda: "actual-boot")
    monkeypatch.setattr(phase, "validated_inputs", lambda *a: dict(ticket="frozen"))
    monkeypatch.setattr(phase.n, "root_snapshot", lambda: {"parent": "unchanged"})
    descriptors = []
    log = []

    class Assets:
        def __init__(self, directory):
            self.work = directory
            self.created = {}
            self.foreign = "foreign-1234abcd"

        def setup(self):
            assert self.names == phase.plan.names()
            phase.n.write_new(
                self.work / "namespace-intent-1.json", dict(state="creation_intent")
            )
            path = tmp_path / "namespace-handle"
            path.write_text("kernel handle stand-in")
            fd = os.open(path, os.O_RDONLY)
            info = os.fstat(fd)
            descriptors.append(fd)
            self.created["edge"] = (fd, info.st_dev, info.st_ino)
            phase.n.write_new(
                self.work / "namespace-confirmed-1.json",
                dict(
                    state="confirmed_created",
                    identity=dict(device=info.st_dev, inode=info.st_ino),
                ),
            )
            log.append("confirmed")
            if failure:
                raise RuntimeError("original namespace setup failure")

        def close(self):
            log.append("close-once")
            for fd, _, _ in self.created.values():
                os.close(fd)

    monkeypatch.setattr(phase.n, "Assets", Assets)
    if failure:
        with pytest.raises(RuntimeError, match="original namespace setup"):
            phase.namespace_prepare("a" * 64, "b" * 64)
        assert log == ["confirmed", "close-once"]
        assert not (work / "namespace-boot.json").exists()
    else:
        phase.namespace_prepare("a" * 64, "b" * 64)
        proof = json.loads((work / "namespace-boot.json").read_text())
        assert proof == dict(
            kernel_boot_id="actual-boot",
            names=phase.plan.names(),
            root_before={"parent": "unchanged"},
            foreign="foreign-1234abcd",
        )
    assert (work / "namespace-intent-1.json").exists() and (
        work / "namespace-confirmed-1.json"
    ).exists()
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_init_callback_refuses_recovery_without_touching_permissions(monkeypatch):
    monkeypatch.setattr(phase.os, "fchmod", lambda *a: pytest.fail("must not chmod"))
    monkeypatch.setattr(
        phase.subprocess, "run", lambda *a, **k: pytest.fail("must not launch")
    )
    with pytest.raises(BenefitInputError, match="new-scope"):
        phase._initialize_new_observer(False)
