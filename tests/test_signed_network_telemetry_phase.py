"""Synthetic Root/namespace/unit/API flow; real protected JSON/hash/FD checks.

No actual actor, namespace, kernel policy, native producer or measurement runs.
The flow fixture reuses declared ephemeral crypto/journal fixtures, not a live API.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.outcome.input_auth import read_regular

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_phase as p
from test_signed_network_telemetry_commission import Case
from test_signed_network_telemetry_namespaces import fixture as namespace_fixture


def put(path, value):
    path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
    path.chmod(0o600)


def inputs_fixture(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    (source / "SOURCE_REVISION").write_text("a" * 40 + "\n")
    code = source / "helper.py"
    code.write_bytes(b"# PUBLIC synthetic source\n")
    core = tmp_path / "core"
    core.write_bytes(b"\x7fELF\x02\x01PUBLIC synthetic unexecuted core")
    core.chmod(0o755)
    monkeypatch.setattr(p.g, "guard", lambda: None)
    monkeypatch.setenv(p.material.FLAG, "1")
    monkeypatch.setattr(p.material, "SRC", source)
    monkeypatch.setattr(p.material, "source_paths", lambda: [code])
    monkeypatch.setattr(
        p.material,
        "_read",
        lambda path, limit=1024 * 1024, mode=None: read_regular(
            path, owner=os.geteuid(), max_bytes=limit, mode=mode
        )[0],
    )
    monkeypatch.setattr(p.g, "CORE", core)
    monkeypatch.setattr(p, "MANIFEST", tmp_path / "manifest.json")
    monkeypatch.setattr(p, "TICKET", tmp_path / "ticket.json")
    pins = dict(
        source_commit="a" * 40,
        archive_sha256="b" * 64,
        core_sha256=hashlib.sha256(core.read_bytes()).hexdigest(),
        abi_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    manifest, _ = p.plan.planned_telemetry(
        pins["source_commit"],
        pins["core_sha256"],
        source_archive_sha256=pins["archive_sha256"],
        abi_sha256=pins["abi_sha256"],
        interpreter_sha256=pins["interpreter_sha256"],
    )
    digest, head = p.plan.manifest_digest(manifest), "f" * 64
    ticket = dict(
        schema_version="signed-network-telemetry-ticket/v2",
        manifest_sha256=digest,
        assignment_id=manifest["assignments"][0]["id"],
        run_id="fresh-run",
        start_head=head,
    )
    put(p.MANIFEST, manifest)
    put(p.TICKET, ticket)
    return pins, manifest, ticket, digest, head


def test_v2_readonly_validator_binds_external_pins_and_never_creates_work(
    tmp_path, monkeypatch
):
    pins, manifest, ticket, digest, head = inputs_fixture(tmp_path, monkeypatch)
    before = set(tmp_path.iterdir())
    result = p.validated_telemetry_inputs(digest, head, **pins)
    assert result["manifest"] == manifest and result["ticket"] == ticket
    assert result["assignment"] == manifest["assignments"][0]
    assert result["external_pins"] == pins and result["schema_version"].endswith("/v2")
    assert (
        result["manifest_file_sha256"]
        == hashlib.sha256(p.MANIFEST.read_bytes()).hexdigest()
    )
    assert set(tmp_path.iterdir()) == before


@pytest.mark.parametrize(
    "field",
    [
        "source_commit",
        "archive_sha256",
        "core_sha256",
        "abi_sha256",
        "interpreter_sha256",
    ],
)
@pytest.mark.parametrize("bad", [None, True, 0, "A" * 64, "1" * 63, "x" * 64])
def test_external_pin_types_and_substitutions_refuse_before_writes(
    tmp_path, monkeypatch, field, bad
):
    pins, _, _, digest, head = inputs_fixture(tmp_path, monkeypatch)
    pins[field] = bad
    with pytest.raises((AssertionError, ValueError)):
        p.validated_telemetry_inputs(digest, head, **pins)


@pytest.mark.parametrize(
    "fault",
    [
        "old-ticket",
        "extra-ticket",
        "missing-ticket",
        "bool-run",
        "unicode-run",
        "other-head",
        "unknown-assignment",
        "archive",
        "mode",
        "revision",
        "core",
        "source",
        "manifest-pin",
    ],
)
def test_current_inputs_or_ticket_never_fall_back_to_legacy(
    tmp_path, monkeypatch, fault
):
    pins, manifest, ticket, digest, head = inputs_fixture(tmp_path, monkeypatch)
    if fault == "old-ticket":
        del ticket["schema_version"]
    elif fault == "extra-ticket":
        ticket["unknown"] = False
    elif fault == "missing-ticket":
        del ticket["assignment_id"]
    elif fault == "bool-run":
        ticket["run_id"] = True
    elif fault == "unicode-run":
        ticket["run_id"] = "а-run"  # Cyrillic first character.
    elif fault == "other-head":
        ticket["start_head"] = "e" * 64
    elif fault == "unknown-assignment":
        ticket["assignment_id"] = "unknown"
    elif fault in ("archive", "mode"):
        spec = manifest["measurement_binding"]["telemetry_lab"]
        spec[
            "source_archive_sha256" if fault == "archive" else "assignment_mode_sha256"
        ] = "e" * 64
        digest = p.plan.manifest_digest(manifest)
        ticket["manifest_sha256"] = digest
    elif fault == "revision":
        (p.material.SRC / "SOURCE_REVISION").write_text("b" * 40)
    elif fault == "core":
        p.g.CORE.write_bytes(b"\x7fELF\x02\x01changed")
    elif fault == "source":
        (p.material.SRC / "helper.py").write_text("changed")
    elif fault == "manifest-pin":
        digest = "0" * 64
    put(p.MANIFEST, manifest)
    put(p.TICKET, ticket)
    with pytest.raises((AssertionError, ValueError)):
        p.validated_telemetry_inputs(digest, head, **pins)


def flow_fixture(tmp_path, monkeypatch, fault=None, arm="c0"):
    case = Case(tmp_path, monkeypatch, fault)
    case.baseline.update(root_before={"root": "same"}, assets={"old": "same"})
    monkeypatch.setattr(p, "WORK", case.output)
    monkeypatch.setattr(
        p.setup.n, "root_snapshot", lambda: deepcopy(case.baseline["root_before"])
    )
    monkeypatch.setattr(p.setup, "_assets", lambda: deepcopy(case.baseline["assets"]))
    monkeypatch.setattr(
        p.material, "verify_current", lambda **kw: deepcopy(case.baseline["material"])
    )
    monkeypatch.setattr(p.g.Systemd, "cores", lambda self: [])
    inputs = dict(
        schema_version="signed-network-telemetry-inputs/v2",
        assignment={"id": "pair-1-" + arm, "arm": arm},
        external_pins=case.pins,
        assignment_mode_sha256=p.plan.manifest_digest(
            p.plan.telemetry_assignment_mode()
        ),
    )
    monkeypatch.setattr(
        p, "validated_telemetry_inputs", lambda *a, **kw: deepcopy(inputs)
    )
    original = p.manual.NamespaceSetup

    class Namespace(original):
        def __init__(self, output, baseline):
            super().__init__(output, baseline)
            self.work = output / "namespace-evidence"
            self.assets = SimpleNamespace(processes=[], foreign="foreign-synthetic")

        def prepare_service(self):
            self.prepare()
            self.work.mkdir(mode=0o700)
            for index in (1, 2, 3):
                for kind in ("intent", "confirmed"):
                    put(
                        self.work / f"namespace-{kind}-{index}.json",
                        dict(declared_synthetic=True, index=index, kind=kind),
                    )

        def close(self):
            super().close()
            receipt = dict(cleanup_verified=True, errors=[])
            put(self.work / "cleanup.json", receipt)
            return receipt

    monkeypatch.setattr(p.manual, "NamespaceSetup", Namespace)
    actual_stat = os.stat
    monkeypatch.setattr(
        p,
        "os",
        SimpleNamespace(
            **{key: getattr(os, key) for key in dir(os) if not key.startswith("__")},
            **{},
        ),
    )

    def root_metadata(path, **kw):
        info = actual_stat(path, **kw)
        return SimpleNamespace(
            st_uid=0,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_mode=info.st_mode,
            st_nlink=info.st_nlink,
        )

    monkeypatch.setattr(p.os, "stat", root_metadata)
    return case, dict(manifest_sha256="e" * 64, start_head="f" * 64, **case.pins)


@pytest.mark.parametrize("arm", ["c0", "flow_throttle"])
def test_direct_owner_prepares_empty_without_native_and_close_restores_globals(
    tmp_path, monkeypatch, arm
):
    case, args = flow_fixture(tmp_path, monkeypatch, arm=arm)
    original = (
        p.g.write,
        p.g.prepare,
        p.g.observer,
        dict(p.g.ENV),
        p.plan.p.a.NATIVE,
        p.g.Systemd.witness,
    )
    with p.prepare_telemetry_assignment(case.output, **args) as context:
        assert context.initialization is case.initialized
        assert context.args["transport_context"] is context.transport_context
        assert context.inputs["assignment"]["arm"] == arm
        assert p.g.ENV["AZAZEL_DEFENSE_ENFORCE"] == (
            "1" if arm == "flow_throttle" else "0"
        )
        assert "sealed-switch" not in case.events and "live-enter" not in case.events
        assert not any(str(event).startswith("manager:start") for event in case.events)
        prepared = json.loads((case.output / "prepared.json").read_bytes())
        assert (
            "native_pid" not in prepared and prepared["measurement_completed"] is False
        )
        for index in (1, 2, 3):
            for kind in ("intent", "confirmed"):
                name = f"namespace-{kind}-{index}.json"
                assert (case.output / name).read_bytes() == (
                    context.namespaces.work / name
                ).read_bytes()
    assert (
        context.closed
        and (
            p.g.write,
            p.g.prepare,
            p.g.observer,
            dict(p.g.ENV),
            p.plan.p.a.NATIVE,
            p.g.Systemd.witness,
        )
        == original
    )
    assert case.cleaned[-1] == p.g.WITNESS and p._active is None
    context.close()  # Clean close is idempotent, with no repeated actor stop.


@pytest.mark.parametrize("fault", ["namespace", "init", "cleanup", "namespaceclose"])
def test_prepare_failure_has_no_returned_owner_and_independent_cleanup(
    tmp_path, monkeypatch, fault
):
    case, args = flow_fixture(tmp_path, monkeypatch, fault)
    original = (
        p.g.write,
        p.g.prepare,
        p.g.observer,
        dict(p.g.ENV),
        p.g.Systemd.witness,
    )
    if fault in ("cleanup", "namespaceclose"):
        context = p.prepare_telemetry_assignment(case.output, **args)
        with pytest.raises(AssertionError) as first:
            context.close()
        with pytest.raises(AssertionError) as second:
            context.close()
        assert second.value is first.value
    else:
        with pytest.raises(RuntimeError):
            p.prepare_telemetry_assignment(case.output, **args)
    assert "outer-cleanup" in case.events and "namespace-close" in case.events
    assert (
        p.g.write,
        p.g.prepare,
        p.g.observer,
        dict(p.g.ENV),
        p.g.Systemd.witness,
    ) == original and p._active is None


@pytest.mark.parametrize(
    "receipt",
    [
        None,
        {},
        {"cleanup_verified": False, "errors": []},
        {"cleanup_verified": True, "errors": ["unknown"]},
        {"cleanup_verified": 1, "errors": []},
    ],
)
def test_incomplete_namespace_return_is_sticky_and_never_claims_cleanup(
    tmp_path, monkeypatch, receipt
):
    case, args = flow_fixture(tmp_path, monkeypatch)
    context = p.prepare_telemetry_assignment(case.output, **args)
    real_close = context.namespaces.close

    def close():
        real_close()
        return receipt

    monkeypatch.setattr(context.namespaces, "close", close)
    with pytest.raises(AssertionError) as first:
        context.close()
    saved = json.loads((case.output / "assignment-cleanup.json").read_bytes())
    assert (
        saved["cleanup_verified"] is False
        and saved["errors"]
        and context.namespaces.failed
    )
    with pytest.raises(AssertionError) as second:
        context.close()
    assert first.value is second.value and p._active is None


def test_imported_json_cannot_construct_an_owned_context():
    with pytest.raises(AssertionError):
        p.TelemetryAssignmentContext({}, Path("/unused"), {}, {})


def test_service_topology_uses_owned_names_once_and_no_dummy_or_root_commands(
    tmp_path, monkeypatch
):
    state, named, events, inspected = namespace_fixture(tmp_path, monkeypatch)
    state.assets.foreign = "foreign-synthetic"
    original = type(state.assets).ns
    commands = []

    def ns(self, kind, *argv, **kwargs):
        commands.append((kind, argv, kwargs))
        original(self, kind, *argv)
        return SimpleNamespace(stdout="")

    monkeypatch.setattr(type(state.assets), "ns", ns)
    assert state.prepare_service() is state
    assert (
        len(
            [
                row
                for row in events
                if isinstance(row, str) and row.startswith("create:")
            ]
        )
        == 3
    )
    links = [
        (kind, argv) for kind, argv, _ in commands if argv[:3] == ("ip", "link", "add")
    ]
    assert links == [
        (
            "edge",
            (
                "ip",
                "link",
                "add",
                "ec",
                "type",
                "veth",
                "peer",
                "name",
                "peer0",
                "netns",
                state.assets.names["client"],
            ),
        ),
        (
            "edge",
            (
                "ip",
                "link",
                "add",
                "es",
                "type",
                "veth",
                "peer",
                "name",
                "peer0",
                "netns",
                state.assets.names["service"],
            ),
        ),
    ]
    assert not any("dummy" in argv for _, argv, _ in commands)
    assert [(kind, argv) for kind, argv, _ in commands if argv[0] == "sysctl"] == [
        ("edge", ("sysctl", "-qw", "net.ipv4.ip_forward=1"))
    ]
    assert (
        sum(
            argv[:2] == ("ip", "-4") or argv[:2] == ("ip", "-6")
            for _, argv, _ in commands
        )
        == 6
    )
    nft = [
        (kind, kwargs["input"]) for kind, argv, kwargs in commands if argv[0] == "nft"
    ]
    assert len(nft) == 1 and nft[0][0] == "edge"
    assert (
        "type filter hook prerouting priority -150" in nft[0][1]
        and 'comment "foreign-synthetic"' in nft[0][1]
    )
    assert state.close()["cleanup_verified"] is True and not list(named.iterdir())
    assert set(inspected) == set(p.setup.UNITS)


@pytest.mark.parametrize("fault", ["veth", "default", "nft"])
def test_partial_service_topology_failure_retains_names_and_closes_own_fds(
    tmp_path, monkeypatch, fault
):
    state, named, events, inspected = namespace_fixture(tmp_path, monkeypatch)
    state.assets.foreign = "foreign-synthetic"
    original = type(state.assets).ns

    def ns(self, kind, *argv, **kwargs):
        original(self, kind, *argv)
        if (
            fault == "veth"
            and argv[:3] == ("ip", "link", "add")
            or fault == "nft"
            and argv[0] == "nft"
        ):
            raise RuntimeError("synthetic topology operation failed")
        return SimpleNamespace(
            stdout="default via foreign"
            if fault == "default" and argv[:2] == ("ip", "-4")
            else ""
        )

    monkeypatch.setattr(type(state.assets), "ns", ns)
    with pytest.raises((AssertionError, RuntimeError)):
        state.prepare_service()
    with pytest.raises(AssertionError):
        state.close()
    assert state.failed and len(list(named.iterdir())) == 3
    assert not any(isinstance(row, str) and row.startswith("delete:") for row in events)
    for fd, _, _ in state.assets.created.values():
        with pytest.raises(OSError):
            os.fstat(fd)


def test_real_owned_stuck_child_is_killed_reaped_and_pipes_closed_before_ns_gate(
    tmp_path, monkeypatch
):
    import select

    case, args = flow_fixture(tmp_path, monkeypatch)
    context = p.prepare_telemetry_assignment(case.output, **args)
    child = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-c",
            "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('ready',flush=True);time.sleep(30)",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert select.select([child.stdout], [], [], 1)[0]
        assert child.stdout.readline() == b"ready\n"
        context.namespaces.assets.processes.append(child)
        original = context.namespaces.close

        def close():
            assert child.returncode is not None
            assert child.stdin.closed and child.stdout.closed and child.stderr.closed
            return original()

        monkeypatch.setattr(context.namespaces, "close", close)
        with pytest.raises(AssertionError):
            context.close()
        assert child.poll() is not None and context.namespaces.failed
        saved = json.loads((case.output / "assignment-cleanup.json").read_bytes())
        assert (
            saved["processes"][0]["forced"] is True
            and saved["cleanup_verified"] is False
        )
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=2)
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()
        if not context.closed:
            context.close()


@pytest.mark.parametrize("arm", [None, True, "observe", "flow_throttle ", {}, 1])
def test_configuration_refuses_unknown_arm_before_namespace_or_write(arm, tmp_path):
    with pytest.raises(AssertionError, match="fixed native arm"):
        p.manual._configure(
            None, None, [1, 2], owner=object(), output=tmp_path, arm=arm
        )
    assert not list(tmp_path.iterdir())


def test_actual_preparation_module_is_mandatory_plan_source_material():
    path = p.material.SRC / "tests/real_systemd/signed_network_telemetry_phase.py"
    assert path in p.material.source_paths()
    assert (
        p.material.source_hashes()[str(path.relative_to(p.material.SRC))]
        == hashlib.sha256(path.read_bytes()).hexdigest()
    )


def test_created_unit_receipt_failure_keeps_stop_ownership_and_restores_globals(
    tmp_path, monkeypatch
):
    case, args = flow_fixture(tmp_path, monkeypatch)
    saved = p.lab.save_json
    cleanup = []
    monkeypatch.setattr(
        p.lab,
        "cleanup",
        lambda units, tracked: cleanup.append(units) or dict(errors=[]),
    )

    def saving(path, value):
        if path.name == "created-" + p.g.UNIT + ".json":
            raise OSError("synthetic created-unit receipt failure")
        return saved(path, value)

    monkeypatch.setattr(p.lab, "save_json", saving)

    # The declared fixture namespace close expects this event, as in its normal cleanup.
    def cleanup_owned(units, tracked):
        case.events.append("outer-cleanup")
        cleanup.append(units)
        return dict(errors=[])

    monkeypatch.setattr(p.lab, "cleanup", cleanup_owned)
    before = (p.g.write, p.g.prepare, p.g.observer, dict(p.g.ENV), p.g.Systemd.witness)
    with pytest.raises(OSError, match="created-unit receipt"):
        p.prepare_telemetry_assignment(case.output, **args)
    assert cleanup == [(p.g.UNIT,)] and p._active is None
    assert (
        p.g.write,
        p.g.prepare,
        p.g.observer,
        dict(p.g.ENV),
        p.g.Systemd.witness,
    ) == before
