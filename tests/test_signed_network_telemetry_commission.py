"""SYNTHETIC Root/role lifecycle, real public crypto and original-byte validators.

No systemd/UID/AppArmor/native process/journal persistence/witness server is run.
Journal fixture bytes use the existing wire writer; existing Fixture.anchors signs
real ephemeral witness envelopes. No production secret, chown or crypto stub.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace

import pytest
from auth_input_helpers import make_policy
from test_outcome_live_origin import frame, signed_frame
from test_outcome_input_auth import signed
from test_signed_network_read import journal
from test_signed_network_composition import Fixture
from test_telemetry_isolation_result import sample as proc_sample
from azazel_edge.outcome.telemetry import persistence_context
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
from azazel_edge.outcome.input_terminal import TerminalControlStop
from azazel_edge.outcome.journal import _json
from azazel_edge.outcome import input_live
from azazel_edge.outcome.input_transport import transport

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_telemetry_commission as main

BOOT = "095d28ff-ca7d-4b08-9e4b-e36a62db4810"


def witness_unit():
    return (
        "[Unit]\n[Service]\nType=notify\nNotifyAccess=main\n"
        f"ExecStart={main.g.PYTHON} -I -m azazel_edge.outcome.input_witness "
        f"--policy {main.g.BUNDLE}/trust.json --private-key {main.g.BUNDLE}/witness/key.raw "
        "--systemd-notify --apparmor-profile edge400-witness\n"
    )


@pytest.mark.parametrize(
    "fault",
    [
        None,
        "wrong",
        "duplicate",
        "missing",
        "type",
        "notify",
        "duplicate-type",
        "duplicate-notify",
        "crlf-type",
    ],
)
def test_witness_no_bytecode_changes_only_exact_command_and_recorded_bytes(
    tmp_path, monkeypatch, fault
):
    monkeypatch.setattr(main.g, "UNITS", tmp_path)
    monkeypatch.setattr(main.g, "ENV", dict(main.g.ENV))
    monkeypatch.setattr(main.g, "observer", None)
    monkeypatch.setattr(main.plan.p, "configure", lambda: None)
    prepared = main.g.prepare
    calls = []
    monkeypatch.setattr(main.g, "prepare", lambda *args, **kwargs: calls.append(kwargs))
    monkeypatch.setattr(main.g.Systemd, "witness", main.g.Systemd.witness)
    monkeypatch.setattr(
        main.WitnessProof,
        "sample_namespace",
        lambda self: dict(cookie=71, kernel_boot_id=BOOT),
    )
    captured = []

    def write(path, data, mode):
        with path.open("xb") as stream:
            stream.write(data.encode())
        path.chmod(mode)

    monkeypatch.setattr(main.g, "write", write)
    main._configure(
        lambda: None,
        lambda path, data: captured.append((path, data)),
        [5, 100],
        owner=SimpleNamespace(edge=lambda: (99, [5, 100])),
        output=tmp_path,
    )
    main.g.prepare()
    assert calls == [
        {"witness_network_namespace": {"cookie": 71, "kernel_boot_id": BOOT}}
    ]
    assert prepared is not main.g.prepare
    original = witness_unit()
    payload = original
    if fault == "wrong":
        payload = original.replace(" -I -m ", " -m ")
    elif fault == "duplicate":
        payload = original + "ExecStart=/usr/bin/true\n"
    elif fault == "missing":
        payload = "[Service]\nUser=root\n"
    elif fault == "type":
        payload = original.replace("Type=notify", "Type=simple")
    elif fault == "notify":
        payload = original.replace("NotifyAccess=main", "NotifyAccess=all")
    elif fault == "duplicate-type":
        payload = original + "Type=notify\n"
    elif fault == "duplicate-notify":
        payload = original + "NotifyAccess=main\n"
    elif fault == "crlf-type":
        payload = original.replace("Type=notify\n", "Type=notify\r\n")
    target = tmp_path / main.g.WITNESS
    if fault:
        with pytest.raises(
            AssertionError,
            match="exact current witness command|exact witness notify source",
        ):
            main.g.write(target, payload)
        assert not target.exists() and captured == []
        return
    main.g.write(target, payload)
    expected = original.replace(" -I -m ", " -I -B -m ").replace(
        " --systemd-notify", ""
    ).replace("Type=notify\n", "Type=exec\n").replace(
        "NotifyAccess=main\n", "NotifyAccess=none\n"
    ) + ("\n[Service]\nNetworkNamespacePath=" + main.setup.role.NSFS_TARGETS[0] + "\n")
    assert target.read_bytes() == expected.encode() == captured[0][1].encode()
    assert target.stat().st_mode & 0o7777 == 0o644
    core = tmp_path / main.g.UNIT
    main.g.write(core, original)
    assert core.read_bytes() == original.encode() == captured[1][1].encode()
    with pytest.raises(AssertionError, match="fixed owned namespace"):
        main.g.prepare(witness_network_namespace={"device": 5, "inode": 101})


class Case:
    def __init__(self, root, monkeypatch, fault=None):
        self.root, self.fault, self.events, self.source, self.rows = (
            root,
            fault,
            [],
            b"",
            [],
        )
        self.session = "1" * 32  # Valid native session beginning with a digit.
        self.output = root / "evidence"
        old_base = main.g.BASE
        monkeypatch.setattr(main.g, "BASE", root / "scope")
        monkeypatch.setattr(main.g, "BUNDLE", main.g.BASE / "bundle")
        monkeypatch.setattr(main.g, "UNITS", root / "units")
        main.g.UNITS.mkdir()
        monkeypatch.setattr(main.g, "CORE", root / "core")
        self.image = b"\x7fELF\x02\x01synthetic-unexecuted-core"
        main.g.CORE.write_bytes(self.image)
        main.g.CORE.chmod(0o755)
        monkeypatch.setattr(
            main.plan,
            "BASE_ENV",
            {
                k: str(main.g.BASE / Path(v).relative_to(old_base))
                if v.startswith(str(old_base) + "/")
                else v
                for k, v in main.plan.BASE_ENV.items()
            },
        )
        monkeypatch.setattr(main.material, "SRC", Path("/opt/edge400-src"))
        self.pins = dict(
            source_commit="a" * 40,
            archive_sha256="b" * 64,
            core_sha256=hashlib.sha256(self.image).hexdigest(),
            abi_sha256="c" * 64,
            interpreter_sha256="d" * 64,
        )
        source_key = str(Path(main.setup.role.SOURCE).relative_to(main.material.SRC))
        self.baseline = dict(
            pins=self.pins,
            kernel_boot_id=BOOT,
            material=dict(source_sha256={source_key: "e" * 64}),
        )

        def preflight(output, **pins):
            assert pins == self.pins
            output.mkdir(mode=0o700)
            self.events.append("preflight")
            return self.baseline

        monkeypatch.setattr(main.setup, "preflight", preflight)
        monkeypatch.setattr(
            main.WitnessProof,
            "sample_namespace",
            lambda self: dict(cookie=71, kernel_boot_id=BOOT),
        )
        case = self

        class Namespaces:
            failed = False

            def __init__(self, output, baseline):
                assert output == case.output and baseline is case.baseline

            def prepare(self):
                case.events.append("namespace-prepare")
                if fault == "namespace":
                    raise RuntimeError("synthetic namespace failure")

            def edge(self):
                return 99, [1, 2]

            def close(self):
                case.events.append("namespace-close")
                assert "outer-cleanup" in case.events
                if fault == "namespaceclose" or self.failed:
                    raise RuntimeError("synthetic namespace retention")

        monkeypatch.setattr(main, "NamespaceSetup", Namespaces)
        original_read = main.reader.read_regular

        def reading(path, *, owner, max_bytes, **kwargs):
            # Only role-ownership adapter; original protected IO still checks the
            # real physical file, type, parent, identity, mode and finite bytes.
            return original_read(
                path, owner=Path(path).stat().st_uid, max_bytes=max_bytes, **kwargs
            )

        for module in (main, main.reader, input_live, main.initializer.observer):
            monkeypatch.setattr(module, "read_regular", reading)
        monkeypatch.setattr(
            main.material,
            "_read",
            lambda path, limit=1024 * 1024, mode=None: reading(
                path, owner=0, max_bytes=limit, mode=mode
            )[0],
        )
        monkeypatch.setattr(
            main.material.preflight.old,
            "private_output",
            lambda path: path.mkdir(mode=0o700),
        )
        actual_open_parent = main.material.preflight.open_parent
        monkeypatch.setattr(
            main.material.preflight,
            "open_parent",
            lambda path, **kw: actual_open_parent(path, trusted_owner=os.geteuid()),
        )

        def info(value):
            return SimpleNamespace(
                st_dev=value.st_dev,
                st_ino=value.st_ino,
                st_mode=value.st_mode,
                st_nlink=value.st_nlink,
                st_uid=0,
            )

        monkeypatch.setattr(
            main,
            "os",
            SimpleNamespace(
                **{
                    k: getattr(os, k)
                    for k in (
                        "open",
                        "close",
                        "fchmod",
                        "fsync",
                        "O_RDONLY",
                        "O_DIRECTORY",
                        "O_NOFOLLOW",
                        "path",
                    )
                },
                stat=lambda *a, **kw: info(os.stat(*a, **kw)),
                fstat=lambda fd: info(os.fstat(fd)),
            ),
        )

        def write(path, data, mode=0o644):
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with path.open("xb") as f:
                f.write(data if type(data) is bytes else data.encode())
            path.chmod(mode)

        monkeypatch.setattr(main.g, "write", write)
        monkeypatch.setattr(main.g, "boot", lambda: BOOT)
        monkeypatch.setattr(main.g, "prepare_lab", self.provision)
        monkeypatch.setattr(main.initializer, "initialize", self.initialize)

        class SyntheticSystemd:
            def cores(self):
                return [{"pid": 111}]

            def witness(self, *args):
                raise AssertionError(
                    "synthetic Switch must not claim actual witness execution"
                )

        monkeypatch.setattr(main.g, "Systemd", SyntheticSystemd)
        monkeypatch.setattr(
            main.g, "systemctl", lambda *a: self.events.append("manager:" + ":".join(a))
        )
        monkeypatch.setattr(main.g, "wait_for", lambda fn: fn())
        monkeypatch.setattr(main.g, "live", self.start)
        monkeypatch.setattr(main.g, "stop", self.stop)

        class Switch:
            def __init__(self, bundle):
                assert bundle == main.g.BUNDLE

            def plan(self):
                return {"synthetic-sealed-plan": True}

            def apply(self, plan, digest):
                case.events.append("sealed-switch")
                if fault == "switch":
                    raise RuntimeError("synthetic switch failure")
                return {"status": "started"}

        monkeypatch.setattr(main.g, "Switch", Switch)
        monkeypatch.setattr(
            main.lab,
            "unit_snapshot",
            lambda unit: dict(
                LoadState="loaded",
                ActiveState="active",
                MainPID="123",
                ControlPID="0",
                ControlGroup="/system.slice/" + unit,
                pid_stat="synthetic",
            ),
        )

        @contextmanager
        def live(output, initialization, **args):
            assert initialization is self.initialized
            self.events.append("live-enter")
            positions = self.positions()
            self.rows += [
                ("session_open", {"boot_id": main.plan.n.boot_reference(BOOT)})
            ]
            self.rows += [
                ("cursor", dict(position=pos, missed=True)) for pos in positions
            ]
            self.rows += [("input_ready", positions[-1])]
            self.journal()
            self.context = dict(
                kernel_boot_id=BOOT,
                boot_ref=main.plan.n.boot_reference(BOOT),
                signed_boot_ref=BOOT.replace("-", ""),
                scope_ref=self.trust.data["scope_ref"],
                registration_sha256=self.trust.data["origin_registration_sha256"],
                source_start_position=positions[-1],
                policy_sha256=main.plan.manifest_digest(self.payload),
                policy_file_sha256=hashlib.sha256(
                    main.plan.POLICY_PATH.read_bytes()
                ).hexdigest(),
            )
            self.put(self.directory / "observer-start-context.json", self.context)
            self.record = main.reader.recording.CallRecording(
                self.directory / "actual-collector-calls.jsonl",
                metadata=dict(
                    policy_sha256=main.plan.manifest_digest(self.payload),
                    policy_source_ref=str(main.plan.POLICY_PATH),
                    policy_ref=self.policy.policy_ref,
                ),
            )
            if fault != "emptycalls":
                proc = self.root / "synthetic-proc"
                proc.mkdir()
                sample = proc_sample(proc)  # Actual parser, synthetic public proc text.
                if fault == "samplecoverage":
                    sample["coverage"]["proc_uptime"] = False
                if fault == "sampletype":
                    sample["system"]["memory_total_kib"] = 1000.0
                self.record.append(
                    "sample",
                    dict(
                        epoch=1001.0 if fault == "sampleepoch" else sample["epoch"],
                        start_ns=2,
                        end_ns=3,
                        clock_before=dict(
                            monotonic_before_ns=0, epoch_ns=10**12, monotonic_after_ns=1
                        ),
                        clock_after=dict(
                            monotonic_before_ns=4, epoch_ns=10**12, monotonic_after_ns=5
                        ),
                        sample=sample,
                    ),
                )
            session = SimpleNamespace(
                result=None, poll=lambda: 1 if fault == "ready" else None
            )
            try:
                yield session
                self.record.close(complete=True)
                if fault != "terminal":
                    session.result = {"terminal": self.terminal}
            finally:
                self.record.close(complete=False)
                self.events.append("live-helper-cleanup")

        monkeypatch.setattr(main, "live", live)

        def cleanup(units, tracked):
            self.events.append("outer-cleanup")
            self.cleaned = units
            assert (
                main.setup.scope.INITIALIZER_UNIT not in units
                and main.setup.scope.OBSERVER_UNIT not in units
            )
            if units:
                assert units[-1] == main.g.WITNESS
            return dict(
                errors=["synthetic unknown actor"] if fault == "cleanup" else []
            )

        monkeypatch.setattr(main.lab, "cleanup", cleanup)

    def put(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        raw = value if type(value) is bytes else _json(value)
        if path.exists():
            previous = path.read_bytes()
            assert raw.startswith(previous)
            with path.open("ab") as f:
                f.write(raw[len(previous) :])
        else:
            path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def provision(self):
        self.events.append("provision")
        main.g.BASE.mkdir(mode=0o700)
        (main.g.BASE / "native").mkdir()
        for key in (
            "EVE_PATH",
            "NORMALIZED_EVENT_LOG",
            "DEFENSE_RELEASE_LEDGER",
            "REDIRECT_POLICY_PATH",
            "PROTECTED_FLOWS_PATH",
        ):
            path = Path(main.g.ENV["AZAZEL_" + key])
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_text(
                main.plan.PROTECTED if key == "PROTECTED_FLOWS_PATH" else ""
            )
            path.chmod(0o600)
        main.g.write(
            main.g.UNITS / main.g.UNIT,
            "[Unit]\n[Service]\nExecStart=/unexecuted-core\n",
        )
        main.g.write(
            main.g.UNITS / main.g.WITNESS,
            # The real armor writer appends the confinement argument itself.
            witness_unit().replace(" --apparmor-profile edge400-witness", ""),
        )
        bundle = main.g.BUNDLE
        base, self.pk, self.wk, *_ = make_policy(
            bundle, producer=61001, observer=61002, witness=0
        )
        origin = dict(
            schema_version="outcome-live-origin-registration/v4",
            mode="live-core",
            scope_ref=base.data["scope_ref"],
            **{
                k: base.data[k]
                for k in ("producer_ref", "stream_ref", "producer_public_key")
            },
            binary_path=str(main.g.CORE),
            binary_sha256=self.pins["core_sha256"],
            launcher_uid=0,
            ai_socket_uid=0,
            capture_apparmor_profile="edge400-capture",
            native_apparmor_profile="edge400-provider",
            environment=dict(main.g.ENV),
        )
        self.trust = TrustPolicy(
            dict(
                base.data,
                schema_version="outcome-input-trust/v4",
                witness_transport=transport(
                    base.data["scope_ref"], dict(cookie=71, kernel_boot_id=BOOT)
                ),
                source_path=str(bundle / "input"),
                journal_directory=str(bundle / "observer"),
                anchor_directory=str(bundle / "witness/anchors"),
                socket_path=str(bundle / "socket/witness.sock"),
                origin_registration_sha256=hashlib.sha256(_json(origin)).hexdigest(),
            )
        )
        self.put(bundle / "trust.json", dict(self.trust.data))
        self.put(bundle / "origin.json", origin)
        self.source_file = self.put(bundle / "input", b"")
        self.directory = Path(self.trust.data["journal_directory"])
        self.directory.mkdir()
        self.verifier = SourceVerifier(self.trust)
        self.events.append("witness-ready")
        main.g.observer(True)

    def initialize(self, output, **args):
        self.events.append("genuine-init-fixture")
        if self.fault == "init":
            raise RuntimeError("synthetic init failure")
        assert main.g.BASE.stat().st_mode & 0o7777 == 0o755
        self.payload, self.policy, _ = main.initializer.observer.policy_material()
        data = self.trust.data
        info = self.source_file.stat()
        header = dict(
            schema_version="outcome-observation-journal/v3",
            scope_ref=data["scope_ref"],
            policy_sha256=main.reader.sha(
                persistence_context(self.policy, "es", 0.25).encode()
            ),
            max_identities=4096,
            max_bytes=data["journal_max_bytes"],
            input_config=dict(
                path_sha256=main.reader.sha(data["source_path"].encode()),
                device=info.st_dev,
                inode=info.st_ino,
                uid=61001,
                max_bytes=data["input_max_bytes"],
                max_records=data["input_max_records"],
                authentication=self.trust.binding(),
            ),
        )
        self.rows = [
            ("header", header),
            ("session_open", {"boot_id": main.plan.n.boot_reference(BOOT)}),
            ("input_ready", dict(offset=0, sha256=main.reader.sha(b""))),
            ("session_close", {"boot_id": main.plan.n.boot_reference(BOOT)}),
        ]
        self.journal()
        self.initialized = dict(
            proof=dict(actor=dict(evidence=dict(before={"synthetic-init-unit": True})))
        )
        return self.initialized

    def append(self, kind, index):
        event = json.loads(
            signed_frame(
                self.trust,
                self.pk,
                frame(kind, index, self.session),
                self.verifier.seq + 1,
                self.verifier.head,
            )
        )["event"]
        self.source += signed(
            self.trust,
            self.pk,
            seq=self.verifier.seq + 1,
            prev=self.verifier.head,
            event=event,
            boot_ref=BOOT.replace("-", ""),
        )
        self.verifier.verify(self.source)
        self.put(self.source_file, self.source)

    def positions(self):
        offset = 0
        rows = []
        for line in self.source.splitlines(keepends=True):
            offset += len(line)
            rows.append(
                dict(offset=offset, sha256=main.reader.sha(self.source[:offset]))
            )
        return rows

    def start(self):
        self.events.append("signed-prefix")
        self.append("session_prepare", 0)
        self.append("session_start", 1)

    def journal(self):
        raw, frames = journal(self.rows)
        path = self.put(self.directory / "observations.journal", raw)
        # Reuse the existing full-composition fixture's real witness signer.
        self.witness = Fixture.anchors(
            self, self.trust, self.wk, self.source, raw, frames, path.stat()
        )

    def stop(self):
        self.events.append("native-stop")
        self.append("session_end", 2)
        positions = self.positions()
        self.rows += [
            ("cursor", dict(position=positions[-1], missed=True)),
            (
                "session_close",
                {}
                if self.fault == "close"
                else {"boot_id": main.plan.n.boot_reference(BOOT)},
            ),
        ]
        self.journal()
        wire = self.source.splitlines(keepends=True)[-1]
        decoded = SourceVerifier.unwrap(wire)
        self.terminal = dict(
            context=self.context,
            witness_state=self.witness,
            terminal=TerminalControlStop(
                self.trust.data["origin_registration_sha256"],
                self.session,
                self.verifier.live_state.seq,
                positions[-2],
                positions[-1],
                wire,
                decoded,
                0,
            ).to_dict(),
        )
        self.put(self.directory / "observer-terminal-result.json", self.terminal)
        self.put(self.directory / "terminal.wire", wire)
        self.put(self.directory / "terminal.decoded", decoded)
        if self.fault == "signature":
            wire = json.loads(self.source.splitlines()[-1])
            wire["signature"] = "0" * 128
            self.source_file.write_bytes(
                b"".join(self.source.splitlines(keepends=True)[:-1])
                + _json(wire)
                + b"\n"
            )


@contextmanager
def case(monkeypatch, fault=None):
    with tempfile.TemporaryDirectory(prefix="ec-", dir="/tmp") as directory:
        yield Case(Path(directory).resolve(), monkeypatch, fault)


def test_complete_synthetic_auth_connection_uses_real_source_journal_witness_validators(
    monkeypatch,
):
    with case(monkeypatch) as fixture:
        result = main.commission_telemetry(fixture.output, **fixture.pins)
        assert result["status"] == "authenticated_connection_complete"
        assert result["evidence"]["session_ref"] == "1" * 32
        assert (
            result["measurement_completed"]
            is result["authorizes_transition"]
            is result["experiment"]
            is result["production_admission"]
            is False
        )
        assert (
            fixture.events.index("witness-ready")
            < fixture.events.index("genuine-init-fixture")
            < fixture.events.index("signed-prefix")
            < fixture.events.index("live-enter")
            < fixture.events.index("native-stop")
            < fixture.events.index("outer-cleanup")
            < fixture.events.index("namespace-close")
        )
        recorded = main.reader.recording.read_calls(
            fixture.output / "actual-collector-calls.jsonl"
        )
        assert [row["kind"] for row in recorded["calls"]] == ["sample"]
        assert all(recorded["calls"][0]["data"]["sample"]["coverage"].values())
        assert (fixture.output / "witness-anchors.raw").exists() and (
            fixture.output / "actual-collector-calls.jsonl"
        ).exists()


@pytest.mark.parametrize(
    "fault",
    [
        "namespace",
        "init",
        "switch",
        "ready",
        "terminal",
        "signature",
        "close",
        "cleanup",
        "namespaceclose",
        "emptycalls",
        "samplecoverage",
        "sampletype",
        "sampleepoch",
    ],
)
def test_every_auth_or_cleanup_gap_withholds_result_and_attempts_outer_cleanup(
    monkeypatch, fault
):
    with case(monkeypatch, fault) as fixture:
        with pytest.raises(Exception) as caught:
            main.commission_telemetry(fixture.output, **fixture.pins)
        if fault == "emptycalls":
            assert "lacks an actual telemetry sample" in str(caught.value)
            assert (
                main.reader.recording.read_calls(
                    fixture.output / "actual-collector-calls.jsonl"
                )["calls"]
                == []
            )
        assert "outer-cleanup" in fixture.events and "namespace-close" in fixture.events
        assert not (fixture.output / "commission-result.json").exists()
        if fault in (
            "signature",
            "close",
            "emptycalls",
            "samplecoverage",
            "sampletype",
            "sampleepoch",
        ):
            assert (
                (fixture.output / "source-final.raw").exists()
                and (fixture.output / "journal-final.raw").exists()
                and (fixture.output / "witness-anchors.raw").exists()
            )
            assert (
                fixture.output / "source-final.raw"
            ).read_bytes() == fixture.source_file.read_bytes()


def test_failed_root_namespace_sample_precedes_all_configuration(tmp_path, monkeypatch):
    before = (
        main.g.write,
        main.g.prepare,
        main.g.Systemd.witness,
        main.g.observer,
        dict(main.g.ENV),
    )
    calls = []

    def sample(self):
        calls.append("metadata-only")
        self.owner.failed = True
        raise RuntimeError("synthetic unavailable namespace cookie")

    monkeypatch.setattr(main.WitnessProof, "sample_namespace", sample)
    monkeypatch.setattr(
        main.plan.p,
        "configure",
        lambda: pytest.fail("no provider configuration before sampling"),
    )
    owner = SimpleNamespace(failed=False, edge=lambda: (99, [5, 100]))
    with pytest.raises(RuntimeError, match="unavailable namespace cookie"):
        main._configure(
            lambda: pytest.fail("no observer"),
            lambda *args: pytest.fail("no units"),
            [5, 100],
            owner=owner,
            output=tmp_path,
        )
    assert calls == ["metadata-only"] and owner.failed
    assert (
        main.g.write,
        main.g.prepare,
        main.g.Systemd.witness,
        main.g.observer,
        dict(main.g.ENV),
    ) == before
    assert list(tmp_path.iterdir()) == []
