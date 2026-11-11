"""SYNTHETIC v2 Root metadata/IO; real crypto, replay, clocks and measurement.

Uses the existing four-context fixture's actual collector (persistence=None),
manually assembled journal with real ephemeral source/witness signatures. No
runtime/UID/LSM/durable-store/namespace/native execution or efficacy is proved.
"""

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import stat
from types import SimpleNamespace
import uuid

import pytest
import test_signed_network_composition as fixture_source
from test_signed_network_composition import Fixture, anchor
from test_signed_network_telemetry_proof import actual_effective, identity
from azazel_edge.outcome.input_auth import TrustPolicy
from azazel_edge.outcome.input_transport import transport
from azazel_edge.outcome.journal import _json
import signed_network_telemetry_read as new
import signed_network_telemetry_phase as prep
import signed_network_telemetry_run as runner
from signed_network_telemetry_commission_setup import UNITS

old, plan, phase, material, role = new.old, new.plan, new.phase, new.material, new.role


class TelemetryFixture(Fixture):
    def __init__(self, root, monkeypatch):
        super().__init__(root, monkeypatch)
        self.pins = dict(
            source_commit="a" * 40,
            archive_sha256="e" * 64,
            core_sha256=self.core_sha,
            abi_sha256=old.sha(b"SYNTHETIC ABI"),
            interpreter_sha256=old.sha(b"SYNTHETIC INTERPRETER"),
        )
        self.manifest, self.safety = plan.planned_telemetry(
            "a" * 40,
            self.core_sha,
            abi_sha256=self.pins["abi_sha256"],
            interpreter_sha256=self.pins["interpreter_sha256"],
            source_archive_sha256=self.pins["archive_sha256"],
        )
        self.manifest_sha = plan.manifest_digest(self.manifest)
        monkeypatch.setattr(material, "read_regular", self.read)
        monkeypatch.setattr(
            phase.g, "guard", lambda: None
        )  # Explicit synthetic Root/VM boundary only.
        monkeypatch.setenv(material.FLAG, "1")
        monkeypatch.setattr(
            new,
            "_root_children",
            lambda: [
                phase.WORK / p.name
                for p in self.physical(phase.WORK).glob("*-receipt.json")
                if p.name.startswith(("namespace-cookie-", "switch-witness-"))
            ],
        )
        monkeypatch.setattr(
            phase,
            "validated_inputs",
            lambda a, b: prep.validated_telemetry_inputs(a, b, **self.pins),
        )

        def enrolled(value):
            boot = str(uuid.uuid5(uuid.NAMESPACE_DNS, "synthetic-" + self.active.name))
            return TrustPolicy(
                dict(
                    value,
                    schema_version="outcome-input-trust/v4",
                    witness_transport=transport(
                        value["scope_ref"], dict(cookie=71, kernel_boot_id=boot)
                    ),
                )
            )

        monkeypatch.setattr(fixture_source, "TrustPolicy", enrolled)

    def physical(self, path):
        path = Path(path)
        if path == Path(role.ALIAS) or path == material.preflight.ABI:
            return self.active / str(path).lstrip("/")
        return super().physical(path)

    def read(self, path, *, owner, max_bytes, **kwargs):
        raw, info = super().read(path, owner=owner, max_bytes=max_bytes, **kwargs)
        # Declared role-ownership adapter, never a privileged file operation.
        projected = SimpleNamespace(
            **{
                key: getattr(info, key)
                for key in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size")
            },
            st_uid=owner,
            st_gid=owner,
        )
        return raw, projected

    def put(self, path, value):
        if Path(path) == phase.TICKET:
            value = dict(value, schema_version="signed-network-telemetry-ticket/v2")
        actual = super().put(path, value)
        if Path(path) == phase.g.CORE:
            actual.chmod(0o755)
        return actual

    def read_result(self):
        self.enrich()
        before = {p: p.read_bytes() for p in self.active.rglob("*") if p.is_file()}
        result = new.read_telemetry_assignment(
            self.manifest_sha, self.head, **self.pins
        )
        assert before == {
            p: p.read_bytes() for p in self.active.rglob("*") if p.is_file()
        }
        return result

    def bundle(self, mode, binding, handles):
        unit = role.observer_spec(mode)["unit"]
        pid = 123 if mode == "initialize" else 124
        actual = identity()
        actual.update(pid=pid, tgid=pid)
        ready = dict(
            kind=role.READY_KIND,
            role=role.ROLE,
            mode=mode,
            identity=actual,
            kernel_boot_id=binding["kernel_boot_id"],
            source=role.SOURCE,
            source_sha256=binding["observer_source_sha256"],
        )
        state = dict(
            LoadState="loaded",
            ActiveState="active",
            MainPID=str(pid),
            ControlPID="0",
            ControlGroup="/system.slice/" + unit,
            pid_stat=str(pid) + " (worker) " + " ".join(["S"] + ["0"] * 18 + ["10"]),
        )
        mounts = "30 1 0:4 / /proc rw - proc proc rw,hidepid=ptraceable\n" + "".join(
            f"{40 + i} 1 0:1 net:[{pair[1]}] {path} rw - nsfs nsfs rw\n"
            for i, (path, pair) in enumerate(handles.items())
        )
        status = (
            f"Pid:\t{pid}\nTgid:\t{pid}\nUid:\t61002 61002 61002 61002\nGid:\t61002 61002 61002 61002\nGroups:\t61002\nNoNewPrivs:\t1\n"
            + "".join(
                key + ":\t0000000000000000\n"
                for key in ("CapEff", "CapPrm", "CapAmb", "CapBnd")
            )
        )
        raw = dict(
            status=status,
            label=role.PROFILE + " (enforce)\n",
            cgroup="0::/system.slice/" + unit + "\n",
            mountinfo=mounts,
        )
        namespaces = dict(net=[1, 101], mnt=[5, 10], pid1_mnt=[5, 11])
        evidence = dict(
            before=state,
            after=deepcopy(state),
            raw=raw,
            namespaces=namespaces,
            namespace_after=deepcopy(namespaces),
            proc_device=[0, 4],
            fd_names=["0", "1", "2"],
            expected_stdio={str(i): dict(device=16, inode=100 + i) for i in range(3)},
            fds=[
                dict(
                    fd=i,
                    device=16,
                    inode=100 + i,
                    mode=stat.S_IFIFO | 0o600,
                    target=f"pipe:[{100 + i}]",
                )
                for i in range(3)
            ],
        )
        metadata = dict(
            mode=mode,
            kernel_boot_id=binding["kernel_boot_id"],
            observed_kernel_boot_id=binding["kernel_boot_id"],
            source_sha256=binding["observer_source_sha256"],
            observed_source_sha256=binding["observer_source_sha256"],
            reserved_argv=new.proof.reserved_argv(mode),
            namespaces_before=handles,
            namespaces_after=handles,
        )
        effective = actual_effective(mode)
        data = dict(
            ready=ready,
            effective=effective,
            actor=dict(identity=actual, evidence=evidence),
            metadata=metadata,
        )
        directory = phase.WORK / ("initialize" if mode == "initialize" else "live")
        self.put(directory / (mode + "-pre-api-ready.raw"), _json(ready) + b"\n")
        for key, value in raw.items():
            self.put(directory / (mode + "-" + key + ".raw"), value.encode())
        bus = "/org/freedesktop/systemd1/unit/" + unit.replace("-", "_2d").replace(
            ".", "_2e"
        )
        commands = dict(
            systemctl=[
                "systemctl",
                "show",
                unit,
                "--property=" + ",".join(new.proof.p.EFFECTIVE),
            ],
            busctl=[
                "/usr/bin/busctl",
                "--system",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                bus,
                "org.freedesktop.systemd1.Service",
                *new.proof.p.old.HOOKS,
            ],
        )
        for backend, argv in commands.items():
            prefix = directory / (mode + "-effective-" + backend)
            self.put(str(prefix) + ".argv.json", argv)
            self.put(str(prefix) + ".result.json", dict(returncode=0, error=None))
            self.put(str(prefix) + ".stderr", b"")
            output = (
                (
                    "\n".join(
                        k + "=" + v
                        for k, v in effective.items()
                        if k not in new.proof.p.old.HOOKS
                    )
                    + "\n"
                ).encode()
                if backend == "systemctl"
                else b"\n".join(
                    _json(dict(type="a(sasbttttuii)", data=[]))
                    for _ in new.proof.p.old.HOOKS
                )
                + b"\n"
            )
            self.put(str(prefix) + ".stdout", output)
        value = dict(
            proof=data, binding=binding, binding_sha256=plan.manifest_digest(binding)
        )
        self.put(
            directory
            / (
                ("initializer" if mode == "initialize" else "live")
                + "-verified-bundle.json"
            ),
            value,
        )
        return data

    def enrich(self):
        def load(path):
            return json.loads(self.physical(path).read_bytes())

        prepared = load(phase.WORK / "prepared.json")
        facts = load(phase.WORK / "run-facts.json")
        record = facts["record"]
        trust = TrustPolicy(prepared["trust_policy"])
        boot = record["kernel_boot_id"]
        terminal = record["observer_terminal"]
        self.put(material.preflight.ABI, b"SYNTHETIC ABI")
        self.put(Path(role.ALIAS), b"SYNTHETIC INTERPRETER")
        handles = {path: [1, 101 + i] for i, path in enumerate(role.NSFS_TARGETS)}
        pub = dict(
            trust_sha256=trust.digest,
            trust_schema="outcome-input-trust/v4",
            trust_file_sha256=old.sha(
                self.physical(phase.g.BUNDLE / "trust.json").read_bytes()
            ),
            origin_file_sha256=old.sha(
                self.physical(phase.g.BUNDLE / "origin.json").read_bytes()
            ),
            witness_transport=trust.data["witness_transport"],
            **{
                key: trust.data[key]
                for key in (
                    "scope_ref",
                    "source_path",
                    "journal_directory",
                    "origin_registration_sha256",
                    "producer_uid",
                    "observer_uid",
                    "witness_uid",
                )
            },
        )
        sources = material.source_hashes()
        binding = dict(
            kernel_boot_id=boot,
            role=role.ROLE,
            namespace=[1, 101],
            material=dict(
                source_sha256=sources,
                abi_sha256=self.pins["abi_sha256"],
                interpreter_sha256=self.pins["interpreter_sha256"],
            ),
            observer_source_sha256=sources[
                str(Path(role.SOURCE).relative_to(Path("/opt/edge400-src")))
            ],
            roles={mode: role.observer_spec(mode) for mode in ("initialize", "live")},
            public_auth=pub,
            policy_file_sha256=terminal["context"]["policy_file_sha256"],
            policy_sha256=terminal["context"]["policy_sha256"],
            witness_actor=dict(
                unit=phase.g.WITNESS,
                pid=200,
                apparmor="edge400-witness (enforce)",
                network_namespace=dict(device=1, inode=101),
                witness_transport=trust.data["witness_transport"],
                namespace_observation=trust.data["witness_transport"][
                    "network_namespace"
                ],
                listener=dict(
                    abstract_name=trust.data["witness_transport"]["name"],
                    inode="444",
                    fd="4",
                ),
            ),
        )
        initproof = self.bundle("initialize", binding, handles)
        self.bundle("live", binding, handles)
        initial = dict(
            initialization=dict(
                initialized_empty=True,
                identity=initproof["ready"]["identity"],
                kernel_boot_id=boot,
                boot_ref=plan.n.boot_reference(boot),
                policy_sha256=binding["policy_sha256"],
                policy_file_sha256=binding["policy_file_sha256"],
            ),
            binding=binding,
            proof=initproof,
            authorizes_transition=False,
            experiment=False,
            production_admission=False,
        )
        self.put(phase.WORK / "initialize/initializer-result.json", initial)
        prepared.update(
            schema_version="signed-network-telemetry-prepared/v2",
            namespace_kind=plan.telemetry_assignment_mode()["namespace_kind"],
            measurement_completed=False,
            production_admission=False,
            initialization=initial,
            assignment_mode_sha256=prepared["inputs"]["assignment_mode_sha256"],
        )
        self.put(phase.WORK / "prepared.json", prepared)
        self.put(phase.WORK / "live/live-result.json", dict(terminal=terminal))
        self.put(
            phase.WORK / "live/live-launch.json",
            dict(
                kind="owned_systemd_run_client_popen/v1",
                client_pid=999,
                client_launch_before_ns=790000000,
                client_launch_after_ns=790001000,
                deadline_monotonic_ns=40790000000,
                budget_seconds=40,
            ),
        )
        self.put(
            phase.WORK / "live/live-client-reap.json",
            dict(pid=999, reaped=True, forced=False, errors=[]),
        )
        record.update(
            controller_start_anchor=anchor(-0.4),
            controller_end_anchor=anchor(33.0),
            observer_helper_return_ns=34300000000,
        )
        record["source_identity"] = runner._source_identity()
        calls = old.recording.decode_calls(
            self.physical(
                phase.g.BUNDLE / "observer/actual-collector-calls.jsonl"
            ).read_bytes()
        )
        for i, (label, key, seconds, event) in enumerate(
            (
                ("baseline", "baseline_probe", -0.3, None),
                ("active", "active_probe", 1.4, record["event"]),
                ("absence", "absence_probe", 32.5, record["release"]),
            )
        ):
            query = load(phase.WORK / (label + "-query.json"))
            start, end = anchor(seconds), anchor(seconds + 0.001)
            query.update(
                query_start_clock_anchor=start,
                query_end_clock_anchor=end,
                query_started_at=datetime.fromtimestamp(
                    start["epoch_ns"] / 1e9, timezone.utc
                ).isoformat(),
                query_ended_at=datetime.fromtimestamp(
                    end["epoch_ns"] / 1e9, timezone.utc
                ).isoformat(),
                source_identity=record["source_identity"],
            )
            self.put(phase.WORK / (label + "-query.json"), query)
            record[key] = query
            launch = dict(
                pid=query["root_pid"],
                actual_child_argv=["SYNTHETIC-query-" + label],
                namespace_identity=dict(device=1, inode=101),
                launch_before_ns=start["monotonic_before_ns"] - 1000,
                launch_after_ns=start["monotonic_before_ns"] - 500,
            )
            self.put(phase.WORK / (label + "-query-launch.json"), launch)
            if event is not None:
                row = next(
                    r
                    for r in calls["calls"]
                    if r["kind"] == "event"
                    and old.recording.canonical(r["data"]["event"])
                    == old.recording.canonical(event)
                )
                closed = self.physical(
                    phase.g.BUNDLE / "observer/actual-collector-calls.jsonl"
                ).read_bytes()
                lines = closed.splitlines(keepends=True)
                prefix = b"".join(lines[: row["seq"] + 1])
                info = self.physical(
                    phase.g.BUNDLE / "observer/actual-collector-calls.jsonl"
                ).stat()
                self.put(phase.WORK / (label + "-callback-prefix.raw"), prefix)
                self.put(phase.WORK / (label + "-callback-complete.raw"), prefix)
                self.put(
                    phase.WORK / (label + "-callback-ready.json"),
                    dict(
                        row=row,
                        recording_identity=dict(
                            device=info.st_dev, inode=info.st_ino, uid=61002
                        ),
                        raw_sha256=old.sha(prefix),
                        complete_sha256=old.sha(prefix),
                        partial_tail_bytes=0,
                        observed_before_ns=row["data"]["clock_after"][
                            "monotonic_after_ns"
                        ]
                        + 100,
                        observed_after_ns=row["data"]["clock_after"][
                            "monotonic_after_ns"
                        ]
                        + 200,
                    ),
                )
        self.put(phase.WORK / "run-facts.json", facts)
        for i in (1, 2, 3):
            for kind in ("intent", "confirmed"):
                name = f"namespace-{kind}-{i}.json"
                self.put(
                    phase.WORK / "namespace-evidence" / name,
                    self.physical(phase.WORK / name).read_bytes(),
                )
        states = [
            dict(
                unit=u,
                state=dict(
                    ActiveState="inactive", MainPID="0", ControlPID="0", ControlGroup=""
                ),
            )
            for u in UNITS
        ]
        actors = dict(errors=[], units=states[:4])
        namespaces = dict(
            errors=[],
            cleanup_verified=True,
            actors=states,
            names=list(reversed(role.NAMESPACE_NAMES)),
        )
        self.put(phase.WORK / "actor-cleanup.json", actors)
        self.put(phase.WORK / "namespace-evidence/cleanup.json", namespaces)
        self.put(
            phase.WORK / "namespace-cookie-1-receipt.json",
            dict(
                error=None,
                errors=[],
                group_empty_before_reap=True,
                reaped=True,
                status=0,
            ),
        )
        processes = [
            dict(
                pid=200 + i,
                argv=["SYNTHETIC-query-" + label],
                forced=False,
                returncode=0,
            )
            for i, label in enumerate(("baseline", "active", "absence"))
        ] + [
            dict(
                pid=300 + i,
                argv=["SYNTHETIC-peer-" + label],
                forced=False,
                returncode=0,
            )
            for i, label in enumerate(("service", "client"))
        ]
        for i, label in enumerate(("service", "client")):
            self.put(
                phase.WORK / (label + "-peer-launch.json"),
                dict(
                    pid=300 + i,
                    actual_child_argv=["SYNTHETIC-peer-" + label],
                    launch_before_ns=1,
                    launch_after_ns=2,
                ),
            )
        self.put(
            phase.WORK / "assignment-cleanup.json",
            dict(
                schema_version="signed-network-telemetry-cleanup/v2",
                errors=[],
                processes=processes,
                actor_cleanup=actors,
                namespace_cleanup=namespaces,
                root_child_count=1,
                cleanup_verified=True,
                measurement_completed=False,
                production_admission=False,
            ),
        )


def test_four_v2_records_compose_through_real_crypto_and_unchanged_measurement(
    tmp_path, monkeypatch
):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    results = []
    for i in range(4):
        result, outcomes = fixture.build(i)
        assert result["status"] == "calculation_available", result["reasons"]
        assert result["live_outcomes"] == [o.to_dict() for o in outcomes]
        results.append(result)
    before = old.recording.canonical(results)
    records = new.validate_fresh_telemetry_records(
        fixture.manifest, results, **fixture.pins
    )
    assert all(
        record
        is next(
            result["measurement_record"]
            for result in results
            if result["measurement_record"]["assignment_id"] == record["assignment_id"]
        )
        for record in records
    )
    report = new.read_telemetry_experiment(fixture.manifest, results, **fixture.pins)
    assert report["integrity_rejections"] == 0 and report["received_runs"] == 4
    assert [row["status"] for row in report["ledger"]] == ["qualified"] * 4
    assert (
        report["comparison"]["complete_pairs"] == 2
        and report["comparison"]["claim_status"] == "mechanical_only"
    )
    assert before == old.recording.canonical(results)


def reread(fixture):
    before = {p: p.read_bytes() for p in fixture.active.rglob("*") if p.is_file()}
    result = new.read_telemetry_assignment(
        fixture.manifest_sha, fixture.head, **fixture.pins
    )
    assert before == {
        p: p.read_bytes() for p in fixture.active.rglob("*") if p.is_file()
    }
    assert result["independent_service_facts"]["service"]["legitimate_accepted"] == 6
    return result


@pytest.mark.parametrize("mode", ["initialize", "live"])
@pytest.mark.parametrize("backend", ["systemctl", "busctl"])
@pytest.mark.parametrize("suffix", ["argv.json", "stdout", "stderr", "result.json"])
def test_each_original_backend_artifact_is_required(
    mode, backend, suffix, tmp_path, monkeypatch
):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    valid, _ = fixture.build(1)
    assert valid["status"] == "calculation_available", valid["reasons"]
    fixture.physical(
        phase.WORK / mode / (mode + "-effective-" + backend + "." + suffix)
    ).unlink()
    result = reread(fixture)
    assert result["status"] == "withheld" and result["measurement_record"] is None
    assert result["live_outcomes"] == valid["live_outcomes"]


@pytest.mark.parametrize(
    "fault", ["wrongargv", "nonzero", "boolrc", "stderr", "typedhook", "malformedtext"]
)
def test_raw_backend_semantics_are_replayed_not_trusted_flags(
    fault, tmp_path, monkeypatch
):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    valid, _ = fixture.build(1)
    assert valid["status"] == "calculation_available", valid["reasons"]
    prefix = phase.WORK / "live/live-effective-"
    if fault == "wrongargv":
        fixture.put(
            str(prefix) + "systemctl.argv.json",
            ["systemctl", "show", "foreign.service"],
        )
    elif fault in ("nonzero", "boolrc"):
        fixture.put(
            str(prefix) + "busctl.result.json",
            dict(returncode=1 if fault == "nonzero" else False, error=None),
        )
    elif fault == "stderr":
        fixture.put(str(prefix) + "systemctl.stderr", b"backend warning\n")
    elif fault == "malformedtext":
        fixture.put(str(prefix) + "systemctl.stdout", b"Unknown=value\n")
    else:
        raw = fixture.physical(str(prefix) + "busctl.stdout").read_bytes().splitlines()
        raw[0] = _json(dict(type="a(sasbttttuii)", data=[["/usr/bin/true"]]))
        fixture.put(str(prefix) + "busctl.stdout", b"\n".join(raw) + b"\n")
    result = reread(fixture)
    assert result["status"] == "withheld" and result["measurement_record"] is None


@pytest.mark.parametrize(
    "fault",
    [
        "wrongrole",
        "unregistered",
        "callbackbeforequery",
        "partialprefix",
        "clockdrift",
        "outsidecontroller",
        "lateactive",
        "latehelper",
        "missingpeer",
        "wrongcleanupargv",
        "replayedcleanuppid",
    ],
)
def test_independent_runtime_or_order_gap_withholds_without_repair(
    fault, tmp_path, monkeypatch
):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    valid, _ = fixture.build(1)
    assert valid["status"] == "calculation_available", valid["reasons"]

    def load(path):
        return json.loads(fixture.physical(path).read_bytes())

    if fault == "wrongrole":
        path = phase.WORK / "live/live-verified-bundle.json"
        data = load(path)
        data["proof"]["actor"]["identity"]["uid"] = 0
        fixture.put(path, data)
    elif fault == "unregistered":
        path = phase.g.BUNDLE / "origin.json"
        data = load(path)
        data["mode"] = "readonly-core"
        fixture.put(path, data)
    elif fault == "callbackbeforequery":
        path = phase.WORK / "active-callback-ready.json"
        data = load(path)
        data["observed_after_ns"] = (
            load(phase.WORK / "active-query-launch.json")["launch_before_ns"] + 1
        )
        fixture.put(path, data)
    elif fault == "partialprefix":
        fixture.put(phase.WORK / "active-callback-prefix.raw", b'{"not-original":')
    elif fault in ("clockdrift", "outsidecontroller", "lateactive"):
        label = "baseline" if fault == "outsidecontroller" else "active"
        path = phase.WORK / (label + "-query.json")
        data = load(path)
        if fault == "clockdrift":
            for key in ("query_start_clock_anchor", "query_end_clock_anchor"):
                data[key]["epoch_ns"] += 6000000
        else:
            start, end = (-0.5, -0.49) if fault == "outsidecontroller" else (3.9, 4.0)
            data.update(
                query_start_clock_anchor=anchor(start),
                query_end_clock_anchor=anchor(end),
            )
        data.update(
            query_started_at=datetime.fromtimestamp(
                data["query_start_clock_anchor"]["epoch_ns"] / 1e9, timezone.utc
            ).isoformat(),
            query_ended_at=datetime.fromtimestamp(
                data["query_end_clock_anchor"]["epoch_ns"] / 1e9, timezone.utc
            ).isoformat(),
        )
        fixture.put(path, data)
        path = phase.WORK / "run-facts.json"
        facts = load(path)
        facts["record"][label + "_probe"] = data
        fixture.put(path, facts)
    elif fault == "latehelper":
        path = phase.WORK / "run-facts.json"
        data = load(path)
        data["record"]["observer_helper_return_ns"] = (
            load(phase.WORK / "live/live-launch.json")["deadline_monotonic_ns"] + 1
        )
        fixture.put(path, data)
    elif fault == "missingpeer":
        fixture.physical(phase.WORK / "service-peer-launch.json").unlink()
    else:
        path = phase.WORK / "assignment-cleanup.json"
        data = load(path)
        if fault == "wrongcleanupargv":
            data["processes"][0]["argv"] = ["foreign-command"]
        else:
            data["processes"][0]["pid"] = data["processes"][1]["pid"]
        fixture.put(path, data)
    result = reread(fixture)
    assert result["status"] == "withheld" and result["measurement_record"] is None
    assert result["live_outcomes"] == valid["live_outcomes"]


@pytest.mark.parametrize("fault", ["end", "close", "release"])
def test_v2_never_waives_full_signed_baseline_or_candidate_chain(
    fault, tmp_path, monkeypatch
):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    result, _ = fixture.build(1 if fault == "release" else 0, fault)
    assert result["status"] == "withheld" and result["measurement_record"] is None


@pytest.mark.parametrize(
    "fault", ["missingC0", "keyreuse", "bootreuse", "wrongmapping", "wrongpin"]
)
def test_cross_four_requires_fresh_original_records_and_shared_external_pins(
    fault, tmp_path, monkeypatch
):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    results = [fixture.build(i)[0] for i in range(4)]
    assert all(r["status"] == "calculation_available" for r in results)
    pins = dict(fixture.pins)
    if fault == "missingC0":
        results[0]["status"] = "withheld"
    elif fault == "keyreuse":
        results[2]["authenticated_origin"]["witness_public_key"] = results[0][
            "authenticated_origin"
        ]["producer_public_key"]
    elif fault == "bootreuse":
        results[2]["authenticated_origin"]["kernel_boot_id"] = results[0][
            "authenticated_origin"
        ]["kernel_boot_id"]
    elif fault == "wrongmapping":
        results[2]["measurement_record"]["linkage"]["session_ref"] = (
            "native-session-" + "0" * 32
        )
    else:
        pins["archive_sha256"] = "f" * 64
    with pytest.raises((OSError, ValueError)):
        new.validate_fresh_telemetry_records(fixture.manifest, results, **pins)


def test_missing_prepared_mode_is_not_runtime_provenance(tmp_path, monkeypatch):
    fixture = TelemetryFixture(tmp_path, monkeypatch)
    valid, _ = fixture.build(1)
    assert valid["status"] == "calculation_available", valid["reasons"]
    path = phase.WORK / "prepared.json"
    prepared = json.loads(fixture.physical(path).read_bytes())
    del prepared["namespace_kind"]
    fixture.put(path, prepared)
    result = reread(fixture)
    assert result["status"] == "withheld" and result["measurement_record"] is None
