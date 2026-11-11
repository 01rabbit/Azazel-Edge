"""SYNTHETIC composition, never VM/UID/enforcement/efficacy evidence.

Only fixed-path/role-ownership IO and telemetry/clock SOURCES are adapted.
Signatures, public registration, source/journal/witness verification, collector,
replay, clock qualification, service joins and measurement all execute unchanged.
Root launch/netns/stop receipts below are deliberately synthetic fixture facts.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

import pytest
from auth_input_helpers import make_policy
from test_outcome_input_auth import signed
from test_outcome_live_origin import frame, signed_frame
from test_outcome_nft_flow_evidence import payload
from test_signed_network_read import journal
from test_signed_network_run import decision, release
from azazel_edge.benchmark.measurement import measure_experiment
from azazel_edge.outcome import from_rust_event, input_auth, input_live, input_resume
from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier, sign
from azazel_edge.outcome.input_witness import ANCHOR_DOMAIN, digest
from azazel_edge.outcome.input_terminal import TerminalControlStop
from azazel_edge.outcome.journal import _json, ZERO_HASH
from azazel_edge.outcome.telemetry import OutcomeTelemetryPolicy, TelemetrySample, persistence_context

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_read as reader
import signed_network_recording as recording
from signed_network_freshness import validate_fresh_records

phase, run, service = reader.phase, reader.run, reader.service
EPOCH, NS = 1794387600, 1_000_000_000


def anchor(seconds):
    mono = round((seconds + 1) * NS)
    return dict(monotonic_before_ns=mono, epoch_ns=EPOCH * NS + mono - NS + 50, monotonic_after_ns=mono + 100)


class SyntheticClock:
    def __init__(self):
        self.ns = 0

    def at(self, seconds):
        self.ns = max(self.ns, round((seconds + 1) * NS))

    def monotonic_ns(self):
        self.ns += 100
        return self.ns

    def time_ns(self):
        return EPOCH * NS + self.ns - NS


class SyntheticTelemetry:
    def __init__(self, coverage=True):
        self.coverage = coverage

    def sample(self, *, interface, epoch):
        return TelemetrySample(
            epoch=epoch,
            observed_at=datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
            interface=interface,
            network=dict(
                rx_bytes=round((epoch - EPOCH) * 1024),
                rx_packets=10,
                rx_errors=0,
                rx_dropped=0,
                tx_bytes=1,
                tx_packets=1,
                tx_errors=0,
                tx_dropped=0,
            ),
            system=dict(load1=0.1, memory_available_kib=100000),
            coverage={
                k: self.coverage for k in ("proc_net_dev", "proc_loadavg", "proc_meminfo", "proc_uptime")
            },
            evidence_ref="synthetic-telemetry",
        )


class Fixture:
    """Four separate synthetic filesystem/role contexts; no privileged calls."""

    def __init__(self, root, monkeypatch):
        self.root, self.active = root, None
        self.original_read = input_auth.read_regular
        self.image = b"\x7fELF\x02\x01synthetic-unexecuted-core"
        self.core_sha = hashlib.sha256(self.image).hexdigest()
        self.manifest, self.safety = phase.plan.planned("a" * 40, self.core_sha)
        self.manifest_sha = recording.manifest_digest(self.manifest)
        self.head = "b" * 64
        for module in (input_auth, input_live, reader, phase, run, phase.observer):
            monkeypatch.setattr(module, "read_regular", self.read)
        self.clock = SyntheticClock()
        monkeypatch.setattr(recording, "time", self.clock)

    def physical(self, path):
        path = Path(path)
        if str(path).startswith("/var/lib/edge400") or path in (phase.g.CORE, phase.SRC / "SOURCE_REVISION"):
            return self.active / str(path).lstrip("/")
        return path

    def read(self, path, *, owner, max_bytes, **kwargs):
        # Explicit synthetic role ownership boundary; actual file identity/mode,
        # complete bytes and all upper-layer authentication remain checked.
        return self.original_read(self.physical(path), owner=os.geteuid(), max_bytes=max_bytes, **kwargs)

    def put(self, path, value):
        path = self.physical(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(value if type(value) is bytes else _json(value))
        path.chmod(0o600)
        return path

    def collect(self, directory, events, candidate, fault):
        policy_raw = phase.plan.strict(phase.plan.POLICY_PATH.read_bytes())
        policy = OutcomeTelemetryPolicy.from_mapping(policy_raw, source_ref=str(phase.plan.POLICY_PATH))
        self.clock.ns = 0
        outcomes = []
        with recording.record_collector(
            directory, policy=policy_raw, policy_source_ref=str(phase.plan.POLICY_PATH)
        ):
            collector = input_resume.OutcomeTelemetryCollector(
                source=SyntheticTelemetry(fault != "coverage"),
                policy=policy,
                interface="es",
                sample_interval_seconds=0.25,
            )
            for quarter in range(21):
                if fault == "samples" and quarter == 2:
                    continue
                t = quarter / 4
                self.clock.at(t)
                collector.record_sample(epoch=EPOCH + t)
                if t == 1.25:
                    collector.observe_event(events[2], observed_epoch=EPOCH + t)
                self.clock.at(t + 0.001)
                outcomes.extend(collector.finalize_due(epoch=EPOCH + t + 0.001))
            if candidate and fault != "release":
                for t, event in zip((31.25, 32.25), events[3:-1] if fault != "end" else events[3:]):
                    self.clock.at(t)
                    collector.observe_event(event, observed_epoch=EPOCH + t)
                    collector.finalize_due(epoch=EPOCH + t + 0.001)
        return policy, outcomes, recording.read_calls(directory)

    def build(self, index, fault=None):
        assignment = self.manifest["assignments"][index]
        candidate = assignment["arm"] == "flow_throttle"
        self.active = self.root / assignment["id"]
        self.active.mkdir(mode=0o700)
        boot = str(uuid.uuid5(uuid.NAMESPACE_DNS, "synthetic-" + assignment["id"]))
        session = ("b" * 32, "7" + "a" * 31, "3" + "c" * 31, "d" * 32)[index]
        run_id = "synthetic-run-" + str(index)
        ticket = dict(
            manifest_sha256=self.manifest_sha,
            assignment_id=assignment["id"],
            run_id=run_id,
            start_head=self.head,
        )
        for path, value in (
            (phase.MANIFEST, self.manifest),
            (phase.TICKET, ticket),
            (phase.g.CORE, self.image),
            (phase.SRC / "SOURCE_REVISION", b"a" * 40 + b"\n"),
        ):
            self.put(path, value)
        inputs = phase.validated_inputs(self.manifest_sha, self.head)
        bundle = phase.g.BUNDLE
        trust, pk, wk, *_ = make_policy(self.active, producer=61001, observer=61002, witness=0)
        registration = dict(
            schema_version="outcome-live-origin-registration/v4",
            mode="live-core",
            **{k: trust.data[k] for k in ("producer_ref", "stream_ref", "producer_public_key")},
            scope_ref="synthetic-scope-" + str(index),
            binary_path=str(phase.g.CORE),
            binary_sha256=self.core_sha,
            launcher_uid=0,
            ai_socket_uid=0,
            capture_apparmor_profile="edge400-capture",
            native_apparmor_profile="edge400-provider",
            environment=phase.plan.native_environment(assignment["arm"]),
        )
        trust = TrustPolicy(
            dict(
                trust.data,
                schema_version="outcome-input-trust/v3",
                scope_ref=registration["scope_ref"],
                source_path=str(bundle / "input"),
                journal_directory=str(bundle / "observer"),
                socket_path=str(bundle / "socket/witness.sock"),
                anchor_directory=str(bundle / "witness/anchors"),
                origin_registration_sha256=reader.sha(_json(registration)),
            )
        )
        input_live.validate_registration(trust, registration)
        self.put(bundle / "trust.json", dict(trust.data))
        self.put(bundle / "origin.json", registration)
        event = decision(candidate)
        event["normalized"]["ts"] = datetime.fromtimestamp(EPOCH + 1.25, timezone.utc).isoformat()
        event["enforcement"]["metadata"]["release_due_epoch"] = EPOCH + 31.25
        ordinary = [("session_prepare", None), ("session_start", None), ("decision_execution", event)]
        if candidate and fault != "release":
            pending = release(event)
            pending["release"].update(
                status="retry_pending", result="synthetic-retry", attempted_at_epoch=EPOCH + 31.25
            )
            ordinary.extend([("release", pending), ("release", release(event))])
        if fault != "end":
            ordinary.append(("session_end", None))
        raw = b""
        verifier = SourceVerifier(trust)
        for seq, (kind, body) in enumerate(ordinary):
            unsigned = json.loads(
                signed_frame(trust, pk, frame(kind, seq, session, body), seq + 1, verifier.head)
            )["event"]
            raw += signed(
                trust, pk, seq=seq + 1, prev=verifier.head, event=unsigned, boot_ref=boot.replace("-", "")
            )
            verifier.verify(raw)
        events = [json.loads(line)["event"] for line in raw.splitlines()]
        source_file = self.put(bundle / "input", raw)
        self.put(phase.WORK / "source-final.raw", raw)
        call_file = self.physical(bundle / "observer/actual-collector-calls.jsonl")
        call_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        policy, outcomes, calls = self.collect(call_file, events, candidate, fault)
        positions = []
        offset = 0
        for line in raw.splitlines(keepends=True):
            offset += len(line)
            positions.append(dict(offset=offset, sha256=reader.sha(raw[:offset])))
        source_info = source_file.stat()
        header = dict(
            schema_version="outcome-observation-journal/v3",
            scope_ref=trust.data["scope_ref"],
            policy_sha256=reader.sha(persistence_context(policy, "es", 0.25).encode()),
            max_identities=4096,
            max_bytes=trust.data["journal_max_bytes"],
            input_config=dict(
                path_sha256=reader.sha(str(bundle / "input").encode()),
                device=source_info.st_dev,
                inode=source_info.st_ino,
                uid=61001,
                max_bytes=trust.data["input_max_bytes"],
                max_records=trust.data["input_max_records"],
                authentication=trust.binding(),
            ),
        )
        rows = [
            ("header", header),
            ("session_open", dict(boot_id=phase.n.boot_reference(boot))),
            ("input_ready", dict(offset=0, sha256=reader.sha(b""))),
            ("session_close", {}),
            ("session_open", dict(boot_id=phase.n.boot_reference(boot))),
        ]
        for number, pos in enumerate(positions):
            rows.append(
                ("cursor", dict(position=pos, missed=events[number]["pipeline"] == "rust_live_origin_v1"))
            )
            if number == 1:
                rows.append(("input_ready", pos))
            if number == 2:
                for outcome in outcomes:
                    meta = {k: getattr(outcome, k) for k in ("decision_id", "execution_id", "objective_id")}
                    meta["boot_id"] = phase.n.boot_reference(boot)
                    rows.extend([("begin", meta), ("commit", dict(meta, outcome=outcome.to_dict()))])
        rows.append(("session_close", {}))
        journal_raw, frames = journal(rows)
        journal_file = self.put(bundle / "observer/observations.journal", journal_raw)
        state = self.anchors(trust, wk, raw, journal_raw, frames, journal_file.stat())
        context = dict(
            kernel_boot_id=boot,
            boot_ref=phase.n.boot_reference(boot),
            signed_boot_ref=boot.replace("-", ""),
            scope_ref=trust.data["scope_ref"],
            registration_sha256=trust.data["origin_registration_sha256"],
            source_start_position=positions[1],
            clock_anchor=anchor(-0.5),
            policy_sha256=recording.manifest_digest(phase.plan.strict(phase.plan.POLICY_PATH.read_bytes())),
            policy_file_sha256=reader.sha(phase.plan.POLICY_PATH.read_bytes()),
        )
        last = raw.splitlines(keepends=True)[-1]
        decoded = SourceVerifier.unwrap(last)
        terminal = dict(
            context=context,
            witness_state=state,
            end_clock_anchor=anchor(33.25),
            terminal=TerminalControlStop(
                trust.data["origin_registration_sha256"],
                session,
                verifier.live_state.seq,
                positions[-2],
                positions[-1],
                last,
                decoded,
                0,
            ).to_dict(),
        )
        self.put(bundle / "observer/observer-terminal-result.json", terminal)
        self.put(bundle / "observer/terminal.wire", last)
        self.put(bundle / "observer/terminal.decoded", decoded)
        if outcomes:
            self.put(
                bundle / "observer/outcomes.jsonl",
                b"".join(
                    _json(
                        dict(
                            schema_version=o.schema_version,
                            outcome=o.to_dict(),
                            collector_mode="passive_g3",
                            effect_assessment=None,
                        )
                    )
                    + b"\n"
                    for o in outcomes
                ),
            )
        self.put(
            phase.WORK / "prepared.json",
            dict(
                inputs=inputs, kernel_boot_id=boot, trust_policy=dict(trust.data), registration=registration
            ),
        )
        origin = NS + (NS // 2 if fault == "window" else 0)
        deadline = origin + 5 * NS
        service_audit = dict(
            kind="audit",
            nonce=run_id,
            started_ns=0,
            origin_ns=origin,
            deadline_ns=deadline,
            ended_ns=deadline,
            goal_ns=None if candidate else origin + 1_650_000_000,
            legitimate_accepted=6,
        )
        client = dict(
            kind="client",
            nonce=run_id,
            ended_ns=deadline,
            objective_attempt_ns=origin + 1_650_000_000,
            objective_attempt_complete=True,
            transactions=[
                dict(id="legitimate-" + str(i), elapsed_seconds=0.201 + i * 0.6, duration_ms=1, error=False)
                for i in range(6)
            ],
        )
        self.put(phase.WORK / "service-audit.json", service_audit)
        self.put(phase.WORK / "client-audit.json", client)
        capture, receipt, binding = service.service_capture(
            self.manifest,
            assignment,
            run_id,
            inputs["safety"],
            origin_ns=origin,
            deadline_ns=deadline,
            client_origin_ns=origin + 1_250_000_000,
            service=service_audit,
            client=client,
            kernel_boot_id=boot,
        )
        record = dict(
            inputs=inputs,
            kernel_boot_id=boot,
            withheld_reasons=[],
            event=events[2],
            release=events[-2]
            if candidate and fault not in ("release", "end")
            else (events[-1] if candidate and fault == "end" else None),
            observer_terminal=terminal,
            closed_call_chain_sha256=reader.sha(call_file.read_bytes()),
            source_sha256=reader.sha(raw),
            source_bytes=len(raw),
            decision_callback_receipt_epoch=EPOCH + 1.25,
            release_callback_receipt_epoch=EPOCH + 32.25 if candidate and fault != "release" else None,
            controller_start_anchor=anchor(-0.1),
            controller_end_anchor=anchor(5.6 if fault == "window" else 5.1),
            origin_ns=origin,
            deadline_ns=deadline,
            client_origin_ns=origin + 1_250_000_000,
            capture=capture,
            service_receipt=receipt,
            service_binding=binding,
            source_identity=run._source_identity(),
        )
        self.probes(record, events[2], candidate, boot, fault)
        if fault == "clock":
            terminal["end_clock_anchor"]["epoch_ns"] += 6_000_000
            self.put(bundle / "observer/observer-terminal-result.json", terminal)
        if fault == "canonical":
            parsed = [json.loads(line) for line in call_file.read_bytes().splitlines()]
            target = next(
                row
                for row in parsed
                if row["kind"] == "event" and row["data"]["event"].get("pipeline") == "rust_release_engine_v1"
            )
            target["data"]["event"]["release"]["command_count"] = 1.0
            previous = ZERO_HASH
            for row in parsed:
                row["prev"] = previous
                row["sha256"] = recording.manifest_digest(
                    {k: row[k] for k in ("seq", "prev", "kind", "data")}
                )
                previous = row["sha256"]
            call_file.write_bytes(b"".join(recording.canonical(row) + b"\n" for row in parsed))
            record["closed_call_chain_sha256"] = reader.sha(call_file.read_bytes())
        self.put(
            phase.WORK / "run-facts.json",
            dict(
                status="run_facts_complete",
                measurement_completed=False,
                production_admission=False,
                record=record,
            ),
        )
        self.put(
            phase.WORK / "systemd-stop-receipt.json",
            dict(
                status="verified_stopped",
                failures=[],
                actors=[
                    dict(
                        unit=unit,
                        stop_returncode=0,
                        after=dict(ActiveState="inactive", MainPID="0", ControlPID="0"),
                    )
                    for unit in phase.scope.ACTOR_UNITS
                ],
            ),
        )
        if fault == "client":
            self.physical(phase.WORK / "client-audit.json").unlink()
        return self.read_result(), outcomes

    def anchors(self, trust, key, source, raw, frames, info):
        anchors = []
        previous = ZERO_HASH
        position = 0
        for seq in range(len(frames) + 1):
            if seq and frames[seq - 1]["kind"] == "cursor":
                position = frames[seq - 1]["data"]["position"]["offset"]
            prefix = b"".join(raw.splitlines(keepends=True)[:seq])
            tip = SourceVerifier(trust).verify(source[:position])
            state = dict(
                journal_seq=seq,
                journal_head=frames[seq - 1]["sha256"] if seq else ZERO_HASH,
                journal_size=len(prefix),
                journal_sha256=reader.sha(prefix),
                journal_device=info.st_dev if seq else 0,
                journal_inode=info.st_ino if seq else 0,
                **{"source_" + k: v for k, v in tip.items()},
            )
            core = dict(
                schema_version="outcome-input-anchor/v1",
                counter=seq + 1,
                prev=previous,
                trust_sha256=trust.digest,
                state=state,
            )
            wire = dict(core, signature=sign(key, ANCHOR_DOMAIN, core))
            anchors.append(wire)
            previous = digest(wire)
        self.put(
            Path(trust.data["anchor_directory"]) / "anchors.journal",
            b"".join(_json(a) + b"\n" for a in anchors),
        )
        return state

    def probes(self, record, event, candidate, boot, fault):
        active = payload(from_rust_event(event).execution.scope)
        foreign = dict(
            rule=dict(
                family="inet",
                table="azazel_edge",
                chain="throttle",
                handle=7,
                comment="synthetic-foreign",
                expr=[{"counter": {"packets": 0, "bytes": 0}}],
            )
        )
        baseline = dict(nftables=[row for row in active["nftables"] if "rule" not in row] + [foreign])
        active["nftables"].append(foreign)
        self.put(
            phase.WORK / "namespace-boot.json",
            dict(kernel_boot_id=boot, names=phase.scope.names(), foreign="synthetic-foreign"),
        )
        for i, name in enumerate(phase.scope.names().values(), 1):
            self.put(phase.WORK / f"namespace-intent-{i}.json", dict(name=name, state="creation_intent"))
            self.put(
                phase.WORK / f"namespace-confirmed-{i}.json",
                dict(name=name, state="confirmed_created", identity=dict(device=1, inode=100 + i)),
            )
        for index, (label, key, t, data) in enumerate(
            (
                ("baseline", "baseline_probe", 0.5, baseline),
                (
                    "active",
                    "active_probe",
                    1.2 if fault == "late_probe" else 1.4,
                    active if candidate else baseline,
                ),
                ("absence", "absence_probe", 32.5, baseline),
            )
        ):

            def stamp(seconds):
                return datetime.fromtimestamp(EPOCH + seconds, timezone.utc).isoformat()

            value = dict(
                argv=list(run.flow.QUERY),
                returncode=0,
                stdout=json.dumps(data),
                stderr="",
                root_uid=0,
                root_pid=200 + index,
                kernel_boot_id=boot,
                netns_inode=101,
                source_identity=record["source_identity"],
                query_started_at=stamp(t),
                query_ended_at=stamp(t + 0.001),
                capture_boundary="actual_root_SubprocessReadOnlyRunner_inside_owned_netns",
                source="live_root_query_recorded_once_for_pure_projection",
            )
            record[key] = value
            self.put(phase.WORK / (label + "-query.json"), value)
            self.put(
                phase.WORK / (label + "-query-launch.json"),
                dict(namespace_identity=dict(device=1, inode=101), pid=200 + index),
            )

    def read_result(self):
        before = {p: p.read_bytes() for p in self.active.rglob("*") if p.is_file()}
        result = reader.read_assignment_artifacts(self.manifest_sha, self.head)
        assert before == {p: p.read_bytes() for p in self.active.rglob("*") if p.is_file()}
        return result


def test_all_four_synthetic_assignments_compose_through_unchanged_measurement(tmp_path, monkeypatch):
    fixture = Fixture(tmp_path, monkeypatch)
    results = []
    for index in range(4):
        result, outcomes = fixture.build(index)
        assert result["status"] == "calculation_available", result["reasons"]
        assert result["live_outcomes"] == [o.to_dict() for o in outcomes]
        assert (
            result["measurement_completed"]
            is result["production_admission"]
            is result["resume_authorized"]
            is False
        )
        assert all(o.causal_support.value == "inconclusive" for o in outcomes)
        results.append(result)
    original_results = recording.canonical(results)
    records = validate_fresh_records(fixture.manifest, results, core_sha256=fixture.core_sha)
    originals = {r["measurement_record"]["assignment_id"]: r["measurement_record"] for r in results}
    assert all(record is originals[record["assignment_id"]] for record in records)
    assert [r["assignment_id"] for r in records] == [a["id"] for a in phase.plan.order(fixture.manifest)]
    assert {r["authenticated_origin"]["session_ref"][0].isdigit() for r in results} == {True, False}
    assert all(
        r["measurement_record"]["linkage"]["session_ref"]
        == "native-session-" + r["authenticated_origin"]["session_ref"]
        for r in results
    )
    report = measure_experiment(fixture.manifest, dict(manifest_sha256=fixture.manifest_sha, records=records))
    assert recording.canonical(results) == original_results
    assert report["integrity_rejections"] == 0
    assert [r["status"] for r in report["ledger"]] == ["qualified"] * 4
    assert report["comparison"]["assigned_runs"] == 4
    assert report["comparison"]["complete_pairs"] == 2
    assert report["comparison"]["measurement_gate"] == "recorded_thresholds_met_requires_independent_review"
    assert report["comparison"]["claim_status"] == "mechanical_only"


@pytest.mark.parametrize(
    "fault", ["release", "end", "late_probe", "coverage", "samples", "window", "clock", "client", "canonical"]
)
def test_independent_composition_gap_preserves_original_facts_and_withholds(tmp_path, monkeypatch, fault):
    fixture = Fixture(tmp_path, monkeypatch)
    result, outcomes = fixture.build(1, fault)
    assert result["independent_service_facts"]["service"]["legitimate_accepted"] == 6
    assert result["live_outcomes"] == [o.to_dict() for o in outcomes]
    if result["measurement_record"] is None:
        assert result["status"] == "withheld" and result["reasons"]
        expected = {
            "end": "terminal original wire",
            "late_probe": "root probe precedes actual callback",
            "coverage": "sample coverage incomplete",
            "clock": "actual clock/horizon qualification withheld",
            "client": "client_audit",
            "canonical": "exact ordered signed callback coverage",
        }
        assert any(expected[fault] in reason for reason in result["reasons"]), result["reasons"]
    else:
        report = measure_experiment(
            fixture.manifest,
            dict(manifest_sha256=fixture.manifest_sha, records=[result["measurement_record"]]),
        )
        row = next(
            row
            for row in report["ledger"]
            if row["assignment_id"] == result["measurement_record"]["assignment_id"]
        )
        expected = {
            "release": "release_absence_not_verified",
            "samples": "telemetry_coverage_incomplete",
            "window": "edge_window_outside_trial_horizon",
        }
        assert row["status"] == "withheld" and expected[fault] in row["reasons"], row


def test_c0_never_waives_full_signed_terminal_even_without_outcome(tmp_path, monkeypatch):
    fixture = Fixture(tmp_path, monkeypatch)
    result, outcomes = fixture.build(0, "end")
    assert outcomes == [] and result["live_outcomes"] == []
    assert result["status"] == "withheld" and result["measurement_record"] is None
    assert any("terminal original wire" in reason for reason in result["reasons"])
    assert result["independent_service_facts"]["service"]["goal_ns"] is not None


def test_one_complete_pair_cannot_substitute_for_registered_four_assignments(tmp_path, monkeypatch):
    fixture = Fixture(tmp_path, monkeypatch)
    results = [fixture.build(i)[0] for i in (0, 1)]
    assert all(result["status"] == "calculation_available" for result in results)
    with pytest.raises(ValueError):
        validate_fresh_records(fixture.manifest, results, core_sha256=fixture.core_sha)
    report = measure_experiment(
        fixture.manifest,
        dict(
            manifest_sha256=fixture.manifest_sha, records=[result["measurement_record"] for result in results]
        ),
    )
    assert report["comparison"]["measurement_gate"] == "inconclusive_missing_or_insufficient_pairs"
    assert report["comparison"]["missing_runs"] == 2
