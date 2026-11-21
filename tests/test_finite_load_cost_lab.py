"""Synthetic lab mechanics and retained-byte checks, never native load evidence."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

REAL = Path(__file__).parent / "real_systemd"
sys.path.insert(0, str(REAL))
import finite_load_cost as lab  # noqa: E402
import finite_load_observer as observer  # noqa: E402


def pins(artifacts):
    return {
        k: lab.accounting.sha256(v) if v is not None else None
        for k, v in artifacts.items()
    }


def test_corpus_has_exact_frozen_spans_and_no_fresh_event_claim():
    raw, manifest = lab.materialize_corpus()
    assert len(raw) < 16 * 1024 * 1024 and raw.count(b"\n") == 27007
    assert manifest["per_class"] == dict.fromkeys(
        ("flow", "dns", "stats", "http"), 6751
    )
    for marker in manifest["markers"]:
        line = raw[marker["start_offset"] : marker["end_offset"]]
        assert lab.accounting.sha256(line) == marker["raw_sha256"]
        assert json.loads(line)["timestamp"] == "2026-01-01T00:00:00Z"
        assert json.loads(line)["alert"]["signature_id"] == marker["sid"]


def synthetic_writer(tmp_path, monkeypatch):
    path = tmp_path / "eve.json"
    path.write_bytes(b"")
    instance = object.__new__(lab.FiniteLoadCostLab)
    instance.corpus, instance.manifest = lab.materialize_corpus()
    instance.eve_path = lambda: path
    context = dict(
        load={},
        ingress=dict(
            writer=[],
            held_fd=dict(
                object=lab.accounting.source_metadata(path.stat(), detailed=True)
            ),
        ),
    )
    clock = SimpleNamespace(ns=1_000_000_000)
    monkeypatch.setattr(lab.time, "monotonic_ns", lambda: clock.ns)

    def sleep(seconds):
        clock.ns += round(seconds * 1e9)

    monkeypatch.setattr(lab.time, "sleep", sleep)
    return instance, context, path


def test_paced_writer_actual_bytes_and_same_ingress_fields(tmp_path, monkeypatch):
    instance, context, path = synthetic_writer(tmp_path, monkeypatch)
    thread, writer, ingress = instance.paced_writer(context)
    thread.join(5)
    assert not thread.is_alive() and writer["error"] is None
    writer.update(joined=True, joined_ns=lab.time.monotonic_ns())
    for key in ingress.keys() & writer.keys():
        ingress[key] = copy.deepcopy(writer[key])
    assert path.read_bytes() == instance.corpus
    assert writer["sha256"] == instance.manifest["sha256"]
    assert writer["nonalert_records"] == 27004
    assert (
        writer["marker_one_before_ns"] - writer["first_write_before_ns"]
        >= 3_000_000_000
    )
    assert (
        writer["final_nonalert_after_ns"] - writer["marker_one_before_ns"]
        >= 6_000_000_000
    )
    assert (
        writer["final_nonalert_after_ns"] - writer["first_write_before_ns"]
        > 9_000_000_000
    )
    assert writer["write_calls"] == 27007 and writer["fsync_completed"] is True
    assert all(writer[k] == ingress[k] for k in writer.keys() & ingress.keys())
    assert ingress["offset_after"] == len(instance.corpus)


def test_paced_writer_retains_actual_prefix_after_write_failure(tmp_path, monkeypatch):
    instance, context, path = synthetic_writer(tmp_path, monkeypatch)
    original = os.write
    calls = []

    def fail_after_first(fd, raw):
        calls.append(len(raw))
        if len(calls) == 2:
            raise OSError("synthetic write failure")
        return original(fd, raw)

    monkeypatch.setattr(lab.os, "write", fail_after_first)
    thread, writer, _ = instance.paced_writer(context)
    thread.join(5)
    assert writer["error"]["type"] == "OSError" and writer["written_bytes"] == 600
    assert writer["nonalert_records"] == 1 and writer[
        "sha256"
    ] == lab.accounting.sha256(path.read_bytes())
    assert (
        writer["fsync_completed"] is False and writer["final_nonalert_after_ns"] is None
    )


def test_root_domain_unavailable_stays_unestablished(monkeypatch):
    monkeypatch.setattr(lab.accounting, "actor", lambda pid: dict(start_ticks=12))
    original = Path.stat

    def deny_namespace(path, *args, **kwargs):
        if str(path).endswith("/ns/time"):
            raise PermissionError("synthetic denial")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", deny_namespace)
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return "12345678-1234-4234-8234-123456789abc"
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    result = lab.root_identity(os.getpid())
    assert (
        result["start_ticks"] == 12 and result["clock_domain"]["established"] is False
    )
    assert result["clock_domain"]["timens_offsets"] is None


def test_new_bound_identity_never_calls_legacy_self_stat(monkeypatch):
    identity = dict(
        pid=os.getpid(), native_tid=observer.threading.get_native_id(), start_ticks=5
    )
    originals = [
        module._identity for module in (observer.phase, observer.clock, observer.normal)
    ]
    with observer.bound_identity(identity):
        assert all(
            module._identity() == identity
            for module in (observer.phase, observer.clock, observer.normal)
        )
    assert [
        module._identity for module in (observer.phase, observer.clock, observer.normal)
    ] == originals


def test_new_phase_initializer_preserves_new_arm_and_old_rejection(
    tmp_path, monkeypatch
):
    identity = dict(
        pid=os.getpid(), native_tid=observer.threading.get_native_id(), start_ticks=5
    )
    metadata = dict(
        run_id="test",
        arm="load-on",
        role="observer",
        input_sha256="a" * 64,
        code_sha256="b" * 64,
        core_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    with observer.bound_identity(identity):
        recording = observer.LoadPhaseRecording(tmp_path / "phase", metadata=metadata)
        assert recording.call("input_snapshot", lambda: 3) == 3
        recording.close(normal_return=True)
        old = observer.phase.PhaseRecording(tmp_path / "legacy", metadata=metadata)
    assert old.incomplete is True and old.fd is None
    raw = (tmp_path / "phase").read_bytes()
    facts = lab._phase_facts(raw, metadata=metadata, identity=identity, complete=True)
    assert facts["complete"] is True and facts["phases"]["input_snapshot"]["count"] == 1
    assert json.loads(raw.splitlines()[0])["data"]["arm"] == "load-on"


def test_phase_original_mutation_and_missing_footer_are_not_complete(tmp_path):
    identity = dict(
        pid=os.getpid(), native_tid=observer.threading.get_native_id(), start_ticks=5
    )
    metadata = dict(
        run_id="test",
        arm="load-faulted",
        role="observer",
        input_sha256="a" * 64,
        code_sha256="b" * 64,
        core_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    with observer.bound_identity(identity):
        recording = observer.LoadPhaseRecording(tmp_path / "phase", metadata=metadata)
        recording.call("input_snapshot", lambda: None)
        recording.close(normal_return=False)
    raw = (tmp_path / "phase").read_bytes()
    assert (
        lab._phase_facts(raw, metadata=metadata, identity=identity, complete=False)[
            "complete"
        ]
        is False
    )
    with pytest.raises(AssertionError):
        lab._phase_facts(raw, metadata=metadata, identity=identity, complete=True)
    with pytest.raises(AssertionError):
        lab._phase_facts(
            raw.replace(b'"seq":2', b'"seq":4'),
            metadata=metadata,
            identity=identity,
            complete=False,
        )


def test_off_verifier_requires_absent_observer_not_fabricated_zero():
    artifacts = dict.fromkeys(lab.FILES)
    artifacts["load-controller.json"] = lab.accounting.canonical(
        dict(case_id="load-off", observer=None)
    )
    assert (
        lab.evaluate_observer_originals(artifacts, pins(artifacts))["status"]
        == "absent"
    )
    artifacts["observer-calls.raw"] = b""
    result = lab.evaluate_observer_originals(artifacts, pins(artifacts))
    assert result["status"] == "withheld" and result["clock"] is None


def test_verifier_cannot_read_stored_evaluation_as_clock_authority():
    artifacts = dict.fromkeys(lab.FILES)
    artifacts["evaluation.json"] = b'{"observer":{"status":"qualified"}}\n'
    result = lab.evaluate_observer_originals(artifacts, pins(artifacts))
    assert result["status"] == "withheld" and result["normal_completion"] is None


def test_wait_retains_original_output_before_systemd_metadata_failure():
    process = object.__new__(lab.ObserverProcess)
    process.process = SimpleNamespace(wait=lambda timeout: None, returncode=1)

    class Drain:
        thread = SimpleNamespace(join=lambda timeout: None)

        def __init__(self, raw):
            self.raw = raw

        def snapshot(self):
            return self.raw, len(self.raw), True, None

    process.drains = {
        "stdout": Drain(b"bootstrap\noriginal output\n"),
        "stderr": Drain(b"original stderr\n"),
    }
    process.bootstrap_raw = b"bootstrap\n"
    process.receipt = dict(drain_errors=[])

    def failed_properties(*names):
        raise OSError("synthetic systemd query failure")

    process.properties = failed_properties
    with pytest.raises(OSError):
        process.wait()
    assert (
        process.stdout == b"bootstrap\noriginal output\n"
        and process.stderr == b"original stderr\n"
    )
    assert process.receipt["runner_returncode"] == 1


def test_ci_new_flavor_and_collector_have_exact_static_public_names():
    spec = importlib.util.spec_from_file_location(
        "load_collector",
        REAL.parents[1] / ".github/scripts/collect_finite_load_cost.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.NAMES == lab.FILES
    assert module.CASES == lab.ARMS
    workflow = (REAL.parents[1] / ".github/workflows/ci.yml").read_text()
    assert "--native-core --finite-load-cost" in workflow
    assert "collect_finite_load_cost.py" in workflow


def complete_observer_fixture():
    """Synthetic original-byte contract; not actual clock or service evidence."""
    from dataclasses import fields
    from azazel_edge.outcome.input_control_stop import ObserverControlStop
    from azazel_edge.outcome.telemetry import (
        OutcomeTelemetryPolicy,
        persistence_context,
    )
    from signed_network_recording import CallRecording
    from tempfile import TemporaryDirectory

    domain = dict(
        time_namespace_device=1,
        time_namespace_inode=2,
        timens_offsets=[
            dict(clock=k, seconds=0, nanoseconds=0) for k in ("monotonic", "boottime")
        ],
        established=True,
    )
    identity = dict(
        pid=123,
        start_ticks=4,
        native_tid=123,
        boot_id="12345678-1234-4234-8234-123456789abc",
        clock_domain=domain,
        clock_ticks_per_second=100,
        clock_resolutions=dict(monotonic=1e-9, process_time=1e-9, thread_time=1e-9),
    )
    actor = dict(
        pid=123,
        ppid=1,
        start_ticks=4,
        uid=61002,
        gid=61002,
        groups=[61002],
        apparmor_label="edge400-observer (enforce)",
        no_new_privs=True,
        cap_eff=0,
        cap_prm=0,
        cap_bnd=0,
        cap_amb=0,
    )
    metadata = dict(
        run_id="synthetic",
        arm="load-on",
        role="observer",
        input_sha256="a" * 64,
        code_sha256="b" * 64,
        core_sha256="c" * 64,
        interpreter_sha256="d" * 64,
    )
    policy_raw = lab.POLICY_PATH.read_bytes()
    policy_value = json.loads(policy_raw)
    policy = OutcomeTelemetryPolicy.from_mapping(
        policy_value, source_ref=str(lab.POLICY_PATH)
    )
    policy_context = dict(
        policy_sha256=lab.accounting.sha256(
            lab.accounting.canonical(policy_value).rstrip(b"\n")
        ),
        policy_source_ref=str(lab.POLICY_PATH),
        policy_ref=policy.policy_ref,
    )
    artifacts = dict.fromkeys(lab.FILES)
    source = b"synthetic authenticated Source prefix\n"
    trust = dict(scope_ref="synthetic-scope")
    artifacts["trust.json"] = lab.accounting.canonical(trust).rstrip(b"\n")
    artifacts["registration.json"] = b"{}"
    config = dict(
        case_id="load-on",
        protocol_sha256=lab.PROTOCOL_SHA256,
        corpus_sha256="a" * 64,
        registration_sha256=lab.accounting.sha256(artifacts["registration.json"]),
        trust_sha256=lab.accounting.sha256(artifacts["trust.json"]),
        metadata=metadata,
        paths=dict(policy=str(lab.POLICY_PATH)),
    )
    artifacts["observer-config.json"] = lab.accounting.canonical(config)

    def anchor(n):
        return dict(monotonic_before_ns=n, epoch_ns=n, monotonic_after_ns=n)

    def chain(schema, rows):
        previous = "0" * 64
        result = []
        for i, (kind, data) in enumerate(rows, 1):
            raw = lab.accounting.canonical(
                dict(schema_version=schema, seq=i, prev=previous, kind=kind, data=data)
            )
            result.append(raw)
            previous = lab.accounting.sha256(raw)
        return b"".join(result)

    phase_data = dict(
        span_id=1,
        parent_id=None,
        phase="input_snapshot",
        event_kind=None,
        event_seq=None,
        operation=None,
        previous_write_cost=None,
    )
    span = dict(
        phase_data,
        start_ns=1_100_000_000,
        end_ns=1_100_000_001,
        process_cpu_start_ns=1,
        process_cpu_end_ns=2,
        thread_cpu_start_ns=1,
        thread_cpu_end_ns=2,
        native_tid=123,
        outcome="returned",
    )
    artifacts["observer-phase.raw"] = chain(
        "edge-phase-timing-record/v1",
        [
            ("header", dict(metadata, **identity)),
            ("intent", phase_data),
            ("span", span),
            ("end", dict(normal_return=True, incomplete=False)),
        ],
    )
    artifacts["observer-context.raw"] = chain(
        "edge-load-clock-context/v1",
        [
            (
                "begin",
                dict(
                    metadata=metadata, identity=identity, anchor=anchor(1_000_000_000)
                ),
            ),
            ("end", dict(normal_return=True, anchor=anchor(1_800_000_000))),
        ],
    )
    with TemporaryDirectory() as directory:
        path = Path(directory) / "calls"
        recording = CallRecording(path, metadata=policy_context)
        recording.append(
            "finalize",
            dict(
                epoch=1.2,
                start_ns=1_200_000_001,
                end_ns=1_200_000_010,
                clock_before=anchor(1_200_000_000),
                clock_after=anchor(1_200_000_011),
                outcomes=[],
            ),
        )
        recording.close(complete=True)
        artifacts["observer-calls.raw"] = path.read_bytes()
    journal = []
    previous = "0" * 64
    for seq, (kind, data) in enumerate(
        (
            ("header", {}),
            (
                "cursor",
                dict(
                    position=dict(
                        offset=len(source), sha256=lab.accounting.sha256(source)
                    ),
                    missed=True,
                ),
            ),
            ("session_close", {}),
        ),
        1,
    ):
        unsigned = dict(seq=seq, prev=previous, kind=kind, data=data)
        digest = lab.accounting.sha256(lab.accounting.canonical(unsigned).rstrip(b"\n"))
        journal.append(lab.accounting.canonical(dict(unsigned, sha256=digest)))
        previous = digest
    artifacts["observer-journal.raw"] = b"".join(journal)
    control = ObserverControlStop(
        scope_ref="synthetic-scope",
        trust_sha256=config["trust_sha256"],
        journal_policy_sha256=lab.accounting.sha256(
            persistence_context(policy, "lo", 0.05).encode()
        ),
        journal_boot_id=identity["boot_id"],
        input_offset=len(source),
        input_sha256=lab.accounting.sha256(source),
        journal_sequence_before=2,
        journal_sequence_after=3,
        journal_head_after=previous,
        journal_bytes_after=len(artifacts["observer-journal.raw"]),
        pending_windows_before=0,
        pending_windows_lost=0,
        committed_outcomes=0,
        lost_before=0,
        lost_after=0,
    ).to_dict()
    assert fields(ObserverControlStop)
    artifacts["observer-completion.json"] = lab.accounting.canonical(
        dict(
            schema_version="edge-observer-normal-stop-completion/v1",
            identity=identity,
            metadata=metadata,
            control_stop=control,
            policy_context=policy_context,
            sidecars={
                k: dict(
                    bytes=len(artifacts[lab.SIDE_FILES[k]]),
                    sha256=lab.accounting.sha256(artifacts[lab.SIDE_FILES[k]]),
                )
                for k in ("phase", "calls", "context")
            },
        )
    )
    artifacts["observer-outcomes.raw"] = b""
    sidecars = {}
    for key, name in lab.SIDE_FILES.items():
        raw = artifacts[name]
        obj = dict(size=len(raw), owner_uid=61002)
        sidecars[key] = dict(
            before=obj, after=obj, sha256=lab.accounting.sha256(raw), size=len(raw)
        )
    artifacts["observer-stdout.raw"] = b"synthetic stdout\n"
    artifacts["observer-stderr.raw"] = b""
    receipt = dict(
        error=None,
        identity=identity,
        actor=actor,
        command_verified=True,
        bootstrap=dict(pid=123, challenge="a" * 32, invocation_id="b" * 32),
        challenge="a" * 32,
        unit_properties=dict(MainPID="123", InvocationID="b" * 32),
        signal_target=actor,
        started_ns=0,
        ready_ns=1,
        stop_requested_ns=2,
        finished_ns=3,
        signal=15,
        runner_returncode=0,
        exit=dict(ExecMainPID="123", ExecMainCode="1", ExecMainStatus="0"),
        sidecars=sidecars,
        stdout_truncated=False,
        stderr_truncated=False,
        stdout_bytes=len(artifacts["observer-stdout.raw"]),
        stderr_bytes=0,
        stdout_eof=True,
        stderr_eof=True,
        drain_errors=[],
        fault_boundary=None,
    )
    controller = dict(
        case_id="load-on",
        observer=receipt,
        protocol_sha256=lab.PROTOCOL_SHA256,
        corpus_sha256="a" * 64,
        controller_identity=identity,
        controller_anchors=dict(
            before=anchor(900_000_000), after=anchor(2_000_000_000)
        ),
    )
    artifacts["load-controller.json"] = lab.accounting.canonical(controller)
    artifacts["close-controller.json"] = lab.accounting.canonical(
        dict(boot_id=identity["boot_id"])
    )
    artifacts["observer-policy.json"] = policy_raw
    artifacts["source-after.raw"] = source
    return artifacts, controller


def test_on_original_verification_and_legitimate_clock_withholding():
    artifacts, controller = complete_observer_fixture()
    result = lab.evaluate_observer_originals(artifacts, pins(artifacts))
    assert result["normal_completion"] is True and result["status"] == "qualified", (
        result
    )
    calls = json.loads(artifacts["observer-calls.raw"].splitlines()[1])
    assert calls["kind"] == "finalize"
    controller["controller_anchors"]["after"]["epoch_ns"] += 6_000_000
    artifacts["load-controller.json"] = lab.accounting.canonical(controller)
    result = lab.evaluate_observer_originals(artifacts, pins(artifacts))
    assert result["normal_completion"] is True and result["status"] == "withheld"
    assert "sampled_offset_envelope_exceeds_budget" in result["clock"]["reasons"]


@pytest.mark.parametrize(
    "kind", ["exit", "domain", "close", "source", "sidecar", "pin"]
)
def test_on_custody_closure_and_original_tampering_withholds(kind):
    artifacts, controller = complete_observer_fixture()
    if kind == "exit":
        controller["observer"]["exit"]["ExecMainStatus"] = "9"
    elif kind == "domain":
        controller["observer"]["identity"]["clock_domain"]["established"] = False
    elif kind == "close":
        completion = json.loads(artifacts["observer-completion.json"])
        completion["control_stop"]["resources_closed"] = False
        artifacts["observer-completion.json"] = lab.accounting.canonical(completion)
    elif kind == "source":
        artifacts["source-after.raw"] = b"changed\n"
    elif kind == "sidecar":
        artifacts["observer-phase.raw"] += b"extra\n"
    artifacts["load-controller.json"] = lab.accounting.canonical(controller)
    expected = pins(artifacts)
    if kind == "pin":
        expected["observer-calls.raw"] = "0" * 64
    result = lab.evaluate_observer_originals(artifacts, expected)
    assert result["status"] == "withheld", result


def test_bounded_drains_keep_original_prefix_and_count_full_stream():
    import threading

    read, write = os.pipe()
    pipe = os.fdopen(read, "rb", buffering=0)
    drain = lab.BoundedDrain(pipe, "stdout")
    raw = b"bootstrap\n" + b"x" * 100000

    def feed():
        view = memoryview(raw)
        while view:
            n = os.write(write, view)
            view = view[n:]
        os.close(write)

    writer = threading.Thread(target=feed)
    writer.start()
    writer.join(5)
    drain.thread.join(5)
    prefix, count, eof, error = drain.snapshot()
    pipe.close()
    assert prefix == raw[:65536] and count == len(raw) and eof is True and error is None
    assert drain.first_line == b"bootstrap\n"


def test_wait_timeout_retains_bounded_prefix_and_eof_before_cleanup():
    import subprocess

    process = object.__new__(lab.ObserverProcess)

    def timeout(timeout):
        raise subprocess.TimeoutExpired("synthetic owned actor", timeout)

    process.process = SimpleNamespace(wait=timeout, returncode=None)

    class Drain:
        def snapshot(self):
            return b"original prefix", 100000, False, None

    process.drains = {"stdout": Drain(), "stderr": Drain()}
    process.receipt = dict(drain_errors=[])
    with pytest.raises(subprocess.TimeoutExpired):
        process.wait()
    assert (
        process.stdout == b"original prefix"
        and process.receipt["stdout_bytes"] == 100000
    )
    assert (
        process.receipt["stdout_eof"] is False
        and process.receipt["stdout_truncated"] is True
    )


def test_phase_partial_tail_and_unclean_footer_keep_verified_spans():
    artifacts, _ = complete_observer_fixture()
    config = json.loads(artifacts["observer-config.json"])
    identity = json.loads(artifacts["load-controller.json"])["observer"]["identity"]
    raw = artifacts["observer-phase.raw"]
    prefix = b"".join(raw.splitlines(keepends=True)[:-1])
    partial = prefix + b'{"schema_version":'
    result = lab._phase_facts(
        partial, metadata=config["metadata"], identity=identity, complete=False
    )
    assert (
        result["complete"] is False
        and result["phases"]["input_snapshot"]["count"] == 1
        and result["partial_tail_bytes"] > 0
    )
    footer = json.loads(raw.splitlines()[-1])
    footer["data"]["normal_return"] = False
    footer["data"]["incomplete"] = True
    result = lab._phase_facts(
        prefix + lab.accounting.canonical(footer),
        metadata=config["metadata"],
        identity=identity,
        complete=False,
    )
    assert (
        result["complete"] is False and result["phases"]["input_snapshot"]["count"] == 1
    )


def fault_boundary_fixture():
    from test_finite_load_cost import fixture
    from azazel_edge.outcome.input_auth import TrustPolicy, SourceVerifier
    from source_witness_data import sign_anchors

    artifacts, c, _, _ = fixture()
    policy = TrustPolicy(json.loads(artifacts["trust.json"]))
    source = artifacts["source-after.raw"]
    selected = []
    for line in source.splitlines(keepends=True):
        selected.append(line)
        if json.loads(line)["event"].get("normalized", {}).get("sid") == 90232001:
            break
    tip = SourceVerifier(policy).verify(b"".join(selected))
    pos = dict(offset=tip["size"], sha256=tip["sha256"])
    journal = []
    previous = "0" * 64
    for seq, (kind, data) in enumerate(
        (("header", {}), ("cursor", dict(position=pos, missed=True))), 1
    ):
        value = dict(seq=seq, prev=previous, kind=kind, data=data)
        previous = lab.accounting.sha256(lab.accounting.canonical(value).rstrip(b"\n"))
        journal.append(lab.accounting.canonical(dict(value, sha256=previous)))
    jraw = b"".join(journal)
    artifacts["observer-journal.raw"] = jraw + b'{"partial":'
    empty = SourceVerifier(policy).tip()
    rows = []
    for count, (st, body) in enumerate(
        ((empty, b""), (empty, journal[0]), (tip, jraw)), 1
    ):
        state = {"source_" + k: v for k, v in st.items()}
        state.update(
            journal_seq=count - 1,
            journal_head="0" * 64
            if count == 1
            else json.loads(body.splitlines()[-1])["sha256"],
            journal_size=len(body),
            journal_sha256=lab.accounting.sha256(body),
            journal_device=0 if count == 1 else 2,
            journal_inode=0 if count == 1 else 3,
        )
        rows.append(
            dict(
                schema_version="outcome-input-anchor/v1",
                counter=count,
                prev="0" * 64,
                trust_sha256=policy.digest,
                state=state,
            )
        )
    anchors = sign_anchors(rows)
    artifacts["observer-fault-anchors.raw"] = anchors
    boundary = dict(
        observed_ns=4_000_000_000,
        source_checkpoint=tip,
        cursor_position=pos,
        journal_checkpoint=dict(size=len(jraw), sha256=lab.accounting.sha256(jraw)),
        witness_sha256=lab.accounting.sha256(anchors),
        witness_boundary=lab.accounting.witness_boundary(anchors),
    )
    controller = dict(
        session_ref=c["session_ref"],
        writer=dict(
            first_write_before_ns=1_000_000_000, marker_one_before_ns=4_000_000_000
        ),
    )
    observer = dict(stop_requested_ns=4_000_000_001, fault_boundary=boundary)
    return artifacts, controller, observer


def test_fault_boundary_reverifies_real_test_key_source_witness_and_journal_prefix():
    artifacts, controller, observer = fault_boundary_fixture()
    lab._verify_fault_boundary(controller, observer, artifacts.__getitem__)


@pytest.mark.parametrize(
    "field", ["late", "cursor", "witness", "journal", "session", "marker"]
)
def test_fault_boundary_rejects_unbound_or_late_progress(field):
    artifacts, controller, observer = fault_boundary_fixture()
    if field == "late":
        observer["stop_requested_ns"] = 7_000_000_000
    elif field == "cursor":
        observer["fault_boundary"]["cursor_position"]["offset"] += 1
    elif field == "witness":
        artifacts["observer-fault-anchors.raw"] += b"bad\n"
    elif field == "journal":
        artifacts["observer-journal.raw"] = b"changed\n"
    elif field == "session":
        controller["session_ref"] = "f" * 32
    else:
        observer["fault_boundary"]["source_checkpoint"]["size"] = len(
            artifacts["source-after.raw"]
        )
    with pytest.raises((AssertionError, ValueError, KeyError)):
        lab._verify_fault_boundary(controller, observer, artifacts.__getitem__)


def test_collector_uses_frozen_per_file_limits():
    spec = importlib.util.spec_from_file_location(
        "load_collector_limits",
        REAL.parents[1] / ".github/scripts/collect_finite_load_cost.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name, limit in {
        "root-custody.raw": 32768,
        "launcher-journal.raw": 65536,
        "unit-exec-start.raw": 131072,
        "native-close.raw": 4096,
        "receiver-close.raw": 4096,
        "observer-context.raw": 16384,
        "observer-calls.raw": 4 * 1024 * 1024,
        "observer-stdout.raw": 65536,
        "observer-stderr.raw": 65536,
        "observer-completion.json": 65536,
        "load-controller.json": 131072,
        "observer-fault-anchors.raw": 8 * 1024 * 1024,
        "eve-held-final.raw": 16 * 1024 * 1024,
    }.items():
        assert module.file_limit(name) == limit


def test_observer_config_refuses_old_observer_owned_location_before_read(monkeypatch):
    def unexpected_read(*args, **kwargs):
        raise AssertionError("legacy location must never reach trusted read")

    monkeypatch.setattr(observer.input_auth, "read_regular", unexpected_read)
    with pytest.raises(ValueError, match="fixed Root config path"):
        observer.load_config(
            Path(
                "/var/lib/edge400-systemd-lab/bundle/observer/load-"
                + "a" * 32
                + "-config.json"
            ),
            "b" * 64,
        )


def test_observer_root_config_keeps_owner_mode_and_pin_guards(monkeypatch):
    path = Path(
        "/opt/edge400-runtime/finite-load-configs/load-" + "a" * 32 + "-config.json"
    )
    raw = lab.accounting.canonical(dict(metadata=dict(run_id="a" * 32)))
    calls = []

    def read(target, **kwargs):
        calls.append((target, kwargs))
        return raw, None

    monkeypatch.setattr(observer.input_auth, "read_regular", read)
    with pytest.raises(ValueError, match="config pin differs"):
        observer.load_config(path, "0" * 64)
    assert calls == [(path, dict(owner=0, mode=0o444, max_bytes=65536))]
    with pytest.raises(ValueError, match="filename/run id differs"):
        observer.load_config(
            path.with_name("load-" + "c" * 32 + "-config.json"),
            lab.accounting.sha256(raw),
        )


def test_authentication_read_still_refuses_other_role_ancestor(tmp_path, monkeypatch):
    from azazel_edge.outcome import input_auth
    from azazel_edge.outcome.journal import OutcomeJournalError

    directory = tmp_path / "observer-owned"
    directory.mkdir(mode=0o700)
    path = directory / "root-config.json"
    path.write_bytes(b"{}\n")
    path.chmod(0o444)
    identity = directory.stat()
    original = os.fstat

    def observed(fd):
        info = original(fd)
        if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
            return SimpleNamespace(st_uid=61002, st_mode=info.st_mode)
        return info

    monkeypatch.setattr(input_auth.os, "fstat", observed)
    with pytest.raises(
        OutcomeJournalError, match="ancestor is writable by another role"
    ):
        input_auth.read_regular(path, owner=os.getuid(), mode=0o444, max_bytes=65536)


def test_all_trusted_observer_parent_walk_components_have_existing_read_grants():
    import fnmatch
    import re

    profile = (
        (REAL / "edge400.apparmor")
        .read_text()
        .split("profile edge400-observer ", 1)[1]
        .split("profile edge400-native ", 1)[0]
    )
    reads = []
    for line in profile.splitlines():
        match = re.fullmatch(r"\s*(/\S*)\s+([a-z]+),\s*", line)
        if match and "r" in match[2]:
            reads.append(match[1])

    def missing(path):
        return [
            str(parent) + "/" if str(parent) != "/" else "/"
            for parent in reversed(Path(path).parents)
            if not any(
                fnmatch.fnmatchcase(
                    str(parent) + "/" if str(parent) != "/" else "/", pattern
                )
                for pattern in reads
            )
        ]

    paths = (
        "/opt/edge400-runtime/finite-load-configs/load-" + "a" * 32 + "-config.json",
        "/var/lib/edge400-systemd-lab/bundle/trust.json",
        "/var/lib/edge400-systemd-lab/bundle/origin.json",
        "/var/lib/edge400-systemd-lab/bundle/observer/load-" + "a" * 32 + "-calls",
        "/var/lib/edge400-systemd-lab/bundle/observer/load-" + "a" * 32 + "-context",
        "/var/lib/edge400-systemd-lab/bundle/observer/load-" + "a" * 32 + "-phase",
    )
    assert all(not missing(path) for path in paths)
    assert "/opt/edge400-src/" in missing(
        "/opt/edge400-src/tests/real_systemd/finite-load-configs/config.json"
    )
    assert '"/proc/self/stat"' not in (REAL / "finite_load_observer.py").read_text()
    assert (
        "/proc/self/timens_offsets"
        not in (REAL / "finite_load_observer.py").read_text()
    )


def test_source_tree_config_is_rejected_before_any_trusted_walk(monkeypatch):
    def unexpected_read(*args, **kwargs):
        raise AssertionError("superseded source path cannot be used")

    monkeypatch.setattr(observer.input_auth, "read_regular", unexpected_read)
    with pytest.raises(ValueError, match="fixed Root config path"):
        observer.load_config(
            "/opt/edge400-src/tests/real_systemd/finite-load-configs/load-"
            + "a" * 32
            + "-config.json",
            "0" * 64,
        )
