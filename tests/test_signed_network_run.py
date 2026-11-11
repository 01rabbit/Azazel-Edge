"""Synthetic signed-source and mocked manual-run fault tests; no kernel/VM proof."""

import copy
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError
from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from test_outcome_live_origin import enrolled, frame, signed_frame
from test_outcome_input_auth import signed
from test_outcome_nft_flow_evidence import event as flow_event, payload
from test_signed_network_recording import POLICY

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_run as run

KERNEL = "7be45004-1731-4b7c-8e62-59a5ddf129a4"


def decision(candidate=True):
    event = flow_event()
    event["source"] = "suricata_eve"
    event["enforcement_status"] = dict(
        enforce_enabled=candidate, dry_run=False, high_impact_auto=True
    )
    if not candidate:
        event["enforcement"].update(
            mode="disabled", result="no_disruptive_action", executed_count=0
        )
    return event


def release(event):
    m = event["enforcement"]["metadata"]
    return dict(
        pipeline="rust_release_engine_v1",
        source="release_ledger",
        enforcement_status=event["enforcement_status"],
        release=dict(
            release_task_id=m["release_task_id"],
            trace_id=event["enforcement"]["trace_id"],
            action="throttle",
            resource_key=m["release_resource_key"],
            owner_token=m["release_owner_token"],
            tc_handle="",
            due_epoch=m["release_due_epoch"],
            attempted_at_epoch=m["release_due_epoch"] + 1,
            status="released",
            result="rollback_applied_and_absence_verified",
            command_count=1,
            failed_count=0,
            errors=[],
            postcondition=dict(verified=True, owned_state_present=False),
        ),
    )


def signed_source_fixture(tmp_path, monkeypatch, candidate=True):
    trust, key = enrolled(tmp_path)
    state = {"raw": b"", "inode": 2}
    v = SourceVerifier(trust)

    def append(kind, seq, event=None, session="a" * 32, boot=KERNEL.replace("-", "")):
        native = frame(kind, seq, session, event)
        unsigned_event = json.loads(
            signed_frame(trust, key, native, v.seq + 1, v.head)
        )["event"]
        state["raw"] += signed(
            trust, key, seq=v.seq + 1, prev=v.head, event=unsigned_event, boot_ref=boot
        )
        v.verify(state["raw"])

    append("session_prepare", 0)
    append("session_start", 1)
    monkeypatch.setattr(
        run,
        "read_regular",
        lambda *a, **k: (
            state["raw"],
            SimpleNamespace(st_dev=1, st_ino=state["inode"]),
        ),
    )
    return run.SignedSource(trust, KERNEL, candidate), state, append


def test_complete_signed_release_and_terminal_preserve_original_source(
    tmp_path, monkeypatch
):
    reader, state, append = signed_source_fixture(tmp_path, monkeypatch)
    assert len(reader.poll()) == 2
    event = decision()
    append("decision_execution", 2, event)
    append("release", 3, release(event))
    append("session_end", 4)
    original = state["raw"]
    assert len(reader.poll(terminal=True)) == 5 and reader.raw == original
    assert state["raw"] == original


def test_incomplete_tail_only_is_not_ready_and_is_preserved(tmp_path, monkeypatch):
    reader, state, _ = signed_source_fixture(tmp_path, monkeypatch)
    assert len(reader.poll()) == 2
    state["raw"] += b'{"unfinished"'
    assert len(reader.poll()) == 2 and reader.raw.endswith(b'{"unfinished"')
    with pytest.raises(BenefitInputError):
        reader.poll(terminal=True)


@pytest.mark.parametrize(
    "fault",
    [
        "signature",
        "identity",
        "boot",
        "decision_tuple",
        "release_owner",
        "premature_terminal",
        "extra_decision",
    ],
)
def test_complete_mismatch_refuses_immediately_without_source_repair(
    tmp_path, monkeypatch, fault
):
    reader, state, append = signed_source_fixture(tmp_path, monkeypatch)
    reader.poll()
    event = decision()
    if fault == "signature":
        state["raw"] = state["raw"].replace(b'"signature":"', b'"signature":"0', 1)
    elif fault == "identity":
        state["inode"] = 3
    elif fault == "boot":
        append("decision_execution", 2, event, boot="b" * 32)
    elif fault == "decision_tuple":
        event["normalized"]["target_port"] = 999
        append("decision_execution", 2, event)
    elif fault == "release_owner":
        append("decision_execution", 2, event)
        r = release(event)
        r["release"]["owner_token"] = "azazel-edge:release-" + "f" * 16
        append("release", 3, r)
    elif fault == "premature_terminal":
        append("session_end", 2)
    else:
        append("decision_execution", 2, event)
        append("decision_execution", 3, event)
    before = state["raw"]
    with pytest.raises((OSError, BenefitInputError, ValueError)):
        reader.poll()
    assert state["raw"] == before


def test_c0_retains_native_disabled_unverified_fact():
    event = decision(False)
    before = copy.deepcopy(event)
    assert run._decision([event], False) == event
    assert run.from_rust_event(event).execution.status.value == "unverified"
    assert event == before
    with pytest.raises(BenefitInputError):
        run._decision([decision(True)], False)


def test_closed_callback_requires_exact_original_event_not_just_task_or_epoch():
    event = decision()
    data = dict(event=event, epoch=101.125, accepted=False)
    result = run._closed_callback(dict(calls=[dict(kind="event", data=data)]), event)
    assert result is data and result["epoch"] == 101.125
    changed = copy.deepcopy(event)
    changed["enforcement"]["failed_count"] = 1
    assert (
        run._closed_callback(dict(calls=[dict(kind="event", data=data)]), changed)
        is None
    )
    assert (
        run._closed_callback(dict(calls=[dict(kind="event", data=data)] * 2), event)
        is None
    )


class Clock:
    def __init__(self):
        self.ns = 1_000_000_000
        self.deadline = None

    def monotonic_ns(self):
        return self.ns

    def monotonic(self):
        return self.ns / 1e9

    def sleep(self, seconds):
        self.ns += int(seconds * 1e9)


def run_fixture(
    tmp_path,
    monkeypatch,
    candidate=True,
    missing_release_callback=False,
    readiness_failure=False,
    persist_failure=False,
):
    clock = Clock()
    monkeypatch.setattr(run, "time", clock)
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    base = tmp_path / "base"
    base.mkdir()
    eve = base / "eve.json"
    eve.touch()
    monkeypatch.setattr(run.phase, "WORK", work)
    monkeypatch.setattr(run.g, "BASE", base)
    monkeypatch.setattr(run.g, "guard", lambda: None)
    monkeypatch.setattr(run.g, "boot", lambda: KERNEL)
    trust, _ = enrolled(tmp_path)
    trust = TrustPolicy(
        {
            **dict(trust.data),
            "producer_uid": 61001,
            "observer_uid": 61002,
            "witness_uid": 0,
        }
    )
    directory = Path(trust.data["journal_directory"])
    directory.mkdir(mode=0o700)
    manifest, safety = run.plan.planned("a" * 40, "b" * 64)
    assignment = manifest["assignments"][1 if candidate else 0]
    inputs = dict(
        manifest=manifest,
        assignment=assignment,
        ticket=dict(run_id="run-fresh"),
        safety=safety[assignment["id"]],
    )
    prepared = dict(
        inputs=inputs,
        kernel_boot_id=KERNEL,
        trust_policy=dict(trust.data),
        registration={"actual": "v4"},
        native_pid=123,
    )
    log = []
    event = decision(candidate)
    released = release(event)
    initial = [dict(pipeline="rust_live_origin_v1")] * 2

    class Reader:
        instance = None

        def __init__(self, *a):
            self.raw = b"prefix"
            self.events = initial[:]
            self.verifier = SimpleNamespace(raw=self.raw)
            self.terminal = False
            Reader.instance = self

        def poll(self, *, terminal=False):
            self.events = initial[:]
            if (work / "eve-transcript.raw").exists():
                self.events.append(event)
            if candidate and clock.ns >= 32_250_000_000:
                self.events.append(released)
            if terminal:
                self.events.append(dict(pipeline="rust_live_origin_v1"))
                self.terminal = True
            self.raw = (
                b"final-source"
                if terminal
                else b"prefix"
                if len(self.events) == 2
                else b"live-source"
            )
            self.verifier.raw = self.raw
            return self.events

    monkeypatch.setattr(run, "SignedSource", Reader)

    class Stdin:
        def write(self, raw):
            clock.deadline = json.loads(raw)["deadline_ns"]
            return len(raw)

        def flush(self):
            pass

    class Process:
        def __init__(self, kind, args):
            self.kind = kind
            self.args = args
            self.stdin = Stdin()
            self.returncode = None

        def poll(self):
            return None

        def wait(self, timeout):
            if self.kind == "observer":
                log.append("natural-terminal-wait")
                self.returncode = 0
            return 0

        def kill(self):
            log.append("kill-owned-client")

    class Assets:
        def __init__(self):
            self.work = work
            self.created = {run.p.EDGE: (None, 1, 2)}
            self.foreign = "foreign-1234abcd"

        def spawn(self, kind, args, **kwargs):
            log.append("spawn-" + kind)
            return Process(kind, list(map(str, args)))

    assets = Assets()
    proof = dict(root_before={})
    monkeypatch.setattr(run.scope, "reopen_assets", lambda work: (assets, proof))
    monkeypatch.setattr(
        run.scope,
        "close_namespaces_after_actors",
        lambda *a: log.append("all-actors-stop-and-fenced-delete"),
    )
    monkeypatch.setattr(run.phase, "validated_inputs", lambda *a: inputs)
    monkeypatch.setattr(
        run.phase,
        "_read",
        lambda path, maximum=8 * 1024 * 1024: Path(path).read_bytes(),
    )
    monkeypatch.setattr(run.TrustPolicy, "from_file", lambda *a, **k: trust)
    monkeypatch.setattr(run, "registration", lambda *a: prepared["registration"])
    monkeypatch.setattr(run.p, "identity", lambda: 123)
    monkeypatch.setattr(run, "_source_identity", lambda: {"reviewed": "source"})
    monkeypatch.setattr(
        run.observer,
        "effective_observer",
        lambda identity: (log.append("effective-role") or dict(identity=identity)),
    )
    monkeypatch.setattr(
        run.subprocess,
        "Popen",
        lambda args, **kwargs: (
            log.append("observer-start") or Process("observer", args)
        ),
    )
    monkeypatch.setattr(
        run.service,
        "record_clock_anchor",
        lambda: dict(
            monotonic_before_ns=clock.ns,
            epoch_ns=clock.ns + 100_000_000_000,
            monotonic_after_ns=clock.ns,
        ),
    )
    native = run.from_rust_event(event)
    active = payload(native.execution.scope)
    base_payload = dict(
        nftables=[row for row in active["nftables"] if "rule" not in row]
    )

    foreign = dict(
        rule=dict(
            family="inet",
            table="azazel_edge",
            chain="throttle",
            handle=999,
            comment=assets.foreign,
            expr=[],
        )
    )
    base_payload["nftables"].append(foreign)
    active["nftables"].append(copy.deepcopy(foreign))

    def query(a, label, *pins):
        log.append("root-readonly-" + label)
        return dict(
            label=label
        ), active if label == "active" and candidate else base_payload

    monkeypatch.setattr(run, "root_query", query)
    counts = {}

    def receive(process):
        counts[process.kind] = counts.get(process.kind, 0) + 1
        if process.kind == "service" and counts[process.kind] == 1:
            return dict(kind="ready", nonce="run-fresh")
        origin = clock.deadline - 5_000_000_000
        if process.kind == "service":
            return dict(
                kind="audit",
                nonce="run-fresh",
                started_ns=1,
                origin_ns=origin,
                deadline_ns=clock.deadline,
                ended_ns=clock.deadline,
                goal_ns=None,
                legitimate_accepted=6,
            )
        return dict(
            kind="client",
            nonce="run-fresh",
            ended_ns=clock.deadline,
            objective_attempt_ns=origin + 1_650_000_000,
            objective_attempt_complete=True,
            transactions=[
                dict(
                    id="legitimate-" + str(i),
                    elapsed_seconds=0.3 + i * 0.6,
                    duration_ms=1,
                    error=False,
                )
                for i in range(6)
            ],
        )

    monkeypatch.setattr(run.n, "receive", receive)

    def stop(*args, **kwargs):
        log.append("capture-core-stop")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(run.n, "command", stop)
    before = dict(offset=len(b"prefix"), sha256=hashlib.sha256(b"prefix").hexdigest())

    def json_artifact(path, *a, **k):
        if Path(path).name == "prepared.json":
            return prepared
        context = dict(
            source_start_position=before,
            kernel_boot_id=KERNEL,
            scope_ref=trust.data["scope_ref"],
            registration_sha256=trust.data["origin_registration_sha256"],
        )
        if Path(path).name == "observer-start-context.json":
            return context
        position = dict(
            offset=len(Reader.instance.raw),
            sha256=hashlib.sha256(Reader.instance.raw).hexdigest(),
        )
        return dict(
            context=context,
            terminal=dict(
                disposition="verified_terminal_control_stop",
                source_position_after=position,
                cursor_missed=True,
                measurement_completed=False,
                resume_authorized=False,
                pending_windows_lost=0,
            ),
            witness_state=dict(journal_head="a" * 64, source_sha256=position["sha256"]),
        )

    monkeypatch.setattr(run, "_json", json_artifact)

    def frames(raw):
        position = dict(
            offset=len(Reader.instance.raw),
            sha256=hashlib.sha256(Reader.instance.raw).hexdigest(),
        )
        return [
            dict(kind="cursor", data=dict(position=position, missed=True)),
            dict(kind="session_close", sha256="a" * 64),
        ]

    monkeypatch.setattr(run.lab, "journal_frames", frames)
    monkeypatch.setattr(run.lab, "ready_for", lambda *a: not readiness_failure)
    call_path = directory / "actual-collector-calls.jsonl"
    sink = run.recording.CallRecording(
        call_path,
        metadata=dict(
            policy_sha256=run.n.manifest_digest(POLICY),
            policy_source_ref="synthetic",
            policy_ref="synthetic",
        ),
    )
    events = [event] + (
        [released] if candidate and not missing_release_callback else []
    )
    for index, e in enumerate(events):
        x = 10 + index * 10

        def anchor(ns):
            return dict(
                monotonic_before_ns=ns,
                monotonic_after_ns=ns,
                epoch_ns=100_000_000_000 + ns,
            )

        sink.append(
            "event",
            dict(
                epoch=100.0 + index,
                start_ns=x,
                end_ns=x + 1,
                clock_before=anchor(x - 1),
                clock_after=anchor(x + 2),
                event=e,
                accepted=False,
            ),
        )
    sink.close(complete=True)
    monkeypatch.setattr(
        run,
        "read_regular",
        lambda path, **k: (
            call_path.read_bytes() if Path(path) == call_path else b"journal\n",
            None,
        ),
    )
    original_save = run.lab.save
    if persist_failure:

        def save(path, raw):
            if Path(path).name == "failure-source-observation.raw":
                raise OSError("disk unavailable")
            original_save(path, raw)

        monkeypatch.setattr(run.lab, "save", save)
    return log, work, clock, Reader, event, released


@pytest.mark.parametrize(
    "candidate,missing", [(False, False), (True, False), (True, True)]
)
def test_manual_run_order_and_closed_release_callback_withholding(
    tmp_path, monkeypatch, candidate, missing
):
    log, work, _, _, event, released = run_fixture(
        tmp_path, monkeypatch, candidate, missing
    )
    result = run.run_assignment("a" * 64, "b" * 64)
    assert result["status"] == ("withheld" if missing else "run_facts_complete")
    assert (
        result["measurement_completed"] is False
        and result["production_admission"] is False
    )
    assert (
        log.index("spawn-service")
        < log.index("observer-start")
        < log.index("effective-role")
        < log.index("spawn-client")
        < log.index("root-readonly-active")
    )
    assert (
        log.index("capture-core-stop")
        < log.index("natural-terminal-wait")
        < log.index("all-actors-stop-and-fenced-delete")
    )
    assert (work / "run-facts.json").exists()
    assert result["record"]["event"] == event
    assert result["record"]["decision_callback_receipt_epoch"] == 100.0
    assert result["record"]["release_callback_receipt_epoch"] == (
        101.0 if candidate and not missing else None
    )
    if candidate:
        assert result["record"]["release"] == released
    assert result["record"]["withheld_reasons"] == (
        ["actual_release_callback_missing"] if missing else []
    )
    assert (
        result["record"]["controller_start_anchor"]
        and result["record"]["controller_end_anchor"]
    )


def test_readiness_failure_and_persistence_error_never_skip_actor_cleanup(
    tmp_path, monkeypatch
):
    log, work, _, _, _, _ = run_fixture(
        tmp_path, monkeypatch, readiness_failure=True, persist_failure=True
    )
    with pytest.raises(BenefitInputError, match="readiness") as failure:
        run.run_assignment("a" * 64, "b" * 64)
    assert "all-actors-stop-and-fenced-delete" in log
    assert any("persistence gap" in note for note in failure.value.__notes__)
    assert not (work / "run-facts.json").exists()


def test_existing_intent_never_stops_or_cleans_other_started_run(tmp_path, monkeypatch):
    log, work, _, _, _, _ = run_fixture(tmp_path, monkeypatch)
    (work / "run-intent.json").write_bytes(b"original started run")
    with pytest.raises(FileExistsError):
        run.run_assignment("a" * 64, "b" * 64)
    assert (
        "all-actors-stop-and-fenced-delete" not in log and "observer-start" not in log
    )
    assert (work / "run-intent.json").read_bytes() == b"original started run"


def test_callback_does_not_treat_bool_and_number_metadata_as_exact_same_event():
    original = decision()
    original["enforcement"]["metadata"]["extra_flag"] = 1
    recorded = copy.deepcopy(original)
    recorded["enforcement"]["metadata"]["extra_flag"] = True
    assert recorded == original  # Python mapping equality is too weak here.
    assert (
        run._closed_callback(
            dict(calls=[dict(kind="event", data=dict(event=recorded, epoch=1.0))]),
            original,
        )
        is None
    )


def test_terminal_origin_mismatch_prevents_facts_success_but_still_cleans(
    tmp_path, monkeypatch
):
    log, work, _, _, _, _ = run_fixture(tmp_path, monkeypatch)
    original = run._json

    def read(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if Path(path).name == "observer-terminal-result.json":
            value["terminal"]["source_position_after"]["sha256"] = "0" * 64
        return value

    monkeypatch.setattr(run, "_json", read)
    with pytest.raises(BenefitInputError, match="terminal control"):
        run.run_assignment("a" * 64, "b" * 64)
    assert (
        "all-actors-stop-and-fenced-delete" in log
        and not (work / "run-facts.json").exists()
    )


def test_cleanup_gap_never_publishes_success(tmp_path, monkeypatch):
    _, work, _, _, _, _ = run_fixture(tmp_path, monkeypatch, candidate=False)

    def fail(*args):
        raise BenefitInputError("actor not stopped")

    monkeypatch.setattr(run.scope, "close_namespaces_after_actors", fail)
    with pytest.raises(BenefitInputError, match="not stopped"):
        run.run_assignment("a" * 64, "b" * 64)
    assert not (work / "run-facts.json").exists()


def test_client_reap_and_all_log_closes_continue_after_cleanup_exception(
    tmp_path, monkeypatch
):
    log, _, _, _, _, _ = run_fixture(tmp_path, monkeypatch, candidate=False)

    def fail(*args):
        raise OSError("stop unavailable")

    monkeypatch.setattr(run.scope, "close_namespaces_after_actors", fail)
    with pytest.raises(OSError):
        run.run_assignment("a" * 64, "b" * 64)
    # One wait drains the terminal; the second always reaps the owned client
    # after the cleanup error instead of skipping it on the exception path.
    assert log.count("natural-terminal-wait") == 2


def test_disk_error_on_first_log_close_still_closes_remaining_logs(
    tmp_path, monkeypatch
):
    _, _, _, _, _, _ = run_fixture(tmp_path, monkeypatch, candidate=False)
    real = Path.open
    closed = []

    class Log:
        def __init__(self, file, name):
            self.file = file
            self.name = name

        def fileno(self):
            return self.file.fileno()

        def close(self):
            self.file.close()
            closed.append(self.name)
            if self.name == "observer.stdout":
                raise OSError("close unavailable")

    def opened(path, *args, **kwargs):
        file = real(path, *args, **kwargs)
        return (
            Log(file, path.name)
            if path.name in ("observer.stdout", "observer.stderr")
            and args
            and args[0] == "xb"
            else file
        )

    monkeypatch.setattr(Path, "open", opened)
    with pytest.raises(OSError):
        run.run_assignment("a" * 64, "b" * 64)
    assert closed == ["observer.stdout", "observer.stderr"]


@pytest.mark.parametrize("fault", [None, "bool_root", "wrong_pid", "partial"])
def test_root_query_retains_raw_envelope_and_refuses_identity_or_partial_failure(
    tmp_path, monkeypatch, fault
):
    import os

    monkeypatch.setattr(run.phase, "WORK", tmp_path)
    identity = dict(
        source_revision="a" * 40, helper_sha256="b" * 64, network_driver_sha256="c" * 64
    )
    monkeypatch.setattr(run, "_source_identity", lambda: identity)
    monkeypatch.setattr(run.g, "boot", lambda: KERNEL)
    receipt = dict(
        root_pid=123,
        root_uid=0,
        argv=list(run.flow.QUERY),
        returncode=0,
        source_identity=identity,
        kernel_boot_id=KERNEL,
        netns_inode=2,
        stdout='{"nftables":[]}',
        stderr="",
    )
    if fault == "bool_root":
        receipt["root_uid"] = False
    elif fault == "wrong_pid":
        receipt["root_pid"] = 999
    raw = json.dumps(receipt).encode() + b"\n"
    if fault == "partial":
        raw = raw[:-1]
    read, write = os.pipe()
    os.write(write, raw)
    os.close(write)
    stream = os.fdopen(read, "rb")
    child = SimpleNamespace(
        pid=123,
        args=["fixed root query"],
        stdout=stream,
        returncode=0,
        wait=lambda **k: 0,
    )
    assets = SimpleNamespace(
        created={run.p.EDGE: (None, 1, 2)}, spawn=lambda *a, **k: child
    )
    try:
        if fault is None:
            assert run.root_query(assets, "sample", "a" * 64, "b" * 64)[0] == receipt
        else:
            with pytest.raises(BenefitInputError):
                run.root_query(assets, "sample", "a" * 64, "b" * 64)
    finally:
        stream.close()
    assert (tmp_path / "sample-query.raw").read_bytes() == raw


@pytest.mark.parametrize("fault", ["action", "result", "failed"])
def test_complete_release_semantics_cannot_be_promoted_by_matching_marker(fault):
    event = decision()
    r = release(event)
    if fault == "action":
        r["release"]["action"] = "isolate"
    elif fault == "result":
        r["release"]["result"] = "command-returned-zero"
    else:
        r["release"]["failed_count"] = 1
    with pytest.raises(BenefitInputError):
        run._released([r], event)
