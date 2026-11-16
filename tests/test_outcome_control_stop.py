"""SYNTHETIC authentication/telemetry with real bounded descriptors/journal writes."""

from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from azazel_edge.outcome import input_resume as driver
from azazel_edge.outcome import input_witness, input_auth, telemetry
from azazel_edge.outcome.input_cursor import BoundedInput
from azazel_edge.outcome.journal import ObservationJournal, OutcomeJournalError
from azazel_edge.outcome.input_control_stop import ObserverControlStop


class SyntheticSampleSource:
    def sample(self, *, interface, epoch):
        return telemetry.TelemetrySample(epoch=epoch, observed_at="SYNTHETIC", interface=interface,
                                         network={}, system={}, coverage={}, evidence_ref="synthetic")


class Lab:
    def __init__(self, tmp_path, monkeypatch, *, pending=0, sample_hook=None, finalize_hook=None):
        self.input = tmp_path / "input"
        self.input.touch(mode=0o600)
        self.folder = tmp_path / "journal"
        self.folder.mkdir(mode=0o700)
        self.policy_file = tmp_path / "policy"
        self.policy_file.write_text(json.dumps(dict(schema_version=telemetry.POLICY_SCHEMA_VERSION,
                                                    policy_version="synthetic-control", actions={})))
        self.calls = []
        self.ack_fail = False
        self.close_fault = None
        data = dict(schema_version="outcome-input-trust/v3", producer_uid=os.geteuid(),
                    source_path=str(self.input), input_max_bytes=1024 * 1024, input_max_records=8192,
                    journal_directory=str(self.folder), journal_max_bytes=1024 * 1024,
                    scope_ref="synthetic-scope", socket_path=str(tmp_path / "socket"),
                    anchor_directory=str(tmp_path / "anchor"))
        policy = SimpleNamespace(data=data, digest="1" * 64,
                                 binding=lambda: dict(schema_version="outcome-input-auth/v1", trust_sha256="1" * 64))
        auth = object.__new__(input_witness.InputAuthentication)
        auth.policy = policy
        auth.client = SimpleNamespace(state=None)

        def verify(raw):
            self.calls.append("verify")
            if b"INVALID" in raw or raw and not raw.endswith(b"\n"):
                raise OutcomeJournalError("SYNTHETIC invalid/partial Source")

        def advance(seq, head, size):
            self.calls.append("ack")
            if self.ack_fail:
                raise OutcomeJournalError("SYNTHETIC witness loss")
            verify(self.input.read_bytes())
            auth.client.state = dict(journal_seq=seq, journal_head=head, journal_size=size)

        auth.verify, auth.advance = verify, advance
        self.authentication = auth
        monkeypatch.setattr(input_auth.TrustPolicy, "from_file", lambda *a, **k: policy)
        # The driver constructor binding is replaced, while concrete guard types remain original.
        def source_factory(*args, **kwargs):
            source = BoundedInput(*args, **kwargs)
            original_snapshot = source.snapshot

            def snapshot(*args, **kwargs):
                self.calls.append("snapshot")
                return original_snapshot(*args, **kwargs)

            source.snapshot = snapshot
            self.source = source
            return source

        # BoundedInput imports InputAuthentication for its exact type guard.
        # A role-aware constructor facade cannot replace that class globally.
        monkeypatch.setattr(input_witness, "InputAuthentication", type(auth))
        monkeypatch.setattr(type(auth), "__init__", lambda self, supplied: None)
        monkeypatch.setattr(type(auth), "policy", policy, raising=False)
        monkeypatch.setattr(type(auth), "client", auth.client, raising=False)
        monkeypatch.setattr(type(auth), "verify", lambda self, raw: verify(raw))
        monkeypatch.setattr(type(auth), "advance", lambda self, *args: advance(*args))
        monkeypatch.setattr(type(auth), "preflight", lambda self, *args: None)
        # New driver auth instance shares only the explicitly SYNTHETIC client.
        monkeypatch.setattr(driver, "BoundedInput", source_factory)

        def journal_factory(*args, **kwargs):
            journal = ObservationJournal(*args, **kwargs)
            original_close = journal.close

            def close():
                self.calls.append("journal_close")
                if self.close_fault == "skip":
                    return
                if self.close_fault == "write":
                    self.ack_fail = True
                original_close()
                if self.close_fault == "journal_descriptor":
                    raise OSError("SYNTHETIC descriptor close loss")

            journal.close = close
            self.journal = journal
            return journal

        monkeypatch.setattr(driver, "ObservationJournal", journal_factory)
        monkeypatch.setattr(driver, "LinuxProcTelemetrySource", SyntheticSampleSource)
        original_collector = telemetry.OutcomeTelemetryCollector

        class Collector(original_collector):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                for index in range(pending):
                    assert kwargs["persistence"].begin_window(decision_id=f"decision{index}",
                        execution_id=f"execution{index}", objective_id=f"objective{index}")

            def record_sample(self, **kwargs):
                self_outer.calls.append("sample")
                result = super().record_sample(**kwargs)
                if sample_hook:
                    sample_hook(self_outer)
                return result

            def finalize_due(self, **kwargs):
                self_outer.calls.append("finalize")
                result = super().finalize_due(**kwargs)
                if finalize_hook:
                    finalize_hook(self_outer)
                return result

        self_outer = self
        monkeypatch.setattr(driver, "OutcomeTelemetryCollector", Collector)
        monkeypatch.setattr(driver.time, "sleep", lambda seconds: self.calls.append("sleep"))
        self.arguments = dict(input_path=self.input, output_path=tmp_path / "output", policy_path=self.policy_file,
            interface="lo", poll_seconds=0.05, sample_interval_seconds=0.05, max_output_bytes=1024 * 1024,
            journal_directory=self.folder, journal_scope="synthetic-scope", journal_boot_id="synthetic-boot",
            initialize_journal=True, journal_max_bytes=1024 * 1024, journal_max_identities=4096,
            input_max_bytes=1024 * 1024, input_max_records=8192, authentication_policy=tmp_path / "trust")

    def run(self, stop):
        return driver.run_live_resumable(**self.arguments, stop_requested=stop)


def test_preiteration_request_closes_real_resources_and_loses_pending_once(tmp_path, monkeypatch):
    lab = Lab(tmp_path, monkeypatch, pending=2)
    count = []
    receipt = lab.run(lambda: count.append(True) or True)
    assert type(receipt) is ObserverControlStop
    assert count == [True]
    assert receipt.pending_windows_before == receipt.pending_windows_lost == 2
    assert receipt.journal_sequence_after == receipt.journal_sequence_before + 3
    assert not {"sample", "finalize", "sleep"} & set(lab.calls)
    assert lab.source.fd is lab.source.parent is lab.journal._fd is lab.journal._dir is None
    rows = [json.loads(line) for line in (lab.folder / "observations.journal").read_bytes().splitlines()]
    assert [row["kind"] for row in rows].count("lost") == 2
    assert [row["kind"] for row in rows].count("session_close") == 1
    value = receipt.to_dict()
    assert value["input_coverage_complete"] is False
    assert value["source_producer_terminated"] is value["signal_received_time"] is None
    assert value["input_position_before"] == value["input_position_after"]
    assert all(value[key] is False for key in ("authorizes_transition", "experiment", "measurement_completed", "production_admission", "resume_authorized"))
    with pytest.raises(FrozenInstanceError):
        receipt.pending_windows_lost = 0
    value["input_position_before"]["offset"] = 999
    assert receipt.to_dict()["input_position_before"]["offset"] == 0


def test_miditeration_request_finishes_current_callbacks_and_leaves_unread_input(tmp_path, monkeypatch):
    request = {"stop": False}

    def requested_during_sample(lab):
        request["stop"] = True

    def append_unread_after_revalidation(lab):
        with lab.input.open("ab") as stream:
            stream.write(b'{"SYNTHETIC_unread":true}\n')

    lab = Lab(tmp_path, monkeypatch, sample_hook=requested_during_sample,
              finalize_hook=append_unread_after_revalidation)
    checks, snapshots_at_honor = [], []

    def query():
        checks.append(request["stop"])
        if request["stop"]:
            snapshots_at_honor.append(lab.calls.count("snapshot"))
        return request["stop"]

    receipt = lab.run(query)
    assert checks == [False, True]
    assert lab.calls.count("sample") == lab.calls.count("finalize") == lab.calls.count("sleep") == 1
    assert receipt.input_offset == 0
    assert lab.input.read_bytes() == b'{"SYNTHETIC_unread":true}\n'
    # The ordinary iteration retains its snapshots; shutdown adds none.
    assert lab.calls.count("snapshot") == snapshots_at_honor[0]


@pytest.mark.parametrize("value", [None, 1, 0, "yes", [], object()])
def test_nonbool_callback_result_fails_without_control_receipt(tmp_path, monkeypatch, value):
    lab = Lab(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="exact bool"):
        lab.run(lambda: value)
    assert lab.source.fd is lab.journal._fd is None
    assert not {"sample", "finalize"} & set(lab.calls)


def test_raising_callback_preserves_original_exception(tmp_path, monkeypatch):
    lab = Lab(tmp_path, monkeypatch)
    original = RuntimeError("SYNTHETIC request callback")

    def callback():
        raise original

    with pytest.raises(RuntimeError) as caught:
        lab.run(callback)
    assert caught.value is original
    assert lab.source.fd is lab.journal._fd is None


@pytest.mark.parametrize("fault", ["poison", "sealed", "inactive", "recovery", "admission", "write_error"])
def test_unusable_boundary_cannot_quietly_skip_close_and_return_receipt(tmp_path, monkeypatch, fault):
    lab = Lab(tmp_path, monkeypatch)

    def callback():
        if fault == "poison":
            lab.journal._poisoned = True
        elif fault == "sealed":
            lab.journal._sealed = True
        elif fault == "inactive":
            lab.journal._active = False
        elif fault == "recovery":
            lab.journal._recovering = True
        elif fault == "admission":
            lab.journal.counters["capacity_drops"] = 1
        else:
            lab.journal.counters["write_failures"] = 1
        return True

    with pytest.raises(OutcomeJournalError):
        lab.run(callback)


@pytest.mark.parametrize("fault", ["write", "fsync", "witness_ack", "journal_descriptor", "source_descriptor", "bad_source", "partial_source", "stale_ack", "skip"])
def test_close_ack_and_source_errors_never_return_normal_stop(tmp_path, monkeypatch, fault):
    lab = Lab(tmp_path, monkeypatch)

    def callback():
        if fault in ("write", "fsync"):
            from azazel_edge.outcome import journal as module
            original_os = module.os

            class FaultOS:
                def __getattr__(self, name):
                    if name == fault:
                        def fail(*args):
                            raise OSError("SYNTHETIC journal write/sync loss")
                        return fail
                    return getattr(original_os, name)

            monkeypatch.setattr(module, "os", FaultOS())
        elif fault == "witness_ack":
            lab.ack_fail = True
        elif fault in ("journal_descriptor", "skip"):
            lab.close_fault = fault
        elif fault == "source_descriptor":
            original = lab.source.close

            def close():
                original()
                raise OSError("SYNTHETIC source close failure")

            lab.source.close = close
        elif fault in ("bad_source", "partial_source"):
            lab.input.write_bytes(b"INVALID\n" if fault == "bad_source" else b"partial")
        elif fault == "stale_ack":
            lab.source.authentication.advance = lambda *args: None
        return True

    try:
        with pytest.raises((OSError, ValueError)):
            lab.run(callback)
    finally:
        # A deliberately skipped journal close is retained until this unit's explicit cleanup.
        if lab.journal._fd is not None:
            lab.close_fault = None
            lab.journal.close()


@pytest.mark.parametrize("updates", [dict(authentication_policy=None), dict(stop_requested=True), dict(terminal_stop_registration=Path("v4"))])
def test_optin_combination_refusals_precede_resource_open(tmp_path, monkeypatch, updates):
    lab = Lab(tmp_path, monkeypatch)
    arguments = dict(lab.arguments, stop_requested=lambda: True)
    arguments.update(updates)
    with pytest.raises(ValueError):
        driver.run_live_resumable(**arguments)
    assert not hasattr(lab, "source")


def test_forwarder_rejects_nonresumable_or_unauthenticated_control(tmp_path, monkeypatch):
    base = dict(input_path=tmp_path / "input", output_path=tmp_path / "output",
                policy_path=tmp_path / "policy", interface="lo", stop_requested=lambda: True)
    for updates in ({}, dict(resume_input=True), dict(authentication_policy=tmp_path / "trust")):
        with pytest.raises(ValueError, match="authenticated resumable"):
            telemetry.run_live(**base, **updates)


def test_forwarder_preserves_default_kwargs_and_explicit_actual_return(tmp_path, monkeypatch):
    calls = []
    result = object()
    monkeypatch.setattr(driver, "run_live_resumable", lambda **kwargs: calls.append(kwargs) or result)
    base = dict(input_path=tmp_path / "input", output_path=tmp_path / "output", policy_path=tmp_path / "policy",
                interface="lo", resume_input=True, authentication_policy=tmp_path / "trust")
    assert telemetry.run_live(**base) is result
    assert "stop_requested" not in calls[-1]
    def callback():
        return True

    assert telemetry.run_live(**base, stop_requested=callback) is result
    assert calls[-1]["stop_requested"] is callback


def test_structural_receipt_validation_refuses_bool_counter(tmp_path, monkeypatch):
    receipt = Lab(tmp_path, monkeypatch).run(lambda: True)
    with pytest.raises(OutcomeJournalError):
        replace(receipt, journal_sequence_after=True).validate()
