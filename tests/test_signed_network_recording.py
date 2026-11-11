"""Hardware-free real collector recording tests; synthetic data, no VM claim."""

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from azazel_edge.benchmark.benefit import BenefitInputError
from azazel_edge.outcome import input_resume
from azazel_edge.outcome.telemetry import (
    OutcomeTelemetryCollector,
    OutcomeTelemetryPolicy,
    TelemetrySample,
)
from test_outcome_nft_flow_evidence import event

SPEC = importlib.util.spec_from_file_location(
    "signed_network_recording",
    Path(__file__).parent / "real_systemd/signed_network_recording.py",
)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)
POLICY = json.loads(
    (Path(__file__).parent / "fixtures/signed_network_observer_policy.json").read_text()
)


class Source:
    def sample(self, *, interface, epoch):
        return TelemetrySample(
            epoch=epoch,
            observed_at=datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
            interface=interface,
            network={"rx_bytes": int(epoch * 1024)},
            system={"load_1m": 0.1},
            coverage={
                k: True
                for k in ("proc_net_dev", "proc_loadavg", "proc_meminfo", "proc_uptime")
            },
            evidence_ref="actual-test-sample",
        )


def collect(path):
    with r.record_collector(path, policy=POLICY, policy_source_ref="inline"):
        collector = input_resume.OutcomeTelemetryCollector(
            source=Source(),
            policy=OutcomeTelemetryPolicy.from_mapping(POLICY),
            interface="es",
            sample_interval_seconds=0.25,
        )
        for epoch in (99, 99.25, 99.5, 99.75, 100):
            collector.record_sample(epoch=epoch)
        original = event()
        collector.observe_event(original, observed_epoch=100)
        for epoch in (100.25, 100.5, 100.75, 101, 101.25, 101.5, 101.75, 102):
            collector.record_sample(epoch=epoch)
        outcomes = collector.finalize_due(epoch=102)
    return original, outcomes


def test_records_original_calls_and_live_outcome_without_extra_sampling(tmp_path):
    path = tmp_path / "calls"
    original, outcomes = collect(path)
    recorded = r.read_calls(path)
    rows = recorded["calls"]
    assert len(rows) == 15
    assert (
        next(row["data"]["event"] for row in rows if row["kind"] == "event") == original
    )
    projection = r.replay_calls(recorded, policy=POLICY, boot="kernel-test")
    assert projection["live_outcomes"] == [o.to_dict() for o in outcomes]
    replay_outcome = projection["plain_replay"]["decisions"][0]["stages"]["outcome"]
    assert replay_outcome["outcome_id"] == outcomes[0].outcome_id
    assert projection["comparison"] == "equal_except_explicit_policy_source_ref"
    assert projection["live_policy_ref"] != projection["replay_policy_ref"]
    assert (
        projection["live_outcomes"][0]["telemetry_coverage"]["policy_ref"]
        == projection["live_policy_ref"]
    )
    assert projection["root_augmented_replay"] is None
    assert projection["production_origin_admitted"] is False
    assert input_resume.OutcomeTelemetryCollector is OutcomeTelemetryCollector


def test_exception_restores_class_retains_unfinished_record(tmp_path):
    path = tmp_path / "calls"
    with pytest.raises(RuntimeError):
        with r.record_collector(path, policy=POLICY, policy_source_ref="inline"):
            raise RuntimeError("observer failed")
    assert path.exists()
    assert input_resume.OutcomeTelemetryCollector is OutcomeTelemetryCollector
    with pytest.raises(BenefitInputError, match="unfinished"):
        r.read_calls(path)


def test_rejects_existing_file_and_symlink(tmp_path):
    path = tmp_path / "calls"
    collect(path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        with r.record_collector(path, policy=POLICY, policy_source_ref="inline"):
            pass
    assert path.read_bytes() == before
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        r.read_calls(link)


def test_write_failure_restores_class(tmp_path):
    with patch.object(r.os, "write", side_effect=OSError("storage unavailable")):
        with pytest.raises(OSError):
            with r.record_collector(
                tmp_path / "calls", policy=POLICY, policy_source_ref="inline"
            ):
                pass
    assert input_resume.OutcomeTelemetryCollector is OutcomeTelemetryCollector


@pytest.mark.parametrize(
    "mutation", ["incomplete", "duplicate", "nan", "digest", "trailing", "oversized"]
)
def test_strict_raw_recording(tmp_path, mutation):
    path = tmp_path / "calls"
    collect(path)
    raw = path.read_bytes()
    if mutation == "incomplete":
        raw = b"\n".join(raw.splitlines()[:-1]) + b"\n"
    elif mutation == "duplicate":
        raw = raw.replace(b'"seq":0', b'"seq":0,"seq":0', 1)
    elif mutation == "nan":
        raw = raw.replace(b'"epoch":99', b'"epoch":NaN', 1)
    elif mutation == "digest":
        raw = raw.replace(b'"epoch":99', b'"epoch":98', 1)
    elif mutation == "trailing":
        raw = raw[:-1]
    else:
        raw = b" " * (r.MAX_BYTES + 1)
    with pytest.raises((BenefitInputError, ValueError)):
        r.decode_calls(raw)


@pytest.mark.parametrize(
    "kind", ["sample_loss", "coverage", "sample_timestamp", "outcome", "time_backwards"]
)
def test_join_withholds_changed_or_unavailable_actual_calls(tmp_path, kind):
    path = tmp_path / "calls"
    collect(path)
    recorded = r.read_calls(path)
    rows = recorded["calls"]
    if kind == "sample_loss":
        rows[0]["data"]["sample"] = None
    elif kind == "coverage":
        rows[0]["data"]["sample"]["coverage"]["proc_net_dev"] = False
    elif kind == "sample_timestamp":
        rows[0]["data"]["sample"]["observed_at"] = "invented"
    elif kind == "outcome":
        rows[-1]["data"]["outcomes"][0]["assessment"] = "supported"
    else:
        raw = path.read_bytes()
        parsed = [json.loads(line) for line in raw.splitlines()]
        parsed[2]["data"]["start_ns"] = 0
        sink = r.CallRecording(tmp_path / "bad", metadata=parsed[0]["data"])
        for row in parsed[1:-1]:
            sink.append(row["kind"], row["data"])
        sink.close(complete=True)
        with pytest.raises(BenefitInputError, match="monotonic"):
            r.read_calls(tmp_path / "bad")
        return
    with pytest.raises(BenefitInputError):
        r.replay_calls(recorded, policy=POLICY, boot="kernel-test")


def test_bounds_poison_recording_without_end(tmp_path):
    path = tmp_path / "calls"
    with patch.object(r, "MAX_ROWS", 2):
        with pytest.raises(BenefitInputError, match="bound"):
            with r.record_collector(path, policy=POLICY, policy_source_ref="inline"):
                collector = input_resume.OutcomeTelemetryCollector(
                    source=Source(),
                    policy=OutcomeTelemetryPolicy.from_mapping(POLICY),
                    interface="es",
                )
                collector.record_sample(epoch=100)
    with pytest.raises(BenefitInputError, match="unfinished"):
        r.read_calls(path)


def test_rejects_hardlink_and_writable_mode(tmp_path):
    path = tmp_path / "calls"
    collect(path)
    path.chmod(0o666)
    with pytest.raises(BenefitInputError, match="unsafe"):
        r.read_calls(path)
    path.chmod(0o600)
    import os

    os.link(path, tmp_path / "hard")
    with pytest.raises(BenefitInputError, match="unsafe"):
        r.read_calls(path)


def test_exact_policy_binding_and_two_label_differences(tmp_path):
    path = tmp_path / "calls"
    collect(path)
    recorded = r.read_calls(path)
    result = r.replay_calls(recorded, policy=POLICY, boot="kernel-test")
    assert len(result["exact_differences"]) == 2
    assert {d["path"] for d in result["exact_differences"]} == {
        "telemetry_coverage.policy_ref",
        "evidence_refs[1]",
    }
    assert result["live_outcomes_sha256"] == r.manifest_digest(result["live_outcomes"])
    recorded["context"]["policy_sha256"] = "0" * 64
    with pytest.raises(BenefitInputError, match="canonical policy"):
        r.replay_calls(recorded, policy=POLICY, boot="kernel-test")


def test_actual_collector_policy_mismatch_fails_before_calls(tmp_path):
    with pytest.raises(BenefitInputError, match="actual collector policy"):
        with r.record_collector(
            tmp_path / "calls", policy=POLICY, policy_source_ref="actual-file"
        ):
            input_resume.OutcomeTelemetryCollector(
                source=Source(),
                policy=OutcomeTelemetryPolicy.from_mapping(POLICY),
                interface="es",
            )
    assert input_resume.OutcomeTelemetryCollector is OutcomeTelemetryCollector


@pytest.mark.parametrize("failure", ["append", "super_signal", "caught_bound"])
def test_caught_operation_failure_never_writes_clean_end(tmp_path, failure):
    path = tmp_path / "calls"
    with r.record_collector(path, policy=POLICY, policy_source_ref="inline"):
        collector = input_resume.OutcomeTelemetryCollector(
            source=Source(),
            policy=OutcomeTelemetryPolicy.from_mapping(POLICY),
            interface="es",
        )
        if failure == "append":
            original = r.CallRecording.append

            def append(sink, kind, data):
                if kind == "sample":
                    raise OSError("after super before append")
                return original(sink, kind, data)

            with patch.object(r.CallRecording, "append", append):
                with pytest.raises(OSError):
                    collector.record_sample(epoch=100)
            assert len(collector.samples) == 1
        elif failure == "super_signal":

            class StopObservation(BaseException):
                pass

            original = r.OutcomeTelemetryCollector.finalize_due

            def finalize(self, *, epoch):
                original(self, epoch=epoch)
                raise StopObservation()

            with patch.object(r.OutcomeTelemetryCollector, "finalize_due", finalize):
                with pytest.raises(StopObservation):
                    collector.finalize_due(epoch=100)
        else:
            with patch.object(r, "MAX_ROWS", 1):
                with pytest.raises(BenefitInputError):
                    collector.record_sample(epoch=100)
    with pytest.raises(BenefitInputError, match="unfinished"):
        r.read_calls(path)
    assert input_resume.OutcomeTelemetryCollector is OutcomeTelemetryCollector
