"""SYNTHETIC driver boundaries only; no core, UID change or real load trial."""

from copy import deepcopy
import io
import os
from types import SimpleNamespace

import pytest

import run_observer_hostile_cost as lab


def test_marker_proxy_preserves_exact_bytes_and_return_without_extra_io():
    stream = io.BytesIO()
    state = dict(marker_samples=[], pending_marker=None)
    proxy = lab.MarkerStream(stream, state)
    raw = lab.phase._wire(lab.ORIGINAL.TRANSCRIPT[0])
    assert proxy.write(raw) == len(raw)
    assert stream.getvalue() == raw
    assert state["pending_marker"]["end_monotonic_ns"] is None
    assert state["marker_samples"] == []


@pytest.mark.parametrize(
    "fault", ["changed", "duplicate_pending", "wrong_order", "extra"]
)
def test_marker_proxy_rejects_changed_reordered_or_extra_recipe_before_write(fault):
    stream = io.BytesIO()
    state = dict(marker_samples=[], pending_marker=None)
    raw = lab.phase._wire(lab.ORIGINAL.TRANSCRIPT[0])
    if fault == "changed":
        raw += b" "
    elif fault == "duplicate_pending":
        state["pending_marker"] = {}
    elif fault == "wrong_order":
        raw = lab.phase._wire(lab.ORIGINAL.TRANSCRIPT[1])
    else:
        state["marker_samples"] = [{}, {}, {}]
    with pytest.raises(ValueError):
        lab.MarkerStream(stream, state).write(raw)
    assert stream.getvalue() == b""


def test_original_marker_write_exception_is_not_replaced_or_completed():
    error = OSError("SYNTHETIC original write error")

    def fail(raw):
        raise error

    state = dict(marker_samples=[], pending_marker=None)
    with pytest.raises(OSError) as caught:
        lab.MarkerStream(SimpleNamespace(write=fail), state).write(
            lab.phase._wire(lab.ORIGINAL.TRANSCRIPT[0])
        )
    assert caught.value is error
    assert state["pending_marker"]["end_monotonic_ns"] is None
    assert state["marker_samples"] == []


def test_full_stderr_startup_and_sole_reader_handover_are_exact(tmp_path):
    captured = lab.StderrCapture(tmp_path / "core.stderr")
    captured.append(b"actual startup prefix\n")
    read_fd, write_fd = os.pipe()
    try:
        captured.start(read_fd)
        os.write(write_fd, b"actual later suffix\n")
        os.close(write_fd)
        write_fd = None
        result = captured.finish()
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
    expected = b"actual startup prefix\nactual later suffix\n"
    assert (tmp_path / "core.stderr").read_bytes() == expected
    assert result["complete"] is result["joined"] is result["eof"] is True
    assert result["sha256"] == lab.phase._sha(expected)
    assert result["bytes"] == len(expected)
    assert result["coverage"] == "mixed_launcher_native_from_start_to_EOF"


def test_stderr_capture_bound_failure_stays_incomplete_and_keeps_prefix(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(lab, "MAX_EVE_BYTES", 4)
    capture = lab.StderrCapture(tmp_path / "core.stderr")
    capture.append(b"abcd")
    capture.append(b"too much")
    read_fd, write_fd = os.pipe()
    try:
        os.close(write_fd)
        capture.start(read_fd)
        result = capture.finish()
    finally:
        os.close(read_fd)
    assert result["complete"] is False
    assert result["error"] == "ValueError"
    assert (tmp_path / "core.stderr").read_bytes() == b"abcd"


def test_bounded_original_read_does_not_follow_symlink_or_invent_absence(tmp_path):
    path = tmp_path / "original"
    path.write_bytes(b"original bytes")
    assert lab.read_original(path, 4) == b"origi"  # Bound + one detects overflow.
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        lab.read_original(alias, 100)
    with pytest.raises(FileNotFoundError):
        lab.read_original(tmp_path / "missing", 100)
    assert path.read_bytes() == b"original bytes"


def test_hostile_context_restores_only_owned_module_bindings_on_refusal():
    names = (
        "register_live",
        "children",
        "Run",
        "store_bytes",
        "process_sample",
        "wait_observer",
    )
    originals = {name: getattr(lab.ORIGINAL, name) for name in names}
    import subprocess

    popen = subprocess.Popen
    with pytest.raises(ValueError):
        with lab.hostile_arm("off"):
            raise ValueError("SYNTHETIC setup refused")
    assert all(
        getattr(lab.ORIGINAL, name) is value for name, value in originals.items()
    )
    assert subprocess.Popen is popen


def finish_fixture(
    tmp_path, monkeypatch, *, writer_error=None, joined=True, core_alive=True
):
    now = [0]
    calls = []

    class Stop:
        stopped = False

        def is_set(self):
            return self.stopped

        def set(self):
            self.stopped = True
            calls.append(("stop", now[0]))

        def wait(self, seconds):
            now[0] += max(1, int(seconds * 1e9))

    stop = Stop()
    load = SimpleNamespace(
        window=dict(window_start_monotonic_ns=0),
        stop=stop,
        error=writer_error,
        is_alive=lambda: not stop.stopped or not joined,
        join=lambda timeout: calls.append(("join", timeout)),
    )
    audit = SimpleNamespace(
        before_stop=lambda work, **kw: calls.append(("pre_stop", kw)),
        pre=SimpleNamespace(metadata={}),
    )
    state = dict(
        load=load,
        load_finished=False,
        run=SimpleNamespace(
            process=SimpleNamespace(poll=lambda: None if core_alive else 1)
        ),
        quota={"audit_interval_ms": 1000},
        final_audit=audit,
        fixture=SimpleNamespace(root=tmp_path),
        quota_load={},
        pids={},
        proc_samples={},
    )
    monkeypatch.setattr(
        lab,
        "time",
        SimpleNamespace(
            monotonic_ns=lambda: now[0],
            sleep=lambda seconds: calls.append(("drain", seconds)),
        ),
    )
    monkeypatch.setattr(
        lab,
        "quota",
        lab.phase.ForwardingModule(
            lab.quota, observation=lambda *args, **kwargs: {"actual": "observation"}
        ),
    )
    return state, calls


def test_writer_stays_active_for_full_six_seconds_then_join_and_unchanged_drain(
    tmp_path, monkeypatch
):
    state, calls = finish_fixture(tmp_path, monkeypatch)
    lab.finish_load(state)
    assert calls[0] == ("stop", 6_000_000_000)
    assert calls[1] == ("join", 10)
    assert calls[2] == ("drain", 1.5)
    assert calls[3][0] == "pre_stop"
    assert calls[3][1]["writer_joined"] is True
    assert state["quota_load"] == {"actual": "observation"}


@pytest.mark.parametrize("fault", ["writer_error", "early_core_exit", "missing_start"])
def test_writer_failure_or_missing_actual_start_never_becomes_valid_window(
    tmp_path, monkeypatch, fault
):
    state, calls = finish_fixture(
        tmp_path,
        monkeypatch,
        writer_error="SYNTHETIC" if fault == "writer_error" else None,
        core_alive=fault != "early_core_exit",
    )
    if fault == "missing_start":
        state["load"].window = {}
    with pytest.raises(RuntimeError):
        lab.finish_load(state)
    assert not any(call[0] == "pre_stop" for call in calls)
    assert state["quota_load"] == {}


def test_unjoined_writer_records_failure_without_fabricated_join_timestamp(
    tmp_path, monkeypatch
):
    state, calls = finish_fixture(tmp_path, monkeypatch, joined=False)
    lab.finish_load(state)
    assert state["load"].error == "writer join timeout"
    assert calls[-1][1]["writer_joined"] is False
    assert calls[-1][1]["writer_joined_ns"] is None


def test_export_public_allowlist_preserves_hashes_and_excludes_keys(tmp_path):
    raw = tmp_path / "eve"
    raw.write_bytes(b"actual retained EVE\n")
    (tmp_path / "producer-private-key").write_bytes(b"NEVER COPY")
    descriptor = lab._artifact(raw, 100)
    inputs = [
        dict(
            arm_id="instrumented_on",
            raw_artifacts={"eve": descriptor},
            phase_artifacts={},
            clock_artifacts={},
        )
    ]
    report = dict(arms=[], original_arm_inputs=inputs)
    before = deepcopy(report)
    output = tmp_path / "public"
    lab.export_public(report, output)
    assert sorted(path.name for path in output.iterdir()) == [
        "instrumented_on-raw_artifacts-eve.raw",
        "report.json",
    ]
    assert (
        output / "instrumented_on-raw_artifacts-eve.raw"
    ).read_bytes() == raw.read_bytes()
    assert report == before


def test_export_changed_original_refuses_copy_and_retains_report(tmp_path):
    path = tmp_path / "eve"
    path.write_bytes(b"original")
    descriptor = lab._artifact(path, 100)
    path.write_bytes(b"changed")
    result = dict(
        arms=[dict(arm_id="original_off", raw_artifacts=dict(eve=descriptor))]
    )
    with pytest.raises(ValueError):
        lab.export_public(result, tmp_path / "public")
    assert [path.name for path in (tmp_path / "public").iterdir()] == ["report.json"]


def test_unstarted_stderr_capture_closes_owned_fd_and_withholds_completion(tmp_path):
    capture = lab.StderrCapture(tmp_path / "core.stderr")
    capture.append(b"original startup prefix")
    result = capture.finish()
    assert capture.fd is None
    assert result["complete"] is False and result["joined"] is False
    assert result["error"] == "stderr drainer unjoined"
    assert (tmp_path / "core.stderr").read_bytes() == b"original startup prefix"


def test_v2_staging_pins_all_four_original_helpers_without_creating_role_sidecars(
    tmp_path, monkeypatch
):
    import json
    import stat

    producer, witness, journal = [
        tmp_path / name for name in ("producer", "witness", "journal")
    ]
    for folder in (producer, witness, journal):
        folder.mkdir(mode=0o700)
    registration = tmp_path / "registration"
    registration.write_text(
        json.dumps(
            dict(
                schema_version="outcome-live-origin-registration/v1",
                binary_sha256="a" * 64,
            )
        )
    )
    fixture = SimpleNamespace(
        root=tmp_path,
        registration=registration,
        p=SimpleNamespace(
            data=dict(
                schema_version="outcome-input-trust/v3", journal_directory=str(journal)
            )
        ),
        pk=producer / "unused-test-key",
        wk=witness / "unused-test-key",
        policy_file=tmp_path / "trust",
    )
    monkeypatch.setattr(lab, "os", lab.phase.ForwardingModule(os, geteuid=lambda: 0))
    staged = lab.stage_v2(fixture, run_id="SYNTHETIC-run", arm_id="instrumented_on")
    config = staged["config"]
    assert config["schema_version"] == "edge-phase-timing-config/v2"
    assert set(config["clock"]) == {
        "helper_path",
        "helper_sha256",
        "recording_path",
        "recording_sha256",
        "calls_path",
        "context_path",
    }
    bootstrap = staged["worker_path"].parent
    assert stat.S_IMODE(bootstrap.stat().st_mode) == 0o555
    expected = []
    for name in lab.CLOCK_FILES:
        path = bootstrap / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        expected.append(path.read_bytes())
    assert config["metadata"]["code_sha256"] == lab.phase._sha(b"\0".join(expected))
    assert (
        list(journal.iterdir())
        == list(producer.iterdir())
        == list(witness.iterdir())
        == []
    )


def test_profile_declaration_refused_before_v2_bootstrap_creation(
    tmp_path, monkeypatch
):
    import json

    registration = tmp_path / "registration"
    registration.write_text(
        json.dumps(dict(capture_apparmor_profile="existing-must-not-relax"))
    )
    fixture = SimpleNamespace(root=tmp_path, registration=registration)
    monkeypatch.setattr(lab, "os", lab.phase.ForwardingModule(os, geteuid=lambda: 0))
    with pytest.raises(ValueError, match="profile-declared"):
        lab.stage_v2(fixture, run_id="run", arm_id="instrumented_on")
    assert not (tmp_path / "hostile-phase-bootstrap").exists()


def test_recording_binding_uses_actual_root_policy_and_independently_retained_file_pins(
    tmp_path,
):
    import json
    from azazel_edge.benchmark.benefit import manifest_digest
    from azazel_edge.outcome.telemetry import (
        OutcomeTelemetryPolicy,
        POLICY_SCHEMA_VERSION,
    )

    path = tmp_path / "actual-policy.json"
    payload = dict(
        schema_version=POLICY_SCHEMA_VERSION,
        policy_version="SYNTHETIC-disabled",
        actions={},
    )
    path.write_text(json.dumps(payload))
    context = lab.policy_context(path)
    assert context == dict(
        policy_sha256=manifest_digest(payload),
        policy_source_ref=str(path),
        policy_ref=OutcomeTelemetryPolicy.from_mapping(
            payload, source_ref=str(path)
        ).policy_ref,
    )
    metadata = dict(
        run_id="run",
        arm="instrumented_on",
        input_sha256="1" * 64,
        code_sha256="2" * 64,
        core_sha256="3" * 64,
        interpreter_sha256="4" * 64,
    )
    artifacts = dict(calls=dict(sha256="5" * 64), context=dict(sha256="6" * 64))
    binding = lab.recording_binding(artifacts, metadata, context)
    assert set(binding) == {
        "calls_sha256",
        "context_sha256",
        "policy_context",
        "scope_pins",
    }
    assert binding["calls_sha256"] == "5" * 64 and binding["context_sha256"] == "6" * 64
    assert binding["scope_pins"] == dict(metadata, role="observer")
    original = deepcopy(binding)
    context["policy_sha256"] = "changed-after-retention"
    metadata["code_sha256"] = "changed-after-retention"
    assert binding == original


def test_ingress_diagnostics_copies_only_actual_hash_size_error_without_text_or_paths():
    actual = dict(
        sha256="a" * 64,
        bytes=123,
        error=None,
        text_prefix="private diagnostic",
        path="private path",
    )
    audit = SimpleNamespace(diagnostics=dict(core_stderr=actual))
    result = lab.ingress_diagnostics(audit)
    assert result == dict(core_stderr=dict(sha256="a" * 64, bytes=123, error=None))
    actual["sha256"] = "changed"
    assert result["core_stderr"]["sha256"] == "a" * 64


def capture_guard_fixture(mode="on"):
    original = dict(
        instrumented=True, mode=mode, functional_phase_gate=dict(accepted=True)
    )
    arm = dict(
        clock_report=dict(
            observed_calls=3,
            calls_error=None,
            context=dict(begin={"known": "prefix"}, end=None, error=None),
            reasons=[
                "complete_observer_clock_closure_unavailable",
                "original_5ms_qualification_withheld",
            ],
            eligible=False,
        ),
        observed_completed_callbacks_inside_load_after_warmup=1,
    )
    return arm, original


@pytest.mark.parametrize(
    "fault",
    [
        "missing_phases",
        "no_calls",
        "bool_calls",
        "calls_error",
        "no_context",
        "bad_context",
        "unbound_pair",
        "no_on_callback",
        "bool_on_callback",
    ],
)
def test_actual_linux_capture_guard_rejects_missing_or_invalid_cost_recording(fault):
    from test_observer_hostile_cost_linux import require_instrumented_capture

    arm, original = capture_guard_fixture()
    clock = arm["clock_report"]
    if fault == "missing_phases":
        original["functional_phase_gate"]["accepted"] = False
    elif fault == "no_calls":
        clock["observed_calls"] = 0
    elif fault == "bool_calls":
        clock["observed_calls"] = True
    elif fault == "calls_error":
        clock["calls_error"] = "missing_calls"
    elif fault == "no_context":
        clock["context"]["begin"] = None
    elif fault == "bad_context":
        clock["context"]["error"] = "invalid_context"
    elif fault == "unbound_pair":
        clock["reasons"].append("external_recording_pair_policy_binding_unavailable")
    else:
        arm["observed_completed_callbacks_inside_load_after_warmup"] = (
            True if fault == "bool_on_callback" else 0
        )
    with pytest.raises(AssertionError):
        require_instrumented_capture(arm, original)


def test_capture_guard_accepts_real_prefix_with_missing_clock_end_and_no_extra_fault_callback():
    from test_observer_hostile_cost_linux import require_instrumented_capture

    arm, original = capture_guard_fixture()
    before = deepcopy(arm)
    require_instrumented_capture(arm, original)
    assert arm == before and arm["clock_report"]["eligible"] is False
    arm, original = capture_guard_fixture("faulted")
    arm["observed_completed_callbacks_inside_load_after_warmup"] = 0
    require_instrumented_capture(arm, original)
    assert arm["clock_report"]["context"]["end"] is None


def test_public_trust_export_contains_only_existing_public_policy_and_never_private_files(
    tmp_path,
):
    from auth_input_helpers import make_policy
    from azazel_edge.outcome.journal import _json

    policy, *_ = make_policy(tmp_path)
    path = tmp_path / "trust.json"
    raw = _json(dict(policy.data))
    path.write_bytes(raw)
    fixture = SimpleNamespace(
        policy_file=path,
        p=policy,
        pk=tmp_path / "producer-secret" / "key",
        wk=tmp_path / "root-secret" / "key",
    )
    descriptor = lab.public_trust_artifact(fixture)
    result = dict(
        arms=[dict(arm_id="original_off", raw_artifacts=dict(trust=descriptor))]
    )
    lab.export_public(result, tmp_path / "public")
    assert (
        tmp_path / "public" / "original_off-raw_artifacts-trust.raw"
    ).read_bytes() == raw
    assert set(policy.data).isdisjoint(
        {"private_key", "producer_private_key", "witness_private_key"}
    )
    assert descriptor["max_bytes"] == 65536


def test_public_trust_rejects_private_key_fields_and_export_rejects_private_artifact_names(
    tmp_path,
):
    from auth_input_helpers import make_policy
    from azazel_edge.outcome.journal import _json, OutcomeJournalError

    policy, *_ = make_policy(tmp_path)
    path = tmp_path / "trust.json"
    path.write_bytes(
        _json(dict(policy.data, private_key="SYNTHETIC-SECRET-DO-NOT-COPY"))
    )
    fixture = SimpleNamespace(
        policy_file=path,
        p=policy,
        pk=tmp_path / "producer-secret" / "key",
        wk=tmp_path / "root-secret" / "key",
    )
    with pytest.raises(OutcomeJournalError):
        lab.public_trust_artifact(fixture)
    assert not (tmp_path / "public").exists()
    result = dict(
        arms=[
            dict(
                arm_id="original_off",
                raw_artifacts={
                    "private_key": dict(
                        path=str(tmp_path / "never-read-key"), sha256="a" * 64, bytes=1
                    )
                },
            )
        ]
    )
    with pytest.raises(ValueError, match="unlisted public"):
        lab.export_public(result, tmp_path / "public")
    assert sorted(item.name for item in (tmp_path / "public").iterdir()) == [
        "report.json"
    ]
