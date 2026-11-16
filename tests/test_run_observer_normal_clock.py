"""SYNTHETIC driver/pin/proxy controls; no actor, UID or load trial."""

from contextlib import contextmanager
from copy import deepcopy
import json
import os
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

import run_observer_normal_clock as driver


def fixture(tmp_path):
    for name in ("producer", "witness", "journal"):
        (tmp_path / name).mkdir(mode=0o700)
    registration = tmp_path / "registration.json"
    registration.write_text(
        json.dumps(
            dict(
                schema_version="outcome-live-origin-registration/v1",
                binary_sha256="a" * 64,
            )
        )
    )
    return SimpleNamespace(
        root=tmp_path,
        registration=registration,
        policy_file=tmp_path / "trust.json",
        p=SimpleNamespace(
            data=dict(
                schema_version="outcome-input-trust/v3",
                journal_directory=str(tmp_path / "journal"),
            )
        ),
        pk=tmp_path / "producer" / "unused-key",
        wk=tmp_path / "witness" / "unused-key",
    )


@pytest.mark.parametrize(
    "arm,profile",
    [
        ("original_on", "stop_only"),
        ("original_faulted", "stop_only"),
        ("instrumented_off", "phase_and_clock"),
        ("instrumented_on", "phase_and_clock"),
        ("instrumented_faulted", "phase_and_clock"),
    ],
)
def test_root_readonly_v3_staging_pins_exact_five_files_and_profile(
    tmp_path, monkeypatch, arm, profile
):
    f = fixture(tmp_path)
    monkeypatch.setattr(
        driver, "os", driver.phase.ForwardingModule(os, geteuid=lambda: 0)
    )
    staged = driver.stage_v3(f, run_id="SYNTHETIC-run", arm_id=arm)
    config = staged["config"]
    assert config["schema_version"] == "edge-phase-timing-config/v3"
    assert config["normal_stop"]["profile"] == profile
    assert config["metadata"]["arm"] == arm
    bootstrap = staged["worker_path"].parent
    assert stat.S_IMODE(bootstrap.stat().st_mode) == 0o555
    blobs = []
    for name in driver.FILES:
        path = bootstrap / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o444
        original = (driver.ROOT / "tests" / "real_systemd" / name).read_bytes()
        assert path.read_bytes() == original
        blobs.append(original)
    assert len(blobs) == 5
    assert config["metadata"]["code_sha256"] == driver.phase._sha(b"\0".join(blobs))
    assert config["normal_stop"]["helper_sha256"] == driver.phase._sha(blobs[-1])
    assert staged["config_sha256"] == driver.phase._sha(
        staged["config_path"].read_bytes()
    )
    assert stat.S_IMODE(staged["config_path"].stat().st_mode) == 0o444
    assert (
        list((tmp_path / "journal").iterdir())
        == list((tmp_path / "producer").iterdir())
        == list((tmp_path / "witness").iterdir())
        == []
    )


@pytest.mark.parametrize(
    "fault",
    [
        "not_root",
        "profile_declared",
        "wrong_registration",
        "wrong_trust",
        "baseline_off",
        "baseline_as_instrumented",
        "instrumented_as_baseline",
        "unknown_profile",
        "unknown_arm",
    ],
)
def test_staging_refuses_wrong_authority_or_frozen_profile_before_writes(
    tmp_path, monkeypatch, fault
):
    f = fixture(tmp_path)
    monkeypatch.setattr(
        driver,
        "os",
        driver.phase.ForwardingModule(
            os, geteuid=lambda: 1 if fault == "not_root" else 0
        ),
    )
    options = dict(run_id="SYNTHETIC", arm_id="instrumented_on")
    if fault == "profile_declared":
        f.registration.write_text(
            json.dumps(dict(capture_apparmor_profile="existing-enforced"))
        )
    elif fault == "wrong_registration":
        f.registration.write_text(
            json.dumps(dict(schema_version="outcome-live-origin-registration/v4"))
        )
    elif fault == "wrong_trust":
        f.p.data["schema_version"] = "outcome-input-trust/v4"
    elif fault == "baseline_off":
        options["arm_id"] = "original_off"
    elif fault == "baseline_as_instrumented":
        options.update(arm_id="original_on", profile="phase_and_clock")
    elif fault == "instrumented_as_baseline":
        options["profile"] = "stop_only"
    elif fault == "unknown_profile":
        options["profile"] = "unknown"
    elif fault == "unknown_arm":
        options["arm_id"] = "instrumented_unlisted"
    with pytest.raises((ValueError, RuntimeError)):
        driver.stage_v3(f, **options)
    assert not (tmp_path / "normal-clock-bootstrap").exists()


def observer(monkeypatch, *, terminate=None, wait=None):
    entry, operations = {}, []
    anchors = iter([dict(order=i) for i in range(10)])
    monkeypatch.setattr(
        driver,
        "process_sample",
        lambda pid: dict(pid=pid, start_ticks=456, available=True),
    )
    monkeypatch.setattr(driver.load, "anchor", lambda: next(anchors))
    monkeypatch.setattr(
        driver.load, "pid_view", lambda pid: dict(disposition="absent", checked_ns=99)
    )
    process = SimpleNamespace(
        pid=123,
        returncode=None,
        terminate=terminate
        or (lambda: operations.append("terminate") or "original-terminate-result"),
        wait=wait or (lambda *a, **kw: operations.append((a, kw)) or 0),
    )
    return driver.RequestedObserver(process, entry), entry, operations


def test_requested_observer_forwards_once_with_real_root_brackets_and_exact_int_signal(
    monkeypatch,
):
    proxy, entry, operations = observer(monkeypatch)
    assert proxy.terminate() == "original-terminate-result"
    assert operations == ["terminate"]
    request = entry["requests"][0]
    assert type(request["signal"]) is int and request["signal"] == 15
    assert request["pid"] == 123 and request["start_ticks"] == 456
    assert request["before"] == {"order": 0} and request["after"] == {"order": 1}
    assert request["delivery_time"] is None
    assert proxy.wait(timeout=5) == 0
    assert operations == ["terminate", ((), {"timeout": 5})]
    assert entry["wait_result"] == dict(
        pid=123,
        start_ticks=456,
        returncode=0,
        after={"order": 2},
        view=dict(disposition="absent", checked_ns=99),
    )


def test_cleanup_waits_remain_real_calls_but_never_overwrite_first_wait_receipt(
    monkeypatch,
):
    results = iter([0, 99])
    called = []

    def wait(*args, **kwargs):
        called.append(kwargs)
        return next(results)

    proxy, entry, _ = observer(monkeypatch, wait=wait)
    assert proxy.wait(timeout=5) == 0
    first = deepcopy(entry["wait_result"])
    assert proxy.wait(timeout=10) == 99
    assert called == [{"timeout": 5}, {"timeout": 10}]
    assert entry["wait_result"] == first


@pytest.mark.parametrize("operation", ["terminate", "wait"])
def test_original_send_or_wait_failure_keeps_exact_exception_and_no_fake_success(
    monkeypatch, operation
):
    error = OSError("SYNTHETIC original operation failed")
    calls = []

    def fail(*args, **kwargs):
        calls.append((args, kwargs))
        raise error

    proxy, entry, _ = observer(monkeypatch, **{operation: fail})
    with pytest.raises(OSError) as caught:
        getattr(proxy, operation)()
    assert caught.value is error and calls == [((), {})]
    assert entry["requests"] == [] and entry["wait_result"] is None


def test_normal_profile_maps_only_declared_baselines_and_restores_module_bindings(
    monkeypatch, tmp_path
):
    staged, spawned = [], []

    @contextmanager
    def old_arm(mode):
        yield {"mode": mode}

    def stage(f, *, run_id, arm_id, profile=None):
        staged.append((arm_id, profile or "phase_and_clock"))
        return dict(
            worker_path="/ROOT-readonly/worker.py",
            config_path="/ROOT-readonly/config",
            config_sha256="a" * 64,
        )

    def popen(argv, *args, **kwargs):
        spawned.append((list(argv), kwargs))
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(driver, "stage_v3", stage)
    monkeypatch.setattr(driver.load, "hostile_arm", old_arm)
    monkeypatch.setattr(
        driver.load.ORIGINAL, "register_live", lambda f: "original-registration-result"
    )
    monkeypatch.setattr(
        driver.load.ORIGINAL,
        "subprocess",
        driver.phase.ForwardingModule(subprocess, Popen=popen),
    )
    monkeypatch.setattr(
        driver, "process_sample", lambda pid: dict(pid=pid, start_ticks=456)
    )
    before_stage, before_arm = driver.load.stage_v2, driver.load.hostile_arm
    original_argv = [sys.executable, "-m", driver.phase.OBSERVER]
    for option in driver.phase.OBSERVER_OPTIONS:
        original_argv.append(option)
        if option != "--journal-resume-input":
            original_argv.append("same-original-value")
    with driver.normal_profile("SYNTHETIC-group") as entries:
        for arm_id in driver.phase.ARM_ORDER:
            mode = arm_id.split("_", 1)[1]
            f = SimpleNamespace(root=tmp_path / arm_id)
            if arm_id.startswith("instrumented_"):
                driver.load.stage_v2(f, run_id="unused", arm_id=arm_id)
            with driver.load.hostile_arm(mode):
                assert (
                    driver.load.ORIGINAL.register_live(f)
                    == "original-registration-result"
                )
                if mode != "off":
                    proxy = driver.load.ORIGINAL.subprocess.Popen(
                        original_argv, user=65534, extra_groups=[], cwd="/unchanged"
                    )
                    assert type(proxy) is driver.RequestedObserver
        assert entries["original_off"].get("staged") is None
    assert (
        driver.load.stage_v2 is before_stage and driver.load.hostile_arm is before_arm
    )
    assert staged == [
        ("instrumented_off", "phase_and_clock"),
        ("original_on", "stop_only"),
        ("instrumented_on", "phase_and_clock"),
        ("original_faulted", "stop_only"),
        ("instrumented_faulted", "phase_and_clock"),
    ]
    assert len(spawned) == 4
    for index, (argv, kwargs) in enumerate(spawned):
        assert kwargs == dict(user=65534, extra_groups=[], cwd="/unchanged")
        if index % 2 == 0:
            assert (
                argv[1] == "/ROOT-readonly/worker.py"
                and argv[argv.index("--") + 1 :] == original_argv[3:]
            )
        else:
            assert argv == original_argv


def public_fixture(tmp_path, *, partial=False):
    raw = b"SYNTHETIC retained original prefix\n"
    path = tmp_path / "original"
    path.write_bytes(raw)
    descriptor = driver.load._artifact(path, 100)
    arm = dict(
        arm_id="instrumented_faulted",
        raw_artifacts=dict(eve=descriptor),
        phase_artifacts={},
        clock_artifacts={},
    )
    control = dict(
        artifacts=dict(
            request=descriptor, completion=None, journal=descriptor, anchors=descriptor
        )
    )
    if partial:
        result = dict(
            original_load_evaluation=dict(arms=[arm]),
            control_evidence={"instrumented_faulted": control},
        )
    else:
        arm["normal_stop"] = control
        result = dict(original_load_evaluation=dict(original_arm_inputs=[arm]))
    return result, raw


@pytest.mark.parametrize("partial", [False, True])
def test_export_preserves_original_and_partial_control_prefixes_without_private_files(
    tmp_path, partial
):
    result, raw = public_fixture(tmp_path, partial=partial)
    (tmp_path / "private-test-key").write_bytes(b"NEVER EXPORT")
    before = deepcopy(result)
    output = tmp_path / "public"
    driver.export_public(result, output)
    assert sorted(path.name for path in output.iterdir()) == [
        "instrumented_faulted-control_artifacts-anchors.raw",
        "instrumented_faulted-control_artifacts-journal.raw",
        "instrumented_faulted-control_artifacts-request.raw",
        "instrumented_faulted-raw_artifacts-eve.raw",
        "report.json",
    ]
    assert result == before
    assert all(
        path.read_bytes() == raw for path in output.iterdir() if path.suffix == ".raw"
    )
    assert b"NEVER EXPORT" not in (output / "report.json").read_bytes()


@pytest.mark.parametrize("fault", ["private_name", "unknown_arm", "mutation"])
def test_export_refuses_private_names_unknown_arms_and_changed_originals(
    tmp_path, fault
):
    result, _ = public_fixture(tmp_path)
    arm = result["original_load_evaluation"]["original_arm_inputs"][0]
    if fault == "private_name":
        arm["raw_artifacts"]["private_key"] = dict(
            path=str(tmp_path / "must-never-open"), bytes=1, sha256="a" * 64
        )
    elif fault == "unknown_arm":
        arm["arm_id"] = "unlisted"
    else:
        (tmp_path / "original").write_bytes(b"changed")
    with pytest.raises(ValueError):
        driver.export_public(result, tmp_path / "public")
    assert (tmp_path / "public" / "report.json").exists()
    assert not any(
        "private_key" in path.name for path in (tmp_path / "public").iterdir()
    )


def test_export_control_only_failed_scope_preserves_actual_prefixes(tmp_path):
    result, raw = public_fixture(tmp_path, partial=True)
    result["original_load_evaluation"]["arms"] = []
    (tmp_path / "private-test-key").write_bytes(b"NEVER EXPORT")
    before = deepcopy(result)
    output = tmp_path / "public"
    driver.export_public(result, output)
    assert sorted(path.name for path in output.iterdir()) == [
        "instrumented_faulted-control_artifacts-anchors.raw",
        "instrumented_faulted-control_artifacts-journal.raw",
        "instrumented_faulted-control_artifacts-request.raw",
        "report.json",
    ]
    assert result == before
    assert all(
        path.read_bytes() == raw for path in output.iterdir() if path.suffix == ".raw"
    )


@pytest.mark.parametrize("fail_policy", [False, True])
def test_collect_control_retains_valid_originals_after_later_anchor_identity_or_policy_failure(
    tmp_path, monkeypatch, fail_policy
):
    from azazel_edge.outcome.telemetry import POLICY_SCHEMA_VERSION

    f = fixture(tmp_path)
    f.source = tmp_path / "source"
    f.journal = tmp_path / "journal" / "observations.journal"
    f.anchors = tmp_path / "witness" / "anchors.journal"
    completion = tmp_path / "journal" / "completion.json"
    for path in (f.source, f.journal, f.anchors, completion):
        path.write_bytes(b"SYNTHETIC immutable original prefix\n")
    (tmp_path / "telemetry-policy.json").write_text(
        json.dumps(
            dict(
                schema_version=POLICY_SCHEMA_VERSION,
                policy_version="synthetic-disabled",
                actions={},
            )
        )
    )
    entry = dict(
        arm_id="instrumented_on",
        state=dict(fixture=f, policy_context={"retained": "actual prior context"}),
        staged=dict(
            config=dict(
                metadata={"run_id": "synthetic"},
                normal_stop=dict(
                    profile="phase_and_clock", receipt_path=str(completion)
                ),
            )
        ),
    )
    request = dict(
        schema_version="edge-observer-stop-request/v1",
        arm_id="instrumented_on",
        requests=[],
        wait_result=None,
        observer_initial=None,
        controller_identity=None,
    )
    request_path = f.wk.parent / "normal-stop-request.json"
    request_path.write_bytes(driver.phase._wire(request))
    originals = {
        path: path.read_bytes()
        for path in (f.source, f.journal, f.anchors, completion, request_path)
    }
    real_artifact, real_metadata = driver.load._artifact, driver._metadata
    artifact_calls, metadata_calls, policy_calls = [], [], []

    def artifact(path, maximum):
        artifact_calls.append(str(path))
        if path == f.anchors:
            raise PermissionError("SYNTHETIC later anchor read refused")
        return real_artifact(path, maximum)

    def metadata(path):
        metadata_calls.append(str(path))
        if path == f.journal:
            raise OSError("SYNTHETIC later journal identity unavailable")
        return real_metadata(path)

    monkeypatch.setattr(driver.load, "_artifact", artifact)
    monkeypatch.setattr(driver, "_metadata", metadata)
    if fail_policy:

        def unavailable_policy(path):
            policy_calls.append(str(path))
            raise ValueError("SYNTHETIC policy read failure")

        monkeypatch.setattr(
            driver,
            "OutcomeTelemetryPolicy",
            SimpleNamespace(from_file=unavailable_policy),
        )
    result = driver.collect_control(entry, dict(mode="on"))
    expected_errors = dict(anchors="PermissionError", journal_identity="OSError")
    if fail_policy:
        expected_errors["journal_policy"] = "ValueError"
    assert result["collection_errors"] == expected_errors
    assert result["artifacts"]["anchors"] is None
    assert result["journal_identity"] is None
    for name, path in (
        ("completion", completion),
        ("request", request_path),
        ("journal", f.journal),
    ):
        assert result["artifacts"][name]["sha256"] == driver.phase._sha(originals[path])
        assert artifact_calls.count(str(path)) == 1
    assert artifact_calls.count(str(f.anchors)) == 1
    assert metadata_calls.count(str(f.journal)) == 1
    assert result["source_identity"] == real_metadata(f.source)
    assert result["request_record"] == request
    assert result["policy_context"] == {"retained": "actual prior context"}
    assert (result["expected_journal_policy_sha256"] is None) is fail_policy
    assert len(policy_calls) == (1 if fail_policy else 0)
    assert all(path.read_bytes() == raw for path, raw in originals.items())
