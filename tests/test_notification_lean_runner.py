"""Synthetic child-enrollment tests; never an actual Linux timing result."""

import json
from types import SimpleNamespace

import pytest

import run_notification_lean as study


@pytest.mark.parametrize("mutation", ["arm", "profile", "study_protocol_sha256", "pid", "trailing"])
def test_child_envelope_or_external_pid_mismatch_blocks_qualification(tmp_path, monkeypatch, mutation):
    _, protocol = study.load_protocol()
    arm = protocol["arms"][2]
    metadata = dict(run_id="synthetic", case_id=arm["fixture_case"],
        protocol_sha256=study.SUPPLEMENT_SHA256, source_inventory_sha256="1" * 64,
        fixture_sha256="2" * 64, interpreter_sha256="3" * 64)
    identity = dict(pid=100, process_start_ticks=1, boot_id="synthetic",
        clock_domain=dict(time_namespace_device=1, time_namespace_inode=2, timens_offsets=[], established=False))
    envelope = dict(arm=arm["id"], profile=arm["profile"], study_protocol_sha256=study.PROTOCOL_SHA256)
    bootstrap = dict(kind="bootstrap", boundary=dict(identity=identity), **envelope)
    completion = dict(kind="completion", expected=dict(header=dict(metadata, **identity)),
        safe_to_continue=True, collection_errors={}, **envelope)
    if mutation in envelope:
        completion[mutation] = "WRONG"
    elif mutation == "pid":
        bootstrap["boundary"]["identity"]["pid"] = 101
    raw = study.canonical(bootstrap) + study.canonical(completion)
    if mutation == "trailing":
        raw += b"invalid trailing row\n"
    monkeypatch.setattr(study.subprocess, "Popen", lambda *args, **kwargs: SimpleNamespace(pid=100, returncode=0))
    monkeypatch.setattr(study, "drain_child", lambda *args, **kwargs: (
        dict(stdout=raw, stderr=b""), dict(stdout={}, stderr={}), False, None))
    child = study._launch(tmp_path, arm, metadata)
    assert child["binding_errors"] or child["stdout_decode_error"]
    assert child["bootstrap"] is not None  # Valid prefix remains retained.
    assert (tmp_path / (arm["fixture_case"] + ".child-stdout.raw")).read_bytes() == raw
    recorded = json.loads((tmp_path / (arm["fixture_case"] + ".child-process.json")).read_bytes())
    assert recorded["binding_errors"] or recorded["stdout_decode_error"]


def test_protocol_changes_are_rejected_before_workload(tmp_path, monkeypatch):
    path = tmp_path / "protocol.json"
    raw = study.PROTOCOL.read_bytes()
    path.write_bytes(raw.replace(b'"seed":20261117', b'"seed":20261118'))
    monkeypatch.setattr(study, "PROTOCOL", path)
    with pytest.raises(ValueError, match="protocol changed"):
        study.load_protocol()


def test_contradictory_export_does_not_inherit_embedded_original_validity(tmp_path, monkeypatch):
    arm = study.load_protocol()[1]["arms"][0]
    identifier = arm["fixture_case"]
    for suffix, raw in (("original-result.json", b"{}\n"), ("event-index.json", b"{}\n"),
                        ("audit.raw", b"contradictory\n"), ("queue.raw", b"exact\n")):
        (tmp_path / (identifier + "." + suffix)).write_bytes(raw)
    monkeypatch.setattr(study, "analyze_notification_timing", lambda *args, **kwargs: dict(
        original_result=dict(audit_raw="embedded\n", queue_raw="exact\n"), normal_return_confirmed=True))
    analysis, _, exports, validation = study._evaluate(tmp_path, arm, None)
    assert analysis["normal_return_confirmed"] is True  # Original evaluator output retained.
    assert exports == dict(match=False, reasons=["audit_export_missing_or_differs_from_embedded_original"])
    assert validation["valid"] is False
    assert (tmp_path / (identifier + ".audit.raw")).read_bytes() == b"contradictory\n"


def test_bad_optional_leaf_is_recorded_without_losing_valid_sibling(tmp_path):
    (tmp_path / "bad").symlink_to(tmp_path / "good")
    (tmp_path / "good").write_bytes(b"valid original\n")
    errors = []
    assert study._safe_artifact(tmp_path, "bad", errors) is None
    assert errors and "bad:artifact_unreadable_or_unsafe:" in errors[0]
    assert study._safe_artifact(tmp_path, "good", errors)["sha256"] == study.sha(b"valid original\n")


@pytest.mark.parametrize("analysis", [
    dict(normal_return_confirmed=True, event_index_valid=False),
    dict(normal_return_confirmed=True, event_index_valid=True, original_result={}),
])
def test_footer_alone_cannot_qualify_originals_or_opportunities(analysis):
    arm = study.load_protocol()[1]["arms"][2]
    result = study._original_acceptance(analysis, arm, b'{"events":[]}')
    assert result["valid"] is False and result["reasons"]
