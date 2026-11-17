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
