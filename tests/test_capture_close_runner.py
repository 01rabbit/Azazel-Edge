"""Synthetic orchestration negatives, not a real sealed-capture trial."""

import json

import pytest

import run_capture_close as runner


@pytest.mark.parametrize("case", runner.CASES)
def test_generic_false_or_missing_analysis_never_passes_a_negative_case(case):
    raw = {"terminal.json": b'{}\n', "collector.json": b'{}\n', "capture.raw": b""}
    assert runner.disposition(case, {}, raw) is False
    assert runner.disposition(case, dict(schema_version="edge-capture-close-analysis/v1"), raw) is False


def test_missing_counter_case_requires_the_intended_read_data_and_fault():
    analysis = dict(schema_version="edge-capture-close-analysis/v1", known_matching_ids=list(range(16)),
        finite_accounting_complete=False, complete_finite_capture=False, terminal_missing_count=None, **runner.FLAGS)
    raw = dict(**{"terminal.json": b'{"W":{"returncode":0},"S":{"result":"sealed"}}\n',
        "collector.json": b'{"complete":true}\n',
        "capture.raw": b'{"kind":"terminal","declared_lost":0}\n'})
    assert runner.disposition("missing_loss_counter", analysis, raw) is False
    raw["capture.raw"] = b'{"kind":"terminal"}\n'
    assert runner.disposition("missing_loss_counter", analysis, raw) is True
    raw["collector.json"] = b'{"complete":false}\n'
    assert runner.disposition("missing_loss_counter", analysis, raw) is False


def test_changed_frozen_protocol_is_rejected_before_launch(tmp_path, monkeypatch):
    raw = runner.PROTOCOL.read_bytes()
    changed = tmp_path / "protocol.json"
    changed.write_bytes(raw.replace(b'"required_seals":15', b'"required_seals":7'))
    monkeypatch.setattr(runner, "PROTOCOL", changed)
    with pytest.raises(ValueError, match="frozen_protocol_changed"):
        runner.protocol()


def test_duplicate_reply_or_partial_tail_preserves_bootstrap_but_is_not_valid():
    bootstrap = dict(kind="bootstrap", case_id="clean")
    completion = dict(kind="completion", safe_to_continue=True)
    raw = runner.canonical(bootstrap) + runner.canonical(completion)
    for suffix in (runner.canonical(completion), b'{"kind":"completion"'):
        rows, error = runner._reply(raw + suffix)
        assert error and rows[0] == bootstrap
    rows, error = runner._reply(b'{"kind":"bootstrap","kind":"completion"}\n')
    assert error and rows == []


def test_unsafe_leaf_does_not_change_readable_original(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"raw evidence\n")
    alias = tmp_path / "alias"
    alias.symlink_to(original)
    with pytest.raises((OSError, ValueError)):
        runner.read(alias)
    assert runner.read(original) == b"raw evidence\n"


def test_nonfinite_reply_is_not_accepted():
    rows, error = runner._reply(b'{"kind":"bootstrap","pid":NaN}\n')
    assert rows == [] and error
    assert json.loads(runner.canonical(dict(data_kind="SYNTHETIC"))) == dict(data_kind="SYNTHETIC")
