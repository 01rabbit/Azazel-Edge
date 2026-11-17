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


def test_changed_one_original_blocks_even_when_evaluation_would_pass(tmp_path, monkeypatch):
    """Fault-inject orchestration only; no processes or kernel capture exist."""
    source = tmp_path / "source.py"
    source.write_bytes(b"SYNTHETIC source\n")
    monkeypatch.setattr(runner, "ROOT", tmp_path)
    monkeypatch.setattr(runner, "SOURCES", ("source.py",))
    identity = dict(pid=123, data_kind="SYNTHETIC")
    monkeypatch.setattr(runner, "boundary", lambda: dict(identity=identity))
    monkeypatch.setenv("EDGE_CAPTURE_CLOSE_SOURCE_HEAD", "1" * 40)
    monkeypatch.setenv("EDGE_CAPTURE_CLOSE_SOURCE_TREE", "2" * 40)
    output = tmp_path / "study"

    def launch(directory, case, run_id, inventory_hash):
        raw = {name: b"{}\n" for name in runner.ORIGINALS}
        raw["plan.json"] = runner.canonical(dict(controller_identity=identity, case_id=case,
            run_id=run_id, source_inventory_sha256=inventory_hash))
        for name, value in raw.items():
            (directory / name).write_bytes(value)
        expected = {runner.PINS[name]: runner.sha(value) for name, value in raw.items()}
        return dict(returncode=0, timed_out=False, capture_errors=[], binding_errors=[], stdout_decode_error=None,
            streams={}, bootstrap=dict(boundary=dict(identity=identity)), completion=dict(safe_to_continue=True, expected=expected))

    called = []
    def evaluate(*args, **kwargs):
        called.append(1)
        if len(called) == 1:
            (output / "clean/collector.json").write_bytes(b"SYNTHETIC changed after evaluation input\n")
        return dict(data_kind="SYNTHETIC_FAULT_INJECTION")

    monkeypatch.setattr(runner, "launch", launch)
    monkeypatch.setattr(runner, "evaluate_capture_close", evaluate)
    monkeypatch.setattr(runner, "disposition", lambda *args: True)
    result = runner.run(output)
    assert all(entry["expected_disposition"] for entry in result["cases"])
    assert "clean/collector.json:changed_between_evaluation_and_inventory" in result["blockers"]
    assert len(result["blockers"]) == 1
    manifest = json.loads((output / "manifest.json").read_bytes())
    assert manifest["files"]["clean/plan.json"]["sha256"] == result["cases"][0]["expected"]["plan_sha256"]
    assert manifest["files"]["clean/collector.json"]["sha256"] != result["cases"][0]["expected"]["collector_sha256"]
