"""Real-file crash, competing writer and accounting controls for lab runs."""
import copy
import os
from unittest import mock

import pytest

from azazel_edge.benchmark.benefit import BenefitInputError, analyze
from azazel_edge.benchmark.run_ledger import RunLedger
from test_benefit_comparison import manifest, observations


def private_path(tmp_path):
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    return parent / "runs.jsonl"


def test_all_assignments_frozen_and_complete_receipts_reuse_existing_analysis(tmp_path):
    path, m = private_path(tmp_path), manifest()
    with RunLedger(path, manifest=m) as ledger:
        assert len(ledger.snapshot()["assignments"]) == 4
        assert {r["status"] for r in ledger.snapshot()["assignments"]} == {"pending"}
        for receipt in observations(m)["runs"]:
            ledger.start(receipt["assignment_id"], receipt["run_id"])
            ledger.finish(receipt)
        expected = analyze(m, observations(m))
        assert analyze(m, ledger.snapshot()["observations"]) == expected
        head = ledger.head_sha256
    with RunLedger(path, expected_head=head) as reopened:
        assert analyze(m, reopened.snapshot()["observations"]) == expected
        assert reopened.head_sha256 == head


def test_crashed_and_unstarted_work_never_disappears_or_restarts(tmp_path):
    path, m = private_path(tmp_path), manifest()
    with RunLedger(path, manifest=m) as ledger:
        head = ledger.start("0-block", "interrupted")
    with RunLedger(path, expected_head=head) as ledger:
        rows = ledger.snapshot()["assignments"]
        assert sum(r["status"] == "running" for r in rows) == 1
        assert sum(r["status"] == "pending" for r in rows) == 3
        report = analyze(m, ledger.snapshot()["observations"])
        assert report["assigned_runs"] == report["missing_runs"] == 4
        assert report["measurement_gate"] == "inconclusive_missing_or_insufficient_pairs"
        with pytest.raises(BenefitInputError, match="repeated"):
            ledger.start("0-block", "retry-cannot-hide-crash")


def test_competing_open_and_stale_checkpoint_refuse_without_mutation(tmp_path):
    path = private_path(tmp_path)
    with RunLedger(path, manifest=manifest()) as ledger:
        stale = ledger.head_sha256
        with pytest.raises(BenefitInputError, match="already held"):
            RunLedger(path, expected_head=stale)
        head = ledger.start("0-block", "run-one")
    before = path.read_bytes()
    for checkpoint in (None, stale, "0" * 64):
        with pytest.raises(BenefitInputError):
            RunLedger(path, expected_head=checkpoint)
        assert path.read_bytes() == before
    with RunLedger(path, expected_head=head):
        pass


@pytest.mark.parametrize("fault", ["tail", "truncate", "edit", "duplicate", "nonfinite"])
def test_tampered_or_partial_history_is_never_repaired(tmp_path, fault):
    path = private_path(tmp_path)
    with RunLedger(path, manifest=manifest()) as ledger:
        ledger.start("0-block", "first")
        head = ledger.head_sha256
    raw = path.read_bytes()
    if fault == "tail":
        raw += b'{"incomplete":'
    elif fault == "truncate":
        raw = raw.splitlines(keepends=True)[0]
    elif fault == "edit":
        raw = raw.replace(b'"first"', b'"other"')
    elif fault == "duplicate":
        raw += raw.splitlines(keepends=True)[-1]
    else:
        raw = raw.replace(b'"sequence":1', b'"sequence":NaN')
    path.write_bytes(raw)
    with pytest.raises(BenefitInputError):
        RunLedger(path, expected_head=head)
    assert path.read_bytes() == raw


def test_fsync_failure_poisoned_writer_does_not_publish_or_retry(tmp_path):
    path = private_path(tmp_path)
    with RunLedger(path, manifest=manifest()) as ledger:
        retained = ledger.head_sha256
        with mock.patch("os.fsync", side_effect=OSError("disk failure")):
            with pytest.raises(OSError):
                ledger.start("0-block", "uncertain")
        assert ledger.head_sha256 == retained
        for operation in (lambda: ledger.snapshot(), lambda: ledger.start("0-block", "retry")):
            with pytest.raises(BenefitInputError):
                operation()
    # Even if bytes became visible, the last acknowledged checkpoint cannot
    # authorize reopening past an uncertain durability boundary.
    with pytest.raises(BenefitInputError):
        RunLedger(path, expected_head=retained)


def test_private_regular_single_link_file_and_no_overwrite_required(tmp_path):
    path = private_path(tmp_path)
    with RunLedger(path, manifest=manifest()) as ledger:
        head = ledger.head_sha256
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        RunLedger(path, manifest=manifest())
    assert path.read_bytes() == before
    alias = path.parent / "alias"
    alias.symlink_to(path)
    with pytest.raises(OSError):
        RunLedger(alias, expected_head=head)
    alias.unlink()
    os.link(path, alias)
    with pytest.raises(BenefitInputError, match="unsafe"):
        RunLedger(path, expected_head=head)
    alias.unlink()
    path.chmod(0o644)
    with pytest.raises(BenefitInputError, match="unsafe"):
        RunLedger(path, expected_head=head)
    path.chmod(0o600)
    path.parent.chmod(0o755)
    with pytest.raises(BenefitInputError, match="private"):
        RunLedger(path, expected_head=head)


def test_invalid_or_duplicate_finalization_leaves_head_unchanged(tmp_path):
    path, m = private_path(tmp_path), manifest()
    receipt = observations(m)["runs"][0]
    with RunLedger(path, manifest=m) as ledger:
        initial = ledger.head_sha256
        with pytest.raises(BenefitInputError):
            ledger.finish(receipt)
        assert ledger.head_sha256 == initial
        ledger.start(receipt["assignment_id"], receipt["run_id"])
        head = ledger.head_sha256
        for field, value in (("run_id", "wrong"), ("safety_violations", {}), ("legitimate_transactions", 0)):
            bad = copy.deepcopy(receipt)
            bad[field] = value
            with pytest.raises(BenefitInputError):
                ledger.finish(bad)
            assert ledger.head_sha256 == head
        ledger.finish(receipt)
        head = ledger.head_sha256
        with pytest.raises(BenefitInputError):
            ledger.finish(receipt)
        assert ledger.head_sha256 == head


def test_output_and_manifest_cannot_mutate_internal_state(tmp_path):
    path, m = private_path(tmp_path), manifest()
    with RunLedger(path, manifest=m) as ledger:
        frozen = ledger.manifest
        m["assignments"].clear()
        ledger.manifest["assignments"].clear()
        exported = ledger.snapshot()
        exported["assignments"].clear()
        assert ledger.manifest == frozen
        assert len(ledger.snapshot()["assignments"]) == 4


def test_no_traffic_commands_or_model_are_needed_for_accounting(tmp_path):
    path = private_path(tmp_path)
    with mock.patch("socket.socket", side_effect=AssertionError("network")), mock.patch("subprocess.Popen", side_effect=AssertionError("process")):
        with RunLedger(path, manifest=manifest()) as ledger:
            assert len(ledger.snapshot()["assignments"]) == 4


def test_snapshot_has_separate_finite_export_budget_and_rejects_raw_payloads(tmp_path, monkeypatch):
    from azazel_edge.benchmark import run_ledger

    path, m = private_path(tmp_path), manifest()
    with RunLedger(path, manifest=m) as ledger:
        # Each record stays below this reduced record cap; the complete export
        # legitimately repeats receipt projections and is much larger.
        monkeypatch.setattr(run_ledger, "MAX_BYTES", 1500)
        for receipt in observations(m)["runs"]:
            ledger.start(receipt["assignment_id"], receipt["run_id"])
            bad = {**receipt, "raw_capture_note": "x" * 200}
            before = ledger.head_sha256
            with pytest.raises(BenefitInputError, match="unsupported"):
                ledger.finish(bad)
            assert ledger.head_sha256 == before
            ledger.finish(receipt)
        assert len(ledger.snapshot()["observations"]["runs"]) == 4


@pytest.mark.parametrize("fault", ["replace", "append", "link", "permissions"])
def test_external_file_identity_or_length_changes_poison_writer(tmp_path, fault):
    path = private_path(tmp_path)
    with RunLedger(path, manifest=manifest()) as ledger:
        head = ledger.head_sha256
        if fault == "replace":
            path.rename(path.with_suffix(".retained"))
            path.write_bytes(b"")
        elif fault == "append":
            with path.open("ab") as stream:
                stream.write(b"external")
        elif fault == "link":
            os.link(path, path.with_suffix(".linked"))
        else:
            path.chmod(0o644)
        before = path.read_bytes()
        with pytest.raises(BenefitInputError, match="changed outside"):
            ledger.start("0-block", "not-started")
        assert ledger.head_sha256 == head and path.read_bytes() == before
        with pytest.raises(BenefitInputError):
            ledger.snapshot()
