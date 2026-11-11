"""Real-file v2 terminal accounting; no execution or invented safety observations."""

import json
from unittest import mock

import pytest

from azazel_edge.benchmark.benefit import BenefitInputError, analyze
from azazel_edge.benchmark.run_ledger import RunLedger, UNQUALIFIED_REASONS
from test_benefit_comparison import manifest, observations
from test_benefit_run_ledger import private_path


@pytest.mark.parametrize("reason", sorted(UNQUALIFIED_REASONS))
def test_unqualified_is_terminal_and_missing_in_existing_analysis(tmp_path, reason):
    path, registered = private_path(tmp_path), manifest()
    receipts = observations(registered)["runs"]
    first = receipts[0]
    with RunLedger(
        path, manifest=registered, allow_unqualified_attempts=True
    ) as ledger:
        ledger.start(first["assignment_id"], first["run_id"])
        ledger.record_unqualified_attempt(
            first["assignment_id"], first["run_id"], reason, "a" * 64
        )
        for receipt in receipts[1:]:
            ledger.start(receipt["assignment_id"], receipt["run_id"])
            ledger.finish(receipt)
        snapshot, head = ledger.snapshot(), ledger.head_sha256
        row = next(
            row
            for row in snapshot["assignments"]
            if row["assignment_id"] == first["assignment_id"]
        )
        assert row == dict(
            assignment_id=first["assignment_id"],
            run_id=first["run_id"],
            status="unqualified",
            reason_code=reason,
            evidence_sha256="a" * 64,
        )
        assert len(snapshot["observations"]["runs"]) == 3
        assert all(
            row["run_id"] != first["run_id"] for row in snapshot["observations"]["runs"]
        )
        report = analyze(registered, snapshot["observations"])
        assert report["assigned_runs"] == 4 and report["missing_runs"] == 1
        assert report["complete_pairs"] == 1 and report["incomplete_pairs"]
        assert (
            report["measurement_gate"] == "inconclusive_missing_or_insufficient_pairs"
        )
        for operation in (
            lambda: ledger.start(first["assignment_id"], "retry"),
            lambda: ledger.start(receipts[1]["assignment_id"], first["run_id"]),
            lambda: ledger.finish(first),
            lambda: ledger.record_unqualified_attempt(
                first["assignment_id"], first["run_id"], reason, "a" * 64
            ),
        ):
            with pytest.raises(BenefitInputError):
                operation()
            assert ledger.head_sha256 == head
    with RunLedger(path, expected_head=head, allow_unqualified_attempts=True) as ledger:
        assert ledger.snapshot() == snapshot
        with pytest.raises(BenefitInputError):
            ledger.finish(first)


@pytest.mark.parametrize("create_mode,reopen_mode", [(False, True), (True, False)])
def test_schema_mode_never_auto_upgrades_or_downgrades(
    tmp_path, create_mode, reopen_mode
):
    path = private_path(tmp_path)
    with RunLedger(
        path, manifest=manifest(), allow_unqualified_attempts=create_mode
    ) as ledger:
        head = ledger.head_sha256
    raw = path.read_bytes()
    with pytest.raises(BenefitInputError, match="frozen manifest"):
        RunLedger(path, expected_head=head, allow_unqualified_attempts=reopen_mode)
    assert path.read_bytes() == raw
    with RunLedger(path, expected_head=head, allow_unqualified_attempts=create_mode):
        pass


def test_default_v1_bytes_and_snapshot_are_identical_to_explicit_false(tmp_path):
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir(mode=0o700)
    right.mkdir(mode=0o700)
    with (
        RunLedger(left / "ledger", manifest=manifest()) as default,
        RunLedger(
            right / "ledger", manifest=manifest(), allow_unqualified_attempts=False
        ) as explicit,
    ):
        assert default.snapshot() == explicit.snapshot()
        for ledger in (default, explicit):
            ledger.start("0-block", "unfinished")
            with pytest.raises(BenefitInputError, match="explicit v2"):
                ledger.record_unqualified_attempt(
                    "0-block", "unfinished", "clock_withheld", "a" * 64
                )
            with pytest.raises(BenefitInputError, match="explicit v2"):
                ledger._append(
                    dict(
                        op="unqualified_attempt",
                        assignment_id="0-block",
                        run_id="unfinished",
                        reason_code="clock_withheld",
                        evidence_sha256="a" * 64,
                    )
                )
        assert default.snapshot() == explicit.snapshot()
    assert (left / "ledger").read_bytes() == (right / "ledger").read_bytes()
    assert json.loads((left / "ledger").read_bytes().splitlines()[0])["event"][
        "schema_version"
    ].endswith("/v1")


@pytest.mark.parametrize(
    "field,value",
    [
        ("assignment_id", "unknown"),
        ("run_id", "other"),
        ("reason_code", "arbitrary"),
        ("reason_code", []),
        ("evidence_sha256", "A" * 64),
        ("evidence_sha256", "a" * 63),
        ("evidence_sha256", False),
    ],
)
def test_invalid_attempt_never_mutates_ledger(tmp_path, field, value):
    path = private_path(tmp_path)
    with RunLedger(
        path, manifest=manifest(), allow_unqualified_attempts=True
    ) as ledger:
        arguments = dict(
            assignment_id="0-block",
            run_id="run-one",
            reason_code="clock_withheld",
            evidence_sha256="a" * 64,
        )
        with pytest.raises(BenefitInputError):
            ledger.record_unqualified_attempt(**arguments)
        ledger.start("0-block", "run-one")
        arguments[field] = value
        raw, head = path.read_bytes(), ledger.head_sha256
        with pytest.raises(BenefitInputError):
            ledger.record_unqualified_attempt(**arguments)
        assert path.read_bytes() == raw and ledger.head_sha256 == head


def test_no_extra_metrics_or_safety_counts_can_enter_attempt_event(tmp_path):
    path = private_path(tmp_path)
    with RunLedger(
        path, manifest=manifest(), allow_unqualified_attempts=True
    ) as ledger:
        ledger.start("0-block", "one")
        before = path.read_bytes()
        with pytest.raises(BenefitInputError):
            ledger._append(
                dict(
                    op="unqualified_attempt",
                    assignment_id="0-block",
                    run_id="one",
                    reason_code="safety_unmeasured",
                    evidence_sha256="a" * 64,
                    safety_violations={},
                )
            )
        assert path.read_bytes() == before
        ledger.record_unqualified_attempt(
            "0-block", "one", "safety_unmeasured", "a" * 64
        )
        event = json.loads(path.read_bytes().splitlines()[-1])["event"]
        assert set(event) == {
            "op",
            "assignment_id",
            "run_id",
            "reason_code",
            "evidence_sha256",
        }
        assert ledger.snapshot()["observations"]["runs"] == []


def test_unqualified_append_fsync_failure_poison_retains_acknowledged_head(tmp_path):
    path = private_path(tmp_path)
    with RunLedger(
        path, manifest=manifest(), allow_unqualified_attempts=True
    ) as ledger:
        retained = ledger.start("0-block", "uncertain")
        with mock.patch("os.fsync", side_effect=OSError("durability unknown")):
            with pytest.raises(OSError):
                ledger.record_unqualified_attempt(
                    "0-block", "uncertain", "execution_failed", "a" * 64
                )
        assert ledger.head_sha256 == retained
        with pytest.raises(BenefitInputError):
            ledger.snapshot()
        with pytest.raises(BenefitInputError):
            ledger.record_unqualified_attempt(
                "0-block", "uncertain", "execution_failed", "a" * 64
            )
    raw = path.read_bytes()
    with pytest.raises(BenefitInputError):
        RunLedger(path, expected_head=retained, allow_unqualified_attempts=True)
    assert path.read_bytes() == raw


def test_v2_lock_stale_head_and_incomplete_tail_remain_fail_closed(tmp_path):
    path = private_path(tmp_path)
    with RunLedger(
        path, manifest=manifest(), allow_unqualified_attempts=True
    ) as ledger:
        stale = ledger.head_sha256
        with pytest.raises(BenefitInputError, match="already held"):
            RunLedger(path, expected_head=stale, allow_unqualified_attempts=True)
        ledger.start("0-block", "one")
        head = ledger.record_unqualified_attempt(
            "0-block", "one", "operator_interrupted", "a" * 64
        )
    for expected in (None, stale):
        with pytest.raises(BenefitInputError):
            RunLedger(path, expected_head=expected, allow_unqualified_attempts=True)
    with path.open("ab") as stream:
        stream.write(b'{"partial":')
    raw = path.read_bytes()
    with pytest.raises(BenefitInputError, match="incomplete"):
        RunLedger(path, expected_head=head, allow_unqualified_attempts=True)
    assert path.read_bytes() == raw


@pytest.mark.parametrize("mode", [1, "true", None, []])
def test_mode_requires_literal_boolean_before_any_creation(tmp_path, mode):
    path = private_path(tmp_path)
    with pytest.raises(BenefitInputError, match="boolean"):
        RunLedger(path, manifest=manifest(), allow_unqualified_attempts=mode)
    assert not path.exists()
