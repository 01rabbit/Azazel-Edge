"""Real signed terminal bytes; mocked journal/OS role boundaries, no VM claim."""

import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from azazel_edge.outcome import input_resume as driver
from azazel_edge.outcome import input_terminal as terminal
from azazel_edge.outcome.input_auth import SourceVerifier
from azazel_edge.outcome.input_cursor import BoundedInput, InputLine
from azazel_edge.outcome.input_witness import InputAuthentication
from azazel_edge.outcome.journal import OutcomeJournalError
from test_outcome_live_origin import enrolled, frame, signed_frame


class Journal:
    def __init__(self, source, before, log):
        self.input_source = source
        self.position = dict(before)
        self.log = log
        self.data = dict(
            continuity_available=True,
            new_admission_closed=False,
            input_recovery_pending=False,
            pending=2,
            lost=0,
            committed=1,
            counters={"write_failures": 0},
            sequence=10,
            chain_head="b" * 64,
            bytes=200,
            input_position=self.position,
        )

    def status(self):
        return copy.deepcopy(self.data)

    def input_position(self):
        return dict(self.position)

    def advance_input(self, position, *, missed):
        assert missed is True
        self.log.append("control_cursor")
        self.position = dict(position)
        self.data["input_position"] = dict(position)
        self.data["sequence"] += 1

    def close(self):
        self.log.append("durable_close_lost_ack")
        self.data["sequence"] += self.data["pending"]
        self.data["continuity_available"] = False
        self.data["lost"] += self.data["pending"]
        self.data["pending"] = 0
        self.data["sequence"] += 1
        self.data["bytes"] += 50
        v = SourceVerifier(self.input_source.authentication.policy)
        tip = v.verify(self.input_source.current)
        self.input_source.authentication.client.state = dict(
            journal_seq=self.data["sequence"],
            journal_head=self.data["chain_head"],
            journal_size=self.data["bytes"],
            source_seq=tip["seq"],
            source_head=tip["head"],
            source_size=tip["size"],
            source_sha256=tip["sha256"],
        )

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def fixture(tmp_path, *, kind="session_end", tail=b""):
    p, key = enrolled(tmp_path)
    v = SourceVerifier(p)
    raw = b""
    for n, f in enumerate([frame("session_prepare", 0), frame("session_start", 1)], 1):
        raw += signed_frame(p, key, f, n, v.head)
        v.verify(raw)
    before = dict(offset=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    last = signed_frame(p, key, frame(kind, 2), 3, v.head)
    raw += last
    decoded = SourceVerifier.unwrap(last)
    line = InputLine(
        decoded, dict(offset=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    )
    source = object.__new__(BoundedInput)
    authentication = object.__new__(InputAuthentication)
    authentication.policy = p
    authentication.verifier = SourceVerifier(p)
    authentication.client = SimpleNamespace(state=None)
    source.authentication = authentication
    source.current = raw + tail
    source.fd = None
    source.parent = None
    log = []

    def snapshot(position, *, require_complete=False):
        assert require_complete or position == before or position == line.position
        data = source.current
        if require_complete and not data.endswith(b"\n"):
            raise OutcomeJournalError("partial source")
        source.authentication.verify(data)
        return data

    source.snapshot = snapshot
    source.lines = lambda position, data: iter([line])
    source.close = lambda: log.append("source_close")
    journal = Journal(source, before, log)
    return SimpleNamespace(
        p=p,
        key=key,
        source=source,
        journal=journal,
        line=line,
        before=before,
        raw=raw,
        last=last,
        log=log,
    )


def prepare(f):
    return terminal.prepare_terminal_stop(
        f.line, f.journal, registration_sha256=f.p.data["origin_registration_sha256"]
    )


def test_real_signed_terminal_control_preserves_bytes_and_pending_losses(tmp_path):
    f = fixture(tmp_path)
    result = prepare(f)
    assert f.journal.status()["pending"] == 2 and f.journal.status()["committed"] == 1
    assert f.journal.input_position() == f.line.position
    f.journal.close()
    receipt = result.after_journal_close(f.journal, f.source)
    assert receipt.signed_wire == f.last and receipt.decoded_record == f.line.raw
    assert receipt.to_dict()["signed_wire_sha256"] == hashlib.sha256(f.last).hexdigest()
    assert (
        receipt.to_dict()["decoded_record_sha256"]
        == hashlib.sha256(f.line.raw).hexdigest()
    )
    assert (
        receipt.source_position_before == f.before
        and receipt.source_position_after == f.line.position
    )
    assert receipt.pending_windows_lost == 2
    assert (
        receipt.to_dict()["resume_authorized"] is False
        and receipt.to_dict()["measurement_completed"] is False
    )
    assert f.source.current == f.raw


@pytest.mark.parametrize(
    "fault",
    [
        "wrong_registration",
        "signature",
        "trailing_partial",
        "trailing_complete",
        "open_session",
        "other_boundary",
        "changed_decoded",
        "wrong_cursor",
        "poison",
        "sealed",
        "recovering",
        "source_class",
        "auth_class",
    ],
)
def test_terminal_refusal_does_not_advance_cursor(tmp_path, fault):
    f = fixture(tmp_path)
    registration = f.p.data["origin_registration_sha256"]
    if fault == "wrong_registration":
        registration = "0" * 64
    elif fault == "signature":
        f.source.current = f.raw.replace(b'"signature":"', b'"signature":"0', 1)
    elif fault == "trailing_partial":
        f.source.current += b"{"
    elif fault == "trailing_complete":
        f.source.current += f.last
    elif fault == "open_session":
        f = fixture(tmp_path / "open", kind="decision_execution")
    elif fault == "other_boundary":
        f = fixture(tmp_path / "other", kind="session_start")
    elif fault == "changed_decoded":
        f.line = InputLine(f.line.raw + b" ", f.line.position)
    elif fault == "wrong_cursor":
        f.line = InputLine(f.line.raw, dict(offset=1, sha256="0" * 64))
    elif fault == "poison":
        f.journal.data["continuity_available"] = False
    elif fault == "sealed":
        f.journal.data["new_admission_closed"] = True
    elif fault == "recovering":
        f.journal.data["input_recovery_pending"] = True
    elif fault == "source_class":
        f.journal.input_source = SimpleNamespace()
    else:
        f.source.authentication = SimpleNamespace()
    with pytest.raises((OutcomeJournalError, ValueError)):
        terminal.prepare_terminal_stop(
            f.line, f.journal, registration_sha256=registration
        )
    assert f.journal.input_position() == f.before
    assert f.journal.data["pending"] == 2


@pytest.mark.parametrize(
    "fault",
    [
        "source_after_cursor",
        "source_after_close",
        "lost",
        "commit",
        "write_failure",
        "witness",
        "journal_cursor",
        "unclosed",
    ],
)
def test_no_result_after_mutation_close_or_protected_ack_gap(tmp_path, fault):
    f = fixture(tmp_path)
    if fault == "source_after_cursor":
        original = f.journal.advance_input

        def advance(*args, **kwargs):
            original(*args, **kwargs)
            f.source.current += b"{"

        f.journal.advance_input = advance
        with pytest.raises(OutcomeJournalError):
            prepare(f)
        assert f.journal.input_position() == f.line.position  # no rollback/repair
        return
    pending = prepare(f)
    if fault != "unclosed":
        f.journal.close()
    if fault == "source_after_close":
        f.source.current += b"{"
    elif fault == "lost":
        f.journal.data["lost"] -= 1
    elif fault == "commit":
        f.journal.data["committed"] += 1
    elif fault == "write_failure":
        f.journal.data["counters"]["write_failures"] = 1
    elif fault == "witness":
        f.source.authentication.client.state["journal_head"] = "0" * 64
    elif fault == "journal_cursor":
        f.journal.data["input_position"] = f.before
    with pytest.raises(OutcomeJournalError):
        pending.after_journal_close(f.journal, f.source)


@pytest.mark.parametrize(
    "schema",
    [
        "outcome-live-origin-registration/v1",
        "outcome-live-origin-registration/v3",
        "outcome-live-origin-registration/v4",
    ],
)
def test_opt_in_uses_existing_registration_validator_and_requires_v4(tmp_path, schema):
    f = fixture(tmp_path)
    with patch.object(
        terminal,
        "registration",
        return_value=dict(schema_version=schema, mode="live-core"),
    ) as validate:
        if schema.endswith("/v4"):
            assert (
                terminal.validate_terminal_registration(
                    f.source.authentication, Path("/protected/origin.json")
                )
                == f.p.data["origin_registration_sha256"]
            )
        else:
            with pytest.raises(OutcomeJournalError):
                terminal.validate_terminal_registration(
                    f.source.authentication, Path("/protected/origin.json")
                )
        validate.assert_called_once_with(f.p, Path("/protected/origin.json"))
    with pytest.raises(OutcomeJournalError):
        terminal.validate_terminal_registration(None, Path("/protected/origin.json"))


def run_driver(f, *, enabled=True):
    from azazel_edge.outcome import input_witness
    from test_outcome_telemetry_g3 import policy

    class Collector:
        def __init__(self, **kwargs):
            pass

        def record_sample(self, *, epoch):
            f.log.append("actual_loop_sample")

        def observe_event(self, *a, **k):
            raise AssertionError("terminal reached activity")

        def finalize_due(self, *a, **k):
            raise AssertionError("terminal force-finalized")

    p = f.p.data
    with (
        patch.object(driver, "BoundedInput", lambda *a, **k: f.source),
        patch.object(driver, "ObservationJournal", lambda *a, **k: f.journal),
        patch.object(driver, "recover_input", lambda *a: None),
        patch.object(driver, "OutcomeTelemetryCollector", Collector),
        patch.object(driver.OutcomeTelemetryPolicy, "from_file", return_value=policy()),
        patch.object(
            input_witness, "InputAuthentication", lambda *a: f.source.authentication
        ),
        patch("azazel_edge.outcome.input_auth.TrustPolicy.from_file", return_value=f.p),
        patch.object(
            terminal,
            "validate_terminal_registration",
            return_value=p["origin_registration_sha256"],
        ),
    ):
        return driver.run_live_resumable(
            input_path=Path(p["source_path"]),
            output_path=Path(p["source_path"]).with_name("outcomes"),
            policy_path=Path("unused-policy"),
            interface="br0",
            poll_seconds=0.05,
            sample_interval_seconds=1,
            max_output_bytes=1024,
            journal_directory=Path(p["journal_directory"]),
            journal_scope=p["scope_ref"],
            journal_boot_id="boot-a",
            initialize_journal=False,
            journal_max_bytes=p["journal_max_bytes"],
            journal_max_identities=4096,
            input_max_bytes=p["input_max_bytes"],
            input_max_records=p["input_max_records"],
            authentication_policy=Path("unused-trust"),
            terminal_stop_registration=Path("protected-origin") if enabled else None,
        )


def test_optional_driver_returns_control_only_after_durable_close_and_source_close(
    tmp_path,
):
    f = fixture(tmp_path)
    result = run_driver(f)
    f.log.append("returned")
    assert isinstance(result, terminal.TerminalControlStop)
    assert f.log == [
        "actual_loop_sample",
        "control_cursor",
        "durable_close_lost_ack",
        "source_close",
        "returned",
    ]
    assert f.journal.data["committed"] == 1 and f.journal.data["lost"] == 2


def test_default_driver_still_refuses_before_terminal_cursor(tmp_path):
    f = fixture(tmp_path)
    with pytest.raises(
        OutcomeJournalError, match="requires verified observer recovery"
    ):
        run_driver(f, enabled=False)
    assert f.journal.input_position() == f.before
    assert "control_cursor" not in f.log


def test_driver_never_returns_result_when_journal_close_fails(tmp_path):
    f = fixture(tmp_path)

    def fail():
        f.log.append("close_failed")
        raise OSError("witness unavailable at close")

    f.journal.close = fail
    with pytest.raises(OSError):
        run_driver(f)
    assert f.log[-2:] == ["close_failed", "source_close"]


def test_missing_auth_refuses_optin_before_journal_construction(tmp_path):
    called = []
    with (
        patch.object(
            driver, "ObservationJournal", lambda *a, **k: called.append("journal")
        ),
        patch.object(driver.OutcomeTelemetryPolicy, "from_file", return_value=None),
    ):
        with pytest.raises(OutcomeJournalError, match="authenticated"):
            driver.run_live_resumable(
                input_path=tmp_path / "input",
                output_path=tmp_path / "output",
                policy_path=tmp_path / "policy",
                interface="br0",
                poll_seconds=0.05,
                sample_interval_seconds=1,
                max_output_bytes=1024,
                journal_directory=tmp_path / "journal",
                journal_scope="scope",
                journal_boot_id="boot",
                initialize_journal=False,
                journal_max_bytes=131072,
                journal_max_identities=4096,
                input_max_bytes=65536,
                input_max_records=1024,
                terminal_stop_registration=tmp_path / "registration",
            )
    assert called == []


def test_genuinely_valid_later_session_prevents_terminal_stop(tmp_path):
    f = fixture(tmp_path)
    verifier = SourceVerifier(f.p)
    verifier.verify(f.raw)
    for index, wire in enumerate(
        [
            frame("session_prepare", 0, "b" * 32),
            frame("session_start", 1, "b" * 32),
            frame("session_end", 2, "b" * 32),
        ],
        4,
    ):
        f.source.current += signed_frame(f.p, f.key, wire, index, verifier.head)
        verifier.verify(f.source.current)
    assert verifier.live_state.closed and len(verifier.live_state.sessions) == 2
    with pytest.raises(OutcomeJournalError):
        prepare(f)
    assert f.journal.input_position() == f.before


def test_final_witness_source_ack_must_match_original_closed_tip(tmp_path):
    f = fixture(tmp_path)
    pending = prepare(f)
    f.journal.close()
    f.source.authentication.client.state["source_size"] += 1
    with pytest.raises(OutcomeJournalError):
        pending.after_journal_close(f.journal, f.source)


def test_empty_pending_does_not_allow_result_before_real_journal_close(tmp_path):
    f = fixture(tmp_path)
    f.journal.data["pending"] = 0
    pending = prepare(f)
    with pytest.raises(OutcomeJournalError, match="close not complete"):
        pending.after_journal_close(f.journal, f.source)
    f.journal.close()
    f.journal.data["sequence"] -= 1
    with pytest.raises(OutcomeJournalError, match="close not complete"):
        pending.after_journal_close(f.journal, f.source)
