"""Explicit authenticated terminal CONTROL stop, never observation or resumption."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .input_auth import SourceVerifier
from .input_cursor import BoundedInput
from .input_live import registration
from .input_witness import InputAuthentication
from .journal import OutcomeJournalError, _parse, _json


def _need(value, message):
    if not value:
        raise OutcomeJournalError(message)


def validate_terminal_registration(authentication, path):
    """Existing public registration validation only; never native_gate/key access."""
    _need(
        type(authentication) is InputAuthentication,
        "terminal stop requires authenticated input",
    )
    value = registration(authentication.policy, path)
    _need(
        value["schema_version"] == "outcome-live-origin-registration/v4"
        and value["mode"] == "live-core",
        "terminal stop requires registered v4 normal core",
    )
    return authentication.policy.data["origin_registration_sha256"]


@dataclass(frozen=True)
class TerminalControlStop:
    registration_sha256: str
    session_ref: str
    native_seq: int
    source_position_before: dict
    source_position_after: dict
    signed_wire: bytes = field(repr=False)
    decoded_record: bytes = field(repr=False)
    pending_windows_lost: int

    def to_dict(self):
        return dict(
            disposition="verified_terminal_control_stop",
            cursor_disposition="control_not_observed",
            cursor_missed=True,
            registration_sha256=self.registration_sha256,
            session_ref=self.session_ref,
            native_seq=self.native_seq,
            source_position_before=dict(self.source_position_before),
            source_position_after=dict(self.source_position_after),
            signed_wire_sha256=hashlib.sha256(self.signed_wire).hexdigest(),
            signed_wire_bytes=len(self.signed_wire),
            decoded_record_sha256=hashlib.sha256(self.decoded_record).hexdigest(),
            decoded_record_bytes=len(self.decoded_record),
            pending_windows_lost=self.pending_windows_lost,
            measurement_completed=False,
            resume_authorized=False,
        )


@dataclass(frozen=True)
class _PreparedTerminal:
    source_bytes: bytes = field(repr=False)
    source_tip: dict
    registration_sha256: str
    session_ref: str
    native_seq: int
    before: dict
    after: dict
    signed_wire: bytes = field(repr=False)
    decoded_record: bytes = field(repr=False)
    journal_before: dict

    def after_journal_close(self, journal, source):
        """Called only AFTER ordinary __exit__ lost/session_close fsync+witness ack."""
        state = journal.status()
        old = self.journal_before
        _need(
            not state["continuity_available"]
            and state["sequence"] == old["sequence"] + old["pending"] + 2,
            "terminal journal cursor/loss/session close not complete",
        )
        _need(
            state["pending"] == 0
            and state["lost"] == old["lost"] + old["pending"]
            and state["committed"] == old["committed"]
            and state["counters"]["write_failures"] == 0,
            "terminal journal close did not preserve all pending losses",
        )
        _need(state["input_position"] == self.after, "terminal durable cursor differs")
        data = source.snapshot(self.after, require_complete=True)
        _need(
            data == self.source_bytes, "source changed after terminal cursor; no repair"
        )
        protected = source.authentication.client.state
        _need(
            protected is not None
            and all(
                protected.get(key) == value
                for key, value in dict(
                    journal_seq=state["sequence"],
                    journal_head=state["chain_head"],
                    journal_size=state["bytes"],
                    source_seq=self.source_tip["seq"],
                    source_head=self.source_tip["head"],
                    source_size=self.source_tip["size"],
                    source_sha256=self.source_tip["sha256"],
                ).items()
            ),
            "terminal protected close acknowledgement differs",
        )
        return TerminalControlStop(
            self.registration_sha256,
            self.session_ref,
            self.native_seq,
            dict(self.before),
            dict(self.after),
            self.signed_wire,
            self.decoded_record,
            old["pending"],
        )


def prepare_terminal_stop(line, journal, *, registration_sha256):
    """Consume ONLY a verified final terminal as CONTROL; never call collector.

    All pending durable identities are left pending for the existing journal
    close path to mark lost. No activity, sample, Outcome or finalization occurs.
    """
    source = journal.input_source
    _need(
        type(source) is BoundedInput
        and type(source.authentication) is InputAuthentication,
        "terminal stop requires verified authenticated source",
    )
    authentication = source.authentication
    policy = authentication.policy
    _need(
        policy.data["schema_version"]
        in ("outcome-input-trust/v3", "outcome-input-trust/v4")
        and policy.data["origin_registration_sha256"] == registration_sha256,
        "terminal trust registration mismatch",
    )
    state = journal.status()
    _need(
        state["continuity_available"]
        and not state["new_admission_closed"]
        and not state["input_recovery_pending"],
        "terminal journal admission unavailable",
    )
    before = journal.input_position()
    # Snapshot invalidates the old candidate: read the same actual final line
    # again through BoundedInput.lines rather than fabricating a cursor.
    data = source.snapshot(before, require_complete=True)
    actual = iter(source.lines(before, data))
    _need(
        next(actual, None) == line and next(actual, None) is None,
        "terminal is not the exact final unread source line",
    )
    verifier = SourceVerifier(policy)
    tip = verifier.verify(data)
    event = _parse(line.raw)
    origin = event.get("capture_origin") if type(event) is dict else None
    _need(
        type(origin) is dict
        and origin.get("kind") == "session_end"
        and event.get("pipeline") == "rust_live_origin_v1"
        and event.get("source") == "rust_core"
        and event.get("capture_lifecycle") == {"state": "end"},
        "only normal-core session_end may stop input",
    )
    _need(
        verifier.live_state.closed
        and origin["session_ref"] == verifier.live_state.session
        and origin["seq"] == verifier.live_state.seq
        and line.position
        == dict(offset=len(data), sha256=hashlib.sha256(data).hexdigest()),
        "terminal source tip/session/sequence differs",
    )
    wire = data[before["offset"] :]
    _need(
        wire.count(b"\n") == 1
        and authentication.unwrap(wire) == line.raw
        and _json(event) + b"\n" == line.raw,
        "terminal signed/decoded byte binding differs",
    )
    journal.advance_input(line.position, missed=True)
    # Refuse changes after advance without rollback, reconstruction or retry.
    _need(
        source.snapshot(line.position, require_complete=True) == data,
        "source changed after terminal cursor; no repair",
    )
    return _PreparedTerminal(
        data,
        tip,
        registration_sha256,
        origin["session_ref"],
        origin["seq"],
        before,
        dict(line.position),
        wire,
        line.raw,
        state,
    )
