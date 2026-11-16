"""Explicit observer exit control, never Source terminal or input coverage proof."""

from dataclasses import asdict, dataclass
import json
import re

from .input_cursor import BoundedInput
from .input_witness import InputAuthentication
from .journal import ObservationJournal, OutcomeJournalError, _json, _ref


def _need(value, message):
    if not value:
        raise OutcomeJournalError(message)


def _uint(value):
    return type(value) is int and 0 <= value < 2**64


def _hex(value):
    return type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class ObserverControlStop:
    """Immutable evidence of this observer's ordinary close, not a v4 terminal."""

    scope_ref: str
    trust_sha256: str
    journal_policy_sha256: str
    journal_boot_id: str
    input_offset: int
    input_sha256: str
    journal_sequence_before: int
    journal_sequence_after: int
    journal_head_after: str
    journal_bytes_after: int
    pending_windows_before: int
    pending_windows_lost: int
    committed_outcomes: int
    lost_before: int
    lost_after: int

    def validate(self):
        """Structural checks only; live resource/ACK checks belong to finish."""
        _ref(self.scope_ref)
        _ref(self.journal_boot_id)
        for value in (self.trust_sha256, self.journal_policy_sha256,
                      self.input_sha256, self.journal_head_after):
            _need(_hex(value), "invalid observer control hash")
        for name in ("input_offset", "journal_sequence_before", "journal_sequence_after",
                     "journal_bytes_after", "pending_windows_before", "pending_windows_lost",
                     "committed_outcomes", "lost_before", "lost_after"):
            _need(_uint(getattr(self, name)), "invalid observer control counter")
        _need(self.journal_bytes_after > 0
              and self.journal_sequence_after == self.journal_sequence_before + self.pending_windows_before + 1
              and self.pending_windows_lost == self.pending_windows_before
              and self.lost_after == self.lost_before + self.pending_windows_before,
              "observer control close counters differ")

    def to_dict(self):
        self.validate()
        position = dict(offset=self.input_offset, sha256=self.input_sha256)
        return dict(
            schema_version="outcome-observer-control-stop/v1",
            disposition="observer_control_stop",
            **asdict(self),
            stop_requested=True,
            stop_honored=True,
            honored_boundary="before_iteration",
            resources_closed=True,
            journal_descriptors_closed=True,
            source_descriptors_closed=True,
            protected_journal_acknowledged=True,
            input_position_before=dict(position),
            input_position_after=dict(position),
            input_coverage_complete=False,
            source_stability_verified=False,
            source_producer_terminated=None,
            signal_received_time=None,
            authorizes_transition=False,
            experiment=False,
            measurement_completed=False,
            production_admission=False,
            resume_authorized=False,
            qualified_safety_count=None,
        )


@dataclass(frozen=True)
class _PreparedControlStop:
    state_raw: bytes
    source: object
    journal: object
    authentication: object
    scope_ref: str
    trust_sha256: str
    journal_policy_sha256: str
    journal_boot_id: str


def prepare_control_stop(journal, source, *, journal_boot_id):
    """Retain the actual boundary without sampling or reading more Source bytes."""
    _need(type(journal) is ObservationJournal and type(source) is BoundedInput,
          "original observer resources required")
    authentication = source.authentication
    _need(type(authentication) is InputAuthentication
          and authentication.policy is not None
          and journal.authentication is authentication
          and journal.input_source is source,
          "authenticated observer resources required")
    state = journal.status()
    _need(journal._ready and journal._active and not journal._poisoned
          and not journal._sealed and not journal._recovering
          and journal._fd is not None and journal._dir is not None
          and source.fd is not None and source.parent is not None
          and state["continuity_available"] is True
          and state["new_admission_closed"] is False
          and state["input_recovery_pending"] is False
          and state["seal_reason"] is None
          and state["counters"]["write_failures"] == 0
          and state["counters"]["capacity_drops"] == 0,
          "observer control boundary is not usable")
    _need(journal._session_boot == journal_boot_id, "observer control boot differs")
    return _PreparedControlStop(
        state_raw=_json(state), source=source, journal=journal, authentication=authentication,
        scope_ref=journal.config["scope_ref"], trust_sha256=authentication.policy.digest,
        journal_policy_sha256=journal.config["policy_sha256"], journal_boot_id=journal_boot_id,
    )


def finish_control_stop(prepared, journal, source):
    """Called only after both ordinary context managers successfully returned."""
    _need(type(prepared) is _PreparedControlStop
          and prepared.journal is journal and prepared.source is source
          and source.authentication is prepared.authentication
          and journal.authentication is prepared.authentication,
          "observer control resources changed")
    _need(journal._fd is None and journal._dir is None
          and source.fd is None and source.parent is None,
          "observer control resources still open")
    before = json.loads(prepared.state_raw)
    after = journal.status()
    _need(not journal._poisoned and not journal._active and not journal._sealed and not journal._recovering
          and after["continuity_available"] is False
          and after["sequence"] == before["sequence"] + before["pending"] + 1
          and after["pending"] == 0
          and after["lost"] == before["lost"] + before["pending"]
          and after["committed"] == before["committed"]
          and after["input_position"] == before["input_position"]
          and after["input_records"] == before["input_records"]
          and after["missed_input_records"] == before["missed_input_records"]
          and after["counters"]["write_failures"] == 0
          and after["counters"]["capacity_drops"] == 0,
          "observer control ordinary close unverified")
    acknowledged = prepared.authentication.client.state
    _need(type(acknowledged) is dict
          and all(type(acknowledged.get(key)) is type(value) and acknowledged.get(key) == value
                  for key, value in dict(journal_seq=after["sequence"],
                                         journal_head=after["chain_head"],
                                         journal_size=after["bytes"]).items()),
          "observer control protected journal acknowledgement differs")
    position = before["input_position"]
    receipt = ObserverControlStop(
        scope_ref=prepared.scope_ref, trust_sha256=prepared.trust_sha256,
        journal_policy_sha256=prepared.journal_policy_sha256, journal_boot_id=prepared.journal_boot_id,
        input_offset=position["offset"], input_sha256=position["sha256"],
        journal_sequence_before=before["sequence"], journal_sequence_after=after["sequence"],
        journal_head_after=after["chain_head"], journal_bytes_after=after["bytes"],
        pending_windows_before=before["pending"], pending_windows_lost=after["lost"] - before["lost"],
        committed_outcomes=after["committed"], lost_before=before["lost"], lost_after=after["lost"],
    )
    receipt.validate()
    return receipt
