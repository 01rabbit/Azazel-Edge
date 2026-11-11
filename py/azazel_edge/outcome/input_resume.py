"""Opt-in verified-input driver: never reconstruct missed telemetry."""

from __future__ import annotations

from pathlib import Path
from datetime import datetime
import math
import time

from .adapter import from_rust_event
from .contracts import ExecutionStatus
from .input_cursor import BoundedInput
from .journal import NAME, ObservationJournal, OutcomeJournalError, _parse, _json
from .release_evidence import from_rust_release_event
from .telemetry import (
    LinuxProcTelemetrySource,
    OutcomeTelemetryCollector,
    OutcomeTelemetryPolicy,
    _window_seconds,
    persistence_context,
)
from .observer import append_jsonl

MAX_BATCH_RECORDS = 256
MAX_RECOVERY_PASSES = 4


def decode_input(raw, *, allow_live_lifecycle=False):
    event = _parse(raw)
    _json(event)  # Reject overflowed numeric literals even in unused source fields.
    if type(event) is not dict:
        raise OutcomeJournalError("input record must be an object")
    try:
        if event.get("pipeline") == "rust_live_origin_v1":
            origin = event.get("capture_origin", {})
            kind = origin.get("kind") if type(origin) is dict else None
            if (
                not allow_live_lifecycle
                or set(event)
                != {"pipeline", "source", "capture_lifecycle", "capture_origin"}
                or event.get("source")
                != ("capture_producer" if kind == "session_prepare" else "rust_core")
                or kind not in ("session_prepare", "session_start", "session_end")
                or origin.get("schema_version") != "outcome-registered-origin/v2"
                or origin.get("mode") != "live-core"
                or event.get("capture_lifecycle")
                != {
                    "state": {
                        "session_prepare": "prepare",
                        "session_start": "start",
                        "session_end": "end",
                    }.get(kind)
                }
            ):
                raise ValueError("unverified live lifecycle input")
        elif event.get("pipeline") == "rust_release_engine_v1":
            from_rust_release_event(event)
        elif (
            event.get("pipeline") == "rust_event_engine_v1"
            and type(event.get("normalized")) is dict
            and type(event.get("enforcement")) is dict
            and event["enforcement"].get("trace_id")
        ):
            from_rust_event(event)
        else:
            raise ValueError("unrecognized input source")
    except (ValueError, TypeError, OverflowError) as exc:
        raise OutcomeJournalError(
            "invalid source record; position not advanced"
        ) from exc
    return event


def objective_identity(event, policy):
    if event.get("pipeline") in ("rust_release_engine_v1", "rust_live_origin_v1"):
        return None, None
    execution = from_rust_event(event).execution
    if (
        execution.action_kind not in ("throttle", "redirect", "isolate")
        or execution.status is not ExecutionStatus.APPLIED
    ):
        return None, None
    objective = policy.objective_for(execution.action_kind, execution.decision_id)
    if objective is None:
        return None, None
    return (
        dict(
            decision_id=execution.decision_id,
            execution_id=execution.execution_id,
            objective_id=objective.objective_id,
        ),
        objective,
    )


def _open_admission(journal):
    state = journal.status()
    if not state["continuity_available"] or state["new_admission_closed"]:
        raise OutcomeJournalError(
            "input observation admission unavailable: "
            + str(state["seal_reason"] or "capacity")
        )


def _live_lifecycle_allowed(journal):
    authentication = journal.input_source.authentication
    return (
        authentication is not None
        and authentication.policy.data["schema_version"] in ("outcome-input-trust/v3", "outcome-input-trust/v4")
    )


def miss_record(line, journal, policy):
    event = decode_input(
        line.raw, allow_live_lifecycle=_live_lifecycle_allowed(journal)
    )
    identity, _ = objective_identity(event, policy)
    if identity is not None:
        journal.lose_window(**identity, reason="restart_input_missed")
    _open_admission(journal)
    journal.advance_input(line.position, missed=True)


def recover_input(journal, policy):
    """Discard restart backlog as explicit loss, never live observation/activity."""
    _open_admission(journal)
    source = journal.input_source
    for _ in range(MAX_RECOVERY_PASSES):
        for line in source.lines(journal.input_position(), journal.recovery_input):
            miss_record(line, journal, policy)
        if journal.finish_input_recovery():
            return
    raise OutcomeJournalError("input remained active during bounded startup recovery")


def _event_epoch(event):
    try:
        if event.get("pipeline") == "rust_release_engine_v1":
            return from_rust_release_event(event).attempted_at_epoch
        value = event["normalized"]["ts"]
        if type(value) is not str:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        epoch = parsed.timestamp()
        return epoch if math.isfinite(epoch) else None
    except (ValueError, TypeError, KeyError, OverflowError):
        return None


def observe_input(line, journal, collector, *, live_floor, now):
    event = decode_input(
        line.raw, allow_live_lifecycle=_live_lifecycle_allowed(journal)
    )
    if event.get("pipeline") == "rust_live_origin_v1":
        # The live source's process boundary cannot preserve a pre/post window.
        # Stop before cursor/activity changes. Verified observer reopen applies
        # the existing durable pending-loss, backlog exclusion and fresh fence.
        raise OutcomeJournalError(
            "live core boundary requires verified observer recovery; no window continuation"
        )
    identity, objective = objective_identity(event, collector.policy)
    if identity is not None and journal.retained_identity_state(**identity) is not None:
        # Do not let a re-dated retained execution add even activity/baseline
        # facts to a fresh collector before its normal duplicate guard runs.
        _open_admission(journal)
        journal.advance_input(line.position, missed=True)
        return
    stamp = _event_epoch(event)
    pre = (
        _window_seconds(objective.observation_window)[0] if objective is not None else 0
    )
    # This filters stale/future/unclocked input only. It does NOT turn the alert
    # timestamp into an authoritative provider completion timestamp. G3 retains
    # its receipt-bound window and inconclusive/confounder semantics.
    missed = (
        stamp is None
        or not live_floor + pre <= stamp <= now
        or now - stamp > collector.sample_interval_seconds
    )
    if missed:
        if identity is not None:
            journal.lose_window(**identity, reason="input_time_unusable")
    else:
        collector.observe_event(event, observed_epoch=now)
        if collector.persistence_errors:
            raise OutcomeJournalError("collector persistence failed; cursor withheld")
    _open_admission(journal)
    journal.advance_input(line.position, missed=missed)


def run_live_resumable(
    *,
    input_path,
    output_path,
    policy_path,
    interface,
    poll_seconds,
    sample_interval_seconds,
    max_output_bytes,
    journal_directory,
    journal_scope,
    journal_boot_id,
    initialize_journal,
    journal_max_bytes,
    journal_max_identities,
    input_max_bytes,
    input_max_records,
    authentication_policy=None,
    terminal_stop_registration=None,
):
    if journal_directory is None:
        raise ValueError("input resume requires a journal directory")
    journal_path = (journal_directory / NAME).resolve()
    if len({input_path.resolve(), output_path.resolve(), journal_path}) != 3:
        raise ValueError("input, output and journal must be separate")
    if not math.isfinite(poll_seconds) or poll_seconds <= 0:
        raise ValueError("poll interval must be finite and positive")
    policy = OutcomeTelemetryPolicy.from_file(policy_path)
    authentication = None
    if authentication_policy is not None:
        from .input_auth import TrustPolicy
        from .input_witness import InputAuthentication

        trust = TrustPolicy.from_file(authentication_policy, role="observer")
        p = trust.data
        if (
            str(journal_directory) != p["journal_directory"]
            or journal_scope != p["scope_ref"]
            or journal_max_bytes != p["journal_max_bytes"]
        ):
            raise OutcomeJournalError("journal authentication context mismatch")
        if output_path.resolve() in {
            Path(p["socket_path"]),
            Path(p["anchor_directory"]) / "anchors.journal",
            Path(authentication_policy).resolve(),
        }:
            raise OutcomeJournalError("output aliases authentication storage")
        authentication = InputAuthentication(trust)
    terminal_registration_sha256 = None
    if terminal_stop_registration is not None:
        from .input_terminal import validate_terminal_registration
        terminal_registration_sha256 = validate_terminal_registration(authentication, terminal_stop_registration)
    terminal = None
    result = None
    with BoundedInput(
        input_path,
        max_bytes=input_max_bytes,
        max_records=input_max_records,
        authentication=authentication,
    ) as source:
        with ObservationJournal(
            journal_directory,
            scope_ref=journal_scope,
            policy_ref=persistence_context(policy, interface, sample_interval_seconds),
            boot_id=journal_boot_id,
            create=initialize_journal,
            max_bytes=journal_max_bytes,
            max_identities=journal_max_identities,
            input_source=source,
        ) as journal:
            recover_input(journal, policy)
            collector = OutcomeTelemetryCollector(
                source=LinuxProcTelemetrySource(),
                policy=policy,
                interface=interface,
                sample_interval_seconds=sample_interval_seconds,
                persistence=journal,
            )
            live_floor = time.time()
            last_wall = live_floor
            last_mono = time.monotonic()
            if not math.isfinite(last_wall) or not math.isfinite(last_mono):
                raise OutcomeJournalError("clock continuity unavailable")
            next_sample = last_mono
            while terminal is None:
                now = time.time()
                mono = time.monotonic()
                if (
                    not math.isfinite(now)
                    or not math.isfinite(mono)
                    or now < last_wall
                    or mono < last_mono
                    or abs((now - last_wall) - (mono - last_mono))
                    > sample_interval_seconds
                ):
                    raise OutcomeJournalError(
                        "clock continuity unavailable; no shifted observation windows"
                    )
                last_wall = now
                last_mono = mono
                if mono >= next_sample:
                    collector.record_sample(epoch=now)
                    next_sample = mono + sample_interval_seconds
                data = source.snapshot(journal.input_position())
                count = 0
                for line in source.lines(journal.input_position(), data):
                    parsed = _parse(line.raw) if terminal_registration_sha256 is not None else None
                    if type(parsed) is dict and parsed.get("pipeline") == "rust_live_origin_v1":
                        from .input_terminal import prepare_terminal_stop
                        terminal = prepare_terminal_stop(line, journal, registration_sha256=terminal_registration_sha256)
                        break
                    observe_input(
                        line, journal, collector, live_floor=live_floor, now=time.time()
                    )
                    count += 1
                    if count >= MAX_BATCH_RECORDS:
                        break
                if terminal is not None:
                    break  # Never sample/observe/finalize across the terminal boundary.
                # Revalidate bytes before any result can be committed/emitted.
                source.snapshot(journal.input_position())
                end_wall = time.time()
                end_mono = time.monotonic()
                if (
                    not math.isfinite(end_wall)
                    or not math.isfinite(end_mono)
                    or end_wall < last_wall
                    or end_mono < last_mono
                    or abs((end_wall - last_wall) - (end_mono - last_mono))
                    > sample_interval_seconds
                ):
                    raise OutcomeJournalError(
                        "clock continuity unavailable before result commit"
                    )
                last_wall = end_wall
                last_mono = end_mono
                records = collector.finalize_due(epoch=end_wall)
                if collector.persistence_errors:
                    raise OutcomeJournalError(
                        "collector persistence failed; intake stopped"
                    )
                _open_admission(journal)
                if records:
                    append_jsonl(
                        output_path,
                        (
                            {
                                "schema_version": r.schema_version,
                                "outcome": r.to_dict(),
                                "collector_mode": "passive_g3",
                                "effect_assessment": None,
                            }
                            for r in records
                        ),
                        max_bytes=max_output_bytes,
                    )
                time.sleep(max(0.05, poll_seconds))
        if terminal is not None:
            result = terminal.after_journal_close(journal, source)
    return result
