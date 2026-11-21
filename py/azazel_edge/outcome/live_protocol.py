"""Live process provenance is distinct from read-only calculation and effect."""

from dataclasses import dataclass
import re

from .journal import OutcomeJournalError


@dataclass(frozen=True)
class LiveState:
    sessions: frozenset = frozenset()
    session: str = ""
    seq: int = 0
    closed: bool = True
    accounting_profile: str | None = None
    activity_count: int = 0


COUNTERS = frozenset(
    ("produced", "admitted", "enqueued", "written", "dropped", "inflight")
)
LIFECYCLE_SCHEMA = "outcome-live-origin-lifecycle/v2"


def validate_lifecycle(event, kind, *, activity_count=None):
    """Validate lifecycle shape; return its explicit profile, never infer counts."""
    states = {
        "session_prepare": "prepare",
        "session_start": "start",
        "session_end": "end",
    }
    if (
        type(kind) is not str
        or kind not in states
        or type(event) is not dict
        or set(event)
        not in (
            {"pipeline", "source", "capture_lifecycle"},
            {"pipeline", "source", "capture_lifecycle", "capture_origin"},
        )
        or event.get("pipeline") != "rust_live_origin_v1"
        or event.get("source")
        != ("capture_producer" if kind == "session_prepare" else "rust_core")
    ):
        raise OutcomeJournalError("live process lifecycle mismatch")
    lifecycle = event["capture_lifecycle"]
    if lifecycle == {"state": states[kind]}:
        return None
    expected = dict(
        schema_version=LIFECYCLE_SCHEMA, state=states[kind], accounting_profile="v1"
    )
    if kind == "session_end" and type(lifecycle) is dict:
        counts = lifecycle.get("counts")
        if (
            type(counts) is not dict
            or set(counts) != COUNTERS
            or any(type(n) is not int or not 0 <= n < 2**63 for n in counts.values())
            or counts["dropped"] != 0
            or counts["inflight"] != 0
            or any(
                counts[k] != counts["written"]
                for k in ("produced", "admitted", "enqueued")
            )
            or (activity_count is not None and counts["written"] != activity_count)
        ):
            raise OutcomeJournalError("live process accounting mismatch")
        expected["counts"] = counts
    if kind == "session_prepare" or lifecycle != expected:
        raise OutcomeJournalError("live process lifecycle mismatch")
    return "v1"


def validate_ingress_origin(event, session, kind, *, required=False):
    origin = event.get("ingress_origin")
    if "ingress_origin" not in event:
        if required and kind == "decision_execution":
            raise OutcomeJournalError("registered ingress origin missing")
        return
    if (
        kind != "decision_execution"
        or type(origin) is not dict
        or set(origin)
        != {
            "schema_version",
            "range_ref",
            "device",
            "inode",
            "start_offset",
            "end_offset",
            "raw_sha256",
        }
        or origin["schema_version"] != "azazel-edge/ingress-origin/v1"
        or origin["range_ref"] != session
        or any(
            type(origin[k]) is not int or not 0 <= origin[k] < 2**63
            for k in ("device", "inode", "start_offset", "end_offset")
        )
        or origin["end_offset"] <= origin["start_offset"]
        or type(origin["raw_sha256"]) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", origin["raw_sha256"])
    ):
        raise OutcomeJournalError("invalid native ingress origin")


def native_frame(wire, state):
    if (
        type(wire) is not dict
        or set(wire) != {"schema_version", "session_ref", "seq", "kind", "event"}
        or wire["schema_version"] != "outcome-live-origin/v1"
    ):
        raise OutcomeJournalError("invalid live process frame")
    session, seq, kind, event = (
        wire[k] for k in ("session_ref", "seq", "kind", "event")
    )
    if (
        type(session) is not str
        or not re.fullmatch(r"[0-9a-f]{32}", session)
        or type(seq) is not int
        or not 1 <= seq < 2**63
        or type(event) is not dict
    ):
        raise OutcomeJournalError("invalid live process identity")
    if "capture_origin" in event:
        raise OutcomeJournalError("native provenance injection")
    validate_ingress_origin(event, session, kind)
    if kind == "session_start":
        prepared = not state.closed and state.session == session and state.seq == 0
        if seq != 1 or (
            not prepared and (not state.closed or session in state.sessions)
        ):
            raise OutcomeJournalError("live process session not safely prepared/new")
        state = LiveState(state.sessions | {session}, session, 0, False)
    elif state.closed or session != state.session:
        raise OutcomeJournalError("live process session mismatch")
    if seq != state.seq + 1:
        raise OutcomeJournalError("live process sequence gap or replay")
    if kind in ("session_start", "session_end"):
        profile = validate_lifecycle(event, kind, activity_count=state.activity_count)
        if kind == "session_end" and profile != state.accounting_profile:
            raise OutcomeJournalError("live process accounting profile changed")
        if kind == "session_start":
            state = LiveState(state.sessions, session, state.seq, False, profile, 0)
    elif kind == "decision_execution":
        if (
            event.get("pipeline") != "rust_event_engine_v1"
            or event.get("source") != "suricata_eve"
            or any(
                type(event.get(k)) is not dict
                for k in ("normalized", "defense", "enforcement", "enforcement_status")
            )
        ):
            raise OutcomeJournalError("live provider event shape mismatch")
        e, status = event["enforcement"], event["enforcement_status"]
        if (
            type(e.get("metadata")) is not dict
            or e["metadata"].get("capture_only") is True
        ):
            raise OutcomeJournalError(
                "read-only calculation cannot become live provider fact"
            )
        for k in ("executed_count", "failed_count"):
            if type(e.get(k)) is not int or not 0 <= e[k] < 2**32:
                raise OutcomeJournalError("invalid provider command counts")
        for k in ("mode", "result", "trace_id"):
            if type(e.get(k)) is not str or not 1 <= len(e[k]) <= 256:
                raise OutcomeJournalError("missing provider fact")
        for k in ("command_plan", "rollback_plan", "errors"):
            if type(e.get(k)) is not list or any(type(x) is not str for x in e[k]):
                raise OutcomeJournalError("invalid provider details")
        for k in ("enforce_enabled", "dry_run", "high_impact_auto"):
            if type(status.get(k)) is not bool:
                raise OutcomeJournalError("invalid provider posture")
    elif kind == "release":
        if (
            event.get("pipeline") != "rust_release_engine_v1"
            or event.get("source") != "release_ledger"
            or type(event.get("release")) is not dict
            or type(event.get("enforcement_status")) is not dict
        ):
            raise OutcomeJournalError("release provider event mismatch")
    else:
        raise OutcomeJournalError("unknown live process record kind")
    activity_count = state.activity_count
    if state.accounting_profile is not None and kind in (
        "decision_execution",
        "release",
    ):
        activity_count += 1
        if activity_count >= 2**63:
            raise OutcomeJournalError("live process activity count exhausted")
    return LiveState(
        state.sessions,
        session,
        seq,
        kind == "session_end",
        state.accounting_profile,
        activity_count,
    )


def signed_live_event(event, registration, state):
    origin = event.get("capture_origin")
    fields = {
        "schema_version",
        "registration_sha256",
        "mode",
        "session_ref",
        "seq",
        "kind",
    }
    if (
        type(origin) is not dict
        or set(origin) != fields
        or origin["schema_version"] != "outcome-registered-origin/v2"
        or origin["mode"] != "live-core"
        or origin["registration_sha256"] != registration
    ):
        raise OutcomeJournalError("live input registration mismatch")
    if origin["kind"] == "session_prepare":
        session = origin["session_ref"]
        if (
            type(session) is not str
            or not re.fullmatch(r"[0-9a-f]{32}", session)
            or type(origin["seq"]) is not int
            or origin["seq"] != 0
            or not state.closed
            or session in state.sessions
            or {k: v for k, v in event.items() if k != "capture_origin"}
            != dict(
                pipeline="rust_live_origin_v1",
                source="capture_producer",
                capture_lifecycle=dict(state="prepare"),
            )
        ):
            raise OutcomeJournalError("invalid or replayed live preparation")
        return LiveState(state.sessions | {session}, session, 0, False)
    if origin["kind"] == "session_start" and (
        state.closed or state.seq != 0 or state.session != origin["session_ref"]
    ):
        raise OutcomeJournalError(
            "live source requires durable preparation before core start"
        )
    native = dict(
        schema_version="outcome-live-origin/v1",
        **{k: origin[k] for k in ("session_ref", "seq", "kind")},
        event={k: v for k, v in event.items() if k != "capture_origin"},
    )
    return native_frame(native, state)
