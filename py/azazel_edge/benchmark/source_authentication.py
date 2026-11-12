"""Pure recorded Source-byte provenance, never execution truth or recovery.

Externally retained prefix/final checkpoints and Root enrollment remain trust
assumptions. A bad suffix must not erase an independently authenticated prefix.
"""

import hashlib

from azazel_edge.outcome.input_auth import SourceVerifier, TrustPolicy
from azazel_edge.outcome.journal import OutcomeJournalError, _json, _parse, _ref
from .safety_observations import _fields, _hex, _int


class SourceAuthenticationInputError(ValueError):
    """Malformed global trust, independently supplied context, or checkpoints."""


def _need(value, message):
    if not value:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _checkpoint(value, policy):
    if value is None:
        return None
    _fields(value, "seq head size sha256")
    value = value.copy()
    _int(value["seq"], 0, policy.data["input_max_records"])
    _int(value["size"], 0, policy.data["input_max_bytes"])
    _hex(value["head"])
    _hex(value["sha256"])
    return value


def _context(value, policy):
    _fields(
        value,
        "scope_ref producer_ref stream_ref registration_sha256 session_ref boot_ref producer_public_key witness_public_key producer_uid observer_uid",
    )
    value = value.copy()
    for key in ("scope_ref", "producer_ref", "stream_ref"):
        _ref(value[key])
    for key in ("registration_sha256", "producer_public_key", "witness_public_key"):
        _hex(value[key])
    for key in ("session_ref", "boot_ref"):
        _hex(value[key], 32)
    for key in ("producer_uid", "observer_uid"):
        _int(value[key], 1, 2**32 - 1)
    _need(
        value["producer_public_key"] != value["witness_public_key"],
        "Source key roles overlap",
    )
    for key in (
        "scope_ref",
        "producer_ref",
        "stream_ref",
        "producer_public_key",
        "witness_public_key",
        "producer_uid",
        "observer_uid",
    ):
        _need(
            value[key] == policy.data[key], "expected Source context differs from trust"
        )
    _need(
        value["registration_sha256"] == policy.data["origin_registration_sha256"],
        "expected registration differs from trust",
    )
    return value


def _bound_context(verifier, raw, context):
    # Only called AFTER the existing verifier authenticated these complete bytes.
    _need(
        verifier.live_state.sessions == frozenset({context["session_ref"]})
        and verifier.live_state.session == context["session_ref"],
        "Source session differs",
    )
    last = None
    for line in raw.splitlines(keepends=True):
        wire = _parse(line)
        _need(
            wire["boot_ref"] == context["boot_ref"]
            and wire["event"]["capture_origin"]["session_ref"]
            == context["session_ref"],
            "Source boot/session differs",
        )
        last = wire["event"]
    return last


def verify_source_bytes(
    trust_raw,
    source_raw,
    *,
    expected_trust_sha256,
    expected_context,
    expected_prefix_checkpoint,
    expected_final_checkpoint,
):
    """Authenticate one enrolled prefix and full input separately; never consume it."""
    try:
        _hex(expected_trust_sha256)
        _need(
            type(trust_raw) is bytes and 0 < len(trust_raw) <= 32 * 1024,
            "bounded trust bytes required",
        )
        _need(_sha(trust_raw) == expected_trust_sha256, "external trust digest differs")
        parsed = _parse(trust_raw)
        _need(
            _json(parsed) + b"\n" == trust_raw, "canonical trust plus one LF required"
        )
        policy = TrustPolicy(parsed)
        _need(
            policy.data["schema_version"]
            in ("outcome-input-trust/v3", "outcome-input-trust/v4"),
            "registered live trust required",
        )
        context = _context(expected_context, policy)
        prefix_checkpoint = _checkpoint(expected_prefix_checkpoint, policy)
        final_checkpoint = _checkpoint(expected_final_checkpoint, policy)
        _need(
            source_raw is None or type(source_raw) is bytes,
            "Source must be bytes or unavailable",
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        OutcomeJournalError,
    ) as exc:
        raise SourceAuthenticationInputError(str(exc)) from exc

    within_bytes = (
        source_raw is not None and len(source_raw) <= policy.data["input_max_bytes"]
    )
    result = dict(
        schema_version="edge-source-byte-diagnostic/v1",
        authenticated_prefix=False,
        authenticated_full_source=False,
        normal_terminal_verified=False,
        prefix_tip=None,
        final_tip=None,
        raw_sha256=dict(
            trust=_sha(trust_raw),
            source=_sha(source_raw) if within_bytes else None,
            prefix=None,
            suffix=None,
        ),
        reasons=[],
        authorizes_transition=False,
        experiment=False,
        measurement_completed=False,
        production_admission=False,
        resume_authorized=False,
        qualified_safety_count=None,
    )
    reasons = result["reasons"]
    if source_raw is None:
        reasons.append("source_unavailable")
        return result
    if not source_raw:
        reasons.append("source_empty")
        return result
    if prefix_checkpoint is None:
        reasons.append("prefix_checkpoint_unavailable")
        return result
    size = prefix_checkpoint["size"]
    if size > len(source_raw):
        reasons.append("prefix_bytes_unavailable")
        return result
    prefix = source_raw[:size]
    result["raw_sha256"]["prefix"] = _sha(prefix)
    if within_bytes:
        result["raw_sha256"]["suffix"] = _sha(source_raw[size:])
    if not prefix:
        reasons.append("prefix_empty")
        return result
    verifier = SourceVerifier(policy)
    try:
        prefix_tip = verifier.verify(prefix)
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        OutcomeJournalError,
    ):
        reasons.append("prefix_authentication_failed")
        return result
    try:
        _bound_context(verifier, prefix, context)
    except (ValueError, TypeError, KeyError, OutcomeJournalError):
        reasons.append("prefix_context_mismatch")
        return result
    if prefix_tip != prefix_checkpoint:
        reasons.append("prefix_checkpoint_mismatch")
        return result
    result["authenticated_prefix"] = True
    result["prefix_tip"] = dict(prefix_tip)
    if final_checkpoint is None:
        reasons.append("final_checkpoint_unavailable")
        return result
    if not within_bytes:
        reasons.append("source_bounds_invalid")
        return result
    try:
        # This verifies ONLY the suffix, preserving the prior verifier state on error.
        final_tip = verifier.verify(source_raw)
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        OutcomeJournalError,
    ):
        reasons.append("full_authentication_failed")
        return result
    try:
        last = _bound_context(verifier, source_raw, context)
    except (ValueError, TypeError, KeyError, OutcomeJournalError):
        reasons.append("full_context_mismatch")
        return result
    if final_tip != final_checkpoint:
        reasons.append("final_checkpoint_mismatch")
        return result
    result["authenticated_full_source"] = True
    result["final_tip"] = dict(final_tip)
    result["normal_terminal_verified"] = bool(
        verifier.live_state.closed
        and last["pipeline"] == "rust_live_origin_v1"
        and last["source"] == "rust_core"
        and last.get("capture_lifecycle") == {"state": "end"}
        and last["capture_origin"]["kind"] == "session_end"
    )
    if not result["normal_terminal_verified"]:
        reasons.append("normal_terminal_unavailable")
    return result
