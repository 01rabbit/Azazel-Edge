"""Pure verification of independently checkpointed witness Source prefixes.

No journal bytes/cursors, live witness availability, freshness, execution truth or
recovery are verified. Unselected Source/anchor suffixes remain unverified.
"""

import hashlib

from azazel_edge.outcome.input_auth import TrustPolicy, verify_signature
from azazel_edge.outcome.input_witness import (
    ANCHOR_DOMAIN,
    MESSAGE_BYTES,
    digest,
    validate_state,
)
from azazel_edge.outcome.journal import OutcomeJournalError, ZERO_HASH, _json, _parse
from .source_authentication import SourceAuthenticationInputError, verify_source_bytes
from .safety_observations import FLAGS, _fields, _hex, _int

MAX_ANCHOR_BYTES = 8 * 1024 * 1024
MAX_ANCHOR_ROWS = 4097


class SourceWitnessInputError(ValueError):
    """Malformed externally supplied trust, context or checkpoint parameters."""


def _need(condition, message):
    if not condition:
        raise ValueError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _checkpoint(value, policy):
    if value is None:
        return None
    _fields(value, "counter head size sha256")
    value = value.copy()
    _int(value["counter"], 0, min(MAX_ANCHOR_ROWS, policy.data["anchor_max_records"]))
    _int(value["size"], 0, min(MAX_ANCHOR_BYTES, policy.data["anchor_max_bytes"]))
    _hex(value["head"])
    _hex(value["sha256"])
    return value


def _source_tips(raw):
    """One linear pass over bytes ALREADY authenticated by the Source verifier."""
    tips = {0: dict(seq=0, head=ZERO_HASH, size=0, sha256=_sha(b""))}
    offset = 0
    hasher = hashlib.sha256()
    for line in raw.splitlines(keepends=True):
        offset += len(line)
        hasher.update(line)
        wire = _parse(line)
        tips[offset] = dict(
            seq=wire["seq"], head=digest(wire), size=offset, sha256=hasher.hexdigest()
        )
    return tips


def _verify_anchors(policy, raw, tips, expected_source):
    _need(
        raw.endswith(b"\n")
        and raw.count(b"\n") <= min(MAX_ANCHOR_ROWS, policy.data["anchor_max_records"]),
        "anchor prefix frame bound",
    )
    head = ZERO_HASH
    previous = None
    journal_identity = None
    counter = 0
    for counter, line in enumerate(raw.splitlines(keepends=True), 1):
        _need(len(line) <= MESSAGE_BYTES, "anchor row bound")
        wire = _parse(line)
        _fields(wire, "schema_version counter prev trust_sha256 state signature")
        _need(
            _json(wire) + b"\n" == line
            and wire["schema_version"] == "outcome-input-anchor/v1"
            and type(wire["counter"]) is int
            and wire["counter"] == counter
            and wire["prev"] == head
            and wire["trust_sha256"] == policy.digest,
            "anchor canonical chain/context differs",
        )
        verify_signature(
            policy.data["witness_public_key"],
            wire["signature"],
            ANCHOR_DOMAIN,
            {k: v for k, v in wire.items() if k != "signature"},
        )
        state = validate_state(wire["state"])
        source = {
            key: state["source_" + key] for key in ("seq", "head", "size", "sha256")
        }
        _need(
            state["source_size"] in tips and source == tips[state["source_size"]],
            "anchor Source boundary differs",
        )
        if previous is None:
            _need(
                state["source_seq"]
                == state["source_size"]
                == state["journal_seq"]
                == state["journal_size"]
                == state["journal_device"]
                == state["journal_inode"]
                == 0
                and state["source_head"] == state["journal_head"] == ZERO_HASH
                and state["source_sha256"] == state["journal_sha256"] == _sha(b""),
                "anchor genesis differs",
            )
        else:
            _need(
                state["journal_seq"] == previous["journal_seq"] + 1
                and state["source_seq"] >= previous["source_seq"]
                and state["source_size"] >= previous["source_size"],
                "witness assertion progression differs",
            )
            if state["source_seq"] == previous["source_seq"]:
                _need(
                    all(
                        state["source_" + key] == previous["source_" + key]
                        for key in ("seq", "head", "size", "sha256")
                    ),
                    "unchanged Source sequence changed tip",
                )
        if state["journal_seq"]:
            identity = (state["journal_device"], state["journal_inode"])
            _need(
                all(value > 0 for value in identity),
                "nonzero journal assertion requires identity",
            )
            if journal_identity is None:
                journal_identity = identity
            _need(
                identity == journal_identity,
                "witness journal assertion identity changed",
            )
        previous = state
        head = digest(wire)
    _need(
        previous is not None
        and all(
            previous["source_" + key] == expected_source[key]
            for key in ("seq", "head", "size", "sha256")
        ),
        "last anchor Source tip differs",
    )
    return dict(counter=counter, head=head, size=len(raw), sha256=_sha(raw))


def verify_witnessed_source_prefix(
    trust_raw,
    source_raw,
    anchors_raw,
    *,
    expected_trust_sha256,
    expected_context,
    expected_source_checkpoint,
    expected_anchor_checkpoint,
):
    """Authenticate ONLY independently selected prefixes, never adopt suffixes."""
    try:
        source = verify_source_bytes(
            trust_raw,
            source_raw,
            expected_trust_sha256=expected_trust_sha256,
            expected_context=expected_context,
            expected_prefix_checkpoint=expected_source_checkpoint,
            expected_final_checkpoint=None,
        )
        policy = TrustPolicy(_parse(trust_raw))
        checkpoint = _checkpoint(expected_anchor_checkpoint, policy)
        _need(
            anchors_raw is None or type(anchors_raw) is bytes,
            "anchors must be bytes or unavailable",
        )
    except (
        SourceAuthenticationInputError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        OutcomeJournalError,
    ) as exc:
        raise SourceWitnessInputError(str(exc)) from exc
    hashes = source["raw_sha256"]
    bounded = anchors_raw is not None and len(anchors_raw) <= min(
        MAX_ANCHOR_BYTES, policy.data["anchor_max_bytes"]
    )
    result = dict(
        schema_version="edge-source-witness-prefix-diagnostic/v1",
        source_prefix_authenticated=source["authenticated_prefix"],
        witness_prefix_authenticated=False,
        source_checkpoint=source["prefix_tip"],
        anchor_checkpoint=None,
        raw_sha256=dict(
            trust=hashes["trust"],
            source=hashes["source"],
            source_prefix=hashes["prefix"],
            source_suffix=hashes["suffix"],
            anchors=_sha(anchors_raw) if bounded else None,
            anchor_prefix=None,
            anchor_suffix=None,
        ),
        reasons=[],
        journal_verified=False,
        qualified_safety_count=None,
        **FLAGS,
    )
    reasons = result["reasons"]
    if not source["authenticated_prefix"]:
        reasons.extend(["source_prefix_unavailable", *source["reasons"]])
        return result
    if anchors_raw is None:
        reasons.append("anchors_unavailable")
        return result
    if checkpoint is None:
        reasons.append("anchor_checkpoint_unavailable")
        return result
    size = checkpoint["size"]
    if size > len(anchors_raw):
        reasons.append("anchor_prefix_unavailable")
        return result
    prefix = anchors_raw[:size]
    result["raw_sha256"]["anchor_prefix"] = _sha(prefix)
    if bounded:
        result["raw_sha256"]["anchor_suffix"] = _sha(anchors_raw[size:])
    if not prefix:
        reasons.append("anchor_prefix_empty")
        return result
    tips = _source_tips(source_raw[: source["prefix_tip"]["size"]])
    try:
        actual = _verify_anchors(policy, prefix, tips, source["prefix_tip"])
    except (
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        RecursionError,
        OutcomeJournalError,
    ):
        reasons.append("anchor_prefix_verification_failed")
        return result
    if actual != checkpoint:
        reasons.append("anchor_checkpoint_mismatch")
        return result
    result["witness_prefix_authenticated"] = True
    result["anchor_checkpoint"] = actual
    return result
