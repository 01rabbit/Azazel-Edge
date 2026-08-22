"""Edge-side producer for canonical AZ-06 environment-transition decisions.

Edge is the sole authority over deception-environment transitions. This module
turns an Action-Arbiter outcome (or explicit inputs) into a canonical Fabric
``EnvironmentTransitionDecision`` (Azazel-Fabric#9) and, when a shared transport
key is supplied, signs it with the canonical HMAC transport signature
(``azazel_fabric.deception_contracts.decision_signing``) that the Azazel-Deception
``TransitionExecutor`` already verifies. It is the producer counterpart to that
consumer.

Doctrine:

* Building/signing a decision grants no runtime authority and performs no live
  action -- it only produces the authoritative, schema-versioned, expiring,
  replay-safe decision record. Whether AZ-06 materializes it is gated entirely
  on AZ-06's own live posture; this module never contacts a decoy.
* Deterministic. ``as_of`` (the decision-time context) is supplied by the
  caller and is the only time source -- there is no ``datetime.now`` / RNG here,
  so the same inputs always yield the same decision (and the same signature).
* Every decision carries a unique ``decision_id`` (the AZ-06 anti-replay key), a
  ``[effective_at, expires_at)`` validity window, and Edge as the fixed
  authority; unknown/extra fields are rejected by the Fabric model.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

from azazel_fabric.deception_contracts import EnvironmentTransitionDecision

try:  # Canonical decision-signing lands in Fabric#9 (>= 0.8.0); optional here.
    from azazel_fabric.deception_contracts import sign_decision
except ImportError:  # pragma: no cover - exercised only on an older pinned Fabric
    sign_decision = None

_EXECUTABLE_STATUSES = frozenset({"accepted", "modified"})


class TransitionDecisionError(ValueError):
    """Raised when a transition decision cannot be built from the given inputs."""


def _parse_iso_aware(value: str, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise TransitionDecisionError(f"{field} must be a non-empty ISO-8601 timestamp string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise TransitionDecisionError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def derive_decision_id(
    *,
    environment_id: str,
    current_state: str,
    target_state: str,
    as_of: str,
    status: str = "accepted",
    expires_at: str | None = None,
    evidence_refs: Iterable[str] = (),
    reason_codes: Iterable[str] = (),
) -> str:
    """Deterministically derive a unique decision id from the salient inputs.

    Two *materially distinct* decisions get distinct ids, so AZ-06's one-shot
    anti-replay ledger (keyed purely on ``decision_id``) admits each exactly
    once; identical inputs reproduce the same id (replayable). Never random.

    The id binds every field that makes a decision distinct -- not only
    environment/state/time/evidence but also ``status``, the ``expires_at``
    validity bound, and ``reason_codes``. Omitting any of these would let two
    decisions that differ only in, say, status ("accepted" vs "modified") or
    window (a 60s vs a 10-year expiry) collide on one id: the consumer would
    then reject the second, independently-signed decision as a replay of the
    first, silently blackholing a legitimate corrected/re-scoped decision (and
    making *which* window/status is actually consumed depend on arrival order).

    The inputs are encoded as unambiguous JSON (not delimiter-joined), so a
    control character embedded in one field can never make two semantically
    different tuples hash to the same id -- which would otherwise collide their
    AZ-06 anti-replay slots and wrongly reject a legitimate transition.
    """

    canonical = json.dumps(
        [
            environment_id,
            current_state,
            target_state,
            as_of,
            status,
            expires_at,
            [str(e) for e in evidence_refs],
            [str(r) for r in reason_codes],
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"edge-transition-{digest}"


def build_transition_decision(
    *,
    environment_id: str,
    current_state: str,
    target_state: str,
    as_of: str,
    ttl_seconds: int = 300,
    status: str = "accepted",
    evidence_refs: Iterable[str] = (),
    reason_codes: Iterable[str] = (),
    decision_id: str | None = None,
    key: str | bytes | None = None,
) -> dict[str, Any]:
    """Build (and optionally sign) a canonical ``EnvironmentTransitionDecision``.

    ``effective_at`` is ``as_of`` and ``expires_at`` is ``as_of + ttl_seconds``
    (deterministic; no wall-clock). ``status`` must be executable
    (accepted/modified). When ``key`` is given the returned dict carries the
    canonical HMAC transport signature the AZ-06 consumer verifies; the
    signature is computed over the model's canonical JSON, so it round-trips
    through AZ-06 unchanged.
    """

    if status not in _EXECUTABLE_STATUSES:
        raise TransitionDecisionError(
            f"status must be one of {sorted(_EXECUTABLE_STATUSES)}, got {status!r}"
        )
    # bool is an int subclass; reject it explicitly so True/False can't pass as a ttl.
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise TransitionDecisionError("ttl_seconds must be a positive integer")

    effective_dt = _parse_iso_aware(as_of, field="as_of")
    try:
        # A very large ttl overflows timedelta/datetime arithmetic; keep the
        # module's contract that bad inputs raise TransitionDecisionError rather
        # than leaking a raw OverflowError to callers catching the former.
        expires_dt = effective_dt + timedelta(seconds=ttl_seconds)
    except (OverflowError, ValueError, OSError) as exc:
        raise TransitionDecisionError(
            f"ttl_seconds is out of range for a valid expiry: {ttl_seconds!r}"
        ) from exc
    evidence = [str(e) for e in evidence_refs]
    reasons = [str(r) for r in reason_codes]
    decision_id = decision_id or derive_decision_id(
        environment_id=environment_id,
        current_state=current_state,
        target_state=target_state,
        as_of=as_of,
        status=status,
        expires_at=expires_dt.isoformat(),
        evidence_refs=evidence,
        reason_codes=reasons,
    )

    try:
        decision = EnvironmentTransitionDecision(
            decision_id=decision_id,
            status=status,
            environment_id=environment_id,
            current_state=current_state,
            target_state=target_state,
            effective_at=effective_dt,
            expires_at=expires_dt,
            evidence_refs=evidence,
            reason_codes=reasons,
        )
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        raise TransitionDecisionError(f"invalid transition decision: {exc}") from exc

    payload = decision.model_dump(mode="json")
    if key is not None:
        if sign_decision is None:
            raise TransitionDecisionError(
                "signing a decision requires azazel_fabric >= 0.8.0 "
                "(deception_contracts.decision_signing, Fabric#9)"
            )
        payload = sign_decision(payload, key)
    return payload


def transition_decision_from_arbiter(
    arbiter_decision: Mapping[str, Any],
    *,
    environment_id: str,
    current_state: str,
    target_state: str,
    as_of: str,
    ttl_seconds: int = 300,
    status: str = "accepted",
    key: str | bytes | None = None,
) -> dict[str, Any]:
    """Build a transition decision from an Action-Arbiter ``decide()`` result.

    Pulls ``evidence_refs`` from the arbiter's ``chosen_evidence_ids`` and a
    single ``reason_code`` from the arbiter's ``reason`` so the AZ-06 decision is
    traceable back to exactly the evidence the arbiter selected. The arbiter
    remains the authority; this only records its decision in the canonical wire
    form.
    """

    if not isinstance(arbiter_decision, Mapping):
        raise TransitionDecisionError("arbiter_decision must be a mapping")
    chosen = arbiter_decision.get("chosen_evidence_ids") or []
    if not isinstance(chosen, (list, tuple)):
        raise TransitionDecisionError("arbiter_decision.chosen_evidence_ids must be a list")
    reason = arbiter_decision.get("reason")
    reason_codes = [str(reason)] if reason else []
    return build_transition_decision(
        environment_id=environment_id,
        current_state=current_state,
        target_state=target_state,
        as_of=as_of,
        ttl_seconds=ttl_seconds,
        status=status,
        evidence_refs=[str(e) for e in chosen],
        reason_codes=reason_codes,
        key=key,
    )
