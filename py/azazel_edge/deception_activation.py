"""Edge-side producers for canonical AZ-06 activation / termination decisions.

Sibling of :mod:`azazel_edge.deception_transition`. Edge is the sole authority
over deception-environment lifecycle. This module only *records*, in the
canonical Fabric wire form, a decision that Edge has **already made elsewhere**
(Action Arbiter / operator approval path), and, when a shared transport key is
supplied, signs it with the canonical HMAC transport signature
(``azazel_fabric.deception_contracts.decision_signing``) that the
Azazel-Deception adapter verifies.

Doctrine:

* **The builders decide nothing.** Every input is a value Edge has already
  fixed: package id/digest, target node, tier, budget, validity window, reason.
  Whether to activate or terminate is the caller's responsibility (the existing
  Edge decision path). There is no parameter through which a M.I.O. objective,
  hypothesis or other advisory can *cause* a decision.
* ``objective_refs`` (optional) is a record, not a trigger. It lists opaque
  ``advisory:`` references of a M.I.O. observation objective that Edge
  *considered* when it authorized, so the signed ``evidence_refs`` bind them
  (Azazel-Deception#55 / #59 reads exactly these). Passing refs never makes a
  decision acceptable, never widens a budget or window, and is refused unless
  the caller also supplies non-empty ``evidence_refs`` and ``reason_codes``
  without advisory kinds. That is a light lint against passing advice as the
  basis, not a guarantee of authorization: whether the basis is real is the
  calling Edge arbiter's responsibility, not checked here.
* Building/signing grants no runtime authority and performs no live action.
  There is no production caller yet; wiring is a separate, reviewed stage.
* Deterministic. ``as_of`` is the only time source (no ``datetime.now`` / RNG),
  so identical inputs yield the identical decision, id and signature.
* Fail-closed: only executable statuses (accepted/modified) can be issued;
  unknown or extra fields, a non-positive window, and a malformed ref raise
  :class:`ActivationDecisionError`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from azazel_fabric.deception_contracts import (
    EnvironmentActivationDecision,
    EnvironmentTerminationDecision,
    ResourceBudget,
)

try:  # Canonical decision-signing lands in Fabric#9 (>= 0.8.0); optional here.
    from azazel_fabric.deception_contracts import sign_decision
except ImportError:  # pragma: no cover - exercised only on an older pinned Fabric
    sign_decision = None

_EXECUTABLE_STATUSES = frozenset({"accepted", "modified"})

#: Upper bound on any single ref / reason string (matches the Deception reader).
MAX_REF_LENGTH = 200
MAX_OBJECTIVE_REFS = 16
MAX_HYPOTHESIS_REFS = 8
MAX_EVIDENCE_REFS = 32
MAX_REASON_CODES = 16

_OPAQUE_BODY = r"[A-Za-z0-9._~@=+:-]"
_DIGEST_PREFIX = "advisory:mio-objective-digest-"
_DIGEST_RE = re.compile(r"advisory:mio-objective-digest-[0-9a-f]{32}")
_OBJECTIVE_RE = re.compile(rf"advisory:mio-objective-{_OPAQUE_BODY}{{1,{MAX_REF_LENGTH - 14}}}")
_HYPOTHESIS_RE = re.compile(rf"advisory:mio-hypothesis-{_OPAQUE_BODY}{{1,{MAX_REF_LENGTH - 15}}}")
_FRAME_RE = re.compile(rf"advisory:mio-frame-{_OPAQUE_BODY}{{1,{MAX_REF_LENGTH - 10}}}")
_REASON_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")

#: Segments that make an "id" read as an instruction. A ref is an opaque
#: identifier; one that spells a verb is refused rather than carried into a
#: signed record.
_DIRECTIVE_SEGMENTS = frozenset(
    """
    activate activation deactivate execute exec run start stop open allow
    authorize authorized approve approved enable extend terminate withdraw block
    isolate quarantine redirect expose command shell sudo deploy install delete
    kill
    """.split()
)
# Mirror of the cross-repo set (CONVENTIONS C3); segments are split on _ - . ~ :
#: Kinds that name advice, not Edge's own evidence (CONVENTIONS C4).
_ADVISORY_KINDS = frozenset({"advisory", "observation_objective", "hypothesis", "frame"})
_SEGMENT_SPLIT = re.compile(r"[-._~:]+")


class ActivationDecisionError(ValueError):
    """Raised when an activation/termination decision cannot be built."""


def _parse_iso_aware(value: str, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ActivationDecisionError(f"{field} must be a non-empty ISO-8601 timestamp string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ActivationDecisionError(f"{field} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _window(as_of: str, ttl_seconds: int) -> tuple[datetime, datetime]:
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ActivationDecisionError("ttl_seconds must be a positive integer")
    start = _parse_iso_aware(as_of, field="as_of")
    try:
        return start, start + timedelta(seconds=ttl_seconds)
    except (OverflowError, ValueError, OSError) as exc:
        raise ActivationDecisionError(
            f"ttl_seconds is out of range for a valid expiry: {ttl_seconds!r}"
        ) from exc


def _string_list(values: Iterable[str] | None, *, field: str, limit: int) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, Mapping)):
        raise ActivationDecisionError(f"{field} must be a list of strings")
    out = list(values)
    if len(out) > limit:
        raise ActivationDecisionError(f"{field} has more than {limit} entries")
    for item in out:
        if not isinstance(item, str) or not item or len(item) > MAX_REF_LENGTH:
            raise ActivationDecisionError(
                f"{field} entries must be non-empty strings of at most {MAX_REF_LENGTH} characters"
            )
        if any(ch.isspace() or not ch.isprintable() for ch in item):
            raise ActivationDecisionError(f"{field} entries must not contain whitespace or control characters")
    return out


def _reject_directive(ref: str) -> None:
    body = ref.split(":", 1)[1]
    for segment in _SEGMENT_SPLIT.split(body.lower()):
        if segment in _DIRECTIVE_SEGMENTS:
            raise ActivationDecisionError(
                f"objective ref reads as an instruction ({segment!r}); refs must be opaque identifiers"
            )


def validate_objective_refs(objective_refs: Iterable[str] | None) -> list[str]:
    """Return the canonical (sorted, de-duplicated) objective refs, or raise.

    Accepted shapes only: ``advisory:mio-objective-<id>``,
    ``advisory:mio-hypothesis-<id>``, ``advisory:mio-frame-<id>`` and
    ``advisory:mio-objective-digest-<hex32>``. Exactly one objective, exactly
    one frame, at most :data:`MAX_HYPOTHESIS_REFS` hypotheses and at most one
    digest. A partial set is refused: the consumer binds the whole chain or
    retains the objective as advice, so a partial listing would only be noise
    in a signed record. ``None`` / empty returns ``[]`` (no objective recorded).
    """

    refs = _string_list(objective_refs, field="objective_refs", limit=MAX_OBJECTIVE_REFS)
    if not refs:
        return []
    if len(set(refs)) != len(refs):
        raise ActivationDecisionError("objective_refs must not contain duplicates")
    objectives: list[str] = []
    hypotheses: list[str] = []
    frames: list[str] = []
    digests: list[str] = []
    for ref in refs:
        if _DIGEST_RE.fullmatch(ref):
            digests.append(ref)
        elif ref.startswith(_DIGEST_PREFIX):
            raise ActivationDecisionError("objective digest ref must be 32 lowercase hex characters")
        elif _OBJECTIVE_RE.fullmatch(ref):
            _reject_directive(ref)
            objectives.append(ref)
        elif _HYPOTHESIS_RE.fullmatch(ref):
            _reject_directive(ref)
            hypotheses.append(ref)
        elif _FRAME_RE.fullmatch(ref):
            _reject_directive(ref)
            frames.append(ref)
        else:
            raise ActivationDecisionError(
                "objective_refs accepts only advisory:mio-objective-*, advisory:mio-hypothesis-*, "
                "advisory:mio-frame-* and advisory:mio-objective-digest-<hex32> references"
            )
    if len(objectives) != 1 or len(frames) != 1:
        raise ActivationDecisionError("objective_refs must carry exactly one objective ref and one frame ref")
    if len(hypotheses) > MAX_HYPOTHESIS_REFS:
        raise ActivationDecisionError(f"objective_refs has more than {MAX_HYPOTHESIS_REFS} hypothesis refs")
    if len(digests) > 1:
        raise ActivationDecisionError("objective_refs must carry at most one objective digest ref")
    return sorted(refs)


def _compose_evidence(
    evidence_refs: Iterable[str] | None,
    reason_codes: list[str],
    objective_refs: Iterable[str] | None,
) -> list[str]:
    own = _string_list(evidence_refs, field="evidence_refs", limit=MAX_EVIDENCE_REFS)
    for ref in own:
        kind = ref.split(":", 1)[0].strip().lower() if ":" in ref else ""
        if kind in _ADVISORY_KINDS:
            raise ActivationDecisionError(
                "evidence_refs must not carry advisory kinds (advisory, observation_objective, "
                "hypothesis, frame); MIO refs go through objective_refs only"
            )
    objective = validate_objective_refs(objective_refs)
    if objective and (not own or not reason_codes):
        raise ActivationDecisionError(
            "objective_refs may only annotate a decision that already has Edge's own "
            "evidence_refs and reason_codes; an advisory alone cannot be the basis"
        )
    return own + objective


def _reason_codes(values: Iterable[str] | None) -> list[str]:
    out = _string_list(values, field="reason_codes", limit=MAX_REASON_CODES)
    for item in out:
        if not _REASON_RE.fullmatch(item):
            raise ActivationDecisionError(f"reason_codes entry is not a short opaque code: {item!r}")
    return out


def _digest(prefix: str, parts: list[Any]) -> str:
    canonical = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return f"{prefix}-{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:24]}"


def derive_activation_decision_id(
    *,
    package_id: str,
    package_digest: str,
    target_node_id: str,
    selected_tier: str,
    budget: Mapping[str, Any],
    status: str,
    effective_at: str,
    expires_at: str,
    evidence_refs: Iterable[str] = (),
    reason_codes: Iterable[str] = (),
) -> str:
    """Deterministic id binding every field that makes two activations distinct.

    Same rationale as ``derive_decision_id`` in ``deception_transition``: the
    AZ-06 anti-replay ledger is keyed on ``decision_id`` alone, so two
    materially different decisions must never share one. Never random.
    """

    return _digest(
        "edge-activation",
        [
            package_id, package_digest, target_node_id, selected_tier,
            dict(budget), status, effective_at, expires_at,
            [str(e) for e in evidence_refs], [str(r) for r in reason_codes],
        ],
    )


def derive_termination_decision_id(
    *,
    environment_id: str,
    reason: str,
    issued_at: str,
    expires_at: str,
    evidence_refs: Iterable[str] = (),
) -> str:
    """Deterministic id for a termination (see :func:`derive_activation_decision_id`)."""

    return _digest(
        "edge-termination",
        [environment_id, reason, issued_at, expires_at, [str(e) for e in evidence_refs]],
    )


def _sign(payload: dict[str, Any], key: str | bytes | None) -> dict[str, Any]:
    if key is None:
        return payload
    if sign_decision is None:
        raise ActivationDecisionError(
            "signing a decision requires azazel_fabric >= 0.8.0 "
            "(deception_contracts.decision_signing, Fabric#9)"
        )
    return sign_decision(payload, key)


def build_activation_decision(
    *,
    package_id: str,
    package_digest: str,
    target_node_id: str,
    selected_tier: str,
    budget: Mapping[str, Any] | ResourceBudget,
    as_of: str,
    ttl_seconds: int = 300,
    status: str = "accepted",
    evidence_refs: Iterable[str] = (),
    reason_codes: Iterable[str] = (),
    objective_refs: Iterable[str] | None = None,
    decision_id: str | None = None,
    key: str | bytes | None = None,
) -> dict[str, Any]:
    """Record (and optionally sign) an activation Edge has already authorized.

    This function does **not** decide to activate. The caller has done that
    through Edge's own decision path and passes the resulting values.
    ``effective_at`` is ``as_of`` and ``expires_at`` is ``as_of + ttl_seconds``;
    ``status`` must be executable (accepted/modified).

    ``objective_refs`` records which M.I.O. objective Edge considered (see the
    module docstring and :func:`validate_objective_refs`). It is advice that was
    looked at, never a reason to authorize: it requires Edge's own
    ``evidence_refs`` and ``reason_codes``, and it changes neither the budget,
    the window nor the status. It is appended to ``evidence_refs`` and is
    covered by the signature.
    """

    if status not in _EXECUTABLE_STATUSES:
        raise ActivationDecisionError(
            f"status must be one of {sorted(_EXECUTABLE_STATUSES)}, got {status!r}"
        )
    effective_dt, expires_dt = _window(as_of, ttl_seconds)
    reasons = _reason_codes(reason_codes)
    evidence = _compose_evidence(evidence_refs, reasons, objective_refs)
    budget_data = budget.model_dump(mode="json") if isinstance(budget, ResourceBudget) else budget
    if not isinstance(budget_data, Mapping):
        raise ActivationDecisionError("budget must be a mapping or ResourceBudget")

    try:
        budget_model = ResourceBudget.model_validate(dict(budget_data))
        if budget_model.bandwidth_kbps is None:
            # The consumer refuses an unbounded allocation; fail here, earlier.
            raise ActivationDecisionError("budget must declare a finite bandwidth_kbps")
        decision = EnvironmentActivationDecision(
            decision_id=decision_id
            or derive_activation_decision_id(
                package_id=package_id,
                package_digest=package_digest,
                target_node_id=target_node_id,
                selected_tier=selected_tier,
                budget=budget_model.model_dump(mode="json"),
                status=status,
                effective_at=effective_dt.isoformat(),
                expires_at=expires_dt.isoformat(),
                evidence_refs=evidence,
                reason_codes=reasons,
            ),
            status=status,
            package_id=package_id,
            package_digest=package_digest,
            target_node_id=target_node_id,
            selected_tier=selected_tier,
            budget=budget_model,
            effective_at=effective_dt,
            expires_at=expires_dt,
            evidence_refs=evidence,
            reason_codes=reasons,
        )
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        if isinstance(exc, ActivationDecisionError):
            raise
        raise ActivationDecisionError(f"invalid activation decision: {exc}") from exc

    return _sign(decision.model_dump(mode="json"), key)


def build_termination_decision(
    *,
    environment_id: str,
    reason: str,
    as_of: str,
    ttl_seconds: int = 300,
    evidence_refs: Iterable[str] = (),
    objective_refs: Iterable[str] | None = None,
    decision_id: str | None = None,
    key: str | bytes | None = None,
) -> dict[str, Any]:
    """Record (and optionally sign) a termination Edge has already authorized.

    Like :func:`build_activation_decision` this decides nothing: drift, lease
    expiry or an operator request must already have been judged by the caller.
    ``issued_at`` is ``as_of``; ``expires_at`` is ``as_of + ttl_seconds``. The
    Fabric termination model carries a single opaque ``reason`` code; that is
    Edge's stated basis, and ``objective_refs`` additionally requires Edge's own
    non-empty ``evidence_refs``.
    """

    if not isinstance(reason, str) or not _REASON_RE.fullmatch(reason):
        raise ActivationDecisionError("reason must be a short opaque code ([A-Za-z0-9._-]{1,64})")
    issued_dt, expires_dt = _window(as_of, ttl_seconds)
    evidence = _compose_evidence(evidence_refs, [reason], objective_refs)
    try:
        decision = EnvironmentTerminationDecision(
            decision_id=decision_id
            or derive_termination_decision_id(
                environment_id=environment_id,
                reason=reason,
                issued_at=issued_dt.isoformat(),
                expires_at=expires_dt.isoformat(),
                evidence_refs=evidence,
            ),
            environment_id=environment_id,
            reason=reason,
            issued_at=issued_dt,
            expires_at=expires_dt,
            evidence_refs=evidence,
        )
    except ValueError as exc:
        raise ActivationDecisionError(f"invalid termination decision: {exc}") from exc
    return _sign(decision.model_dump(mode="json"), key)
