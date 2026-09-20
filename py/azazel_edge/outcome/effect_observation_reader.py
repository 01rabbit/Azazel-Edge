"""Edge <- AZ-06: the read side of an effect observation.

Edge constructs the effect (`effect_export`); Azazel-Deception materializes it
and states what it observed. This module is where Edge reads that statement
back, which is what makes `effect_contracts` an exchanged contract rather than
a serialized one -- a contract that has only ever been written is not known to
interoperate, and the first read is where a disagreement shows
(Azazel-Fabric#23, the R1c evidence gate).

It mirrors `engagement_advisory_client` deliberately, including its two failure
disciplines, because the authority boundary is the same one:

* **Record verification is fail-CLOSED.** The payload is the canonical Fabric
  `EffectObservation` or it is rejected outright. Fabric's `extra="forbid"`
  means an observation cannot arrive carrying a field it was never allowed to
  hold, and `directive` is pinned `False` by the model.
* **Edge-operation availability is fail-OPEN.** AZ-06 is optional. A missing,
  malformed or rejected observation degrades to "nothing observed" and never
  raises into a caller, never blocks, and never changes what Edge's
  deterministic arbiter decides.

**What this module does not do.** It returns data. It selects no action, writes
into no decision path, and grants no authority. An observation says an effect
was seen in some state; whether that changes anything is the arbiter's
question, and the arbiter decides identically whether this module returned an
observation, returned nothing, or was never called.

Two narrowings Fabric does not make
-----------------------------------
Both were measured against the pinned models rather than assumed, and both are
stricter than the contract, never looser.

*An observation may not claim a decision.* `DefensiveEffectRef` refuses
`observed_fact` and `active_materialized` outright -- "that is an observation's
claim to make, not an effect reference's". The symmetric refusal is **missing**
on `EffectObservation`: measured, Fabric accepts `producer_decision_ref`,
`advisory_inference` and `planned_shadow` on one. A materializer's observation
carrying a decision's authority is precisely the confusion `authority_class`
exists to prevent, so this reader refuses it here and the gap is reported
upstream rather than worked around silently.

*A producer may not observe itself into evidence.* An observation whose
`materialization_producer` is Edge would be Edge vouching for its own
materialization through a contract meant to carry somebody else's statement.
"""

from __future__ import annotations

from typing import Any, Mapping

try:  # Fabric is an optional extra (requirements/fabric.txt), pinned to an exact tag.
    from azazel_fabric.effect_contracts import (
        AuthorityClass,
        EffectObservation,
        assert_effect_chain_consistent,
        assert_observation_within_effect_window,
    )

    _FABRIC_UNAVAILABLE: Exception | None = None
except ImportError as _exc:  # pragma: no cover - exercised by the absence test
    AuthorityClass = EffectObservation = None  # type: ignore[assignment]
    assert_effect_chain_consistent = assert_observation_within_effect_window = None  # type: ignore[assignment]
    _FABRIC_UNAVAILABLE = _exc

__all__ = [
    "OBSERVER_AUTHORITY_CLASSES",
    "ObservationRejected",
    "ReadResult",
    "read_effect_observation",
]

#: The only two claims an observer may make.
#:
#: Named rather than derived: the point is that Fabric's enum is wider here
#: than this boundary allows, so a set computed from the enum would be the
#: thing it is supposed to narrow.
OBSERVER_AUTHORITY_CLASSES = frozenset({"observed_fact", "active_materialized"})


class ObservationRejected(Exception):
    """The payload is not an observation Edge may read, and why."""


class ReadResult:
    """What the reader found. Three outcomes, not two.

    "AZ-06 answered and had nothing to report" and "AZ-06 is not there" are
    different facts, and an operator reading Edge's context needs to tell them
    apart. Folding them together is what `engagement_advisory_client` refuses
    to do with `no_advisory`, for the same reason.
    """

    __slots__ = ("observation", "reason")

    def __init__(self, observation: Any = None, reason: str = "") -> None:
        self.observation = observation
        self.reason = reason

    @property
    def observed(self) -> bool:
        return self.observation is not None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ReadResult(observed={self.observed}, reason={self.reason!r})"


def read_effect_observation(
    payload: Mapping[str, Any] | None, *, effect: Any = None
) -> ReadResult:
    """Read one observation, or report why there is none. Never raise.

    `effect` is optional and is the `DefensiveEffectRef` Edge holds for this
    effect. When it is supplied the observation is checked against it with
    Fabric's own chain and window rules, so a replayed `active` arriving after
    the effect expired is refused rather than read as a live environment.
    Without it the observation is still validated, but Edge has only the
    observation's word about which effect it belongs to.
    """

    if _FABRIC_UNAVAILABLE is not None:
        return ReadResult(reason=f"azazel_fabric is not installed ({_FABRIC_UNAVAILABLE})")
    if payload is None:
        return ReadResult(reason="no observation")

    try:
        observation = _verified(payload, effect)
    except ObservationRejected as exc:
        return ReadResult(reason=str(exc))
    except Exception as exc:  # noqa: BLE001 - availability is fail-open
        return ReadResult(reason=f"observation rejected ({type(exc).__name__}: {exc})")
    return ReadResult(observation=observation)


def _claimed_authority(payload: Mapping[str, Any]) -> str:
    """The raw claim, without asking Fabric to interpret it.

    An unrecognized value comes back as itself rather than being coerced to
    the weakest class. Fabric's coercion is right for Fabric -- an unknown
    input must not escalate -- but here it would turn "I could not read this"
    into `stale_or_unknown`, and this boundary would then refuse it with a
    message naming a class the payload never claimed.
    """

    raw = payload.get("authority_class")
    value = getattr(raw, "value", raw)
    return value if isinstance(value, str) else repr(raw)


def _verified(payload: Mapping[str, Any], effect: Any) -> Any:
    if not isinstance(payload, Mapping):
        raise ObservationRejected("an observation payload must be a mapping")

    # Read before the model is built, and this ordering is load-bearing.
    #
    # It used to run after. That worked while Fabric accepted every authority
    # class on an observation -- Edge's check was the only refusal there was.
    # `v0.9.0rc4` refuses four of them itself (Fabric#52), which made the
    # check below unreachable: Fabric raised first and an operator reading
    # Edge's context got a pydantic dump where Edge had a sentence explaining
    # what was wrong.
    #
    # Moving it up keeps it a guard rather than a comment. It also keeps the
    # refusal Edge's own, which matters if Fabric ever widens the class again
    # -- it narrowed in this direction once, and nothing says the next change
    # goes the same way.
    claimed = _claimed_authority(payload)
    if claimed not in OBSERVER_AUTHORITY_CLASSES:
        raise ObservationRejected(
            f"observation {payload.get('observation_id', '<unidentified>')!r} "
            f"claims {claimed!r}; an observer reports what it saw and does not "
            "carry a decision's authority"
        )

    observation = EffectObservation(**dict(payload))

    if observation.materialization_producer == "azazel-edge":
        raise ObservationRejected(
            "Edge will not read its own materialization back as evidence; an "
            "observation naming Edge as materializer is Edge vouching for itself"
        )

    if effect is not None:
        assert_effect_chain_consistent(effect, observations=[observation])
        assert_observation_within_effect_window(effect, observation)
    return observation
