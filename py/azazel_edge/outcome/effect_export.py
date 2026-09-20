"""Mint the `effect:` reference nothing in Azazel mints, from Edge's receipts.

Azazel-Fabric's `effect_contracts` family (Fabric#15) is keyed on an
`effect:`-typed id produced by whoever constructed the effect. Measured across
the series, **no repository minted one**, so two of the family's records --
`EffectObservation` and `OutcomeObservationEnvelope` -- had no possible
producer anywhere, whatever product adopted the family. Azazel-Deception, which
is the materializer and therefore owns those observations, had nothing to make
them against (Azazel-Deception#46).

The chain head belongs here. `DefensiveEffectRef` carries
``authority_class = producer_decision_ref``, and Edge's deterministic arbiter is
the only decision authority in the series; a product that did not decide cannot
honestly claim that class. So Edge mints the id, and AZ-06 can then observe
against it.

What this is not
----------------
Not a planner, not a selector, not an enforcement path. It reads an
`ActionExecutionReceipt` that Edge's arbiter already produced and renders it as
a cross-series reference. Nothing here decides, ranks, or applies anything, and
nothing on the deterministic decision or enforcement path imports this module:
its unavailability costs an export, not a decision.

**There is deliberately no fallback**, on the same reasoning as
`shared_export`: a record Fabric did not validate must never travel as one that
it did.

Facts Edge does not hold are refused, never defaulted
-----------------------------------------------------
Three of them, and each default would produce a record that validates and
misreports:

*An unbounded action.* Fabric requires `expires_at` after `created_at`;
`ActionExecutionReceipt.expires_at` is optional and empty for an action with no
lease. Inventing a bound would tell a consumer that Edge time-boxed an effect
it did not.

*A mechanism Fabric has no class for.* `ROUTE_CHANGE` is not in `EffectClass`,
which is deliberately small -- Fabric names an effect so two products can talk
about the same one and does not enumerate every effect a product can build.
Mapping it onto a neighbour would describe a different effect.

*`UNKNOWN`.* Fabric lands an unrecognized class on `observe_only` so that a
*consumer* fails safe. A *producer* doing the same would be asserting
`observe_only` about a mechanism it could not identify, which is a claim, not a
fallback.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

try:  # Fabric is an optional extra (requirements/fabric.txt), pinned to an exact tag.
    from azazel_fabric.effect_contracts import (
        AuthorityClass,
        DefensiveEffectRef,
        EffectClass,
    )

    _FABRIC_UNAVAILABLE: Exception | None = None
except ImportError as _exc:  # pragma: no cover - exercised by the absence test
    AuthorityClass = DefensiveEffectRef = EffectClass = None  # type: ignore[assignment]
    _FABRIC_UNAVAILABLE = _exc

from .contracts import ActionExecutionReceipt, MechanismKind

__all__ = [
    "EFFECT_CLASS_BY_MECHANISM",
    "UNMAPPABLE_MECHANISMS",
    "EffectExportRefused",
    "effect_id_for",
    "export_defensive_effect_ref",
    "scope_ref_for",
]


class EffectExportRefused(Exception):
    """Edge does not hold a fact the Fabric record requires, and says which."""


#: Edge's observed mechanism kinds, onto Fabric's effect classes.
#:
#: Written out rather than derived from either side. A mapping generated from
#: name similarity would have paired `ROUTE_CHANGE` with something, and the
#: whole value of this table is that two entries are missing from it.
EFFECT_CLASS_BY_MECHANISM: Mapping[str, str] = {
    MechanismKind.TRAFFIC_SHAPING.value: "rate_limit",
    MechanismKind.REDIRECTION.value: "redirect_to_presented_terrain",
    MechanismKind.ISOLATION.value: "network_isolation",
    MechanismKind.NOTIFICATION.value: "notify_only",
    MechanismKind.OBSERVATION_ONLY.value: "observe_only",
}

#: The two Edge mechanisms this family cannot describe, and why each one is a
#: refusal rather than a near-enough match.
UNMAPPABLE_MECHANISMS: Mapping[str, str] = {
    MechanismKind.ROUTE_CHANGE.value: (
        "EffectClass has no route-change member. It is deliberately small: "
        "Fabric names an effect so two products can talk about the same one, "
        "not every effect a product can build. The nearest members describe "
        "different effects"
    ),
    MechanismKind.UNKNOWN.value: (
        "a producer may not claim an effect class for a mechanism it could not "
        "identify. Fabric's fallback to observe_only exists so a consumer fails "
        "safe; used here it would be Edge asserting observe_only"
    ),
}


def _require_fabric() -> None:
    if _FABRIC_UNAVAILABLE is not None:
        raise EffectExportRefused(
            f"azazel_fabric is not installed ({_FABRIC_UNAVAILABLE}); a record "
            "Fabric did not validate must not travel as one that it did"
        )


def _opaque(*parts: str) -> str:
    material = "\x1f".join(parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def effect_id_for(receipt: ActionExecutionReceipt) -> str:
    """The `effect:` id for one execution. Deterministic, and Edge's to mint.

    Derived from the decision, the action and the execution together, so two
    executions of one decision get two effects and a replay of one execution
    gets the same effect. Nothing about the mechanism goes into it: an effect
    is the thing the execution established, and its identity must not move if
    the observed mechanism is later corrected.
    """

    return "effect:" + _opaque(
        receipt.decision_id, receipt.action_id, receipt.execution_id
    )


def scope_ref_for(receipt: ActionExecutionReceipt) -> str:
    """A `scope:` handle for what the effect applies to.

    Fabric requires an opaque typed reference here and says why: it must never
    be "a provider command" or "an address the receiver is expected to act on".
    Edge's scope is a mapping of match fields, so the projection publishes a
    digest of it. The scope map stays Edge-local; what crosses is a handle Edge
    can resolve and a receiver cannot act on.

    Canonical JSON, so two receipts with the same scope written in a different
    key order get the same handle.
    """

    canonical = json.dumps(
        dict(receipt.scope), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return "scope:" + _opaque(canonical)


def export_defensive_effect_ref(
    receipt: ActionExecutionReceipt,
    *,
    mechanism_kind: str,
    producer_node: str,
    trace_id: str,
    policy_ref: str,
    profile_ref: str | None = None,
    config_digest: str | None = None,
) -> dict[str, Any]:
    """Render one receipt as a `DefensiveEffectRef`, or refuse and say why.

    Returns the dumped record, matching `shared_export`'s surface: the caller
    gets Fabric's shape, and it got there by Fabric validating it.

    `mechanism_kind` is supplied rather than read off the receipt because the
    receipt records the action Edge *requested* and the mechanism is what was
    *observed* -- `AppliedMechanism` is a separate record for that reason, and
    collapsing the two here would let a requested action stand in for an
    observed one.
    """

    _require_fabric()

    reason = UNMAPPABLE_MECHANISMS.get(mechanism_kind)
    if reason is not None:
        raise EffectExportRefused(f"{mechanism_kind}: {reason}")
    effect_class = EFFECT_CLASS_BY_MECHANISM.get(mechanism_kind)
    if effect_class is None:
        raise EffectExportRefused(
            f"{mechanism_kind!r} is not an Edge mechanism kind this module maps; "
            "add it to EFFECT_CLASS_BY_MECHANISM or to UNMAPPABLE_MECHANISMS with "
            "a reason, but do not let it fall through to a neighbour"
        )

    if not receipt.requested_at:
        raise EffectExportRefused(
            "the receipt records no requested_at, and Fabric's reference has no "
            "form for an effect that never began"
        )
    if not receipt.expires_at:
        raise EffectExportRefused(
            "this action carries no lease. Fabric requires a bounded effect, and "
            "a bound invented here would report that Edge time-boxed an effect "
            "it did not"
        )

    record = DefensiveEffectRef(
        effect_id=effect_id_for(receipt),
        effect_class=EffectClass(effect_class),
        producer_product="azazel-edge",
        producer_node=producer_node,
        trace_id=trace_id,
        decision_ref=receipt.decision_id,
        target_scope_ref=scope_ref_for(receipt),
        policy_ref=policy_ref,
        profile_ref=profile_ref,
        config_digest=config_digest,
        created_at=receipt.requested_at,
        expires_at=receipt.expires_at,
        # Edge's arbiter decided this. It is the one product that can say so,
        # and Fabric then requires the decision to be named -- which it is.
        authority_class=AuthorityClass.PRODUCER_DECISION_REF,
    )
    return record.model_dump(mode="json")
