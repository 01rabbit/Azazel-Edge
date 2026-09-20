"""Edge mints the `effect:` id nothing in Azazel minted.

Azazel-Fabric's `effect_contracts` family is keyed on an `effect:`-typed id
produced by whoever constructed the effect. Measured across the series, no
repository minted one, so `EffectObservation` and `OutcomeObservationEnvelope`
had no possible producer anywhere -- Azazel-Deception owns those observations
and had nothing to make them against (Azazel-Deception#46).

The chain head belongs to Edge: `DefensiveEffectRef` carries
``authority_class = producer_decision_ref`` and Edge's arbiter is the only
decision authority in the series.

These tests are mostly about refusals, because that is where a projection like
this goes wrong: a default for a fact Edge does not hold produces a record that
validates and misreports, and the consumer has no way to tell.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py"))

from azazel_edge.outcome.contracts import (  # noqa: E402
    ActionExecutionReceipt,
    ExecutionStatus,
    MechanismKind,
)
from azazel_edge.outcome.effect_export import (  # noqa: E402
    EFFECT_CLASS_BY_MECHANISM,
    UNMAPPABLE_MECHANISMS,
    EffectExportRefused,
    effect_id_for,
    export_defensive_effect_ref,
    scope_ref_for,
)

fabric = pytest.importorskip(
    "azazel_fabric",
    reason="Fabric is an optional extra; the deterministic path does not need it",
)

from azazel_fabric.effect_contracts import (  # noqa: E402
    EffectClass,
    assert_effect_chain_consistent,
    parse_ref,
)


def a_receipt(**overrides) -> ActionExecutionReceipt:
    data = {
        "incident_id": "inc-1",
        "decision_id": "decision-1",
        "action_id": "action-1",
        "execution_id": "execution-1",
        "action_kind": "throttle",
        "provider": "tc",
        "scope": {"src_ip": "198.51.100.7", "dst_port": 443},
        "requested_parameters": {"rate_kbit": 256},
        "applied_parameters": {"rate_kbit": 256},
        "status": ExecutionStatus.APPLIED,
        "requested_at": "2026-09-20T12:00:00+00:00",
        "started_at": "2026-09-20T12:00:01+00:00",
        "completed_at": "2026-09-20T12:00:02+00:00",
        "expires_at": "2026-09-20T13:00:00+00:00",
    }
    data.update(overrides)
    return ActionExecutionReceipt(**data)


def export(**overrides):
    receipt = overrides.pop("receipt", a_receipt())
    data = {
        "mechanism_kind": "TRAFFIC_SHAPING",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "policy_ref": "policy:soc-default",
    }
    data.update(overrides)
    return export_defensive_effect_ref(receipt, **data)


# --------------------------------------------------------------------------
# The id, which is the point of the module
# --------------------------------------------------------------------------


def test_edge_mints_a_typed_effect_reference():
    record = export()

    kind, _ = parse_ref(record["effect_id"])
    assert kind is not None and kind.value == "effect"
    assert record["authority_class"] == "producer_decision_ref"
    assert record["decision_ref"] == "decision-1"
    assert record["directive"] is False


def test_the_effect_id_identifies_the_execution_and_not_the_mechanism():
    """An effect is what an execution established.

    If the observed mechanism were in the id, correcting a misread mechanism
    would silently create a second effect, and every observation already made
    against the first would be orphaned.
    """

    shaping = export(mechanism_kind="TRAFFIC_SHAPING")
    isolation = export(mechanism_kind="ISOLATION")

    assert shaping["effect_id"] == isolation["effect_id"]
    assert shaping["effect_class"] != isolation["effect_class"]


def test_two_executions_of_one_decision_are_two_effects():
    first = export()
    second = export(receipt=a_receipt(execution_id="execution-2"))

    assert first["effect_id"] != second["effect_id"]
    assert first["decision_ref"] == second["decision_ref"]


def test_replaying_one_execution_gives_the_same_effect():
    assert effect_id_for(a_receipt()) == effect_id_for(a_receipt())


def test_exactly_three_fields_determine_the_effect_id():
    """Everything else on the receipt is excluded, and this is what proves it.

    The obvious test -- export twice with different mechanisms and compare --
    varies an argument rather than the receipt, so it passes while a receipt
    field is quietly folded into the id. A mutation that added `action_kind`
    survived it.

    Every field below can be corrected after the fact: a mechanism is re-read,
    a lease is extended, a status moves from applied to released. None of those
    is a different effect, and an id that moved on any of them would orphan
    every observation already made against the old one.
    """

    varied = a_receipt(
        incident_id="inc-99",
        action_kind="isolate",
        provider="nft",
        scope={"src_ip": "203.0.113.9"},
        requested_parameters={"rate_kbit": 1},
        applied_parameters={"rate_kbit": 2},
        status=ExecutionStatus.FAILED,
        requested_at="2026-09-21T00:00:00+00:00",
        started_at="2026-09-21T00:00:01+00:00",
        completed_at="2026-09-21T00:00:02+00:00",
        expires_at="2026-09-21T01:00:00+00:00",
        reversible=True,
        release_ref="release-1",
    )

    assert effect_id_for(varied) == effect_id_for(a_receipt())

    for changed in (
        a_receipt(decision_id="decision-2"),
        a_receipt(action_id="action-2"),
        a_receipt(execution_id="execution-2"),
    ):
        assert effect_id_for(changed) != effect_id_for(a_receipt())


# --------------------------------------------------------------------------
# The scope handle
# --------------------------------------------------------------------------


def test_the_scope_crosses_as_an_opaque_handle_and_not_as_an_address():
    """Fabric's words: never "an address the receiver is expected to act on".

    The match fields stay Edge-local. What crosses is a digest Edge can resolve
    and a receiver cannot act on -- which is the whole reason the slot requires
    a typed opaque ref rather than a mapping.
    """

    record = export()

    kind, body = parse_ref(record["target_scope_ref"])
    assert kind is not None and kind.value == "scope"
    assert "198.51.100.7" not in json.dumps(record)
    assert "443" not in body


def test_the_scope_handle_ignores_key_order():
    reordered = a_receipt(scope={"dst_port": 443, "src_ip": "198.51.100.7"})

    assert scope_ref_for(reordered) == scope_ref_for(a_receipt())


def test_a_different_scope_is_a_different_handle():
    other = a_receipt(scope={"src_ip": "198.51.100.8", "dst_port": 443})

    assert scope_ref_for(other) != scope_ref_for(a_receipt())


# --------------------------------------------------------------------------
# Refusals: a fact Edge does not hold is never a default
# --------------------------------------------------------------------------


def test_an_action_with_no_lease_is_refused_rather_than_bounded_here():
    """The refusal that matters most.

    Fabric requires a bounded effect; `expires_at` is optional on Edge's
    receipt. Any value invented here would report that Edge time-boxed an
    effect it did not, in a record that validates.
    """

    with pytest.raises(EffectExportRefused, match="time-boxed"):
        export(receipt=a_receipt(expires_at=""))


def test_a_route_change_has_no_effect_class_and_is_not_given_a_neighbour():
    """`EffectClass` is deliberately small; a near-enough match is a wrong one."""

    with pytest.raises(EffectExportRefused, match="no route-change member"):
        export(mechanism_kind=MechanismKind.ROUTE_CHANGE.value)


def test_an_unknown_mechanism_is_refused_rather_than_failed_safe():
    """Fabric's fallback is a *consumer's*, and using it here would be a claim.

    Landing an unrecognized class on `observe_only` lets a consumer fail safe.
    A producer doing the same asserts `observe_only` about a mechanism it could
    not identify -- which is exactly the kind of statement `authority_class`
    exists to make legible.
    """

    with pytest.raises(EffectExportRefused, match="may not claim"):
        export(mechanism_kind=MechanismKind.UNKNOWN.value)


def test_a_mechanism_kind_nobody_classified_does_not_fall_through():
    """A new `MechanismKind` must be decided about, not defaulted."""

    with pytest.raises(EffectExportRefused, match="do not let it fall through"):
        export(mechanism_kind="QUANTUM_ENTANGLEMENT")


def test_every_edge_mechanism_kind_is_either_mapped_or_refused_with_a_reason():
    """No third category. An unclassified kind is one that will fall through."""

    classified = set(EFFECT_CLASS_BY_MECHANISM) | set(UNMAPPABLE_MECHANISMS)
    known = {kind.value for kind in MechanismKind}

    assert known == classified, (
        f"unclassified: {sorted(known - classified)}; "
        f"stale: {sorted(classified - known)}"
    )


def test_every_mapped_class_is_one_fabric_actually_has():
    for mechanism, effect_class in EFFECT_CLASS_BY_MECHANISM.items():
        assert EffectClass(effect_class), mechanism


def test_no_two_mechanisms_claim_the_same_effect_class():
    """A collision would make two observed mechanisms indistinguishable
    downstream, and the id deliberately does not carry the mechanism."""

    values = list(EFFECT_CLASS_BY_MECHANISM.values())
    assert len(set(values)) == len(values), values


# --------------------------------------------------------------------------
# What this unblocks
# --------------------------------------------------------------------------


def test_the_minted_reference_chains_with_a_materializers_observation():
    """The measurement that motivated this module, now satisfied.

    Azazel-Deception could not produce an `EffectObservation` because nothing
    minted the `effect:` id it is keyed on. Given one, the chain check passes.
    """

    from azazel_fabric.effect_contracts import AuthorityClass, DefensiveEffectRef, EffectObservation

    record = export()
    effect = DefensiveEffectRef(**record)

    observation = EffectObservation(
        observation_id="effect_observation:az06-1",
        effect_ref=record["effect_id"],
        trace_id=record["trace_id"],
        status="active",
        observed_at="2026-09-20T12:05:00+00:00",
        materialization_producer="azazel-deception",
        authority_class=AuthorityClass.ACTIVE_MATERIALIZED,
    )

    assert_effect_chain_consistent(effect, observations=[observation])


def test_a_stale_observation_cannot_prolong_the_effect():
    """The bound Edge refused to invent is what makes this check possible."""

    from azazel_fabric.effect_contracts import (
        AuthorityClass,
        DefensiveEffectRef,
        EffectObservation,
        assert_observation_within_effect_window,
    )

    record = export()
    effect = DefensiveEffectRef(**record)
    late = EffectObservation(
        observation_id="effect_observation:az06-2",
        effect_ref=record["effect_id"],
        trace_id=record["trace_id"],
        status="active",
        observed_at="2026-09-20T14:00:00+00:00",
        materialization_producer="azazel-deception",
        authority_class=AuthorityClass.ACTIVE_MATERIALIZED,
    )

    with pytest.raises(ValueError, match="cannot prolong"):
        assert_observation_within_effect_window(effect, late)


def test_nothing_on_the_deterministic_path_imports_this_module():
    """An export's unavailability must cost an export, not a decision."""

    import ast

    package = Path(__file__).resolve().parents[1] / "py" / "azazel_edge"
    importers = []
    for path in sorted(package.rglob("*.py")):
        if path.name == "effect_export.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "effect_export" in node.module:
                importers.append(str(path.relative_to(package)))
            elif isinstance(node, ast.Import) and any(
                "effect_export" in alias.name for alias in node.names
            ):
                importers.append(str(path.relative_to(package)))
    assert importers == [], f"{importers} import the effect export"
