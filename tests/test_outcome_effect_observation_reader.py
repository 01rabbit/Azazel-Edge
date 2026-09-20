"""Edge reads back what AZ-06 observed, which is what exchanges the contract.

`effect_contracts` had two producers and no consumer: the records had been
serialized and never read. The R1c gate asks whether the two sides agree, and
the first read is where a disagreement shows. Azazel-Deception#48 is the other
consumer; this is Edge's.

Most of what follows is about refusals and about availability, because those
are the two ways a read side goes wrong: it accepts something it should not, or
its absence changes what the arbiter does.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py"))

from azazel_edge.outcome.effect_observation_reader import (  # noqa: E402
    OBSERVER_AUTHORITY_CLASSES,
    read_effect_observation,
)

fabric = pytest.importorskip(
    "azazel_fabric",
    reason="Fabric is an optional extra; the deterministic path does not need it",
)

from azazel_fabric.effect_contracts import (  # noqa: E402
    AuthorityClass,
    DefensiveEffectRef,
    EffectObservation,
)


def an_effect(**overrides) -> DefensiveEffectRef:
    data = {
        "effect_id": "effect:cff74a8556ff401bc72249812018afcc",
        "effect_class": "redirect_to_presented_terrain",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": "trace-1",
        "decision_ref": "decision-1",
        "target_scope_ref": "scope:6617f9307d832d50e04395e5604619cd",
        "policy_ref": "policy:soc-default",
        "created_at": "2026-09-20T12:00:00+00:00",
        "expires_at": "2026-09-20T13:00:00+00:00",
        "authority_class": "producer_decision_ref",
    }
    data.update(overrides)
    return DefensiveEffectRef(**data)


def an_observation(**overrides) -> dict:
    """Shaped as Azazel-Deception's `observe_effect` emits one."""

    data = {
        "observation_id": "effect_observation:f5bcec11a1362af80fd98cba",
        "effect_ref": "effect:cff74a8556ff401bc72249812018afcc",
        "trace_id": "trace-1",
        "status": "active",
        "observed_at": "2026-09-20T12:05:00+00:00",
        "materialization_producer": "azazel-deception",
        "authority_class": "active_materialized",
    }
    data.update(overrides)
    return data


# --------------------------------------------------------------------------
# The read
# --------------------------------------------------------------------------


def test_an_az06_observation_is_read_and_chains_to_the_effect():
    result = read_effect_observation(an_observation(), effect=an_effect())

    assert result.observed is True
    assert result.observation.materialization_producer == "azazel-deception"
    assert result.observation.directive is False
    assert result.reason == ""


def test_the_record_is_fabrics_statement_and_is_not_restated_here():
    """A malformed payload is refused by the model, not by a local check."""

    for broken in (
        an_observation(observation_id="not-a-typed-ref"),
        an_observation(effect_ref="lifecycle:l1"),
        an_observation(status="terminated"),  # no termination_reason
        an_observation(status="completed"),  # active_materialized on a dead status
        {**an_observation(), "directive": True},
        {**an_observation(), "unexpected": 1},
    ):
        assert read_effect_observation(broken, effect=an_effect()).observed is False


# --------------------------------------------------------------------------
# Two narrowings Fabric does not make
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claimed", ["producer_decision_ref", "advisory_inference", "planned_shadow", "stale_or_unknown"]
)
def test_an_observation_may_not_carry_a_decisions_authority(claimed):
    """Measured: Fabric accepts every one of these on an observation.

    `DefensiveEffectRef` refuses `observed_fact` and `active_materialized`
    outright -- "that is an observation's claim to make, not an effect
    reference's". The symmetric refusal is missing here, so a materializer's
    observation can assert it carries a decision's authority. That is the
    confusion `authority_class` exists to prevent.
    """

    payload = an_observation(status="completed", authority_class=claimed)

    # The contract itself lets it through...
    assert EffectObservation(**payload)

    # ...and this boundary does not.
    result = read_effect_observation(payload, effect=an_effect())
    assert result.observed is False
    assert "decision's authority" in result.reason


def test_the_observer_classes_are_pinned_rather_than_derived():
    """A set computed from Fabric's enum would be the thing it must narrow."""

    assert OBSERVER_AUTHORITY_CLASSES == {"observed_fact", "active_materialized"}
    assert OBSERVER_AUTHORITY_CLASSES < {member.value for member in AuthorityClass}


def test_edge_will_not_read_its_own_materialization_back_as_evidence():
    result = read_effect_observation(
        an_observation(materialization_producer="azazel-edge"), effect=an_effect()
    )

    assert result.observed is False
    assert "vouching for itself" in result.reason


# --------------------------------------------------------------------------
# Fabric's own rules, applied by calling them
# --------------------------------------------------------------------------


def test_a_stale_live_observation_is_refused():
    """A replayed `active` after expiry is how a bounded effect silently
    becomes unbounded."""

    result = read_effect_observation(
        an_observation(observed_at="2026-09-20T14:00:00+00:00"), effect=an_effect()
    )

    assert result.observed is False
    assert "prolong" in result.reason


def test_an_observation_from_another_trace_does_not_chain():
    assert (
        read_effect_observation(an_observation(trace_id="trace-9"), effect=an_effect()).observed
        is False
    )


def test_an_observation_of_another_effect_does_not_chain():
    other = an_observation(effect_ref="effect:0000000000000000000000000000000a")

    assert read_effect_observation(other, effect=an_effect()).observed is False


def test_without_the_effect_the_observation_is_still_validated():
    """Edge then has only the observation's word about what it belongs to,
    which is worth less -- but a malformed record is still refused."""

    assert read_effect_observation(an_observation()).observed is True
    assert read_effect_observation(an_observation(observation_id="x")).observed is False


# --------------------------------------------------------------------------
# Availability is fail-open
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "absent", [None, {}, {"observation_id": "effect_observation:o1"}, "not-a-mapping", 42]
)
def test_nothing_the_reader_is_handed_can_raise(absent):
    """AZ-06 is optional. Its absence, its silence and its mistakes all degrade
    to "nothing observed" and never reach a caller as an exception."""

    result = read_effect_observation(absent, effect=an_effect())

    assert result.observed is False
    assert result.reason


def test_absence_and_a_refusal_are_different_reasons():
    """"AZ-06 is not there" and "AZ-06 said something Edge will not read" are
    different facts, and an operator needs to tell them apart."""

    absent = read_effect_observation(None)
    refused = read_effect_observation(
        an_observation(materialization_producer="azazel-edge"), effect=an_effect()
    )

    assert absent.reason == "no observation"
    assert refused.reason != absent.reason


def test_nothing_on_the_deterministic_path_imports_this_reader():
    """An optional contract's absence must cost a read, not a decision."""

    package = Path(__file__).resolve().parents[1] / "py" / "azazel_edge"
    importers = []
    for path in sorted(package.rglob("*.py")):
        if path.name == "effect_observation_reader.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(
                "effect_observation_reader"
            ):
                importers.append(path.relative_to(package).as_posix())
            elif isinstance(node, ast.Import) and any(
                alias.name.endswith("effect_observation_reader") for alias in node.names
            ):
                importers.append(path.relative_to(package).as_posix())
    assert importers == [], f"{importers} import the observation reader"


def test_the_round_trip_edge_built_is_the_one_edge_reads():
    """End to end across two products, through Fabric in both directions.

    Edge's exporter mints the effect; AZ-06's shape of observation comes back;
    this reader accepts it. That is the exchange the R1c gate is asking about,
    and until both halves existed it had never happened.
    """

    from azazel_edge.outcome.contracts import ActionExecutionReceipt, ExecutionStatus
    from azazel_edge.outcome.effect_export import export_defensive_effect_ref

    receipt = ActionExecutionReceipt(
        incident_id="inc-1",
        decision_id="decision-1",
        action_id="action-1",
        execution_id="execution-1",
        action_kind="redirect",
        provider="nft",
        scope={"src_ip": "198.51.100.7"},
        requested_parameters={},
        applied_parameters={},
        status=ExecutionStatus.APPLIED,
        requested_at="2026-09-20T12:00:00+00:00",
        started_at="2026-09-20T12:00:01+00:00",
        completed_at="2026-09-20T12:00:02+00:00",
        expires_at="2026-09-20T13:00:00+00:00",
    )
    exported = export_defensive_effect_ref(
        receipt,
        mechanism_kind="REDIRECTION",
        producer_node="edge-1",
        trace_id="trace-1",
        policy_ref="policy:soc-default",
    )
    effect = DefensiveEffectRef(**exported)

    observation = an_observation(
        effect_ref=exported["effect_id"], trace_id=exported["trace_id"]
    )
    result = read_effect_observation(observation, effect=effect)

    assert result.observed is True
    assert result.observation.effect_ref == exported["effect_id"]
