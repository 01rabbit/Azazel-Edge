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

#: What Fabric raises when a payload is not a valid record.
#:
#: Derived from Fabric's behaviour rather than imported. The class is
#: pydantic's, and Edge does not declare pydantic -- it arrives only with the
#: Fabric extra, and `tests/test_runtime_dependency_contract.py` refuses an
#: undeclared import. Adding pydantic to that test's allowance so this file
#: could name a class would be weakening a guard to suit a test.
#:
#: The `else` below is not ceremony. If Fabric ever accepts a payload with no
#: fields at all, that is a finding, and it surfaces here rather than as every
#: refusal test in this file quietly passing against `type(None)`.
try:
    EffectObservation()
except Exception as _probe:  # noqa: BLE001 - the class is what is wanted
    ValidationError = type(_probe)
else:  # pragma: no cover
    raise AssertionError(
        "EffectObservation accepted a payload with no fields; the refusal "
        "tests below would then be asserting nothing"
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
# A narrowing Edge made first, and Fabric now makes too
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "claimed", ["producer_decision_ref", "advisory_inference", "planned_shadow", "stale_or_unknown"]
)
def test_an_observation_may_not_carry_a_decisions_authority(claimed):
    """Refused twice, and the two refusals are not the same refusal.

    This test was written when Fabric accepted every one of these on an
    observation and asserted so: `assert EffectObservation(**payload)`, with
    the comment "the contract itself lets it through". That was measured, it
    was true, and it was the finding that became Fabric#52. `v0.9.0rc4`
    refuses them, so the assertion inverted -- which is the correct outcome
    for a test whose job was to record a gap until it closed.

    Both refusals stay, for a reason that had to be corrected while making
    this change. The first attempt said Edge's check covered the
    Fabric-absent configuration; it does not -- `read_effect_observation`
    returns early when Fabric is missing, so the check was never reached
    there either. Between that and Fabric raising first, it was unreachable
    in *both* configurations: a guard that existed and never ran.

    It now runs before the model is built, which is what makes keeping it
    worth anything. Fabric's refusal protects every consumer of the contract.
    Edge's produces Edge's own sentence for an operator reading Edge's
    context, instead of a pydantic dump, and does not assume the next change
    to `AuthorityClass` narrows the way this one did.
    """

    payload = an_observation(status="completed", authority_class=claimed)

    # The contract refuses to build it at all (Fabric#52, v0.9.0rc4)...
    with pytest.raises(ValidationError):
        EffectObservation(**payload)

    # ...and this boundary refuses the payload without needing the contract.
    result = read_effect_observation(payload, effect=an_effect())
    assert result.observed is False
    assert "decision's authority" in result.reason


def test_edges_own_refusal_reaches_the_operator_before_fabrics_does():
    """Otherwise Edge's sentence is dead code with a comment on it.

    Fabric refuses the same payload, so "is it refused" cannot tell whether
    Edge's check ran. What distinguishes them is the reason a reader gets:
    Edge's explains what an observer may claim, Fabric's is a validation dump.
    Reordering the two lines in `_verified` flips this assertion, which is
    what makes the ordering checked rather than merely intended.
    """

    result = read_effect_observation(
        an_observation(status="completed", authority_class="producer_decision_ref"),
        effect=an_effect(),
    )

    assert "decision's authority" in result.reason
    assert "ValidationError" not in result.reason, (
        "Fabric refused this before Edge did; Edge's check is unreachable and "
        "the operator is reading a pydantic dump instead of an explanation"
    )


def test_an_unreadable_authority_claim_is_refused_as_what_it_said():
    """Not coerced to the weakest class first.

    Fabric maps an unknown value to `stale_or_unknown` so that an unparseable
    record cannot escalate, which is right for Fabric. Doing it here would
    make this boundary refuse a payload with a message naming a class the
    payload never claimed, and an operator would go looking for a record that
    does not exist.
    """

    result = read_effect_observation(
        an_observation(status="completed", authority_class="not_a_class"),
        effect=an_effect(),
    )

    assert result.observed is False
    assert "not_a_class" in result.reason
    assert "stale_or_unknown" not in result.reason


def test_the_observer_classes_agree_with_fabrics_exactly():
    """Two statements of one set; this is what keeps them the same one.

    Until `v0.9.0rc4` this test asserted a strict subset -- Edge narrowing an
    enum Fabric left wide. Fabric has since narrowed it to the same two, so a
    subset assertion would now pass on an Edge set that had silently lost a
    member, and "these agree" is the property that actually matters.

    Edge still names the set literally rather than importing it. It has to:
    `effect_observation_reader` is on the deterministic path and must work
    with Fabric absent. That makes this a deliberate duplication, and a
    deliberate duplication is one with a test under it -- which is the whole
    difference between this and the coincidence of maintenance Azazel-Edge#413
    found, where a local dataclass matched a Fabric model field for field and
    nothing compared them.
    """

    from azazel_fabric.effect_contracts import OBSERVABLE_AUTHORITY_CLASSES

    assert OBSERVER_AUTHORITY_CLASSES == {
        member.value for member in OBSERVABLE_AUTHORITY_CLASSES
    }


def test_the_two_sides_still_partition_the_enum_between_them():
    """What each side must refuse, derived from the enum rather than restated.

    Enumerating from `AuthorityClass` is what lets a member added to Fabric
    later be *seen* here: it lands in the complement, and the loop below asks
    Edge to refuse it. A list kept in this file would cover exactly the four
    classes that existed when it was written.
    """

    every = {member.value for member in AuthorityClass}
    assert OBSERVER_AUTHORITY_CLASSES < every, (
        "Fabric's enum no longer has anything an observation may not claim; "
        "this boundary would then be narrowing nothing"
    )

    for claimed in sorted(every - OBSERVER_AUTHORITY_CLASSES):
        result = read_effect_observation(
            an_observation(status="completed", authority_class=claimed),
            effect=an_effect(),
        )
        assert result.observed is False, (
            f"{claimed!r} is not an observer class and this boundary read it "
            "anyway"
        )


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
