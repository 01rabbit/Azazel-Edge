"""Edge#379 / #390: one outward state vocabulary, and the words it is not.

This is a **terminology guard, not a behaviour change**. Edge#379 is explicit
that the migration "must not silently alter live enforcement semantics", so
nothing here asserts what the arbiter decides -- only what its output is
*called*, and that the other concepts historically described as a "mode" stay
separate from it.

What was already true, and is now held:

* the arbiter's own action table is keyed on exactly the five canonical
  Defensive States, so criterion 5 ("Arbiter output maps deterministically to
  the five states") holds today rather than needing new machinery;
* the `mode` key *inside* each action profile is a **control class**
  (`passive` / `human_loop` / `bounded_control` / `high_risk_control`), which
  is a different axis entirely and must never be read as a state;
* M.I.O. carries the five states and cannot set them.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py"))

from azazel_edge.arbiter.action import ActionArbiter  # noqa: E402
from azazel_edge.mio.contracts import DEFENSIVE_STATES  # noqa: E402

#: The canonical vocabulary (Azazel#62, Azazel-Fabric#14).
CANONICAL = frozenset({"OBSERVE", "NOTIFY", "THROTTLE", "REDIRECT", "ISOLATE"})

#: Legacy names. Permitted as concept branding; never a state vocabulary.
LEGACY_NAMES = frozenset({"portal", "shield", "scapegoat"})


def test_the_canonical_vocabulary_is_exactly_five_values():
    """Pinned by literal, not derived from the constant under test.

    A test that iterates `DEFENSIVE_STATES` to check `DEFENSIVE_STATES` follows
    it wherever it goes and cannot see a value being added or removed.
    """

    assert DEFENSIVE_STATES == set(CANONICAL)


def test_the_arbiters_action_table_is_the_canonical_vocabulary():
    """Criterion 5: arbiter output maps deterministically to the five states.

    It already does -- the table is keyed on them. This holds that, so an added
    or renamed action cannot quietly widen what Edge can outwardly be doing.
    """

    actions = {name.upper() for name in ActionArbiter.ACTION_PROFILES}

    assert actions == set(CANONICAL)


def test_the_control_class_inside_a_profile_is_not_a_state():
    """`mode` in an action profile answers a different question.

    `passive` / `human_loop` / `bounded_control` / `high_risk_control` describe
    how much control an action exerts and whether a human is in the loop. That
    axis is orthogonal to *what Edge is currently doing*, and the two sets must
    not overlap -- an overlap is how one gets read as the other.
    """

    control_classes = {
        str(profile["mode"]).upper() for profile in ActionArbiter.ACTION_PROFILES.values()
    }

    assert control_classes & CANONICAL == set(), (
        f"a control class collides with a Defensive State: "
        f"{sorted(control_classes & CANONICAL)}"
    )
    assert control_classes == {"PASSIVE", "HUMAN_LOOP", "BOUNDED_CONTROL", "HIGH_RISK_CONTROL"}


@pytest.mark.parametrize("state", sorted(CANONICAL))
def test_a_defensive_state_is_never_a_control_class(state):
    for profile in ActionArbiter.ACTION_PROFILES.values():
        assert str(profile["mode"]).upper() != state


def test_an_unknown_action_falls_back_to_the_weakest_state(): 
    """`action_profile` defaults to `observe`, which is the state that does
    least. An unknown action must not resolve to a stronger one."""
    profile = ActionArbiter.action_profile("not-a-real-action")

    assert profile == ActionArbiter.ACTION_PROFILES["observe"]
    assert profile["effect"] == "visibility_only"


def test_the_cross_product_projection_carries_no_legacy_default():
    """The outward projection must not assert a legacy state nobody chose.

    `build_edge_status_view` previously defaulted to `"shield"` when a snapshot
    carried no mode, which asserted a legacy posture out of the absence of one.
    Absence is not a state -- the same rule Knowledge applies to a reported
    Defensive State, for the same reason.
    """

    from azazel_edge import fabric_view

    source = Path(fabric_view.__file__).read_text(encoding="utf-8")

    for legacy in sorted(LEGACY_NAMES):
        assert f'or "{legacy}"' not in source and f"or '{legacy}'" not in source, (
            f"the projection falls back to the legacy name {legacy!r}; "
            "absence of a mode is not evidence of that mode"
        )


def test_the_projection_reports_unknown_rather_than_inventing_one():
    fabric_view = pytest.importorskip(
        "azazel_edge.fabric_view", reason="needs the module under test"
    )
    if not getattr(fabric_view, "HAVE_AZAZEL_FABRIC", False):
        pytest.skip("needs the optional azazel_fabric dependency")

    view = fabric_view.status_view_from_snapshot({"now_time": "2026-09-19T00:00:00+00:00"})

    assert view is not None
    # Pinned by literal, not read back from the constant under test. Deriving
    # the expectation from `UNKNOWN_MODE_NAME` would follow it wherever it went
    # -- including onto a canonical state, which is the one value it must not
    # become.
    assert view.mode.name == "unknown"
    assert view.mode.name not in LEGACY_NAMES


def test_the_unknown_marker_is_not_itself_a_defensive_state():
    """"The snapshot did not say" and "Edge is observing" are different facts.

    Setting the unknown marker to `observe` would make them indistinguishable
    on the wire, and every other assertion in this file would still pass --
    which is why this one is pinned against the canonical set by name.
    """

    from azazel_edge import fabric_view

    assert fabric_view.UNKNOWN_MODE_NAME.upper() not in CANONICAL
    assert fabric_view.UNKNOWN_MODE_NAME not in LEGACY_NAMES
