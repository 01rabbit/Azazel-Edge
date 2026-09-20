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

import re
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


def test_edge_agrees_with_fabric_when_fabric_carries_the_vocabulary():
    """The drift guard the other two tests cannot be.

    Edge keeps its own `DEFENSIVE_STATES` on purpose. It is not the same thing
    as Knowledge or Deception holding a copy: those are advisory consumers, and
    a copy there is a second *definition* of a word they do not own. Edge is
    the authority that produces the state, and its arbiter must keep working
    with no `azazel_fabric` installed at all -- the deterministic control path
    never depends on an optional package (see `audit/fabric_adapter.py` and
    `fabric_view.py` for the same posture).

    What Edge must not do is drift. If Fabric ever gains, loses or renames a
    value, Edge staying green while disagreeing with the system-wide canon is
    exactly the failure Azazel#62 exists to prevent. So: no import at module
    scope, no dependency added, but when the pinned Fabric does carry the
    vocabulary the two must be identical.

    Skipping when Fabric is absent is deliberate and not a hole. The two tests
    around this one pin Edge's vocabulary by literal regardless, so Edge is
    never unguarded -- this one adds cross-product agreement on top, in the
    environments that can see both.
    """

    fabric = pytest.importorskip(
        "azazel_fabric.schema.defensive_state",
        reason="pinned azazel_fabric predates the canonical vocabulary (Fabric#14)",
    )

    fabric_values = {member.value for member in fabric.DefensiveState}

    assert fabric_values == DEFENSIVE_STATES, (
        f"Edge and Fabric disagree about the canonical vocabulary: "
        f"Edge has {sorted(DEFENSIVE_STATES)}, Fabric has {sorted(fabric_values)}. "
        "One definition is the whole point of Azazel#62 -- reconcile them "
        "rather than widening either side to accommodate the other."
    )


def test_the_fabric_pin_still_activates_the_drift_guard():
    """A guard that stops guarding must not do it silently.

    The test above skips when the pinned Fabric predates the vocabulary, which
    is correct -- but it means reverting `requirements/fabric.txt` to an older
    tag turns the drift guard off and everything stays green. Nothing would
    say so. This reads the pin file itself, so the revert is what fails,
    rather than the absence it would cause.

    It checks the declared pin, not the installed distribution: the two can
    differ in a stale local environment, and the tree is what CI installs from
    and what a reviewer reads.
    """

    pin_file = Path(__file__).resolve().parents[1] / "requirements" / "fabric.txt"
    pins = [
        line.strip()
        for line in pin_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    assert len(pins) == 1, f"expected exactly one requirement in {pin_file.name}: {pins}"
    tag = pins[0].rsplit("@", 1)[-1]

    assert re.fullmatch(r"v\d+\.\d+\.\d+(rc\d+|a\d+|b\d+)?", tag), (
        f"Fabric must be pinned to an exact tag, got {tag!r} -- "
        "pinning a branch is what this file's own policy forbids"
    )

    # The vocabulary landed in v0.9.0rc2. Compared as a tuple so that v0.10.0
    # and v1.0.0 read as newer, which a string comparison gets wrong.
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:rc(\d+))?", tag)
    assert match is not None, f"unparseable pin {tag!r}"
    release = tuple(int(part) for part in match.group(1, 2, 3))
    candidate = int(match.group(4)) if match.group(4) else None
    # A final release sorts after every candidate of the same version.
    ordered = release + (candidate if candidate is not None else float("inf"),)

    assert ordered >= (0, 9, 0, 2), (
        f"the Fabric pin {tag} predates v0.9.0rc2, so "
        "test_edge_agrees_with_fabric_when_fabric_carries_the_vocabulary now "
        "skips and Edge is no longer checked against the canonical vocabulary. "
        "If this downgrade is deliberate, say so here rather than letting the "
        "guard go quiet."
    )


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
