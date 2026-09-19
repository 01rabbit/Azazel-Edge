"""The shared export is Fabric's shape, and it never quietly becomes Edge's again.

Azazel-Edge#413: `shared_export.py` emitted four `schema_version` values as
literal dicts while Azazel-Fabric defined the same four as Pydantic models. The
literals matched Fabric byte-for-byte — not by construction, but because nobody
had changed either side yet. Two definitions of one contract stay equal only
until one of them moves.

The module now builds Fabric's models. These tests hold the three properties
that make that worth doing:

1. the wire shape did not change when the source of truth did (golden fixture
   captured from the pre-change implementation and committed with it);
2. a Fabric model that tightens fails **visibly** at the export boundary;
3. Fabric's absence raises rather than falling back to a locally shaped dict.

They assert nothing about Edge's authority, which this change does not touch:
the deterministic arbiter decides and enforces whether or not Fabric is
installed, and nothing on that path imports this module.
"""

from __future__ import annotations

import importlib
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from azazel_edge.outcome.adapter import from_rust_event
from azazel_edge.outcome import shared_export
from azazel_edge.outcome.shared_export import (
    SharedOutcomeExportError,
    assessment_to_shared_v0,
    execution_to_shared_v0,
    mechanism_to_shared_v0,
    outcome_to_shared_v0,
)

from test_outcome_shared_export import _assessment, _objective, _outcome, rust_event

GOLDEN = Path(__file__).resolve().parent / "fixtures" / "outcome" / "shared_v0_wire_shape_golden.json"

#: The four contracts Fabric owns, and the Edge function that projects onto each.
PROJECTIONS = ("execution", "mechanism", "outcome", "assessment")


def _export_all(action: str) -> dict[str, dict]:
    bundle = from_rust_event(rust_event(action))
    objective = _objective(bundle.correlation.decision_id)
    outcome = _outcome(bundle, objective)
    assessment = _assessment(bundle, objective, outcome)
    correlation = replace(
        bundle.correlation,
        objective_id=objective.objective_id,
        outcome_id=outcome.outcome_id,
        effect_assessment_id=assessment.effect_assessment_id,
    )
    return {
        "execution": execution_to_shared_v0(
            bundle.correlation, bundle.execution, producer_node="edge-1"
        ),
        "mechanism": mechanism_to_shared_v0(
            bundle.correlation, bundle.mechanism, producer_node="edge-1"
        ),
        "outcome": outcome_to_shared_v0(correlation, outcome, producer_node="edge-1"),
        "assessment": assessment_to_shared_v0(
            correlation, assessment, objective, outcome, producer_node="edge-1"
        ),
    }


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@pytest.mark.parametrize("action", ["throttle", "redirect"])
@pytest.mark.parametrize("kind", PROJECTIONS)
def test_projecting_through_fabric_did_not_change_the_wire_shape(action, kind):
    """The golden file was produced by the literal-dict implementation.

    It is checked in alongside the change that replaced that implementation, so
    a match is evidence that the representation moved and the contract did not.
    """

    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    produced = _export_all(action)[kind]
    assert _canonical(produced) == _canonical(golden[f"{action}/{kind}"])


def test_the_golden_file_covers_every_contract_this_module_projects():
    """A projection added without a golden entry would be silently unguarded."""

    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
    expected = {f"{a}/{k}" for a in ("throttle", "redirect") for k in PROJECTIONS}
    assert set(golden) == expected


@pytest.mark.parametrize("kind", PROJECTIONS)
def test_a_tightened_fabric_model_fails_visibly_rather_than_being_routed_around(
    kind, monkeypatch
):
    """Simulate Fabric narrowing a field: the export must raise, not degrade.

    The failure mode this rules out is an export that notices the model no
    longer accepts a record and emits the old locally-shaped dict instead —
    which would look like success and ship an unvalidated record.
    """

    model_attr = {
        "execution": "ExecutionRefV0",
        "mechanism": "MechanismObservationV0",
        "outcome": "OutcomeObservationV0",
        "assessment": "TacticalEffectAssessmentRefV0",
    }[kind]

    class _Tightened:
        def __init__(self, **_fields):
            raise ValueError("field 'status' narrowed in a later Fabric release")

    # type.__name__ is a metaclass descriptor, so it has to be set on the class
    # object rather than in its body for the error message to name the contract.
    _Tightened.__name__ = model_attr

    monkeypatch.setattr(shared_export, model_attr, _Tightened)
    with pytest.raises(SharedOutcomeExportError) as excinfo:
        _export_all("throttle")[kind]
    assert model_attr in str(excinfo.value)
    assert "narrowed" in str(excinfo.value)


def test_fabric_absence_raises_instead_of_producing_a_locally_shaped_record(monkeypatch):
    """No fallback. An unvalidated record must not travel as a validated one."""

    monkeypatch.setattr(shared_export, "_FABRIC_UNAVAILABLE", ImportError("no azazel_fabric"))
    with pytest.raises(SharedOutcomeExportError) as excinfo:
        _export_all("throttle")
    message = str(excinfo.value)
    assert "azazel_fabric" in message
    assert "fallback" in message


def test_the_module_imports_the_contracts_from_fabric_not_from_a_local_copy():
    """Guards against the fork this change exists to remove.

    A re-vendored copy under azazel_edge would make the models importable again
    while re-creating two definitions of one contract.
    """

    for attr in (
        "ExecutionRefV0",
        "MechanismObservationV0",
        "OutcomeObservationV0",
        "TacticalEffectAssessmentRefV0",
    ):
        model = getattr(shared_export, attr)
        assert model is not None, f"{attr} is unavailable; Fabric is not installed"
        assert model.__module__.startswith("azazel_fabric."), (
            f"{attr} resolves to {model.__module__}, not to Fabric"
        )


def test_nothing_on_the_deterministic_path_imports_this_export_surface():
    """Fabric's absence may cost an export; it may never cost a decision."""

    package_root = Path(__file__).resolve().parents[1] / "py" / "azazel_edge"
    importers = [
        path.relative_to(package_root).as_posix()
        for path in package_root.rglob("*.py")
        if path.name != "shared_export.py"
        and "shared_export" in path.read_text(encoding="utf-8")
    ]
    assert importers == [], (
        "shared_export is imported by product code: "
        f"{importers}. Fabric is an optional extra, so a decision or enforcement "
        "path must not depend on it."
    )


def test_the_module_is_importable_and_the_projection_helper_is_the_only_emitter():
    """Every export goes through the one place that validates and fails closed."""

    source = (
        Path(shared_export.__file__).read_text(encoding="utf-8")
    )
    body = source.split("def _project(", 1)[1]
    assert "return {" not in body, (
        "a projection still returns a literal dict; every shared record must be "
        "built by a Fabric model through _project()"
    )
    assert importlib.import_module("azazel_edge.outcome.shared_export") is shared_export
    assert "azazel_edge.outcome.shared_export" in sys.modules
