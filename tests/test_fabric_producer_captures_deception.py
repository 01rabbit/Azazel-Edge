"""Edge's consumers read what Azazel-Deception actually emitted (Fabric#23).

Every other Fabric test here builds its payload from Fabric's own models or
from a shape written by hand "as Deception emits it". These feed Edge the
records Azazel-Deception's producer functions returned at commit 305af85,
carried by `azazel_fabric.testing` as *producer captures*. Edge's own
captures (product="edge") are deliberately not used: Edge reading what Edge
wrote is not an independent consumer test.

Which Edge code reads which Deception record
--------------------------------------------
* `EffectObservation` (2 captures) -> `azazel_edge.outcome.effect_observation_reader.read_effect_observation`
* `InteractionObservation` (3 captures) -> `azazel_edge.deception_effectiveness_client.KnowledgeIngestClient.submit_observations`
  (a relay: it checks key names with `assert_no_runtime_directives` and
  forwards the dicts verbatim; it does not build the model)

Out of scope, and why (each is asserted below so a new capture cannot slip in
unclassified):
* `PresentedTerrainRef` (4) -- Edge has no reader for it. Edge mints terrain
  *requests* and reads only the `EffectObservation` that reports them.
* `OutcomeObservationV0` (2, presented_terrain_lifecycle) -- Edge exports its
  own outcome records (`outcome/shared_export.py`); it does not consume
  Deception's.
* The engagement model (`engagement_advisory_client`) has captures only from
  Edge (product="edge"), none from Deception, so it is out of scope here.

Captures exist from Fabric v0.10.0rc1 on, and the tag
`requirements/fabric.txt` pins carries them, so with the Fabric extra
installed this file runs. It skips only when
Fabric is not installed (the extra is optional) or when the installed Fabric
predates the pin; the second case is a wrong install, which
`test_fabric_pin_integrity.py` reports as a failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py"))

pytest.importorskip(
    "azazel_fabric",
    reason="Fabric is an optional extra; the deterministic path does not need it",
)
_testing = pytest.importorskip(
    "azazel_fabric.testing",
    reason="azazel_fabric.testing is not available in this Fabric",
)
if not hasattr(_testing, "producer_capture_names"):
    pytest.skip(
        "the installed Fabric predates v0.10.0rc1 and has no producer captures (the pin carries them)",
        allow_module_level=True,
    )

from azazel_fabric.deception_contracts import BANNED_RUNTIME_DIRECTIVE_FIELDS  # noqa: E402
from azazel_fabric.effect_contracts import DefensiveEffectRef  # noqa: E402
from azazel_fabric.testing import (  # noqa: E402
    load_producer_capture,
    producer_capture_names,
    producer_capture_provenance,
)

from azazel_edge import deception_effectiveness_client as client  # noqa: E402
from azazel_edge.outcome.effect_observation_reader import read_effect_observation  # noqa: E402

ACTIVE = "deception/effect_contracts_effect_observation_active_v0"
TERMINATED = "deception/effect_contracts_effect_observation_terminated_v0"
INTERACTION_LIST = "deception/deception_contracts_interaction_observation_export_list_v0"
INTERACTION_SINGLES = (
    "deception/deception_contracts_interaction_observation_interaction_port_v0",
    "deception/deception_contracts_interaction_observation_reaction_service_v0",
)

READ_BY_EDGE = {
    ACTIVE: "effect_observation_reader",
    TERMINATED: "effect_observation_reader",
    INTERACTION_LIST: "KnowledgeIngestClient",
    **{name: "KnowledgeIngestClient" for name in INTERACTION_SINGLES},
}
NOT_READ_BY_EDGE = {
    "PresentedTerrainRef": "Edge has no reader for presented-terrain-ref",
    "OutcomeObservationV0": "Edge exports outcome records; it does not consume Deception's",
}


def _effect_for(observation: dict, **overrides) -> DefensiveEffectRef:
    """The effect Edge would hold for the capture's `effect_ref`.

    The window is Edge's own (12:00-13:00), chosen to contain both captured
    observation times (12:05, 12:30); the captures carry no Edge effect.
    """

    data = {
        "effect_id": observation["effect_ref"],
        "effect_class": "redirect_to_presented_terrain",
        "producer_product": "azazel-edge",
        "producer_node": "edge-1",
        "trace_id": observation["trace_id"],
        "decision_ref": "decision-1",
        "target_scope_ref": "scope:6617f9307d832d50e04395e5604619cd",
        "policy_ref": "policy:soc-default",
        "created_at": "2026-09-20T12:00:00+00:00",
        "expires_at": "2026-09-20T13:00:00+00:00",
        "authority_class": "producer_decision_ref",
    }
    data.update(overrides)
    return DefensiveEffectRef(**data)


# --------------------------------------------------------------------------
# Inventory: every Deception capture is either read or explicitly set aside
# --------------------------------------------------------------------------


def test_every_deception_capture_is_classified():
    names = set(producer_capture_names(product="deception"))
    assert names, "no Deception captures; the producer-capture surface changed"
    unclassified = {
        name
        for name in names
        if name not in READ_BY_EDGE
        and producer_capture_provenance(name)["model"].rsplit(".", 1)[-1] not in NOT_READ_BY_EDGE
    }
    assert not unclassified, f"classify these as read or out of scope: {sorted(unclassified)}"
    assert set(READ_BY_EDGE) <= names


# --------------------------------------------------------------------------
# EffectObservation -> effect_observation_reader
# --------------------------------------------------------------------------


def test_the_active_capture_is_read_as_a_live_observation():
    payload = load_producer_capture(ACTIVE)
    result = read_effect_observation(payload)

    assert result.observed is True and result.reason == ""
    obs = result.observation
    assert obs.status == "active"
    assert obs.authority_class.value == "active_materialized"
    assert obs.materialization_producer == "azazel-deception"
    assert obs.directive is False
    assert obs.effect_ref == payload["effect_ref"]
    assert obs.termination_reason is None


def test_the_terminated_capture_is_read_with_its_reason():
    result = read_effect_observation(load_producer_capture(TERMINATED))

    assert result.observed is True and result.reason == ""
    obs = result.observation
    assert obs.status == "terminated"
    assert obs.termination_reason == "expired"
    assert obs.authority_class.value == "observed_fact"
    assert list(obs.evidence_refs) == ["runtime-inspect-2"]
    assert obs.directive is False


@pytest.mark.parametrize("name", [ACTIVE, TERMINATED])
def test_each_capture_chains_to_the_effect_it_names_inside_its_window(name):
    payload = load_producer_capture(name)
    result = read_effect_observation(payload, effect=_effect_for(payload))

    assert result.observed is True, result.reason


@pytest.mark.parametrize("name", [ACTIVE, TERMINATED])
def test_a_capture_is_refused_against_an_effect_it_does_not_belong_to(name):
    payload = load_producer_capture(name)
    other = _effect_for(payload, effect_id="effect:00000000000000000000000000000000")
    result = read_effect_observation(payload, effect=other)

    assert result.observed is False
    assert result.reason  # degraded to "nothing observed", not raised


def test_a_capture_arriving_after_the_effect_expired_is_not_read_as_live():
    payload = load_producer_capture(ACTIVE)  # observed_at 12:05
    expired = _effect_for(
        payload,
        created_at="2026-09-20T11:00:00+00:00",
        expires_at="2026-09-20T12:00:00+00:00",
    )
    result = read_effect_observation(payload, effect=expired)

    assert result.observed is False
    assert result.reason


@pytest.mark.parametrize("name", [ACTIVE, TERMINATED])
@pytest.mark.parametrize("claimed", ["producer_decision_ref", "advisory_inference", "planned_shadow"])
def test_a_capture_that_claims_a_decisions_authority_is_refused_by_edge(name, claimed):
    payload = dict(load_producer_capture(name), authority_class=claimed)
    result = read_effect_observation(payload)

    assert result.observed is False
    assert claimed in result.reason
    assert "does not carry a decision's authority" in result.reason


@pytest.mark.parametrize("name", [ACTIVE, TERMINATED])
def test_a_capture_naming_edge_as_materializer_is_refused(name):
    payload = dict(load_producer_capture(name), materialization_producer="azazel-edge")
    result = read_effect_observation(payload)

    assert result.observed is False
    assert "vouching for itself" in result.reason


@pytest.mark.parametrize("name", [ACTIVE, TERMINATED])
def test_a_capture_with_directive_true_or_an_extra_field_is_refused(name):
    payload = load_producer_capture(name)

    directive = read_effect_observation(dict(payload, directive=True))
    assert directive.observed is False
    assert "directive" in directive.reason

    extra = read_effect_observation(dict(payload, action="block 10.0.0.1"))
    assert extra.observed is False
    assert "action" in extra.reason and "Extra inputs are not permitted" in extra.reason


def test_a_terminated_capture_cannot_be_relabelled_active():
    payload = dict(load_producer_capture(TERMINATED), status="active")
    result = read_effect_observation(payload)

    assert result.observed is False
    assert "active_materialized" in result.reason


def test_an_unreadable_authority_claim_is_reported_as_itself():
    result = read_effect_observation(dict(load_producer_capture(ACTIVE), authority_class="bogus"))

    assert result.observed is False
    assert "'bogus'" in result.reason


def test_a_capture_with_its_required_fields_removed_degrades_without_raising():
    payload = load_producer_capture(ACTIVE)
    payload.pop("effect_ref")
    payload.pop("observed_at")
    result = read_effect_observation(payload)

    assert result.observed is False
    assert "effect_ref" in result.reason and "observed_at" in result.reason


# --------------------------------------------------------------------------
# InteractionObservation -> KnowledgeIngestClient (relay)
# --------------------------------------------------------------------------


class _Response:
    def __init__(self, status=202):
        self._status = status

    def getcode(self):
        return self._status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def wire(monkeypatch):
    """Capture what would be POSTed; no socket is opened."""

    sent = []

    def fake_urlopen(request, timeout=None):
        sent.append(json.loads(request.data.decode("utf-8")))
        return _Response(202)

    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen)
    return sent


def _ingest():
    return client.KnowledgeIngestClient("http://knowledge.invalid", edge_node_id="edge-1")


@pytest.mark.skipif(not client.fabric_available(), reason="Fabric directive guard unavailable")
def test_the_exported_observation_batch_is_relayed_verbatim(wire):
    batch = load_producer_capture(INTERACTION_LIST)
    assert isinstance(batch, list) and len(batch) == 2

    result = _ingest().submit_observations(batch)

    assert result.ok and result.submitted_count == 2
    (envelope,) = wire
    assert envelope["items"] == batch  # not interpreted, not rewritten
    assert envelope["environment_id"] == "env-export-1"
    assert envelope["schema_version"] == client.INGEST_BATCH_SCHEMA


@pytest.mark.skipif(not client.fabric_available(), reason="Fabric directive guard unavailable")
@pytest.mark.parametrize("name", INTERACTION_SINGLES)
def test_a_single_captured_observation_is_relayed_as_a_one_item_batch(wire, name):
    observation = load_producer_capture(name)
    result = _ingest().submit_observations([observation])

    assert result.ok and result.submitted_count == 1
    assert wire[0]["items"] == [observation]


@pytest.mark.skipif(not client.fabric_available(), reason="Fabric directive guard unavailable")
@pytest.mark.parametrize("key", sorted(BANNED_RUNTIME_DIRECTIVE_FIELDS))
def test_a_captured_observation_carrying_a_runtime_directive_key_is_not_relayed(wire, key):
    tampered = dict(load_producer_capture(INTERACTION_SINGLES[0]), **{key: True})
    result = _ingest().submit_observations([tampered])

    assert result.status == "invalid_batch" and result.submitted_count == 0
    assert "authority invariant violated" in (result.detail or "")
    assert wire == []  # nothing reached the wire


def test_the_bare_list_capture_is_not_a_batch_of_dicts_when_a_scalar_is_mixed_in(wire):
    batch = load_producer_capture(INTERACTION_LIST) + ["not-a-dict"]
    result = _ingest().submit_observations(batch)

    assert result.status == "invalid_batch"
    assert wire == []


def test_the_loader_returns_a_fresh_copy_each_time():
    first = load_producer_capture(ACTIVE)
    first["status"] = "mutated"
    assert load_producer_capture(ACTIVE)["status"] == "active"
