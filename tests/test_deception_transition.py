"""Edge-side canonical EnvironmentTransitionDecision producer (Edge#358 / Fabric#9)."""

from __future__ import annotations

import pytest

from azazel_fabric.deception_contracts import verify_decision_signature

from azazel_edge.deception_transition import (
    TransitionDecisionError,
    build_transition_decision,
    derive_decision_id,
    transition_decision_from_arbiter,
)

AS_OF = "2026-08-21T00:00:00+00:00"
_KEY = "shared-operator-transport-key"


def _kw(**over):
    base = dict(
        environment_id="env-1",
        current_state="baseline",
        target_state="smb-share-open",
        as_of=AS_OF,
        ttl_seconds=300,
    )
    base.update(over)
    return base


# -- shape + window ----------------------------------------------------------

def test_build_produces_canonical_decision():
    d = build_transition_decision(**_kw())
    assert d["schema_version"] == "environment-transition-decision/v0.1"
    assert d["decision_authority"] == "azazel-edge"
    assert d["status"] == "accepted"
    assert d["environment_id"] == "env-1"
    assert d["current_state"] == "baseline"
    assert d["target_state"] == "smb-share-open"
    assert d["effective_at"].startswith("2026-08-21T00:00:00")
    # expires_at = as_of + 300s
    assert d["expires_at"].startswith("2026-08-21T00:05:00")
    assert d["decision_id"].startswith("edge-transition-")


# -- determinism -------------------------------------------------------------

def test_build_is_deterministic():
    a = build_transition_decision(**_kw(), key=_KEY)
    b = build_transition_decision(**_kw(), key=_KEY)
    assert a == b  # identical decision AND identical signature, no wall-clock


def test_derive_decision_id_is_stable_and_distinct():
    base = dict(environment_id="env-1", current_state="baseline",
                target_state="smb-share-open", as_of=AS_OF, evidence_refs=["e1"])
    assert derive_decision_id(**base) == derive_decision_id(**base)
    assert derive_decision_id(**{**base, "target_state": "other"}) != derive_decision_id(**base)
    assert derive_decision_id(**{**base, "as_of": "2027-01-01T00:00:00+00:00"}) != derive_decision_id(**base)


# -- validation --------------------------------------------------------------

def test_non_executable_status_rejected():
    with pytest.raises(TransitionDecisionError, match="status"):
        build_transition_decision(**_kw(status="rejected"))


def test_non_positive_ttl_rejected():
    with pytest.raises(TransitionDecisionError, match="ttl_seconds"):
        build_transition_decision(**_kw(ttl_seconds=0))


def test_bad_as_of_rejected():
    with pytest.raises(TransitionDecisionError, match="as_of"):
        build_transition_decision(**_kw(as_of="not-a-timestamp"))


# -- signing -----------------------------------------------------------------

def test_signed_decision_verifies_and_unsigned_has_no_signature():
    unsigned = build_transition_decision(**_kw())
    assert "decision_signature" not in unsigned
    signed = build_transition_decision(**_kw(), key=_KEY)
    assert verify_decision_signature(signed, _KEY) is True
    assert verify_decision_signature(signed, "wrong-key") is False


# -- from arbiter ------------------------------------------------------------

def test_from_arbiter_carries_evidence_and_reason():
    arbiter = {
        "action": "redirect",
        "reason": "soc_high_confidence_redirect_is_preferred",
        "chosen_evidence_ids": ["ev-soc-1", "ev-noc-1"],
    }
    d = transition_decision_from_arbiter(
        arbiter, environment_id="env-1", current_state="baseline",
        target_state="smb-share-open", as_of=AS_OF, key=_KEY,
    )
    assert d["evidence_refs"] == ["ev-soc-1", "ev-noc-1"]
    assert d["reason_codes"] == ["soc_high_confidence_redirect_is_preferred"]
    assert verify_decision_signature(d, _KEY) is True


# -- end-to-end interop with the AZ-06 consumer (skip if not installed) ------

def test_edge_produced_decision_drives_az06_consumer():
    az06 = pytest.importorskip("azazel_deception.runtime.transitions")
    transport = pytest.importorskip("azazel_deception.runtime.transport")
    state_mod = pytest.importorskip("azazel_deception.runtime.state")
    testing = pytest.importorskip("azazel_fabric.testing")

    signed = build_transition_decision(**_kw(), key=_KEY)
    executor = az06.TransitionExecutor(
        testing.make_transition_catalog(),
        decision_authenticator=transport.HmacDecisionAuthenticator(_KEY),
        require_authenticated_decisions=True,
        require_canonical_decision=True,
        require_decision_expiry=True,
    )
    result = executor.execute(
        environment_id="env-1",
        current_state="baseline",
        transition_id="open-smb-share",
        edge_decision=signed,
        as_of=AS_OF,
    )
    assert result["status"] == "shadow_simulated"
    assert result["edge_decision_id"] == signed["decision_id"]
