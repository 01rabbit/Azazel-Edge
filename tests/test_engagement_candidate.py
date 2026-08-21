"""Edge#319 engagement candidate builder + arbiter-authority evaluation."""

from __future__ import annotations

import pytest

from azazel_edge.engagement import (
    build_engagement_candidate,
    engagement_available,
    evaluate_engagement,
    engagement_event,
    EngagementDisabled,
)

pytestmark = pytest.mark.skipif(
    not engagement_available(),
    reason="requires azazel_fabric.engagement_contracts (Fabric v0.7.0)",
)


def _soc(action_conf=80, techniques=("T1110",)):
    return {
        "suspicion": {"score": 90, "label": "high"},
        "confidence": {"score": action_conf},
        "technique_likelihood": {"score": 70, "techniques": list(techniques)},
        "blast_radius": {"score": 20},
        "summary": "s",
        "evidence_ids": ["ev-soc-1"],
    }


def _noc():
    return {
        "availability": {"label": "good"},
        "path_health": {"label": "good"},
        "device_health": {"label": "good"},
        "client_health": {"label": "good"},
        "summary": "n",
        "evidence_ids": ["ev-noc-1"],
    }


def _decision(action="redirect", **over):
    d = {
        "action": action,
        "reason": "soc_high_confidence_redirect_is_preferred",
        "chosen_evidence_ids": ["ev-soc-1", "ev-noc-1"],
        "rejected_alternatives": [{"action": "isolate", "reason": "blast too wide"}],
    }
    d.update(over)
    return d


# -- feature flag (baseline unchanged) --------------------------------------

def test_disabled_is_a_noop():
    assert build_engagement_candidate(_soc(), _noc(), _decision(), enabled=False) is None
    # evaluate on a None candidate is inert
    assert evaluate_engagement(None, _decision())["status"] == "disabled"


# -- deterministic build -----------------------------------------------------

def test_build_maps_redirect_to_decoy_engagement():
    c = build_engagement_candidate(_soc(), _noc(), _decision("redirect"), enabled=True)
    assert c.authority == "candidate_only"
    assert c.objective == "collect" and c.approach == "channel"
    assert c.activity == "redirect_to_decoy"
    assert c.attack_techniques == ["T1110"]
    assert c.constraints.outbound_allowed is False
    assert c.constraints.production_access is False
    assert "ev-soc-1" in c.evidence_refs and "ev-noc-1" in c.evidence_refs
    assert c.trigger.attack_technique == "T1110"


def test_build_is_deterministic():
    a = build_engagement_candidate(_soc(), _noc(), _decision("redirect"), enabled=True)
    b = build_engagement_candidate(_soc(), _noc(), _decision("redirect"), enabled=True)
    assert a.model_dump() == b.model_dump()


# -- arbiter authority: only downgrade, never escalate ----------------------

def test_accepted_when_arbiter_matches_request():
    c = build_engagement_candidate(_soc(), _noc(), _decision("redirect"), enabled=True)
    r = evaluate_engagement(c, _decision("redirect"))
    assert r["status"] == "accepted"
    assert r["accepted_activity"] == "redirect_to_decoy"
    assert r["authority"] == "azazel-edge-arbiter"


def test_downgraded_when_arbiter_chose_weaker_action():
    # Candidate framed for redirect, but the arbiter actually selected notify
    # (e.g. NOC fragile). The engagement must downgrade, never escalate.
    c = build_engagement_candidate(_soc(), _noc(), _decision("redirect"), enabled=True)
    r = evaluate_engagement(c, _decision("notify", reason="soc_high_but_noc_fragile"))
    assert r["status"] == "downgraded"
    assert r["accepted_activity"] == "notify"
    assert any(alt.get("activity") == "redirect_to_decoy" for alt in r["rejected_alternatives"])


def test_isolate_request_downgraded_to_redirect():
    c = build_engagement_candidate(_soc(), _noc(), _decision("isolate"), enabled=True)
    r = evaluate_engagement(c, _decision("redirect"))
    assert r["status"] == "downgraded"
    assert r["accepted_activity"] == "redirect_to_decoy"


# -- audit event -------------------------------------------------------------

def test_engagement_event_records_accepted_activity_and_reaction():
    c = build_engagement_candidate(_soc(), _noc(), _decision("redirect"), enabled=True)
    ev = engagement_event(c, _decision("redirect"), attacker_reaction="decoy_engaged")
    assert ev.activity == "redirect_to_decoy"
    assert ev.outcome.attacker_reaction == "decoy_engaged"
    assert ev.product == "AZ-01"


# -- fail closed -------------------------------------------------------------

def test_tampered_candidate_fails_closed():
    class _Tampered:
        activity = "isolate"
        constraints = None
        def model_dump(self, *a, **k):
            return {"activity": "isolate", "select_action": "isolate"}
    with pytest.raises(ValueError):
        evaluate_engagement(_Tampered(), _decision("isolate"))
