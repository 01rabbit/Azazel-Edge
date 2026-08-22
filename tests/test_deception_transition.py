"""Edge-side canonical EnvironmentTransitionDecision producer (Edge#358 / Fabric#9)."""

from __future__ import annotations

import pytest

from azazel_edge.deception_transition import (
    TransitionDecisionError,
    build_transition_decision,
    derive_decision_id,
    transition_decision_from_arbiter,
)

try:  # Canonical decision-signing lands in Fabric#9 (>= 0.8.0).
    from azazel_fabric.deception_contracts import verify_decision_signature
    _SIGNING = True
except ImportError:  # pragma: no cover
    verify_decision_signature = None
    _SIGNING = False

_needs_signing = pytest.mark.skipif(
    not _SIGNING, reason="requires azazel_fabric >= 0.8.0 (decision_signing, Fabric#9)"
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

@_needs_signing
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


def test_derive_decision_id_no_delimiter_collision():
    # A control character embedded in one field must not let two semantically
    # different tuples hash to the same id (would collide AZ-06 anti-replay
    # slots and wrongly reject a legit transition). Regression for the former
    # \x1f-delimiter-join.
    a = derive_decision_id(environment_id="A\x1fB", current_state="C",
                           target_state="D", as_of="T")
    b = derive_decision_id(environment_id="A", current_state="B\x1fC",
                           target_state="D", as_of="T")
    assert a != b
    # evidence boundary likewise cannot be smuggled across fields
    c = derive_decision_id(environment_id="e", current_state="s", target_state="t",
                           as_of="T", evidence_refs=["x", "y"])
    d = derive_decision_id(environment_id="e", current_state="s", target_state="t",
                           as_of="T", evidence_refs=["x\x1ey"])
    assert c != d


def test_materially_different_decisions_get_distinct_ids():
    # A decision id must bind status, the expiry window (ttl), and reason_codes,
    # not only environment/state/time/evidence. Otherwise two decisions that
    # differ only in one of those collide on one id, and AZ-06's anti-replay
    # ledger (keyed purely on decision_id) rejects the second, independently
    # signed decision as a replay of the first -- silently blackholing a
    # legitimate corrected/re-scoped decision.
    base = _kw()
    assert (
        build_transition_decision(**base, status="accepted")["decision_id"]
        != build_transition_decision(**base, status="modified")["decision_id"]
    )
    assert (
        build_transition_decision(**_kw(ttl_seconds=60))["decision_id"]
        != build_transition_decision(**_kw(ttl_seconds=315360000))["decision_id"]
    )
    assert (
        build_transition_decision(**base)["decision_id"]
        != build_transition_decision(**base, reason_codes=["soc_redirect"])["decision_id"]
    )


# -- validation --------------------------------------------------------------

def test_non_executable_status_rejected():
    with pytest.raises(TransitionDecisionError, match="status"):
        build_transition_decision(**_kw(status="rejected"))


def test_non_positive_ttl_rejected():
    with pytest.raises(TransitionDecisionError, match="ttl_seconds"):
        build_transition_decision(**_kw(ttl_seconds=0))


def test_oversized_ttl_raises_transition_decision_error():
    # A ttl large enough to overflow datetime arithmetic must fail closed with
    # the module's own error type, not leak a raw OverflowError to callers that
    # catch TransitionDecisionError.
    with pytest.raises(TransitionDecisionError, match="ttl_seconds"):
        build_transition_decision(**_kw(ttl_seconds=10 ** 18))


def test_bool_ttl_rejected():
    # bool is an int subclass; True must not sneak through as ttl_seconds=1.
    with pytest.raises(TransitionDecisionError, match="ttl_seconds"):
        build_transition_decision(**_kw(ttl_seconds=True))


def test_bad_as_of_rejected():
    with pytest.raises(TransitionDecisionError, match="as_of"):
        build_transition_decision(**_kw(as_of="not-a-timestamp"))


# -- signing -----------------------------------------------------------------

@_needs_signing
def test_signed_decision_verifies_and_unsigned_has_no_signature():
    unsigned = build_transition_decision(**_kw())
    assert "decision_signature" not in unsigned
    signed = build_transition_decision(**_kw(), key=_KEY)
    assert verify_decision_signature(signed, _KEY) is True
    assert verify_decision_signature(signed, "wrong-key") is False


# -- from arbiter ------------------------------------------------------------

@_needs_signing
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

@_needs_signing
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


@_needs_signing
def test_distinct_windows_are_not_false_replays_on_consumer(tmp_path):
    # Regression: two decisions identical except for their expiry window must get
    # distinct ids so the consumer's one-shot ledger admits BOTH, rather than
    # rejecting the second as a replay of the first (which would happen if the id
    # were blind to ttl/expiry).
    az06 = pytest.importorskip("azazel_deception.runtime.transitions")
    transport = pytest.importorskip("azazel_deception.runtime.transport")
    state_mod = pytest.importorskip("azazel_deception.runtime.state")
    testing = pytest.importorskip("azazel_fabric.testing")

    executor = az06.TransitionExecutor.strict(
        testing.make_transition_catalog(),
        decision_authenticator=transport.HmacDecisionAuthenticator(_KEY),
        state=state_mod.RuntimeStateStore(tmp_path),
    )
    common = dict(environment_id="env-1", current_state="baseline",
                  transition_id="open-smb-share", as_of=AS_OF)
    d_short = build_transition_decision(**_kw(ttl_seconds=60), key=_KEY)
    d_long = build_transition_decision(**_kw(ttl_seconds=315360000), key=_KEY)
    assert d_short["decision_id"] != d_long["decision_id"]
    assert executor.execute(edge_decision=d_short, **common)["status"] == "shadow_simulated"
    # The second, genuinely distinct decision is NOT treated as a replay.
    assert executor.execute(edge_decision=d_long, **common)["status"] == "shadow_simulated"
