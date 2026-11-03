"""Edge-side AZ-06 activation/termination decision builders (Deception#55 G3/G4).

The builders record decisions Edge already made. These tests pin: the Fabric
round trip, signature verification, determinism, objective_refs grammar and the
refusal fixtures, and that an advisory alone cannot be the basis.
"""

from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("azazel_fabric.deception_contracts")

from azazel_fabric.deception_contracts import (  # noqa: E402
    EnvironmentActivationDecision,
    EnvironmentTerminationDecision,
    verify_decision_signature,
)

from azazel_edge import deception_activation as da  # noqa: E402
from azazel_edge.deception_activation import (  # noqa: E402
    ActivationDecisionError,
    build_activation_decision,
    build_termination_decision,
    derive_activation_decision_id,
    validate_objective_refs,
)

AS_OF = "2026-11-03T00:00:00+00:00"
KEY = "shared-operator-transport-key"
DIGEST = "sha256:" + "ab" * 32
BUDGET = {
    "cpu_cores": 2, "memory_mb": 1024, "storage_mb": 2048,
    "max_connections": 100, "max_duration_seconds": 300, "bandwidth_kbps": 5000,
}
OBJ = ["advisory:mio-objective-o1", "advisory:mio-hypothesis-h1",
       "advisory:mio-hypothesis-h2", "advisory:mio-frame-f1",
       "advisory:mio-objective-digest-" + "0123456789abcdef" * 2]
OWN = ["evidence:arbiter-chosen-1"]
WHY = ["t4-redirect-to-decoy"]


def _act(**over):
    base = dict(package_id="pkg-1", package_digest=DIGEST, target_node_id="node-1",
                selected_tier="lite", budget=BUDGET, as_of=AS_OF,
                evidence_refs=OWN, reason_codes=WHY)
    base.update(over)
    return build_activation_decision(**base)


def test_activation_roundtrips_through_fabric_and_signature():
    signed = _act(objective_refs=OBJ, key=KEY)
    assert verify_decision_signature(signed, KEY)
    assert not verify_decision_signature(signed, "other-key")
    contract = {k: v for k, v in signed.items() if k != "decision_signature"}
    model = EnvironmentActivationDecision.model_validate(contract)
    assert model.decision_authority == "azazel-edge"
    assert model.status == "accepted"
    assert model.effective_at == datetime(2026, 11, 3, tzinfo=timezone.utc)
    assert model.expires_at - model.effective_at == timedelta(seconds=300)
    assert set(OBJ) <= set(model.evidence_refs) and OWN[0] in model.evidence_refs
    # Tampering with the recorded refs breaks the signature.
    tampered = dict(signed, evidence_refs=OWN)
    assert not verify_decision_signature(tampered, KEY)


def test_activation_without_objective_is_plain_and_unsigned_without_key():
    plain = _act()
    assert plain["evidence_refs"] == OWN
    assert "decision_signature" not in plain


def test_objective_refs_do_not_change_authority_fields():
    a, b = _act(), _act(objective_refs=OBJ)
    for f in ("status", "budget", "effective_at", "expires_at", "selected_tier",
              "target_node_id", "package_digest", "reason_codes", "safety"):
        assert a[f] == b[f]
    assert a["decision_id"] != b["decision_id"]  # but the record is distinct


def test_activation_is_deterministic_and_ref_order_independent():
    one = _act(objective_refs=OBJ, key=KEY)
    two = _act(objective_refs=list(reversed(OBJ)), key=KEY)
    assert one == two
    assert one["decision_id"].startswith("edge-activation-")
    assert _act(ttl_seconds=301)["decision_id"] != _act()["decision_id"]
    assert _act(status="modified")["decision_id"] != _act()["decision_id"]


def test_termination_roundtrip_and_determinism():
    t = build_termination_decision(environment_id="env-1", reason="lease-expired",
                                   as_of=AS_OF, evidence_refs=OWN,
                                   objective_refs=OBJ, key=KEY)
    assert verify_decision_signature(t, KEY)
    model = EnvironmentTerminationDecision.model_validate(
        {k: v for k, v in t.items() if k != "decision_signature"})
    assert model.reason == "lease-expired" and set(OBJ) <= set(model.evidence_refs)
    again = build_termination_decision(environment_id="env-1", reason="lease-expired",
                                       as_of=AS_OF, evidence_refs=OWN,
                                       objective_refs=list(reversed(OBJ)), key=KEY)
    assert t == again and t["decision_id"].startswith("edge-termination-")


@pytest.mark.parametrize("bad_status", ["rejected", "terminated", "downgraded", "x", None])
def test_non_executable_status_refused(bad_status):
    with pytest.raises(ActivationDecisionError):
        _act(status=bad_status)


@pytest.mark.parametrize("over", [
    dict(ttl_seconds=0), dict(ttl_seconds=-1), dict(ttl_seconds=True),
    dict(ttl_seconds=10**15), dict(as_of="not-a-time"), dict(package_digest="sha256:zz"),
    dict(selected_tier=""), dict(budget={**BUDGET, "bandwidth_kbps": None}),
    dict(budget={**BUDGET, "extra": 1}), dict(budget={**BUDGET, "cpu_cores": 0}),
    dict(reason_codes=["bad code"]), dict(evidence_refs=["advisory:mio-objective-o1"]),
    dict(evidence_refs="evidence:x"),
])
def test_model_and_input_validation_refuses(over):
    with pytest.raises(ActivationDecisionError):
        _act(**over)


REJECTED_REFS = [
    ["decision:edge-1"],                                   # other kind
    ["evidence:mio-objective-o1"],
    ["advisory:other-thing"],
    ["mio-objective-o1"],                                  # untyped
    OBJ[:1] + OBJ[3:4] + ["advisory:mio-objective-digest-xyz"],   # bad digest
    OBJ[:1] + OBJ[3:4] + ["advisory:mio-objective-digest-" + "A" * 32],
    ["advisory:mio-objective-activate-now", OBJ[3]],       # imperative
    ["advisory:mio-objective-o1", "advisory:mio-frame-terminate"],
    ["advisory:mio-objective-o1", "advisory:mio-hypothesis-run_it", OBJ[3]],
    ["advisory:mio-objective-" + "a" * 190, OBJ[3]],       # too long
    ["advisory:mio-objective-o 1", OBJ[3]],                # whitespace
    ["advisory:mio-objective-o/../1", OBJ[3]],             # path-like
    ["advisory:mio-objective-o1"],                         # no frame
    [OBJ[3]],                                              # no objective
    OBJ[:1] + OBJ[3:4] + OBJ[:1],                          # duplicate
    ["advisory:mio-objective-o1", "advisory:mio-objective-o2", OBJ[3]],  # two objectives
    OBJ[:1] + OBJ[3:4] + [f"advisory:mio-hypothesis-h{i}" for i in range(9)],
    OBJ + ["advisory:mio-objective-digest-" + "1" * 32],   # two digests
    [f"advisory:mio-hypothesis-h{i}" for i in range(20)] + OBJ[:1] + OBJ[3:4],
    "advisory:mio-objective-o1",                           # bare string, not a list
    {"advisory:mio-objective-o1": 1},                      # mapping
    [{"objective_ref": "advisory:mio-objective-o1"}],      # object, not an opaque ref
    [None],
]


@pytest.mark.parametrize("refs", REJECTED_REFS)
def test_objective_refs_rejected(refs):
    with pytest.raises(ActivationDecisionError):
        _act(objective_refs=refs)
    with pytest.raises(ActivationDecisionError):
        build_termination_decision(environment_id="e", reason="r", as_of=AS_OF,
                                   evidence_refs=OWN, objective_refs=refs)


def test_advisory_alone_cannot_be_the_basis():
    with pytest.raises(ActivationDecisionError):
        _act(objective_refs=OBJ, evidence_refs=[])
    with pytest.raises(ActivationDecisionError):
        _act(objective_refs=OBJ, reason_codes=[])
    with pytest.raises(ActivationDecisionError):
        build_termination_decision(environment_id="e", reason="r", as_of=AS_OF,
                                   objective_refs=OBJ)


def test_no_parameter_lets_advice_drive_the_decision():
    for fn in (build_activation_decision, build_termination_decision):
        names = set(inspect.signature(fn).parameters)
        assert not names & {"objective", "recommendation", "advice", "mio", "hypotheses",
                            "frame", "desired_observations", "executable", "authority"}
        with pytest.raises(TypeError):
            fn(objective={"objective_ref": OBJ[0]}, as_of=AS_OF)
    tree = ast.parse(inspect.getsource(da))
    called = {ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    assert not {c for c in called if c.endswith((".now", ".utcnow", ".time")) or c.startswith("random")}


def test_validate_objective_refs_canonical_and_empty():
    assert validate_objective_refs(None) == []
    assert validate_objective_refs([]) == []
    assert validate_objective_refs(reversed(OBJ)) == sorted(OBJ)


def test_deception_consumer_roundtrip_if_available():
    """Deception#59 admit_objective accepts exactly the refs this builder writes."""
    mio = pytest.importorskip("azazel_deception.runtime.mio_feedback")
    obj = mio.MioObservationObjective(
        objective_ref=OBJ[0], hypothesis_refs=tuple(OBJ[1:3]), frame_ref=OBJ[3],
        desired_observations=())
    digest_ref = mio._digest_ref(mio.objective_digest(obj))
    signed = _act(objective_refs=[*OBJ[:4], digest_ref], key=KEY)
    now = datetime(2026, 11, 3, 0, 1, tzinfo=timezone.utc)
    result = mio.admit_objective(
        obj, signed, authenticator=lambda d: verify_decision_signature(d, KEY), now=now)
    assert isinstance(result, mio.AdmittedObjective) and result.objective_content_bound
    unlisted = _act(key=KEY)
    kept = mio.admit_objective(
        obj, unlisted, authenticator=lambda d: verify_decision_signature(d, KEY), now=now)
    assert isinstance(kept, mio.AdvisoryRetained)


@pytest.mark.parametrize("bad", [
    "observation_objective:obs-1", "hypothesis:h1", "frame:f1", "ADVISORY:x",
    "Advisory:mio-objective-o1", "HYPOTHESIS:h1", " frame:f1",
])
def test_advisory_kinds_rejected_in_own_evidence_any_case(bad):
    with pytest.raises(ActivationDecisionError):
        _act(evidence_refs=[bad])


def test_current_deception_hypothesis_form_with_tilde_is_accepted():
    refs = ["advisory:mio-objective-o1", "advisory:mio-frame-frame-dec-1",
            "advisory:mio-hypothesis-frame-dec-1~h1"]
    signed = _act(objective_refs=refs, key=KEY)
    assert set(refs) <= set(signed["evidence_refs"])
    assert verify_decision_signature(signed, KEY)


def test_directive_set_is_c3_and_segment_based():
    assert da._DIRECTIVE_SEGMENTS == frozenset(
        "activate activation deactivate execute exec run start stop open allow "
        "authorize authorized approve approved enable extend terminate withdraw "
        "block isolate quarantine redirect expose command shell sudo deploy "
        "install delete kill override enforce grant granted bypass".split())
    ok = ["advisory:mio-objective-obj-1", "advisory:mio-frame-frame-dec-1",
          "advisory:mio-hypothesis-h1", "advisory:mio-hypothesis-redirection~isolation",
          "advisory:mio-hypothesis-frame-dec-1~active"]
    assert validate_objective_refs(ok[:2] + ok[2:3]) 
    assert validate_objective_refs([ok[0], ok[1], ok[3]])
    assert validate_objective_refs([ok[0], ok[1], ok[4]])
    for bad in ("advisory:mio-objective-run~1", "advisory:mio-objective-x.withdraw",
                "advisory:mio-objective-a:Redirect"):
        with pytest.raises(ActivationDecisionError):
            validate_objective_refs([bad, "advisory:mio-frame-f1"])


@pytest.mark.parametrize("word", ["override", "enforce", "grant", "granted", "bypass"])
def test_r2_directive_words_rejected(word):
    with pytest.raises(ActivationDecisionError):
        validate_objective_refs([f"advisory:mio-objective-a-{word}", "advisory:mio-frame-f1"])


@pytest.mark.parametrize("token", [
    "objective_content_not_bound", "isolation_drift_observed", "runtime_active_after_lease_end",
    "redirection_does_not_imply_diversion", "enforcement-note", "granted1"])
def test_r2_words_do_not_overreach(token):
    assert validate_objective_refs([f"advisory:mio-objective-{token}", "advisory:mio-frame-f1"])
