"""Hardware-free preparation-plan tests; never invoke the lab or systemd."""

import copy
from pathlib import Path
import sys

import pytest
from azazel_edge.benchmark.benefit import BenefitInputError, manifest_digest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_plan as d


def test_exact_new_manifest_has_four_fresh_source_bound_assignments():
    m, s = d.planned("a" * 40, "b" * 64)
    assert len(m["assignments"]) == 4 and len(s) == 4
    assert {a["pair_id"] for a in m["assignments"]} == {"pair-0", "pair-1"}
    assert [a["arm"] for a in d.order(m)] == [
        "c0",
        "flow_throttle",
        "flow_throttle",
        "c0",
    ]
    assert m["arms"][0]["role"] == "observe_only"
    assert m["provenance"]["policy_sha256"] == manifest_digest(
        d.strict(d.POLICY_PATH.read_bytes())
    )
    assert d.validate_manifest(m, "b" * 64) == s
    for arm in m["arms"]:
        expected = d.arm_configuration(
            arm["id"],
            "b" * 64,
            m["measurement_binding"],
            m["observer_policy_sha256"],
            m["protected_policy_sha256"],
        )
        assert manifest_digest(expected) == arm["config_sha256"]
        assert expected["native_environment"]["AZAZEL_DEFENSE_IFACE"] == "es"
        assert expected["native_environment"]["AZAZEL_EVE_FROM_START"] == "0"


@pytest.mark.parametrize(
    "field", ["source", "core", "policy", "environment", "assignment"]
)
def test_exact_frozen_plan_refuses_mutation(field):
    m, _ = d.planned("a" * 40, "b" * 64)
    core = "b" * 64
    if field == "source":
        m["provenance"]["repo_commits"]["01rabbit/Azazel-Edge"] = "c" * 40
    elif field == "core":
        core = "c" * 64
    elif field == "policy":
        m["observer_policy_sha256"] = "c" * 64
    elif field == "environment":
        m["arms"][0]["config_sha256"] = "c" * 64
    else:
        m["assignments"][0]["order"] = 1
    with pytest.raises(BenefitInputError):
        d.validate_manifest(m, core)


@pytest.mark.parametrize("arm", ["c0", "flow_throttle"])
def test_protected_policy_override_precedes_provider_captured_writer(monkeypatch, arm):
    writes = []
    monkeypatch.setattr(
        d.g, "write", lambda path, data, mode=0o644: writes.append((path, data, mode))
    )
    monkeypatch.setattr(d.g, "prepare", lambda *a, **k: None)
    monkeypatch.setattr(d.g, "observer", lambda *a: None)
    monkeypatch.setattr(d.g, "ENV", dict(d.BASE_ENV))
    monkeypatch.setattr(d.p.a, "NATIVE", False)
    monkeypatch.setattr(d.g, "boot", lambda: "7be45004-1731-4b7c-8e62-59a5ddf129a4")
    observer_initializer = lambda *args: None
    d.configure_assignment(
        {"assignment": {"arm": arm}}, observer_initializer=observer_initializer
    )
    # This is the actual provider wrapper's template-time raw_write path. The
    # outer-after-provider order silently misses this write in the old draft.
    d.g.write(d.g.BASE / "template.json", "template")
    protected = [
        (data, mode)
        for path, data, mode in writes
        if path == d.g.BASE / "native/protected.yaml"
    ]
    assert protected == [(d.PROTECTED, 0o600)]
    assert "10.91.2.2/32" in protected[0][0]
    assert d.g.ENV == d.native_environment(arm)
    assert d.g.ENV["AZAZEL_DEFENSE_ENFORCE"] == ("1" if arm == "flow_throttle" else "0")
    assert d.g.ENV["AZAZEL_DEFENSE_DRY_RUN"] == "0"
    assert d.g.observer is observer_initializer
    assert d.names() == dict(
        edge="edge400-provider-edge",
        client="edge400-provider-client",
        service="edge400-provider-service",
    )


def test_old_v3_registration_is_not_modified():
    before = copy.deepcopy(d.n.instrumentation_registration("a" * 40, "b" * 64))
    d.planned("a" * 40, "b" * 64)
    assert d.n.instrumentation_registration("a" * 40, "b" * 64) == before
