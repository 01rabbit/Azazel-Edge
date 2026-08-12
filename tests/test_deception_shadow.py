from azazel_edge.deception_shadow import evaluate_az06_shadow
from azazel_fabric.testing import (
    make_deception_host_capabilities,
    make_deception_package,
    make_deception_placement,
)


def _payloads(*, verified=True, decision_id="edge-shadow-fixture", architecture="amd64"):
    package = make_deception_package(verified=verified)
    host = make_deception_host_capabilities(architecture=architecture)
    placement = make_deception_placement(
        decision_id=decision_id,
        architecture=architecture,
        verified=verified,
    )
    return (
        package.model_dump(mode="json"),
        host.model_dump(mode="json"),
        placement.model_dump(mode="json"),
    )


def test_valid_inputs_would_accept_but_never_enforce():
    package, capabilities, placement = _payloads()
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-fixture",
        package_payload=package,
        capability_payload=capabilities,
        placement_payload=placement,
    )
    assert result.status == "would_accept"
    assert result.enforcement_applied is False
    assert result.reason_codes == ("shadow_only_no_enforcement",)


def test_same_golden_package_supports_arm64_and_amd64():
    for architecture in ("arm64", "amd64"):
        package, capabilities, placement = _payloads(architecture=architecture)
        result = evaluate_az06_shadow(
            decision_id="edge-shadow-fixture",
            package_payload=package,
            capability_payload=capabilities,
            placement_payload=placement,
        )
        assert result.status == "would_accept"
        assert result.architecture == architecture
        assert result.package_id == "municipal-linux-v1"
        assert result.enforcement_applied is False


def test_unverified_oci_would_reject():
    package, capabilities, placement = _payloads(verified=False)
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-fixture",
        package_payload=package,
        capability_payload=capabilities,
        placement_payload=placement,
    )
    assert result.status == "would_reject"
    assert "unverified_oci_provenance" in result.reason_codes
    assert result.enforcement_applied is False


def test_decision_binding_mismatch_would_reject():
    package, capabilities, placement = _payloads(decision_id="other")
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-fixture",
        package_payload=package,
        capability_payload=capabilities,
        placement_payload=placement,
    )
    assert "edge_decision_binding_mismatch" in result.reason_codes
    assert result.enforcement_applied is False


def test_package_digest_mismatch_would_reject():
    package, capabilities, placement = _payloads()
    placement["package_digest"] = "sha256:" + "e" * 64
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-fixture",
        package_payload=package,
        capability_payload=capabilities,
        placement_payload=placement,
    )
    assert "package_digest_mismatch" in result.reason_codes


def test_nested_runtime_directive_fails_closed():
    package, capabilities, placement = _payloads()
    package["narrative"]["docker_command"] = "docker run something"
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-fixture",
        package_payload=package,
        capability_payload=capabilities,
        placement_payload=placement,
    )
    assert result.status == "would_reject"
    assert "invalid_or_unsafe_contract" in result.reason_codes
    assert result.enforcement_applied is False
