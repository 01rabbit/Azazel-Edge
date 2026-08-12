import hashlib
import json

from azazel_edge.deception_shadow import evaluate_az06_shadow


def _sha(char: str) -> str:
    return "sha256:" + char * 64


def _capabilities():
    return {
        "schema_version": "host-capabilities/v0.1",
        "node_id": "az06-test",
        "architecture": "amd64",
        "cpu_cores": 4,
        "memory_mb": 8192,
        "storage_free_mb": 65536,
        "runtime_adapters": {"docker_compose": True},
        "runtime_versions": {"docker_compose": "Docker version test"},
        "kvm_available": False,
        "gpu_available": False,
        "network_features": {"network_namespace": True},
        "supported_profile_classes": ["static_linux"],
        "authority": "descriptive_only",
    }


def _digest_json(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _package(verified=True):
    return {
        "schema_version": "deception-package/v0.1",
        "package_id": "municipal-linux-v1",
        "package_version": "0.2.0",
        "package_digest": _sha("d"),
        "narrative": {
            "narrative_id": "municipal-public-health-v1",
            "purpose": "synthetic reference",
            "environment_profile_id": "municipal-public-health",
            "synthetic_only": True,
            "locale": "ja-JP",
            "timezone": "Asia/Tokyo",
            "engage_objective": "collect",
            "engage_approach": "channel",
            "engage_activities": ["record_interaction"],
        },
        "runtime_requirements": {
            "architectures": ["arm64", "amd64"],
            "runtime_adapter": "docker_compose",
            "minimum": {
                "cpu_cores": 2,
                "memory_mb": 1024,
                "storage_mb": 2048,
                "max_connections": 100,
                "max_duration_seconds": 300,
            },
            "kvm_required": False,
            "gpu_required": False,
            "required_runtime_features": ["isolated_network"],
            "required_profile_classes": ["static_linux"],
        },
        "safety": {
            "outbound_allowed": False,
            "production_access": False,
            "privileged_containers": False,
            "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "components": [
            {
                "component_id": "intranet-web",
                "required": True,
                "image": {
                    "image": "example.invalid/az06/intranet-web:0.2",
                    "manifest_digest": _sha("a"),
                    "platforms": [
                        {"architecture": "arm64", "digest": _sha("b")},
                        {"architecture": "amd64", "digest": _sha("c")},
                    ],
                    "provenance_ref": "test:provenance",
                    "sbom_ref": "test:sbom",
                    "verified": verified,
                },
                "privileged": False,
                "host_network": False,
                "read_only_rootfs": True,
                "surfaces": [
                    {
                        "surface_id": "web",
                        "protocol": "tcp",
                        "port": 80,
                        "service": "http",
                    }
                ],
            }
        ],
        "deployment_tiers": [
            {
                "tier_id": "lite",
                "minimum": {
                    "cpu_cores": 2,
                    "memory_mb": 1024,
                    "storage_mb": 2048,
                    "max_connections": 100,
                    "max_duration_seconds": 300,
                },
                "include_components": ["intranet-web"],
            }
        ],
        "consistency": {
            "report_id": "test-consistency",
            "fatal_contradictions": [],
            "warnings": [],
            "waivers": [],
        },
        "credentials": [],
        "signer_ref": "test:signer",
        "signature_ref": "test:signature",
    }


def _placement(capabilities, decision_id="edge-shadow-1"):
    return {
        "schema_version": "placement-plan/v0.1",
        "placement_id": "az06-placement-test",
        "package_id": "municipal-linux-v1",
        "package_digest": _sha("d"),
        "node_id": capabilities["node_id"],
        "architecture": capabilities["architecture"],
        "runtime_adapter": "docker_compose",
        "selected_tier": "lite",
        "component_ids": ["intranet-web"],
        "capability_snapshot_digest": _digest_json(capabilities),
        "edge_decision_id": decision_id,
        "authority": "descriptive_only",
    }


def test_valid_inputs_would_accept_but_never_enforce():
    capabilities = _capabilities()
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-1",
        package_payload=_package(verified=True),
        capability_payload=capabilities,
        placement_payload=_placement(capabilities),
    )
    assert result.status == "would_accept"
    assert result.enforcement_applied is False
    assert result.reason_codes == ("shadow_only_no_enforcement",)


def test_unverified_oci_would_reject():
    capabilities = _capabilities()
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-1",
        package_payload=_package(verified=False),
        capability_payload=capabilities,
        placement_payload=_placement(capabilities),
    )
    assert result.status == "would_reject"
    assert "unverified_oci_provenance" in result.reason_codes
    assert result.enforcement_applied is False


def test_decision_binding_mismatch_would_reject():
    capabilities = _capabilities()
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-1",
        package_payload=_package(),
        capability_payload=capabilities,
        placement_payload=_placement(capabilities, decision_id="other"),
    )
    assert "edge_decision_binding_mismatch" in result.reason_codes
    assert result.enforcement_applied is False


def test_package_digest_mismatch_would_reject():
    capabilities = _capabilities()
    placement = _placement(capabilities)
    placement["package_digest"] = _sha("e")
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-1",
        package_payload=_package(),
        capability_payload=capabilities,
        placement_payload=placement,
    )
    assert "package_digest_mismatch" in result.reason_codes


def test_nested_runtime_directive_fails_closed():
    capabilities = _capabilities()
    package = _package()
    package["narrative"]["docker_command"] = "docker run something"
    result = evaluate_az06_shadow(
        decision_id="edge-shadow-1",
        package_payload=package,
        capability_payload=capabilities,
        placement_payload=_placement(capabilities),
    )
    assert result.status == "would_reject"
    assert "invalid_or_unsafe_contract" in result.reason_codes
    assert result.enforcement_applied is False
