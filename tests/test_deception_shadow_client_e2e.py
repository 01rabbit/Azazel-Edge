"""Networked Edge -> AZ-06 shadow/replay end-to-end tests.

These run the real azazel_deception shadow/replay HTTP service on localhost
and drive it with the Edge client, proving the full bootstrap integration
flow of Azazel-Edge#325 (authenticate + discover, package identity, plan,
local shadow evaluation, activation/termination rehearsal) with zero
container start and zero enforcement.

They require the azazel-deception package (plus its Fabric dependency) to be
importable and are skipped otherwise, so baseline Edge CI does not depend on
AZ-06 being present.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

azazel_deception = pytest.importorskip("azazel_deception")

from azazel_deception.package import calculate_package_digest, load_package  # noqa: E402
from azazel_deception.runtime.shadow_server import (  # noqa: E402
    ShadowReplayHTTPServer,
    ShadowReplayService,
)

from azazel_edge.deception_shadow_client import (  # noqa: E402
    Az06ShadowClient,
    ShadowTransportError,
)

KEY = "edge-az06-e2e-key"
EDGE_ID = "edge-e2e-node"
NODE_ID = "az06-e2e-node"

REFERENCE_PACKAGE = "examples/packages/municipal-linux-v1/package.yaml"
REFERENCE_COMPOSE = "runtime/compose/reference-linux.compose.yaml"


def _deception_repo_path(name: str):
    import azazel_deception

    repo_root = azazel_deception.__file__
    from pathlib import Path

    for candidate in Path(repo_root).parents:
        if (candidate / name).exists():
            return candidate / name
    pytest.skip(f"azazel-deception checkout does not provide {name}")


@pytest.fixture(scope="module")
def lite_package_path(tmp_path_factory):
    package = load_package(_deception_repo_path(REFERENCE_PACKAGE))
    for component in package["components"]:
        component["image"]["verified"] = component["component_id"] == "intranet-web"
    package["package_digest"] = calculate_package_digest(package)
    path = tmp_path_factory.mktemp("package") / "package.json"
    path.write_text(json.dumps(package), encoding="utf-8")
    return path


@pytest.fixture
def server(tmp_path, lite_package_path):
    service = ShadowReplayService(
        node_id=NODE_ID,
        transport_key=KEY,
        allowed_edge_ids=[EDGE_ID],
        package_path=lite_package_path,
        state_root=tmp_path / "state",
        compose_file=_deception_repo_path(REFERENCE_COMPOSE),
    )
    with ShadowReplayHTTPServer(service) as running:
        yield running, service


def _client(server, *, key=KEY, edge_id=EDGE_ID, node_id=NODE_ID):
    host, port = server.address
    return Az06ShadowClient(
        f"http://{host}:{port}",
        transport_key=key,
        edge_node_id=edge_id,
        az06_node_id=node_id,
    )


def _activation_decision(package, capabilities, plan):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-activation-decision/v0.1",
        "decision_id": plan["edge_decision_id"],
        "decision_authority": "azazel-edge",
        "status": "accepted",
        "package_id": package["package_id"],
        "package_digest": package["package_digest"],
        "target_node_id": plan["node_id"],
        "selected_tier": plan["selected_tier"],
        "budget": {
            "cpu_cores": 2,
            "memory_mb": 1024,
            "storage_mb": 2048,
            "max_connections": 100,
            "max_duration_seconds": 300,
            "bandwidth_kbps": 5000,
        },
        "safety": {
            "outbound_allowed": False,
            "production_access": False,
            "privileged_containers": False,
            "host_network": False,
            "runtime_socket_exposed_to_decoys": False,
            "edge_control_access_from_decoys": False,
        },
        "effective_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "evidence_refs": [],
        "reason_codes": ["e2e-shadow"],
    }


def _termination_decision(environment_id):
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "environment-termination-decision/v0.1",
        "decision_id": "edge-e2e-terminate-1",
        "decision_authority": "azazel-edge",
        "environment_id": environment_id,
        "reason": "shadow_rehearsal_complete",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=1)).isoformat(),
        "evidence_refs": [],
    }


def test_full_networked_bootstrap_shadow_session(server):
    running, service = server
    client = _client(running)
    environment_id = "env-e2e-shadow-1"

    trace = client.run_bootstrap_session(
        edge_decision_id="edge-e2e-decision-1",
        requested_tier="lite",
        environment_id=environment_id,
        build_activation_decision=_activation_decision,
        termination_decision=_termination_decision(environment_id),
    )

    assert trace["outcome"] == "shadow_complete"
    assert trace["enforcement_applied"] is False
    assert trace["container_start_count"] == 0
    assert [step["step"] for step in trace["steps"]] == [
        "capabilities",
        "package",
        "plan",
        "shadow_activate",
        "shadow_terminate",
    ]

    # Authenticated identity + capability snapshot recorded for audit.
    assert trace["capability_snapshot"]["authority"] == "descriptive_only"
    assert trace["package_identity"]["package_id"] == "municipal-linux-v1"

    # Placement plan is bound to the Edge decision, and rejected alternatives
    # stay visible.
    assert trace["placement_plan"]["edge_decision_id"] == "edge-e2e-decision-1"
    assert trace["placement_plan"]["selected_tier"] == "lite"
    assert {alt["tier_id"] for alt in trace["rejected_alternatives"]} == {"standard"}

    # Edge's own deterministic evaluator agrees, and the rehearsal produced
    # simulated (never enforced) lifecycle state.
    assert trace["local_shadow_evaluation"]["status"] == "would_accept"
    assert trace["simulated_activation"]["simulated_state"] == "active"
    assert trace["simulated_activation"]["live_execution"] is False
    assert trace["simulated_termination"]["simulated_state"] == "terminated"

    # Zero container start and zero live state on the AZ-06 side; the one-shot
    # decision ledger is untouched so the same decision can later go live.
    assert service.adapter.collect_status(environment_id)["state"] == "absent"
    assert service.state.decision_consumed("edge-e2e-decision-1") is False

    # The AZ-06 side audited every request with an intact evidence chain.
    from azazel_deception.runtime.shadow_server import AUDIT_ENVIRONMENT_ID

    assert service.state.verify_evidence_chain(AUDIT_ENVIRONMENT_ID) is True
    audit_actions = [
        json.loads(line)["action"]
        for line in service.state.evidence_path(AUDIT_ENVIRONMENT_ID)
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert audit_actions == [
        "capabilities",
        "package",
        "plan",
        "activate",
        "terminate",
    ]


def test_wrong_transport_key_fails_closed(server):
    running, _ = server
    client = _client(running, key="wrong-key")
    with pytest.raises(ShadowTransportError):
        client.discover_capabilities()


def test_unallowlisted_edge_identity_fails_closed(server):
    running, _ = server
    client = _client(running, edge_id="edge-rogue")
    with pytest.raises(ShadowTransportError):
        client.run_bootstrap_session(
            edge_decision_id="edge-e2e-decision-2",
            requested_tier="lite",
            environment_id="env-e2e-shadow-2",
        )


def test_wrong_node_identity_fails_closed(server):
    running, _ = server
    client = _client(running, node_id="az06-other-node")
    with pytest.raises(ShadowTransportError):
        client.discover_capabilities()


def test_binding_mismatch_is_a_deterministic_rejection(server):
    running, _ = server
    client = _client(running)
    environment_id = "env-e2e-shadow-3"

    def _mismatched_decision(package, capabilities, plan):
        decision = _activation_decision(package, capabilities, plan)
        decision["decision_id"] = "edge-a-different-decision"
        return decision

    with pytest.raises(ShadowTransportError) as excinfo:
        client.run_bootstrap_session(
            edge_decision_id="edge-e2e-decision-3",
            requested_tier="lite",
            environment_id=environment_id,
            build_activation_decision=_mismatched_decision,
        )
    assert "shadow_validation_failed" in str(excinfo.value)
