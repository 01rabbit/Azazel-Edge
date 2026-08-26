from __future__ import annotations

import json
from pathlib import Path

from azazel_edge.outcome.contracts import (
    ActionExecutionReceipt,
    ActionLifecycle,
    AppliedMechanism,
    Correlation,
    ExecutionStatus,
    MechanismKind,
    MechanismStatus,
)
from azazel_edge.outcome.shared_export import execution_to_shared_v0, mechanism_to_shared_v0


FIXTURES = Path(__file__).parent / "fixtures" / "outcome"


def correlation() -> Correlation:
    return Correlation(
        incident_id="incident-golden-redirect-1",
        decision_id="decision-golden-redirect-1",
        action_id="action-golden-redirect-1",
        execution_id="execution-golden-redirect-1",
        mechanism_id="mechanism-golden-redirection-1",
        reasoning_trace_id="trace-golden-redirect-1",
    )


def execution() -> ActionExecutionReceipt:
    return ActionExecutionReceipt(
        incident_id="incident-golden-redirect-1",
        decision_id="decision-golden-redirect-1",
        action_id="action-golden-redirect-1",
        execution_id="execution-golden-redirect-1",
        action_kind="redirect",
        provider="golden-fixture",
        scope={"scope_kind": "source_ip_and_destination_port"},
        requested_parameters={},
        applied_parameters={},
        status=ExecutionStatus.APPLIED,
        requested_at="2026-08-26T06:10:00Z",
        started_at="2026-08-26T06:10:00Z",
        completed_at="2026-08-26T06:10:01Z",
        reversible=True,
        provider_evidence_refs=("edge:execution:golden:1",),
        lifecycle=ActionLifecycle.ACTIVE,
    )


def mechanism() -> AppliedMechanism:
    return AppliedMechanism(
        mechanism_id="mechanism-golden-redirection-1",
        execution_id="execution-golden-redirect-1",
        decision_id="decision-golden-redirect-1",
        mechanism_kind=MechanismKind.REDIRECTION,
        scope={"scope_kind": "source_ip_and_destination_port"},
        observed_parameters={
            "redirect_port": 12222,
            "verification_basis": "nft_redirect_rule_readback_match",
        },
        status=MechanismStatus.OBSERVED,
        observed_at="2026-08-26T06:10:02Z",
        evidence_refs=("edge:mechanism:golden:1",),
    )


def _fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_edge_execution_export_matches_cross_product_fixture_exactly():
    actual = execution_to_shared_v0(correlation(), execution(), producer_node="edge-golden-1")
    assert actual == _fixture("cross_product_redirect_execution_v0.json")


def test_edge_mechanism_export_matches_cross_product_fixture_exactly():
    actual = mechanism_to_shared_v0(correlation(), mechanism(), producer_node="edge-golden-1")
    assert actual == _fixture("cross_product_redirection_mechanism_v0.json")
    assert actual["mechanism_kind"] == "redirection"
    assert "tactical_effect" not in actual
