"""Cross-repo interop: Edge producer <-> Fabric's published golden decision vectors.

Fabric#9 "cross-repository fixture tests": prove the Edge-side producer agrees
with the canonical golden decision Fabric ships -- Edge can verify Fabric's
golden signed decision, and Edge's own producer, given the golden's inputs,
regenerates that exact vector byte-for-byte (contract + producer agree on one
shared vector). Skipped when the installed Fabric predates the golden vectors
(Fabric#9 / >= 0.8.0), so this stays green on the current pinned Fabric.
"""

from __future__ import annotations

import pytest

_fabric_testing = pytest.importorskip("azazel_fabric.testing")
if not hasattr(_fabric_testing, "load_golden_decision"):  # Fabric < 0.8.0
    pytest.skip(
        "requires azazel_fabric >= 0.8.0 golden decision vectors",
        allow_module_level=True,
    )

from azazel_fabric.deception_contracts import verify_decision_signature  # noqa: E402
from azazel_fabric.testing import (  # noqa: E402
    GOLDEN_DECISION_SIGNATURE_KEY,
    load_golden_decision,
)

from azazel_edge.deception_transition import build_transition_decision  # noqa: E402

# The golden signed vector's window: effective 2026-08-20 .. expires 2026-08-22.
_EFFECTIVE = "2026-08-20T00:00:00+00:00"
_TTL_TWO_DAYS = 2 * 24 * 3600


def test_edge_verifies_fabric_golden_signed_decision():
    golden = load_golden_decision("decision_signed_valid")
    assert verify_decision_signature(golden, GOLDEN_DECISION_SIGNATURE_KEY) is True


def test_edge_producer_regenerates_the_golden_vector_byte_for_byte():
    golden = load_golden_decision("decision_signed_valid")
    produced = build_transition_decision(
        environment_id=golden["environment_id"],
        current_state=golden["current_state"],
        target_state=golden["target_state"],
        as_of=_EFFECTIVE,
        ttl_seconds=_TTL_TWO_DAYS,
        decision_id=golden["decision_id"],
        key=GOLDEN_DECISION_SIGNATURE_KEY,
    )
    # Edge's producer output IS the Fabric-published golden vector.
    assert produced == golden
    assert verify_decision_signature(produced, GOLDEN_DECISION_SIGNATURE_KEY) is True
