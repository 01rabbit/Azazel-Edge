"""Shadow/replay boundary for AZ-06 Azazel-Deception Host.

This module deliberately contains no container, VM, route, nftables, tc, or
other enforcement operation.  It lets Edge validate a canonical deception
package, an authenticated AZ-06 capability snapshot, and a descriptive
placement plan against an Edge-local prospective decision ID.

The output is advisory to Edge's existing deterministic Action Arbiter and
always records ``enforcement_applied=False``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any

try:
    from azazel_fabric.deception_contracts import (
        DeceptionPackage,
        HostCapabilities,
        PlacementPlan,
        assert_no_runtime_directives,
    )
except ImportError:  # Fabric remains an optional Edge integration dependency.
    DeceptionPackage = None  # type: ignore[assignment,misc]
    HostCapabilities = None  # type: ignore[assignment,misc]
    PlacementPlan = None  # type: ignore[assignment,misc]
    assert_no_runtime_directives = None  # type: ignore[assignment]


@dataclass(frozen=True)
class Az06ShadowResult:
    status: str
    reason_codes: tuple[str, ...]
    enforcement_applied: bool
    decision_id: str
    package_id: str | None = None
    package_digest: str | None = None
    node_id: str | None = None
    architecture: str | None = None
    selected_tier: str | None = None
    placement_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fabric_available() -> bool:
    return all(
        value is not None
        for value in (
            DeceptionPackage,
            HostCapabilities,
            PlacementPlan,
            assert_no_runtime_directives,
        )
    )


def _sha_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _rejected(decision_id: str, reasons: list[str], **context: Any) -> Az06ShadowResult:
    return Az06ShadowResult(
        status="would_reject",
        reason_codes=tuple(sorted(set(reasons))),
        enforcement_applied=False,
        decision_id=decision_id,
        **context,
    )


def evaluate_az06_shadow(
    *,
    decision_id: str,
    package_payload: dict[str, Any],
    capability_payload: dict[str, Any],
    placement_payload: dict[str, Any],
) -> Az06ShadowResult:
    """Evaluate AZ-06 materialization inputs without executing anything.

    ``decision_id`` is generated/owned by Edge.  A placement plan may refer to
    it, but cannot create or upgrade authority.  All malformed or ambiguous
    data fail closed to ``would_reject``.
    """

    if not decision_id:
        return _rejected("missing", ["missing_edge_decision_id"])
    if not fabric_available():
        return _rejected(decision_id, ["fabric_unavailable"])

    assert assert_no_runtime_directives is not None
    try:
        assert_no_runtime_directives(package_payload)
        assert_no_runtime_directives(capability_payload)
        assert_no_runtime_directives(placement_payload)
        package = DeceptionPackage.model_validate(package_payload)  # type: ignore[union-attr]
        host = HostCapabilities.model_validate(capability_payload)  # type: ignore[union-attr]
        placement = PlacementPlan.model_validate(placement_payload)  # type: ignore[union-attr]
    except Exception as exc:
        return _rejected(decision_id, ["invalid_or_unsafe_contract", exc.__class__.__name__])

    context = {
        "package_id": package.package_id,
        "package_digest": package.package_digest,
        "node_id": host.node_id,
        "architecture": host.architecture,
        "selected_tier": placement.selected_tier,
        "placement_id": placement.placement_id,
    }
    reasons: list[str] = []

    if placement.authority != "descriptive_only" or host.authority != "descriptive_only":
        reasons.append("authority_ambiguity")
    if placement.edge_decision_id != decision_id:
        reasons.append("edge_decision_binding_mismatch")
    if placement.package_id != package.package_id:
        reasons.append("package_id_mismatch")
    if placement.package_digest != package.package_digest:
        reasons.append("package_digest_mismatch")
    if placement.node_id != host.node_id:
        reasons.append("node_binding_mismatch")
    if placement.architecture != host.architecture:
        reasons.append("architecture_binding_mismatch")
    if host.architecture not in package.runtime_requirements.architectures:
        reasons.append("unsupported_architecture")
    if placement.runtime_adapter != package.runtime_requirements.runtime_adapter:
        reasons.append("runtime_adapter_mismatch")
    if not host.runtime_adapters.get(package.runtime_requirements.runtime_adapter, False):
        reasons.append("runtime_adapter_unavailable")

    expected_capability_digest = _sha_json(host.model_dump(mode="json"))
    if placement.capability_snapshot_digest != expected_capability_digest:
        reasons.append("capability_snapshot_digest_mismatch")

    tiers = {tier.tier_id: tier for tier in package.deployment_tiers}
    tier = tiers.get(placement.selected_tier)
    if tier is None:
        reasons.append("unknown_deployment_tier")
    else:
        if tuple(placement.component_ids) != tuple(tier.include_components):
            reasons.append("placement_component_set_mismatch")
        if host.cpu_cores < tier.minimum.cpu_cores:
            reasons.append("insufficient_cpu")
        if host.memory_mb < tier.minimum.memory_mb:
            reasons.append("insufficient_memory")
        if host.storage_free_mb < tier.minimum.storage_mb:
            reasons.append("insufficient_storage")

    # Verified OCI provenance is required for the components this placement
    # would actually materialize; an unselected optional component does not
    # block the placement (matching AZ-06's live-gate semantics).
    selected_components = set(placement.component_ids)
    unverified = [
        c.component_id
        for c in package.components
        if c.component_id in selected_components and not c.image.verified
    ]
    if unverified:
        reasons.append("unverified_oci_provenance")

    if reasons:
        return _rejected(decision_id, reasons, **context)

    return Az06ShadowResult(
        status="would_accept",
        reason_codes=("shadow_only_no_enforcement",),
        enforcement_applied=False,
        decision_id=decision_id,
        **context,
    )
