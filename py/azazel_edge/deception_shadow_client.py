"""Networked shadow/replay client for the AZ-06 Azazel-Deception Host.

This is the Edge side of the strictly non-executing bootstrap integration
(Azazel-Edge#325): it can discover and authenticate an AZ-06 node's identity
and capabilities, read the reference package identity, request deterministic
descriptive placement plans, and rehearse activation/termination decisions —
producing a complete audit trace with zero container start and zero
enforcement. The wire protocol is owned by AZ-06
(`azazel_deception.runtime.shadow_server`); this module mirrors its envelope
canonicalization and HMAC-SHA256 transport signature.

Authority rule: nothing returned by AZ-06 can create or upgrade authority.
Every response is checked to be `descriptive_only` with
`enforcement_applied=False`; anything else fails closed. AZ-06 stays
optional — a connection failure degrades to an explicit error, never to a
baseline Edge behavior change.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from azazel_edge.deception_shadow import evaluate_az06_shadow, fabric_available

REQUEST_SCHEMA = "az06-shadow-request/v0.1"
RESPONSE_SCHEMA = "az06-shadow-response/v0.1"
SESSION_SCHEMA = "az06-shadow-session/v0.1"
SIGNATURE_FIELD = "signature"


class ShadowTransportError(RuntimeError):
    """A shadow request could not be completed or verified."""


def _canonical_bytes(envelope: dict[str, Any]) -> bytes:
    payload = {k: v for k, v in envelope.items() if k != SIGNATURE_FIELD}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _signature(envelope: dict[str, Any], key: str | bytes) -> str:
    key_bytes = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    return hmac.new(key_bytes, _canonical_bytes(envelope), hashlib.sha256).hexdigest()


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Az06ShadowClient:
    """Authenticated client for one AZ-06 shadow/replay endpoint."""

    def __init__(
        self,
        base_url: str,
        *,
        transport_key: str | bytes,
        edge_node_id: str,
        az06_node_id: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        if not edge_node_id or not az06_node_id:
            raise ValueError("edge_node_id and az06_node_id are required")
        self.base_url = base_url.rstrip("/")
        self._key = transport_key
        self.edge_node_id = edge_node_id
        self.az06_node_id = az06_node_id
        self.timeout_seconds = float(timeout_seconds)

    # -- transport -----------------------------------------------------------

    def request(self, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send one signed envelope and return the verified response."""

        envelope: dict[str, Any] = {
            "schema_version": REQUEST_SCHEMA,
            "request_id": f"{self.edge_node_id}-{uuid.uuid4().hex}",
            "edge_node_id": self.edge_node_id,
            "az06_node_id": self.az06_node_id,
            "action": action,
            "issued_at": _utcnow_iso(),
            "payload": payload or {},
        }
        envelope[SIGNATURE_FIELD] = _signature(envelope, self._key)
        http_request = urllib.request.Request(
            f"{self.base_url}/shadow",
            data=json.dumps(envelope).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout_seconds) as raw:
                response = json.loads(raw.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise ShadowTransportError(f"shadow transport failed: {exc}") from exc
        self._verify_response(envelope, response)
        return response

    def _verify_response(self, envelope: dict[str, Any], response: Any) -> None:
        if not isinstance(response, dict):
            raise ShadowTransportError("shadow response is not a JSON object")
        if response.get("schema_version") != RESPONSE_SCHEMA:
            raise ShadowTransportError("unsupported shadow response schema")
        provided = response.get(SIGNATURE_FIELD)
        if not isinstance(provided, str) or not hmac.compare_digest(
            provided, _signature(response, self._key)
        ):
            raise ShadowTransportError("shadow response failed authentication")
        if response.get("request_id") != envelope["request_id"]:
            raise ShadowTransportError("shadow response request binding mismatch")
        if response.get("az06_node_id") != self.az06_node_id:
            raise ShadowTransportError("shadow response node identity mismatch")
        # Descriptive-only is not negotiable: an endpoint claiming authority or
        # enforcement is treated as hostile, whatever its status code says.
        if response.get("authority") != "descriptive_only":
            raise ShadowTransportError("shadow response claims non-descriptive authority")
        if response.get("enforcement_applied") is not False:
            raise ShadowTransportError("shadow response claims enforcement was applied")

    # -- typed actions -------------------------------------------------------

    def discover_capabilities(self) -> dict[str, Any]:
        return self.request("capabilities")

    def fetch_package(self) -> dict[str, Any]:
        return self.request("package")

    def request_plan(
        self, *, requested_tier: str | None, edge_decision_id: str
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"edge_decision_id": edge_decision_id}
        if requested_tier is not None:
            payload["requested_tier"] = requested_tier
        return self.request("plan", payload)

    def shadow_activate(
        self,
        *,
        environment_id: str,
        package: dict[str, Any],
        placement: dict[str, Any],
        decision: dict[str, Any],
    ) -> dict[str, Any]:
        return self.request(
            "activate",
            {
                "environment_id": environment_id,
                "package": package,
                "placement": placement,
                "decision": decision,
            },
        )

    def shadow_terminate(
        self, *, environment_id: str, decision: dict[str, Any]
    ) -> dict[str, Any]:
        return self.request(
            "terminate", {"environment_id": environment_id, "decision": decision}
        )

    # -- bootstrap session ---------------------------------------------------

    def run_bootstrap_session(
        self,
        *,
        edge_decision_id: str,
        requested_tier: str,
        environment_id: str,
        activation_decision: dict[str, Any] | None = None,
        termination_decision: dict[str, Any] | None = None,
        build_activation_decision=None,
        build_termination_decision=None,
    ) -> dict[str, Any]:
        """Run the full non-executing bootstrap integration flow.

        Implements Azazel-Edge#325's bootstrap target: authenticate and
        discover capabilities, read the package identity, request a plan bound
        to the Edge decision ID, validate everything locally with the shadow
        evaluator, record rejected tier alternatives, and rehearse
        activation/termination — with zero container start.

        The activation/termination decisions come from the caller (normally
        the Action Arbiter): pass them directly, or pass builder callables
        that receive the AZ-06-reported package/capabilities/plan so decision
        bindings can be derived from what the node actually reported.
        """

        if not fabric_available():
            raise ShadowTransportError(
                "canonical Fabric deception contracts are unavailable"
            )

        started = time.time()
        trace: dict[str, Any] = {
            "schema_version": SESSION_SCHEMA,
            "edge_node_id": self.edge_node_id,
            "az06_node_id": self.az06_node_id,
            "edge_decision_id": edge_decision_id,
            "requested_tier": requested_tier,
            "environment_id": environment_id,
            "started_at": _utcnow_iso(),
            "steps": [],
            "rejected_alternatives": [],
            "enforcement_applied": False,
            "container_start_count": 0,
        }

        def _step(name: str, response: dict[str, Any]) -> dict[str, Any]:
            entry = {
                "step": name,
                "status": response.get("status"),
                "reason_codes": response.get("reason_codes"),
                "result": response.get("result"),
            }
            trace["steps"].append(entry)
            if response.get("status") != "ok":
                raise ShadowTransportError(
                    f"shadow step {name} rejected: {response.get('reason_codes')}"
                )
            return response["result"]

        capabilities = _step("capabilities", self.discover_capabilities())["capabilities"]
        package_result = _step("package", self.fetch_package())
        package = package_result["package"]
        trace["package_identity"] = {
            "package_id": package_result["package_id"],
            "package_version": package_result["package_version"],
            "package_digest": package_result["package_digest"],
            "components": [
                {
                    "component_id": component.get("component_id"),
                    "verified": component.get("image", {}).get("verified"),
                    "provenance_ref": component.get("image", {}).get("provenance_ref"),
                    "sbom_ref": component.get("image", {}).get("sbom_ref"),
                }
                for component in package.get("components", [])
            ],
        }
        trace["capability_snapshot"] = capabilities

        # Record every non-selected authored tier as a visible, reasoned
        # rejected alternative instead of silently dropping it.
        for tier in package.get("deployment_tiers", []):
            tier_id = tier.get("tier_id")
            if tier_id == requested_tier:
                continue
            trace["rejected_alternatives"].append(
                {"tier_id": tier_id, "reason": "not_selected_by_edge_decision"}
            )

        plan = _step(
            "plan",
            self.request_plan(
                requested_tier=requested_tier, edge_decision_id=edge_decision_id
            ),
        )["placement_plan"]
        trace["placement_plan"] = plan

        local = evaluate_az06_shadow(
            decision_id=edge_decision_id,
            package_payload=package,
            capability_payload=capabilities,
            placement_payload=plan,
        )
        trace["local_shadow_evaluation"] = local.to_dict()
        if local.status != "would_accept":
            trace["completed_at"] = _utcnow_iso()
            trace["outcome"] = "rejected_by_local_evaluation"
            return trace

        if activation_decision is None and build_activation_decision is not None:
            activation_decision = build_activation_decision(package, capabilities, plan)
        if activation_decision is not None:
            activation = _step(
                "shadow_activate",
                self.shadow_activate(
                    environment_id=environment_id,
                    package=package,
                    placement=plan,
                    decision=activation_decision,
                ),
            )
            trace["simulated_activation"] = activation

            if termination_decision is None and build_termination_decision is not None:
                termination_decision = build_termination_decision(
                    package, capabilities, plan
                )
            if termination_decision is not None:
                termination = _step(
                    "shadow_terminate",
                    self.shadow_terminate(
                        environment_id=environment_id, decision=termination_decision
                    ),
                )
                trace["simulated_termination"] = termination

        trace["completed_at"] = _utcnow_iso()
        trace["duration_seconds"] = round(time.time() - started, 3)
        trace["outcome"] = "shadow_complete"
        return trace
