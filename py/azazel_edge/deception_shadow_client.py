"""Networked shadow/replay client for the AZ-06 Azazel-Deception Host.

This is the Edge side of the strictly non-executing bootstrap integration
(Azazel-Edge#325): it can discover and authenticate an AZ-06 node's identity
and capabilities, read the reference package identity, request deterministic
descriptive placement plans, and rehearse activation/termination decisions —
producing a complete audit trace with zero container start and zero
enforcement. The wire protocol is owned by AZ-06
(`azazel_deception.runtime.shadow_server`); this module mirrors its envelope
canonicalization and HMAC-SHA256 transport signature.

:class:`HeartbeatLoop` extends this to a steady-state posture: an
authenticated heartbeat on an interval plus an automatic reconciliation pass
that compares Edge's authoritative active set against what AZ-06 reports
locally, surfacing any divergence to a caller-supplied reporting hook.

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
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable, Iterable
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

    def heartbeat(
        self,
        edge_sequence: int | None = None,
        edge_active_environment_ids: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Poll an AZ-06 node for liveness and a small health summary.

        Purely observational: the response tells Edge whether the node is
        reachable, authentic, and what it believes is running. It cannot make
        Edge do anything, and Edge sending its own active set here is a
        statement of authority, not a request for AZ-06 to act on it.
        """

        payload: dict[str, Any] = {}
        if edge_sequence is not None:
            payload["edge_sequence"] = int(edge_sequence)
        if edge_active_environment_ids is not None:
            payload["edge_active_environment_ids"] = [
                str(environment_id) for environment_id in edge_active_environment_ids
            ]
        return self.request("heartbeat", payload)

    def reconcile(self, edge_active_environment_ids: Iterable[str]) -> dict[str, Any]:
        """Ask AZ-06 how local runtime state diverges from Edge's active set.

        Edge supplies the authoritative set; AZ-06 answers descriptively. Any
        remediation of a reported divergence is an Edge decision (or the
        operator kill switch) made after this call, never a side effect of it.
        """

        return self.request(
            "reconcile",
            {
                "edge_active_environment_ids": [
                    str(environment_id) for environment_id in edge_active_environment_ids
                ]
            },
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


class HeartbeatLoop:
    """Background liveness + state-reconciliation loop against one AZ-06 node.

    Every ``interval_seconds`` the loop sends one authenticated heartbeat and,
    on success, one reconcile request carrying the *Edge-supplied* active
    environment set (from the ``edge_active_environment_ids`` callable). If
    AZ-06 reports the two views are not consistent, ``on_divergence`` is
    invoked with the divergence dict.

    Authority model: the callback is a reporting hook and decides nothing. It
    cannot activate, terminate, or reconcile anything — Edge (the caller)
    remains the sole authority and must issue a decision or use the operator
    kill switch to act on a reported divergence. AZ-06 acts on nothing either.

    Fail-closed liveness: any transport, authentication, or rejection error
    marks the loop unhealthy, is counted as a consecutive failure, and never
    escapes the thread. The loop keeps retrying on its interval until
    :meth:`stop`, because AZ-06 is optional — an unreachable node must degrade
    to "unhealthy, no fresh state", never to a crash or a stalled Edge.
    """

    def __init__(
        self,
        client: Az06ShadowClient,
        *,
        interval_seconds: float = 30.0,
        max_age_seconds: float | None = None,
        edge_active_environment_ids: Callable[[], Iterable[str]] | None = None,
        on_divergence: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self._client = client
        self.interval_seconds = float(interval_seconds)
        # Default staleness window tolerates two missed beats before the last
        # success stops counting as "recent".
        self.max_age_seconds = (
            float(max_age_seconds)
            if max_age_seconds is not None
            else self.interval_seconds * 3.0
        )
        self._edge_active = edge_active_environment_ids or (lambda: [])
        self._on_divergence = on_divergence
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._edge_sequence = 0
        self._failure_count = 0
        self._last_result: dict[str, Any] | None = None
        self._last_divergence: dict[str, Any] | None = None
        self._last_error: str | None = None
        self._last_success_monotonic: float | None = None

    # -- observable state ----------------------------------------------------

    @property
    def is_healthy(self) -> bool:
        """True iff the last heartbeat succeeded and is younger than max_age.

        Fail-closed on both counts: a failed most-recent attempt is unhealthy
        immediately, and an old success goes stale on its own even if the
        thread stopped ticking entirely.
        """

        with self._lock:
            if self._failure_count or self._last_success_monotonic is None:
                return False
            return (
                time.monotonic() - self._last_success_monotonic
            ) <= self.max_age_seconds

    @property
    def last_result(self) -> dict[str, Any] | None:
        """Result payload of the last successful heartbeat, if any."""

        with self._lock:
            return self._last_result

    @property
    def last_divergence(self) -> dict[str, Any] | None:
        with self._lock:
            return self._last_divergence

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    @property
    def failure_count(self) -> int:
        """Consecutive failed heartbeats; reset to zero by any success."""

        with self._lock:
            return self._failure_count

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("heartbeat loop is already running")
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._run, name="az06-heartbeat-loop", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        self._stopping.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def __enter__(self) -> "HeartbeatLoop":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()

    def wait_until_healthy(self, timeout: float, poll_seconds: float = 0.02) -> bool:
        """Block until the loop is healthy or ``timeout`` elapses."""

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_healthy:
                return True
            time.sleep(poll_seconds)
        return self.is_healthy

    # -- loop body -----------------------------------------------------------

    def _run(self) -> None:
        while not self._stopping.is_set():
            self._tick()
            self._stopping.wait(self.interval_seconds)

    def _tick(self) -> None:
        """Run one heartbeat + reconcile pass. Never raises."""

        try:
            edge_active = [
                str(environment_id) for environment_id in self._edge_active()
            ]
            with self._lock:
                self._edge_sequence += 1
                sequence = self._edge_sequence
            result = self._ok_result(
                self._client.heartbeat(
                    edge_sequence=sequence,
                    edge_active_environment_ids=edge_active,
                ),
                "heartbeat",
            )
            reconcile = self._ok_result(
                self._client.reconcile(edge_active), "reconcile"
            )
        except Exception as exc:  # fail closed; the thread must survive anything
            with self._lock:
                self._failure_count += 1
                self._last_error = f"{exc.__class__.__name__}: {exc}"
            return

        divergence = reconcile.get("divergence")
        with self._lock:
            self._failure_count = 0
            self._last_error = None
            self._last_result = result
            self._last_divergence = divergence
            self._last_success_monotonic = time.monotonic()

        if isinstance(divergence, dict) and divergence.get("consistent") is not True:
            self._report_divergence(divergence)

    @staticmethod
    def _ok_result(response: dict[str, Any], action: str) -> dict[str, Any]:
        if response.get("status") != "ok":
            raise ShadowTransportError(
                f"shadow {action} rejected: {response.get('reason_codes')}"
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise ShadowTransportError(f"shadow {action} returned no result object")
        return result

    def _report_divergence(self, divergence: dict[str, Any]) -> None:
        """Hand the divergence report to the caller's hook, defensively.

        A broken reporting hook is not an AZ-06 liveness failure, so it does
        not mark the loop unhealthy — but it must never kill the loop either.
        """

        if self._on_divergence is None:
            return
        try:
            self._on_divergence(divergence)
        except Exception as exc:
            with self._lock:
                self._last_error = (
                    f"on_divergence callback failed: {exc.__class__.__name__}: {exc}"
                )
