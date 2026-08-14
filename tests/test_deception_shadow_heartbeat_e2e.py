"""Networked Edge -> AZ-06 heartbeat + reconciliation end-to-end tests.

These run the real azazel_deception shadow/replay HTTP service on localhost and
drive it with the Edge :class:`HeartbeatLoop`, proving the steady-state half of
the AZ-06 integration: an authenticated heartbeat on an interval, an automatic
reconciliation pass against Edge's own authoritative active set, a divergence
report surfaced to the Edge caller, and fail-closed liveness when the node
disappears — all with zero container start and zero enforcement.

They require the azazel-deception package (plus its Fabric dependency) to be
importable and are skipped otherwise, so baseline Edge CI does not depend on
AZ-06 being present.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

azazel_deception = pytest.importorskip("azazel_deception")

from azazel_deception.package import calculate_package_digest, load_package  # noqa: E402
from azazel_deception.runtime.shadow_server import (  # noqa: E402
    ShadowReplayHTTPServer,
    ShadowReplayService,
)

from azazel_edge.deception_shadow_client import (  # noqa: E402
    Az06ShadowClient,
    HeartbeatLoop,
)

KEY = "edge-az06-heartbeat-key"
EDGE_ID = "edge-heartbeat-node"
NODE_ID = "az06-heartbeat-node"

INTERVAL = 0.2
TIMEOUT = 10.0

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


class _StoppableServer:
    """Server handle a test can stop mid-flight to simulate node loss."""

    def __init__(self, service):
        self.service = service
        self._server = ShadowReplayHTTPServer(service)
        self._server.start()
        self._stopped = False

    @property
    def address(self):
        return self._server.address

    def stop(self) -> None:
        if not self._stopped:
            self._stopped = True
            self._server.stop()


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
    running = _StoppableServer(service)
    try:
        yield running
    finally:
        running.stop()


def _client(server):
    host, port = server.address
    return Az06ShadowClient(
        f"http://{host}:{port}",
        transport_key=KEY,
        edge_node_id=EDGE_ID,
        az06_node_id=NODE_ID,
        timeout_seconds=5.0,
    )


class _EdgeAuthority:
    """Stand-in for the Edge-side owner of the authoritative active set."""

    def __init__(self):
        self._lock = threading.Lock()
        self._active: list[str] = []
        self.divergences: list[dict] = []

    def set_active(self, environment_ids):
        with self._lock:
            self._active = list(environment_ids)

    def current_active(self):
        with self._lock:
            return list(self._active)

    # The reporting hook: it records, it never decides or enforces.
    def on_divergence(self, divergence):
        with self._lock:
            self.divergences.append(divergence)

    def find_divergence(self, *, local_only, edge_only):
        with self._lock:
            for report in self.divergences:
                if (
                    report["local_only_active"] == local_only
                    and report["edge_only_active"] == edge_only
                ):
                    return report
        return None


def _wait_for(predicate, timeout=TIMEOUT, poll=0.02):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(poll)
    return predicate()


def _mark_locally_active(service, environment_id):
    """Simulate a locally materialized environment without executing anything."""

    service.state.write(
        environment_id,
        {
            "environment_id": environment_id,
            "state": "active",
            "package_id": "municipal-linux-v1",
            "node_id": NODE_ID,
            "decision_id": f"edge-decision-{environment_id}",
        },
    )


def test_heartbeat_loop_reports_health_divergence_and_fails_closed(server):
    edge = _EdgeAuthority()
    loop = HeartbeatLoop(
        _client(server),
        interval_seconds=INTERVAL,
        max_age_seconds=INTERVAL * 3,
        edge_active_environment_ids=edge.current_active,
        on_divergence=edge.on_divergence,
    )

    loop.start()
    try:
        # 1. The authenticated loop becomes healthy against a live node.
        assert loop.wait_until_healthy(TIMEOUT) is True
        assert loop.failure_count == 0
        result = loop.last_result
        assert result is not None
        assert result["node_id"] == NODE_ID
        assert result["authority"] == "descriptive_only"
        assert result["enforcement_applied"] is False
        assert result["heartbeat_sequence"] >= 1
        assert result["health"]["live_enabled"] is False
        # Agreeing views produce no divergence report.
        assert loop.last_divergence["consistent"] is True
        assert edge.divergences == []

        # 2. Simulate drift in both directions: one environment running locally
        #    that Edge does not authorize, and one Edge expects that is absent.
        _mark_locally_active(server.service, "env-heartbeat-local-orphan")
        edge.set_active(["env-heartbeat-edge-expects"])

        report = _wait_for(
            lambda: edge.find_divergence(
                local_only=["env-heartbeat-local-orphan"],
                edge_only=["env-heartbeat-edge-expects"],
            )
        )
        assert report is not None, f"no matching divergence: {edge.divergences}"
        assert report["consistent"] is False
        assert report["authority"] == "descriptive_only"
        # The hook only reports; AZ-06 changed nothing in response to it.
        assert (
            server.service.adapter.collect_status("env-heartbeat-local-orphan")["state"]
            == "active"
        )
        assert loop.is_healthy is True

        # 3. The node disappears: the loop fails closed, keeps running, and
        #    never raises out of its thread.
        beats_before = loop.last_result["heartbeat_sequence"]
        server.stop()
        assert _wait_for(lambda: loop.is_healthy is False) is True
        failures = loop.failure_count
        assert failures >= 1
        assert loop.last_error is not None
        # Still retrying rather than dead, and holding the last known state.
        assert _wait_for(lambda: loop.failure_count > failures) is True
        assert loop.last_result["heartbeat_sequence"] == beats_before
    finally:
        loop.stop()

    assert loop.is_healthy is False


def test_heartbeat_loop_survives_a_broken_divergence_callback(server):
    edge = _EdgeAuthority()
    _mark_locally_active(server.service, "env-heartbeat-callback-orphan")

    def _explode(divergence):
        raise RuntimeError("edge reporting hook is broken")

    loop = HeartbeatLoop(
        _client(server),
        interval_seconds=INTERVAL,
        max_age_seconds=INTERVAL * 3,
        edge_active_environment_ids=edge.current_active,
        on_divergence=_explode,
    )
    loop.start()
    try:
        assert loop.wait_until_healthy(TIMEOUT) is True
        assert _wait_for(lambda: loop.last_divergence is not None) is not None
        assert loop.last_divergence["local_only_active"] == [
            "env-heartbeat-callback-orphan"
        ]
        # A broken Edge-side reporting hook is not an AZ-06 liveness failure,
        # and it must not kill the loop.
        assert _wait_for(
            lambda: (loop.last_result or {}).get("heartbeat_sequence", 0) >= 3
        )
        assert loop.failure_count == 0
        assert loop.is_healthy is True
    finally:
        loop.stop()


def test_typed_heartbeat_and_reconcile_round_trip(server):
    client = _client(server)

    heartbeat = client.heartbeat(
        edge_sequence=42, edge_active_environment_ids=["env-b", "env-a"]
    )
    assert heartbeat["status"] == "ok"
    assert heartbeat["authority"] == "descriptive_only"
    assert heartbeat["enforcement_applied"] is False
    assert heartbeat["result"]["edge_sequence"] == 42
    assert heartbeat["result"]["edge_active_environment_ids"] == ["env-a", "env-b"]
    assert heartbeat["result"]["issued_at"]
    assert heartbeat["result"]["responded_at"]

    _mark_locally_active(server.service, "env-heartbeat-typed-orphan")
    reconcile = client.reconcile(["env-heartbeat-typed-missing"])
    assert reconcile["status"] == "ok"
    result = reconcile["result"]
    assert result["divergence"]["local_only_active"] == ["env-heartbeat-typed-orphan"]
    assert result["divergence"]["edge_only_active"] == ["env-heartbeat-typed-missing"]
    states = result["divergent_environment_states"]
    assert states["env-heartbeat-typed-orphan"]["state"] == "active"
    assert states["env-heartbeat-typed-missing"]["state"] == "absent"

    # Anti-replay and node binding still hold for the new actions.
    assert client.heartbeat()["result"]["heartbeat_sequence"] > (
        heartbeat["result"]["heartbeat_sequence"]
    )
