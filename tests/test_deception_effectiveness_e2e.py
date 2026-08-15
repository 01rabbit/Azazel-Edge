"""Networked Edge -> Knowledge (AZ-04) effectiveness-advisory end-to-end tests.

These exercise :mod:`azazel_edge.deception_effectiveness_client` against a
lightweight stdlib ``http.server`` stub standing in for the real
Azazel-Knowledge AZ-04 ingest/advisory HTTP API, so the suite runs without
that application being installed (baseline Edge CI does not depend on
Knowledge being present).

Covered, per the Deception -> Edge -> Knowledge interlock contract:

* observation batches relay successfully, untouched, to ``POST
  /v1/deception-observations``;
* a valid ``EffectivenessAdvisory`` from ``GET
  /v1/deception-advisories/{environment_id}`` is returned and verified;
* a response claiming executable/verdict/authority is rejected fail-closed;
* a Knowledge outage degrades to "advisory unavailable" fail-open, without
  raising;
* baseline Edge behavior (the optional advisory source) is unaffected when
  Knowledge is unconfigured.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

azazel_fabric = pytest.importorskip("azazel_fabric.deception_contracts")

from azazel_fabric.deception_contracts import (  # noqa: E402
    EffectivenessAdvisory,
    InteractionObservation,
)

from azazel_edge.deception_effectiveness_client import (  # noqa: E402
    AdvisoryReadResult,
    EffectivenessAdvisoryReader,
    IngestResult,
    KnowledgeAuthConfig,
    KnowledgeIngestClient,
    OptionalEffectivenessAdvisorySource,
)

ENVIRONMENT_ID = "env-eff-e2e-1"
PACKAGE_ID = "municipal-linux-v1"
NODE_ID = "az06-eff-e2e-node"
EDGE_NODE_ID = "edge-eff-e2e-node"
TOKEN = "eff-e2e-ingest-token"

# Deliberately markup/script-shaped: proves the client forwards attacker
# authored content verbatim instead of interpreting it.
HOSTILE_LOOKING_LURE_ID = "lure-<script>alert('pwn')</script>-${jndi:ldap://x}"


def _observation(observation_id: str, *, environment_id: str = ENVIRONMENT_ID) -> dict[str, Any]:
    obs = InteractionObservation(
        observation_id=observation_id,
        environment_id=environment_id,
        package_id=PACKAGE_ID,
        node_id=NODE_ID,
        observed_at=datetime.now(timezone.utc),
        observation_class="interaction",
        surface="credential_lure",
        lure_id=HOSTILE_LOOKING_LURE_ID,
        first_contact_latency_ms=120,
        evidence_refs=["evid-eff-1"],
    )
    return obs.model_dump(mode="json")


def _valid_advisory(*, environment_id: str = ENVIRONMENT_ID) -> dict[str, Any]:
    advisory = EffectivenessAdvisory(
        advisory_id="adv-eff-e2e-1",
        environment_id=environment_id,
        package_id=PACKAGE_ID,
        node_id=NODE_ID,
        produced_at=datetime.now(timezone.utc),
        assessment="Attacker dwelled on the credential lure beyond baseline.",
        confidence=0.55,
        counter_evidence=["dwell_time_may_reflect_automation_not_belief"],
        observation_refs=["obs-eff-e2e-1"],
        unknowns=["attacker_intent"],
    )
    return advisory.model_dump(mode="json")


class _StubState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.received_batches: list[Any] = []
        self.received_ingest_auth: list[str | None] = []
        self.received_advisory_auth: list[str | None] = []
        self.ingest_status = 202
        self.advisory_payload: Any = None
        self.advisory_status = 200


class _StubHandler(BaseHTTPRequestHandler):
    state: _StubState  # bound per-server via subclassing

    def log_message(self, format: str, *args: Any) -> None:  # silence test noise
        pass

    def do_POST(self) -> None:  # noqa: N802 (stdlib handler naming)
        if self.path != "/v1/deception-observations":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        try:
            payload = json.loads(body.decode("utf-8")) if body else None
        except json.JSONDecodeError:
            payload = None
        with self.state.lock:
            self.state.received_batches.append(payload)
            self.state.received_ingest_auth.append(self.headers.get("Authorization"))
            status = self.state.ingest_status
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"received": True}).encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        if not self.path.startswith("/v1/deception-advisories/"):
            self.send_response(404)
            self.end_headers()
            return
        with self.state.lock:
            self.state.received_advisory_auth.append(self.headers.get("Authorization"))
            payload = self.state.advisory_payload
            status = self.state.advisory_status
        if payload is None:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class StubKnowledgeServer:
    """Minimal stand-in for the AZ-04 ingest/advisory HTTP API, localhost only."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.state = _StubState()
        handler = type("BoundStubHandler", (_StubHandler,), {"state": self.state})
        self._server = ThreadingHTTPServer((host, port), handler)
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address[0], self._server.server_address[1]

    @property
    def base_url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def start(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def __enter__(self) -> "StubKnowledgeServer":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()


@pytest.fixture
def server():
    with StubKnowledgeServer() as running:
        yield running


def _ingest_client(server: StubKnowledgeServer, **kwargs: Any) -> KnowledgeIngestClient:
    return KnowledgeIngestClient(
        server.base_url,
        edge_node_id=EDGE_NODE_ID,
        auth=KnowledgeAuthConfig(token=TOKEN),
        timeout_seconds=5.0,
        **kwargs,
    )


def _advisory_reader(server: StubKnowledgeServer, **kwargs: Any) -> EffectivenessAdvisoryReader:
    return EffectivenessAdvisoryReader(
        server.base_url,
        auth=KnowledgeAuthConfig(token=TOKEN),
        timeout_seconds=5.0,
        **kwargs,
    )


# -- 1. observation relay -----------------------------------------------------


def test_observations_relay_successfully_and_untouched(server):
    client = _ingest_client(server)
    observation = _observation("obs-eff-e2e-1")

    result = client.submit_observations([observation])

    assert isinstance(result, IngestResult)
    assert result.status == "accepted"
    assert result.ok is True
    assert result.http_status == 202
    assert result.submitted_count == 1

    # The server received exactly what was sent, including the hostile
    # looking attacker-authored string -- unmodified, un-escaped, un-executed.
    assert len(server.state.received_batches) == 1
    received = server.state.received_batches[0]
    assert received["schema_version"] == "deception-observation-batch/v0.1"
    assert received["source_edge_node_id"] == EDGE_NODE_ID
    assert received["observations"] == [observation]
    assert (
        received["observations"][0]["lure_id"] == HOSTILE_LOOKING_LURE_ID
    )

    # Configurable, non-hardcoded bearer auth actually made it onto the wire.
    assert server.state.received_ingest_auth == [f"Bearer {TOKEN}"]


def test_observation_batch_backpressure_is_not_raised(server):
    server.state.ingest_status = 503
    client = _ingest_client(server)

    result = client.submit_observations([_observation("obs-eff-e2e-2")])

    assert result.status == "backpressure"
    assert result.ok is False
    assert result.http_status == 503


def test_observation_batch_too_large_is_backpressure_not_raised(server):
    server.state.ingest_status = 413
    client = _ingest_client(server)

    result = client.submit_observations([_observation("obs-eff-e2e-3")])

    assert result.status == "backpressure"
    assert result.http_status == 413


def test_invalid_local_batch_never_reaches_the_wire(server):
    client = _ingest_client(server)

    result = client.submit_observations([])
    assert result.status == "invalid_batch"

    result = client.submit_observations([{"not": "an observation"}, "not-a-dict"])  # type: ignore[list-item]
    assert result.status == "invalid_batch"

    assert server.state.received_batches == []


def test_ingest_never_raises_when_knowledge_is_unreachable():
    # Nothing is listening on this port.
    client = KnowledgeIngestClient(
        "http://127.0.0.1:1",
        edge_node_id=EDGE_NODE_ID,
        auth=KnowledgeAuthConfig(token=TOKEN),
        timeout_seconds=1.0,
    )
    result = client.submit_observations([_observation("obs-eff-e2e-unreachable")])
    assert result.status == "unreachable"
    assert result.ok is False


# -- 2. advisory read + fail-closed verification ------------------------------


def test_valid_advisory_returned_and_verified(server):
    server.state.advisory_payload = _valid_advisory()
    reader = _advisory_reader(server)

    result = reader.get_advisory(ENVIRONMENT_ID)

    assert isinstance(result, AdvisoryReadResult)
    assert result.available is True
    assert result.reason == "ok"
    assert result.advisory is not None
    assert result.advisory["authority"] == "advisory_only"
    assert result.advisory["executable"] is False
    assert result.advisory["environment_id"] == ENVIRONMENT_ID
    assert result.advisory["confidence"] == pytest.approx(0.55)

    assert server.state.received_advisory_auth == [f"Bearer {TOKEN}"]

    # Low-level fail-closed API returns the same verified dict directly.
    direct = reader.fetch_advisory(ENVIRONMENT_ID)
    assert direct["advisory_id"] == "adv-eff-e2e-1"


def test_advisory_claiming_executable_is_rejected_fail_closed(server):
    hostile = _valid_advisory()
    hostile["executable"] = True  # claims it can act -- must be rejected
    server.state.advisory_payload = hostile
    reader = _advisory_reader(server)

    result = reader.get_advisory(ENVIRONMENT_ID)

    assert result.available is False
    assert result.reason == "hostile_response"
    assert result.advisory is None

    from azazel_edge.deception_effectiveness_client import AdvisoryVerificationError

    with pytest.raises(AdvisoryVerificationError):
        reader.fetch_advisory(ENVIRONMENT_ID)


def test_advisory_carrying_a_verdict_field_is_rejected_fail_closed(server):
    hostile = _valid_advisory()
    hostile["verdict"] = "attacker_fully_deceived"  # not a field on the contract
    server.state.advisory_payload = hostile
    reader = _advisory_reader(server)

    result = reader.get_advisory(ENVIRONMENT_ID)

    assert result.available is False
    assert result.reason == "hostile_response"


def test_advisory_carrying_a_runtime_directive_is_rejected_fail_closed(server):
    hostile = _valid_advisory()
    hostile["bypass_arbiter"] = True  # a banned Fabric runtime-directive key
    server.state.advisory_payload = hostile
    reader = _advisory_reader(server)

    result = reader.get_advisory(ENVIRONMENT_ID)

    assert result.available is False
    assert result.reason == "hostile_response"


def test_advisory_claiming_non_advisory_authority_is_rejected_fail_closed(server):
    hostile = _valid_advisory()
    hostile["authority"] = "authoritative"
    server.state.advisory_payload = hostile
    reader = _advisory_reader(server)

    result = reader.get_advisory(ENVIRONMENT_ID)

    assert result.available is False
    assert result.reason == "hostile_response"


def test_malformed_advisory_body_degrades_without_raising(server):
    server.state.advisory_payload = ["not", "an", "object"]
    reader = _advisory_reader(server)

    result = reader.get_advisory(ENVIRONMENT_ID)

    assert result.available is False
    assert result.reason == "malformed_response"


# -- 3. fail-open at the Edge-operation level ---------------------------------


def test_knowledge_outage_degrades_to_advisory_unavailable_fail_open():
    # Nothing is listening on this port: simulates Knowledge being down.
    reader = EffectivenessAdvisoryReader(
        "http://127.0.0.1:1",
        auth=KnowledgeAuthConfig(token=TOKEN),
        timeout_seconds=1.0,
    )

    result = reader.get_advisory(ENVIRONMENT_ID)  # must not raise

    assert result.available is False
    assert result.reason == "unreachable"
    assert result.advisory is None


def test_advisory_missing_for_environment_degrades_gracefully(server):
    # No advisory configured for this environment: stub 404s.
    reader = _advisory_reader(server)

    result = reader.get_advisory("env-with-no-advisory-yet")

    assert result.available is False
    assert result.reason == "unreachable"


# -- 4. optional advisory source / unconfigured baseline ----------------------


def test_optional_source_consult_returns_advisory_when_configured(server):
    server.state.advisory_payload = _valid_advisory()
    source = OptionalEffectivenessAdvisorySource(_advisory_reader(server))

    assert source.configured is True
    result = source.consult(ENVIRONMENT_ID)
    assert result.available is True
    assert result.advisory["authority"] == "advisory_only"


def test_optional_source_is_unconfigured_and_makes_no_network_call(monkeypatch):
    def _forbidden(*args: Any, **kwargs: Any):
        raise AssertionError("no network call should happen when unconfigured")

    monkeypatch.setattr("urllib.request.urlopen", _forbidden)

    source = OptionalEffectivenessAdvisorySource()  # reader=None: unconfigured

    assert source.configured is False
    result = source.consult(ENVIRONMENT_ID)

    assert result.available is False
    assert result.reason == "unconfigured"
    assert result.advisory is None


def test_baseline_edge_behavior_unchanged_when_client_not_configured():
    """The advisory source existing in a call graph must be a no-op absent config.

    This models how the operator/arbiter would consult advisory context: the
    call is always safe to make, and when Knowledge was never wired up it
    returns the same "unconfigured" result deterministically, with no side
    effects, no exception, and no network I/O -- so any code path that calls
    it behaves identically to code that never mentions this module at all.
    """

    source = OptionalEffectivenessAdvisorySource(reader=None)
    results = [source.consult(f"env-{i}") for i in range(5)]

    assert all(r.available is False and r.reason == "unconfigured" for r in results)
