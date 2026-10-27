"""Edge#388: the agent sends model requests to loopback only.

The analyst, ops-coach and manual-query payloads carry fields an attacker can
influence (Suricata EVE). `AZAZEL_OLLAMA_ENDPOINT` is accepted only when every
address it names or resolves to is loopback; the request then goes to the
checked address, redirects are not followed and proxy settings are not used.
Any other endpoint is refused before a connection is made and the agent stays
in its no-model fallback, which the advisory, the metrics and one log line
show.
"""

from __future__ import annotations

import http.client
import http.server
import json
import logging
import queue
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "py"))

from azazel_edge_ai import agent  # noqa: E402

REAL_CREATE_CONNECTION = socket.create_connection


def _resolver(mapping: dict[str, list[str]]):
    calls: list[str] = []

    def resolve(host: str, port: int) -> list[str]:
        calls.append(host)
        if host not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "unknown")
        return list(mapping[host])

    resolve.calls = calls  # type: ignore[attr-defined]
    return resolve


@pytest.fixture
def no_network(monkeypatch):
    """Fail the test if anything opens a connection."""
    attempts: list[object] = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise AssertionError(f"unexpected connection {args!r}")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "connect", refuse)
    return attempts


@pytest.fixture(autouse=True)
def _fresh_log_state(monkeypatch):
    monkeypatch.setattr(agent, "_LLM_ENDPOINT_LOGGED", set())


@pytest.mark.parametrize(
    ("endpoint", "address", "port"),
    [
        ("http://127.0.0.1:11434", "127.0.0.1", 11434),
        ("http://127.0.0.1:11434/", "127.0.0.1", 11434),
        ("http://127.8.9.10:11434", "127.8.9.10", 11434),
        ("http://[::1]:11434", "::1", 11434),
        ("http://localhost:11434", "127.0.0.1", 11434),
        ("http://LOCALHOST:11434", "127.0.0.1", 11434),
        ("http://model.internal.test:11434", "127.0.0.2", 11434),
        ("https://127.0.0.1", "127.0.0.1", 443),
        ("http://127.0.0.1", "127.0.0.1", 80),
    ],
)
def test_loopback_forms_are_allowed(monkeypatch, endpoint, address, port):
    monkeypatch.setattr(
        agent,
        "_resolve_llm_host",
        _resolver({"localhost": ["127.0.0.1", "::1"], "model.internal.test": ["127.0.0.2"]}),
    )
    scheme, _name, checked, checked_port, _base = agent._check_llm_endpoint(endpoint)
    assert scheme == endpoint.split(":", 1)[0]
    assert checked == address
    assert checked_port == port


@pytest.mark.parametrize(
    ("endpoint", "reason"),
    [
        ("http://203.0.113.5:11434", "llm_endpoint_not_loopback"),
        ("http://8.8.8.8:11434", "llm_endpoint_not_loopback"),
        ("http://192.168.1.10:11434", "llm_endpoint_not_loopback"),
        ("http://10.0.0.1:11434", "llm_endpoint_not_loopback"),
        ("http://169.254.1.1:11434", "llm_endpoint_not_loopback"),
        ("http://0.0.0.0:11434", "llm_endpoint_not_loopback"),
        ("http://[2001:db8::1]:11434", "llm_endpoint_not_loopback"),
        ("http://[fe80::1]:11434", "llm_endpoint_not_loopback"),
        ("http://[::ffff:8.8.8.8]:11434", "llm_endpoint_not_loopback"),
        ("http://[::]:11434", "llm_endpoint_not_loopback"),
        ("http://ollama.example.com:11434", "llm_endpoint_not_loopback"),
        ("http://mixed.example.test:11434", "llm_endpoint_not_loopback"),
        ("http://nowhere.invalid:11434", "llm_endpoint_unresolvable"),
        ("http://user:secret@127.0.0.1:11434", "llm_endpoint_has_userinfo"),
        ("http://user@127.0.0.1:11434", "llm_endpoint_has_userinfo"),
        ("http://127.0.0.1:11434/?next=http://203.0.113.5", "llm_endpoint_has_query"),
        ("ftp://127.0.0.1:11434", "llm_endpoint_scheme_not_http"),
        ("file:///run/ollama.sock", "llm_endpoint_scheme_not_http"),
        ("127.0.0.1:11434", "llm_endpoint_scheme_not_http"),
        ("http://:11434", "llm_endpoint_no_host"),
        ("http://127.0.0.1:99999", "llm_endpoint_invalid"),
        ("", "llm_endpoint_scheme_not_http"),
    ],
)
def test_other_endpoints_are_refused_without_a_connection(monkeypatch, no_network, endpoint, reason):
    monkeypatch.setattr(
        agent,
        "_resolve_llm_host",
        _resolver({"ollama.example.com": ["93.184.216.34"], "mixed.example.test": ["127.0.0.1", "203.0.113.7"]}),
    )
    with pytest.raises(agent.LlmEndpointRejected) as err:
        agent._check_llm_endpoint(endpoint)
    assert str(err.value) == reason
    monkeypatch.setattr(agent, "LLM_ENDPOINT", endpoint)
    with pytest.raises(agent.LlmEndpointRejected):
        agent._ollama_chat({"sid": 1}, model="qwen3.5:2b")
    assert no_network == []


def test_localhost_is_checked_by_its_resolved_address(monkeypatch, no_network):
    """A changed hosts file or DNS answer for localhost does not move the request off the host."""
    monkeypatch.setattr(agent, "_resolve_llm_host", _resolver({"localhost": ["203.0.113.9"]}))
    monkeypatch.setattr(agent, "LLM_ENDPOINT", "http://localhost:11434")
    with pytest.raises(agent.LlmEndpointRejected, match="llm_endpoint_not_loopback"):
        agent._ollama_chat({"sid": 1}, model="qwen3.5:2b")
    assert no_network == []


def test_the_name_is_resolved_on_every_call(monkeypatch, no_network):
    answers = {"model.internal.test": ["127.0.0.1"]}
    resolve = _resolver(answers)
    monkeypatch.setattr(agent, "_resolve_llm_host", resolve)
    monkeypatch.setattr(agent, "LLM_ENDPOINT", "http://model.internal.test:11434")
    assert agent._llm_endpoint_target()[2] == "127.0.0.1"
    answers["model.internal.test"] = ["198.51.100.4"]
    with pytest.raises(agent.LlmEndpointRejected, match="llm_endpoint_not_loopback"):
        agent._llm_endpoint_target()
    assert resolve.calls == ["model.internal.test", "model.internal.test"]


class _Handler(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    status = 200
    location = ""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        type(self).requests.append((self.path, self.headers.get("Host", "")))
        if type(self).status != 200:
            self.send_response(type(self).status)
            self.send_header("Location", type(self).location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(
            {
                "message": {
                    "content": json.dumps(
                        {
                            "verdict": "monitor",
                            "confidence": 0.7,
                            "reason": "r",
                            "suggested_action": "a",
                            "escalation": False,
                        }
                    )
                }
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


@pytest.fixture
def local_server():
    class Handler(_Handler):
        requests: list[tuple[str, str]] = []
        status = 200
        location = ""

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, Handler
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def loopback_only_connections(monkeypatch):
    seen: list[str] = []

    def guarded(address, *args, **kwargs):
        seen.append(address[0])
        assert address[0] in {"127.0.0.1", "::1"}, address
        return REAL_CREATE_CONNECTION(address, *args, **kwargs)

    monkeypatch.setattr(socket, "create_connection", guarded)
    return seen


def test_a_loopback_endpoint_is_called(monkeypatch, local_server, loopback_only_connections):
    server, handler = local_server
    port = server.server_address[1]
    monkeypatch.setattr(agent, "_resolve_llm_host", _resolver({"model.internal.test": ["127.0.0.1"]}))
    # Proxy settings are not used for the model request.
    monkeypatch.setenv("http_proxy", "http://203.0.113.20:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://203.0.113.20:3128")
    monkeypatch.setattr(agent, "LLM_ENDPOINT", f"http://model.internal.test:{port}/base/")
    result = agent._ollama_chat({"sid": 1}, model="qwen3.5:2b")
    assert result["verdict"] == "monitor"
    assert handler.requests == [("/base/api/chat", f"127.0.0.1:{port}")]
    assert loopback_only_connections == ["127.0.0.1"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_is_not_followed(monkeypatch, local_server, loopback_only_connections, status):
    server, handler = local_server
    handler.status = status
    handler.location = "http://203.0.113.5:11434/api/chat"
    monkeypatch.setattr(agent, "LLM_ENDPOINT", f"http://127.0.0.1:{server.server_address[1]}")
    with pytest.raises(agent.LlmEndpointRejected, match="llm_endpoint_redirect_refused"):
        agent._ollama_chat({"sid": 1}, model="qwen3.5:2b")
    assert len(handler.requests) == 1
    assert loopback_only_connections == ["127.0.0.1"]


def test_the_refusal_is_logged_once_with_credentials_hidden(monkeypatch, no_network, caplog):
    monkeypatch.setattr(agent, "LLM_ENDPOINT", "http://admin:hunter2@203.0.113.5:11434/?token=abc")
    with caplog.at_level(logging.WARNING, logger="azazel-edge-ai-agent"):
        for _ in range(3):
            with pytest.raises(agent.LlmEndpointRejected):
                agent._llm_endpoint_target()
    lines = [r.getMessage() for r in caplog.records if "LLM endpoint refused" in r.getMessage()]
    assert len(lines) == 1
    assert "llm_endpoint_has_userinfo" in lines[0]
    assert "203.0.113.5:11434" in lines[0]
    assert "hunter2" not in lines[0] and "admin" not in lines[0] and "token=abc" not in lines[0]
    assert "fallback" in lines[0]


def test_the_analyst_falls_back_visibly_and_does_not_retry(monkeypatch, tmp_path, no_network):
    for name in ("ADVISORY_PATH", "SNAPSHOT_PATH", "LLM_DEFERRED_LOG_PATH", "LLM_RESULT_LOG_PATH", "METRICS_PATH", "POLICY_PATH"):
        monkeypatch.setattr(agent, name, tmp_path / f"{name.lower()}.json")
    monkeypatch.setattr(agent, "METRICS", dict(agent.METRICS))
    monkeypatch.setattr(agent, "RUNTIME_POLICY", dict(agent.RUNTIME_POLICY))
    monkeypatch.setattr(agent, "LLM_QUEUE", queue.Queue(maxsize=4))
    monkeypatch.setattr(agent, "LLM_ENABLED", True)
    monkeypatch.setattr(agent, "LLM_RETRY_MAX", 3)
    monkeypatch.setattr(agent, "OPS_COACH_ENABLED", False)
    monkeypatch.setattr(agent, "LLM_ENDPOINT", "http://198.51.100.7:11434")
    monkeypatch.setattr(agent, "LLM_RETRY_BACKOFF_SEC", 0.0)
    checks: list[int] = []
    real_target = agent._llm_endpoint_target

    def counted_target():
        checks.append(1)
        return real_target()

    monkeypatch.setattr(agent, "_llm_endpoint_target", counted_target)
    event = {
        "normalized": {
            "sid": 200002,
            "severity": 3,
            "attack_type": "port scan",
            "category": "attempted-recon",
            "action": "allowed",
            "target_port": 80,
            "protocol": "tcp",
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.1",
        }
    }
    completed_before = int(agent.METRICS.get("llm_completed", 0))
    retried_before = int(agent.METRICS.get("llm_retried", 0))
    advisory = agent._build_advisory(event)
    recommendation = advisory["recommendation"]
    task = {"event": event, "advisory": advisory.copy(), "enqueued_at": 0.0, "model": "qwen3.5:2b"}
    processed = agent._process_llm_task(task)
    assert processed["llm"]["status"] == "fallback"
    assert processed["llm"]["policy"] == "tactical_only_keep_recommendation"
    assert processed["llm"]["reason"] == "llm_endpoint_not_loopback"
    assert processed["llm"]["attempts"] == 1
    assert processed["recommendation"] == recommendation
    assert len(checks) == 1  # no retry of a refused endpoint
    metrics = json.loads(agent.METRICS_PATH.read_text(encoding="utf-8"))
    assert metrics["last_error"] == "llm_endpoint_not_loopback"
    assert int(metrics["llm_fallback_count"]) >= 1
    assert int(metrics.get("llm_completed", 0)) == completed_before
    assert int(metrics.get("llm_retried", 0)) == retried_before
    assert no_network == []


def test_the_ops_coach_and_manual_query_stop_at_the_refusal(monkeypatch, tmp_path, no_network):
    monkeypatch.setattr(agent, "LLM_RESULT_LOG_PATH", tmp_path / "ai-llm.jsonl")
    monkeypatch.setattr(agent, "METRICS", dict(agent.METRICS))
    monkeypatch.setattr(agent, "LLM_ENDPOINT", "http://ollama.example.com:11434")
    monkeypatch.setattr(agent, "_resolve_llm_host", _resolver({"ollama.example.com": ["93.184.216.34"]}))
    monkeypatch.setattr(agent, "_ops_coach_allowed", lambda: (True, "ok"))
    monkeypatch.setattr(agent, "_manual_router_response", lambda *a, **k: None)
    monkeypatch.setattr(agent, "OPS_MODEL_CHAIN", ["qwen3.5:2b", "qwen3.5:0.8b"])
    monkeypatch.setattr(agent, "MANUAL_MODEL_CHAIN", ["qwen3.5:2b", "qwen3.5:0.8b"])

    ops = agent._run_ops_coach({"risk_score": 90}, verdict="fallback", confidence=0.0, reason="x", trigger_reason="t")
    assert ops["status"] == "error"
    assert ops["errors"] == [{"model": "qwen3.5:2b", "reason": "llm_endpoint_not_loopback"}]

    manual = agent._run_manual_query("free form question", sender="op", source="webui")
    assert manual.get("status") != "completed"
    assert manual["reason"] == "all_manual_models_failed"
    assert manual["errors"] == [{"model": "qwen3.5:2b", "reason": "llm_endpoint_not_loopback"}]
    assert no_network == []


def test_the_default_endpoint_is_loopback():
    source = (ROOT / "py" / "azazel_edge_ai" / "agent.py").read_text(encoding="utf-8")
    assert 'os.environ.get("AZAZEL_OLLAMA_ENDPOINT", "http://127.0.0.1:11434")' in source
    assert agent._check_llm_endpoint("http://127.0.0.1:11434")[2] == "127.0.0.1"
    # The old unchecked call path is gone.
    assert "urllib.request" not in source
