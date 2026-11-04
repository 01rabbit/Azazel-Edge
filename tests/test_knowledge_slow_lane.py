from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import textwrap
import time

import pytest

from azazel_edge_ai.agent import _knowledge_private_input as private_input, _query_knowledge_context as query_context

# Opt-in local model lane (only used by the real-process test below). The
# endpoint is fixed: no environment variable can point the model at another host.
OLLAMA_LOOPBACK = ('127.0.0.1', 11434)
OLLAMA_ENDPOINT = 'http://127.0.0.1:11434'
OLLAMA_MODEL_PATTERN = re.compile(r'[A-Za-z0-9._:/-]{1,96}')


def _assert_ollama_model_preinstalled(model):
    """Read-only loopback check that the named model already exists locally."""
    connection = http.client.HTTPConnection(*OLLAMA_LOOPBACK, timeout=3)
    try:
        connection.request('GET', '/api/tags')
        response = connection.getresponse()
        if response.status != 200:
            pytest.fail('local Ollama on 127.0.0.1:11434 did not answer /api/tags')
        listing = json.loads(response.read(1 << 20))
    except (OSError, ValueError):
        pytest.fail('EDGE_TEST_MIO_OLLAMA=1 requires a running local Ollama on 127.0.0.1:11434')
    finally:
        connection.close()
    if not isinstance(listing, dict) or not isinstance(listing.get('models'), list):
        pytest.fail('local Ollama /api/tags response has an unexpected shape')
    names = {item.get('name') for item in listing['models'] if isinstance(item, dict)}
    if model not in names:
        pytest.fail('EDGE_TEST_OLLAMA_MODEL must name a model already installed locally; nothing is downloaded')


@contextmanager
def server(monkeypatch, status=200, body=b'{}', delay=0):
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append((self.path, json.loads(self.rfile.read(int(self.headers['Content-Length'])))))
            time.sleep(delay)
            self.send_response(status)
            self.send_header('Location', 'http://198.51.100.1/private')
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *_args):
            pass
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED', '1')
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN', 'synthetic_test_token_123')
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT', f'http://127.0.0.1:{httpd.server_port}')
    try:
        yield requests
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def query(context=None, stale=lambda: False, seconds=1):
    return query_context(context, deadline=time.monotonic() + seconds, stale_check=stale)


def test_disabled_and_missing_token_make_zero_connections(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail('disabled transport attempted a connection')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.delenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED', raising=False)
    assert query()[0] == 'disabled'
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED', '1')
    monkeypatch.delenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN', raising=False)
    assert query()[0] == 'missing_token'


@pytest.mark.parametrize('endpoint', ['http://localhost:1234', 'http://192.0.2.1:1234',
    'https://127.0.0.1:1234', 'http://127.0.0.1:1234/v1/context', 'http://user@127.0.0.1:1234'])
def test_invalid_endpoint_never_resolves_or_connects(monkeypatch, endpoint):
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED', '1')
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN', 'synthetic_test_token_123')
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT', endpoint)
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *_a, **_k: pytest.fail('DNS resolution'))
    assert query()[0] == 'invalid_configuration'


@pytest.mark.parametrize('status,body,expected', [(302,b'{}','redirect_rejected'),
    (401,b'{}','auth_rejected'), (403,b'{}','scope_rejected'),
    (200,b'x'*16385,'oversized'), (200,b'not-json','malformed'), (503,b'{}','unavailable')])
def test_transport_rejects_without_retry(monkeypatch, status, body, expected):
    with server(monkeypatch, status, body) as requests:
        assert query()[0] == expected
        assert len(requests) == 1


def test_minimal_wire_and_generation_checks(monkeypatch):
    from azazel_edge_ai.mio_live_auxiliary import _source_context
    source = _source_context({'normalized': {'event_type':'alert', 'sid':1,
        'src_ip':'203.0.113.7', 'payload':'secret', 'technique_ids':['T1059']}})
    with server(monkeypatch) as requests:
        monkeypatch.setattr(socket, 'getaddrinfo', lambda *_a, **_k: pytest.fail('numeric path attempted DNS'))
        assert query(source)[0] == 'received'
        path, wire = requests[0]
        assert path == '/v1/context'
        assert wire == {'entities': [], 'actor_key': '', 'event': {
            'kind':'alert', 'sid':1, 'technique_ids':['T1059']}}
        assert query(source, stale=lambda: True)[0] == 'superseded'
        assert len(requests) == 1
    with server(monkeypatch, delay=.1) as requests:
        assert query(source, stale=lambda: bool(requests))[0] == 'superseded'


def test_absolute_deadline(monkeypatch):
    with server(monkeypatch, delay=.5):
        started = time.monotonic()
        assert query(seconds=.08)[0] == 'timeout'
        assert time.monotonic() - started < .3


@pytest.mark.parametrize('stall_phase', ['headers', 'body'])
def test_stalled_old_transport_releases_latest_lane(monkeypatch, stall_phase):
    from azazel_edge_ai.mio_knowledge_lane import LiveMioKnowledgeLane

    entered, release, latest_requested = (threading.Event() for _ in range(3))
    requests, projected = [], []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers['Content-Length']))
            requests.append(self.path)
            first = len(requests) == 1
            if first and stall_phase == 'headers':
                entered.set()
                release.wait(3)
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            if first and stall_phase == 'body':
                self.wfile.flush()
                entered.set()
                release.wait(3)
            if not first:
                latest_requested.set()
            try:
                self.wfile.write(b'{}')
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *_args):
            pass
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED', '1')
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN', 'synthetic_test_token_123')
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT', f'http://127.0.0.1:{httpd.server_port}')
    state = {}
    frames = {g: {'trace_id': 'mio-' + g, 'frame_id': 'frame-' + g} for g in ('1', '2')}
    def select(g):
        state.update(generation=g, trace_id='edge-' + g, status='complete', is_current=True,
                     advisory=frames[g], source_context={'event_key': 'event-' + g})
    def project(frame, *_args):
        projected.append(frame['frame_id'])
        return {'claim_status': 'reported_unverified'}
    lane = LiveMioKnowledgeLane(enabled=lambda: True, query=query_context,
        fast_snapshot=lambda: dict(state), frame_snapshot=frames.get,
        knowledge_input_snapshot=lambda _g: {}, project=project, max_age_seconds=.4)
    try:
        select('1')
        lane.submit('1', 'edge-1')
        assert entered.wait(1)
        select('2')
        started = time.monotonic()
        lane.submit('2', 'edge-2')
        assert latest_requested.wait(.25)
        until = started + .35
        while lane.snapshot()['status'] == 'queued' and time.monotonic() < until:
            time.sleep(.005)
        result = lane.snapshot()
        assert result['generation'] == '2'
        assert result['status'] == 'projected'
        assert result['is_current'] is True
        assert not release.is_set()
        # Keep the old server-side I/O held beyond the latest request's deadline.
        time.sleep(max(0, started + .45 - time.monotonic()))
        assert projected == ['frame-2']
        assert lane.snapshot()['generation'] == '2'
        release.set()
        assert projected == ['frame-2']
        assert requests == ['/v1/context', '/v1/context']
    finally:
        release.set()
        httpd.shutdown()
        httpd.server_close()
        thread.join()


def test_actual_knowledge_process_and_mio18_projection(monkeypatch, tmp_path, caplog):
    """Opt-in local integration: real Uvicorn, temporary synthetic DB and keys."""
    source = os.environ.get('EDGE_TEST_KNOWLEDGE_SOURCE')
    fabric = os.environ.get('EDGE_TEST_FABRIC_SOURCE')
    if not source or not fabric:
        pytest.skip('set EDGE_TEST_KNOWLEDGE_SOURCE and EDGE_TEST_FABRIC_SOURCE to local exact exports')
    # Default-off: without EDGE_TEST_MIO_OLLAMA=1 no Ollama request is ever made.
    model_switch = os.environ.get('EDGE_TEST_MIO_OLLAMA') == '1'
    model_name = os.environ.get('EDGE_TEST_OLLAMA_MODEL', '')
    if model_switch and not OLLAMA_MODEL_PATTERN.fullmatch(model_name):
        pytest.fail('EDGE_TEST_MIO_OLLAMA=1 requires EDGE_TEST_OLLAMA_MODEL naming a preinstalled local model')
    if model_switch:
        # Fail before starting the Knowledge process or running the baselines.
        _assert_ollama_model_preinstalled(model_name)
    source = Path(source)
    monkeypatch.syspath_prepend(str(Path(fabric) / 'src'))
    monkeypatch.syspath_prepend(str(source / 'src'))
    monkeypatch.syspath_prepend(str(source / 'tests/unit'))
    spec = importlib.util.spec_from_file_location('knowledge_api_test_support', source / 'tests/unit/_api_support.py')
    support = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(support)
    add_api_client, make_intel_generation, make_local_db = (support.add_api_client,
        support.make_intel_generation, support.make_local_db)
    from azazel_edge_ai import agent
    from azazel_edge_ai.mio_live_auxiliary import _safe_event, _source_context
    from azazel_mio.assistant import AssistantCore, KnowledgeContextResponseAdvisory
    root = tmp_path / 'runtime'
    local = root / 'data/db/local.db'
    make_local_db(local)
    make_intel_generation(local.parent, 1)
    token = add_api_client(local, 'edge-synthetic-query', ['query'])
    wrong_scope = add_api_client(local, 'edge-synthetic-ingest', ['ingest'])
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    env = dict(os.environ, AZAZEL_ROOT=str(root), AZAZEL_CONFIG_DIR=str(source / 'config'),
        PYTHONPATH=os.pathsep.join([str(source / 'src'), str(Path(fabric) / 'src')]),
        PYTHONDONTWRITEBYTECODE='1')
    log = tmp_path / 'knowledge.log'
    with log.open('wb') as output:
        process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'azazel_knowledge.api.app:app',
                '--host', '127.0.0.1', '--port', str(port), '--no-access-log'],
            cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        try:
            until = time.monotonic() + 8
            while True:
                if process.poll() is not None:
                    pytest.fail('synthetic Knowledge process exited before readiness')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < until
                    time.sleep(.03)
            monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED','1')
            monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT',f'http://127.0.0.1:{port}')
            monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN','synthetic_invalid_token_123')
            assert query()[0] == 'auth_rejected'
            monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN',wrong_scope)
            assert query()[0] == 'scope_rejected'
            monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN',token)
            event = {'normalized': {'event_type':'alert','sid':1,'severity':2,'src_ip':'203.0.113.7',
                'dst_ip':'198.51.100.8','category':'scan','protocol':'http'},
                     'defense': {'action':'observe'},
                     'enforcement': {'trace_id':'trace-synthetic','mode':'dry_run','result':'planned_not_applied'}}
            source_context = private_input(event, _source_context(event))
            near = json.loads(json.dumps(source_context))
            near['entities'] = []
            near['fields']['category']['value'] = 'scan-near-miss'
            near_status, near_response = query(near)
            assert near_status == 'received'
            assert 'T1595.002' not in [x['technique'] for x in near_response['threat_context']['attack_mapping']]
            from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary
            auxiliary = LiveMioAuxiliary(knowledge_input_builder=private_input)
            submitted = auxiliary.submit(event, score=50, factors=['synthetic factor'], risk_level='MEDIUM')
            ready_by = time.monotonic() + 2
            while auxiliary.snapshot()['status'] == 'queued' and time.monotonic() < ready_by:
                time.sleep(.01)
            assert auxiliary.snapshot()['is_current'] is True
            assert '203.0.113.7' not in json.dumps(auxiliary.snapshot())
            frame = auxiliary.frame_snapshot(submitted['generation'])
            assert '203.0.113.7' not in json.dumps(frame)
            before = json.loads(json.dumps(frame))
            observed = []
            original = AssistantCore.explain
            def explain(self, *args, **kwargs):
                assert type(kwargs['knowledge_context_response']) is KnowledgeContextResponseAdvisory
                raw = kwargs['knowledge_context_response'].context_response
                assert raw['threat_context']['ioc_matches']
                assert any(item.get('sources') for item in raw['threat_context']['ioc_matches'])
                assert 'T1595.002' in [x['technique'] for x in raw['threat_context']['attack_mapping']]
                result = original(self, *args, **kwargs)
                observed.append(result.to_dict())
                return result
            monkeypatch.setattr(AssistantCore, 'explain', explain)
            monkeypatch.setattr(agent, 'MIO_MODEL_ENABLED', False)
            monkeypatch.setattr(agent,'_ollama_chat',lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError('synthetic model failure')))
            monkeypatch.setattr(agent,'_mio_model_endpoint_target',lambda: None)
            from azazel_edge_ai.mio_knowledge_lane import LiveMioKnowledgeLane
            lane = LiveMioKnowledgeLane(enabled=lambda: True, query=agent._query_knowledge_context,
                project=agent._project_mio_knowledge, fast_snapshot=auxiliary.snapshot,
                frame_snapshot=auxiliary.frame_snapshot,
                knowledge_input_snapshot=auxiliary.knowledge_input_snapshot,
                max_age_seconds=3)
            lane.submit('1', 'trace-synthetic')
            until = time.monotonic() + 4
            result = lane.snapshot()
            while result['status'] in {'queued', 'starting'} and time.monotonic() < until:
                time.sleep(.01)
                result = lane.snapshot()
            assert observed[0]['knowledge_context_response_advisory']['claim_status'] == 'reported_unverified'
            assert observed[0]['knowledge_context_response_advisory']['source_groups'] == ['abusech']
            observed_json = json.dumps(observed[0])
            assert '203.0.113.7' not in observed_json
            assert 'urlhaus' not in observed_json
            assert result['status'] == 'projected'
            assert result['is_current'] is True
            assert result['projection']['source_groups'] == ['abusech']
            assert result['projection']['claim_status'] == 'reported_unverified'
            assert frame == before
            assert frame['knowledge_refs'] == []
            assert '203.0.113.7' not in json.dumps(result) + caplog.text + log.read_text()
            assert 'urlhaus' not in json.dumps(result)
            assert token not in json.dumps(result) + caplog.text + log.read_text()

            # Exercise the production handler and its module-global lanes in
            # fresh interpreters so those worker generations cannot leak into
            # other tests. All files remain under this test's temporary root.
            handler_script = textwrap.dedent('''\
                import json, os, socket, sys, threading, time
                from pathlib import Path
                connections = []
                original_socket = socket.socket
                knowledge_port = int(os.environ['EDGE_TEST_KNOWLEDGE_PORT'])
                run_root = os.path.realpath(os.environ['EDGE_TEST_RUN_ROOT'])
                loopback_ports = {knowledge_port}
                if os.environ.get('EDGE_TEST_MIO_MODEL_RUN') == '1':
                    loopback_ports.add(11434)
                def audit_boundary(event, args):
                    # Best-effort child boundary: writes stay under this run root, stream
                    # connects use the loopback allowlist, and the child cannot spawn processes.
                    if event in {"subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.fork",
                                 "os.forkpty", "os.posix_spawn", "socket.sendto", "socket.sendmsg"}:
                        raise PermissionError('synthetic handler child may not spawn processes or send UDP')
                    if event == 'open':
                        path, mode, flags = args[0], args[1], args[2]
                        if isinstance(path, int):
                            return
                        writable = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or (
                            isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
                        if writable:
                            target = os.path.realpath(os.fsdecode(path))
                            if target != run_root and not target.startswith(run_root + os.sep):
                                raise PermissionError('synthetic test write outside its temporary tree')
                    elif event == 'socket.connect':
                        address = args[1]
                        if isinstance(address, str):
                            allowed = address == run_root or address.startswith(run_root + os.sep)
                        else:
                            allowed = (isinstance(address, tuple) and len(address) >= 2
                                       and address[0] == '127.0.0.1' and address[1] in loopback_ports)
                        if not allowed:
                            raise PermissionError('synthetic test connect outside loopback allowlist')
                sys.addaudithook(audit_boundary)
                class TrackedSocket(original_socket):
                    def _record_knowledge_attempt(self, address):
                        if (isinstance(address, tuple) and len(address) > 1 and address[1] == knowledge_port
                                and not getattr(self, '_knowledge_counted', False)):
                            self._knowledge_counted = True
                            connections.append(self)
                    def connect(self, address):
                        self._record_knowledge_attempt(address)
                        return super().connect(address)
                    def connect_ex(self, address):
                        self._record_knowledge_attempt(address)
                        return super().connect_ex(address)
                socket.socket = TrackedSocket
                from azazel_edge_ai import agent

                model_payload_checks = []
                model_payload_violations = []
                original_model_post = agent._post_to_llm_endpoint
                def check_model_payload(target, path, body, timeout_sec, deadline_monotonic=None):
                    if path != "/api/chat":
                        model_payload_violations.append("unexpected_model_path")
                        raise RuntimeError("synthetic test permits only the model chat path")
                    encoded = body.decode("utf-8", errors="strict")
                    forbidden = (
                        ("query_token", os.environ.get("AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN", "")),
                        ("source_ip", "203.0.113.7"), ("source_subnet", "203.0.113.0/24"),
                        ("destination_ip", "198.51.100.8"), ("destination_subnet", "198.51.100.0/24"),
                    )
                    for label, value in forbidden:
                        if value and value in encoded:
                            model_payload_violations.append(label)
                            raise RuntimeError("synthetic model payload redaction check failed")
                    model_payload_checks.append(path)
                    return original_model_post(target, path, body, timeout_sec,
                        deadline_monotonic=deadline_monotonic)
                agent._post_to_llm_endpoint = check_model_payload
                calls = []
                original_query = agent.LIVE_MIO_KNOWLEDGE_LANE._query
                def counted_query(*args, **kwargs):
                    calls.append(1)
                    return original_query(*args, **kwargs)
                agent.LIVE_MIO_KNOWLEDGE_LANE._query = counted_query
                agent._default_route_info = lambda: {
                    "up_if": "-", "up_ip": "-", "gateway_ip": "-", "uplink_type": "unknown"}
                stop = threading.Event()
                agent._MIO_SNAPSHOT_STOP = stop
                writer = threading.Thread(target=agent._mio_snapshot_worker, daemon=True)
                writer.start()
                event = json.loads(os.environ["EDGE_TEST_EVENT_JSON"])
                agent._handle_event(event)
                snapshot_path = agent.SNAPSHOT_PATH
                deadline = time.monotonic() + float(os.environ.get("EDGE_TEST_HANDLER_SECONDS", "6"))
                model_enabled = os.environ["AZAZEL_MIO_MODEL_ENABLED"] == "1"
                knowledge_enabled = os.environ["AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED"] == "1"
                model_terminal = {"complete", "partial", "degraded", "skipped", "disabled", "superseded"}
                snapshot = {}
                while time.monotonic() < deadline:
                    try:
                        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
                    except (FileNotFoundError, json.JSONDecodeError):
                        time.sleep(.02)
                        continue
                    mio = snapshot.get("mio_auxiliary", {})
                    knowledge = mio.get("knowledge_analysis", {})
                    model = mio.get("model_analysis", {})
                    trace_ready = mio.get("trace_id") == event["enforcement"]["trace_id"]
                    if model_enabled:
                        # The asynchronous lanes settle independently; assert their final
                        # states together without claiming an ordering between poll observations.
                        ready = (trace_ready and knowledge.get("status") == "projected"
                                 and knowledge.get("is_current") is True and model.get("status") in model_terminal)
                    elif knowledge_enabled:
                        ready = (trace_ready and knowledge.get("status") == "projected"
                                 and knowledge.get("is_current") is True)
                    else:
                        ready = (trace_ready and mio.get("status") == "complete"
                                 and knowledge.get("status") == "disabled")
                    if ready:
                        break
                    time.sleep(.02)
                else:
                    raise AssertionError("ordinary handler snapshot did not reach its expected terminal state")
                advisory = json.loads(agent.ADVISORY_PATH.read_text(encoding="utf-8"))
                stop.set()
                writer.join(timeout=2)
                assert not writer.is_alive(), "snapshot worker did not stop before test process exit"
                result = {"query_count": len(calls),
                          "knowledge_connection_count": len(connections),
                          "model_payload_check_count": len(model_payload_checks),
                          "model_payload_violations": model_payload_violations,
                          "risk_score": advisory["risk_score"],
                          "risk_level": advisory["risk_level"],
                          "recommendation": advisory["recommendation"],
                          "mio": mio, "knowledge": knowledge,
                          "advisory": advisory, "snapshot_path": str(snapshot_path)}
                print(json.dumps(result, sort_keys=True))
            ''')
            base_env = dict(os.environ,
                AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT=f'http://127.0.0.1:{port}',
                AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN=token,
                AZAZEL_LLM_ENABLED='0', AZAZEL_MIO_MODEL_ENABLED='0',
                AZAZEL_AI_METRICS_HEARTBEAT_SEC='60', PYTHONDONTWRITEBYTECODE='1',
                PYTHONPATH=os.pathsep.join(filter(None, [str(Path(__file__).resolve().parents[1] / 'py'),
                    os.environ.get('PYTHONPATH', '')])),
                EDGE_TEST_EVENT_JSON=json.dumps(event))
            base_env['EDGE_TEST_KNOWLEDGE_PORT'] = str(port)
            def run_normal_handler(enabled, trace_id, model_enabled=False):
                run_root = tmp_path / f'edge-{trace_id}'
                run_root.mkdir()
                child_env = {key: value for key, value in base_env.items() if not key.startswith('AZAZEL_')}
                child_env.update(
                    AZAZEL_ROOT=str(run_root / 'root'), AZAZEL_CONFIG_DIR=str(source / 'config'),
                    AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED='1' if enabled else '0',
                    AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENDPOINT=f'http://127.0.0.1:{port}',
                    AZAZEL_MIO_KNOWLEDGE_CONTEXT_QUERY_TOKEN=token,
                    AZAZEL_LLM_ENABLED='0', AZAZEL_MIO_MODEL_ENABLED='1' if model_enabled else '0',
                    EDGE_TEST_RUN_ROOT=str(run_root),
                    EDGE_TEST_MIO_MODEL_RUN='1' if model_enabled else '0',
                    EDGE_TEST_HANDLER_SECONDS='12' if model_enabled else '6',
                    AZAZEL_AI_ADVISORY=str(run_root / 'advisory.json'),
                    AZAZEL_AI_EVENT_LOG=str(run_root / 'events.jsonl'),
                    AZAZEL_AI_DEFERRED_LOG=str(run_root / 'deferred.jsonl'),
                    AZAZEL_AI_LLM_LOG=str(run_root / 'llm.jsonl'),
                    AZAZEL_AI_METRICS=str(run_root / 'metrics.json'),
                    AZAZEL_AI_POLICY=str(run_root / 'policy.json'),
                    AZAZEL_AI_AUDIT_LOG=str(run_root / 'audit.jsonl'),
                    AZAZEL_AI_SOCKET=str(run_root / 'ai-bridge.sock'),
                    AZAZEL_AI_QUERY_SOCKET=str(run_root / 'agent-query.sock'),
                    AZAZEL_NORMALIZED_EVENT_LOG=str(run_root / 'normalized-events.jsonl'),
                    AZAZEL_DECISION_LOG_DIR=str(run_root / 'decisions'),
                    AZAZEL_LLM_NUM_CTX='2048', AZAZEL_LLM_KEEP_ALIVE='10s',
                    AZAZEL_MIO_MODEL_TIMEOUT_SEC='8')
                run_event = json.loads(json.dumps(event))
                run_event['enforcement']['trace_id'] = trace_id
                run_event['source'] = 'suricata_eve'
                run_event['pipeline'] = 'rust_event_engine_v1'
                run_event['normalized'].update(event_id=108, sid=9901221, severity=2,
                    attack_type='Synthetic scan', category='network-scan', target_port=443,
                    protocol='TCP', action='allowed', ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
                run_event['defense']['action'] = 'notify'
                run_event['enforcement_status'] = {
                    'dry_run': True, 'enforce_enabled': False,
                    'allowed_actions': ['observe', 'notify']}
                child_env['EDGE_TEST_EVENT_JSON'] = json.dumps(run_event)
                if model_enabled:
                    # Fixed loopback Ollama target and the exact preinstalled model for both model tiers.
                    child_env.update(AZAZEL_OLLAMA_ENDPOINT=OLLAMA_ENDPOINT,
                        AZAZEL_LLM_MODEL_PRIMARY=model_name, AZAZEL_LLM_MODEL_DEGRADED=model_name)
                try:
                    completed = subprocess.run([sys.executable, '-c', handler_script], cwd=Path.cwd(),
                        env=child_env, capture_output=True, text=True, timeout=16 if model_enabled else 12)
                except subprocess.TimeoutExpired:
                    pytest.fail('ordinary handler child exceeded its 16-second model / 12-second baseline deadline')
                assert completed.returncode == 0, completed.stderr[-2000:]
                assert token not in completed.stdout + completed.stderr
                return json.loads(completed.stdout.splitlines()[-1])

            disabled = run_normal_handler(False, 'trace-normal-disabled')
            assert disabled['mio']['status'] == 'complete'
            assert disabled['knowledge']['status'] == 'disabled'
            assert disabled['knowledge'].get('projection') is None
            assert disabled['query_count'] == 0
            assert disabled['knowledge_connection_count'] == 0
            enabled = run_normal_handler(True, 'trace-normal-enabled')
            knowledge = enabled['knowledge']
            assert enabled['query_count'] == 1
            assert enabled['knowledge_connection_count'] == 1
            for baseline in (disabled, enabled):
                assert baseline['model_payload_check_count'] == 0
                assert baseline['mio']['model_analysis']['status'] == 'disabled'
                assert baseline['mio']['model_analysis']['reason'] == 'opt_in_off'
            assert knowledge['status'] == 'projected'
            assert knowledge['is_current'] is True
            assert knowledge['generation'] == enabled['mio']['generation']
            assert knowledge['frame_generation'] == enabled['mio']['generation']
            mio_advisory = enabled['mio'].get('advisory')
            assert isinstance(mio_advisory, dict), 'enabled MIO frame advisory is missing'
            assert mio_advisory.get('trace_id')
            assert mio_advisory.get('frame_id')
            assert knowledge['trace_id'] == mio_advisory['trace_id']
            assert knowledge['frame_id'] == mio_advisory['frame_id']
            assert knowledge['source_trace_id'] == 'trace-normal-enabled'
            assert knowledge['projection']['claim_status'] == 'reported_unverified'
            assert knowledge['source_freshness_verification'] == 'reported_unverified_at_lookup'
            assert knowledge['projection']['source_groups'] == ['abusech']
            score_fields = ('risk_score', 'risk_level', 'recommendation', 'score_factors', 'score_engine',
                            'state_name', 'user_state', 'suricata_severity', 'suricata_sid',
                            'attack_type', 'target_port')
            assert {field: enabled['advisory'].get(field) for field in score_fields} == {
                field: disabled['advisory'].get(field) for field in score_fields}
            comparison_fields = ('schema_version', 'authority', 'status', 'edge_score', 'mio_score',
                                 'matches', 'mio_factors')
            assert {field: enabled['advisory']['mio_score_comparison'].get(field) for field in comparison_fields} == {
                field: disabled['advisory']['mio_score_comparison'].get(field) for field in comparison_fields}
            # Edge's own second-pass SOC display may retain an entity; the shared
            # MIO envelope and Knowledge projection must not expose those values.
            assert '203.0.113.7' not in json.dumps(enabled['mio'])
            assert '198.51.100.8' not in json.dumps(enabled['mio'])
            assert 'urlhaus' not in json.dumps(enabled['knowledge'])
            assert token not in json.dumps(enabled['mio']) + json.dumps(enabled['advisory'])
            run_root = tmp_path / 'edge-trace-normal-enabled'
            assert Path(enabled['snapshot_path']) == run_root / 'ai_snapshot.json'
            required_artifacts = ('advisory.json', 'events.jsonl', 'ai_snapshot.json')
            for filename in required_artifacts:
                assert (run_root / filename).is_file()
            optional_artifacts = ('metrics.json', 'policy.json', 'audit.jsonl', 'deferred.jsonl', 'llm.jsonl',
                                  'core-decision-audit.jsonl', 'decision-explanations.jsonl')
            for filename in required_artifacts + optional_artifacts:
                path = run_root / filename
                if filename in required_artifacts or path.exists():
                    captured = path.read_text(encoding='utf-8')
                    assert token not in captured
                    assert 'urlhaus' not in captured

            if model_switch:
                # Opt-in only: the model lane makes loopback Ollama requests for synthetic input.
                modeled = run_normal_handler(True, 'trace-normal-model', model_enabled=True)
                assert modeled['query_count'] == 1
                assert modeled['knowledge_connection_count'] == 1
                model_state = modeled['mio'].get('model_analysis', {})
                assert modeled['model_payload_violations'] == []
                assert modeled['model_payload_check_count'] == model_state.get('request_count') >= 1, {
                    'edge_risk_score': modeled.get('risk_score'),
                    'model_state': {key: model_state.get(key) for key in ('status', 'reason', 'mio_state',
                        'generation_method', 'outcome', 'request_count', 'is_current',
                        'fast_generation', 'frame_generation')}}
                modeled_knowledge = modeled['knowledge']
                assert modeled_knowledge['status'] == 'projected'
                assert modeled_knowledge['is_current'] is True
                assert modeled_knowledge['generation'] == modeled['mio']['generation']
                assert modeled_knowledge['projection']['claim_status'] == 'reported_unverified'
                model_result = modeled['mio']['model_analysis']
                assert model_result['status'] == 'complete', model_result.get('reason')
                assert model_result['mio_state'] == 'complete'
                assert model_result['usage_status'] == 'complete'
                assert model_result['truncated_count'] == 0
                assert model_result['request_count'] >= 1
                assert model_result['metered_request_count'] == model_result['request_count']
                assert model_result['model'] == model_name
                assert model_result['prompt_tokens'] > 0
                assert model_result['completion_tokens'] > 0
                assert model_result['duration_ms'] > 0
                assert model_result['is_current'] is True
                edge_handoff = modeled['advisory'].get('mio_auxiliary')
                assert isinstance(edge_handoff, dict), 'Edge-to-MIO handoff is missing from the persisted advisory'
                assert edge_handoff['generation'] == modeled['mio']['generation']
                assert edge_handoff['trace_id'] == 'trace-normal-model'
                assert modeled['mio']['trace_id'] == edge_handoff['trace_id']
                assert modeled_knowledge['source_trace_id'] == edge_handoff['trace_id']
                handoff_binding = modeled['mio'].get('handoff_binding')
                assert isinstance(handoff_binding, dict) and handoff_binding.get('valid') is True
                assert handoff_binding['edge_trace_id'] == edge_handoff['trace_id']
                assert model_result['fast_generation'] == edge_handoff['generation']
                assert model_result['frame_generation'] == edge_handoff['generation']
                modeled_advisory = modeled['mio'].get('advisory')
                assert isinstance(modeled_advisory, dict), 'model-enabled MIO frame advisory is missing'
                assert model_result['frame_id'] == modeled_advisory['frame_id']
                assert model_result['frame_trace_id'] == modeled_advisory['trace_id']
                assert model_result['trace_id'] == model_result['frame_trace_id']
                assert handoff_binding['mio_trace_id'] == model_result['frame_trace_id']
                assert handoff_binding['frame_id'] == model_result['frame_id']
                assert {field: modeled['advisory'].get(field) for field in score_fields} == {
                    field: disabled['advisory'].get(field) for field in score_fields}
                assert {field: modeled['advisory']['mio_score_comparison'].get(field) for field in comparison_fields} == {
                    field: disabled['advisory']['mio_score_comparison'].get(field) for field in comparison_fields}
                assert '203.0.113.7' not in json.dumps(modeled['mio'])
                assert '198.51.100.8' not in json.dumps(modeled['mio'])
                assert 'urlhaus' not in json.dumps(modeled['knowledge']) + json.dumps(model_result)
                assert token not in json.dumps(modeled['mio']) + json.dumps(modeled['advisory'])
                model_run_root = tmp_path / 'edge-trace-normal-model'
                for filename in required_artifacts + optional_artifacts:
                    path = model_run_root / filename
                    if filename in required_artifacts or path.exists():
                        captured = path.read_text(encoding='utf-8')
                        assert token not in captured
                        assert 'urlhaus' not in captured
        finally:
            process.send_signal(2)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def test_model_failure_preserves_only_bounded_knowledge_status():
    from azazel_edge_ai.mio_model_lane import MioModelFailure
    assert MioModelFailure('model_error', {'knowledge_status':'projected'}).metrics['knowledge_status'] == 'projected'
    assert MioModelFailure('model_error', {'knowledge_status':'private facts'}).metrics['knowledge_status'] == 'unavailable'


def test_private_indicators_and_exact_alert_semantics(monkeypatch):
    from azazel_edge_ai.mio_live_auxiliary import _source_context
    event = {'normalized': {'event_type':'alert', 'src_ip':'203.0.113.7', 'dst_ip':'2001:db8::1',
                            'dest_ip':'192.0.2.99', 'category':'scan', 'protocol':'http', 'target_port':443}}
    source = _source_context(event)
    monkeypatch.delenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED', raising=False)
    assert private_input(event, source) is None
    with server(monkeypatch) as requests:
        private = private_input(event, source)
        assert query(private)[0] == 'received'
        wire = requests[0][1]
        assert wire['entities'] == [{'type':'ip','value':'203.0.113.7'}, {'type':'ip','value':'2001:db8::1'}]
        assert wire['event']['alert'] == {'category':'scan', 'proto':'http'}
        assert '203.0.113.7' not in json.dumps(source)
        event['normalized'].update(category='scan-near-miss', protocol='TCP', dst_ip='bad-ip', src_ip='host.example')
        assert query(private_input(event, _source_context(event)))[0] == 'received'
        assert requests[1][1]['entities'] == []
        assert requests[1][1]['event']['alert'] == {'category':'scan-near-miss','proto':'TCP'}
        assert requests[1][1]['event']['alert']['proto'] != 'https'


def test_private_input_is_current_only_and_not_retained_when_disabled(monkeypatch):
    from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary
    auxiliary = LiveMioAuxiliary(knowledge_input_builder=private_input)
    event = {'normalized':{'event_type':'alert','sid':1,'src_ip':'203.0.113.7'},
             'defense':{'action':'observe'}}
    monkeypatch.setenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED','1')
    first = auxiliary.submit(event, score=50, factors=[], risk_level='MEDIUM')
    assert auxiliary.knowledge_input_snapshot(first['generation'])['entities'] == [{'type':'ip','value':'203.0.113.7'}]
    assert '203.0.113.7' not in json.dumps(auxiliary.snapshot())
    monkeypatch.delenv('AZAZEL_MIO_KNOWLEDGE_CONTEXT_ENABLED')
    second = auxiliary.submit(event, score=50, factors=[], risk_level='MEDIUM')
    assert auxiliary.knowledge_input_snapshot(first['generation']) is None
    assert auxiliary.knowledge_input_snapshot(second['generation']) is None


def _lane_fixture(max_age=.4, **overrides):
    from azazel_edge_ai.mio_knowledge_lane import LiveMioKnowledgeLane
    state = {'generation': '1', 'trace_id': 'edge-1', 'status': 'complete', 'is_current': True,
             'advisory': {'trace_id': 'mio-1', 'frame_id': 'frame-1'},
             'source_context': {'event_key': 'event-1'}}
    live = {'generation': '1', 'enabled': True}
    seen = {}
    def query(_input, *, deadline, stale_check):
        seen['remaining'] = deadline - time.monotonic()
        return 'received', {}
    kwargs = dict(enabled=lambda: live['enabled'], query=query,
        fast_snapshot=lambda: json.loads(json.dumps(state)),
        frame_snapshot=lambda g: {'trace_id': 'mio-1', 'frame_id': 'frame-1'},
        knowledge_input_snapshot=lambda _g: {},
        project=lambda *_a: {'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only',
                             'attack_techniques': ['T1059'], 'source_groups': ['abusech']},
        max_age_seconds=max_age, current_generation=lambda: live['generation'])
    kwargs.update(overrides)
    return LiveMioKnowledgeLane(**kwargs), state, live, seen


def _wait_done(lane, timeout=1.0):
    until = time.monotonic() + timeout
    while lane.snapshot()['status'] in {'starting', 'queued'} and time.monotonic() < until:
        time.sleep(.005)
    return lane.snapshot()


def test_query_deadline_starts_after_frame_capture_not_at_queue_time():
    lane, state, _live, seen = _lane_fixture(max_age=1.2)
    state['status'] = 'pending'
    threading.Timer(.75, lambda: state.update(status='complete')).start()
    lane.submit('1', 'edge-1')
    result = _wait_done(lane)
    assert result['status'] == 'projected'
    # A queue-anchored deadline would leave about .45 s; the query keeps its own full window.
    assert seen['remaining'] > 1.0


def test_fast_frame_wait_itself_remains_bounded():
    lane, state, _live, seen = _lane_fixture(max_age=.2)
    state['status'] = 'pending'
    lane.submit('1', 'edge-1')
    assert _wait_done(lane)['status'] == 'timeout'
    assert 'remaining' not in seen


def test_expired_fast_frame_keeps_same_event_last_report_with_age_and_not_current():
    lane, state, _live, _seen = _lane_fixture()
    lane.submit('1', 'edge-1')
    assert _wait_done(lane)['is_current'] is True
    state['is_current'] = False
    time.sleep(.02)
    report = lane.snapshot()
    assert report['is_current'] is False and report['report_state'] == 'last_report'
    assert report['report_age_seconds'] > 0
    assert report['projection']['attack_techniques'] == ['T1059']
    assert report['source_freshness_verification'] == 'reported_unverified_at_lookup'


def test_last_report_expires_at_the_independent_knowledge_deadline():
    lane, state, _live, _seen = _lane_fixture(max_age=.8)
    lane.submit('1', 'edge-1')
    assert _wait_done(lane)['is_current'] is True
    state['is_current'] = False
    time.sleep(1.0)
    report = lane.snapshot()
    assert report['is_current'] is False
    assert 'report_state' not in report and 'projection' not in report


@pytest.mark.parametrize('change', ['generation', 'event', 'trace', 'mio_trace', 'frame', 'disabled', 'resubmit'])
def test_historical_report_is_suppressed_on_new_generation_event_mismatch_or_revocation(change):
    lane, state, live, _seen = _lane_fixture()
    lane.submit('1', 'edge-1')
    assert _wait_done(lane)['status'] == 'projected'
    state['is_current'] = False
    if change == 'generation':
        live['generation'] = '2'
    elif change == 'event':
        state['source_context'] = {'event_key': 'event-2'}
    elif change == 'trace':
        state['trace_id'] = 'edge-2'
    elif change == 'mio_trace':
        state['advisory']['trace_id'] = 'mio-2'
    elif change == 'frame':
        state['advisory']['frame_id'] = 'frame-2'
    elif change == 'disabled':
        live['enabled'] = False
    else:
        lane.submit('2', 'edge-2')
    result = lane.snapshot()
    assert 'projection' not in result and 'report_state' not in result
    assert result['is_current'] is False
