from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from azazel_edge_ai.agent import _knowledge_private_input as private_input, _query_knowledge_context as query_context


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


def test_actual_knowledge_process_and_mio18_projection(monkeypatch, tmp_path, caplog):
    """Opt-in local integration: real Uvicorn, temporary synthetic DB and keys."""
    source = os.environ.get('EDGE_TEST_KNOWLEDGE_SOURCE')
    fabric = os.environ.get('EDGE_TEST_FABRIC_SOURCE')
    if not source or not fabric:
        pytest.skip('set EDGE_TEST_KNOWLEDGE_SOURCE and EDGE_TEST_FABRIC_SOURCE to local exact exports')
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
            monkeypatch.setattr(agent,'_ollama_chat',lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError('synthetic model failure')))
            monkeypatch.setattr(agent,'_mio_model_endpoint_target',lambda: None)
            from azazel_edge_ai.mio_model_lane import LiveMioModelLane
            audits = []
            authorized = []
            monkeypatch.setattr(agent, '_audit_mio_model_result', lambda trace, result: audits.append(result))
            lane = LiveMioModelLane(enabled=True, analyze=agent._governed_mio_model_analyze,
                fast_snapshot=auxiliary.snapshot,
                frame_snapshot=auxiliary.frame_snapshot,
                knowledge_input_snapshot=auxiliary.knowledge_input_snapshot,
                authorize=lambda payload: (authorized.append(True) or True, 'synthetic_test'),
                max_age_seconds=3)
            lane.submit('1','trace-synthetic')
            until = time.monotonic() + 4
            result = lane.snapshot()
            while result['status'] in {'pending','queued','starting'} and time.monotonic() < until:
                time.sleep(.01)
                result = lane.snapshot()
            assert authorized == [True]
            assert audits and audits[0]['knowledge_status'] == 'projected' 
            assert observed[0]['knowledge_context_response_advisory']['claim_status'] == 'reported_unverified'
            assert result['knowledge_status'] == 'projected'
            assert frame == before
            assert result['status'] == 'degraded'
            assert result['outcome'] == 'degraded'
            assert frame['knowledge_refs'] == []
            assert '203.0.113.7' not in json.dumps(result) + caplog.text + log.read_text()
            assert 'urlhaus' not in json.dumps(result)
            assert '203.0.113.7' not in json.dumps(lane.diagnostics())
            assert token not in json.dumps(result) + caplog.text + log.read_text()
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
