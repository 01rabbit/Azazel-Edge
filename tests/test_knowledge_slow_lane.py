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
