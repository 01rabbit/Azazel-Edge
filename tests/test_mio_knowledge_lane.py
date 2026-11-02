import time
import threading

from azazel_edge_ai.mio_knowledge_lane import LiveMioKnowledgeLane
from azazel_edge_ai.mio_model_lane import LiveMioModelLane


def wait(lane):
    until = time.monotonic() + 2
    while lane.snapshot()['status'] in {'queued', 'starting'} and time.monotonic() < until:
        time.sleep(.005)
    return lane.snapshot()


def setup(query, enabled=lambda: True, max_age_seconds=1):
    state = {'generation': '1', 'trace_id': 'edge-1', 'status': 'complete', 'is_current': True,
        'advisory': {'trace_id': 'mio-1', 'frame_id': 'frame-1'}, 'source_context': {'event_key': 'event-1'}}
    frames = {'1': {'trace_id': 'mio-1', 'frame_id': 'frame-1'}}
    lane = LiveMioKnowledgeLane(enabled=enabled, query=query, fast_snapshot=lambda: dict(state),
        frame_snapshot=lambda g: frames.get(g), knowledge_input_snapshot=lambda g: {'private': g},
        project=lambda frame, response, deadline, stale: {'claim_status': 'reported_unverified'},
        max_age_seconds=max_age_seconds)
    return lane, state, frames


def test_model_disabled_knowledge_finishes_independently():
    called = []
    lane, state, frames = setup(lambda private, **kw: (called.append(private) or 'received', {}))
    model = LiveMioModelLane(enabled=False, analyze=lambda *_: None, fast_snapshot=lambda: state)
    model.submit('1', 'edge-1')
    lane.submit('1', 'edge-1')
    assert wait(lane)['is_current'] is True
    assert called == [{'private': '1'}]
    assert model.snapshot()['status'] == 'disabled'


def test_model_runs_without_knowledge_and_has_separate_status():
    lane, state, frames = setup(lambda *_a, **_k: (_ for _ in ()).throw(AssertionError()), enabled=lambda: False)
    lane.submit('1', 'edge-1')
    called = threading.Event()
    def analyze(frame, remaining):
        called.set()
        return {**frame, 'generation_method': 'model', 'mio_state': 'complete', 'outcome': 'completed'}
    model = LiveMioModelLane(enabled=True, analyze=analyze, fast_snapshot=lambda: state,
                             frame_snapshot=lambda g: frames[g])
    model.submit('1', 'edge-1')
    assert called.wait(1)
    assert wait(model)['status'] == 'complete'
    assert lane.snapshot()['status'] == 'disabled'


def test_supersession_does_not_wait_or_overwrite():
    entered, release = threading.Event(), threading.Event()
    def query(private, **kwargs):
        if private['private'] == '1':
            entered.set()
            release.wait(1)
        return 'received', {}
    lane, state, frames = setup(query)
    lane.submit('1', 'edge-1')
    assert entered.wait(1)
    state.update(generation='2', trace_id='edge-2', advisory={'frame_id': 'frame-2', 'trace_id': 'mio-2'})
    frames['2'] = {'frame_id': 'frame-2', 'trace_id': 'mio-2'}
    started = time.monotonic()
    lane.submit('2', 'edge-2')
    assert time.monotonic() - started < .1
    assert lane.snapshot()['generation'] == '2'
    release.set()
    result = wait(lane)
    assert result['is_current'] is True
    assert result['frame_id'] == 'frame-2'
    assert state['trace_id'] == 'edge-2'


def test_binding_rejected_before_query_and_expiry_hides_projection():
    calls = []
    lane, state, frames = setup(lambda *_a, **_k: (calls.append(1) or 'received', {}), max_age_seconds=.1)
    lane.submit('1', 'wrong-edge')
    assert wait(lane)['status'] == 'rejected'
    assert calls == []
    lane.submit('1', 'edge-1')
    assert wait(lane)['projection']['claim_status'] == 'reported_unverified'
    time.sleep(.12)
    assert lane.snapshot()['is_current'] is False
    assert 'projection' not in lane.snapshot()
    frames['1']['frame_id'] = 'wrong-frame'
    lane.submit('1', 'edge-1')
    assert wait(lane)['status'] == 'rejected'


def test_model_analysis_never_calls_knowledge(monkeypatch):
    from azazel_edge_ai import agent
    from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary
    aux = LiveMioAuxiliary()
    aux.submit({'normalized': {'event_type': 'alert', 'sid': 1}}, score=5, factors=[], risk_level='LOW')
    until = time.monotonic() + 2
    while aux.snapshot()['status'] in {'queued', 'starting'} and time.monotonic() < until:
        time.sleep(.005)
    monkeypatch.setattr(agent, '_query_knowledge_context', lambda *_a, **_k: (_ for _ in ()).throw(AssertionError('Knowledge crossed timelines')))
    monkeypatch.setattr(agent, '_ollama_chat', lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError('synthetic unavailable model')))
    result = agent._analyze_mio_fast_result(aux.frame_snapshot('1'), 1)
    assert 'knowledge_status' not in result


def test_deadline_and_source_event_mismatch_suppress_current_refs():
    def slow_query(*_args, **_kwargs):
        time.sleep(.12)
        return 'received', {}
    lane, state, frames = setup(slow_query, max_age_seconds=.1)
    lane.submit('1', 'edge-1')
    result = wait(lane)
    assert result['status'] == 'timeout'
    assert result['is_current'] is False
    assert 'projection' not in result
    lane, state, frames = setup(lambda *_a, **_k: ('received', {}))
    lane.submit('1', 'edge-1')
    assert wait(lane)['is_current'] is True
    state['source_context'] = {'event_key': 'other-event'}
    assert lane.snapshot()['is_current'] is False
    assert 'projection' not in lane.snapshot()
