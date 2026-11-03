import time
import threading

from azazel_edge_ai.mio_knowledge_lane import LiveMioKnowledgeLane
from azazel_edge_ai.mio_model_lane import LiveMioModelLane


def bound_fast(state):
    """Return the fixture's fast envelope with its producer binding intact."""
    event_key = 'a1b2c3d4e5f60718293a4b5c'
    edge_trace = state['trace_id']
    generation = state['generation']
    frame_id = state['advisory']['frame_id']
    frame_trace = state['advisory']['trace_id']
    return {**state, 'edge_event': {'action': 'notify', 'mode': 'dry_run',
            'result': 'planned_not_applied', 'trace_id': edge_trace},
        'source_context': {'event_key': event_key},
        'handoff_binding': {'status': 'matched', 'valid': True, 'generation': generation,
            'event_key': event_key, 'edge_trace_id': edge_trace, 'edge_action': 'notify',
            'edge_mode': 'dry_run', 'edge_result': 'planned_not_applied',
            'mio_trace_id': frame_trace, 'frame_id': frame_id}}


def wait(lane):
    until = time.monotonic() + 2
    while lane.snapshot()['status'] in {'queued', 'starting'} and time.monotonic() < until:
        time.sleep(.005)
    return lane.snapshot()


def setup(query, enabled=lambda: True, max_age_seconds=1, **lane_kwargs):
    state = {'generation': '1', 'trace_id': 'edge-1', 'status': 'complete', 'is_current': True,
        'advisory': {'trace_id': 'mio-1', 'frame_id': 'frame-1'}, 'source_context': {'event_key': 'event-1'}}
    frames = {'1': {'trace_id': 'mio-1', 'frame_id': 'frame-1'}}
    lane = LiveMioKnowledgeLane(enabled=enabled, query=query, fast_snapshot=lambda: dict(state),
        frame_snapshot=lambda g: frames.get(g), knowledge_input_snapshot=lambda g: {'private': g},
        project=lambda frame, response, deadline, stale: {'claim_status': 'reported_unverified'},
        max_age_seconds=max_age_seconds, **lane_kwargs)
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
        return {**frame, 'generation_method': 'model', 'mio_state': 'complete', 'outcome': 'completed', 'truncated_count': 0}
    model = LiveMioModelLane(enabled=True, analyze=analyze, fast_snapshot=lambda: bound_fast(state),
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


def test_blocked_knowledge_query_does_not_block_fast_model_path_or_overwrite_newer_generation():
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    def query(private, **kwargs):
        if private['private'] == '1':
            entered.set()
            release.wait(5)
            finished.set()
        return 'received', {}
    lane, state, frames = setup(query)
    lane.submit('1', 'edge-1')
    assert entered.wait(5)
    assert lane.snapshot()['status'] not in {'projected', 'superseded', 'timeout'}

    def analyze(frame, remaining):
        return {**frame, 'generation_method': 'model', 'mio_state': 'complete', 'outcome': 'completed', 'truncated_count': 0}
    model = LiveMioModelLane(enabled=True, analyze=analyze, fast_snapshot=lambda: bound_fast(state),
                             frame_snapshot=lambda g: frames.get(g))
    model.submit('1', 'edge-1')
    model_result = wait(model)
    assert model_result['status'] == 'complete'
    assert model_result['is_current'] is True
    assert lane.snapshot()['status'] not in {'projected', 'superseded', 'timeout'}

    state.update(generation='2', trace_id='edge-2', advisory={'frame_id': 'frame-2', 'trace_id': 'mio-2'})
    frames['2'] = {'frame_id': 'frame-2', 'trace_id': 'mio-2'}
    lane.submit('2', 'edge-2')
    release.set()
    assert finished.wait(5)
    result = wait(lane)
    assert result['generation'] == '2'
    assert result['status'] == 'projected'
    assert result['is_current'] is True
    assert result['frame_id'] == 'frame-2'
    assert result['source_trace_id'] == 'edge-2'


def test_repeated_stale_checks_use_generation_callback_without_full_snapshot():
    generation, snapshots, observed = {'value': 1}, [], {}
    def query(private, stale_check, **kwargs):
        before = len(snapshots)
        observed['fresh'] = [stale_check() for _ in range(500)]
        observed['snapshot_calls'] = len(snapshots) - before
        generation['value'] = 2
        observed['superseded'] = stale_check()
        return 'received', {}
    lane, state, frames = setup(query, current_generation=lambda: generation['value'])
    # fast_snapshot still reports generation '1'; only the scalar callback can observe the supersession.
    lane._fast_snapshot = lambda: (snapshots.append(1), dict(state))[1]
    lane.submit('1', 'edge-1')
    result = wait(lane)
    assert observed['fresh'] == [False] * 500
    assert observed['snapshot_calls'] == 0
    assert observed['superseded'] is True
    assert result['status'] == 'superseded'
    assert result['is_current'] is False
    assert 'projection' not in result


def test_blocking_fast_snapshot_does_not_block_submit():
    entered, release = threading.Event(), threading.Event()
    lane, state, frames = setup(lambda *_a, **_k: ('received', {}))
    def blocking_fast_snapshot():
        entered.set()
        release.wait(2)
        return dict(state)
    lane._fast_snapshot = blocking_fast_snapshot
    try:
        lane.submit('1', 'edge-1')
        assert entered.wait(1)
        started = time.monotonic()
        receipt = lane.submit('1', 'edge-1')
        assert time.monotonic() - started < .5
        assert receipt['status'] == 'queued'
        assert receipt['is_current'] is False
        assert 'projection' not in receipt
    finally:
        release.set()
    assert wait(lane)['is_current'] is True


def test_disabling_opt_in_immediately_hides_projection():
    enabled = {'value': True}
    lane, state, frames = setup(lambda *_a, **_k: ('received', {}), enabled=lambda: enabled['value'])
    lane.submit('1', 'edge-1')
    assert wait(lane)['is_current'] is True
    enabled['value'] = False
    result = lane.snapshot()
    assert result['status'] == 'disabled'
    assert result['is_current'] is False
    assert 'projection' not in result


def test_disabling_during_inflight_snapshot_hides_copied_projection():
    enabled = threading.Event()
    enabled.set()
    lane, state, frames = setup(lambda *_a, **_k: ('received', {}), enabled=enabled.is_set)
    lane.submit('1', 'edge-1')
    projected = wait(lane)
    assert projected['status'] == 'projected'
    assert projected['is_current'] is True
    assert 'projection' in projected
    entered, release = threading.Event(), threading.Event()
    results = []

    def blocking_fast_snapshot():
        entered.set()
        assert release.wait(2)
        return dict(state)

    lane._fast_snapshot = blocking_fast_snapshot
    reader = threading.Thread(target=lambda: results.append(lane.snapshot()))
    reader.start()
    try:
        assert entered.wait(1)
        enabled.clear()
    finally:
        release.set()
        reader.join(2)
    assert not reader.is_alive()
    assert len(results) == 1
    assert results[0]['status'] == 'disabled'
    assert results[0]['generation'] == '1'
    assert results[0]['is_current'] is False
    assert 'projection' not in results[0]


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
