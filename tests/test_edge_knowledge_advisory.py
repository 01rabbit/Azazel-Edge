import threading
import time

import pytest

from azazel_edge_ai.knowledge_advisory import project
from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary


def receipt():
    return dict(kind='knowledge_context_response_advisory', source_kind='knowledge_context_response',
                claim_status='reported_unverified', trust='unverified_advisory_only',
                source_groups=['abusech'], attack_techniques=['T1059.001'],
                source_freshness={'oldest_feed_days': 2, 'attack_version': '16.1'},
                recommendation='never expose', raw_ioc='203.0.113.1', provenance={'token': 'secret'})


def test_allowlist_copies_only_bounded_projection():
    out = project(receipt(), generation=1, trace_id='t1')
    assert set(out) == {'schema_version', 'status', 'authority', 'generation', 'trace_id',
                        'claim_status', 'source_groups', 'attack_techniques', 'source_freshness'}
    assert out['source_groups'] == ['abusech']
    assert out['schema_version'] == 'azazel.edge_knowledge_advisory.v1'


@pytest.mark.parametrize('key,value', [('source_groups', ['raw.example.com']), ('source_groups', ['x'] * 17),
    ('attack_techniques', ['bad']), ('source_freshness', {'oldest_feed_days': True}),
    ('source_freshness', {'oldest_feed_days': float('nan')}),
    ('source_freshness', {'token': 'secret'}), ('claim_status', 'verified')])
def test_reject_malformed(key, value):
    data = receipt()
    data[key] = value
    assert project(data, generation=1, trace_id='t1') is None


@pytest.mark.parametrize('status,age,generation,trace', [
    ('complete', 0, 1, 't1'), ('complete', 20, 1, 't1'),
    ('complete', 0, 2, 't1'), ('complete', 0, 1, 'wrong'),
    ('unavailable', 0, 1, 't1'), ('degraded', 0, 1, 't1')])
def test_snapshot_requires_current_binding(status, age, generation, trace):
    adapter = LiveMioAuxiliary.__new__(LiveMioAuxiliary)
    adapter._lock = threading.Lock()
    adapter._generation = 1
    adapter.max_age_seconds = 10
    adapter._result_completed_monotonic = time.monotonic() - age
    adapter._result_completed_at = '2026-11-02T00:00:00Z'
    adapter._result = dict(status=status, generation='1', trace_id='t1',
        edge_event=dict(trace_id='t1', action='notify', mode='dry_run', result='planned_not_applied'),
        source_context={'event_key': 'e1'}, advisory={'trace_id': 'm1', 'frame_id': 'f1'},
        handoff_binding=dict(status='matched', generation='1', event_key='e1', edge_trace_id='t1',
            edge_action='notify', edge_mode='dry_run', edge_result='planned_not_applied',
            mio_trace_id='m1', frame_id='f1'),
        edge_knowledge_advisory=project(receipt(), generation=generation, trace_id=trace))
    out = adapter.snapshot()
    assert ('edge_knowledge_advisory' in out) == (status == 'complete' and age == 0 and generation == 1 and trace == 't1')
    adapter._result.pop('edge_knowledge_advisory')
    assert 'edge_knowledge_advisory' not in adapter.snapshot()


def test_omission():
    assert project(None, generation=1, trace_id='t1') is None


@pytest.mark.parametrize("delay", [0, .12])
def test_worker_projects_receipt_and_strips_original(monkeypatch, delay):
    from types import SimpleNamespace
    from azazel_mio.assistant import AssistantCore
    original = AssistantCore.explain

    def explain(self, *args, **kwargs):
        out = original(self, *args, **kwargs).to_dict()
        time.sleep(delay)
        out['knowledge_context_response_advisory'] = receipt()
        return SimpleNamespace(to_dict=lambda: out)

    monkeypatch.setattr(AssistantCore, 'explain', explain)
    adapter = LiveMioAuxiliary(max_age_seconds=.1 if delay else 10)
    adapter.submit({'normalized': {'event_type': 'alert', 'sid': 42},
                    'defense': {'action': 'notify'},
                    'enforcement': {'trace_id': 't1', 'mode': 'dry_run', 'result': 'planned_not_applied'}},
                   score=30, factors=[], risk_level='LOW')
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        out = adapter.snapshot()
        if out.get('status') in {'complete', 'degraded'}:
            break
        time.sleep(.01)
    if delay:
        assert out['reason'] == 'stale_job'
        assert 'edge_knowledge_advisory' not in out
        return
    assert out['edge_knowledge_advisory']['source_groups'] == ['abusech']
    assert 'knowledge_context_response_advisory' not in out['advisory']
    assert 'never expose' not in str(out)
