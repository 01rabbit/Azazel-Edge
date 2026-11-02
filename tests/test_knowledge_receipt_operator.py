from copy import deepcopy
from datetime import datetime, timezone

import pytest

from azazel_edge_web.knowledge_receipt import operator_mio_payload


def current():
    return {'status': 'complete', 'is_current': True, 'generation': '1',
        'completed_at': datetime.fromtimestamp(100, timezone.utc).isoformat(),
        'max_age_seconds': 10, 'trace_id': 'edge-1',
        'source_context': {'event_key': 'event-1'},
        'advisory': {'trace_id': 'mio-1', 'frame_id': 'frame-1'},
        'edge_event': {'action': 'notify', 'result': 'planned_not_applied'},
        'model_analysis': {'status': 'disabled'},
        'knowledge_analysis': {'schema_version': 'azazel.mio_knowledge_analysis.v1',
            'authority': 'read_only_advisory', 'usage_status': 'not_applicable',
            'status': 'projected', 'is_current': True, 'generation': '1',
            'frame_generation': '1', 'source_trace_id': 'edge-1', 'trace_id': 'mio-1',
            'frame_id': 'frame-1', 'event_key': 'event-1',
            'projection': {'claim_status': 'reported_unverified',
                'trust': 'unverified_advisory_only', 'attack_techniques': ['T1059.001'],
                'source_groups': ['abusech'], 'summary': 'untrusted prose',
                'action': 'isolate', 'url': 'https://untrusted.invalid'}}}


def test_current_receipt_only_exposes_reference_metadata_without_changing_action_or_model():
    payload = current()
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert payload == original
    receipt = output.pop('knowledge_analysis')
    assert receipt == {'status': 'projected', 'is_current': True,
        'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only',
        'attack_techniques': ['T1059.001'], 'source_groups': ['abusech']}
    original.pop('knowledge_analysis')
    assert output == original  # All decision, action, fast and model fields unchanged.


@pytest.mark.parametrize('now', [111, 99])
def test_cached_expired_or_future_receipt_is_unavailable(now):
    assert operator_mio_payload(current(), now=now)['knowledge_analysis'] == {
        'status': 'unavailable', 'is_current': False}


@pytest.mark.parametrize('key', ['generation', 'frame_generation', 'source_trace_id',
    'trace_id', 'frame_id', 'event_key'])
def test_every_stale_correlation_is_unavailable(key):
    payload = current()
    payload['knowledge_analysis'][key] = 'old'
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['status'] == 'unavailable'


@pytest.mark.parametrize('key,value', [('status', []), ('schema_version', 'wrong'),
    ('authority', 'execute'), ('is_current', False), ('usage_status', 'metered'),
    ('projection', {'claim_status': 'verified'}),
    ('projection', {'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only',
        'attack_techniques': ['<b>bad</b>'], 'source_groups': ['abusech']})])
def test_malformed_receipt_rejected(key, value):
    payload = current()
    payload['knowledge_analysis'][key] = value
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['status'] == 'unavailable'


def test_valid_nonresult_status_is_bounded_and_separate():
    payload = current()
    payload['knowledge_analysis']['status'] = 'disabled'
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == {
        'status': 'disabled', 'is_current': False}


@pytest.mark.parametrize('completed', [None, [], {}, 'bad'])
def test_malformed_clock_is_unavailable(completed):
    payload = current()
    payload['completed_at'] = completed
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['status'] == 'unavailable'
