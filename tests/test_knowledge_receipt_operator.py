from copy import deepcopy
from datetime import datetime, timezone
import time

import pytest

from azazel_edge_web.knowledge_receipt import operator_mio_payload


def current():
    return {'status': 'complete', 'is_current': True, 'generation': '1',
        'completed_at': datetime.fromtimestamp(100, timezone.utc).isoformat(),
        'max_age_seconds': 10, 'trace_id': 'edge-1',
        'source_context': {'event_key': 'event-1'},
        'advisory': {'trace_id': 'mio-1', 'frame_id': 'frame-1'},
        'edge_event': {'action': 'notify', 'mode': 'dry_run',
            'result': 'planned_not_applied', 'trace_id': 'edge-1'},
        'handoff_binding': {'status': 'matched', 'valid': True, 'generation': '1',
            'event_key': 'event-1', 'edge_trace_id': 'edge-1', 'edge_action': 'notify',
            'edge_mode': 'dry_run', 'edge_result': 'planned_not_applied',
            'mio_trace_id': 'mio-1', 'frame_id': 'frame-1'},
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
        'generation': '1', 'frame_generation': '1', 'source_trace_id': 'edge-1',
        'event_key': 'event-1', 'trace_id': 'mio-1', 'frame_id': 'frame-1',
        'attack_techniques': ['T1059.001'], 'source_groups': ['abusech']}
    original.pop('knowledge_analysis')
    assert output == original  # All decision, action, fast and model fields unchanged.


BINDING_KEYS = ('generation', 'frame_generation', 'source_trace_id', 'event_key', 'trace_id', 'frame_id')


@pytest.mark.parametrize('key', BINDING_KEYS)
def test_projected_receipt_requires_every_binding_field(key):
    payload = current()
    del payload['knowledge_analysis'][key]
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == {
        'status': 'unavailable', 'is_current': False}


@pytest.mark.parametrize('key', BINDING_KEYS)
@pytest.mark.parametrize('value', ['', 'x' * 97, 1, None])
def test_binding_field_must_be_bounded_nonempty_string(key, value):
    payload = current()
    payload['knowledge_analysis'][key] = value
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['status'] == 'unavailable'


def test_binding_field_at_96_chars_is_projected():
    value = 'y' * 96
    payload = current()
    payload['generation'] = payload['trace_id'] = value
    payload['source_context']['event_key'] = payload['advisory']['trace_id'] = value
    payload['advisory']['frame_id'] = value
    for key in BINDING_KEYS:
        payload['knowledge_analysis'][key] = value
    receipt = operator_mio_payload(payload, now=101)['knowledge_analysis']
    assert receipt['status'] == 'projected'
    assert {key: receipt[key] for key in BINDING_KEYS} == {key: 'y' * 96 for key in BINDING_KEYS}
def test_receipt_with_real_fast_producer_envelope_survives_typed_overlay():
    from azazel_edge_ai.mio_live_auxiliary import LiveMioAuxiliary
    from azazel_edge_control.daemon import AGENT_SNAPSHOT_VALIDATORS

    producer = LiveMioAuxiliary()
    try:
        producer.submit({'normalized': {'event_type': 'alert', 'sid': 42},
            'defense': {'action': 'notify'}, 'enforcement': {'trace_id': 'edge-1',
                'mode': 'dry_run', 'result': 'planned_not_applied'}},
            score=5, factors=[], risk_level='LOW')
        deadline = time.monotonic() + 2
        payload = producer.snapshot()
        while payload['status'] in {'queued', 'starting'} and time.monotonic() < deadline:
            time.sleep(.005)
            payload = producer.snapshot()
        assert payload['status'] == 'complete'
        assert payload['handoff_binding']['valid'] is True
        assert AGENT_SNAPSHOT_VALIDATORS['mio_auxiliary'](payload)
        receipt = current()['knowledge_analysis']
        receipt.update(generation=payload['generation'], frame_generation=payload['generation'],
            source_trace_id=payload['trace_id'], event_key=payload['source_context']['event_key'],
            trace_id=payload['advisory']['trace_id'], frame_id=payload['advisory']['frame_id'])
        payload['knowledge_analysis'] = receipt
        original = deepcopy(payload)
        output = operator_mio_payload(payload)
        assert output.pop('knowledge_analysis')['status'] == 'projected'
        assert payload == original
        original.pop('knowledge_analysis')
        assert output == original
    finally:
        producer._queue.join()


@pytest.mark.parametrize('field', ['handoff_binding', 'edge_event'])
@pytest.mark.parametrize('value', ['absent', None, [], {}])
def test_missing_or_malformed_enclosing_handoff_is_unavailable(field, value):
    payload = current()
    if value == 'absent':
        payload.pop(field)
    else:
        payload[field] = value
    assert_unavailable_without_other_changes(payload)


def assert_unavailable_without_other_changes(payload):
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert payload == original
    assert output.pop('knowledge_analysis') == {'status': 'unavailable', 'is_current': False}
    original.pop('knowledge_analysis')
    assert output == original


@pytest.mark.parametrize('key', ['status', 'generation', 'event_key', 'edge_trace_id',
    'edge_action', 'edge_mode', 'edge_result', 'mio_trace_id', 'frame_id'])
@pytest.mark.parametrize('value', [None, 'old'])
def test_stale_or_mismatched_handoff_binding_is_unavailable(key, value):
    payload = current()
    payload['handoff_binding'][key] = value
    assert_unavailable_without_other_changes(payload)


@pytest.mark.parametrize('key', ['trace_id', 'action', 'mode', 'result'])
@pytest.mark.parametrize('value', [None, 'old'])
def test_edge_event_must_match_enclosing_handoff(key, value):
    payload = current()
    payload['edge_event'][key] = value
    assert_unavailable_without_other_changes(payload)


def test_edge_event_and_handoff_trace_cannot_disagree_with_receipt_source():
    payload = current()
    payload['edge_event']['trace_id'] = 'other-edge'
    payload['handoff_binding']['edge_trace_id'] = 'other-edge'
    assert_unavailable_without_other_changes(payload)


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


@pytest.mark.parametrize('completed,expected_status', [
    ('1970-01-01T00:01:40', 'unavailable'),
    ('1970-01-01T00:01:40Z', 'projected'),
    ('1970-01-01T09:01:40+09:00', 'projected'),
    ('not-a-timestamp', 'unavailable'),
])
def test_receipt_clock_requires_timezone_without_changing_other_fields(completed, expected_status):
    payload = current()
    payload['completed_at'] = completed
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert payload == original
    assert output.pop('knowledge_analysis')['status'] == expected_status
    original.pop('knowledge_analysis')
    assert output == original  # Includes the action, fast lane and model result.


@pytest.mark.parametrize('status', ('starting queued disabled missing_token invalid_configuration '
    'unavailable timeout oversized redirect_rejected auth_rejected scope_rejected malformed '
    'received superseded rejected projected').split())
@pytest.mark.parametrize('fast_state', ['queued', 'degraded', 'stale', 'mismatched'])
def test_lane_diagnostics_survive_unusable_fast_envelope_without_reference_ids(status, fast_state):
    payload = current()
    payload['knowledge_analysis']['status'] = status
    if fast_state in {'queued', 'degraded'}:
        payload['status'] = fast_state
        payload['is_current'] = False
        payload.pop('completed_at')
    elif fast_state == 'stale':
        payload['completed_at'] = datetime.fromtimestamp(1, timezone.utc).isoformat()
    else:
        payload['handoff_binding']['frame_id'] = 'wrong-frame'
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert output.pop('knowledge_analysis') == {
        'status': 'unavailable' if status == 'projected' else status, 'is_current': False}
    assert payload == original
    original.pop('knowledge_analysis')
    assert output == original


@pytest.mark.parametrize('field,value', [('schema_version', 'wrong'), ('authority', 'execute'),
    ('usage_status', 'metered'), ('status', 'unknown'), ('status', [])])
def test_invalid_lane_diagnostic_schema_is_unavailable_even_when_fast_queued(field, value):
    payload = current()
    payload['status'] = 'queued'
    payload['knowledge_analysis']['status'] = 'disabled'
    payload['knowledge_analysis'][field] = value
    assert_unavailable_without_other_changes(payload)
