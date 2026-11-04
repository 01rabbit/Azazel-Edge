from copy import deepcopy
from datetime import datetime, timezone
import time

import pytest

from azazel_edge_ai.mio_live_auxiliary import _binding_matches, binding_matches_same_envelope
from azazel_edge_web.knowledge_receipt import operator_mio_payload


def current():
    return {'status': 'complete', 'is_current': True, 'generation': '1',
        'completed_at': datetime.fromtimestamp(100, timezone.utc).isoformat(),
        'max_age_seconds': 10, 'trace_id': 'edge-1',
        'source_context': {'event_key': 'a1b2c3d4e5f60718293a4b5c'},
        'advisory': {'trace_id': 'mio-1', 'frame_id': 'frame-1'},
        'edge_event': {'action': 'notify', 'mode': 'dry_run',
            'result': 'planned_not_applied', 'trace_id': 'edge-1'},
        'handoff_binding': {'status': 'matched', 'valid': True, 'generation': '1',
            'event_key': 'a1b2c3d4e5f60718293a4b5c', 'edge_trace_id': 'edge-1', 'edge_action': 'notify',
            'edge_mode': 'dry_run', 'edge_result': 'planned_not_applied',
            'mio_trace_id': 'mio-1', 'frame_id': 'frame-1'},
        'model_analysis': {'status': 'disabled'},
        'knowledge_analysis': {'schema_version': 'azazel.mio_knowledge_analysis.v1',
            'authority': 'read_only_advisory', 'usage_status': 'not_applicable',
            'status': 'projected', 'is_current': True, 'generation': '1',
            'frame_generation': '1', 'source_trace_id': 'edge-1', 'trace_id': 'mio-1',
            'frame_id': 'frame-1', 'event_key': 'a1b2c3d4e5f60718293a4b5c',
            'projection': {'claim_status': 'reported_unverified',
                'trust': 'unverified_advisory_only', 'attack_techniques': ['T1059.001'],
                'source_groups': ['abusech'], 'source_freshness': {'oldest_feed_days': 14.5, 'attack_version': '18.1'},
                'summary': 'untrusted prose',
                'action': 'isolate', 'url': 'https://untrusted.invalid'},
            'source_freshness_verification': 'reported_unverified_at_lookup'}}


def test_public_same_envelope_binding_helper_retains_private_compatibility_alias():
    payload = current()
    assert binding_matches_same_envelope(payload) is True
    assert _binding_matches(payload) is True


def test_current_receipt_only_exposes_reference_metadata_without_changing_action_or_model():
    payload = current()
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert payload == original
    receipt = output.pop('knowledge_analysis')
    assert receipt == {'status': 'projected', 'is_current': True,
        'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only',
        'generation': '1', 'frame_generation': '1', 'source_trace_id': 'edge-1',
        'event_key': 'a1b2c3d4e5f60718293a4b5c', 'trace_id': 'mio-1', 'frame_id': 'frame-1',
        'attack_techniques': ['T1059.001'], 'source_groups': ['abusech'],
        'source_freshness': {'status': 'reported_unverified_at_lookup', 'oldest_feed_days': 14.5, 'attack_version': '18.1'}}
    original.pop('knowledge_analysis')
    assert output == original  # All decision, action, fast and model fields unchanged.


def test_current_dashboard_projection_drops_unrecognized_top_level_and_nested_fields():
    payload = current()
    payload['private_payload'] = 'TOP_SECRET_SHOULD_NOT_ESCAPE'
    payload['advisory'].update(summary='bounded explanation', private_prompt='TOP_SECRET_SHOULD_NOT_ESCAPE',
        hypotheses=[{'statement': 'Check the source event.', 'private_note': 'TOP_SECRET_SHOULD_NOT_ESCAPE'}],
        handoff={'summary': 'Confirm with the operator.', 'credentials': 'TOP_SECRET_SHOULD_NOT_ESCAPE'})
    payload['source_context']['fields'] = {'event_type': {'value': 'alert', 'status': 'observed',
        'provenance': 'rust_core_normalized_event', 'address': 'TOP_SECRET_SHOULD_NOT_ESCAPE'}}
    payload['handoff_binding']['private_token'] = 'TOP_SECRET_SHOULD_NOT_ESCAPE'
    payload['edge_event']['private_reason'] = 'TOP_SECRET_SHOULD_NOT_ESCAPE'
    payload['model_analysis'] = {'schema_version': 'azazel.mio_model_analysis.v1',
        'status': 'complete', 'is_current': True, 'fast_generation': '1',
        'frame_id': 'frame-1', 'trace_id': 'mio-1',
        'summary': 'Bounded analysis.', 'model': 'qwen3.5:0.8b', 'duration_ms': 12,
        'prompt_tokens': 100, 'completion_tokens': 25,
        'request_body': 'TOP_SECRET_SHOULD_NOT_ESCAPE'}
    payload['edge_knowledge_advisory'] = {'schema_version': 'azazel.edge_knowledge_advisory.v1',
        'status': 'complete', 'authority': 'read_only_advisory', 'claim_status': 'reported_unverified',
        'generation': '1', 'trace_id': 'edge-1', 'source_groups': ['abusech'],
        'attack_techniques': ['T1059.001'],
        'source_freshness': {'oldest_feed_days': 14, 'attack_version': '18.1',
            'credential': 'TOP_SECRET_SHOULD_NOT_ESCAPE'},
        'raw_response': 'TOP_SECRET_SHOULD_NOT_ESCAPE'}
    result = operator_mio_payload(payload, now=101)

    assert 'private_payload' not in result
    assert result['advisory']['summary'] == 'bounded explanation'
    assert result['advisory']['hypotheses'] == [{'statement': 'Check the source event.'}]
    assert result['advisory']['handoff'] == {'summary': 'Confirm with the operator.'}
    assert result['source_context']['fields']['event_type'] == {
        'value': 'alert', 'status': 'observed', 'provenance': 'rust_core_normalized_event'}
    assert 'private_token' not in result['handoff_binding']
    assert result['edge_event']['unknown_fields'] is True
    assert result['model_analysis'] == {'schema_version': 'azazel.mio_model_analysis.v1',
        'status': 'complete', 'is_current': True, 'fast_generation': '1',
        'frame_id': 'frame-1', 'trace_id': 'mio-1',
        'summary': 'Bounded analysis.', 'model': 'qwen3.5:0.8b', 'duration_ms': 12,
        'prompt_tokens': 100, 'completion_tokens': 25}
    assert result['edge_knowledge_advisory']['source_freshness'] == {
        'oldest_feed_days': 14, 'attack_version': '18.1'}
    assert 'raw_response' not in result['edge_knowledge_advisory']
    assert 'TOP_SECRET_SHOULD_NOT_ESCAPE' not in repr(result)


def test_private_looking_correlation_value_is_not_reemitted_as_generation():
    payload = current()
    value = 'PRIVATE TOKEN SHOULD NOT ESCAPE'
    payload['generation'] = value
    payload['handoff_binding']['generation'] = value
    payload['knowledge_analysis']['generation'] = value
    payload['knowledge_analysis']['frame_generation'] = value

    result = operator_mio_payload(payload, now=101)

    assert result['knowledge_analysis'] == lane_status_only('projected')
    assert 'generation' not in result
    assert value not in repr(result)


@pytest.mark.parametrize(('field', 'value'), [
    ('status', []), ('status', {}), ('provenance', []), ('provenance', {}),
])
def test_malformed_source_context_metadata_is_omitted_without_failing_dashboard_projection(field, value):
    payload = current()
    item = {'value': 'alert', 'status': 'observed',
        'provenance': 'rust_core_normalized_event'}
    item[field] = value
    payload['source_context']['fields'] = {'event_type': item}

    result = operator_mio_payload(payload, now=101)

    assert result['knowledge_analysis']['status'] == 'projected'
    assert 'event_type' not in result['source_context']['fields']


def test_oversized_integer_age_fields_are_omitted_without_dashboard_exception():
    huge = 10 ** 10000

    envelope = current()
    envelope['max_age_seconds'] = huge
    assert operator_mio_payload(envelope, now=101)['knowledge_analysis'] == status_only('projected')

    knowledge = current()
    knowledge['knowledge_analysis']['projection']['source_freshness']['oldest_feed_days'] = huge
    assert operator_mio_payload(knowledge, now=101)['knowledge_analysis']['source_freshness'] == {
        'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}

    sidecar = current()
    sidecar['edge_knowledge_advisory'] = {'schema_version': 'azazel.edge_knowledge_advisory.v1',
        'status': 'complete', 'authority': 'read_only_advisory', 'claim_status': 'reported_unverified',
        'generation': '1', 'trace_id': 'edge-1', 'source_groups': ['abusech'],
        'attack_techniques': ['T1059.001'], 'source_freshness': {
            'oldest_feed_days': huge, 'attack_version': '18.1'}}
    result = operator_mio_payload(sidecar, now=101)
    assert 'source_freshness' not in result['edge_knowledge_advisory']


BINDING_KEYS = ('generation', 'frame_generation', 'source_trace_id', 'event_key', 'trace_id', 'frame_id')


def status_only(status):
    return {'status': status, 'is_current': False,
        'source_freshness': {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}}


def lane_status_only(status):
    return {'status': status, 'is_current': False}


@pytest.mark.parametrize('key', BINDING_KEYS)
def test_projected_receipt_requires_every_binding_field(key):
    payload = current()
    del payload['knowledge_analysis'][key]
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == lane_status_only('projected')


@pytest.mark.parametrize('key', BINDING_KEYS)
@pytest.mark.parametrize('value', ['', 'x' * 97, 1, None])
def test_binding_field_must_be_bounded_nonempty_string(key, value):
    payload = current()
    payload['knowledge_analysis'][key] = value
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == lane_status_only('projected')


def test_binding_fields_at_96_chars_are_projected_with_valid_event_key():
    value = 'y' * 96
    event_key = 'a1b2c3d4e5f60718293a4b5c'
    payload = current()
    payload['generation'] = payload['trace_id'] = value
    payload['edge_event']['trace_id'] = value
    payload['handoff_binding'].update(generation=value, edge_trace_id=value,
        mio_trace_id=value, frame_id=value)
    payload['advisory'].update(trace_id=value, frame_id=value)
    for key in BINDING_KEYS:
        payload['knowledge_analysis'][key] = event_key if key == 'event_key' else value
    receipt = operator_mio_payload(payload, now=101)['knowledge_analysis']
    assert receipt['status'] == 'projected' and receipt['is_current'] is True
    assert {key: receipt[key] for key in BINDING_KEYS} == {
        key: event_key if key == 'event_key' else value for key in BINDING_KEYS}


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
        output = operator_mio_payload(payload)
        assert output.pop('knowledge_analysis')['status'] == 'projected'
        assert payload['status'] == 'complete' and payload['handoff_binding']['valid'] is True
        assert output['edge_event'] == {'action': 'notify', 'mode': 'dry_run',
            'result': 'planned_not_applied', 'trace_id': 'edge-1'}
        assert output['source_context']['event_key'] == payload['source_context']['event_key']
        assert output['advisory']['trace_id'] == payload['advisory']['trace_id']
        assert output['advisory']['frame_id'] == payload['advisory']['frame_id']
        assert output['handoff_binding']['valid'] is True
        assert set(output) <= {'status', 'is_current', 'generation', 'completed_at', 'max_age_seconds',
            'trace_id', 'edge_event', 'source_context', 'handoff_binding', 'advisory', 'model_analysis',
            'knowledge', 'edge_score_comparison', 'edge_knowledge_advisory'}
    finally:
        producer._queue.join()


@pytest.mark.parametrize('field', ['handoff_binding', 'edge_event'])
@pytest.mark.parametrize('value', ['absent', None, [], {}])
def test_missing_or_malformed_enclosing_handoff_retains_status_only(field, value):
    payload = current()
    if value == 'absent':
        payload.pop(field)
    else:
        payload[field] = value
    assert_status_only_without_other_changes(payload)


def assert_status_only_without_other_changes(payload):
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert payload == original
    status = original.get('knowledge_analysis', {}).get('status', 'unavailable')
    assert output['knowledge_analysis'] == {'status': status, 'is_current': False,
        'source_freshness': {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}}
    assert output['status'] == 'unavailable' and output['is_current'] is False
    edge = original.get('edge_event')
    allowed = {'action': {'observe', 'notify', 'throttle', 'redirect', 'isolate'},
        'mode': {'disabled', 'dry_run', 'policy_gated', 'release_guard_failed', 'enforced'},
        'result': {'no_disruptive_action', 'planned_not_applied', 'extended', 'already_held', 'applied', 'failed', 'uncertain'}}
    expected_edge = {}
    unknown = isinstance(edge, dict) and edge.get('unknown_fields') is True
    for key, values in allowed.items():
        value = edge.get(key) if isinstance(edge, dict) else None
        if type(value) is str and (value.lower() if key == 'action' else value) in values:
            expected_edge[key] = value.lower() if key == 'action' else value
        elif value is not None:
            unknown = True
    if unknown:
        expected_edge['unknown_fields'] = True
    assert output['edge_event'] == expected_edge
    assert set(output) == {'status', 'is_current', 'max_age_seconds', 'edge_event', 'knowledge_analysis'}


@pytest.mark.parametrize('status', ['disabled', 'timeout'])
def test_nonprojected_knowledge_status_preserves_current_fast_and_model_lanes(status):
    payload = current()
    payload['knowledge_analysis']['status'] = status
    payload['knowledge_analysis']['is_current'] = False
    output = operator_mio_payload(payload, now=101)
    assert output['knowledge_analysis'] == {'status': status, 'is_current': False}
    assert output['advisory'] == payload['advisory']
    assert output['model_analysis'] == payload['model_analysis']
    assert output['edge_event'] == payload['edge_event']
    assert output['handoff_binding'] == payload['handoff_binding']
    assert 'projection' not in output['knowledge_analysis']
    assert 'source_freshness' not in output['knowledge_analysis']


def test_missing_knowledge_receipt_preserves_current_fast_and_model_lanes():
    payload = current()
    payload.pop('knowledge_analysis')
    output = operator_mio_payload(payload, now=101)
    assert output['knowledge_analysis'] == {'status': 'unavailable', 'is_current': False}
    assert output['advisory'] == payload['advisory']
    assert output['model_analysis'] == payload['model_analysis']
    assert output['edge_event'] == payload['edge_event']
    assert 'handoff_binding' in output
    assert 'projection' not in output['knowledge_analysis'] and 'source_freshness' not in output['knowledge_analysis']


def test_current_malformed_receipt_schema_preserves_fast_and_model_lanes():
    payload = current()
    payload['knowledge_analysis']['authority'] = 'unexpected'
    output = operator_mio_payload(payload, now=101)
    assert output['knowledge_analysis'] == {'status': 'unavailable', 'is_current': False}
    assert output['advisory'] == payload['advisory'] and output['model_analysis'] == payload['model_analysis']


PROSE_KEYS = ('summary', 'hypotheses', 'next_checks', 'unknowns', 'uncertainties')


def _model_payload():
    payload = current()
    payload['model_analysis'] = {'schema_version': 'azazel.mio_model_analysis.v1',
        'status': 'complete', 'is_current': True, 'fast_generation': '1',
        'frame_id': 'frame-1', 'trace_id': 'mio-1', 'mio_state': 'complete',
        'summary': 'Bounded analysis.', 'hypotheses': [{'statement': 'Probe hypothesis'}],
        'next_checks': ['Review logs'], 'unknowns': ['Source unknown'], 'uncertainties': ['Limited'],
        'model': 'qwen3.5:0.8b', 'duration_ms': 12, 'prompt_tokens': 100, 'completion_tokens': 25,
        'request_count': 1, 'metered_request_count': 1, 'truncated_count': 0, 'usage_status': 'complete'}
    return payload


def _advance_outer_generation(payload):
    """Make the enclosing envelope generation 2 while the model result still reports generation 1."""
    payload['generation'] = '2'
    payload['handoff_binding']['generation'] = '2'
    payload['knowledge_analysis']['generation'] = '2'
    payload['knowledge_analysis']['frame_generation'] = '2'


def test_matching_model_result_keeps_prose_as_current():
    output = operator_mio_payload(_model_payload(), now=101)
    model = output['model_analysis']
    assert model['is_current'] is True
    assert model['summary'] == 'Bounded analysis.'
    assert model['hypotheses'] == [{'statement': 'Probe hypothesis'}]
    assert model['next_checks'] == ['Review logs']
    assert model['unknowns'] == ['Source unknown'] and model['uncertainties'] == ['Limited']


def test_model_result_from_older_generation_is_not_current_and_prose_is_cleared():
    payload = _model_payload()
    _advance_outer_generation(payload)  # outer N+1, model still fast_generation '1' (N)
    output = operator_mio_payload(payload, now=101)
    assert output['advisory'] == payload['advisory']  # fast lane itself stays current
    assert output['model_analysis'] == {'schema_version': 'azazel.mio_model_analysis.v1',
        'status': 'complete', 'is_current': False, 'fast_generation': '1', 'mio_state': 'complete',
        'model': 'qwen3.5:0.8b', 'duration_ms': 12, 'prompt_tokens': 100, 'completion_tokens': 25,
        'request_count': 1, 'metered_request_count': 1, 'truncated_count': 0, 'usage_status': 'complete'}
    for key in PROSE_KEYS:
        assert key not in output['model_analysis']


@pytest.mark.parametrize('key,value', [
    ('frame_id', 'frame-2'), ('trace_id', 'mio-2'), ('fast_generation', '2'),
    ('fast_generation', None), ('is_current', False), ('is_current', 'True'), ('frame_id', None)])
def test_model_result_bound_to_wrong_frame_trace_or_generation_is_not_current(key, value):
    payload = _model_payload()
    if value is None:
        payload['model_analysis'].pop(key)
    else:
        payload['model_analysis'][key] = value
    output = operator_mio_payload(payload, now=101)
    model = output['model_analysis']
    assert model['is_current'] is False
    assert model['status'] == 'complete' and model['duration_ms'] == 12
    for prose in PROSE_KEYS:
        assert prose not in model
    assert 'frame_id' not in model and 'trace_id' not in model


def test_noncurrent_model_status_cannot_reemit_unbound_prose():
    payload = current()
    payload['model_analysis'] = {'status': 'degraded', 'summary': 'unbound stale prose',
        'is_current': False, 'fast_generation': '0'}
    output = operator_mio_payload(payload, now=101)
    model = output['model_analysis']
    assert model['status'] == 'degraded' and model['is_current'] is False
    assert 'summary' not in model and model['fast_generation'] == '0'


def test_edge_fallback_uses_producer_allowlists_and_boolean_unknown_marker():
    payload = current()
    payload['handoff_binding']['valid'] = False
    payload['edge_event'].update(action='launch', mode='arbitrary', result='custom', unknown_fields='yes')
    output = operator_mio_payload(payload, now=101)
    assert output['edge_event'] == {'unknown_fields': True}


@pytest.mark.parametrize('freshness', [
    {'oldest_feed_days': None, 'attack_version': None},
    {'oldest_feed_days': 0, 'attack_version': '1'},
    {'oldest_feed_days': 36500, 'attack_version': '18.1.2'},
])
def test_source_freshness_allowlist_accepts_bounded_values(freshness):
    payload = current()
    payload['knowledge_analysis']['projection']['source_freshness'] = freshness
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['source_freshness'] == {
        'status': 'reported_unverified_at_lookup', **freshness}


@pytest.mark.parametrize('freshness', [
    {}, {'oldest_feed_days': True, 'attack_version': None},
    {'oldest_feed_days': -1, 'attack_version': None},
    {'oldest_feed_days': 36501, 'attack_version': None},
    {'oldest_feed_days': float('inf'), 'attack_version': None},
    {'oldest_feed_days': 1, 'attack_version': 'unknown'},
    {'oldest_feed_days': 1, 'attack_version': '18.1<script>'},
    {'oldest_feed_days': 1, 'attack_version': None, 'url': 'https://evil.invalid'},
])
def test_malformed_source_freshness_is_explicitly_unavailable(freshness):
    payload = current()
    payload['knowledge_analysis']['projection']['source_freshness'] = freshness
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['source_freshness'] == {
        'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}


def test_missing_freshness_verification_marker_is_unavailable():
    payload = current()
    payload['knowledge_analysis'].pop('source_freshness_verification')
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['source_freshness']['status'] == 'unavailable'


@pytest.mark.parametrize('value', [True, -0.1, 36500.1, float('nan'), float('inf')])
def test_source_freshness_rejects_nonfinite_or_out_of_range_age(value):
    payload = current()
    payload['knowledge_analysis']['projection']['source_freshness']['oldest_feed_days'] = value
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['source_freshness']['status'] == 'unavailable'


@pytest.mark.parametrize('version', ['unknown', '1.2.3.4', '1<script>', 1, True])
def test_source_freshness_rejects_unrecognized_attack_version(version):
    payload = current()
    payload['knowledge_analysis']['projection']['source_freshness']['attack_version'] = version
    assert operator_mio_payload(payload, now=101)['knowledge_analysis']['source_freshness']['status'] == 'unavailable'


@pytest.mark.parametrize('key', ['status', 'generation', 'event_key', 'edge_trace_id',
    'edge_action', 'edge_mode', 'edge_result', 'mio_trace_id', 'frame_id'])
@pytest.mark.parametrize('value', [None, 'old'])
def test_stale_or_mismatched_handoff_binding_retains_status_only(key, value):
    payload = current()
    payload['handoff_binding'][key] = value
    assert_status_only_without_other_changes(payload)


@pytest.mark.parametrize('marker', [False, None])
def test_handoff_binding_requires_explicit_true_marker(marker):
    payload = current()
    if marker is None:
        payload['handoff_binding'].pop('valid')
    else:
        payload['handoff_binding']['valid'] = marker
    assert_status_only_without_other_changes(payload)


@pytest.mark.parametrize('key', ['trace_id', 'action', 'mode', 'result'])
@pytest.mark.parametrize('value', [None, 'old'])
def test_edge_event_must_match_enclosing_handoff(key, value):
    payload = current()
    payload['edge_event'][key] = value
    assert_status_only_without_other_changes(payload)


def test_edge_event_and_handoff_trace_cannot_disagree_with_receipt_source():
    payload = current()
    payload['edge_event']['trace_id'] = 'other-edge'
    payload['handoff_binding']['edge_trace_id'] = 'other-edge'
    assert_status_only_without_other_changes(payload)


@pytest.mark.parametrize('now', [111, 99])
def test_cached_expired_or_future_receipt_retains_status_only(now):
    assert operator_mio_payload(current(), now=now)['knowledge_analysis'] == status_only('projected')


@pytest.mark.parametrize('envelope', [{'is_current': False}, {'status': 'queued'}])
def test_unusable_envelope_keeps_projected_status_not_current(envelope):
    payload = current()
    payload.update(envelope)
    output = operator_mio_payload(payload, now=101)
    assert output['knowledge_analysis'] == status_only('projected')


@pytest.mark.parametrize('key', ['generation', 'frame_generation', 'source_trace_id',
    'trace_id', 'frame_id', 'event_key'])
def test_every_stale_correlation_retains_status_only(key):
    payload = current()
    payload['knowledge_analysis'][key] = 'old'
    output = operator_mio_payload(payload, now=101)
    assert output['knowledge_analysis'] == lane_status_only('projected')
    assert 'projection' not in output['knowledge_analysis'] and 'source_freshness' not in output['knowledge_analysis']
    assert output['advisory'] == payload['advisory'] and output['model_analysis'] == payload['model_analysis']


@pytest.mark.parametrize('key,value', [('status', []), ('schema_version', 'wrong'),
    ('authority', 'execute'), ('is_current', False), ('usage_status', 'metered'),
    ('projection', {'claim_status': 'verified'}),
    ('projection', {'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only',
        'attack_techniques': ['<b>bad</b>'], 'source_groups': ['abusech']})])
def test_malformed_receipt_rejected(key, value):
    payload = current()
    payload['knowledge_analysis'][key] = value
    expected_status = 'unavailable' if key in {'status', 'schema_version', 'authority', 'usage_status'} else 'projected'
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == lane_status_only(expected_status)


def test_valid_nonresult_status_is_bounded_and_separate():
    payload = current()
    payload['knowledge_analysis']['status'] = 'disabled'
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == lane_status_only('disabled')


@pytest.mark.parametrize('completed', [None, [], {}, 'bad'])
def test_malformed_clock_retains_status_only(completed):
    payload = current()
    payload['completed_at'] = completed
    assert_status_only_without_other_changes(payload)


@pytest.mark.parametrize('completed,expected_current', [
    ('1970-01-01T00:01:40', False),
    ('1970-01-01T00:01:40Z', True),
    ('1970-01-01T09:01:40+09:00', True),
    ('not-a-timestamp', False),
])
def test_receipt_clock_requires_timezone_without_changing_other_fields(completed, expected_current):
    payload = current()
    payload['completed_at'] = completed
    original = deepcopy(payload)
    output = operator_mio_payload(payload, now=101)
    assert payload == original
    receipt = output.pop('knowledge_analysis')
    assert receipt['is_current'] is expected_current
    if not expected_current:
        assert receipt == status_only('projected')
        assert set(output) == {'status', 'is_current', 'max_age_seconds', 'edge_event'}
        assert 'handoff_binding' not in output and 'trace_id' not in output and 'advisory' not in output
        return
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
    assert output.pop('knowledge_analysis') == status_only(status)
    assert payload == original
    assert set(output) == {'status', 'is_current', 'max_age_seconds', 'edge_event'}


@pytest.mark.parametrize('field,value', [('schema_version', 'wrong'), ('authority', 'execute'),
    ('usage_status', 'metered'), ('status', 'unknown'), ('status', [])])
def test_invalid_lane_diagnostic_schema_is_unavailable_even_when_fast_queued(field, value):
    payload = current()
    payload['status'] = 'queued'
    payload['knowledge_analysis']['status'] = 'disabled'
    payload['knowledge_analysis'][field] = value
    assert operator_mio_payload(payload, now=101)['knowledge_analysis'] == status_only('unavailable')


def historical(age=4.2):
    """Fast frame expired; the lane kept its same-event last report."""
    payload = current()
    payload['is_current'] = False
    receipt = payload['knowledge_analysis']
    receipt.update(is_current=False, report_state='last_report', report_age_seconds=age, max_age_seconds=10,
        report_expires_at_ms=int((time.time() + 10 - age) * 1000))
    return payload


def test_expired_fast_envelope_shows_only_labelled_same_event_last_report():
    payload = historical()
    expected_expires_at = payload['knowledge_analysis']['report_expires_at_ms']
    output = operator_mio_payload(payload, now=500)
    assert output['knowledge_analysis'] == {'status': 'projected', 'is_current': False,
        'report_state': 'last_report', 'claim_status': 'reported_unverified',
        'trust': 'unverified_advisory_only', 'attack_techniques': ['T1059.001'], 'source_groups': ['abusech'],
        'report_age_seconds': 4.2,
        'max_age_seconds': 10,
        'report_expires_at_ms': expected_expires_at,
        'source_freshness': {'status': 'reported_unverified_at_lookup', 'oldest_feed_days': 14.5, 'attack_version': '18.1'}}
    assert set(output) == {'status', 'is_current', 'max_age_seconds', 'edge_event', 'knowledge_analysis'}
    assert output['is_current'] is False


@pytest.mark.parametrize('mutate', [
    lambda p: p['knowledge_analysis'].update(generation='2'),
    lambda p: p['knowledge_analysis'].update(event_key='b' * 24),
    lambda p: p['knowledge_analysis'].update(source_trace_id='edge-9'),
    lambda p: p['knowledge_analysis'].update(frame_id='frame-9'),
    lambda p: p['knowledge_analysis'].update(trace_id='mio-9'),
    lambda p: p['handoff_binding'].update(valid=False),
    lambda p: p['handoff_binding'].update(frame_id='frame-9'),
    lambda p: p['knowledge_analysis'].update(report_state='current'),
    lambda p: p['knowledge_analysis'].update(is_current=True),
    lambda p: p['knowledge_analysis'].pop('report_age_seconds'),
    lambda p: p['knowledge_analysis'].update(report_age_seconds=True),
    lambda p: p['knowledge_analysis'].update(report_age_seconds=-1),
    lambda p: p['knowledge_analysis'].update(report_age_seconds=float('inf')),
    lambda p: p['knowledge_analysis'].update(report_age_seconds=11),
    lambda p: p['knowledge_analysis'].update(max_age_seconds=0),
    lambda p: p['knowledge_analysis'].update(report_expires_at_ms=int(time.time() * 1000) - 1),
    lambda p: p['knowledge_analysis']['projection'].update(trust='trusted'),
    lambda p: p['knowledge_analysis']['projection'].update(attack_techniques=['<script>']),
    lambda p: p.update(status='queued'),
])
def test_last_report_mismatch_or_malformed_value_suppresses_old_refs(mutate):
    payload = historical()
    mutate(payload)
    receipt = operator_mio_payload(payload, now=500)['knowledge_analysis']
    assert receipt['is_current'] is False
    assert 'attack_techniques' not in receipt and 'report_age_seconds' not in receipt


def test_explicit_empty_unknowns_is_preserved_as_none_reported():
    payload = _model_payload()
    payload['model_analysis']['unknowns'] = []
    output = operator_mio_payload(payload, now=101)
    assert output['model_analysis']['is_current'] is True
    assert output['model_analysis']['unknowns'] == []


@pytest.mark.parametrize('unknowns', [
    'not a list',                          # malformed container
    [{'statement': 'dict item'}],          # non-string item
    ['ok', 7],                             # mixed non-string item
    ['x' * 161],                           # rejected by length cap
    ['bad\x01control'],                    # rejected by safety projection
    ['ok', 'bad\x01control'],              # one rejected item drops the whole list
])
def test_malformed_or_filtered_unknowns_omit_the_key_not_empty_list(unknowns):
    payload = _model_payload()
    payload['model_analysis']['unknowns'] = unknowns
    output = operator_mio_payload(payload, now=101)
    assert output['model_analysis']['is_current'] is True
    assert 'unknowns' not in output['model_analysis']
    assert output['model_analysis']['summary'] == 'Bounded analysis.'


def test_absent_unknowns_is_omitted_not_empty_list():
    payload = _model_payload()
    del payload['model_analysis']['unknowns']
    output = operator_mio_payload(payload, now=101)
    assert 'unknowns' not in output['model_analysis']


def test_capped_unknowns_without_explicit_total_are_omitted():
    payload = _model_payload()
    payload['model_analysis']['unknowns'] = [f'gap {index}' for index in range(12)]
    payload['model_analysis'].pop('unknowns_total', None)
    output = operator_mio_payload(payload, now=101)
    assert 'unknowns' not in output['model_analysis']
    assert 'unknowns_total' not in output['model_analysis']


def test_below_cap_unknowns_without_total_and_explicit_null_total():
    payload = _model_payload()
    payload['model_analysis']['unknowns'] = [f'gap {index}' for index in range(11)]
    payload['model_analysis'].pop('unknowns_total', None)
    output = operator_mio_payload(payload, now=101)
    assert output['model_analysis']['unknowns'] == [f'gap {index}' for index in range(11)]
    assert output['model_analysis']['unknowns_total'] == 11

    payload['model_analysis']['unknowns_total'] = None
    output = operator_mio_payload(payload, now=101)
    assert 'unknowns' not in output['model_analysis']
    assert 'unknowns_total' not in output['model_analysis']
