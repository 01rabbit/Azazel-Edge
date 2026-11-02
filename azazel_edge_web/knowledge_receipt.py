"""Read-only display projection; never use Knowledge metadata as control input."""
from datetime import datetime, timezone
import math
import re

from azazel_edge_ai.mio_live_auxiliary import binding_matches_same_envelope, edge_observation_for_display

_STATUSES = frozenset(('starting queued disabled missing_token invalid_configuration unavailable timeout '
    'oversized redirect_rejected auth_rejected scope_rejected malformed received superseded projected rejected').split())
_SOURCE_FRESHNESS_VERIFICATION = 'reported_unverified_at_lookup'
_ATTACK_VERSION = re.compile(r'[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}')
_SAFE_DISPLAY_TEXT = re.compile(r'[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]*')
_SAFE_SOURCE_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._:/+()\[\]-]{0,95}')
_SAFE_TRACE_ID = re.compile(r'[A-Za-z0-9._:-]{1,96}')
_SAFE_GENERATION = re.compile(r'[A-Za-z0-9._:-]{1,96}')
_SOURCE_FIELDS = frozenset(('event_type', 'attack_type', 'category', 'protocol', 'ts',
    'sid', 'severity', 'target_port', 'technique_ids', 'normalized_outcome'))


def _text(value, limit):
    return value if (type(value) is str and len(value) <= limit
        and _SAFE_DISPLAY_TEXT.fullmatch(value) is not None) else None


def _text_list(value, *, count, length):
    if type(value) is not list or len(value) > count:
        return []
    return [item for item in value if _text(item, length) is not None]


def _display_source_context(value):
    """Project the event correlation fields used by the dashboard, not the raw mapping."""
    if type(value) is not dict:
        return None
    event_key = value.get('event_key')
    if type(event_key) is not str or (event_key and re.fullmatch(r'[a-f0-9]{24}', event_key) is None):
        return None
    raw_fields = value.get('fields')
    fields = {}
    if type(raw_fields) is dict:
        for name in _SOURCE_FIELDS:
            item = raw_fields.get(name)
            if type(item) is not dict:
                continue
            status = item.get('status')
            provenance = item.get('provenance')
            if status not in {'observed', 'unavailable'} or provenance != 'rust_core_normalized_event':
                continue
            raw = item.get('value')
            if name == 'technique_ids':
                safe = [x for x in raw[:16] if type(x) is str and re.fullmatch(r'T[0-9]{4}(?:\.[0-9]{3})?', x)] if type(raw) is list else []
                fields[name] = {'value': safe, 'status': status, 'provenance': provenance}
            elif raw is None:
                fields[name] = {'value': None, 'status': status, 'provenance': provenance}
            elif (name == 'sid' and type(raw) is int and 1 <= raw <= 2**31 - 1) or (
                    name == 'severity' and type(raw) is int and 0 <= raw <= 10) or (
                    name == 'target_port' and type(raw) is int and 1 <= raw <= 65535):
                fields[name] = {'value': raw, 'status': status, 'provenance': provenance}
            elif name == 'ts' and type(raw) is str and len(raw) <= 32 and re.fullmatch(r'[0-9TtZz:+.\-]+', raw):
                fields[name] = {'value': raw, 'status': status, 'provenance': provenance}
            elif name == 'protocol' and type(raw) is str and len(raw) <= 16 and re.fullmatch(r'[A-Za-z0-9._:/+()\-]*', raw):
                fields[name] = {'value': raw, 'status': status, 'provenance': provenance}
            elif name in {'event_type', 'attack_type', 'category', 'protocol'}:
                limit = {'event_type': 32, 'attack_type': 96, 'category': 64, 'protocol': 16}[name]
                if (type(raw) is str and len(raw) <= limit and _SAFE_SOURCE_LABEL.fullmatch(raw)
                        and raw.strip().lower() != 'unknown'):
                    fields[name] = {'value': raw, 'status': status, 'provenance': provenance}
            elif name == 'normalized_outcome' and type(raw) is str and raw in {'allowed', 'blocked', 'drop', 'rejected'}:
                fields[name] = {'value': raw, 'status': status, 'provenance': provenance}
    result = {'event_key': event_key}
    if 'fields' in value:
        result['fields'] = fields
    return result


def _display_handoff(value):
    if type(value) is not dict:
        return None
    result = {}
    for key, limit in (('summary', 480), ('operator_note', 480), ('status', 64)):
        text = _text(value.get(key), limit)
        if text is not None:
            result[key] = text
    checks = value.get('check_next')
    if type(checks) is list:
        result['check_next'] = _text_list(checks, count=4, length=200)
    return result


def _display_advisory(value):
    """Allow only the fixed Assistance fields consumed by the operator panel."""
    if type(value) is not dict:
        return None
    result = {}
    for key, limit in (('schema_version', 48), ('trace_id', 96), ('frame_id', 96), ('summary', 480),
            ('generation_method', 32), ('state', 48), ('cycle_disposition', 32)):
        text = _text(value.get(key), limit)
        if key in {'trace_id', 'frame_id'} and type(text) is str and _SAFE_TRACE_ID.fullmatch(text):
            result[key] = text
        elif key not in {'trace_id', 'frame_id'} and text is not None:
            result[key] = text
    for key in ('recommendation',):
        item = value.get(key)
        if type(item) is str:
            text = _text(item, 480)
            if text is not None:
                result[key] = text
        elif type(item) is dict:
            projected = {name: text for name, limit in (('summary', 480), ('recommended_action', 240))
                         if (text := _text(item.get(name), limit)) is not None}
            if projected:
                result[key] = projected
    if 'handoff' in value:
        handoff = _display_handoff(value.get('handoff'))
        if handoff is not None:
            result['handoff'] = handoff
    for key, limit, size in (('hypotheses', 4, 360), ('unknowns', 12, 160),
            ('observations', 16, 480), ('next_checks', 4, 200)):
        raw = value.get(key)
        if type(raw) is list:
            items = []
            for item in raw[:limit]:
                if type(item) is str:
                    text = _text(item, size)
                    if text is not None:
                        items.append(text)
                elif key == 'hypotheses' and type(item) is dict:
                    text = _text(item.get('statement'), size)
                    if text is not None:
                        items.append({'statement': text})
            result[key] = items
    return result


def _display_model(value):
    if type(value) is not dict:
        return None
    result = {}
    text_fields = {'schema_version': 48, 'status': 24,
        'summary': 480, 'mio_state': 48, 'model': 96, 'usage_status': 16,
        'outcome': 32, 'generation_method': 32, 'validation_rejection': 48,
        'frame_id': 96, 'trace_id': 96, 'reason': 64}
    for key, limit in text_fields.items():
        text = _text(value.get(key), limit)
        if text is not None:
            result[key] = text
    fast_generation = value.get('fast_generation')
    if type(fast_generation) is str and _SAFE_GENERATION.fullmatch(fast_generation):
        result['fast_generation'] = fast_generation
    if type(value.get('is_current')) is bool:
        result['is_current'] = value['is_current']
    for key, cap in (('duration_ms', 600000), ('load_duration_ms', 600000),
            ('prompt_tokens', 400000), ('completion_tokens', 400000),
            ('request_count', 4), ('metered_request_count', 4),
            ('unknown_usage_request_count', 4), ('truncated_count', 4)):
        number = value.get(key)
        if type(number) is int and 0 <= number <= cap:
            result[key] = number
    for key, count, size in (('hypotheses', 4, 360), ('next_checks', 4, 200), ('unknowns', 12, 160), ('uncertainties', 3, 100)):
        raw = value.get(key)
        if type(raw) is list:
            items = []
            for item in raw[:count]:
                text = _text(item if type(item) is str else item.get('statement') if type(item) is dict else None, size)
                if text is not None:
                    items.append({'statement': text} if key == 'hypotheses' else text)
            result[key] = items
    return result


def _display_payload(payload):
    """Top-level and nested closed projection for the browser-facing snapshot."""
    result = {}
    status = payload.get('status')
    if type(status) is str and status in {'starting', 'pending', 'complete', 'queued', 'degraded', 'unavailable'}:
        result['status'] = status
    if type(payload.get('is_current')) is bool:
        result['is_current'] = payload['is_current']
    generation = payload.get('generation')
    if type(generation) is str and _SAFE_GENERATION.fullmatch(generation):
        result['generation'] = generation
    trace = payload.get('trace_id')
    if type(trace) is str and _SAFE_TRACE_ID.fullmatch(trace):
        result['trace_id'] = trace
    completed = _text(payload.get('completed_at'), 64)
    if completed is not None:
        result['completed_at'] = completed
    age = payload.get('max_age_seconds')
    if type(age) in (int, float) and math.isfinite(age) and 0 <= age <= 10:
        result['max_age_seconds'] = age
    reason = payload.get('reason')
    if type(reason) is str and (reason in {'starting', 'pending', 'queued', 'queue_full', 'package_unavailable',
            'stale_job', 'invalid_knowledge_status', 'result_too_large'} or
            re.fullmatch(r'mio_failure:[A-Za-z0-9_]{1,48}', reason)):
        result['reason'] = reason
    if 'edge_event' in payload:
        edge = edge_observation_for_display(payload.get('edge_event'))
        raw_edge = payload.get('edge_event')
        if type(raw_edge) is dict:
            trace = raw_edge.get('trace_id')
            if type(trace) is str and re.fullmatch(r'[A-Za-z0-9._:-]{1,96}', trace):
                edge['trace_id'] = trace
        result['edge_event'] = edge
    if 'source_context' in payload:
        context = _display_source_context(payload.get('source_context'))
        if context is not None:
            result['source_context'] = context
    if 'handoff_binding' in payload:
        raw_binding = payload.get('handoff_binding')
        if type(raw_binding) is dict:
            binding = {}
            if raw_binding.get('status') == 'matched':
                binding['status'] = 'matched'
            if type(raw_binding.get('valid')) is bool:
                binding['valid'] = raw_binding['valid']
            if type(raw_binding.get('generation')) is str and _SAFE_GENERATION.fullmatch(raw_binding['generation']):
                binding['generation'] = raw_binding['generation']
            if type(raw_binding.get('event_key')) is str and re.fullmatch(r'[a-f0-9]{24}', raw_binding['event_key']):
                binding['event_key'] = raw_binding['event_key']
            for key in ('edge_trace_id', 'mio_trace_id', 'frame_id'):
                value = raw_binding.get(key)
                if type(value) is str and _SAFE_TRACE_ID.fullmatch(value):
                    binding[key] = value
            if type(raw_binding.get('edge_action')) is str and raw_binding['edge_action'] in {'observe', 'notify', 'throttle', 'redirect', 'isolate'}:
                binding['edge_action'] = raw_binding['edge_action']
            if type(raw_binding.get('edge_mode')) is str and raw_binding['edge_mode'] in {'disabled', 'dry_run', 'policy_gated', 'release_guard_failed', 'enforced'}:
                binding['edge_mode'] = raw_binding['edge_mode']
            if type(raw_binding.get('edge_result')) is str and raw_binding['edge_result'] in {'no_disruptive_action', 'planned_not_applied', 'extended',
                    'already_held', 'applied', 'failed', 'uncertain'}:
                binding['edge_result'] = raw_binding['edge_result']
            result['handoff_binding'] = binding
    for key, project in (('advisory', _display_advisory), ('model_analysis', _display_model)):
        if key in payload:
            value = project(payload.get(key))
            if value is not None:
                result[key] = value
    if 'knowledge' in payload:
        raw = payload.get('knowledge')
        if type(raw) is dict and _text(raw.get('status'), 32) is not None:
            result['knowledge'] = {'status': raw['status']}
    comparison = payload.get('edge_score_comparison')
    if type(comparison) is dict:
        projected = {}
        for key, limit in (('schema_version', 48), ('status', 24), ('authority', 32)):
            text = _text(comparison.get(key), limit)
            if text is not None:
                projected[key] = text
        for key, pattern in (('generation', _SAFE_GENERATION), ('trace_id', _SAFE_TRACE_ID)):
            value = comparison.get(key)
            if type(value) is str and pattern.fullmatch(value):
                projected[key] = value
        for key in ('edge_score', 'mio_score'):
            value = comparison.get(key)
            if type(value) is int and 0 <= value <= 100:
                projected[key] = value
        if type(comparison.get('matches')) is bool:
            projected['matches'] = comparison['matches']
        if projected:
            result['edge_score_comparison'] = projected
    receipt = payload.get('edge_knowledge_advisory')
    if type(receipt) is dict:
        projected = {}
        for key, limit in (('schema_version', 48), ('status', 24), ('authority', 32),
                ('claim_status', 32), ('trust', 32)):
            text = _text(receipt.get(key), limit)
            if text is not None:
                projected[key] = text
        for key, pattern in (('generation', _SAFE_GENERATION), ('trace_id', _SAFE_TRACE_ID)):
            value = receipt.get(key)
            if type(value) is str and pattern.fullmatch(value):
                projected[key] = value
        for key, pattern, maximum in (('source_groups', r'[a-z][a-z0-9_-]{0,31}', 16),
                ('attack_techniques', r'T[0-9]{4}(?:\.[0-9]{3})?', 32)):
            raw = receipt.get(key)
            if type(raw) is list and len(raw) <= maximum and all(
                    type(item) is str and re.fullmatch(pattern, item) for item in raw):
                projected[key] = list(raw)
        freshness = receipt.get('source_freshness')
        if type(freshness) is dict and {'oldest_feed_days', 'attack_version'} <= set(freshness):
            age, version = freshness.get('oldest_feed_days'), freshness.get('attack_version')
            if ((age is None or type(age) in (int, float) and math.isfinite(age) and 0 <= age <= 36500)
                    and (version is None or type(version) is str and _ATTACK_VERSION.fullmatch(version))
                    and {'oldest_feed_days', 'attack_version'} <= set(freshness)):
                projected['source_freshness'] = {'oldest_feed_days': age, 'attack_version': version}
        if projected:
            result['edge_knowledge_advisory'] = projected
    return result


def _status_only_payload(payload, status):
    """Return a browser-safe lane status and observed Edge action/result only."""
    observed = edge_observation_for_display(payload.get('edge_event'))
    safe_status = status if type(status) is str and status in _STATUSES else 'unavailable'
    return {'status': 'unavailable', 'is_current': False, 'max_age_seconds': 0,
        'edge_event': observed,
        'knowledge_analysis': {'status': safe_status, 'is_current': False,
            'source_freshness': {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}}}


def _source_freshness(projection, receipt):
    """Project only the fixed, explicitly unverified lookup-freshness fields."""
    value = projection.get('source_freshness')
    if (not isinstance(value, dict) or set(value) - {'oldest_feed_days', 'attack_version'}
            or receipt.get('source_freshness_verification') != _SOURCE_FRESHNESS_VERIFICATION):
        return {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}
    age = value.get('oldest_feed_days')
    if age is not None and (type(age) not in (int, float) or not math.isfinite(age) or not 0 <= age <= 36500):
        return {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}
    version = value.get('attack_version')
    if version is not None and (type(version) is not str or _ATTACK_VERSION.fullmatch(version) is None):
        return {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}
    if set(value) != {'oldest_feed_days', 'attack_version'}:
        return {'status': 'unavailable', 'oldest_feed_days': None, 'attack_version': None}
    return {'status': _SOURCE_FRESHNESS_VERIFICATION, 'oldest_feed_days': age, 'attack_version': version}


def _fresh_bound_fast_envelope(payload, *, now=None):
    """Whether the fast Edge/M.I.O. envelope itself is current and producer-bound."""
    if payload.get('status') != 'complete' or payload.get('is_current') is not True:
        return False
    try:
        completed_at = datetime.fromisoformat(payload['completed_at'].replace('Z', '+00:00'))
        if completed_at.utcoffset() is None:
            return False
        age = (datetime.now(timezone.utc).timestamp() if now is None else now) - completed_at.timestamp()
        limit = payload['max_age_seconds']
        if type(limit) not in (int, float) or not math.isfinite(limit) or not 0 < limit <= 10 or not 0 <= age <= limit:
            return False
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        return False
    binding = payload.get('handoff_binding')
    return isinstance(binding, dict) and binding.get('valid') is True and binding_matches_same_envelope(payload)


def operator_mio_payload(payload, *, now=None):
    """Expose a current allowlisted projection or a status-only safe envelope.

    The fast completion deadline is deliberately conservative: Knowledge completes
    after that frame, so its own ten-second lifetime cannot end earlier. Unbound,
    stale, or malformed envelopes retain only fixed lane status and bounded Edge
    action/result fields; correlation and advisory data are removed.
    """
    if not isinstance(payload, dict):
        return {}
    # Outer fast-lane validity is independent of whether a Knowledge receipt
    # exists or is valid. Preserve those live fields for valid outer envelopes.
    outer_current = _fresh_bound_fast_envelope(payload, now=now)
    output = _display_payload(payload) if outer_current else _status_only_payload(payload, 'unavailable')
    def knowledge_status_only(status):
        projected = {'status': status, 'is_current': False}
        output['knowledge_analysis'] = projected
        return output

    receipt = payload.get('knowledge_analysis')
    if not isinstance(receipt, dict):
        return knowledge_status_only('unavailable') if outer_current else output
    if (receipt.get('schema_version') != 'azazel.mio_knowledge_analysis.v1'
            or receipt.get('authority') != 'read_only_advisory'
            or receipt.get('usage_status') != 'not_applicable'
            or type(receipt.get('status')) is not str
            or receipt['status'] not in _STATUSES):
        return knowledge_status_only('unavailable') if outer_current else output
    # Lane diagnostics do not assert that reference metadata is current.
    if outer_current:
        output = _display_payload(payload)
    else:
        output = _status_only_payload(payload, receipt['status'])
    if receipt['status'] != 'projected':
        if outer_current:
            output['knowledge_analysis'] = {'status': receipt['status'], 'is_current': False}
        return output
    if not outer_current:
        return output
    if receipt.get('generation') != payload.get('generation'):
        return knowledge_status_only('projected')
    # Use the producer's same-envelope contract, including the observed Edge
    # action/result and both frame IDs; a receipt alone cannot establish it.
    binding = payload.get('handoff_binding')
    # The producer marks a successful same-envelope binding explicitly. An
    # absent or false marker must never be inferred as current from matching IDs.
    if not isinstance(binding, dict) or binding.get('valid') is not True or not binding_matches_same_envelope(payload):
        return knowledge_status_only('projected')
    advisory = payload.get('advisory') or {}
    context = payload.get('source_context') or {}
    if not isinstance(advisory, dict) or not isinstance(context, dict):
        return knowledge_status_only('projected')
    bindings = ((receipt.get('generation'), payload.get('generation')),
        (receipt.get('frame_generation'), payload.get('generation')),
        (receipt.get('source_trace_id'), payload.get('trace_id')),
        (receipt.get('event_key'), context.get('event_key')),
        (receipt.get('trace_id'), advisory.get('trace_id')),
        (receipt.get('frame_id'), advisory.get('frame_id')))
    if (receipt.get('is_current') is not True or any(
            type(a) is not str or not a or len(a) > 96 or a != b for a, b in bindings)
            or type(receipt.get('generation')) is not str or not _SAFE_GENERATION.fullmatch(receipt['generation'])
            or type(receipt.get('frame_generation')) is not str or not _SAFE_GENERATION.fullmatch(receipt['frame_generation'])
            or type(receipt.get('source_trace_id')) is not str or not _SAFE_TRACE_ID.fullmatch(receipt['source_trace_id'])
            or type(receipt.get('trace_id')) is not str or not _SAFE_TRACE_ID.fullmatch(receipt['trace_id'])
            or type(receipt.get('frame_id')) is not str or not _SAFE_TRACE_ID.fullmatch(receipt['frame_id'])
            or type(receipt.get('event_key')) is not str or not re.fullmatch(r'[a-f0-9]{24}', receipt['event_key'])):
        return knowledge_status_only('projected')
    projection = receipt.get('projection')
    if (not isinstance(projection, dict) or projection.get('claim_status') != 'reported_unverified'
            or projection.get('trust') != 'unverified_advisory_only'):
        return knowledge_status_only('projected')
    refs = {}
    for key, pattern in (('attack_techniques', r'T[0-9]{4}(?:\.[0-9]{3})?'),
                         ('source_groups', r'[a-z][a-z0-9_-]{0,31}')):
        values = projection.get(key)
        if (type(values) is not list or len(values) > 16 or any(
                type(v) is not str or re.fullmatch(pattern, v) is None for v in values)):
            return knowledge_status_only('projected')
        refs[key] = list(values)
    # Binding values are already proven equal to the parent envelope above; project them for browser checks.
    bound = {'generation': receipt['generation'], 'frame_generation': receipt['frame_generation'],
        'source_trace_id': receipt['source_trace_id'], 'event_key': receipt['event_key'],
        'trace_id': receipt['trace_id'], 'frame_id': receipt['frame_id']}
    freshness = _source_freshness(projection, receipt)
    output = _display_payload(payload)
    output['knowledge_analysis'] = {'status': 'projected', 'is_current': True,
        'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only', **bound, **refs,
        'source_freshness': freshness}
    return output
