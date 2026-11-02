"""Read-only display projection; never use Knowledge metadata as control input."""
from datetime import datetime, timezone
import math
import re

from azazel_edge_ai.mio_live_auxiliary import binding_matches_same_envelope, edge_observation_for_display

_STATUSES = frozenset(('starting queued disabled missing_token invalid_configuration unavailable timeout '
    'oversized redirect_rejected auth_rejected scope_rejected malformed received superseded projected rejected').split())
_SOURCE_FRESHNESS_VERIFICATION = 'reported_unverified_at_lookup'
_ATTACK_VERSION = re.compile(r'[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}')


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
    output = dict(payload) if outer_current else _status_only_payload(payload, 'unavailable')
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
        output = dict(payload)
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
    if receipt.get('is_current') is not True or any(
            type(a) is not str or not a or len(a) > 96 or a != b for a, b in bindings):
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
    output = dict(payload)
    output['knowledge_analysis'] = {'status': 'projected', 'is_current': True,
        'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only', **bound, **refs,
        'source_freshness': freshness}
    return output
