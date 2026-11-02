"""Read-only display projection; never use Knowledge metadata as control input."""
from datetime import datetime, timezone
import math
import re

from azazel_edge_ai.mio_live_auxiliary import _binding_matches

_STATUSES = frozenset(('starting queued disabled missing_token invalid_configuration unavailable timeout '
    'oversized redirect_rejected auth_rejected scope_rejected malformed received superseded projected rejected').split())
_SOURCE_FRESHNESS_VERIFICATION = 'reported_unverified_at_lookup'
_ATTACK_VERSION = re.compile(r'[0-9]{1,3}(?:\.[0-9]{1,3}){0,2}')


def _status_only_payload(payload, status):
    """Return a browser-safe lane status and observed Edge action/result only."""
    edge = payload.get('edge_event')
    edge = edge if isinstance(edge, dict) else {}
    observed = {}
    for key in ('action', 'mode', 'result'):
        value = edge.get(key)
        if type(value) is str and value and len(value) <= 96:
            observed[key] = value
    if edge.get('unknown_fields') is True:
        observed['unknown_fields'] = True
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


def operator_mio_payload(payload, *, now=None):
    """Expose a current allowlisted projection or a status-only safe envelope.

    The fast completion deadline is deliberately conservative: Knowledge completes
    after that frame, so its own ten-second lifetime cannot end earlier. Unbound,
    stale, or malformed envelopes retain only fixed lane status and bounded Edge
    action/result fields; correlation and advisory data are removed.
    """
    if not isinstance(payload, dict):
        return {}
    output = _status_only_payload(payload, 'unavailable')
    receipt = payload.get('knowledge_analysis')
    if not isinstance(receipt, dict):
        return output
    if (receipt.get('schema_version') != 'azazel.mio_knowledge_analysis.v1'
            or receipt.get('authority') != 'read_only_advisory'
            or receipt.get('usage_status') != 'not_applicable'
            or type(receipt.get('status')) is not str
            or receipt['status'] not in _STATUSES):
        return output
    # Lane diagnostics do not assert that reference metadata is current.
    output = _status_only_payload(payload, receipt['status'])
    if receipt['status'] != 'projected':
        return output
    try:
        completed_at = datetime.fromisoformat(payload['completed_at'].replace('Z', '+00:00'))
        if completed_at.utcoffset() is None:
            return output
        completed = completed_at.timestamp()
        age = (datetime.now(timezone.utc).timestamp() if now is None else now) - completed
        limit = payload['max_age_seconds']
        fresh = type(limit) in (int, float) and math.isfinite(limit) and 0 < limit <= 10 and 0 <= age <= limit
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        fresh = False
    if not fresh or payload.get('is_current') is not True or payload.get('status') != 'complete':
        return output
    if receipt.get('generation') != payload.get('generation'):
        return output
    # Use the producer's same-envelope contract, including the observed Edge
    # action/result and both frame IDs; a receipt alone cannot establish it.
    binding = payload.get('handoff_binding')
    # The producer marks a successful same-envelope binding explicitly. An
    # absent or false marker must never be inferred as current from matching IDs.
    if not isinstance(binding, dict) or binding.get('valid') is not True or not _binding_matches(payload):
        return output
    advisory = payload.get('advisory') or {}
    context = payload.get('source_context') or {}
    if not isinstance(advisory, dict) or not isinstance(context, dict):
        return output
    bindings = ((receipt.get('generation'), payload.get('generation')),
        (receipt.get('frame_generation'), payload.get('generation')),
        (receipt.get('source_trace_id'), payload.get('trace_id')),
        (receipt.get('event_key'), context.get('event_key')),
        (receipt.get('trace_id'), advisory.get('trace_id')),
        (receipt.get('frame_id'), advisory.get('frame_id')))
    if receipt.get('is_current') is not True or any(
            type(a) is not str or not a or len(a) > 96 or a != b for a, b in bindings):
        return output
    projection = receipt.get('projection')
    if (not isinstance(projection, dict) or projection.get('claim_status') != 'reported_unverified'
            or projection.get('trust') != 'unverified_advisory_only'):
        return output
    refs = {}
    for key, pattern in (('attack_techniques', r'T[0-9]{4}(?:\.[0-9]{3})?'),
                         ('source_groups', r'[a-z][a-z0-9_-]{0,31}')):
        values = projection.get(key)
        if (type(values) is not list or len(values) > 16 or any(
                type(v) is not str or re.fullmatch(pattern, v) is None for v in values)):
            return output
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
