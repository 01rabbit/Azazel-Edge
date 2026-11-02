"""Read-only display projection; never use Knowledge metadata as control input."""
from datetime import datetime, timezone
import math
import re

_STATUSES = frozenset(('starting queued disabled missing_token invalid_configuration unavailable timeout '
    'oversized redirect_rejected auth_rejected scope_rejected malformed received superseded projected rejected').split())


def operator_mio_payload(payload, *, now=None):
    """Copy the envelope, replacing its receipt with a small display allowlist.

    The fast completion deadline is deliberately conservative: Knowledge completes
    after that frame, so its own ten-second lifetime cannot end earlier.
    """
    if not isinstance(payload, dict):
        return {}
    output = dict(payload)
    unavailable = {'status': 'unavailable', 'is_current': False}
    output['knowledge_analysis'] = unavailable
    receipt = payload.get('knowledge_analysis')
    if not isinstance(receipt, dict):
        return output
    if (receipt.get('schema_version') != 'azazel.mio_knowledge_analysis.v1'
            or receipt.get('authority') != 'read_only_advisory'
            or receipt.get('usage_status') != 'not_applicable'
            or type(receipt.get('status')) is not str
            or receipt['status'] not in _STATUSES):
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
    if receipt['status'] != 'projected':
        output['knowledge_analysis'] = {'status': receipt['status'], 'is_current': False}
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
    output['knowledge_analysis'] = {'status': 'projected', 'is_current': True,
        'claim_status': 'reported_unverified', 'trust': 'unverified_advisory_only', **bound, **refs}
    return output
