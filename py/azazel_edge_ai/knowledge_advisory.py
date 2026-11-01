"""Optional MIO #18 receipt projection. No decision authority."""
import math
import re


def project(value, *, generation, trace_id):
    if type(value) is not dict:
        return None
    if (value.get('kind') != 'knowledge_context_response_advisory'
            or value.get('source_kind') != 'knowledge_context_response'
            or value.get('claim_status') != 'reported_unverified'
            or value.get('trust') != 'unverified_advisory_only'):
        return None
    groups = value.get('source_groups')
    techniques = value.get('attack_techniques')
    freshness = value.get('source_freshness')
    for items, cap, pattern in ((groups, 16, r'[a-z][a-z0-9_-]{0,31}'),
                                (techniques, 32, r'T\d{4}(?:\.\d{3})?')):
        if type(items) is not list or len(items) > cap or any(
                type(item) is not str or not re.fullmatch(pattern, item) for item in items):
            return None
    if type(freshness) is not dict or set(freshness) - {'oldest_feed_days', 'attack_version'}:
        return None
    days = freshness.get('oldest_feed_days')
    version = freshness.get('attack_version')
    if days is not None and (type(days) not in (int, float) or not math.isfinite(days) or not 0 <= days <= 36500):
        return None
    if version is not None and (type(version) is not str or not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){0,2}', version)):
        return None
    return {'schema_version': 'azazel.edge_knowledge_advisory.v1',
            'status': 'complete', 'authority': 'read_only_advisory',
            'generation': str(generation), 'trace_id': trace_id,
            'claim_status': 'reported_unverified', 'source_groups': list(groups),
            'attack_techniques': list(techniques), 'source_freshness': dict(freshness)}


def current(value, envelope):
    """Caller must also validate the existing handoff binding."""
    return (type(value) is dict and envelope.get('is_current') is True
            and envelope.get('status') == 'complete'
            and bool(envelope.get('trace_id'))
            and value.get('generation') == envelope.get('generation')
            and value.get('trace_id') == envelope.get('trace_id'))
