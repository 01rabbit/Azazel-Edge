from __future__ import annotations

import json

from azazel_edge.mio import (
    BoundedReasoningLoop,
    CapabilityBroker,
    DEFAULT_PLAYBOOKS,
    MioHypothesis,
    MioRecommendation,
    MioSituationFrame,
    OllamaStructuredTransport,
    ReasoningState,
)
from azazel_edge.mio.grounding import GroundingValidator


def _frame() -> MioSituationFrame:
    return MioSituationFrame.build(
        frame_id='frame-real-regression',
        trace_id='trace-real-regression',
        created_at='2026-08-23T00:00:00Z',
        mission='Validate bounded local-model reasoning',
        current_defensive_state='OBSERVE',
        threat_level='AMBIGUOUS',
        evidence_refs=['ev:1', 'ev:2'],
    )


def test_ollama_transport_disables_thinking_for_structured_response(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, _limit):
            return json.dumps({'response': '{"status":"ok"}'}).encode('utf-8')

    def fake_urlopen(request, timeout):
        captured['body'] = json.loads(request.data.decode('utf-8'))
        captured['timeout'] = timeout
        return Response()

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    result = OllamaStructuredTransport(models=('qwen3.5:2b',))('test', 'return json')

    assert result == {'status': 'ok'}
    assert captured['body']['think'] is False
    assert captured['body']['format'] == 'json'


def test_hypothesis_rejects_same_ref_as_supporting_and_contradicting():
    hypothesis = MioHypothesis.from_mapping(
        {
            'hypothesis_id': 'h1',
            'statement': 'ambiguous activity',
            'supporting_evidence_refs': ['ev:1'],
            'contradicting_evidence_refs': ['ev:1'],
        },
        ordinal=1,
    )
    result = GroundingValidator(_frame()).validate_hypotheses((hypothesis,))
    assert not result.ok
    assert 'conflicting_hypothesis_evidence_ref:h1:ev:1' in result.errors


def _recommendation(**overrides) -> MioRecommendation:
    payload = {
        'summary': 'Evidence does not justify escalation.',
        'recommended_action': 'OBSERVE',
        'rationale': 'Current evidence remains ambiguous and bounded observation is safest.',
        'evidence_refs': ['ev:1'],
        'limitations': ['Further evidence may change the assessment.'],
    }
    payload.update(overrides)
    return MioRecommendation.from_mapping(payload, advisory_id='adv:1')


def test_recommendation_requires_nonempty_summary():
    result = GroundingValidator(_frame()).validate_recommendation(_recommendation(summary='   '))
    assert 'empty_recommendation_summary' in result.errors


def test_recommendation_requires_nonempty_rationale():
    result = GroundingValidator(_frame()).validate_recommendation(_recommendation(rationale=''))
    assert 'empty_recommendation_rationale' in result.errors


def test_recommendation_requires_explicit_action():
    result = GroundingValidator(_frame()).validate_recommendation(_recommendation(recommended_action=''))
    assert 'empty_recommended_action' in result.errors


def test_recommendation_requires_evidence_refs():
    result = GroundingValidator(_frame()).validate_recommendation(_recommendation(evidence_refs=[]))
    assert 'empty_recommendation_evidence_refs' in result.errors


def test_empty_model_recommendation_ends_validation_rejected_not_complete():
    def model(task, _prompt):
        if task == 'generate_hypotheses':
            return {
                'hypotheses': [
                    {
                        'hypothesis_id': 'h1',
                        'statement': 'bounded hypothesis',
                        'supporting_evidence_refs': ['ev:1'],
                        'contradicting_evidence_refs': [],
                    }
                ]
            }
        if task == 'identify_evidence_gaps':
            return {'evidence_gaps': []}
        if task == 'recommend':
            return {
                'summary': '',
                'recommended_action': '',
                'rationale': '',
                'evidence_refs': [],
                'limitations': [],
            }
        raise AssertionError(task)

    outcome = BoundedReasoningLoop(model=model, broker=CapabilityBroker()).run(
        frame=_frame(),
        playbook=DEFAULT_PLAYBOOKS['auth-ambiguity-v1'],
        cycle_id='empty-rec-regression',
    )

    assert outcome.state is ReasoningState.VALIDATION_REJECTED
    assert outcome.state is not ReasoningState.COMPLETE
    assert 'empty_recommendation_summary' in outcome.errors
    assert 'empty_recommendation_rationale' in outcome.errors
    assert 'empty_recommended_action' in outcome.errors
    assert 'empty_recommendation_evidence_refs' in outcome.errors
