from __future__ import annotations

import json
from pathlib import Path

from azazel_edge.mio import (
    BoundedReasoningLoop,
    CapabilityBroker,
    CapabilitySpec,
    DEFAULT_PLAYBOOKS,
    MioHypothesis,
    MioRecommendation,
    MioSituationFrame,
    MioSituationFrameBuilder,
    OllamaStructuredTransport,
    PromptCompiler,
    ReasoningState,
)
from azazel_edge.mio.grounding import GroundingValidator


_FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'mio'


def _captured_replay_fixture(name: str):
    return json.loads((_FIXTURE_DIR / name).read_text(encoding='utf-8'))


def _auth_fixture_frame() -> MioSituationFrame:
    source = _captured_replay_fixture('auth_ambiguity_shadow.json')
    return MioSituationFrameBuilder().build(
        events=source['events'],
        noc_evaluation=source['noc_evaluation'],
        soc_evaluation=source['soc_evaluation'],
        current_defensive_state=source['current_defensive_state'],
        mission=source['mission'],
        trace_id=source['trace_id'],
        frame_id=source['frame_id'],
        created_at=source['created_at'],
    )


def _replay_captured_outputs(captured):
    outputs = captured['model_outputs']

    def model(task, _prompt):
        return outputs[task]

    broker = CapabilityBroker({
        'query_recent_alerts': CapabilitySpec(
            lambda _: {'summary': 'authentication failures only', 'evidence_refs': ['sha256:fixture-alert-summary-1']}
        )
    })
    return BoundedReasoningLoop(model=model, broker=broker).run(
        frame=_auth_fixture_frame(),
        playbook=DEFAULT_PLAYBOOKS['auth-ambiguity-v1'],
        cycle_id='captured-real-model-replay',
    )


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
    result = OllamaStructuredTransport(models=('qwen3.5:2b',))('recommend', 'return json')

    assert result == {'status': 'ok'}
    assert captured['body']['think'] is False
    assert captured['body']['format']['type'] == 'object'
    assert captured['body']['format']['required'] == ['summary', 'recommended_action', 'rationale', 'evidence_refs', 'limitations']


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


def test_small_model_prompt_uses_current_refs_not_literal_reference_placeholders():
    prompt = PromptCompiler().compile(
        frame=_frame(),
        playbook=DEFAULT_PLAYBOOKS['auth-ambiguity-v1'],
        task='recommend',
    )
    trusted = json.loads(prompt.split('TRUSTED_CONTROL\n', 1)[1].split('\nEND_TRUSTED_CONTROL', 1)[0])

    assert trusted['allowed_evidence_refs'] == ['ev:1', 'ev:2']
    assert trusted['output_schema']['evidence_refs'] == ['ev:1']
    assert 'existing-ref' not in prompt
    assert 'existing-or-short-id' not in prompt


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


def test_captured_qwen_2b_success_fixture_completes_grounded_advisory():
    captured = _captured_replay_fixture('auth_ambiguity_shadow_real_success_qwen3_5_2b.json')
    outcome = _replay_captured_outputs(captured)

    assert captured['captured_with']['model'] == 'qwen3.5:2b'
    assert outcome.state.value == captured['expected']['state']
    assert list(outcome.errors) == captured['expected']['errors']
    assert outcome.recommendation is not None
    assert outcome.recommendation.summary
    assert outcome.recommendation.rationale
    assert outcome.recommendation.recommended_action == 'OBSERVE'
    assert outcome.recommendation.evidence_refs
    assert outcome.recommendation.executable is False


def test_captured_empty_recommendation_fixture_remains_validation_rejected():
    captured = _captured_replay_fixture('auth_ambiguity_shadow_real_failure_empty_recommendation.json')
    outcome = _replay_captured_outputs(captured)

    assert captured['model_outputs']['recommend']['recommended_action'] == ''
    assert outcome.state.value == captured['expected']['state']
    for error in captured['expected']['errors']:
        assert error in outcome.errors
