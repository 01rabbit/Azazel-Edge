from __future__ import annotations

import pytest

from azazel_edge.mio import (
    BoundedReasoningLoop,
    CapabilityBroker,
    DEFAULT_PLAYBOOKS,
    MioEvidenceGap,
    MioHypothesis,
    MioSituationFrame,
    OllamaStructuredTransport,
    PromptCompiler,
    ReasoningState,
)


def _frame():
    return MioSituationFrame.build(
        frame_id='f',
        trace_id='t',
        created_at='2026-08-23T00:00:00Z',
        mission='test',
        current_defensive_state='OBSERVE',
        threat_level='HIGH',
        evidence_refs=['ev:1'],
    )


def test_string_is_not_silently_treated_as_reference_array():
    hypothesis = MioHypothesis.from_mapping(
        {
            'hypothesis_id': 'h1',
            'statement': 'test',
            'supporting_evidence_refs': 'ev:1',
            'assumptions': 'not-a-list',
        },
        ordinal=1,
    )
    assert hypothesis.supporting_evidence_refs == ()
    assert hypothesis.assumptions == ()


def test_non_numeric_gap_priority_falls_back_without_exception():
    gap = MioEvidenceGap.from_mapping(
        {
            'gap_id': 'g1',
            'question': 'test?',
            'discriminates_hypothesis_ids': ['h1'],
            'capability': 'query_recent_alerts',
            'priority': 'high',
        },
        ordinal=1,
    )
    assert gap.priority == 50


def test_duplicate_hypothesis_ids_fail_closed():
    def model(task, prompt):
        if task == 'generate_hypotheses':
            return {'hypotheses': [
                {'hypothesis_id': 'same', 'statement': 'a', 'supporting_evidence_refs': ['ev:1']},
                {'hypothesis_id': 'same', 'statement': 'b', 'supporting_evidence_refs': ['ev:1']},
            ]}
        raise AssertionError(task)

    outcome = BoundedReasoningLoop(model=model, broker=CapabilityBroker()).run(
        frame=_frame(), playbook=DEFAULT_PLAYBOOKS['auth-ambiguity-v1'], cycle_id='dup'
    )
    assert outcome.state is ReasoningState.VALIDATION_REJECTED
    assert 'duplicate_hypothesis_id:same' in outcome.errors


def test_gap_referencing_unknown_hypothesis_fails_before_broker():
    calls = []

    def model(task, prompt):
        if task == 'generate_hypotheses':
            return {'hypotheses': [{'hypothesis_id': 'h1', 'statement': 'a', 'supporting_evidence_refs': ['ev:1']}]}
        if task == 'identify_evidence_gaps':
            return {'evidence_gaps': [{
                'gap_id': 'g1',
                'question': 'test?',
                'discriminates_hypothesis_ids': ['invented'],
                'capability': 'query_recent_alerts',
                'priority': 90,
            }]}
        raise AssertionError(task)

    class Broker(CapabilityBroker):
        def execute(self, request):
            calls.append(request)
            return super().execute(request)

    outcome = BoundedReasoningLoop(model=model, broker=Broker()).run(
        frame=_frame(), playbook=DEFAULT_PLAYBOOKS['auth-ambiguity-v1'], cycle_id='bad-gap'
    )
    assert outcome.state is ReasoningState.VALIDATION_REJECTED
    assert 'unknown_gap_hypothesis:g1:invented' in outcome.errors
    assert calls == []


def test_update_hypotheses_prompt_has_explicit_schema():
    prompt = PromptCompiler().compile(
        frame=_frame(),
        playbook=DEFAULT_PLAYBOOKS['auth-ambiguity-v1'],
        hypotheses=(MioHypothesis.from_mapping({'hypothesis_id': 'h1', 'statement': 'a'}, ordinal=1),),
        broker_results=({'evidence_refs': ['ev:1']},),
        task='update_hypotheses',
    )
    assert 'update_hypotheses' in prompt
    assert 'revision_summary' in prompt
    assert 'strengthened' in prompt


def test_arbitrary_dns_model_endpoint_is_rejected_even_if_private_network_enabled():
    with pytest.raises(ValueError, match='mio_endpoint_not_local_or_allowed_private'):
        OllamaStructuredTransport(
            endpoint='https://model.internal.example:11434',
            models=('qwen3.5:2b',),
            allow_private_network=True,
            bearer_token='token',
        )
