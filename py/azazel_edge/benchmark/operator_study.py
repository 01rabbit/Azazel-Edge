"""Offline, consented operator-task analysis; never deployed analytics or authority.

A matching digest proves binding, not consent, blinded scoring, preregistration,
human benefit or independent truth. Those declarations need separate review.
"""
from __future__ import annotations

import argparse
import json
import re
import statistics
from collections import defaultdict
from collections.abc import Mapping

from .benefit import BenefitInputError, _digest, _estimate, _load, _number, manifest_digest

SCHEMA = 'azazel-operator-study/v1'
ARMS = ('classic', 'overview')


def _id(value, pattern):
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise BenefitInputError('invalid anonymous study identifier')
    return value


def validate_plan(plan):
    if not isinstance(plan, Mapping) or plan.get('schema_version') != SCHEMA:
        raise BenefitInputError('unsupported operator study plan')
    if plan.get('phase') not in ('pilot', 'confirmatory') or plan.get('evidence_kind') not in ('synthetic', 'human_tasks'):
        raise BenefitInputError('declare phase and evidence kind')
    for name in ('rubric_sha256', 'holdout_corpus_sha256', 'sample_size_plan_sha256', 'registration_sha256'):
        _digest(plan.get(name))
    pins = plan.get('render_sha256')
    if not isinstance(pins, Mapping) or set(pins) != set(ARMS):
        raise BenefitInputError('pin both render variants')
    for value in pins.values(): _digest(value)
    if pins['classic'] == pins['overview']:
        raise BenefitInputError('comparator renders must differ')
    horizon = _number(plan.get('task_horizon_seconds'), minimum=1, maximum=3600)
    analysis = plan.get('analysis')
    if not isinstance(analysis, Mapping):
        raise BenefitInputError('missing frozen analysis')
    for key, lo, hi in (('minimum_participants', 2, 200), ('bootstrap_repeats', 100, 10000), ('seed', 0, 2**32-1)):
        if type(analysis.get(key)) is not int or not lo <= analysis[key] <= hi:
            raise BenefitInputError('invalid bounded analysis')
    for key in ('max_correctness_loss', 'max_handoff_loss'):
        _number(analysis.get(key), maximum=1)
    _number(analysis.get('minimum_time_gain_seconds'), minimum=.001, maximum=horizon)
    assignments = plan.get('assignments')
    if not isinstance(assignments, list) or not 4 <= len(assignments) <= 8000:
        raise BenefitInputError('invalid bounded assignments')
    result, pairs, orders = {}, defaultdict(dict), defaultdict(list)
    participants, cases = set(), set()
    for item in assignments:
        if not isinstance(item, Mapping):
            raise BenefitInputError('invalid assignment')
        ident = _id(item.get('id'), r't-[a-z0-9-]{1,48}')
        participant = _id(item.get('participant'), r'p-[0-9a-f]{16}')
        case = _id(item.get('case'), r'case-[a-z0-9-]{1,40}')
        arm = item.get('arm')
        order = item.get('order')
        if ident in result or arm not in ARMS or type(order) is not int or order not in (1, 2):
            raise BenefitInputError('duplicate/invalid assignment')
        _digest(item.get('snapshot_sha256'))
        if arm in pairs[(participant, case)]:
            raise BenefitInputError('duplicate participant/case/arm')
        pairs[(participant, case)][arm] = item
        participants.add(participant); cases.add(case); result[ident] = item
    if not 2 <= len(participants) <= 200 or not 1 <= len(cases) <= 20 or len(participants) * analysis['bootstrap_repeats'] > 2_000_000:
        raise BenefitInputError('study exceeds work budget or lacks participant clusters')
    for (participant, case), pair in pairs.items():
        if set(pair) != set(ARMS) or {v['order'] for v in pair.values()} != {1, 2}:
            raise BenefitInputError('unpaired task/order')
        if pair['classic']['snapshot_sha256'] != pair['overview']['snapshot_sha256']:
            raise BenefitInputError('layouts require equivalent backend state')
        orders[case].append(pair['classic']['order'])
    if len(pairs) != len(participants) * len(cases):
        raise BenefitInputError('incomplete crossed case plan')
    if any(abs(values.count(1) - values.count(2)) > 1 for values in orders.values()):
        raise BenefitInputError('case order is not counterbalanced')
    cards = plan.get('task_cards')
    if not isinstance(cards, Mapping) or set(cards) != cases:
        raise BenefitInputError('task cards must match frozen cases')
    for card in cards.values():
        if not isinstance(card, Mapping) or type(card.get('prompt')) is not str or not 1 <= len(card['prompt']) <= 500:
            raise BenefitInputError('invalid bounded task prompt')
        options = card.get('options')
        if not isinstance(options, list) or not 2 <= len(options) <= 10:
            raise BenefitInputError('invalid bounded answer options')
        seen = set()
        for option in options:
            if not isinstance(option, Mapping): raise BenefitInputError('invalid answer option')
            ident = _id(option.get('id'), r'choice-[a-z0-9-]{1,30}')
            if ident in seen or type(option.get('label')) is not str or not 1 <= len(option['label']) <= 200:
                raise BenefitInputError('duplicate/invalid bounded answer option')
            seen.add(ident)
    return result


def collector_plan(plan):
    validate_plan(plan)
    return {'schema_version':'azazel-operator-collector-input/v1', 'plan_sha256':manifest_digest(plan),
            'plan_canonical_json':json.dumps(plan, sort_keys=True, separators=(',', ':'), allow_nan=False)}


def analyze(plan, observations):
    assignments = validate_plan(plan)
    digest = manifest_digest(plan)
    if not isinstance(observations, Mapping) or observations.get('plan_sha256') != digest:
        raise BenefitInputError('result/plan binding mismatch')
    receipts = observations.get('receipts')
    if not isinstance(receipts, list) or len(receipts) > len(assignments):
        raise BenefitInputError('invalid bounded receipts')
    captures = observations.get('captures')
    if not isinstance(captures, list) or len(captures) > len(assignments):
        raise BenefitInputError('bounded unscored captures required')
    captured = {}
    keys = {'assignment_id', 'consented', 'elapsed_seconds', 'timed_out', 'answer_ids', 'render_sha256', 'snapshot_sha256', 'rubric_sha256'}
    for capture in captures:
        if not isinstance(capture, Mapping) or set(capture) != keys:
            raise BenefitInputError('invalid minimized capture')
        ident = capture['assignment_id']
        if type(ident) is not str or ident not in assignments or ident in captured:
            raise BenefitInputError('unknown/duplicate capture')
        assignment = assignments[ident]
        if capture['render_sha256'] != plan['render_sha256'][assignment['arm']] or capture['snapshot_sha256'] != assignment['snapshot_sha256'] or capture['rubric_sha256'] != plan['rubric_sha256']:
            raise BenefitInputError('capture binding mismatch')
        if type(capture['consented']) is not bool or type(capture['timed_out']) is not bool:
            raise BenefitInputError('explicit capture consent and deadline required')
        _number(capture['elapsed_seconds'], maximum=plan['task_horizon_seconds'])
        options = {o['id'] for o in plan['task_cards'][assignment['case']]['options']}
        answers = capture['answer_ids']
        if not isinstance(answers, list) or len(answers) > 10 or any(type(a) is not str or a not in options for a in answers) or len(set(answers)) != len(answers):
            raise BenefitInputError('invalid closed answer choices')
        if capture['timed_out'] and (answers or capture['elapsed_seconds'] != plan['task_horizon_seconds']):
            raise BenefitInputError('invalid deadline capture')
        captured[ident] = capture
    found, unsafe, not_consented, unscored = {}, 0, 0, 0
    for receipt in receipts:
        if not isinstance(receipt, Mapping):
            raise BenefitInputError('invalid receipt')
        ident = receipt.get('assignment_id')
        if type(ident) is not str or ident not in assignments or ident in found:
            raise BenefitInputError('unknown/duplicate assignment receipt')
        capture = captured.get(ident)
        if capture is None or receipt.get('capture_sha256') != manifest_digest(capture):
            raise BenefitInputError('score must bind an unscored capture')
        if any(receipt.get(k) != capture[k] for k in ('consented', 'elapsed_seconds', 'timed_out')):
            raise BenefitInputError('score cannot rewrite captured consent, clock or deadline')
        for key in ('consented', 'blinded_scoring', 'correct', 'unsafe_choice', 'timed_out'):
            if type(receipt.get(key)) is not bool:
                raise BenefitInputError('explicit consent/scoring/correctness/safety required')
        _number(receipt.get('elapsed_seconds'), maximum=plan['task_horizon_seconds'])
        _number(receipt.get('handoff_score'), maximum=1)
        if receipt['timed_out'] and (receipt['correct'] or receipt['elapsed_seconds'] != plan['task_horizon_seconds']):
            raise BenefitInputError('timed-out task cannot be correct or finish early')
        if receipt.get('rubric_sha256') != plan['rubric_sha256'] or receipt.get('render_sha256') != plan['render_sha256'][assignments[ident]['arm']]:
            raise BenefitInputError('receipt/rubric/render binding mismatch')
        unsafe += receipt['unsafe_choice']
        not_consented += not receipt['consented']
        unscored += not receipt['blinded_scoring']
        found[ident] = receipt
    pairs, clusters = defaultdict(dict), defaultdict(lambda: defaultdict(list))
    for ident, assignment in assignments.items():
        pairs[(assignment['participant'], assignment['case'])][assignment['arm']] = found.get(ident)
    complete_pairs = both_correct = 0
    for (participant, case), pair in pairs.items():
        old, new = pair['classic'], pair['overview']
        if old is None or new is None or not all(r['consented'] and r['blinded_scoring'] for r in (old, new)):
            continue
        complete_pairs += 1
        clusters[participant]['correctness'].append(int(new['correct']) - int(old['correct']))
        clusters[participant]['handoff'].append(new['handoff_score'] - old['handoff_score'])
        # Incorrect/unfinished answers use the common horizon; fast wrong answers
        # cannot manufacture a time-to-correct improvement.
        a = old['elapsed_seconds'] if old['correct'] else plan['task_horizon_seconds']
        b = new['elapsed_seconds'] if new['correct'] else plan['task_horizon_seconds']
        clusters[participant]['restricted_time'].append(b-a)
        if old['correct'] and new['correct']:
            both_correct += 1
            clusters[participant]['both_correct_time'].append(new['elapsed_seconds']-old['elapsed_seconds'])
    analysis = plan['analysis']; estimates = {}
    for metric in ('correctness', 'handoff', 'restricted_time', 'both_correct_time'):
        means = [statistics.fmean(values[metric]) for values in clusters.values() if values[metric]]
        estimates[metric] = _estimate(means, repeats=analysis['bootstrap_repeats'], seed=analysis['seed'])
        estimates[metric]['unit'] = 'participant_cluster_mean'
    complete = len(found) == len(assignments) and complete_pairs == len(pairs)
    gates = {'complete_consented_blinded_receipts': complete and not not_consented and not unscored,
             'no_unsafe_choice': unsafe == 0 and complete,
             'minimum_participants': len(clusters) >= analysis['minimum_participants']}
    for metric, boundary in (('correctness', -analysis['max_correctness_loss']), ('handoff', -analysis['max_handoff_loss'])):
        interval = estimates[metric]['interval_95']
        gates[metric+'_noninferiority'] = interval is not None and interval[0] >= boundary
    interval = estimates['restricted_time']['interval_95']
    gates['practical_time_gain'] = interval is not None and interval[1] <= -analysis['minimum_time_gain_seconds']
    mechanical = plan['phase'] == 'pilot' or plan['evidence_kind'] == 'synthetic'
    status = 'mechanical_only' if mechanical else 'recorded_criteria_met_requires_independent_review' if all(gates.values()) else 'criteria_not_met'
    return {'schema_version':'azazel-operator-study-report/v1', 'plan_sha256':digest, 'status':status,
            'effect_direction':'overview_minus_classic', 'expected_receipts':len(assignments), 'received_receipts':len(found),
            'received_captures':len(captured), 'missing_captures':len(assignments)-len(captured), 'missing_receipts':len(assignments)-len(found), 'expected_pairs':len(pairs), 'complete_pairs':complete_pairs,
            'both_correct_pairs':both_correct, 'participant_clusters':len(clusters), 'unsafe_choices':unsafe,
            'unconsented_receipts':not_consented, 'unblinded_receipts':unscored, 'effects':estimates, 'gates':gates,
            'limitations':['digests and flags do not prove independent registration, consent or blinded truth',
                           'participant bootstrap does not replace sample-size, order, learning or multiplicity review',
                           'restricted task time assigns the common horizon to incorrect answers',
                           'no deployed analytics, authority, hardware support or external-tool superiority established']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan'); parser.add_argument('observations', nargs='?'); parser.add_argument('--collector-plan', action='store_true'); args=parser.parse_args()
    if args.collector_plan == bool(args.observations): parser.error('provide observations or --collector-plan')
    try:
        plan = _load(args.plan)
        result = collector_plan(plan) if args.collector_plan else analyze(plan,_load(args.observations))
    except (BenefitInputError,OSError,TypeError,KeyError,RecursionError,json.JSONDecodeError) as exc:
        parser.exit(2,f'invalid operator study input: {exc}\n')
    print(json.dumps(result,sort_keys=True,indent=2,allow_nan=False))
    return 0


if __name__=='__main__': raise SystemExit(main())
