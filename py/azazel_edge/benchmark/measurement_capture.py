"""Bounded independent-controller recording API. No client/Edge execution hooks."""
from __future__ import annotations

from copy import deepcopy

from .benefit import BenefitInputError, SAFETY_FIELDS, _number, manifest_digest, validate_manifest
from .measurement import _ref, _bounded

KINDS = {'discovery','protected_reach','authentication_attempt','protected_goal','verified_containment','sensor_gap','actionable_detection'}
MAX_ITEMS = 10000


def _taint_on_invalid(method):
    def checked(self, *args, **kwargs):
        try: return method(self, *args, **kwargs)
        except (BenefitInputError, ValueError, TypeError):
            self._loss = True
            raise
    return checked


class IndependentServiceCapture:
    """Products supply measured elapsed times; no clock/traffic inference here.

    Stop/error/full-disk integration is caller-owned. Saturation/failed export
    must never be filled in as a successful full observation window.
    """
    def __init__(self, manifest, assignment_id, *, run_id, boot_id, clock_id):
        assignments = validate_manifest(manifest)
        if assignment_id not in assignments: raise BenefitInputError('unknown assignment')
        a = assignments[assignment_id]
        self.horizon = manifest['horizon_seconds']
        self._capture = dict(manifest_sha256=manifest_digest(manifest),assignment_id=assignment_id,scenario=a['scenario'],seed=a['seed'],
            source='isolated_scenario_controller',run_id=_ref(run_id),boot_id=_ref(boot_id),clock_id=_ref(clock_id),clock_kind='monotonic_elapsed',
            milestones=[{'id':'controller-start','kind':'run_start','elapsed_seconds':0}],legitimate_transactions=[],safety_violations=dict.fromkeys(SAFETY_FIELDS,0))
        self._events = {'controller-start':self._capture['milestones'][0]}; self._transactions = {}
        self._last = 0; self._finished = False; self._loss = False
        self.counters = dict(duplicate=0,dropped=0)

    def _time(self, elapsed):
        if self._finished: raise BenefitInputError('capture already finished')
        value = _number(elapsed, maximum=self.horizon)
        if value < self._last:
            self._loss = True
            raise BenefitInputError('controller clock moved backwards')
        self._last = value
        return value

    @_taint_on_invalid
    def milestone(self, event_id, kind, *, elapsed_seconds, boot_id=None, clock_id=None):
        if self._finished: raise BenefitInputError('capture already finished')
        if kind not in KINDS: raise BenefitInputError('milestone kind is not independent service truth')
        ident = _ref(event_id)
        if ident.startswith('controller-'): raise BenefitInputError('reserved event reference')
        row = dict(id=ident,kind=kind,elapsed_seconds=_number(elapsed_seconds,maximum=self.horizon))
        for name,value in (('boot_id',boot_id),('clock_id',clock_id)):
            if value is not None and value != self._capture[name]:
                self._loss=True
                raise BenefitInputError('cross-boot/clock controller event')
        if ident in self._events:
            if row == self._events[ident]: self.counters['duplicate']+=1;return False
            self._loss=True;raise BenefitInputError('conflicting event identity')
        self._time(elapsed_seconds)
        if len(self._events) >= MAX_ITEMS-2:
            self._loss=True;self.counters['dropped']+=1;return False
        self._events[ident]=row;self._capture['milestones'].append(row);return True

    @_taint_on_invalid
    def transaction(self, transaction_id, *, elapsed_seconds, duration_ms, error):
        if self._finished: raise BenefitInputError('capture already finished')
        row = dict(id=_ref(transaction_id),elapsed_seconds=_number(elapsed_seconds,maximum=self.horizon),
                   duration_ms=_number(duration_ms,maximum=self.horizon*1000),error=error)
        if type(error) is not bool or row['duration_ms'] > row['elapsed_seconds']*1000:
            raise BenefitInputError('invalid independent transaction interval/result')
        if row['id'] in self._transactions:
            if row==self._transactions[row['id']]:self.counters['duplicate']+=1;return False
            self._loss=True;raise BenefitInputError('conflicting transaction identity')
        self._time(elapsed_seconds)
        if len(self._transactions)>=MAX_ITEMS:
            self._loss=True;self.counters['dropped']+=1;return False
        self._transactions[row['id']]=row;self._capture['legitimate_transactions'].append(row);return True

    @_taint_on_invalid
    def safety_violation(self, kind, *, count=1):
        if self._finished or kind not in SAFETY_FIELDS or type(count) is not int or not 0<=count<=10**9:
            raise BenefitInputError('invalid independent safety observation')
        self._capture['safety_violations'][kind]=min(10**9,self._capture['safety_violations'][kind]+count)

    @_taint_on_invalid
    def finish(self, *, elapsed_seconds):
        end=self._time(elapsed_seconds)
        if self._loss:self._capture['milestones'].append(dict(id='controller-loss',kind='sensor_gap',elapsed_seconds=end))
        self._capture['milestones'].append(dict(id='controller-end',kind='run_end',elapsed_seconds=end))
        self._finished=True
        _bounded(self._capture)
        return deepcopy(self._capture)
