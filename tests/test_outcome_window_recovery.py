"""Lost-window and saturation recovery must never create fresh evidence."""
import copy
import json

import pytest

from azazel_edge.outcome.outcome_identity import AdmissionStatus, OutcomeIdentityLedger
from azazel_edge.outcome.telemetry import OutcomeTelemetryCollector
from test_outcome_golden_replay_g5 import _outcome
from test_outcome_telemetry_g3 import FakeSource, policy, rust_event


def test_lost_window_survives_checkpoint_and_rejects_first_late_outcome():
    ledger = OutcomeIdentityLedger(max_identities=2)
    ledger.mark_window_lost(execution_id="execution-a", objective_id="objective-a", decision_id="decision-a")
    restored = OutcomeIdentityLedger.from_checkpoint(json.loads(json.dumps(ledger.checkpoint())), max_identities=2)
    assert restored.admit(_outcome()).status is AdmissionStatus.WINDOW_LOST
    assert len(restored) == 0
    assert restored.status()["counters"]["window_lost"] == 1


def test_lost_window_never_replaced_by_post_restart_samples():
    ledger = OutcomeIdentityLedger()
    collector = OutcomeTelemetryCollector(source=FakeSource(), policy=policy(), interface="br0", identity_ledger=ledger)
    event = rust_event(ts="2026-01-01T00:00:00+00:00", trace="pending")
    assert collector.observe_event(event, observed_epoch=100)
    collector.invalidate_pending_windows()
    restored = OutcomeIdentityLedger.from_checkpoint(ledger.checkpoint())
    fresh = OutcomeTelemetryCollector(source=FakeSource(), policy=policy(), interface="br0", identity_ledger=restored)
    for epoch in range(200, 210):
        fresh.record_sample(epoch=epoch)
    assert not fresh.observe_event(event, observed_epoch=205)
    assert fresh.finalize_due(epoch=209) == ()
    assert fresh.lost_window_deliveries == 1


def test_full_ledger_seals_unknown_lost_identity_without_eviction():
    ledger = OutcomeIdentityLedger(max_identities=1)
    first = _outcome()
    assert ledger.admit(first).counted
    ledger.mark_window_lost(execution_id="unknown", objective_id="objective-a", decision_id="other")
    restored = OutcomeIdentityLedger.from_checkpoint(ledger.checkpoint(), max_identities=8)
    assert restored.status()["new_admission_closed"]
    assert restored.admit(first).status is AdmissionStatus.DUPLICATE_IDENTICAL
    assert restored.admit(_outcome(execution_id="new")).status is AdmissionStatus.CAPACITY_EXHAUSTED
    assert restored.window_lost(execution_id="unknown", objective_id="objective-a")


def test_restore_retains_counters_and_refuses_corruption_or_old_schema():
    ledger = OutcomeIdentityLedger()
    ledger.admit(_outcome())
    ledger.admit(_outcome())
    checkpoint = ledger.checkpoint()
    restored = OutcomeIdentityLedger.from_checkpoint(checkpoint)
    assert restored.status() == ledger.status()
    damaged = copy.deepcopy(checkpoint)
    damaged["state"]["identities"].clear()
    with pytest.raises(ValueError, match="digest"):
        OutcomeIdentityLedger.from_checkpoint(damaged)
    with pytest.raises(ValueError, match="schema"):
        OutcomeIdentityLedger.from_mapping({**ledger.to_dict(), "schema_version": "outcome-identity-ledger/v1"})
    for value in (True, -1, "1"):
        state = ledger.to_dict()
        state["counters"]["admitted"] = value
        with pytest.raises(ValueError):
            OutcomeIdentityLedger.from_mapping(state)


def test_lost_and_admitted_identity_overlap_is_refused():
    ledger = OutcomeIdentityLedger()
    ledger.admit(_outcome())
    state = ledger.to_dict()
    state["lost_windows"] = [{k: v for k, v in state["identities"][0].items() if k not in ("outcome_id", "content_digest")}]
    with pytest.raises(ValueError, match="conflicting"):
        OutcomeIdentityLedger.from_mapping(state)
