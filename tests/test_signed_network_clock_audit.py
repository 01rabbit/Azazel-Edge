"""Read-only diagnostics; original timing fixture is not evidence authentication."""

import copy
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_clock as clock
import signed_network_clock_audit as audit

BOOT = "7be45004-1731-4b7c-8e62-59a5ddf129a4"


def point(at):
    return dict(monotonic_before_ns=at, epoch_ns=at, monotonic_after_ns=at)


def evidence(span=clock.BUDGET_NS):
    return dict(
        kernel_boot_id=BOOT,
        observer_boot_id=BOOT,
        controller_boot_id=BOOT,
        observer_start=point(0),
        observer_end=point(20_000_000),
        controller_start=point(0),
        controller_end=point(10_000_000),
        recorded=dict(
            calls=[
                dict(
                    seq=1,
                    kind="event",
                    data=dict(
                        epoch=0,
                        clock_before=point(0),
                        start_ns=0,
                        end_ns=span,
                        clock_after=point(span),
                    ),
                )
            ]
        ),
    )


def test_original_a0_exact_timing_is_explained_without_changing_qualification():
    fixture = json.loads(
        (
            Path(__file__).parent / "fixtures/clock-audit/trial1-a0-timing.json"
        ).read_text()
    )
    original = fixture["evidence"]
    before = copy.deepcopy(original)
    result = audit.audit_clock(**original)
    assert (
        result["qualification"]
        == fixture["original_qualification"]
        == clock.qualify_clock(**original)
    )
    assert original == before
    assert len(result["rows"]) == 95
    assert (
        result["rows_exceeding_fixed_budget"] == result["worst_row_sequences"] == [25]
    )
    row = result["rows"][24]
    assert row["kind"] == "event"
    assert row["gate_worst_discrepancy_ns"] == 5_006_790
    assert row["epoch_enclosure_ns"] == dict(
        lower=1794436854164490222, upper=1794436854164490700
    )
    assert row["before_epoch_age_interval_ns"] == dict(lower=4_789_115, upper=4_789_593)
    assert (
        row["before_anchor_span_ns"],
        row["body_span_ns"],
        row["after_anchor_span_ns"],
        row["wrapper_span_ns"],
    ) == (958, 212947, 209, 215489)
    assert result["pre_wrapper_cpu_versus_vm_scheduling_cause"] == "UNKNOWN"
    assert (
        result["evidence_authenticated"]
        is result["measurement_completed"]
        is result["authorizes_transition"]
        is result["production_admission"]
        is False
    )


@pytest.mark.parametrize("excess", [0, 1])
def test_exact_fixed_budget_boundary_and_integer_epoch(excess):
    original = evidence(clock.BUDGET_NS + excess)
    result = audit.audit_clock(**original)
    assert result["qualification"] == clock.qualify_clock(**original)
    assert result["qualification"]["status"] == ("withheld" if excess else "qualified")
    assert result["rows_exceeding_fixed_budget"] == ([1] if excess else [])
    assert result["rows"][0]["gate_worst_discrepancy_ns"] == clock.BUDGET_NS + excess
    assert result["rows"][0]["epoch_enclosure_ns"] == dict(lower=0, upper=0)


@pytest.mark.parametrize(
    "bad", ["missing", "nan", "bool", "malformed_anchor", "over_bound"]
)
def test_invalid_evidence_has_no_row_diagnostics(bad):
    original = evidence()
    data = original["recorded"]["calls"][0]["data"]
    if bad == "missing":
        del data["clock_before"]
    elif bad == "nan":
        data["epoch"] = float("nan")
    elif bad == "bool":
        data["epoch"] = True
    elif bad == "malformed_anchor":
        original["observer_start"]["epoch_ns"] = 0.0
    else:
        original["recorded"]["calls"] *= 901
    result = audit.audit_clock(**original)
    assert result["qualification"] == clock.qualify_clock(**original)
    assert result["diagnostic_status"] == "unavailable_invalid_clock_evidence"
    assert (
        result["rows"]
        == result["worst_row_sequences"]
        == result["rows_exceeding_fixed_budget"]
        == []
    )


def test_qualification_is_called_first_and_preserved_by_identity(monkeypatch):
    real = clock.qualify_clock
    retained = []

    def qualify(**kwargs):
        result = real(**kwargs)
        retained.append(result)
        return result

    monkeypatch.setattr(clock, "qualify_clock", qualify)
    result = audit.audit_clock(**evidence())
    assert len(retained) == 1 and result["qualification"] is retained[0]


def test_missing_required_arguments_keeps_original_call_error():
    with pytest.raises(TypeError):
        audit.audit_clock()
