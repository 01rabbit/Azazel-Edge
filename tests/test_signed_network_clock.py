"""Pure sampled clock qualification; no VM or timing precision claim."""
import copy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).parent / "real_systemd"))
import signed_network_clock as clock

BOOT = "7be45004-1731-4b7c-8e62-59a5ddf129a4"
OFFSET = 1_700_000_000_000_000_000


def anchor(at, offset=OFFSET):
    return dict(monotonic_before_ns=at, epoch_ns=at + offset + 50, monotonic_after_ns=at + 100)


def evidence():
    return dict(kernel_boot_id=BOOT, observer_boot_id=BOOT, controller_boot_id=BOOT,
                observer_start=anchor(0), observer_end=anchor(20_000_000),
                controller_start=anchor(500_000), controller_end=anchor(10_000_000),
                recorded=dict(calls=[dict(seq=1, kind="sample", data=dict(
                    clock_before=anchor(1_000_000), clock_after=anchor(1_100_000),
                    start_ns=1_000_100, end_ns=1_100_000,
                    epoch=(OFFSET + 900_000) / 1e9))]))


def test_legitimately_earlier_epoch_qualifies_without_realigning_or_mutating():
    value = evidence()
    before = copy.deepcopy(value)
    result = clock.qualify_clock(**value)
    assert result["status"] == "qualified"
    assert result["scope"] == "sampled_anchor_consistency_only"
    assert result["continuous_unsampled_stability_proven"] is False
    assert result["worst_call_discrepancy_ns"] > 100_000
    assert value == before


@pytest.mark.parametrize("which", ["observer_start", "observer_end", "controller_start", "controller_end"])
def test_every_external_anchor_contributes_to_fixed_budget(which):
    value = evidence()
    value[which]["epoch_ns"] += 6_000_000
    assert clock.qualify_clock(**value)["status"] == "withheld"


@pytest.mark.parametrize("mutation", ["boot", "missing", "sequence", "overlap", "reverse", "nan", "bool"])
def test_invalid_or_missing_actual_evidence_withholds(mutation):
    value = evidence()
    row = value["recorded"]["calls"][0]
    if mutation == "boot":
        value["observer_boot_id"] = "abe45004-1731-4b7c-8e62-59a5ddf129a4"
    elif mutation == "missing":
        del row["data"]["clock_before"]
    elif mutation == "sequence":
        row["seq"] = 2
    elif mutation == "overlap":
        row["data"]["start_ns"] = 0
    elif mutation == "reverse":
        row["data"]["clock_after"]["monotonic_after_ns"] = 0
    elif mutation == "nan":
        row["data"]["epoch"] = float("nan")
    else:
        row["data"]["epoch"] = True
    assert clock.qualify_clock(**value)["status"] == "withheld"


def test_correct_but_slow_argument_or_operation_withholds_instead_of_retiming():
    for key in ("argument", "operation"):
        value = evidence()
        data = value["recorded"]["calls"][0]["data"]
        if key == "argument":
            data["epoch"] -= .010
        else:
            data["end_ns"] = 12_000_000
            data["clock_after"] = anchor(12_000_000)
        result = clock.qualify_clock(**value)
        assert result["status"] == "withheld"
        assert "supplied_epoch_call_interval_exceeds_budget" in result["reasons"]


def test_exact_float_enclosure_does_not_pretend_integer_nanosecond_precision():
    epoch = 1_700_000_000.1234567
    low, high = clock._epoch_interval(epoch)
    assert high - low >= 400
    assert low <= epoch * 1e9 <= high
