"""Synthetic actual-anchor inputs; no VM clock precision or stability claim."""

from copy import deepcopy

import pytest

from test_signed_network_clock import clock, evidence, anchor


def query_evidence():
    value = evidence()
    value["controller_samples"] = [
        anchor(at) for at in (600000, 700000, 2000000, 2100000, 9000000, 9100000)
    ]
    return value


def test_six_actual_query_anchors_use_same_budget_and_preserve_input():
    value = query_evidence()
    before = deepcopy(value)
    qualified = clock.qualify_clock(**value)
    assert qualified["status"] == "qualified" and qualified["budget_ns"] == 5000000
    assert qualified["scope"] == "sampled_anchor_consistency_only"
    assert (
        qualified["continuous_unsampled_stability_proven"] is False and value == before
    )
    legacy = evidence()
    assert clock.qualify_clock(**legacy) == clock.qualify_clock(
        **dict(legacy, controller_samples=())
    )


@pytest.mark.parametrize("index", range(6))
def test_every_query_anchor_can_withhold_on_original_wall_monotonic_drift(index):
    value = query_evidence()
    value["controller_samples"][index]["epoch_ns"] += 6000000
    assert clock.qualify_clock(**value)["status"] == "withheld"


@pytest.mark.parametrize("fault", ["count", "bool", "float", "missing", "reverse"])
def test_bad_extra_anchors_are_not_supplemented_or_reordered(fault):
    value = query_evidence()
    if fault == "count":
        value["controller_samples"].pop()
    elif fault == "missing":
        del value["controller_samples"][2]["epoch_ns"]
    elif fault == "bool":
        value["controller_samples"][2]["epoch_ns"] = True
    elif fault == "float":
        value["controller_samples"][2]["monotonic_before_ns"] = 2000000.0
    elif fault == "reverse":
        value["controller_samples"].reverse()
    assert clock.qualify_clock(**value)["status"] == "withheld"
