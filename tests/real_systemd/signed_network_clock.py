"""Fixed-budget sampled clock consistency, never continuous clock attestation."""
from fractions import Fraction
import math
import uuid

BUDGET_NS = 5_000_000
NS = 1_000_000_000


def _need(value):
    if not value:
        raise ValueError("invalid actual clock evidence")


def _anchor(value):
    _need(type(value) is dict and set(value) == {"monotonic_before_ns", "epoch_ns", "monotonic_after_ns"})
    _need(all(type(v) is int and 0 <= v < 2**63 for v in value.values()))
    b, e, a = (value[k] for k in ("monotonic_before_ns", "epoch_ns", "monotonic_after_ns"))
    _need(b <= a)
    return b, e, a


def _epoch_interval(epoch):
    _need(type(epoch) in (int, float) and epoch >= 0)
    if type(epoch) is float:
        _need(math.isfinite(epoch))
        center = Fraction.from_float(epoch) * NS
        uncertainty = Fraction.from_float(math.ulp(epoch)) * NS
    else:
        center, uncertainty = Fraction(epoch * NS), Fraction(0)
    low, high = center - uncertainty, center + uncertainty
    return low.numerator // low.denominator, -(-high.numerator // high.denominator)


def qualify_clock(*, kernel_boot_id, observer_boot_id, controller_boot_id,
                  observer_start, observer_end, controller_start, controller_end, recorded):
    """Withhold on missing evidence or any fixed 5ms timing-budget violation.

    Supplied epochs precede calls. Conservatively compare their exact float
    enclosure against the ENTIRE actual call interval and whole-run observed
    offset envelope. Legitimate scheduling/decode/operation delay may withhold.
    No epoch is shifted; no origin is fitted or interpolated. Between anchors,
    a clock step-and-return is unobserved and cannot be ruled out.
    """
    result = dict(status="withheld", scope="sampled_anchor_consistency_only",
                  continuous_unsampled_stability_proven=False, budget_ns=BUDGET_NS,
                  reasons=[], offset_envelope_ns=None, worst_call_discrepancy_ns=None)
    try:
        _need(type(kernel_boot_id) is str and str(uuid.UUID(kernel_boot_id)) == kernel_boot_id
              and kernel_boot_id == observer_boot_id == controller_boot_id)
        os, oe, cs, ce = map(_anchor, (observer_start, observer_end, controller_start, controller_end))
        _need(os[2] <= oe[0] and cs[2] <= ce[0] and os[1] <= oe[1] and cs[1] <= ce[1])
        rows = recorded["calls"]
        _need(type(rows) is list and 0 < len(rows) <= 900)
        anchors, calls, last = [os, oe, cs, ce], [], os[2]
        for sequence, row in enumerate(rows, 1):
            _need(type(row["seq"]) is int and row["seq"] == sequence)
            _need(row["kind"] in ("sample", "event", "finalize"))
            data = row["data"]
            pre, post = _anchor(data["clock_before"]), _anchor(data["clock_after"])
            start, end = data["start_ns"], data["end_ns"]
            _need(type(start) is int and type(end) is int
                  and last <= pre[0] <= pre[2] <= start <= end <= post[0] <= post[2] <= oe[0]
                  and pre[1] <= post[1])
            calls.append((pre[0], post[2], _epoch_interval(data["epoch"])))
            anchors.extend((pre, post))
            last = post[2]
        lower = min(e - a for b, e, a in anchors)
        upper = max(e - b for b, e, a in anchors)
        result["offset_envelope_ns"] = dict(lower=lower, upper=upper, width=upper-lower)
        worst = max(max(abs(b + lower - hi), abs(a + upper - lo)) for b, a, (lo, hi) in calls)
        result["worst_call_discrepancy_ns"] = worst
        if upper - lower > BUDGET_NS:
            result["reasons"].append("sampled_offset_envelope_exceeds_budget")
        if worst > BUDGET_NS:
            result["reasons"].append("supplied_epoch_call_interval_exceeds_budget")
        if not result["reasons"]:
            result["status"] = "qualified"
    except (ValueError, TypeError, KeyError, OverflowError, AttributeError):
        result["reasons"] = ["clock_evidence_invalid_or_missing"]
    return result
