"""Read-only timing diagnostics; original qualification remains authoritative.

No timestamps are moved, no clock is fitted and no evidence is authenticated.
Elapsed time before the wrapper does not identify CPU work versus scheduling.
"""

import signed_network_clock as clock


def audit_clock(**evidence):
    """Take the SAME qualify_clock kwargs; preserve its result without changes.

    Missing required Python arguments propagate the original TypeError. Invalid
    supplied evidence returns no row diagnostics. Valid but over-budget evidence
    remains withheld and can receive diagnostics; the fixed budget never changes.
    """
    qualification = clock.qualify_clock(**evidence)
    result = dict(
        qualification=qualification,
        diagnostic_status="unavailable_invalid_clock_evidence",
        scope="readonly_original_clock_row_diagnostics",
        rows=[],
        rows_exceeding_fixed_budget=[],
        worst_row_sequences=[],
        pre_wrapper_cpu_versus_vm_scheduling_cause="UNKNOWN",
        evidence_authenticated=False,
        continuous_unsampled_stability_proven=False,
        measurement_completed=False,
        authorizes_transition=False,
        production_admission=False,
    )
    if "clock_evidence_invalid_or_missing" in qualification["reasons"]:
        return result
    envelope = qualification["offset_envelope_ns"]
    lower, upper = envelope["lower"], envelope["upper"]
    for row in evidence["recorded"]["calls"]:  # Already bounded to <=900 by qualifier.
        data = row["data"]
        pre, post = data["clock_before"], data["clock_after"]
        epoch_low, epoch_high = clock._epoch_interval(data["epoch"])
        before_error = abs(pre["monotonic_before_ns"] + lower - epoch_high)
        after_error = abs(post["monotonic_after_ns"] + upper - epoch_low)
        worst = max(before_error, after_error)
        exceeds = worst > clock.BUDGET_NS
        result["rows"].append(
            dict(
                seq=row["seq"],
                kind=row["kind"],
                original_epoch=data["epoch"],
                epoch_enclosure_ns=dict(lower=epoch_low, upper=epoch_high),
                before_epoch_age_interval_ns=dict(
                    lower=pre["epoch_ns"] - epoch_high,
                    upper=pre["epoch_ns"] - epoch_low,
                ),
                before_anchor_span_ns=pre["monotonic_after_ns"]
                - pre["monotonic_before_ns"],
                wrapper_span_ns=post["monotonic_after_ns"] - pre["monotonic_before_ns"],
                body_span_ns=data["end_ns"] - data["start_ns"],
                after_anchor_span_ns=post["monotonic_after_ns"]
                - post["monotonic_before_ns"],
                gate_before_discrepancy_ns=before_error,
                gate_after_discrepancy_ns=after_error,
                gate_worst_discrepancy_ns=worst,
                exceeds_fixed_budget=exceeds,
            )
        )
        if exceeds:
            result["rows_exceeding_fixed_budget"].append(row["seq"])
        if worst == qualification["worst_call_discrepancy_ns"]:
            result["worst_row_sequences"].append(row["seq"])
    result["diagnostic_status"] = "original_valid_clock_rows_explained"
    return result
