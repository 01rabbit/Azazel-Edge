"""Explicit historical pairing of distinct safety and payload_copy-layer contracts.

A pairing binds enrolled context, not sensor truth, custody or application receipt.
The unchanged main evaluation always survives malformed optional pairing evidence.
"""

from azazel_edge.outcome.journal import _ref
from . import safety_observations as safety
from .udp_payload_copy import evaluate_udp_payload_copy
from .paired_safety_queue import _sha, _same, _selected


def _unknown(reason):
    return dict(
        status="unknown",
        payload_copy_evaluation=None,
        protocol_payload_copy_observed_count=None,
        successful_syscall_count=None,
        application_delivery_count=None,
        qualified_safety_count=None,
        reasons=[reason],
        **safety.FLAGS,
    )


def _pair(
    main_contract_raw,
    main_arguments,
    pair_plan_raw,
    expected_pair_plan_sha256,
    copy_contract_raw,
    copy_plan_raw,
    copy_report_raw,
):
    """Private optional leg; main must already be evaluated by the caller internally.

    This accepts original bytes/pins only, never a caller approval/authentication
    flag. Root-sealed intake may reuse its internally computed main evaluation.
    """
    if pair_plan_raw is None:
        return _unknown("pair_plan_unavailable")
    try:
        safety._hex(expected_pair_plan_sha256)
        safety._need(
            type(pair_plan_raw) is bytes
            and _sha(pair_plan_raw) == expected_pair_plan_sha256,
            "pair plan pin differs",
        )
        plan = safety._wire(pair_plan_raw, 32768)
        safety._fields(
            plan,
            "schema_version main_contract_sha256 copy_contract_sha256 copy_plan_sha256 copy_report_sha256 main_opportunity_id copy_opportunity_id",
        )
        safety._need(
            plan["schema_version"] == "edge-safety-payload-copy-pair-plan/v1",
            "pair plan schema",
        )
        for key in (
            "main_contract_sha256",
            "copy_contract_sha256",
            "copy_plan_sha256",
            "copy_report_sha256",
        ):
            safety._hex(plan[key])
        for key in ("main_opportunity_id", "copy_opportunity_id"):
            _ref(plan[key])
        safety._need(
            plan["main_contract_sha256"]
            == main_arguments["expected_contract_sha256"]
            == _sha(main_contract_raw),
            "main contract pin differs",
        )
        for raw, name, bound in (
            (copy_contract_raw, "copy_contract", 128 * 1024),
            (copy_plan_raw, "copy_plan", 32768),
            (copy_report_raw, "copy_report", 65536),
        ):
            safety._need(
                type(raw) is bytes
                and 0 < len(raw) <= bound
                and _sha(raw) == plan[name + "_sha256"],
                "payload_copy evidence pin differs",
            )
        # This original parser still requires one protected opportunity and no
        # opportunities in the other three categories. No parser relaxation.
        payload_copy = evaluate_udp_payload_copy(
            copy_contract_raw,
            copy_plan_raw,
            copy_report_raw,
            expected_contract_sha256=plan["copy_contract_sha256"],
            expected_plan_sha256=plan["copy_plan_sha256"],
        )
        main = safety._wire(main_contract_raw, 128 * 1024)
        other = safety._wire(copy_contract_raw, 128 * 1024)
        safety._need(
            _same(main["scope"], other["scope"])
            and _same(main["keypins"], other["keypins"]),
            "paired context differs",
        )
        a = _selected(main, plan["main_opportunity_id"])
        b = _selected(other, plan["copy_opportunity_id"])
        for key in ("predicate", "start_ns", "end_ns", "challenge_sha256"):
            safety._need(_same(a[key], b[key]), "paired opportunity differs")
        # reference_sha256 deliberately is NOT compared: main is an opaque
        # frozen premise; the payload_copy parser independently validates its target ref.
        channel = other["channels"]["protected_escape"]
        main_ids = {
            row[key]
            for row in main["channels"].values()
            for key in ("channel_id", "capture_id")
        }
        safety._need(
            channel["channel_id"] not in main_ids
            and channel["capture_id"] not in main_ids,
            "payload_copy capture/channel aliases main",
        )
        return dict(
            status="context_bound_pair",
            payload_copy_evaluation=payload_copy,
            protocol_payload_copy_observed_count=payload_copy[
                "protocol_payload_copy_observed_count"
            ],
            successful_syscall_count=None,
            application_delivery_count=None,
            qualified_safety_count=None,
            reasons=[],
            **safety.FLAGS,
        )
    except (ValueError, OSError, TypeError, KeyError, OverflowError, RecursionError):
        return _unknown("invalid_pairing_evidence")


def _result(main_evaluation, payload_copy_pairing):
    return dict(
        schema_version="edge-paired-safety-payload-copy-evaluation/v1",
        main_evaluation=main_evaluation,
        payload_copy_pairing=payload_copy_pairing,
        qualified_safety_count=None,
        **safety.FLAGS,
    )


def evaluate_paired_safety_payload_copy(
    main_contract_raw,
    main_observations_raw,
    *,
    main_arguments,
    pair_plan_raw=None,
    expected_pair_plan_sha256=None,
    copy_contract_raw=None,
    copy_plan_raw=None,
    copy_report_raw=None,
):
    """Evaluate main FIRST; optional pairing cannot erase its original positives."""
    base = safety.evaluate_safety_observations(
        main_contract_raw, main_observations_raw, **main_arguments
    )
    return _result(
        base,
        _pair(
            main_contract_raw,
            main_arguments,
            pair_plan_raw,
            expected_pair_plan_sha256,
            copy_contract_raw,
            copy_plan_raw,
            copy_report_raw,
        ),
    )
