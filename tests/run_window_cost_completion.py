"""One existing actual matrix plus separate declared SYNTHETIC window cases."""

import argparse
import json
from pathlib import Path

import run_observer_normal_clock as original
from observer_normal_stop_analysis import _read
from window_cost_completion_lab import run_synthetic_window_cases, wire
from window_cost_completion_analysis import analyze_window_cost_completion, ROLES
from window_cost_publication import publish_publication


def collect_actual_raw(result):
    collected, errors = {}, []
    for arm in result.get("original_load_evaluation", {}).get(
        "original_arm_inputs", []
    ):
        identifier = arm["arm_id"]
        values = collected[identifier] = {}
        descriptors = {
            **arm.get("raw_artifacts", {}),
            **arm.get("normal_stop", {}).get("artifacts", {}),
            **arm.get("clock_artifacts", {}),
        }
        limits = dict(
            completion=65536,
            request=16384,
            trust=65536,
            source=2 * 1024 * 1024,
            journal=4 * 1024 * 1024,
            anchors=4 * 1024 * 1024,
            calls=4 * 1024 * 1024,
            context=16384,
        )
        for name, maximum in limits.items():
            try:
                values[name] = _read(descriptors.get(name), maximum)
            except (OSError, ValueError, TypeError, KeyError):
                values[name] = None
                errors.append(identifier + "." + name + "_original_read_failed")
        for role in ROLES:
            try:
                values[role] = _read(
                    arm.get("phase_artifacts", {}).get(role), 4 * 1024 * 1024
                )
            except (OSError, ValueError, TypeError, KeyError):
                values[role] = None
                errors.append(identifier + "." + role + "_phase_original_read_failed")
    return collected, errors


def collect_synthetic_raw(result, *, errors=None):
    collected = {}
    for case in result["cases"]:
        values = collected[case["id"]] = {}
        for name, descriptor in case["artifacts"].items():
            try:
                values[name] = _read(descriptor, 4 * 1024 * 1024)
            except (OSError, ValueError, TypeError, KeyError) as exc:
                values[name] = None
                if errors is not None:
                    errors.append(
                        case["id"]
                        + "."
                        + name
                        + "_synthetic_read_failed_"
                        + type(exc).__name__
                    )
    return collected


def run(output_dir):
    """Never retry or replace an actual matrix, its output or failed originals."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)
    errors = []
    try:
        actual = original.run()
    except BaseException as exc:
        actual = getattr(
            exc,
            "normal_stop_partial_report",
            dict(
                schema_version="actual_normal_clock_unavailable",
                blocker=type(exc).__name__,
            ),
        )
        errors.append("actual_matrix_failed_" + type(exc).__name__)
    try:
        original.export_public(actual, output / "original-normal-clock")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append("original_public_export_failed_" + type(exc).__name__)
    try:
        synthetic = run_synthetic_window_cases(output / "synthetic-window-cases")
    except Exception as exc:
        synthetic = dict(
            schema_version="edge-synthetic-window-lifecycle/v1",
            data_kind="SYNTHETIC",
            cases=[],
        )
        errors.append("synthetic_bundle_failed_" + type(exc).__name__)
    errors.extend(synthetic.get("blockers", []))
    actual_raw, read_errors = collect_actual_raw(actual)
    synthetic_raw = collect_synthetic_raw(synthetic, errors=read_errors)
    try:
        report = analyze_window_cost_completion(
            actual,
            synthetic,
            actual_phase_raw_by_arm_role=actual_raw,
            synthetic_artifact_raw_by_case=synthetic_raw,
        )
    except Exception as exc:
        # Preserve the already exported actual matrix and raw synthetic prefix.
        report = dict(
            schema_version="edge-window-cost-completion/v1",
            actual_applied_window_status="unavailable_under_existing_authority",
            original_normal_clock_evaluation=actual,
            actual_lifecycle=dict(
                evidence_kind="actual_existing_unconfined_software_lab",
                normal_stops=[],
                fault_prefixes=[],
                applied_window_exercised=False,
                expiry_commit_cost=None,
                pending_stop_loss_cost=None,
                active_deadline_wait=None,
                reasons=["completion_analysis_unavailable"],
            ),
            actual_cost_by_arm_role=[],
            synthetic_window_cases=[],
            blockers=[
                "completion_analysis_failed_" + type(exc).__name__,
                "synthetic_analysis_unavailable_originals_reference_synthetic-window-cases",
            ],
            authority_flags={
                name: False
                for name in (
                    "authorizes_transition",
                    "experiment",
                    "measurement_completed",
                    "production_admission",
                    "resume_authorized",
                )
            },
            whole_measurement_qualified=False,
            comparison_qualified=False,
            qualified_safety_count=None,
        )
    report["blockers"].extend(errors + read_errors)
    with (output / "window-cost-completion.json").open("xb") as stream:
        stream.write(wire(report))
    publish_publication(output)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-isolated-linux-root", action="store_true", required=True
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.output)
    print(
        json.dumps(
            dict(
                report=str(args.output / "window-cost-completion.json"),
                actual_applied_window_status=report["actual_applied_window_status"],
            )
        )
    )


if __name__ == "__main__":
    main()
