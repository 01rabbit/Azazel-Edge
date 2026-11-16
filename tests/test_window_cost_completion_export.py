"""SYNTHETIC read/failure preservation; no actual process matrix or APPLIED action."""

import json

import run_window_cost_completion as runner
import window_cost_completion_lab as lab


def test_one_unreadable_leaf_preserves_valid_siblings_and_reports_blocker(tmp_path, monkeypatch):
    result = lab.run_synthetic_window_cases(tmp_path / "cases")
    first = result["cases"][0]
    missing = first["artifacts"]["phase"]["path"]
    original_read = runner._read

    def read(descriptor, maximum):
        if descriptor["path"] == missing:
            raise PermissionError("SYNTHETIC unavailable leaf")
        return original_read(descriptor, maximum)

    monkeypatch.setattr(runner, "_read", read)
    errors = []
    raw = runner.collect_synthetic_raw(result, errors=errors)
    assert raw[first["id"]]["phase"] is None
    assert raw[first["id"]]["journal"]
    assert raw[first["id"]]["observations"]
    assert raw[result["cases"][1]["id"]]["phase"]
    assert errors == [first["id"] + ".phase_synthetic_read_failed_PermissionError"]


def test_unexpected_case_failure_retains_prior_and_later_actual_synthetic_calls(tmp_path, monkeypatch):
    original_case = lab._case
    called = []

    def fail_one(work, recipe):
        called.append(recipe["id"])
        recorded = original_case(work, recipe)
        if recipe["id"] == "expiry_commit":
            (work / recipe["id"] / "private-key").write_bytes(b"DO NOT EXPORT")
            raise RuntimeError("SYNTHETIC unexpected case failure after real collector calls")
        return recorded

    monkeypatch.setattr(lab, "_case", fail_one)
    actual = {"original_load_evaluation": {"original_arm_inputs": []}}
    actual_calls = []
    monkeypatch.setattr(runner.original, "run", lambda: actual_calls.append("once") or actual)

    def export_original(report, output):
        assert report is actual
        output.mkdir()
        (output / "prior-public.raw").write_bytes(b"SYNTHETIC original public evidence")

    monkeypatch.setattr(runner.original, "export_public", export_original)
    top = runner.run(tmp_path / "output")
    case_directory = tmp_path / "output/synthetic-window-cases"
    result = json.loads((case_directory / "manifest.json").read_bytes())
    assert actual_calls == ["once"]
    assert top["original_normal_clock_evaluation"] == actual
    assert "synthetic_case_failed_expiry_commit_RuntimeError" in top["blockers"]
    assert (tmp_path / "output/original-normal-clock/prior-public.raw").read_bytes() == b"SYNTHETIC original public evidence"
    protocol = json.loads(lab.PROTOCOL.read_bytes())
    assert called == [recipe["id"] for recipe in protocol["cases"]]
    assert len(set(called)) == len(called)
    assert result["cases"][0]["observations"]["callback_log"]
    failed = result["cases"][1]
    assert failed["id"] == "expiry_commit"
    assert failed["case_error"] == "RuntimeError"
    assert failed["evidence_kind"] == lab.EVIDENCE
    assert failed["applied_premise"] == lab.PREMISE
    assert "observations" not in failed and "phase_report" not in failed
    assert set(failed["artifacts"]) == {"event", "policy", "observations", "journal", "phase"}
    assert "private-key" not in json.dumps(failed)
    assert result["cases"][2]["observations"]["control_receipt"]
    assert result["blockers"] == ["synthetic_case_failed_expiry_commit_RuntimeError"]
    assert json.loads((case_directory / "manifest.json").read_bytes()) == result
    assert runner.collect_synthetic_raw(result)["expiry_commit"]["journal"]


def test_unexpected_bundle_and_analysis_failure_keep_original_public_export(tmp_path, monkeypatch):
    actual = {"schema_version": "SYNTHETIC-original-report", "original_load_evaluation": {"original_arm_inputs": []}}
    calls = []
    monkeypatch.setattr(runner.original, "run", lambda: calls.append("actual_once") or actual)

    def export(report, output):
        assert report is actual
        calls.append("export_original")
        output.mkdir()
        (output / "prior-public.raw").write_bytes(b"SYNTHETIC original public evidence")

    def fail_bundle(output):
        assert calls == ["actual_once", "export_original"]
        output.mkdir()
        (output / "prefix.raw").write_bytes(b"SYNTHETIC retained failure prefix")
        raise RuntimeError("SYNTHETIC bundle unavailable")

    def fail_analysis(*args, **kwargs):
        raise ValueError("SYNTHETIC analysis unavailable")

    monkeypatch.setattr(runner.original, "export_public", export)
    monkeypatch.setattr(runner, "run_synthetic_window_cases", fail_bundle)
    monkeypatch.setattr(runner, "analyze_window_cost_completion", fail_analysis)
    report = runner.run(tmp_path / "output")
    assert calls == ["actual_once", "export_original"]
    assert report["original_normal_clock_evaluation"] == actual
    assert set(report) == {
        "schema_version", "actual_applied_window_status", "original_normal_clock_evaluation",
        "actual_lifecycle", "actual_cost_by_arm_role", "synthetic_window_cases", "blockers",
        "authority_flags", "whole_measurement_qualified", "comparison_qualified", "qualified_safety_count",
    }
    assert report["actual_cost_by_arm_role"] == report["synthetic_window_cases"] == []
    assert report["actual_lifecycle"]["reasons"] == ["completion_analysis_unavailable"]
    assert report["actual_lifecycle"]["active_deadline_wait"] is None
    assert report["blockers"] == [
        "completion_analysis_failed_ValueError",
        "synthetic_analysis_unavailable_originals_reference_synthetic-window-cases",
        "synthetic_bundle_failed_RuntimeError",
    ]
    assert report["qualified_safety_count"] is None
    assert report["whole_measurement_qualified"] is False
    assert all(value is False for value in report["authority_flags"].values())
    assert (tmp_path / "output/original-normal-clock/prior-public.raw").read_bytes() == b"SYNTHETIC original public evidence"
    assert (tmp_path / "output/synthetic-window-cases/prefix.raw").read_bytes() == b"SYNTHETIC retained failure prefix"
    assert json.loads((tmp_path / "output/window-cost-completion.json").read_bytes()) == report
