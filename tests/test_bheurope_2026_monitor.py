"""Cross-platform dashboard contract checks; no HTTP socket required."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bheurope_monitor", ROOT / "tools/arsenal_bheurope_monitor.py")
monitor = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(monitor)

def test_missing_artifacts_are_safe(tmp_path):
    data = monitor.status(tmp_path)
    assert data["available"] is False
    assert data["audit_tail"] == []
    assert data["gate"] == {}

def test_artifact_projection(tmp_path):
    (tmp_path / "gate.json").write_text(json.dumps({"ok": True, "action": "throttle"}))
    (tmp_path / "explanations.jsonl").write_text(json.dumps({"selected_action": "throttle"}) + "\n")
    (tmp_path / "audit.jsonl").write_text(json.dumps({"kind": "action_decision"}) + "\n")
    data = monitor.status(tmp_path)
    assert data["available"] is True
    assert data["gate"]["ok"] is True
    assert data["explanation"]["selected_action"] == "throttle"
    assert data["audit_tail"][0]["kind"] == "action_decision"

def test_bad_json_does_not_crash(tmp_path):
    (tmp_path / "gate.json").write_text("{")
    (tmp_path / "audit.jsonl").write_text("broken\n")
    assert monitor.status(tmp_path)["available"] is False
    assert monitor.status(tmp_path)["audit_tail"] == []

def test_incident_console_is_read_only_and_keeps_raw_evidence():
    html = monitor.HTML
    assert "Security Operations Overview" in html
    assert "Incident Queue" in html
    assert "Incident Investigation" in html
    assert "Decision Alternatives" in html
    assert "Audit Evidence" in html
    assert "Evidence Timeline" in html
    assert "Raw evidence (JSONL / troubleshooting)" in html
    assert "SYNTHETIC REPLAY" in html
    assert "NO ENFORCEMENT" in html
    assert "replaceChildren()" in html
    assert "textContent" in html
    assert "fetch('/api/status'" in html
    assert "fetch('/api/execute'" not in html

def test_gate_failure_is_not_reported_as_a_verified_chain(tmp_path):
    (tmp_path / "gate.json").write_text(json.dumps({
        "ok": False,
        "chain_verification": {"ok": False, "entries": 0, "error": "mismatch"}
    }))
    assert monitor.status(tmp_path)["gate"]["chain_verification"]["ok"] is False

def test_valid_tamper_comparison_only_for_matching_capture(tmp_path):
    gate = {"ok": True, "action": "throttle", "trace_id": "demo:case",
            "chain_verification": {"ok": True, "entries": 3, "error": ""}}
    explanation = {"selected_action": "throttle", "trace_id": "demo:case"}
    report = {"recording_ready_replay": True, "selected_action": "throttle",
              "trace_id": "demo:case", "audit_clean": gate["chain_verification"],
              "audit_modified_copy": {"ok": False, "entries": 0,
                                      "error": "chain_hash_mismatch_at:1"}}
    (tmp_path / "gate.json").write_text(json.dumps(gate))
    (tmp_path / "explanations.jsonl").write_text(json.dumps(explanation) + "\n")
    (tmp_path / "capture-report.json").write_text(json.dumps(report))
    (tmp_path / "audit-tampered-COPY.jsonl").write_text("{}\n")
    result = monitor.status(tmp_path)
    assert result["audit_comparison"]["available"] is True
    assert result["audit_comparison"]["original"]["entries"] == 3
    assert result["audit_comparison"]["modified_copy"]["error"] == "chain_hash_mismatch_at:1"
    report["trace_id"] = "different-trace"
    (tmp_path / "capture-report.json").write_text(json.dumps(report))
    assert monitor.status(tmp_path)["audit_comparison"] == {}
    report["trace_id"] = "demo:case"
    (tmp_path / "capture-report.json").write_text(json.dumps(report))
    (tmp_path / "audit-tampered-COPY.jsonl").unlink()
    assert monitor.status(tmp_path)["audit_comparison"] == {}


def test_no_false_tamper_claim_on_missing_or_bad_capture(tmp_path):
    assert monitor.status(tmp_path)["audit_comparison"] == {}
    (tmp_path / "capture-report.json").write_text("{broken")
    assert monitor.status(tmp_path)["audit_comparison"] == {}
    assert "Modified COPY only" in monitor.HTML
    assert "No validated tamper comparison available" in monitor.HTML

def test_prominent_audit_comparison_layout_and_provenance():
    html = monitor.HTML
    assert 'class="audit-stage"' in html
    assert 'class="audit-comparison"' in html
    assert 'class="audit-result original"' in html
    assert 'class="audit-result modified"' in html
    assert 'id="original-check"' in html
    assert 'id="original-detail"' in html
    assert 'id="copy-check"' in html
    assert 'id="copy-error"' in html
    assert 'id="audit-provenance"' in html
    assert 'Synthetic offline replay' in html
    assert 'id="audit-trace"' in html
    assert 'id="audit-selected"' in html
    assert html.count('id="original-check"') == 1
    assert html.count('id="copy-check"') == 1
    assert "Raw evidence (JSONL / troubleshooting)" in html
