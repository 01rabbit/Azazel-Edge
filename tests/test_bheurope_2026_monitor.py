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
