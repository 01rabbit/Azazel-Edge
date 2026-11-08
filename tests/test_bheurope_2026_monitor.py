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
