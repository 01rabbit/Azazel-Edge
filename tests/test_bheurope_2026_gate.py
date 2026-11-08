"""Contract tests for the Black Hat Europe evidence gate; no hardware required."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bheurope_gate", ROOT / "tools/arsenal_bheurope_2026.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

def _fixture(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(json.dumps({"kind": "action_decision", "trace_id": "demo:test"}) + "\n")
    result = {
        "execution": {"mode": "deterministic_replay", "ai_used": False,
                      "live_telemetry": False, "local_only": True, "trace_id": "demo:test"},
        "arbiter": {"action": "throttle"},
    }
    explanation = {"selected_action": "throttle", "rejected_actions": ["isolate"], "why_not_others": [{"action": "isolate", "reason": "bounded"}],
                   "release_condition": "manual review", "policy_profile": "demo",
                   "config_hash": "abc", "trace_id": "demo:test"}
    return result, explanation, audit

def test_valid_contract(tmp_path):
    assert module.validate(*_fixture(tmp_path))["ok"]

def test_ai_usage_is_rejected(tmp_path):
    result, explanation, audit = _fixture(tmp_path)
    result["execution"]["ai_used"] = True
    gate = module.validate(result, explanation, audit)
    assert not gate["ok"]
    assert any("ai_used" in problem for problem in gate["problems"])

def test_action_mismatch_is_rejected(tmp_path):
    result, explanation, audit = _fixture(tmp_path)
    explanation["selected_action"] = "isolate"
    assert not module.validate(result, explanation, audit)["ok"]

def test_missing_audit_is_rejected(tmp_path):
    result, explanation, audit = _fixture(tmp_path)
    audit.unlink()
    assert not module.validate(result, explanation, audit)["ok"]
