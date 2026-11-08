"""Knowledge verifier adapter must fail closed without producer dependency."""
from __future__ import annotations
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("arsenal_knowledge_verify", ROOT / "tools/arsenal_knowledge_verify.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

def test_missing_inputs_refused(tmp_path):
    result = module.verify(tmp_path / "absent.tar.gz", tmp_path / "anchors.toml", tmp_path / "state.toml")
    assert result["ok"] is False
    assert result["status"] == "missing_input"

def test_fixture_anchor_refused_without_fixture_mode(tmp_path):
    bundle = tmp_path / "lite.tar.gz"
    anchor = tmp_path / "fixture-anchors.toml"
    state = tmp_path / "state.toml"
    for path in (bundle, anchor, state):
        path.write_bytes(b"placeholder")
    result = module.verify(bundle, anchor, state)
    assert result["ok"] is False
    assert result["status"] == "fixture_anchor_refused"
