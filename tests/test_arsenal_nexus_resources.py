"""Nexus resource discovery must never imply unverified admission."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("arsenal_resources", ROOT / "tools/arsenal_nexus_resources.py")
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

def test_missing_pin_fails_closed(tmp_path):
    assert module.inspect_edge_pin(tmp_path / "absent.json", tmp_path)["status"] == "invalid_pin"

def test_linux_elf_is_not_mac_runtime(tmp_path):
    pin = tmp_path / "pin.json"
    pin.write_text(json.dumps({"contract": "azazel-edge-core/nexus-pin/v2", "architectures": {}}))
    with patch.object(module.platform, "system", return_value="Darwin"):
        assert module.inspect_edge_pin(pin, tmp_path)["status"] == "unsupported_platform"

def test_knowledge_presence_is_not_verification(tmp_path):
    bundle = tmp_path / "lite.tar.gz"
    bundle.write_bytes(b"not a real signed bundle")
    assert module.inspect_knowledge(bundle)["status"] == "present_unverified"

def test_no_resources_are_admitted(tmp_path):
    result = module.inspect_resources(tmp_path / "pin.json", tmp_path, tmp_path / "lite.tar.gz")
    assert result["admitted"] is False
    assert result["nexus_runtime_required"] is False
