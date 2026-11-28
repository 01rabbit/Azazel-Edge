"""Offline unit tests for the Mac Arsenal recorder. No Mac/FFmpeg device required."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "arsenal_mac_recorder", ROOT / "tools/arsenal_bheurope_record_mac.py"
)
recorder = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(recorder)


def evidence_fixture(tmp_path: Path) -> None:
    chain = {"ok": True, "entries": 3, "error": ""}
    gate = {"ok": True, "trace_id": "demo:case", "action": "throttle",
            "chain_verification": chain}
    capture = {"recording_ready_replay": True, "trace_id": "demo:case",
               "selected_action": "throttle", "audit_clean": chain,
               "audit_modified_copy": {"ok": False, "error": "chain_hash_mismatch_at:1"}}
    (tmp_path / "gate.json").write_text(json.dumps(gate))
    (tmp_path / "capture-report.json").write_text(json.dumps(capture))
    (tmp_path / "explanations.jsonl").write_text(
        json.dumps({"trace_id": "demo:case", "selected_action": "throttle"}) + "\n"
    )
    (tmp_path / "audit.jsonl").write_text("{}\n")
    (tmp_path / "audit-tampered-COPY.jsonl").write_text("{}\n")


def test_matching_capture_evidence(tmp_path):
    evidence_fixture(tmp_path)
    out = recorder.verify_evidence(tmp_path)
    assert out["action"] == "throttle"
    assert out["trace_id"] == "demo:case"
    assert out["audit_entries"] == 3


@pytest.mark.parametrize("name", [
    "gate.json", "capture-report.json", "explanations.jsonl",
    "audit.jsonl", "audit-tampered-COPY.jsonl"
])
def test_missing_evidence_rejected(tmp_path, name):
    evidence_fixture(tmp_path)
    (tmp_path / name).unlink()
    with pytest.raises(recorder.CaptureError):
        recorder.verify_evidence(tmp_path)


def test_different_trace_rejected(tmp_path):
    evidence_fixture(tmp_path)
    gate = json.loads((tmp_path / "gate.json").read_text())
    gate["trace_id"] = "other"
    (tmp_path / "gate.json").write_text(json.dumps(gate))
    with pytest.raises(recorder.CaptureError):
        recorder.verify_evidence(tmp_path)


def test_unaudited_copy_rejected(tmp_path):
    evidence_fixture(tmp_path)
    capture = json.loads((tmp_path / "capture-report.json").read_text())
    capture["audit_modified_copy"] = {"ok": True, "error": ""}
    (tmp_path / "capture-report.json").write_text(json.dumps(capture))
    with pytest.raises(recorder.CaptureError):
        recorder.verify_evidence(tmp_path)


def test_recording_command_uses_video_only_avfoundation(tmp_path):
    command = recorder.ffmpeg_command("2", 45, tmp_path / "test.mp4")
    assert command[command.index("-i") + 1] == "2:none"
    assert command[command.index("-t") + 1] == "45"
    assert "-an" in command
    assert "libx264" in command


@pytest.mark.parametrize("device,duration", [("screen0", 45), ("1", 0), ("1", 1201)])
def test_invalid_capture_args_rejected(tmp_path, device, duration):
    with pytest.raises(recorder.CaptureError):
        recorder.ffmpeg_command(device, duration, tmp_path / "test.mp4")


def test_avfoundation_parses_screen_devices_even_when_list_exits_nonzero(monkeypatch):
    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = (
            "[AVFoundation indev @ 0x123] AVFoundation video devices:\\n"
            "[AVFoundation indev @ 0x123] [0] MacBook Pro camera [uid:a]\\n"
            "[AVFoundation indev @ 0x123] [1] Capture screen 0\\n"
            "[AVFoundation indev @ 0x123] [2] Capture screen 1\\n"
            "[AVFoundation indev @ 0x123] AVFoundation audio devices:\\n"
            "Error opening input file .\\n"
        )
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **kw: FakeResult())
    devices = recorder.avfoundation_video_devices()
    assert devices == {0: "MacBook Pro camera", 1: "Capture screen 0",
                       2: "Capture screen 1"}
    assert recorder.verified_screen_device("auto", 0) == "1"
    with pytest.raises(recorder.CaptureError, match="not 'Capture screen 0'"):
        recorder.verified_screen_device("0", 0)


def test_avfoundation_rejects_listing_without_screen(monkeypatch):
    class FakeResult:
        returncode = 1
        stdout = ""
        stderr = "AVFoundation video devices:\\n[0] Camera\\nAVFoundation audio devices:\\n"
    monkeypatch.setattr(recorder.subprocess, "run", lambda *a, **kw: FakeResult())
    with pytest.raises(recorder.CaptureError, match="No unique"):
        recorder.verified_screen_device("auto", 0)
