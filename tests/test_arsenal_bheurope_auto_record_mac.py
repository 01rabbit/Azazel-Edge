"""Offline tests for the Mac automated Arsenal recording director."""
from __future__ import annotations
import ast
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
spec = importlib.util.spec_from_file_location(
    "arsenal_automation", ROOT / "tools/arsenal_bheurope_auto_record_mac.py"
)
director = importlib.util.module_from_spec(spec)
assert spec.loader
sys.modules[spec.name] = director
spec.loader.exec_module(director)


def test_scene_timelines_fit_recording_window():
    assert len(director.SCENES) == 4
    assert sum(duration for _, duration in director.SCENES.values()) == 600
    for n, (_, duration) in director.SCENES.items():
        events = director.scene_plan(n)
        assert events == tuple(sorted(events, key=lambda event: event.second))
        assert all(0 < e.second < duration for e in events)
        assert len(events) > 1


def test_scene_one_is_real_replay_not_fake_ui():
    first = director.scene_plan(1)
    assert first[0].kind == "replay"
    assert all(e.kind != "terminal" for e in first)
    assert any(e.kind == "scroll" for e in first)
    source = (ROOT / "tools/arsenal_bheurope_auto_record_mac.py").read_text()
    assert "tools/arsenal_bheurope_2026.py" in source
    assert "P0AuditLogger.verify_chain" in source
    assert '"audit-tampered-COPY.jsonl"' in source
    assert "recording_ready_replay" in source
    assert "no live traffic enforcement" in source.lower() or "no network enforcement" in source.lower()


def test_no_network_enforcement_or_silent_result_replacement():
    source = (ROOT / "tools/arsenal_bheurope_auto_record_mac.py").read_text()
    assert "maybe_enforce(" not in source
    assert "AZAZEL_DEFENSE_ENFORCE=1" not in source
    assert "socket.send" not in source
    assert "ffmpeg_command(args.device, duration, video)" in source
    assert "scene_dir / \"fresh-replay\"" in source


def test_browser_allowlist():
    assert "Brave Browser" in director.BROWSERS
    assert "Google Chrome" in director.BROWSERS
    assert "Safari" in director.BROWSERS
    assert "Unknown App" not in director.BROWSERS


def test_all_scripted_actions_supported():
    allowed = {"replay", "terminal", "focus", "pointer", "scroll"}
    for n in director.SCENES:
        assert all(event.kind in allowed for event in director.scene_plan(n))


def test_real_replay_function_requires_validated_report(tmp_path, monkeypatch):
    # No real command is launched in this unit check: safely reject bad fixture.
    class FakeCompleted:
        returncode = 1
        stdout = ""
        stderr = "replay unavailable"
    monkeypatch.setattr(director.subprocess, "run", lambda *a, **kw: FakeCompleted())
    with pytest.raises(director.recorder.CaptureError, match="Genuine replay failed"):
        director.generate_real_replay(tmp_path / "fresh", Path("/usr/bin/python3"))

def test_scene_one_displays_real_replay_output_before_returning_to_console():
    timeline = director.scene_plan(1)
    kinds = [event.kind for event in timeline]
    assert kinds[0] == "replay"
    assert "scroll" in kinds
    assert "terminal" not in kinds
    import inspect
    source = inspect.getsource(director.show_actual_terminal_log)
    assert 'replay log' in source
    assert 'cat ' in source

def test_preview_timeline_includes_real_replay_and_ui_control():
    events = director.scene_plan(1, preview=True)
    assert [e.kind for e in events][:2] == ["replay", "scroll"]
    assert all(e.kind != "terminal" for e in events)
    assert events[-1].second < 45
    assert any(e.kind == "scroll" for e in events)
    with pytest.raises(ValueError):
        director.scene_plan(2, preview=True)
