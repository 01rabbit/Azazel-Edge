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
    assert any(e.kind == "terminal" for e in first)
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

def test_scene_one_preserves_single_screen_review():
    timeline = director.scene_plan(1)
    kinds = [event.kind for event in timeline]
    assert kinds[0] == "replay"
    assert "scroll" in kinds
    assert kinds.index("replay") < kinds.index("terminal") < kinds.index("focus")
    assert all(event.kind in {"replay", "terminal", "focus", "scroll", "pointer"} for event in timeline)

def test_preview_timeline_includes_real_replay_and_ui_control():
    events = director.scene_plan(1, preview=True)
    assert [e.kind for e in events][:3] == ["replay", "terminal", "focus"]
    assert events[-1].second < 45
    assert any(e.kind == "scroll" for e in events)
    with pytest.raises(ValueError):
        director.scene_plan(2, preview=True)

def test_capture_window_target_is_maximized_but_not_native_fullscreen():
    assert director.expected_window((0, 0, 1440, 900)) == (2, 30, 1436, 867)
    assert director.expected_window((1440, 0, 1200, 800)) == (1442, 2, 1196, 795)
    assert director.geometry_within((3, 31, 1430, 865), (2, 30, 1436, 867))
    assert not director.geometry_within((120, 120, 800, 500), (2, 30, 1436, 867))


def test_browser_window_geometry_uses_document_bounds_not_accessibility_popup(monkeypatch):
    calls = []
    def fake_script(script):
        calls.append(script)
        return "2, 30, 1918, 1077|http://127.0.0.1:8776/"
    monkeypatch.setattr(director, "apple_script", fake_script)
    url, bounds = director.browser_window_state("Brave Browser")
    assert url == "http://127.0.0.1:8776/"
    assert bounds == (2, 30, 1916, 1047)
    assert "bounds of front window" in calls[0]
    assert "System Events" not in calls[0]


def test_browser_and_terminal_focus_are_fatal_if_unverified(monkeypatch):
    monkeypatch.setattr(director, "focus_browser", lambda name: None)
    monkeypatch.setattr(director, "apple_script", lambda script: "")
    monkeypatch.setattr(director.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(director, "browser_window_state",
                        lambda browser: ("http://127.0.0.1:8776", (2, 30, 1916, 1047)))
    monkeypatch.setattr(director, "browser_is_frontmost", lambda browser: False)
    with pytest.raises(director.recorder.CaptureError, match="failed verification"):
        director.position_and_verify_browser(
            "Brave Browser", (0, 0, 1920, 1080), "http://127.0.0.1:8776"
        )


def test_browser_rejects_wrong_url_or_tiny_window(monkeypatch):
    monkeypatch.setattr(director, "focus_browser", lambda name: None)
    monkeypatch.setattr(director, "apple_script", lambda script: "")
    monkeypatch.setattr(director.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(director, "browser_is_frontmost", lambda browser: True)
    monkeypatch.setattr(director, "browser_window_state",
                        lambda browser: ("http://example.test", (2, 30, 282, 47)))
    with pytest.raises(director.recorder.CaptureError, match="failed verification"):
        director.position_and_verify_browser(
            "Brave Browser", (0, 0, 1920, 1080), "http://127.0.0.1:8776"
        )


def test_only_local_console_can_be_opened():
    with pytest.raises(director.recorder.CaptureError, match="Only local"):
        director.open_dedicated_browser_window(
            "Brave Browser", "https://example.com"
        )
