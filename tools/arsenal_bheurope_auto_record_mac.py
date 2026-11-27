#!/usr/bin/env python3
"""Automated silent Arsenal screen direction on a Mac.

Scene 1 invokes the REAL synthetic replay in a fresh evidence folder while
recording. Scenes 2–4 review an existing validated capture. Never enables
network enforcement, creates pretend status JSON, or records microphone audio.
Browser focus and mouse/scroll require macOS Accessibility permission.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shlex
import signal
import subprocess
import sys
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import arsenal_bheurope_record_mac as recorder

SCENES = {
    1: ("incident-decision", 120),
    2: ("decision-explanation", 180),
    3: ("audit-integrity", 180),
    4: ("operator-review", 120),
}
BROWSERS = {"Brave Browser", "Google Chrome", "Safari"}


@dataclass(frozen=True)
class Event:
    second: int
    kind: str
    value: int = 0


def scene_plan(number: int) -> tuple[Event, ...]:
    # Timings in seconds, all values under the corresponding scene duration.
    if number == 1:
        return (Event(6, "replay"), Event(17, "terminal"), Event(30, "focus"), Event(37, "scroll", 520),
                Event(68, "scroll", 590), Event(92, "scroll", -1110))
    if number == 2:
        return (Event(8, "scroll", 1000), Event(30, "pointer", 62),
                Event(53, "scroll", 420), Event(83, "scroll", -440),
                Event(113, "scroll", -980), Event(150, "scroll", 920))
    if number == 3:
        return (Event(12, "pointer", 68), Event(35, "pointer", 32),
                Event(64, "scroll", 700), Event(95, "scroll", -700),
                Event(126, "pointer", 72), Event(150, "pointer", 30))
    if number == 4:
        return (Event(9, "scroll", 1020), Event(39, "scroll", 620),
                Event(70, "scroll", -650), Event(90, "scroll", -1000))
    raise ValueError(number)


def screen_backend():
    # macOS Quartz via OS frameworks; no accessibility automation libraries.
    import ctypes.util
    lib = ctypes.CDLL(ctypes.util.find_library("ApplicationServices"))
    lib.AXIsProcessTrusted.restype = ctypes.c_bool
    return lib


class CGPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]


class CGSize(ctypes.Structure):
    _fields_ = [("width", ctypes.c_double), ("height", ctypes.c_double)]


class CGRect(ctypes.Structure):
    _fields_ = [("origin", CGPoint), ("size", CGSize)]


def mouse_and_scroll(lib, kind: str, value: int = 0) -> None:
    lib.CGMainDisplayID.restype = ctypes.c_uint32
    lib.CGDisplayBounds.argtypes = [ctypes.c_uint32]
    lib.CGDisplayBounds.restype = CGRect
    r = lib.CGDisplayBounds(lib.CGMainDisplayID())
    x = r.origin.x + r.size.width * (0.68 if value == 68 else 0.32 if value == 32 else 0.54)
    y = r.origin.y + r.size.height * 0.49
    lib.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
    lib.CFRelease.argtypes = [ctypes.c_void_p]
    if kind in ("pointer", "scroll"):
        lib.CGEventCreateMouseEvent.restype = ctypes.c_void_p
        lib.CGEventCreateMouseEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, CGPoint, ctypes.c_uint32]
        event = lib.CGEventCreateMouseEvent(None, 5, CGPoint(x, y), 0)
        if not event:
            raise recorder.CaptureError("macOS mouse automation failed")
        try:
            lib.CGEventPost(0, event)
        finally:
            lib.CFRelease(event)
    if kind == "scroll":
        lib.CGEventCreateScrollWheelEvent.restype = ctypes.c_void_p
        lib.CGEventCreateScrollWheelEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_int]
        remaining = value
        while remaining:
            step = max(-100, min(100, remaining))
            event = lib.CGEventCreateScrollWheelEvent(None, 1, 1, -step)
            if not event:
                raise recorder.CaptureError("macOS scrolling failed")
            try:
                lib.CGEventPost(0, event)
            finally:
                lib.CFRelease(event)
            remaining -= step
            time.sleep(0.075)


def focus_browser(browser: str) -> None:
    if browser not in BROWSERS:
        raise recorder.CaptureError("Unsupported browser: " + browser)
    script = f'tell application "{browser}" to activate'
    subprocess.run(["osascript", "-e", script], check=True, capture_output=True, text=True)


def show_actual_terminal_log(logpath: Path) -> None:
    """Display only stdout/stderr actually captured from the replay subprocess."""
    if not logpath.is_file():
        raise recorder.CaptureError("No genuine replay log to show in Terminal")
    command = "cat " + shlex.quote(str(logpath))
    # One actual command in a new Terminal session, not a synthetic status graphic.
    applescript_command = command.replace("\\", "\\\\").replace('"', '\\"')
    script = 'tell application "Terminal" to do script "' + applescript_command + '"'
    subprocess.run(["osascript", "-e", script], check=True, capture_output=True, text=True)


def generate_real_replay(folder: Path, python: Path) -> dict:
    """Run genuine replay and independently validate its saved chain and altered COPY."""
    folder.mkdir(parents=True, exist_ok=True)
    p = subprocess.run([str(python), str(ROOT / "tools/arsenal_bheurope_2026.py"),
                        "--out", str(folder)], cwd=ROOT, capture_output=True, text=True)
    (folder / "replay-process.log").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
    if p.returncode:
        raise recorder.CaptureError("Genuine replay failed; inspect replay-process.log")
    sys.path.insert(0, str(ROOT / "py"))
    from azazel_edge.audit.logger import P0AuditLogger
    gate = recorder.read_json(folder / "gate.json")
    explanations = [json.loads(line) for line in
                    (folder / "explanations.jsonl").read_text(encoding="utf-8").splitlines()
                    if line.strip()]
    if gate.get("ok") is not True or not explanations:
        raise recorder.CaptureError("Replay gate did not pass")
    e = explanations[-1]
    if gate.get("trace_id") != e.get("trace_id") or gate.get("action") != e.get("selected_action"):
        raise recorder.CaptureError("Replay action/trace mismatch")
    original = folder / "audit.jsonl"
    original_check = P0AuditLogger.verify_chain(original)
    if original_check.get("ok") is not True or original_check.get("entries", 0) < 1:
        raise recorder.CaptureError("Replay audit failed verification")
    if original_check != gate.get("chain_verification"):
        raise recorder.CaptureError("Audit and gate verification differ")
    altered_path = folder / "audit-tampered-COPY.jsonl"
    rows = original.read_text(encoding="utf-8").splitlines()
    first = json.loads(rows[0])
    first["source"] = str(first.get("source", "")) + "-modified-for-demonstration"
    rows[0] = json.dumps(first, ensure_ascii=False)
    altered_path.write_text("\n".join(rows) + "\n", encoding="utf-8")
    altered_check = P0AuditLogger.verify_chain(altered_path)
    if altered_check.get("ok") is not False or not altered_check.get("error"):
        raise recorder.CaptureError("Modified-copy tamper detection did not fail")
    report = {"recording_ready_replay": True, "selected_action": e["selected_action"],
              "trace_id": e["trace_id"], "release_condition": e.get("release_condition"),
              "policy_profile": e.get("policy_profile"), "config_hash": e.get("config_hash"),
              "rejected_actions": e.get("rejected_actions"),
              "why_not_others": e.get("why_not_others"),
              "audit_clean": original_check, "audit_modified_copy": altered_check,
              "limits": "synthetic offline macOS replay, no live traffic enforcement"}
    (folder / "capture-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return recorder.verify_evidence(folder)


def run_scene(number: int, args, lib, existing: dict, run_root: Path) -> dict:
    title, default_duration = SCENES[number]
    duration = args.duration if args.duration and len(args.scenes) == 1 else default_duration
    events = scene_plan(number)
    if duration < max(e.second for e in events) + 5:
        raise recorder.CaptureError("Duration is shorter than the scripted events")
    scene_dir = run_root / f"{number:02d}-{title}"
    scene_dir.mkdir(parents=True, exist_ok=False)
    evidence_dir = scene_dir / "fresh-replay" if number == 1 else args.evidence.resolve()
    # Scene 1 MUST start empty; no pre-generated decision displayed before replay.
    port = args.port
    python = ROOT / ".venv/bin/python"
    if not python.exists():
        raise recorder.CaptureError("Missing .venv/bin/python")
    monitor = [str(python), str(ROOT / "tools/arsenal_bheurope_monitor.py"),
               "--artifacts", str(evidence_dir), "--port", str(port)]
    video = scene_dir / (title + ".mp4")
    start_log = {"scene": number, "title": title, "planned_duration": duration,
                 "events": [e.__dict__ for e in events]}
    (scene_dir / "plan.json").write_text(json.dumps(start_log, indent=2))
    with (scene_dir / "monitor.log").open("w") as logfile:
        server = subprocess.Popen(monitor, cwd=ROOT, stdout=logfile, stderr=subprocess.STDOUT)
        try:
            # Health check only; scene 1 initially contains no evidence.
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1) as r:
                        payload = json.loads(r.read())
                    if number == 1 or payload.get("gate", {}).get("trace_id") == existing["trace_id"]:
                        break
                except Exception:
                    pass
                if time.monotonic() >= deadline:
                    raise recorder.CaptureError("Local monitor did not start with expected state")
                time.sleep(.25)
            subprocess.run(["open", "-a", args.browser, f"http://127.0.0.1:{port}"], check=True)
            time.sleep(1)
            focus_browser(args.browser)
            print(f"SCENE {number}: {title}. Recording after {args.delay}s countdown.")
            time.sleep(args.delay)
            cmd = recorder.ffmpeg_command(args.device, duration, video)
            events_done = []
            with (scene_dir / "ffmpeg.log").open("w") as log:
                proc = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=subprocess.STDOUT)
                clock = time.monotonic()
                try:
                    for event in events:
                        until = clock + event.second
                        while time.monotonic() < until:
                            if proc.poll() is not None:
                                raise recorder.CaptureError("Recorder exited early; inspect ffmpeg.log")
                            time.sleep(max(0.0, min(.2, until-time.monotonic())))
                        if event.kind == "replay":
                            result = generate_real_replay(evidence_dir, python)
                            events_done.append({"second": event.second, "action": "real synthetic replay", "result": result})
                        elif event.kind == "terminal":
                            show_actual_terminal_log(evidence_dir / "replay-process.log")
                            events_done.append({"second": event.second, "action": "show genuine terminal replay output"})
                        elif event.kind == "focus":
                            focus_browser(args.browser)
                            events_done.append({"second": event.second, "action": "focus browser"})
                        else:
                            mouse_and_scroll(lib, event.kind, event.value)
                            events_done.append({"second": event.second, "action": event.kind, "value": event.value})
                    code = proc.wait(timeout=max(20, duration + 20))
                except BaseException:
                    if proc.poll() is None:
                        proc.send_signal(signal.SIGINT)
                        try:
                            proc.wait(timeout=8)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                    raise
            if code != 0:
                raise recorder.CaptureError("FFmpeg failed; inspect scene ffmpeg.log")
            properties = recorder.video_properties(video)
            if number == 1:
                verified = recorder.verify_evidence(evidence_dir)
            else:
                verified = existing
            manifest = {"scene": number, "title": title,
                        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                        "branch": recorder.BRANCH,
                        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"],
                                                          cwd=ROOT, text=True).strip(),
                        "screen_device": args.device,
                        "actual_evidence": verified, "event_log": events_done,
                        "file": str(video), "sha256": recorder.sha256(video),
                        "video": properties,
                        "no_audio": True, "synthetic_no_enforcement": True}
            (scene_dir / "capture-manifest.json").write_text(json.dumps(manifest, indent=2))
            print("SCENE CAPTURE PASS:", video)
            return manifest
        finally:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scene", default="1", choices=["1", "2", "3", "4", "all"])
    ap.add_argument("--device", required=True, help="AVFoundation screen index, e.g. 3")
    ap.add_argument("--browser", default="Brave Browser", choices=sorted(BROWSERS))
    ap.add_argument("--delay", type=int, default=8)
    ap.add_argument("--port", type=int, default=8776)
    ap.add_argument("--duration", type=int, help="Single-scene duration override")
    ap.add_argument("--evidence", type=Path, default=recorder.DEFAULT_EVIDENCE)
    ap.add_argument("--dry-run", action="store_true", help="Validate plan without recording or UI actions")
    args = ap.parse_args()
    try:
        if sys.platform != "darwin":
            raise recorder.CaptureError("Mac-only automation")
        recorder.require_branch()
        recorder.require_program("ffmpeg")
        recorder.require_program("ffprobe")
        validated = recorder.verify_evidence(args.evidence.resolve())
        args.scenes = list(SCENES) if args.scene == "all" else [int(args.scene)]
        if not args.device.isdigit() or args.delay < 0 or args.delay > 60:
            raise recorder.CaptureError("Invalid screen index or countdown delay")
        for n in args.scenes:
            duration = args.duration if args.duration and len(args.scenes)==1 else SCENES[n][1]
            if not 30 <= duration <= 1200 or duration < max(e.second for e in scene_plan(n))+5:
                raise recorder.CaptureError("Recording duration does not fit the scene timeline")
        print("Verified source evidence:", validated)
        print("Scene plan:", [(n, SCENES[n][0]) for n in args.scenes])
        if args.dry_run:
            print("DRY RUN PASS: no screen action or capture performed")
            return 0
        lib = screen_backend()
        if not lib.AXIsProcessTrusted():
            raise recorder.CaptureError(
                "Accessibility permission required. System Settings > Privacy & Security > Accessibility: enable your Terminal app, then restart it."
            )
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        output = ROOT / "artifacts/bheurope-2026/auto-recordings" / stamp
        output.mkdir(parents=True, exist_ok=False)
        for n in args.scenes:
            run_scene(n, args, lib, validated, output)
        print("AUTOMATED CAPTURE COMPLETE:", output)
        print("Review recordings and manifests before using in the final Arsenal edit.")
        return 0
    except (recorder.CaptureError, OSError, subprocess.CalledProcessError, ValueError) as exc:
        print("AUTOMATION NOT COMPLETE:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
