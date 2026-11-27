#!/usr/bin/env python3
"""Black Hat Europe 2026 Mac screen-recording orchestrator (read-only).

Captures the selected macOS display with FFmpeg's AVFoundation input.
Only displays already verified synthetic replay evidence. It neither
generates fake output nor triggers network enforcement.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
BRANCH = "arsenal/bheurope-2026"
DEFAULT_EVIDENCE = ROOT / "artifacts/bheurope-2026/mac-capture-20261126T100955Z"


class CaptureError(Exception):
    pass


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise CaptureError(f"Unable to read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CaptureError(f"Expected a JSON object in {path}")
    return value


def verify_evidence(folder: Path) -> dict:
    """Verify gate, trace and capture result consistency before recording."""
    gate = read_json(folder / "gate.json")
    capture = read_json(folder / "capture-report.json")
    explanation_path = folder / "explanations.jsonl"
    try:
        lines = [json.loads(s) for s in explanation_path.read_text(encoding="utf-8").splitlines() if s.strip()]
    except (OSError, ValueError) as exc:
        raise CaptureError(f"Invalid explanation JSONL: {exc}") from exc
    if not lines or not isinstance(lines[-1], dict):
        raise CaptureError("Missing explanation record")
    explanation = lines[-1]
    if gate.get("ok") is not True or capture.get("recording_ready_replay") is not True:
        raise CaptureError("Replay/capture gate has not passed")
    trace = gate.get("trace_id")
    action = gate.get("action")
    if not trace or not action or not all(
        d.get("trace_id") == trace and d.get("selected_action") == action
        for d in (capture, explanation)
    ):
        raise CaptureError("Trace/action mismatch among replay evidence files")
    clean = capture.get("audit_clean")
    altered = capture.get("audit_modified_copy")
    if (not isinstance(clean, dict) or clean != gate.get("chain_verification")
            or clean.get("ok") is not True or clean.get("entries", 0) < 1
            or not isinstance(altered, dict) or altered.get("ok") is not False
            or not altered.get("error")
            or not (folder / "audit.jsonl").is_file()
            or not (folder / "audit-tampered-COPY.jsonl").is_file()):
        raise CaptureError("Original-chain/modified-copy evidence not complete")
    return {"trace_id": trace, "action": action, "audit_entries": clean["entries"],
            "tamper_error": altered["error"], "evidence_dir": str(folder)}


def branch_name() -> str:
    result = subprocess.run(
        ["git", "branch", "--show-current"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def require_branch() -> None:
    current = branch_name()
    if current != BRANCH:
        raise CaptureError(f"Wrong working branch: {current!r}; expected {BRANCH}")


def require_program(name: str) -> None:
    from shutil import which
    if which(name) is None:
        raise CaptureError(f"{name} is missing. Install FFmpeg (e.g. brew install ffmpeg).")


def ffmpeg_command(device: str, duration: int, path: Path) -> list[str]:
    """Record video only; English narration is added in post-production."""
    if not device.isdigit():
        raise CaptureError("Screen device must be a number listed by --list-devices")
    if not 1 <= duration <= 1200:
        raise CaptureError("Duration must be between 1 and 1200 seconds")
    return [
        "ffmpeg", "-hide_banner", "-loglevel", "warning",
        "-f", "avfoundation", "-framerate", "30",
        "-capture_cursor", "1", "-i", f"{device}:none",
        "-t", str(duration),
        "-an", "-c:v", "libx264", "-preset", "veryfast",
        "-crf", "18", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
        "-y", str(path)
    ]


def video_properties(path: Path) -> dict:
    p = subprocess.run(
        ["ffprobe", "-v", "error", "-select_streams", "v:0",
         "-show_entries", "stream=width,height,r_frame_rate,codec_name",
         "-show_entries", "format=duration", "-of", "json", str(path)],
        capture_output=True, text=True
    )
    if p.returncode:
        raise CaptureError(f"Video validation failed: {p.stderr.strip()}")
    try:
        info = json.loads(p.stdout)
        stream = info["streams"][0]
        duration = float(info["format"]["duration"])
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise CaptureError(f"Invalid ffprobe result: {exc}") from exc
    if duration < 1 or stream.get("width", 0) < 640 or stream.get("height", 0) < 360:
        raise CaptureError(f"Video has insufficient duration/resolution: {info}")
    return {"width": stream["width"], "height": stream["height"],
            "frame_rate": stream.get("r_frame_rate"), "codec": stream.get("codec_name"),
            "duration_seconds": duration}


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def wait_for_monitor(url: str, trace: str, timeout: int = 12) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                status = json.loads(response.read())
            if status.get("gate", {}).get("trace_id") == trace and status.get("audit_comparison", {}).get("available"):
                return
        except (URLError, OSError, ValueError):
            pass
        time.sleep(0.5)
    raise CaptureError("Local monitor did not serve the expected verified trace and audit comparison")


def record(args: argparse.Namespace, evidence: dict) -> Path:
    require_program("ffmpeg")
    require_program("ffprobe")
    python = ROOT / ".venv/bin/python"
    if not python.is_file():
        raise CaptureError("Python replay venv is missing: .venv/bin/python")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = ROOT / "artifacts/bheurope-2026/recordings" / f"{args.mode}-{stamp}"
    output.mkdir(parents=True, exist_ok=False)
    video = output / f"{args.mode}.mp4"
    port = args.port
    url = f"http://127.0.0.1:{port}"
    command = [str(python), str(ROOT / "tools/arsenal_bheurope_monitor.py"),
               "--artifacts", str(args.evidence), "--port", str(port)]
    with (output / "monitor.log").open("w", encoding="utf-8") as log:
        server = subprocess.Popen(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        try:
            wait_for_monitor(url + "/api/status", evidence["trace_id"])
            if not args.no_open:
                subprocess.run(["open", url], check=True)
            print(f"Read-only console: {url}")
            print("Screen recording requires macOS Screen Recording permission for your terminal/FFmpeg.")
            print(f"Recording in {args.delay} seconds. Select a clean browser window/full-screen view.")
            for left in range(args.delay, 0, -1):
                print(f"  {left}...", flush=True)
                time.sleep(1)
            screen = ffmpeg_command(args.device, args.duration, video)
            print("Starting screen recording. This captures NO microphone audio.")
            with (output / "ffmpeg.log").open("w", encoding="utf-8") as fflog:
                process = subprocess.Popen(screen, cwd=ROOT, stdin=subprocess.DEVNULL,
                                           stdout=fflog, stderr=subprocess.STDOUT)
                try:
                    result = process.wait()
                except KeyboardInterrupt:
                    process.send_signal(signal.SIGINT)
                    result = process.wait(timeout=12)
                    print("Recording stopped by operator.")
            if result != 0:
                raise CaptureError(f"FFmpeg exited with {result}. Review {output / 'ffmpeg.log'}")
            properties = video_properties(video)
            manifest = {
                "created_at_utc": stamp,
                "purpose": "Black Hat Europe 2026 Arsenal genuine macOS offline replay screen capture",
                "mode": args.mode, "branch": BRANCH, "commit": subprocess.run(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
                ).stdout.strip(),
                "screen_device": args.device, "evidence": evidence,
                "filename": video.name, "sha256": sha256(video),
                "video": properties, "no_microphone_recorded": True,
                "limitations": "macOS offline synthetic replay; no live network enforcement; no Raspberry Pi proof"
            }
            (output / "capture-manifest.json").write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
            print(f"CAPTURE PASS: {video}")
            print(json.dumps(properties, indent=2))
            return video
        finally:
            server.terminate()
            try:
                server.wait(timeout=4)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["check", "list-devices", "test", "record"])
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--device", help="AVFoundation Capture screen index from list-devices")
    parser.add_argument("--duration", type=int, help="Recording length in seconds (test defaults 45, record 600)")
    parser.add_argument("--delay", type=int, default=8, help="Countdown before recording starts")
    parser.add_argument("--port", type=int, default=8776, help="Isolated local monitor port")
    parser.add_argument("--no-open", action="store_true", help="Do not open browser automatically")
    args = parser.parse_args()
    try:
        if sys.platform != "darwin":
            raise CaptureError("This orchestrator records only on macOS")
        require_branch()
        details = verify_evidence(args.evidence.expanduser().resolve())
        print("Replay evidence ready:", json.dumps(details, ensure_ascii=False))
        if args.mode == "check":
            require_program("ffmpeg")
            require_program("ffprobe")
            print(f"READY TO TEST on {platform.platform()} (screen index not yet selected)")
        elif args.mode == "list-devices":
            require_program("ffmpeg")
            print("AVFoundation devices are shown below. Select a 'Capture screen' index:")
            subprocess.run(["ffmpeg", "-hide_banner", "-f", "avfoundation",
                            "-list_devices", "true", "-i", ""], check=False)
        else:
            if not args.device:
                raise CaptureError("Provide --device N after running list-devices")
            args.duration = args.duration or (45 if args.mode == "test" else 600)
            if args.delay < 0 or args.delay > 60:
                raise CaptureError("--delay must be between 0 and 60")
            if args.port < 1024 or args.port > 65535:
                raise CaptureError("--port must be 1024–65535")
            record(args, details)
        return 0
    except (CaptureError, OSError, subprocess.CalledProcessError) as exc:
        print(f"CAPTURE NOT READY: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
