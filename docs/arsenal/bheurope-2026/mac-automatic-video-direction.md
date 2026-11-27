# Black Hat Europe 2026 — Automatic Mac Video Director

**Target branch:** `arsenal/bheurope-2026` only; leave `main` as-is.

The automated director:
1. Verifies that actual replay, decision and audit records from Mac are coherent.
2. Starts the **read-only** Incident Console using a temporary port (default 8776).
3. Opens the local page in Brave, Chrome or Safari and attempts fullscreen.
4. Starts FFmpeg screen capture with **no audio**.
5. Drives the mouse cursor, scroll position, and window focus via macOS Quartz/AppleScript.
6. In Scene 1 only, invokes the **real** offline synthetic replay in a separate empty evidence folder. It briefly displays the actual replay output in Terminal, then returns to the console. The dashboard changes from **NOT RUN** to real gate/decision evidence; it is not a fake transition.
7. Creates an MP4 and a capture manifest containing the scene timeline, source trace ID, video dimensions, SHA-256 and actual logged operations.

## Before starting

Stop any prior monitor running on port 8776, if present. Keep macOS Screen Recording permission enabled for Terminal/FFmpeg. **New permission**: System Settings → Privacy & Security → **Accessibility** → enable the Terminal app you are using. Allow Apple Events prompts for Terminal and Brave if presented. macOS requires this permission to move the cursor, scroll, activate apps and enter fullscreen.

This script is intentionally limited to local read-only inspection and an offline synthetic scenario. It does not install packet filters, use sudo, change the Mac networking or apply a security response. All results come from the actual existing replay implementation. No microhone recording.

## Update and validate

```bash
git switch arsenal/bheurope-2026
git pull --ff-only origin arsenal/bheurope-2026

.venv/bin/python -m pytest -q \
  tests/test_arsenal_bheurope_record_mac.py \
  tests/test_arsenal_bheurope_auto_record_mac.py \
  tests/test_bheurope_2026_monitor.py

.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene 1 --device 3 --dry-run
```

If pytest is unavailable, install it in `.venv` with `.venv/bin/python -m pip install 'pytest>=9,<10'` and retry. The `--dry-run` validates evidence and the timeline without moving the mouse or recording.

## Automated 2-minute Scene 1

```bash
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene 1 --device 3 --delay 12
```

On the Mac previously tested, screen capture device **3** was `Capture screen 0`. If the content is on another monitor, rerun `tools/arsenal_bheurope_record_mac.py list-devices` and select the correct screen. Do not assume that AVFoundation numbering is permanent.

The script opens the browser and tries to enter fullscreen, records the empty incident console, invokes genuine replay at ~6 seconds, opens Terminal with actual stdout around ~17 seconds, returns to the console at ~30 seconds, then moves/scrolls to show decision and audit evidence. It stores the new replay evidence separately from the November 26 source capture. The actual replay may complete quickly; no fake incident timer is shown.

## Four scenes automatically (10 minutes raw)

```bash
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene all --device 3 --delay 8
```

| Scene | Duration | Automated staging |
|---|---:|---|
| 1 | 120 s | Empty console → genuine replay → Terminal output → console |
| 2 | 180 s | Decision detail, alternatives and release condition via slow scrolling |
| 3 | 180 s | Original VERIFIED vs modified COPY MISMATCH, audit details |
| 4 | 120 s | Trace, policy, explanation and audit review |

The intended `all` mode is 10 minutes of separate video clips, **not** a final 10-minute movie. It does not generate narration or edit clips into the slide deck.

Videos are saved under `artifacts/bheurope-2026/auto-recordings/<UTC timestamp>/01-.../` etc. Each successful scene should have its own MP4, `plan.json`, `capture-manifest.json`, `ffmpeg.log` and `monitor.log`. Scene 1 also includes a genuine evidence folder with a replay process log, explanation JSONL, audit JSONL and modified-copy proof.

## Operational limits and quality control

- **Automation permission** is required; screenshot/capture permission alone is insufficient.
- No remote control from ChatGPT; run the command directly on the Mac.
- The backend remains offline, loopback-only and read-only. Recording automation moves the cursor and scrolls; it does not send a network request to an external host.
- Browser zoom, window dimensions, unrelated browser tabs, notifications and macOS display selection may need a one-time local adjustment.
- The system captures pixels, not a semantic screen recording; if a popover steals focus or the display moves, the resulting clip may need a retake.
- An apparent `THROTTLE` status is a **selected action** in synthetic replay, not proof of active network throttling.
- A verified retained audit chain does not guarantee resistance to coherent whole-log replacement.
- Run the automated scene **1** first, inspect its resulting MP4 and manifest, then proceed to `--scene all` when the result is readable.
- Any actual automation failure is fatal for that scene and must not be represented as a completed recording.

## Where to share

Upload `01-incident-decision/incident-decision.mp4` from the scene output for visual quality review. The final submission must still be assembled with the official slide deck and English narration and stay within the 10–20-minute organiser requirement.
