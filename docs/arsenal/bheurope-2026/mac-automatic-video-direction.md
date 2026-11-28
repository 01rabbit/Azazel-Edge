# Black Hat Europe 2026 — Automatic Mac Video Director

**Target branch:** `arsenal/bheurope-2026` only; leave `main` as-is.

The automated director:
1. Verifies that actual replay, decision and audit records from Mac are coherent.
2. Starts the **read-only** Incident Console using a temporary port (default 8776).
3. Opens the local page in Brave, Chrome or Safari and attempts fullscreen.
4. Starts FFmpeg screen capture with **no audio**.
5. Drives the mouse cursor, scroll position, and window focus via macOS Quartz/AppleScript.
6. In Scene 1 only, invokes the **real** offline synthetic replay in a separate empty evidence folder. It displays the genuine replay stdout/stderr directly in the read-only console, avoiding unreliable inter-display Terminal switching. The dashboard changes from **NOT RUN** to real gate/decision evidence; it is not a fake transition.
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

## First: short fully automatic 45-second preview

```bash
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene 1 --device 3 --preview --delay 8
```

The recorder starts an empty read-only Incident Console, triggers the genuine synthetic replay after ~4 seconds, reveals the genuine replay process output within the console at ~13 seconds, then scrolls to the audit comparison and back. It does not switch to Terminal. No talking or mouse clicking is needed after starting the command. This should be reviewed before running all four full scenes.

## Automated 2-minute Scene 1

```bash
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene 1 --device 3 --delay 12
```

On the Mac previously tested, screen capture device **3** was `Capture screen 0`. If the content is on another monitor, rerun `tools/arsenal_bheurope_record_mac.py list-devices` and select the correct screen. Do not assume that AVFoundation numbering is permanent.

The script opens the browser and tries to enter fullscreen, records the empty incident console, invokes genuine replay at ~6 seconds, displays the actual replay stdout in the console and scrolls through decision and audit evidence. No Terminal switching. It stores the new replay evidence separately from the November 26 source capture. The actual replay may complete quickly; no fake incident timer is shown.

## Four scenes automatically (10 minutes raw)

```bash
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene all --device 3 --delay 8
```

| Scene | Duration | Automated staging |
|---|---:|---|
| 1 | 120 s | Empty console → genuine replay → on-page authentic process output |
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
- Run the automated 45-second **preview** first, inspect its resulting MP4 and manifest, then proceed to `--scene all` when the result is readable.
- Any actual automation failure is fatal for that scene and must not be represented as a completed recording.

## Where to share

Upload `01-incident-decision/incident-decision.mp4` from the scene output for visual quality review. The final submission must still be assembled with the official slide deck and English narration and stay within the 10–20-minute organiser requirement.

## Scene 1 single-screen capture correction (2026-11-28)

The first automated preview showed the correct screen and a genuine **NOT RUN → PASS** transition, but the Terminal handoff was not visible on the captured display. Therefore Scene 1 no longer switches applications. The monitor now reads the actual `replay-process.log` (maximum 200 KB, local-only) and displays it as a labelled **Replay Execution · Actual Process Output** section only if that file exists. The automated camera scrolls through this section, the audit comparison and the decision explanation on the same browser display.

Re-run the 45-second preview using the currently listed capture-screen index (the most recent list mapped `Capture screen 0` to `--device 2`; recheck device numbering if it changes):

```bash
.venv/bin/python -m pytest -q tests/test_bheurope_2026_monitor.py tests/test_arsenal_bheurope_auto_record_mac.py
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py --scene 1 --device 2 --preview --delay 8
```

Do not proceed to all four scenes until the video itself confirms readable content and an honest before/after transition. The original UI screenshots and evidence remain unchanged.

## Window capture alignment — revised after Scene 1 visual review

The initial automated preview produced a valid MP4 but recorded the browser in only part of the screen and did not show Terminal. The director now:
- Finds the logical bounds of an active Quartz display (`--display-index 0` means the first active display).
- Resizes and moves the **front browser window** to cover that display (maximized standard window, not a native macOS fullscreen Space).
- Reads back actual window geometry and browser frontmost state using System Events; **fails** rather than silently accepting a small or offscreen window.
- For Scene 1, switches to Terminal to show the genuine replay-process log, brings Terminal onto the target display, confirms Terminal is frontmost, then restores and verifies the browser window.
- Runs the pointer/scroll events only after the window has been verified.

Important: `--device` is the **FFmpeg AVFoundation video device number** (which changes when other cameras are present); `--display-index` selects an active **Quartz display** for positioning. They are different numbering systems. At present, the operator should use `--device 2 --display-index 0` only if the device list still reports `[2] Capture screen 0`. Recheck the devices if the Mac display configuration changes.

The display/viewport check validates geometry and app focus, but a real video inspection is still required to confirm AVFoundation captured the intended monitor. There is deliberately no fabricated screenshot validation.

### Verify with a new 45-second preview

```bash
git pull --ff-only origin arsenal/bheurope-2026
.venv/bin/python -m pytest -q tests/test_arsenal_bheurope_auto_record_mac.py
.venv/bin/python tools/arsenal_bheurope_record_mac.py list-devices
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene 1 --device 2 --display-index 0 --preview --delay 8
```

Do not launch `--scene all` until the preview shows a large browser and the genuine Terminal-to-browser transition. If the new geometry check fails, share the exact error rather than bypassing it.

## Browser pop-up mistaken for the recording window — fix after 282×47 failure

A Mac preflight reported `actual=(2,30,282,47)`, while the intended capture viewport was `(2,30,1916,1047)`. This likely came from `System Events` selecting a transient browser UI window rather than the document window.

The capture director now creates a **dedicated browser document window**, sets its localhost page URL and bounds through the browser's own AppleScript interface, then verifies its URL, size, position and process foreground. It refuses a tiny window or unrelated page. This replaces geometry reads via `front window` of `System Events`.

To retest:

```bash
git pull --ff-only origin arsenal/bheurope-2026
.venv/bin/python -m pytest -q tests/test_arsenal_bheurope_auto_record_mac.py
.venv/bin/python tools/arsenal_bheurope_auto_record_mac.py \
  --scene 1 --device 2 --display-index 0 --preview --delay 8
```

If macOS requests permission for iTerm/Terminal to control Brave, allow it. If you get an AppleScript error or a window-verification error, **copy the exact message** instead of overriding the check. Current video-device numbers must still be confirmed with `list-devices` before use. Actual footage requires visual review even after the geometry check passes.
