# Black Hat Europe 2026 — Mac Screen Recording / First Take

**Branch:** \`arsenal/bheurope-2026\` (keep divergent from main).  
**Goal:** capture an authentic 30–60 second silent screen-recording test, then produce four genuine evidence scenes for an 18:50 narrated video.  
**Safety:** no sudo, no packet filtering, no remote uploads, no microphone capture, no model-driven decision. Recorded evidence is from synthetic offline deterministic replay.

## 1. Update (stop the old monitor first)

\`\`\`bash
git switch arsenal/bheurope-2026
git pull --ff-only origin arsenal/bheurope-2026
.venv/bin/python -m pytest -q \
  tests/test_arsenal_bheurope_record_mac.py \
  tests/test_bheurope_2026_monitor.py
\`\`\`

If pytest is absent: \`.venv/bin/python -m pip install 'pytest>=9,<10'\`. Do not treat the new test as passed until this Mac reports it.

## 2. Prerequisites and screen-device selection

\`\`\`bash
brew install ffmpeg  # only if ffmpeg / ffprobe are missing
.venv/bin/python tools/arsenal_bheurope_record_mac.py check
.venv/bin/python tools/arsenal_bheurope_record_mac.py list-devices
\`\`\`

FFmpeg will list devices. Use the number corresponding to \`Capture screen ...\` **on this Mac**. Do not guess a screen ID. Run the recorder using that number, substituted for \`N\` below.

Grant Screen Recording permission to the terminal/FFmpeg when macOS prompts (System Settings → Privacy & Security → Screen & System Audio Recording). Restart the terminal app if macOS requires it.

The recorder launches a **separate** loopback-only read-only monitor on port 8776, opens it in the default browser, waits eight seconds and captures the chosen display using AVFoundation. It will refuse to display the wrong trace. The prior port 8765 may remain open, but do not confuse it with the recording session.

## 3. Capture a 45-second first take

\`\`\`bash
.venv/bin/python tools/arsenal_bheurope_record_mac.py test \
  --device N --duration 45 --delay 12
\`\`\`

During the countdown, put the browser on the newly opened \`http://127.0.0.1:8776\` page, enlarge or full-screen it, and remove personal browser chrome and translation popovers. Record:
- 0–12 seconds: evidence gate, selected action, trace ID;
- 12–30 seconds: original \`VERIFIED\` vs altered-copy \`MISMATCH\`;
- 30–45 seconds: scroll to rejected alternatives, release condition and audit timeline.

The actual recording sequence begins **after** the countdown. Do not narrate this test; voiceover comes later. If permissions are denied, the video fails validation rather than being reported as complete.

Result folder: \`artifacts/bheurope-2026/recordings/test-<UTC timestamp>/\` with \`test.mp4\`, \`capture-manifest.json\`, \`ffmpeg.log\`, \`monitor.log\`. The manifest includes SHA-256, actual recorded duration, stream dimensions/frame rate, branch commit, source evidence location and trace ID.

## 4. Main footage — four planned scenes

The original **confirmed** evidence lives in \`artifacts/bheurope-2026/mac-capture-20261126T100955Z\`. With the same screen index \`N\`, record each scene separately, leaving room for editing:

| Scene | Suggested raw capture length | Camera direction |
|---|---:|---|
| Incident / decision | 120s | Mac offline replay command and genuine status/trace, then Incident Console |
| Why this action | 180s | THROTTLE, rejected observe/notify/redirect/isolate, release condition |
| Audit proof | 180s | Original-chain verification, copy modified, genuine mismatch |
| Operator handoff | 120s | Follow same trace through explanation / audit / policy |

For any scene, run:

\`\`\`bash
.venv/bin/python tools/arsenal_bheurope_record_mac.py record \
  --device N --duration 120 --delay 12
\`\`\`

Change the duration to 180 as required. Each run saves a separate folder under \`recordings/\`, with an integrity manifest. This intentionally records **video only** to prevent accidental microphone capture; English narration is recorded and edited separately.

The recorder serves already captured evidence. **It does not re-run the incident on its own or animate a new event.** To show a genuine terminal replay command on-screen, switch to Terminal while the screen recorder is running and execute \`.venv/bin/python tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026/<new-safe-folder>\` (choose a distinct folder). Do not mistake this newly generated directory for the original monitor folder. Any new run must pass the evidence gate before being described as successful.

## 5. Acceptance checks

- \`capture-manifest.json\` exists and names the actual MP4.
- \`ffprobe\` found a valid video stream with a duration of at least one second, width >=640, height >=360.
- On-screen text is legible at the intended 1080p export size; avoid shrinking a desktop screenshot into a tiny region.
- Top-right \`SYNTHETIC REPLAY · NO ENFORCEMENT\` remains visible.
- No private browsing tabs, passwords, personal communications, usernames or unrelated notifications appear.
- Original chain / modified copy are genuine captured output. They are not shown as a live network containment result.
- No Raspberry Pi execution claim from this Mac capture.
- Final edit including narration, transitions and end card must be 10–20 minutes.

## 6. Troubleshooting

- \`ffmpeg missing\`: install FFmpeg or select existing binary from PATH.
- Screen index invalid: rerun \`list-devices\`; find \`Capture screen N\`.
- Black screen / permission denial: enable Screen Recording permission, restart Terminal, retry the short test.
- Browser opens but says NOT CHECKED: verify \`--evidence\` location and both original and tampered-copy files; no fake fallback.
- Port 8776 already bound: stop an older recorder or use \`--port 8777\`.
- Too much chrome/text too small: enter browser full screen; use Mac display scaling and browser zoom thoughtfully before retesting.
- No audio in test recording: **intentional**; voiceover is separate.

**Completion status:** capture orchestration and tests are committed. Real device recording and video QA require running this on the operator's Mac. No remotely captured MP4 is claimed.
