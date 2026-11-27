# BHEurope 2026 — Mac Incident Console recording runbook

**Working branch:** `arsenal/bheurope-2026` only. Do not merge main.

## 1. Update and test

Stop the current monitor with Ctrl+C, then from the Azazel-Edge root:

```bash
git pull --ff-only origin arsenal/bheurope-2026
.venv/bin/python -m pytest -q tests/test_bheurope_2026_monitor.py
```

If pytest is not installed, install it in the isolated replay venv (`.venv/bin/python -m pip install 'pytest>=9,<10'`) and rerun. **Do not record a test pass unless this Mac actually reports it.**

## 2. Start read-only monitor using already confirmed captured evidence

```bash
.venv/bin/python tools/arsenal_bheurope_monitor.py \
  --artifacts artifacts/bheurope-2026/mac-capture-20261126T100955Z
```

Open `http://127.0.0.1:8765` in the browser. Hard refresh if old HTML remains cached. The updated console presents Audit Evidence near the top, immediately below the KPI strip. Expect:
- Original retained log: `VERIFIED (3)`
- Modified COPY only: `MISMATCH DETECTED`
- Modified-copy verifier result: `chain_hash_mismatch_at:1`

**These are expected values from the operator's previously shared successful Mac command output.** They are not evidence that the updated monitor itself was tested in this development environment. If `capture-report.json` or the altered-copy file is absent, the comparison intentionally shows **NOT CHECKED**, not a fabricated pass.

## 2a. UI verification for the redesigned console

- Check that the two large audit comparison panels appear side by side on a desktop monitor, with legible `VERIFIED` and `MISMATCH` labels. Smaller displays may stack them.
- Confirm they are sourced from matching `capture-report.json` and `gate.json`, not hard-coded example data. A missing report must display `NOT CHECKED`.
- Confirm that the yellow `SYNTHETIC REPLAY · NO ENFORCEMENT` indicator remains visible and that the original decision, alternatives, trace and JSONL drill-down still render.
- Restart the monitor after pulling source changes; a browser refresh alone does not reload Python's embedded HTML.

## 3. Record authentic monitor footage

- Use macOS Screen Recording (Shift-Command-5), choose the browser window or a bounded area, and set a 1920x1080 16:9 crop in the editor. Browser fullscreen is recommended.
- Start with the incident summary, selected response, release condition and rejected alternatives.
- Scroll to `Audit Evidence` and pause to explain clean-chain success and altered-copy mismatch.
- Expand `Raw evidence (JSONL / troubleshooting)` briefly for technical verifiability, then collapse it.
- Capture the terminal command + actual output separately; never paste invented values into the video.

## 4. Editorial distinctions

- `throttle` is the decision selected by synthetic replay, not demonstrated packet shaping.
- The console is a **read-only presentation of evidence**, not a live SIEM or a workflow capable of response execution.
- The modified-copy proof detects changes within the retained hash chain. It does not establish external anchoring or resistance to whole-log replacement.
- Confirm the entire deliverable is between 10 and 20 minutes; edit target 18:50.
- Hardware execution on macOS ARM64 is not verification of Raspberry Pi hardware.

## 5. Status

Code and tests committed to the branch. User's local Mac must run pytest and confirm the final view. No video was automatically recorded on the user's machine.
