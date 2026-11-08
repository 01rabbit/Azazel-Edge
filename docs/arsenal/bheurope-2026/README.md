# Black Hat Europe 2026 Arsenal — Azazel-Edge

**Presentation:** Azazel-Edge: Auditable Edge SOC/NOC Gateway

**Scope:** Edge only. Nexus is excluded. MIO is optional, advisory-only, and not required for the recording.

**Recording requirement:** 10–20 minutes, submitted by 2026-12-01. Target: 15 minutes, ready by 2026-11-29.

## Architecture

Synthetic local telemetry -> NOC and SOC evaluators -> deterministic Action Arbiter
-> exactly one of observe / notify / throttle / redirect / isolate
-> v2 explanation JSONL and hash-chained audit JSONL.

The deterministic replay must not send raw logs to remote services, invoke AI,
or enforce network controls. AI assist is a separate optional demonstration.

## First reproducible evidence gate

From the repository root, in a Python environment with the project's dependencies:

```bash
python3 tools/arsenal_bheurope_2026.py --out artifacts/bheurope-2026
```

Outputs: `result.json`, `explanations.jsonl`, `audit.jsonl`, `gate.json`.
A nonzero exit status means that the recording gate has failed.
The gate uses an isolated temporary directory and a fixed demo policy; it
does not clear or modify operational logs. It explicitly disables enforcement.

**Important:** A passing gate proves only the offline replay and output
consistency checks. It does not prove live packet enforcement, real network
isolation, cryptographic anchoring against whole-log replacement, or successful
execution on Raspberry Pi hardware.

## Recording runbook (15 minutes)

| Time | Content | On-screen evidence |
|---|---|---|
| 00:00–01:30 | Presenter and research motivation | Title and hardware |
| 01:30–03:00 | Explain the deterministic boundary | Architecture |
| 03:00–05:00 | NOC/SOC and five bounded actions | Policy and source |
| 05:00–09:00 | Run the offline scenario | CLI result |
| 09:00–11:30 | Explain chosen/rejected actions and release | explanations.jsonl |
| 11:30–13:30 | Show hash chain and verification | gate.json, audit.jsonl |
| 13:30–14:30 | Explain AI advisory-only and privacy boundaries | Architecture |
| 14:30–15:00 | Recap and limitations | Summary |

## Recording acceptance

- [ ] ARM64/Raspberry Pi-class hardware execution verified by a human.
- [ ] The gate exits 0, and gate.json contains ok=true.
- [ ] The output includes selected and rejected actions, release condition,
      policy profile, config hash, and trace id.
- [ ] The clean chain verifies; a separate tampered copy fails verification.
- [ ] No Nexus references in the presentation or video.
- [ ] All claims distinguish replay decisions from real network enforcement.
- [ ] Recording duration is 10–20 minutes; spoken English is intelligible.
- [ ] Video is reviewed and uploaded before the official deadline.

## Workstreams

Architecture and scope; replay integration; audit assurance; ARM64 packaging;
demo rehearsal; English narration; final evidence and publication.
Each workstream must produce independently reviewable commits and test results.
Do not mark hardware or recording checks complete based on desktop tests.
