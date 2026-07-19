# BHUSA 2026 Recorded Demo — PART 3c Command Sheet

Operator command sheet for the recorded demo's **PART 3c (deterministic
replay)**, aligned to `AzazelEdge_RecordedDemo_Script.md`. Each command is
followed by the exact on-camera line from the script and the fields verified
against live replay output.

This is a hands-on operator reference, not a substitute for the script — read
the full script wording on camera; the abbreviations here are cues only.

## Before recording (once, off camera)

Lock determinism before the take, per the script's recording notes.

```bash
for i in 1 2 3 4 5; do
  bin/azazel-edge-scenario-replay run mixed_correlation_demo >/dev/null 2>&1
  bin/azazel-edge-audit-review \
    --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
    --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
    --trace-id demo:mixed_correlation_demo --compact
done
bin/azazel-edge-scenario-replay clear
```

Expected: all five runs report `action=throttle` and `hash=0ce8c7b59ef2b2ce`.

> `chain:OK(N)` — the `N` is the accumulated audit-chain length and grows with
> each run in the session, so it is not a fixed number. Confirm `schema:OK` and
> `chain:OK(...)`, not a specific count.

## On camera — 【slides ⑩/⑪, switch to terminal】

### ① List the scenarios

```bash
bin/azazel-edge-scenario-replay list
```

Line: *"Let me list the scenarios."*

### ② Primary booth scenario — `mixed_correlation_demo`

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo
```

Line: *"Look at the record it produced. This is real output, not a slide. The
chosen action is **throttle** — because the SOC state is critical and a
reversible control is safe here. NOC is degraded, SOC is critical, the control
mode is route_preference. The evidence is flow-2 and soc-2; the attack
candidates map to MITRE ATT&CK T1021, T1110, and T1190."*

Verified: `selected_action=throttle` · `noc_status=degraded` ·
`soc_status=critical` · `control_mode=route_preference` ·
`chosen_evidence_ids=[flow-2, soc-2]` · MITRE `T1021, T1110, T1190`.

【scroll to the rejected column】 Line: *"…**observe** was rejected as an
insufficient response. **notify** wasn't the primary choice. And notice:
**redirect** and **isolate** — the two strongest actions — were *not* taken,
because their gates weren't satisfied. That restraint is the point."*

Verified rejected reasons: `observe=insufficient_response_for_detected_threat` ·
`notify=operator_notification_not_primary_choice` ·
`redirect=redirect_gate_not_satisfied` · `isolate=isolate_gate_not_satisfied`.

### ③ Change the input — `noc_degraded_demo`

```bash
bin/azazel-edge-scenario-replay run noc_degraded_demo
```

Line: *"Different scenario — this one is a reliability problem. NOC is critical,
SOC is low. The chosen action is **notify**, not throttle — because the stronger
actions here are rejected as 'threat signal not strong enough'. Reliability, not
threat, so it escalates to a human instead of touching traffic."*

Verified: `selected_action=notify` · `noc_status=critical` · `soc_status=low` ·
control `none`. Stronger actions (throttle/redirect/isolate) rejected as
`threat_signal_not_strong_enough`.

> Nuance for the rejected column: in the data `observe` is rejected as
> `deferred_to_higher_visibility_action`, not "threat signal not strong enough".
> The script's phrase applies to the **stronger** actions only, so say it that
> way if the `observe` row is on screen.

### ④ Calm baseline — `shelter_baseline_demo`

```bash
bin/azazel-edge-scenario-replay run shelter_baseline_demo
```

Line: *"And a calm baseline — a shelter network, SOC low. The action is
**observe**. It deliberately does nothing but keep watching, and it records why
the louder actions were held back."*

Verified: `selected_action=observe` · `soc_status=low` · control `none`.
Louder actions rejected as `threat_signal_not_strong_enough`.

Bridge line: *"So: three inputs, three different decisions — observe, notify,
throttle — and every one of them carries its rejected alternatives and its
evidence. That's the whole idea."*

### ⑤ 【audit view】 read-only audit walkthrough for the primary scenario

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo >/dev/null
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo --compact
```

Line: *"Everything is here and local: execution mode deterministic_replay,
ai_used false, local_only true, offline true, the selected action, the rejected
alternatives, the policy profile, and the config hash."*

Verified compact line:
`trace=demo:mixed_correlation_demo action=throttle policy=soc-policy-default-v1 hash=0ce8c7b59ef2b2ce schema:OK chain:OK(...)`.

Determinism line: *"…Same input, same profile, same decision — locked by the
config hash on screen** 0ce8c7b59ef2b2ce**, policy soc-policy-default-v1…"*

Notes:
- `config_hash 0ce8c7b59ef2b2ce` holds at the current repo state — read it as
  is; re-run just before the take only if policy changed.
- `p95 = 0.226 ms` comes from `docs/BENCHMARK_RESULTS.md`, **not** the replay
  output — have the benchmark figure ready as a separate reference; it cannot be
  read off this screen.

### ⑥ 【clear for the next attendee】

```bash
bin/azazel-edge-scenario-replay clear
```

## Notes

- Read one block at a time to give room for narration. To run the whole
  sequence unattended, drop the comment lines and chain the commands.
- Required-to-show fields (per the replay runbook) all appear in ② and ⑤:
  `mode=deterministic_replay`, `ai_used=false`, `live_telemetry=false`,
  `local_only=true`, `offline_demo=true`, selected action, rejected
  alternatives, `policy_profile`, `config_hash`, `evidence_ids`. The raw
  `run mixed_correlation_demo` JSON is the "real output, not a slide" surface.
- Add `--format text` for a one-screen ACTION/CONTROL/rejected summary during
  rehearsal; keep the JSON view on camera for the raw-output feel.

## Related

- Recorded demo script: `AzazelEdge_RecordedDemo_Script.md` (master copy kept outside the repo)
- [BHUSA 2026 Replay Runbook](bhusa-2026-replay-runbook.md)
- [BHUSA 2026 Final Command Sheet](bhusa-2026-final-command-sheet.md)
- [BHUSA 2026 Audit Walkthrough](bhusa-2026-audit-walkthrough.md)
- [Demo Guide](../DEMO_GUIDE.md)
