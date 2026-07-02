# BHUSA 2026 Replay Runbook

This runbook fixes the deterministic replay path for the Black Hat USA 2026
booth session.

## Primary booth scenario

- Freeze candidate: `mixed_correlation_demo`
- Reason:
  - shows cross-source evidence (`suricata_eve`, `flow_min`, `syslog_min`)
  - shows separate NOC and SOC evaluation
  - shows bounded action selection
  - shows explanation, rejected alternatives, Sigma support, and YARA support
  - already serves as the main showcase scenario in the existing demo guide and
    runner tests

Do not change the primary booth scenario during final rehearsal unless a clear
demo blocker is found.

## Booth-safe command sequence

List scenarios:

```bash
bin/azazel-edge-scenario-replay list
```

Run the primary booth scenario:

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo
```

Run and save a compact state snapshot for later inspection:

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo \
  --state-out /tmp/bhusa-2026-replay-state.json
```

If a live dashboard demo is part of the presentation, use `dummy-eve` to feed
fabricated traffic through the real pipeline instead — it shows on the same
dashboard operators use, not a separate overlay:

```bash
bin/azazel-edge-dummy-eve flow
```

Show read-only audit review immediately after replay:

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

Clear the replay artifacts when moving to a clean next visitor state:

```bash
bin/azazel-edge-scenario-replay clear
```

## What must be visible in the replay output

- `execution.mode = deterministic_replay`
- `execution.ai_used = false`
- `execution.live_telemetry = false`
- `execution.local_only = true`
- `execution.offline_demo = true`
- selected action
- rejected alternatives
- `policy_profile`
- `config_hash`
- `evidence_ids`
- operator wording

## Five-run repeatability check

Run the primary scenario 5 times before the session day or after booth machine
changes:

```bash
for i in 1 2 3 4 5; do
  echo "RUN:$i"
  bin/azazel-edge-scenario-replay run mixed_correlation_demo --format json >/tmp/bhusa-run-$i.json
done
```

Confirm these fields stay the same across all 5 runs:

- `result.arbiter.action`
- `result.arbiter.reason`
- `result.arbiter.release_condition`
- `result.arbiter.policy.version`
- `result.arbiter.policy.hash`
- `result.explanation.selected_action`
- `result.explanation.rejected_actions`
- `result.explanation.policy_profile`
- `result.explanation.config_hash`
- `result.explanation.evidence_ids`

Allowed to vary:

- timestamps
- derived incident IDs
- any internal first-seen / last-seen timestamps
- appended explanation log file length

## Reset procedure

CLI-only reset:

```bash
bin/azazel-edge-scenario-replay clear
rm -f /tmp/bhusa-2026-replay-state.json
```

If audit review should reflect only the latest dry run, remove the temporary demo
explanation file before the next rehearsal block:

```bash
rm -f /tmp/azazel-edge-demo-explanations.jsonl
```

This reset is acceptable between rehearsal blocks. It should not be required
between ordinary booth visitors.

## Fallback rule

- Preferred booth path: replay-only demo using `mixed_correlation_demo`
- If Web UI fails: continue with CLI replay output and audit review
- If optional AI surfaces fail: continue deterministic replay without AI
- If network access is unstable: continue local-only replay
- If any live-assisted path is unstable: abandon it and return to replay-only

See also:
- [BHUSA 2026 Live Boundary](bhusa-2026-live-boundary.md)
- [BHUSA 2026 Booth Runbook](bhusa-2026-booth-runbook.md)

Replay is a presentation technique only. It does not replace the normal live
Tactical first-pass path used in operation.

## Hardware verification note

This repository can verify software determinism and command behavior in CI, but
Raspberry Pi-class booth verification must still be completed on the target
device before Vegas:

- `bin/azazel-edge-scenario-replay list`
- `bin/azazel-edge-scenario-replay run mixed_correlation_demo`
- `bin/azazel-edge-audit-review --compact`
- repeatability check across 5 consecutive runs
