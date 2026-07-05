# BHUSA 2026 Booth Runbook

This is the practical booth runbook for Arsenal Station 4.

Session:

- Title: Azazel-Edge: Deterministic Edge Decision Support for Constrained SOC/NOC Operations
- Date: Wednesday, August 5, 2026
- Time: 10:10am-11:10am
- Location: Arsenal Station 4, Business Hall
- Track: Network

## Pre-demo boot checklist

- [ ] Booth machine booted and stable
- [ ] `bin/azazel-edge-bhusa-verify` succeeds on the booth machine
- [ ] `bin/azazel-edge-scenario-replay list` succeeds
- [ ] `bin/azazel-edge-scenario-replay run mixed_correlation_demo` succeeds
- [ ] `bin/azazel-edge-audit-review --explanations-path /tmp/azazel-edge-demo-explanations.jsonl --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl --trace-id demo:mixed_correlation_demo --compact` succeeds
- [ ] real dashboard loads (required: the primary demo is live injection on the real dashboard)
- [ ] `bin/azazel-edge-injector list` succeeds and `bin/azazel-edge-dummy-eve flow` reaches the dashboard
- [ ] one offline copy of BHUSA docs is present on the booth machine

Offline bundle command:

```bash
bin/azazel-edge-bhusa-status
bin/azazel-edge-bhusa-status --include-freeze-check
bin/azazel-edge-bhusa-bundle --force
bin/azazel-edge-bhusa-report --force
bin/azazel-edge-bhusa-prep ops-pack --force
bin/azazel-edge-bhusa-prep full-pack --force
```

One-shot verification command:

```bash
bin/azazel-edge-bhusa-verify
```

## Service health checklist

Run these before public start:

```bash
systemctl status azazel-edge-web --no-pager
systemctl status azazel-edge-control-daemon --no-pager
systemctl status azazel-edge-core --no-pager
systemctl status azazel-edge-opencanary --no-pager
```

Interpretation:

- `azazel-edge-web`: required for the real operational dashboard
- `azazel-edge-control-daemon`: required for consistent control-plane story
- `azazel-edge-core`: required for the primary live-injection path (`azazel-edge-injector` / `dummy-eve`)
- `azazel-edge-opencanary`: optional unless redirect path is part of the live discussion

## Live injection checklist (primary path)

- [ ] injected events appear on the real dashboard within the expected delay
- [ ] presenter narrates: test data in, production pipeline reacts — no demo screen
- [ ] `bin/azazel-edge-injector` menu ready in a terminal (or the frozen `dummy-eve` commands)
- [ ] one-step switch to replay-only rehearsed

Primary commands:

```bash
bin/azazel-edge-injector                      # interactive scenario menu
bin/azazel-edge-dummy-eve flow                # frozen single staged flow
bin/azazel-edge-dummy-eve stream --attack-every 60
```

## Deterministic replay checklist (fallback + audit walkthrough)

- [ ] use `mixed_correlation_demo`
- [ ] keep replay as the immediate fallback and the audit-walkthrough surface
- [ ] confirm `execution.mode = deterministic_replay`
- [ ] confirm `execution.ai_used = false`
- [ ] confirm selected action, rejected alternatives, trace ID, policy profile, and config hash are visible

Fallback / audit commands:

```bash
bin/azazel-edge-bhusa-verify
bin/azazel-edge-scenario-replay run mixed_correlation_demo
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

## Audit review checklist

- [ ] compact review shows `schema:OK`
- [ ] compact review shows `chain:OK(...)`
- [ ] presenter can explain selected action and rejected alternatives
- [ ] presenter can explain that the command is read-only

## Web UI fallback to CLI and JSON logs

If the live dashboard demo fails:

1. run the replay in CLI
2. run compact audit review
3. if needed, print the last full JSON with:

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo --format json
```

This is an acceptable booth path.

## Live-assisted fallback to replay-only

When any live-assisted instability appears:

1. stop the live-assisted explanation
2. say that the booth is moving to the deterministic replay path
3. run `mixed_correlation_demo`
4. run compact audit review

Do not attempt to repair live-assisted mode during active visitor explanation.

## No-network operation checklist

- [ ] replay and audit review both succeed with no Internet access
- [ ] no cloud API is required
- [ ] presenter can explain the full value proposition with only local commands and local Web UI

## No-AI operation checklist

- [ ] presenter can omit all AI references
- [ ] replay still shows decision, explanation, and auditability
- [ ] booth story remains complete without M.I.O. or Ollama

## Reset procedure between rehearsal blocks

```bash
bin/azazel-edge-scenario-replay clear
rm -f /tmp/bhusa-2026-replay-state.json
rm -f /tmp/azazel-edge-demo-explanations.jsonl /tmp/azazel-edge-demo-triage-audit.jsonl
```

Between ordinary visitors, only `bin/azazel-edge-scenario-replay clear` is normally needed.

## Final booth laptop layout

- Left: real dashboard or terminal
- Right: talk notes or booth message
- One terminal reserved for replay and audit review commands
- One offline text copy of key commands available without browser dependency

## Rehearsal protocol

Run at least 3 full rehearsals with the final script.

Recommended recording command:

```bash
bin/azazel-edge-bhusa-rehearse record \
  --variant full \
  --duration-sec 320 \
  --fallback-drill \
  --clear-after
```

For each rehearsal, record:

- 90-second version total time
- 5-minute version total time
- full walkthrough total time
- whether replay-only path remained smooth
- whether a fallback drill was exercised

Rehearsal summary command:

```bash
bin/azazel-edge-bhusa-rehearse summary
```

## Minimum fallback drill

During at least one rehearsal:

- intentionally skip Web UI
- run CLI replay only
- run compact audit review
- confirm the story still works

## Day-of rule

- no code edits unless a true demo blocker exists
- no feature additions
- lead with live injection while it is stable; at the first sign of
  instability switch to replay-only in one step — never improvise repairs
  during visitor explanation
