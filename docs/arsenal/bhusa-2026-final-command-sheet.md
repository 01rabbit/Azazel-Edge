# BHUSA 2026 Final Command Sheet

Use this as the single-page command reference for the booth machine.

## One-shot booth verification

```bash
bin/azazel-edge-bhusa-verify
```

## Read current readiness snapshot

```bash
bin/azazel-edge-bhusa-prep repo-sync
bin/azazel-edge-bhusa-prep daily-pack --force
bin/azazel-edge-bhusa-prep candidate-pack --force
bin/azazel-edge-bhusa-status
bin/azazel-edge-bhusa-status --include-freeze-check
```

## Record one rehearsal

```bash
bin/azazel-edge-bhusa-rehearse record \
  --variant full \
  --duration-sec 320 \
  --fallback-drill \
  --clear-after
```

## Summarize rehearsal log

```bash
bin/azazel-edge-bhusa-rehearse summary
```

## Freeze gate check

```bash
bin/azazel-edge-bhusa-freeze-check
```

## Build offline doc bundle

```bash
bin/azazel-edge-bhusa-bundle --force
```

## Generate readiness report

```bash
bin/azazel-edge-bhusa-report --force
```

The report now writes both `REPORT.md` and `status.json` for handoff.

## Build freeze archive

```bash
bin/azazel-edge-bhusa-archive --force
```

## Stamp freeze record

```bash
bin/azazel-edge-bhusa-freeze-record --force
```

## Generate operator pack

```bash
bin/azazel-edge-bhusa-prep ops-pack --force
```

## Generate daily readiness pack

```bash
bin/azazel-edge-bhusa-prep daily-pack --force
```

## Generate freeze pack

```bash
bin/azazel-edge-bhusa-prep freeze-pack --force
```

## Generate freeze candidate pack

```bash
bin/azazel-edge-bhusa-prep candidate-pack --force
```

This now prints a concise candidate summary including `ready_for_freeze`,
`open_child_issue_count`, and `blocker_count`.

## Generate full pack

```bash
bin/azazel-edge-bhusa-prep full-pack --force
```

## Primary replay path

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

## Compact audit review

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

## Full audit review

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo
```

## JSON audit review

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --json
```

## Write replay overlay for booth page

```bash
bin/azazel-edge-demo run mixed_correlation_demo --apply-overlay
```

## Clear booth overlay

```bash
bin/azazel-edge-demo clear
```

## Replay-only fallback path

```bash
bin/azazel-edge-demo run mixed_correlation_demo
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

## Reset between rehearsal blocks

```bash
bin/azazel-edge-demo clear
rm -f /tmp/bhusa-2026-replay-state.json
rm -f /tmp/azazel-edge-demo-explanations.jsonl /tmp/azazel-edge-demo-triage-audit.jsonl
```

## Service status checks

```bash
bin/azazel-edge-bhusa-verify
systemctl status azazel-edge-web --no-pager
systemctl status azazel-edge-control-daemon --no-pager
systemctl status azazel-edge-core --no-pager
systemctl status azazel-edge-opencanary --no-pager
```

## Expected compact review shape

```text
trace=demo:mixed_correlation_demo action=throttle policy=soc-policy-default-v1 hash=<config-hash> release=no_repeated_failures_for_300_seconds schema:OK chain:OK(<n>)
```

## Do not do at the booth

- do not switch to a new scenario without a blocker
- do not attempt broad live troubleshooting during visitor explanation
- do not claim replay is the normal operating model
- do not claim AI is the action authority
