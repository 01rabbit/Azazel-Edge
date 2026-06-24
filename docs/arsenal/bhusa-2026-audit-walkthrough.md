# BHUSA 2026 Audit Walkthrough

Use this walkthrough immediately after the frozen replay scenario to prove that
Azazel-Edge records selected evidence, rejected alternatives, and structured
explanation without mutating runtime state.

## Scope

- Primary replay scenario: `mixed_correlation_demo`
- Replay explanation path: `/tmp/azazel-edge-demo-explanations.jsonl`
- Replay audit path: `/tmp/azazel-edge-demo-triage-audit.jsonl`
- Review command: `bin/azazel-edge-audit-review`

This is a read-only review step. It does not change policy, enforcement, or
control-plane state.

## Two-minute booth path

### Step 1: run the replay

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

What to say:
- "The replay is booth-stable, but it feeds the same deterministic downstream
  path used for explanation and audit review."

### Step 2: run compact audit review

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

What to say:
- "This is the read-only review command. It walks the decision record and then
  verifies the local hash-chained audit log."
- "The compact line shows the trace ID, selected action, policy profile,
  configuration hash, release condition, schema status, and audit chain status."

### Step 3: point out the key proof fields

The compact line should make these visible or directly reference them:

- trace ID
- selected action
- policy profile
- config hash
- release condition
- schema validation status
- audit chain status

If asked for more detail, switch to formatted output:

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo
```

If asked for machine-readable inspection:

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --json
```

## What this walkthrough proves

- the selected action was recorded
- rejected alternatives were recorded
- `why_not_others` is retained in the explanation record
- the active policy profile and config hash are retained
- the decision is reviewable without writing new state
- the local audit chain verifies the current stored records

## Sample compact transcript

Command:

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

Expected shape:

```text
trace=demo:mixed_correlation_demo action=throttle policy=soc-policy-default-v1 hash=<config-hash> release=no_repeated_failures_for_300_seconds schema:OK chain:OK(<n>)
```

## Negative-path note

If compact review reports `chain:MISMATCH`:

- Say: "The review command found a mismatch in the stored audit chain, so I
  would not treat this record as clean until the local artifacts are
  revalidated."
- Say: "This is evidence of verification working, not evidence that the record
  is safe to trust as-is."
- Do not say: "The system is tamper-proof."
- Do not continue the deep audit story on the mismatched artifact.
- Fall back to rerunning the replay and repeating the read-only review on fresh
  local demo artifacts.

Recovery commands:

```bash
rm -f /tmp/azazel-edge-demo-explanations.jsonl /tmp/azazel-edge-demo-triage-audit.jsonl
bin/azazel-edge-demo run mixed_correlation_demo
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```

## Read-only contract

`bin/azazel-edge-audit-review` opens the explanation file and audit log for
reading only. It validates the explanation schema and checks the audit chain,
but it does not instantiate a writer, change policy, or trigger enforcement.

Repository evidence:
- `py/azazel_edge/audit_review.py`
- `tests/test_audit_review_v1.py`

## Presenter script

- "First I replay the deterministic scenario."
- "Then I use a read-only review command to inspect the recorded explanation."
- "It shows which action was selected, which actions were rejected, and the
  policy/config context used for that decision."
- "The same command also verifies the local hash-chained audit log so I can say
  whether the stored review trail is internally consistent."
- "That is an auditability claim, not a claim of tamper-proof magic."
