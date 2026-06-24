# Arsenal Demo Profile

Last updated: 2026-05-14

## 1. Purpose

This demo shows the deterministic edge SOC/NOC decision loop. It is not a full SIEM replacement, not an autonomous AI defender, and not a broad feature tour.

## 2. Demo story

1. Evidence is ingested.
2. NOC and SOC are evaluated separately.
3. The Action Arbiter selects a bounded response.
4. The system records explanation, rejected alternatives, and audit evidence.
5. The operator inspects the decision and response trace.

## 3. Required components

Mandatory:
- `azazel-edge-web`
- `azazel-edge-control-daemon`
- deterministic replay CLI (`bin/azazel-edge-demo`)
- `azazel-edge-core` when live Suricata path is included
- `azazel-edge-opencanary` when redirect behavior is shown

Optional:
- Mattermost
- Ollama
- Aggregator
- TAXII/STIX
- SNMP/NetFlow
- Vector
- Wazuh

## 4. Demo modes

Replay-only demo (default):
- safest for Arsenal booth
- stable evaluator output
- no dependency on live packet generation
- presentation technique for booth stability only
- does not replace the normal live Tactical first-pass path
- freeze the booth primary scenario to `mixed_correlation_demo` unless a clear demo blocker appears

Live-assisted demo:
- includes Suricata EVE live path
- must preserve immediate fallback to replay-only mode
- remains subordinate to the same deterministic evaluator and Action Arbiter path

Boundary statement:
- normal operation uses live Tactical first-pass triage when available
- BHUSA 2026 booth operation prefers deterministic replay for short-session stability
- booth replay must never be described as the normal operating model

## 5. Pre-demo checklist

```bash
systemctl status azazel-edge-web --no-pager
systemctl status azazel-edge-control-daemon --no-pager
systemctl status azazel-edge-core --no-pager
systemctl status azazel-edge-opencanary --no-pager
bin/azazel-edge-demo list
bin/azazel-edge-demo run mixed_correlation_demo
```

Recommended API sanity checks:

```bash
TOKEN="$(cat ~/.azazel-edge/web_token.txt)"
curl -fsS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/state >/dev/null
curl -fsS -H "X-AZAZEL-TOKEN: ${TOKEN}" http://127.0.0.1:8084/api/aggregator/nodes >/dev/null || true
```

## 6. Failure fallback

- Suricata failure: switch to replay-only path immediately.
- OpenCanary failure: continue replay demo without redirect execution path.
- Mattermost failure: continue local Web UI + audit walkthrough.
- Ollama failure: continue deterministic core story (AI assist is optional).
- Network instability: run local replay scenarios only.
- Web UI failure: use CLI replay output + JSON logs for deterministic trace.

Final fallback rule:
- the deterministic replay path must remain the final fallback.

## BHUSA 2026 booth message

Presenter note:
- [BHUSA 2026 Booth Message](arsenal/bhusa-2026-booth-message.md)
- [BHUSA 2026 Replay Runbook](arsenal/bhusa-2026-replay-runbook.md)
- [BHUSA 2026 Audit Walkthrough](arsenal/bhusa-2026-audit-walkthrough.md)
- [BHUSA 2026 Live Boundary](arsenal/bhusa-2026-live-boundary.md)
- [BHUSA 2026 Booth Runbook](arsenal/bhusa-2026-booth-runbook.md)
- [BHUSA 2026 Freeze Candidate](arsenal/bhusa-2026-freeze-candidate.md)
- [BHUSA 2026 Final Command Sheet](arsenal/bhusa-2026-final-command-sheet.md)

## 7. What not to show first

Do not lead with optional integration tours:
- Wazuh
- TAXII/STIX
- Aggregator fleet view
- multilingual captive portal
- vehicle deployment

Lead with deterministic path consistency and bounded action behavior.

## 8. Audit Review Path (read-only operator command)

`bin/azazel-edge-audit-review` is a read-only CLI tool for walking a decision
through its v2 explanation record and the hash-chained audit log.  It makes no
writes, no policy changes, and no enforcement actions.

### What it does

1. Reads the decision-explanations JSONL file and selects the requested record
   (by `--trace-id`, or the most-recent record if omitted).
2. Prints the review fields: `trace_id`, `selected_action`, `rejected_actions`
   with `why_not_others` reasons, `release_condition`, `policy_profile`,
   `config_hash`, `evidence_ids`, `operator_wording`.
3. Runs `validate_v2_explanation` on the record and reports whether it is
   schema-valid (lists any problems if it is not).
4. Runs `P0AuditLogger.verify_chain` on the triage-audit JSONL and reports
   `OK (N entries)` or `MISMATCH: <error detail>`.

### Usage

Standard (formatted) output:

```bash
bin/azazel-edge-audit-review
```

Select a specific trace:

```bash
bin/azazel-edge-audit-review --trace-id trace-audit-review-01
```

Condensed output for booth screens:

```bash
bin/azazel-edge-audit-review --compact
```

Machine-readable JSON:

```bash
bin/azazel-edge-audit-review --json
```

Custom paths (useful in test or staging environments):

```bash
bin/azazel-edge-audit-review \
  --explanations-path /tmp/decision-explanations.jsonl \
  --audit-path /tmp/triage-audit.jsonl
```

The audit path can also be set via the environment variable
`AZAZEL_TRIAGE_AUDIT_PATH`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0    | Explanation record found; audit chain verified OK |
| 2    | Explanation file missing, empty, or trace-id not found |
| 3    | Audit chain verification failed (hash mismatch or parse error) |

### Read-only contract

The command only opens files for reading.  It calls `P0AuditLogger.verify_chain`
(a classmethod that reads the log file without instantiating a writer) and
`validate_v2_explanation` (a pure validation function).  No logger is
instantiated, no file is opened for writing, and no control-plane state is
modified.  This property is verified by the test suite (see
`tests/test_audit_review_v1.py`, read-only test case).

### Demo talk track

After running a scenario, show the audit review path to demonstrate end-to-end
traceability:

```bash
bin/azazel-edge-demo run mixed_correlation_demo
bin/azazel-edge-audit-review --compact
```

This confirms that the decision recorded in the explanation file matches what
was written to the hash-chained audit log, and that neither has been tampered
with.
