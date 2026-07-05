# BHUSA 2026 Live Boundary

This note fixes the boundary between normal live Tactical first-pass operation
and the Black Hat USA 2026 booth demonstration path.

## Core rule

- Normal operation: live Tactical first-pass triage remains the primary runtime
  path for time-sensitive events.
- Booth operation: live injection through the real pipeline
  (`azazel-edge-injector` / `dummy-eve` -> real dashboard) is the preferred
  presentation path, with deterministic replay as the immediate one-step
  fallback.
- Injected traffic and replay are presentation techniques only. Neither must
  be presented as the normal operating model (normal input is real telemetry).

## Side-by-side boundary

| Topic | Normal operation | BHUSA 2026 booth path |
|---|---|---|
| Event source | Live Suricata, probes, syslog, and runtime telemetry | Injected test events through the real pipeline (fallback: deterministic replay) |
| First minute | Tactical Engine triages live events | Injected events triaged by the same live pipeline |
| Stability goal | Fast response under changing conditions | Real system reaction first; stable explanation and auditability in a short session |
| AI role | Optional post-decision assist | Optional post-decision assist only |
| Live packet generation | Allowed when runtime requires it | Fabricated EVE injection only (no real packet generation required) |
| Final fallback | Local deterministic logic | Replay-only with local audit review |

## Preferred booth order

1. Live injection on the real dashboard (`azazel-edge-injector` menu or the
   frozen `dummy-eve` commands) — the audience watches the production system
   react to injected test data
2. Audit walkthrough: replay `mixed_correlation_demo` plus compact audit
   review (fixed trace id, known expected output)
3. Optional Web UI or reviewer page deep-dive
4. Replay-only presentation at any point the live path is unstable

The live path must be abandoned for replay-only in one step, without
troubleshooting in front of visitors.

## Live-assisted allowed only if all conditions hold

- `azazel-edge-web` is healthy
- `azazel-edge-control-daemon` is healthy
- `azazel-edge-core` is healthy if live Suricata path is shown
- presenter can switch to replay-only in one step
- booth story still starts from deterministic decision support, not from
  optional integrations
- no Internet dependency is required to complete the explanation

If any condition fails, skip live-assisted mode and stay on replay-only.

## Immediate abandon-live conditions

Abandon live-assisted mode and return to replay-only immediately when any of the
following is true:

- Suricata live path is unavailable or visibly inconsistent
- OpenCanary redirect path fails or becomes distracting
- network access is unstable enough to slow explanation or operator flow
- reviewer page or dashboard becomes unreliable during live refresh
- optional AI path stalls, errors, or produces confusing latency
- presenter cannot explain the current state in under 30 seconds

At the booth, there is no value in debating these conditions. If one occurs,
switch to replay-only.

## Failure matrix

| Failure | Booth action | What to say |
|---|---|---|
| Suricata failure | stop live-assisted mode, use replay-only | "The live source is unstable, so I am using the deterministic replay path for the same downstream decision story." |
| OpenCanary failure | continue replay, do not show redirect execution path | "Redirect is optional here; the deterministic decision and audit path still stand." |
| Network instability | use local CLI replay and local audit review only | "The booth path is intentionally local-first, so I can continue offline." |
| Web UI failure | move to CLI replay plus audit review command | "The viewer is down, but the deterministic replay and audit artifacts are still available locally." |
| AI assist failure | continue with no AI references | "AI is optional operator support, not decision authority, so the core path is unchanged." |

## Presenter wording

Say:
- live Tactical first-pass path
- injected test data through the real pipeline, on the real dashboard
- deterministic replay fallback path
- same downstream deterministic evaluators and arbiter
- replay-only final fallback

Do not say:
- injected traffic or replay is how the system normally operates
- live demonstration is required to prove the decision logic
- optional AI is necessary for explanation

## Minimal booth fallback commands

```bash
bin/azazel-edge-scenario-replay run mixed_correlation_demo
bin/azazel-edge-audit-review \
  --explanations-path /tmp/azazel-edge-demo-explanations.jsonl \
  --audit-path /tmp/azazel-edge-demo-triage-audit.jsonl \
  --trace-id demo:mixed_correlation_demo \
  --compact
```
