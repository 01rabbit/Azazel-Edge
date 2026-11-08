# Black Hat Europe 2026 — 15-minute narration draft

## 00:00–01:30 Introduction

Hello, I'm Mr. Rabbit. I work on practical security operations and incident
response. Today I will demonstrate Azazel-Edge, an auditable edge SOC/NOC gateway.
This is a technical demonstration of a deterministic decision pipeline, not a
claim of autonomous AI defense.

## 01:30–03:00 Motivation

Security operators need more than an alert or a black-box recommendation.
They need to know what evidence was considered, why an action was selected,
which alternatives were rejected, and what must happen before the control
can be released. They also need a record that can be reviewed afterward.

## 03:00–05:00 Architecture

Local telemetry is normalized into evidence. Separate NOC and SOC evaluators
assess operational health and security signals. The Action Arbiter selects
exactly one bounded response: observe, notify, throttle, redirect, or isolate.
The decision engine, not the language model, owns this choice.

## 05:00–09:00 Live replay

I will now run the auditable_edge_socnoc scenario in deterministic replay mode.
This uses synthetic evidence, without live traffic enforcement or internet
connectivity. We will inspect the resulting action and trace identifier.
[Run the evidence gate. Read the actual output aloud; do not assume throttle
until the recorded execution confirms it.]

## 09:00–11:30 Explanation

Here is the explanation JSONL record. It identifies the selected action and
rejected alternatives, including why those alternatives were not chosen.
It also records a human-readable release condition, policy profile,
configuration hash, and trace identifier. These are practical handoff fields
for an operator reviewing the decision.

## 11:30–13:30 Audit

The audit log contains a hash chain. We verify the original chain, then
demonstrate that modifying a copied record causes verification to fail.
This provides tamper evidence within the retained chain; it is not a
substitute for an externally anchored audit system.

## 13:30–14:30 AI and privacy

Local AI assistance, when enabled, is advisory. It may help summarize or
explain evidence, but cannot choose or modify the Arbiter's action.
The deterministic demo does not invoke AI. Raw logs remain local by default.

## 14:30–15:00 Closing

Azazel-Edge demonstrates a local-first pattern for reviewable SOC/NOC
decisions: bounded actions, explicit explanations, and verifiable audit
records. The same offline replay can be inspected by another operator.
Thank you.
