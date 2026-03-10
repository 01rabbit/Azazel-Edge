# Azazel-Edge Demo Guide

## Purpose

Azazel-Edge ships with a deterministic demo pack for showing the end-to-end decision path:

1. Evidence Plane input normalization
2. NOC / SOC evaluation
3. Action Arbiter decision
4. Decision Explanation output
5. M.I.O. operator guidance via WebUI or Mattermost

The current demo pack is a backend replay. It does not inject live events into the running system. The intended flow is:

1. Run a scenario
2. Inspect the returned NOC / SOC / arbiter / explanation payload
3. Ask M.I.O. to explain the same situation in operator terms

## Available Scenarios

- `soc_redirect_demo`
  - High-confidence SOC path that supports redirect-capable control
- `noc_degraded_demo`
  - NOC degradation path with poor path health and degraded device state
- `mixed_correlation_demo`
  - Cross-source correlation path with Sigma / YARA assist signals

## CLI Usage

List scenarios:

```bash
bin/azazel-edge-demo list
```

Run a scenario:

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

Pretty-printed JSON is returned by default.

## Web API Usage

List scenarios:

```bash
curl -sS -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/scenarios | jq
```

Run a scenario:

```bash
curl -sS -X POST -H "X-AZAZEL-TOKEN: <token>" \
  http://127.0.0.1:8084/api/demo/run/mixed_correlation_demo | jq
```

## What To Show During a Demo

### 1. NOC degradation demo

Run:

```bash
bin/azazel-edge-demo run noc_degraded_demo
```

Expected result:

- NOC status degrades
- SOC remains low
- Arbiter chooses `notify`

Suggested M.I.O. question:

```text
/mio uplink と device health が同時に悪い時、何から確認すべきか
```

### 2. SOC redirect-capable demo

Run:

```bash
bin/azazel-edge-demo run soc_redirect_demo
```

Expected result:

- SOC becomes critical
- NOC remains degraded but not collapsed
- Arbiter selects a reversible control path first

Suggested M.I.O. question:

```text
/mio この通信で強制遮断より可逆制御を優先する理由は？
```

### 3. Mixed correlation demo

Run:

```bash
bin/azazel-edge-demo run mixed_correlation_demo
```

Expected result:

- Correlated multi-source evidence
- Sigma / YARA assist hits
- SOC critical with explanation payload

Suggested M.I.O. question:

```text
/mio 複数ソースが同じ対象を指している時、何を重視して判断すべきか
```

## Expected Output Shape

Each scenario returns:

- `scenario_id`
- `description`
- `event_count`
- `noc`
- `soc`
- `arbiter`
- `explanation`

This is intentionally backend-oriented. M.I.O. remains a separate explanation layer.
