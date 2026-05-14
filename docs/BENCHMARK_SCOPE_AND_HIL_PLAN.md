# Benchmark Scope Boundary and Hardware-in-the-Loop Plan

Last updated: 2026-05-14

## Current benchmark scope

The current benchmark suite validates deterministic pipeline behavior under software-only EVE replay. It is useful for regression testing and reproducibility.

It does **not** claim:
- full inline forwarding throughput
- live Suricata capture capacity
- nftables/tc enforcement latency
- OpenCanary interaction realism
- co-located Ollama/Mattermost performance on Raspberry Pi hardware

## Current benchmark metadata

`bin/azazel-bench report` records:
- `benchmark_mode`
- `hardware`
- `claim_scope`

Default values for v0.1.1 hardening are:
- `benchmark_mode: software-only-eve-replay`
- `hardware: software-only`
- `claim_scope: deterministic pipeline regression`

## Hardware-in-the-loop plan (next stages)

1. Pi 5 clean install startup timing
- measure service-ready timing for `azazel-edge-web`, `azazel-edge-control-daemon`, and `azazel-edge-core`

2. Suricata live alert ingestion latency
- measure live alert path from packet capture to normalized event emission

3. nftables/tc apply and rollback latency
- measure action apply/revert timing for throttle, redirect, isolate plans

4. OpenCanary redirect behavior validation
- verify protocol-aware redirect mapping behavior against prepared decoys

5. Thermal, memory, and load under Demo profile
- sustained run with deterministic replay and required demo services

6. Optional Heavy lab profile impact
- co-located optional integrations (Ollama, Mattermost, Wazuh, Vector, Aggregator, TAXII)

## Validation commands

```bash
PYTHONPATH=py:. .venv/bin/pytest -q tests/benchmark -v
bin/azazel-bench pipeline
bin/azazel-bench accuracy
bin/azazel-bench report
```
