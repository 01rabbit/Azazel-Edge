# Cross-platform execution contract — Black Hat Europe 2026

## Portability boundary

The presentation must not couple the decision pipeline to an operating system.
Evidence normalization, NOC/SOC scoring, Action Arbiter, explanation generation,
audit logging, deterministic replay and the read-only monitor are portable
Python components.

OS-specific operations must be behind an explicit adapter. The following
contract defines the next implementation milestone:

```python
class ControlBackend(Protocol):
    def capabilities(self) -> set[str]: ...
    def plan(self, action: str, target: str) -> dict: ...
    def apply(self, plan: dict, *, approved: bool = False) -> dict: ...
    def rollback(self, receipt: dict) -> dict: ...
```

Implementations:

| Backend | Platform | Recording mode | Actual enforcement |
|---|---|---|---|
| ReplayBackend | macOS, Linux | deterministic, offline | never |
| LinuxNetworkBackend | Linux | disabled | existing Edge core, separately verified |
| MacNetworkBackend | macOS | disabled | not implemented; do not imply support |

The replay backend must never issue shell commands or modify interfaces.
A live backend must fail closed for unsupported actions, require explicit
operator authorization, emit a durable audit record and a rollback receipt.

## Data-flow contract

Local synthetic evidence -> NOC and SOC evaluators -> Arbiter ->
Explanation JSONL + audit chain -> read-only monitor.

The monitor reads only artifacts produced by the actual Edge replay.
It cannot select an action or invoke a backend. The UI does not simulate
decision results.

## Deployment tiers

**Tier 1 (required for video):** Python environment + replay + evidence gate
+ monitor on macOS. Repeat on ARM64 Linux.

**Tier 2 (optional):** live local telemetry on macOS via a dedicated collector
adapter, feeding the same evidence schema. Requires implementation and testing.

**Tier 3 (out of scope for recording):** macOS traffic enforcement with a
platform-specific and safely reversible implementation.

## Open validation risks

- Python imports in the existing replay pipeline may require more than the
  minimal dependencies listed in the setup script.
- Hardware execution has not been performed.
- Cross-platform reproducibility must be checked by comparing semantic
  fields, not timestamps or machine-dependent paths.
- Browser monitor is local-only and has no authentication; never expose it
  beyond loopback.
