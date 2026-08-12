# AZ-06 Azazel-Deception Integration

Repository: https://github.com/01rabbit/Azazel-Deception
Tracker: https://github.com/01rabbit/Azazel-Edge/issues/325
Parent doctrine: https://github.com/01rabbit/Azazel/issues/61

## Role

Azazel-Edge remains the **sole deterministic engagement authority**. AZ-06 Azazel-Deception Host (`THEATRE`) is an external, attacker-facing Engagement Environment Plane that materializes only Edge-approved deception packages and transitions.

> Engage expresses intent. Knowledge advises. Fabric describes. Edge decides and enforces. Deception Host materializes, transitions, records, and resets.

## Authority boundary

Edge owns:

- evidence evaluation
- engagement candidate evaluation
- accept / modify / downgrade / reject / terminate decisions
- target AZ-06 node or capability-class approval
- deployment-tier and resource-budget approval
- route / channel / redirect / isolate enforcement
- activation, expiry, anti-replay, heartbeat policy, downgrade, and termination
- operator-visible explanation and audit

AZ-06 owns:

- local capability discovery
- validation of an already-approved package
- local placement through its runtime adapter
- isolated decoy runtime lifecycle
- execution of approved finite-state transitions
- interaction evidence export
- deterministic reset and credential invalidation

Edge must not become a Docker, Podman, KVM, Proxmox, or Kubernetes scheduler.

## Current bootstrap integration

AZ-06 currently provides non-executing bootstrap commands for capabilities, package validation, and deterministic placement planning. Edge integration must begin in **shadow/replay mode** and must not start attacker-facing containers.

Initial target:

```text
Evidence -> NOC/SOC -> Engagement Candidate -> Action Arbiter
        -> AZ-06 capability/package validation
        -> descriptive placement plan
        -> simulated lifecycle result
        -> DecisionExplanation / AuditEvent
```

A capability report or placement plan is descriptive only and carries no activation authority.

## Live activation gates

Live activation remains disabled until:

- canonical Azazel-Fabric deception-environment contracts are released (`Azazel-Fabric#9`)
- package/image digest, signature, provenance, and SBOM validation is implemented
- Edge decision ID, expiry, anti-replay, and AZ-06 identity allowlisting are enforced
- decoy egress and production isolation tests pass
- heartbeat/state reconciliation exists
- manual kill switch, deterministic timeout, teardown, and reset acknowledgement exist
- the same signed reference package is proven on ARM64 and AMD64

## Failure behavior

AZ-06 absent, slow, malformed, unsupported, stale, or compromised must not break baseline Edge operation. NOC health and protected-path availability always preempt deception value.

Capability drift, runtime-version drift, route/policy drift, resource exhaustion, heartbeat loss, or reset failure are deterministic reject/downgrade/terminate cases.

## LLM boundary

AZ-06 may use LLM assistance during package preparation, but Edge never accepts LLM output as live authority. Runtime LLM availability is not required for approved package execution.
