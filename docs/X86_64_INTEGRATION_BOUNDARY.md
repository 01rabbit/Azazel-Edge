# x86_64 Package and Commissioning Boundary

Status: **R0 target contract; implementation evidence pending.**

This document defines how a persistent Azazel-Nexus installation or a
removable Azazel-Boot environment may consume the Azazel-Edge runtime without
inheriting the Raspberry Pi appliance installer's network assumptions.

It does not authorize a network change and does not replace a product's own
installer. Existing `installer/internal/install_internal_network.sh` is an
appliance-specific path: it assumes `br0`, `eth0`, and `wlan0` and therefore
MUST NOT be applied automatically on a generic x86_64 host.

## Package boundary

The future `azazel-edge-runtime` x86_64 package MUST contain only the
deterministic runtime and its non-topology-specific dependencies:

- evidence intake, NOC/SOC evaluators, the deterministic decision and
  enforcement path (see "Decision and enforcement authority" below),
  explanations, audit, and operator/API services;
- service definitions that consume rendered configuration rather than discover
  or rename network interfaces themselves;
- Suricata binaries, rules, and a disabled service template;
- optional integrations as separately selected packages or profiles;
- health and self-test commands that report capability without changing it.

The package MUST NOT create bridges, change default routes, enable forwarding,
start DHCP/NAT, bind a listener to a physical interface, or start Suricata
capture during package installation. It MUST be usable with no external
network connectivity once its verified assets are installed.

## Decision and enforcement authority

Decided by the owner on 2026-10-26 (Edge#412). This section names the
component that "the deterministic arbiter" and "arbiter" (singular) refer to
throughout this document.

| Question | Answer |
| --- | --- |
| Authoritative decision and enforcement path, x86_64 profile | Rust `azazel-edge-core`: `decide_defense()` selects the action, `maybe_enforce()` applies it. It is the only component that runs `nft` or `tc` to apply a defensive action (`throttle`, `redirect`, `isolate`). |
| The other path | Python `py/azazel_edge/arbiter/action.py::ActionArbiter` is not an enforcement path. It is a deterministic copy of the decision used for scenario replay, benchmarks, dry runs and service-objective harnesses. It is neither removed nor subordinated, and nothing applies its output to the network. |
| How a consumer verifies it | The systemd unit inventory and its `ExecStart` lines. Exactly one unit (`azazel-edge-core.service`) starts the `azazel-edge-core` binary, and no Python module calls `nft`, `tc` or `iptables` outside a short reviewed list, none of which applies a defensive action. `tests/test_enforcement_boundary_inventory_v1.py` checks both against the repository tree, and pins the modules that import `ActionArbiter`. |
| Constrained-device profile | The same answer. The Rust core has no profile branch (architecture-specific code is limited to constants), and both profiles install the same unit set from `systemd/`. |

This statement names an existing path. It creates no new decision authority,
enforcement authority, approval flag or bypass.

### What "arbiter" means

- **the deterministic arbiter** / **the arbiter** in this document and in
  integration contracts: the Rust `azazel-edge-core` decision and enforcement
  path.
- **`ActionArbiter`**: the Python class. Documents that describe its
  decision fields (rejected alternatives, release conditions, the bounded
  action vocabulary) describe that decision record, not a path that changes
  the network.

### Shipped defaults

`systemd/azazel-edge-core.service` ships with `AZAZEL_DEFENSE_ENFORCE=false`,
`AZAZEL_DEFENSE_DRY_RUN=true`, `AZAZEL_DEFENSE_ENFORCE_LEVEL=advisory` and
`AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO=false`. With these defaults the core
decides and records but does not run enforcement commands.

### Other Python code that runs `nft`, `tc` or `iptables`

None of these consumes an `ActionArbiter` decision or applies a defensive
action. The test fails if a module outside this list starts running these
tools.

| Module | What it runs | Why |
| --- | --- | --- |
| `py/azazel_edge/outcome/postcondition.py` | `tc -j qdisc show`, `nft -j list chain` | Read-only observation of the core's enforcement postcondition |
| `py/azazel_edge/service_objectives/so04_rollback_completion.py` | `tc`, `nft` on dummy interfaces it creates | SO-04 measurement harness, run by CI or an operator, not by a unit |
| `py/azazel_edge_control/wifi_connect.py` | `nft` or `iptables` NAT/forward rules | Uplink NAT for a USB client after a Wi-Fi connect requested through the control daemon; connectivity, not a defensive action |

### Limits of this statement

- There is no released x86_64 artifact yet; the installer copies units from
  the repository. The check above runs against the repository tree, and the
  same inventory check is what a consumer applies to an artifact once one
  exists.
- Enforcement with `AZAZEL_DEFENSE_ENFORCE=true` has not been exercised on
  hardware (HIL) for this statement. It describes which component holds the
  authority, not that the enforcement is proven on a device.

## Two-stage workflow

| Stage | Owner | Allowed effect | Required result |
|---|---|---|---|
| Inventory | Nexus or Boot installer | Read-only host and resource discovery | Signed or locally trusted inventory record; no interface role inferred |
| Commissioning plan | Operator with product installer | Review and assign roles to stable interface identities | Explicit topology plan with intended capture, management, protected, and optional decoy segments |
| Apply | Product installer | Render product-owned networking and Edge configuration | Transactional apply record, pre-change backup, and rollback reference |
| Activate | Edge runtime | Start only topology-authorized services | Suricata/other services bind only to approved configured interfaces |
| Verify | Product installer and operator | Read-only health and policy checks | Capability state and audit evidence; failure reverts to a safer state |

Inventory MAY report interface name, MAC address, driver, link, route, address,
and wireless capability. It MUST NOT label an interface internal or external
from those observations. A role assignment requires operator confirmation and
a stable identity, normally MAC address plus driver/path metadata.

## Commissioning input contract

The product installer supplies a reviewed, immutable commissioning record to
the Edge renderer. A minimum record is:

```yaml
schema_version: edge-commissioning/v0.1
host_id: stable-local-host-id
topology_revision: 1
interfaces:
  - id: pci-0000:03:00.0/mac-00-11-22-33-44-55
    observed_name: enp3s0
    role: protected
  - id: usb-1-2/mac-00-11-22-33-44-66
    observed_name: enx001122334466
    role: capture
suricata:
  capture_interface_id: usb-1-2/mac-00-11-22-33-44-66
  mode: passive
enforcement:
  enabled: false
  reason: operator has not approved an enforcement topology
```

Permitted roles are `management`, `protected`, `external`, `capture`, `decoy`,
and `unused`. The record MUST fail closed on missing, duplicate, changed, or
unrecognized interface identities. A changed interface name with the same
stable identity is a reviewable drift event; a changed identity requires a new
commissioning plan.

The canonical cross-product schema belongs in Azazel-Fabric. Until it ships,
this Edge document is a target boundary and must not be treated as a wire-format
guarantee.

## Suricata activation

Suricata is a sensor, not a topology classifier. The runtime receives a
rendered `SURICATA_IFACE` only after commissioning validates the selected
capture identity. The service MUST remain disabled if no approved capture
interface exists.

For the initial x86_64 implementation:

- passive capture is the default;
- `HOME_NET` is derived from the commissioned protected segments, not from a
  hard-coded appliance subnet;
- `EXTERNAL_NET` is derived from `HOME_NET` through the rendered policy;
- a missing, stale, or invalid record blocks capture start rather than falling
  back to `br0`;
- no tool install or model download may implicitly enable capture or
  enforcement.

## Resource profiles

RAM determines capacity only. It never grants interface roles or enforcement
authority.

| Available RAM | Target envelope | Required behavior |
|---|---|---|
| 8 GB | Core | deterministic evidence/decision/audit; no local model required; optional services disabled by default |
| 16 GB | Lite | Core plus bounded local cognition or selected Lite services when their independent gates pass |
| 32 GB or more | Full-eligible | permits selected models and extended services, subject to storage, topology, trust, and health gates |

If a resource, asset, trust, or health gate fails, the runtime MUST degrade to
a lower capability state without transferring decision authority away from the
deterministic arbiter, which in this document always means the Rust
`azazel-edge-core` decision and enforcement path defined below.

## Rollback and evidence

Before applying a topology plan, the product installer MUST save its own
network configuration backup and record the plan digest. Edge MUST report the
active plan digest, capture interface identity, service state, and policy
version in health output and audit events. A failed apply or failed post-check
MUST disable newly enabled capture/enforcement services and restore the
product-owned prior configuration where safe to do so.

## Acceptance evidence

- package installation on x86_64 makes no network topology changes;
- an uncommissioned host cannot start capture or enforcement;
- a reviewed passive-capture plan starts Suricata only on its selected identity;
- renamed-but-identical hardware requires review, while substituted hardware
  fails closed;
- 8 GB, 16 GB, and 32 GB profiles select different capacity envelopes without
  changing deterministic authority;
- failed apply, service failure, and stale-plan tests leave a reviewable audit
  record and a safe lower-capability state.
