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
throughout this document, and lists every other place in the repository that
runs a firewall tool.

| Question | Answer |
| --- | --- |
| Authoritative decision and enforcement path, x86_64 profile | Rust `azazel-edge-core`: `decide_defense()` selects the action, `maybe_enforce()` applies it. Among the services Edge starts from its units, it is the only one that runs `nft` or `tc` to apply a defensive action (`throttle`, `redirect`, `isolate`). The repository has no other defensive path: no installer, unit or Python module applies a defensive action outside the core (see "No defensive path outside the core" below). |
| The other path | Python `py/azazel_edge/arbiter/action.py::ActionArbiter` is not an enforcement path. It is a deterministic copy of the decision used for scenario replay, benchmarks and dry runs. The SO-03 service-objective harness measures the Rust core's decisions, not this copy. It is neither removed nor subordinated, and nothing applies its output to the network. |
| How a consumer verifies it | The systemd unit inventory and its `Exec*` lines, plus the firewall-tool inventory below. Exactly one unit (`azazel-edge-core.service`) starts the `azazel-edge-core` binary, no unit runs a firewall tool directly, and every Python module and installer line that runs one is in the reviewed lists below. `tests/test_enforcement_boundary_inventory_v1.py` checks this against the repository tree, and also pins the modules that import `ActionArbiter`. |
| Constrained-device profile | The same answer for authority: the Rust core has no profile branch (architecture-specific code is limited to constants). The installed sets differ. The appliance installers copy units from `systemd/` and generate `azazel-internal-apply.service`; the x86_64 package built by `packaging/nexus-core/` (Edge#424) contains the `azazel-edge-core` binary and `config/redirect_policy.yaml`, no unit file and no Python. Neither set contains a second enforcer. |

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
`AZAZEL_DEFENSE_ALLOW_HIGH_IMPACT_AUTO=false`, and the `packaging/nexus-core/`
manifest declares the same observe-only environment. With these defaults the
core decides and records but does not run enforcement commands.

### No defensive path outside the core

No component other than the Rust core applies a defensive action. Every other
firewall-tool use in the repository is listed below as baseline connectivity
setup or read-only observation, and none takes decision input.

The optional Wazuh integration is observation-only. Edge#412 recorded the
Wazuh active response script that `installer/internal/install_wazuh_agent.sh`
used to generate (`/var/ossec/active-response/bin/azazel-block.sh`, an
`iptables` DROP started by the Wazuh manager) as an exception pending an owner
decision. The owner decided to remove it. The installer no longer writes the
script, removes it from a host where an earlier version left it, and sets
`<disabled>yes</disabled>` in the agent's `<active-response>` block, then
restarts a running agent (`systemctl try-restart`) so that no manager-side
command runs on the host. This holds while that setting stays in effect: the
Wazuh package's stock scripts such as `firewall-drop` stay on disk, and a
package update or manual edit that re-enables active response is undone by
re-running the installer. The Wazuh agent (FIM and SCA) and
Vector forwarding remain optional integrations that send telemetry out and
receive no action back (`docs/WAZUH_INTEGRATION_GUIDE.md`).

`tests/test_enforcement_boundary_inventory_v1.py` fails if an installer line
runs a firewall tool and is not in the reviewed baseline list, so a
reintroduced active response script fails the test.

### Baseline firewall written by installers

These set up connectivity and the captive portal. They are not defensive
actions and take no decision input.

| Installer | What it writes or runs | Purpose |
| --- | --- | --- |
| `installer/internal/install_internal_network.sh` | `/etc/nftables.d/azazel-internal.nft` (NAT masquerade and forward accept), loaded with `nft -f`; `net.ipv4.ip_forward=1`; the runner `/usr/local/sbin/azazel-internal-apply` and the unit `azazel-internal-apply.service`, which reload the same file at boot; a read-only `nft list` in its verify step | Appliance internal network baseline |
| `installer/internal/install_captive_portal.sh` | `/etc/nftables.d/azazel-captive.nft` (TCP port 80 redirect to the portal), loaded with `nft -f` | Captive portal |

### Python code that runs `nft`, `tc` or `iptables`

None of these consumes an `ActionArbiter` decision.

| Module | What it runs | Classification |
| --- | --- | --- |
| `py/azazel_edge/outcome/postcondition.py` | `tc -j qdisc show`, `nft -j list chain` | Read-only observation of the core's enforcement postcondition |
| `py/azazel_edge/service_objectives/so04_rollback_completion.py` | `tc`, `nft` on dummy interfaces it creates | SO-04 measurement harness, run by CI or an operator, not by a unit |
| `tools/hil/azazel_hil_remote.py` | `tc qdisc show`, `nft list ruleset` | HIL tool, read-only observation |
| `py/azazel_edge_control/wifi_connect.py` | `sysctl -w net.ipv4.ip_forward=1`, then `nft add table/chain/rule ... masquerade`, or `iptables -t nat -A POSTROUTING ... MASQUERADE` and two `iptables -A FORWARD` rules | Not a defensive action, but it changes network state. A request to `/api/wifi/connect` reaches the control daemon, whose `wifi_connect` calls `apply_nat` when a USB interface is present. Forwarding and the rules stay in place: there is no removal path. Each connect appends the rules again (`iptables -A`, `nft add rule`), so repeated connects leave duplicates; this is a known defect, recorded here and not changed by Edge#412. |

### Limits of this statement

- There is no released x86_64 artifact yet. The `packaging/nexus-core/` tool
  builds a package but none has been published, and the appliance installers
  copy units from the repository. The checks run against the repository tree;
  the same inventory is what a consumer applies to an artifact once one exists.
- Enforcement with `AZAZEL_DEFENSE_ENFORCE=true` has not been exercised on
  hardware (HIL) for this statement. It describes which component holds the
  authority, not that the enforcement is proven on a device.
- The test guards against accidental drift, not against deliberate evasion.
  It does not see an argv built entirely from variables in a module that names
  no tool, a shell command reached through a variable, an inline interpreter
  script, or a library loaded by a computed name. The read-only check on
  `postcondition.py` sees literal argv only, so an argv held in a variable
  passes it. In shell files it does not see a tool named inside a quoted
  string (`bash -c 'nft ...'`), behind a prefix command (`ssh`, `docker exec`)
  or in a `{ ...; }` group, and the unit inventory only parses units written
  with `cat > ... <<`; a unit written with `tee`, `printf` or `cat >>` is not
  listed. An extra copy of an already-reviewed line in the same file also
  passes, because the allowlist is a set of lines, not a count.
- `ip` is not in the checked tool set. The string is too common in this tree
  (about twenty Python modules contain it, mostly as a field name) for the
  file-level check, and its state-changing uses here (`ip link`, `ip netns` in
  the SO-02 harness) move interfaces, not filtering policy. `ipset` and
  `conntrack` are checked.

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
`azazel-edge-core` decision and enforcement path named in "Decision and
enforcement authority".

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
