# Security Policy

Azazel-Edge (AZ-01, codename `SENTINEL`) is a deception/delay gateway that faces hostile traffic by design — scapegoat surfaces exist to be probed, bound, and slowed by attackers. The boundary that matters is not those surfaces; it is the line between them and the protected segment / control plane (deterministic arbiter, nftables/tc policy, audit chain, management interfaces).

## Reporting a vulnerability

Report privately via **GitHub Security Advisories**:
<https://github.com/01rabbit/Azazel-Edge/security/advisories/new>

Do **not** open a public issue for a suspected vulnerability.

Include: affected version or commit hash; deployment profile (e.g. field/vehicle/humanitarian, enabled feature flags); reproduction steps or a minimal PoC; observed impact and, if known, the affected component.

No bounty program. Reporters are credited in the advisory unless anonymity is requested.

## Response targets

- Acknowledgement: within 7 days
- Initial assessment (severity, affected versions): within 14 days
- Fix and disclosure are coordinated with the reporter.

## Scope

**In scope** — anything that crosses the boundary described above:

- Authentication/authorization bypass on the web UI or API (token, mTLS, RBAC role checks)
- Escape from a scapegoat/deception surface — or from the captive portal / portal-viewer — into the protected segment or control plane
- Bypass of nftables/tc policy enforcement
- Audit hash-chain integrity break
- Privilege escalation via the installer or systemd unit files
- Secrets leakage (tokens, certificate/key material) through any endpoint, including the EPD web preview
- Manipulation of the deterministic arbiter's decisions via crafted sensor input, where it crosses a documented security boundary
- AI-assist (local Ollama) prompt-injection paths that cross an authority boundary — AI is assist-only; anything letting it trigger or execute an unapproved action is in scope

**Out of scope**:

- Attacker interaction with deception surfaces — binding, slowing, or observing attackers there is the product working as intended
- Degraded throughput on delaying paths
- Findings that require pre-existing root on the appliance

## Supported versions

Latest tagged release and `main`.
