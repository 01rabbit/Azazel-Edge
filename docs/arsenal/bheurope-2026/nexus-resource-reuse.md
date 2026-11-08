# Selective Nexus resource reuse — admission boundary

The presentation remains **Azazel-Edge**, with no Nexus runtime dependency.
Nexus is a source of potentially reusable, versioned artifacts, not a
decision authority.

## Inspected upstream contracts

- `01rabbit/Azazel-Nexus/contract/azazel-edge-core/pin.json` declares
  `azazel-edge-core/nexus-pin/v2`, version 0.1.0, Linux ELF packages for
  aarch64 and x86_64. The contract explicitly states **signed: false** and
  requires independent manifest, ELF and digest validation. It must not be
  executed on macOS.
- `01rabbit/Azazel-Nexus/contract/azazel-knowledge-lite/` contains a signed
  fixture bundle, trust anchor, positive and negative fixtures. Its anchor is
  explicitly **test-only**, not a production trust root.
- Nexus's contract ownership rules assign decision authority to Edge;
  Knowledge advises and Nexus integrates. The demo must preserve that rule.

## Reuse classification

| Resource | Mac replay | ARM64 Linux | Decision |
|---|---|---|---|
| Existing Edge evaluators/Arbiter | direct Python reuse | direct Python reuse | required |
| Nexus Edge Core pin/manifest | inspect only | admission candidate | optional |
| Knowledge Lite fixture | inspect only | inspect only | not a production knowledge feed |
| Fabric shared contracts | optional future adapter | optional future adapter | no local fork |
| Nexus systemd/bootstrap/activation | not portable | Linux-specific | excluded |
| MIO runtime | not required | not required | optional, advisory-only |

## Implemented discovery tool

```bash
python3 tools/arsenal_nexus_resources.py \
  --pin /path/to/nexus/contract/azazel-edge-core/pin.json \
  --artifact-dir /path/to/linux/core/releases \
  --knowledge-bundle /path/to/nexus/contract/azazel-knowledge-lite/lite.tar.gz
```

This tool returns explicit status for missing resources and unsupported
platforms. It computes hashes of present files but **never claims admission**.
It does not load or execute artifacts. This is intentional: SHA-256 alone does
not establish package authenticity or Knowledge signature validity.

## Required next integration work

1. Bind to the exact Nexus v2 manifest schema and verify the artifact digest,
   version, architecture and ELF header on Linux before enabling any loader.
2. Use the actual Knowledge producer verifier and a production trust anchor;
   reject signature failures, rollback, corrupt bundles and expired claims.
3. Add golden cross-platform fixture tests and audit evidence of each refusal.
4. Only then expose admitted advisory Knowledge data in the monitor. Never
   let it modify the Arbiter's action.

## Current truth

Resource **discovery** is implemented. Verified ingestion, runtime admission,
and real enforcement are not. The Mac demo remains independently operable
using the Edge replay and monitor without Nexus installed.
