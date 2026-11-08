# Nexus v2 Edge Core integrity verification (macOS and Linux)

This verifier is **read-only**. It uses the Nexus v2 pin and the Edge
packager's actual manifest format. It can inspect a Linux aarch64 package on
an Apple Silicon Mac without executing ELF binaries.

```bash
python3 tools/arsenal_edge_core_verify.py \
  --pin /path/to/Azazel-Nexus/contract/azazel-edge-core/pin.json \
  --manifest /path/to/azazel-edge-core-0.1.0-aarch64.manifest.json \
  --artifact /path/to/azazel-edge-core-0.1.0-aarch64.tar.gz \
  --architecture aarch64 \
  --output artifacts/bheurope-2026/resource-status.json
```

The local monitor reads `resource-status.json` when present, and will
display its findings. Use `--architecture x86_64` for x86_64 Linux packages.

**Important:** `ok=true` is only a package **integrity** result.
The upstream pin explicitly states `signed=false`. This is not
authentication, runtime health, successful installation, or proof that a
daemon is running. Do not load the package into the Mac demo.

The tool refuses wrong CPU identities, mismatched artifact or component
digests, archive path traversal, links, missing binary and malformed inputs.

## Knowledge Lite status

The Nexus `contract/azazel-knowledge-lite` directory contains a signed
test fixture, not a production intelligence feed. Its published
`anchors.toml` is test-only. The Edge presentation must not display this
fixture as live threat intelligence or treat its presence as signature
verification.

Next step for verified Knowledge ingestion: use the Knowledge project's
real signature verifier with a production trust anchor, enforce rollback
watermarks and per-claim expiry, then project **advisory-only** information
to the dashboard. The Arbiter must remain the only action authority.

## Local tests

```bash
python3 -m pytest -q tests/test_arsenal_edge_core_verify.py \
  tests/test_arsenal_nexus_resources.py \
  tests/test_bheurope_2026_monitor.py \
  tests/test_bheurope_2026_gate.py
```

Tests are synthetic contract tests and do not replace checking actual
Nexus-produced package bytes. Confirm on macOS and ARM64 Linux before
freezing the Black Hat Europe demo release.
