# One opt-in root kernel proof for native flow evidence

`tests/test_outcome_nft_flow_evidence_linux.py` performs one actual native TCP
flow-rule mechanism/ownership proof in fresh owned namespaces. It reuses the
merged network measurement `Assets`, foreign-canary setup, bounded cleanup and
root route/rules snapshots. It starts the existing pinned release core and
supplies one clearly synthetic local alert. It starts **no TCP traffic, client,
protected service, model or production observer** and makes no service-effect,
sealed-origin, production admission, efficacy or hardware acceptance claim.

Root must review and freeze the combined source containing the native
`nft_flow_evidence` adapter/postcondition/ownership implementation. Stage that
source, its reviewed native core binary and tools in a **fresh clone of an unused
disposable offline VM template**. Do not reuse another proof's active state,
output, namespaces or receipts. The driver never installs a provider/unit/policy,
adds observer capabilities, repairs a failure or fetches dependencies.

Provision `/etc/edge-nft-flow-proof-vm` as a root-owned regular single-link file,
not group/world writable, containing `azazel-edge-nft-flow-proof-v1` plus newline.
The root Linux opt-in, marker, VM identity, actual core SHA-256/native ELF machine,
reviewed source ID and staged `ip`/`nft`/`tc`/`conntrack` are required. Root IPv4
and IPv6 default routes must be absent before execution; no host routes/rules or
sysctls are written. The existing router-local setup is the sole namespace
mutation fixture. Namespace names are fresh and existing names are refused,
never predeleted. Unknown/changed ownership remains a failed cleanup for review.

```sh
EDGE_NFT_FLOW_PROOF_TESTS=1 \
EDGE_NFT_FLOW_PROOF_SOURCE_COMMIT=<reviewed-combined-source> \
EDGE_NETWORK_MEASURE_CORE=/usr/local/bin/edge393-core \
EDGE_NETWORK_MEASURE_CORE_SHA256=<reviewed-native-core-sha256> \
PYTHONPATH=.:py python -m pytest -q \
  tests/test_outcome_nft_flow_evidence_linux.py \
  --basetemp=/opt/new-private-kernel-proof
```

Without the flag the test skips. An opted-in run fails if the new production
flow API is missing; it does not substitute a golden fixture. Preserve every
failed scope; use another independently reviewed experiment/output if corrected
source is later executed. There is no overwrite, resume, retry or backfill path.

The raw original core event lines and their source `events.jsonl` remain intact.
A separate **root lab process inside the owned router namespace** invokes the
existing `SubprocessReadOnlyRunner` on exactly:

```text
nft -j list chain inet azazel_edge throttle
```

The probe retains full raw stdout/stderr/return code, logical query, actual
namespace-exec child arguments, PID/UID/namespace inode, nft binary hash and
actual query start/end UTC times. Chain headers, duplicate rules and original
JSON are not filtered or reconstructed. The pure `RecordedProbeRunner` then
projects this explicitly recorded live receipt through `from_rust_event` and
the existing ownership-aware `verify_mechanism_postcondition`, using the actual
query-end time. It is never presented as a second kernel query or a fake clock.
Exact tuple, protocol, owner, rate, burst and the foreign rule must match.

After the actual minimum 30-second lease, the original core release fact must
report verified absence. Another full independent root readback must show no
owned flow and the unchanged foreign canary. Every exit runs the existing owned
process/namespace cleanup and compares root routes/rules; success is written
only after verified cleanup. Intent, source/core/tool/API hashes, full receipts,
original events, projection and before/after state are private proof artifacts.

This boundary is intentionally **not** the production observer. UID 61002 with
zero capabilities and AF_UNIX-only confinement cannot query nft. No observer
UID, capability, address-family policy, profile or proxy is changed here. A root
lab readback proves local kernel mechanism/ownership facts only; the production
observer privilege/integration gap, genuine signed/sealed origin, protected-host
isolation, routing authority and all effect/efficacy claims remain open.
